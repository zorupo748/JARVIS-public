"""Generic concurrent execution of deterministic hybrid execution plans.

The executor has no provider clients and no model knowledge. Callers inject
handlers, while the real local handlers remain responsible for using
``VramManager`` internally.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from time import monotonic
from typing import Any, Callable, Mapping

from jarvis.core.execution_planner import (
    ExecutionPlan,
    ExecutionTarget,
    WorkerAssignment,
    WorkerKind,
)


Handler = Callable[[], Any]


class WorkerStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    FALLBACK_SUCCESS = "fallback_success"
    FALLBACK_FAILED = "fallback_failed"


@dataclass(frozen=True)
class HandlerOutcome:
    """Optional handler contract for reporting an expected failure without raising."""

    success: bool
    content: Any = None
    error: str | None = None

    @classmethod
    def failed(cls, error: str) -> "HandlerOutcome":
        return cls(success=False, error=error)


@dataclass(frozen=True)
class WorkerResult:
    worker: WorkerKind
    requested_target: ExecutionTarget
    actual_target: ExecutionTarget
    status: WorkerStatus
    content: Any = None
    error: str | None = None
    fallback_used: bool = False
    elapsed_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return self.status in (
            WorkerStatus.SUCCESS,
            WorkerStatus.FALLBACK_SUCCESS,
        )


@dataclass(frozen=True)
class ExecutionResult:
    """Per-worker results, ready for a future ResultBus or streaming adapter."""

    results: tuple[WorkerResult, ...]
    elapsed_seconds: float
    cloud_calls_attempted: int
    cloud_failures: int
    fallbacks_used: int
    success: bool

    def result_for(self, worker: WorkerKind) -> WorkerResult:
        for result in self.results:
            if result.worker is worker:
                return result
        raise KeyError(worker)


class ExecutionConfigurationError(ValueError):
    """Raised for a structurally invalid plan or a missing injected handler."""


@dataclass(frozen=True)
class _Invocation:
    success: bool
    content: Any
    error: str | None
    elapsed_seconds: float


class ExecutionExecutor:
    """Execute a plan without changing its routing policy.

    Cloud handlers start immediately. A single coordinator runs every primary
    local assignment and any cloud fallback in ascending local order, so this
    class never deliberately launches competing local workers.
    """

    def __init__(
        self,
        *,
        local_handlers: Mapping[WorkerKind, Handler],
        cloud_handlers: Mapping[ExecutionTarget, Handler],
    ) -> None:
        self._local_handlers = dict(local_handlers)
        self._cloud_handlers = dict(cloud_handlers)

    def execute(self, plan: ExecutionPlan) -> ExecutionResult:
        self._validate(plan)
        started_at = monotonic()
        if not plan.assignments:
            return ExecutionResult(
                results=(),
                elapsed_seconds=monotonic() - started_at,
                cloud_calls_attempted=0,
                cloud_failures=0,
                fallbacks_used=0,
                success=True,
            )

        cloud_assignments = tuple(
            assignment
            for assignment in plan.assignments
            if assignment.target is not ExecutionTarget.LOCAL
        )
        max_workers = len(cloud_assignments) + 1
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            cloud_futures = {
                assignment.worker: pool.submit(
                    self._invoke, self._cloud_handlers[assignment.target]
                )
                for assignment in cloud_assignments
            }
            local_future = pool.submit(
                self._run_local_queue,
                plan,
                cloud_futures,
            )
            results_by_worker = local_future.result()

            for assignment in cloud_assignments:
                if assignment.fallback_target is not None:
                    continue
                invocation = cloud_futures[assignment.worker].result()
                results_by_worker[assignment.worker] = self._cloud_result(
                    assignment, invocation
                )

            cloud_invocations = tuple(
                cloud_futures[assignment.worker].result()
                for assignment in cloud_assignments
            )

        ordered_results = tuple(
            results_by_worker[assignment.worker] for assignment in plan.assignments
        )
        return ExecutionResult(
            results=ordered_results,
            elapsed_seconds=monotonic() - started_at,
            cloud_calls_attempted=len(cloud_assignments),
            cloud_failures=sum(not invocation.success for invocation in cloud_invocations),
            fallbacks_used=sum(result.fallback_used for result in ordered_results),
            success=all(result.success for result in ordered_results),
        )

    def _run_local_queue(
        self,
        plan: ExecutionPlan,
        cloud_futures: Mapping[WorkerKind, Future[_Invocation]],
    ) -> dict[WorkerKind, WorkerResult]:
        entries: dict[int, WorkerAssignment] = {}
        for assignment in plan.assignments:
            if assignment.target is ExecutionTarget.LOCAL:
                self._register_local_entry(entries, assignment.local_order, assignment)
            elif assignment.fallback_target is ExecutionTarget.LOCAL:
                self._register_local_entry(
                    entries, assignment.fallback_local_order, assignment
                )

        results: dict[WorkerKind, WorkerResult] = {}
        for _order, assignment in sorted(entries.items()):
            if assignment.target is ExecutionTarget.LOCAL:
                invocation = self._invoke(self._local_handlers[assignment.worker])
                results[assignment.worker] = self._local_result(assignment, invocation)
                continue

            cloud_invocation = cloud_futures[assignment.worker].result()
            if cloud_invocation.success:
                results[assignment.worker] = self._cloud_result(
                    assignment, cloud_invocation
                )
                continue

            fallback_invocation = self._invoke(self._local_handlers[assignment.worker])
            results[assignment.worker] = self._fallback_result(
                assignment, cloud_invocation, fallback_invocation
            )
        return results

    @staticmethod
    def _register_local_entry(
        entries: dict[int, WorkerAssignment],
        order: int | None,
        assignment: WorkerAssignment,
    ) -> None:
        if order is None or order < 1:
            raise ExecutionConfigurationError("Local queue entries require a positive order")
        if order in entries:
            raise ExecutionConfigurationError(
                f"Multiple local queue entries use order {order}"
            )
        entries[order] = assignment

    @staticmethod
    def _invoke(handler: Handler) -> _Invocation:
        started_at = monotonic()
        try:
            outcome = handler()
        except Exception as exc:
            return _Invocation(
                success=False,
                content=None,
                error=f"{type(exc).__name__}: {exc}",
                elapsed_seconds=monotonic() - started_at,
            )

        if isinstance(outcome, HandlerOutcome):
            return _Invocation(
                success=outcome.success,
                content=outcome.content,
                error=outcome.error,
                elapsed_seconds=monotonic() - started_at,
            )
        return _Invocation(
            success=True,
            content=outcome,
            error=None,
            elapsed_seconds=monotonic() - started_at,
        )

    @staticmethod
    def _local_result(
        assignment: WorkerAssignment, invocation: _Invocation
    ) -> WorkerResult:
        return WorkerResult(
            worker=assignment.worker,
            requested_target=ExecutionTarget.LOCAL,
            actual_target=ExecutionTarget.LOCAL,
            status=WorkerStatus.SUCCESS if invocation.success else WorkerStatus.FAILED,
            content=invocation.content,
            error=invocation.error,
            elapsed_seconds=invocation.elapsed_seconds,
        )

    @staticmethod
    def _cloud_result(
        assignment: WorkerAssignment, invocation: _Invocation
    ) -> WorkerResult:
        return WorkerResult(
            worker=assignment.worker,
            requested_target=assignment.target,
            actual_target=assignment.target,
            status=WorkerStatus.SUCCESS if invocation.success else WorkerStatus.FAILED,
            content=invocation.content,
            error=invocation.error,
            elapsed_seconds=invocation.elapsed_seconds,
        )

    @staticmethod
    def _fallback_result(
        assignment: WorkerAssignment,
        cloud_invocation: _Invocation,
        fallback_invocation: _Invocation,
    ) -> WorkerResult:
        fallback_success = fallback_invocation.success
        error = cloud_invocation.error
        if not fallback_success:
            error = (
                f"Cloud failure: {cloud_invocation.error}; "
                f"local fallback failure: {fallback_invocation.error}"
            )
        return WorkerResult(
            worker=assignment.worker,
            requested_target=assignment.target,
            actual_target=ExecutionTarget.LOCAL,
            status=(
                WorkerStatus.FALLBACK_SUCCESS
                if fallback_success
                else WorkerStatus.FALLBACK_FAILED
            ),
            content=fallback_invocation.content,
            error=error,
            fallback_used=True,
            elapsed_seconds=(
                cloud_invocation.elapsed_seconds + fallback_invocation.elapsed_seconds
            ),
        )

    def _validate(self, plan: ExecutionPlan) -> None:
        local_orders: set[int] = set()
        for assignment in plan.assignments:
            if assignment.target is ExecutionTarget.LOCAL:
                self._require_local_handler(assignment.worker)
                self._validate_local_order(local_orders, assignment.local_order)
                continue

            if assignment.target not in (ExecutionTarget.GROQ, ExecutionTarget.GEMINI):
                raise ExecutionConfigurationError(
                    f"Unsupported execution target: {assignment.target!r}"
                )
            if assignment.target not in self._cloud_handlers:
                raise ExecutionConfigurationError(
                    f"Missing cloud handler for {assignment.target.value}"
                )
            if assignment.fallback_target is not None:
                if assignment.fallback_target is not ExecutionTarget.LOCAL:
                    raise ExecutionConfigurationError("Only local cloud fallbacks are supported")
                self._require_local_handler(assignment.worker)
                self._validate_local_order(
                    local_orders, assignment.fallback_local_order
                )

    def _require_local_handler(self, worker: WorkerKind) -> None:
        if worker not in self._local_handlers:
            raise ExecutionConfigurationError(
                f"Missing local handler for {worker.value}"
            )

    @staticmethod
    def _validate_local_order(orders: set[int], order: int | None) -> None:
        if order is None or order < 1:
            raise ExecutionConfigurationError("Local queue entries require a positive order")
        if order in orders:
            raise ExecutionConfigurationError(
                f"Multiple local queue entries use order {order}"
            )
        orders.add(order)


__all__ = [
    "ExecutionConfigurationError",
    "ExecutionExecutor",
    "ExecutionResult",
    "HandlerOutcome",
    "WorkerResult",
    "WorkerStatus",
]