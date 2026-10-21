"""Deterministic planning for hybrid local/cloud specialist execution.

This module only selects targets and ordering. It never starts a worker, reserves
VRAM, or makes a provider request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class WorkerKind(str, Enum):
    """Specialist capabilities selected upstream by the architecture layer."""

    CODING = "coding"
    VISION = "vision"
    REASONING = "reasoning"


class ExecutionTarget(str, Enum):
    """Possible provider classes for an individual specialist."""

    LOCAL = "local"
    GROQ = "groq"
    GEMINI = "gemini"


_WORKER_PRIORITY = (
    WorkerKind.CODING,
    WorkerKind.VISION,
    WorkerKind.REASONING,
)


@dataclass(frozen=True)
class CapabilityRequest:
    """Capabilities required for one user request, independent of providers."""

    coding: bool = False
    vision: bool = False
    reasoning: bool = False

    def requested_workers(self) -> tuple[WorkerKind, ...]:
        flags = {
            WorkerKind.CODING: self.coding,
            WorkerKind.VISION: self.vision,
            WorkerKind.REASONING: self.reasoning,
        }
        return tuple(worker for worker in _WORKER_PRIORITY if flags[worker])


@dataclass(frozen=True)
class CloudAvailability:
    """Availability and authorization state supplied by the runtime.

    ``local_available`` is observational only in this phase: local assignments
    remain valid queue entries even when the one heavy slot is busy.
    """

    groq_available: bool = False
    gemini_available: bool = False
    groq_budget_available: bool = False
    gemini_budget_available: bool = False
    local_available: bool = True

    @property
    def groq_usable(self) -> bool:
        return self.groq_available and self.groq_budget_available

    @property
    def gemini_usable(self) -> bool:
        return self.gemini_available and self.gemini_budget_available


@dataclass(frozen=True)
class WorkerAssignment:
    """A deterministic primary target plus an optional future local fallback."""

    worker: WorkerKind
    target: ExecutionTarget
    local_order: int | None
    reason: str
    fallback_target: ExecutionTarget | None = None
    fallback_local_order: int | None = None

    def __post_init__(self) -> None:
        if not self.reason:
            raise ValueError("WorkerAssignment.reason must not be empty")
        if self.target is ExecutionTarget.LOCAL:
            if self.local_order is None or self.local_order < 1:
                raise ValueError("Local assignments require a positive local_order")
        elif self.local_order is not None:
            raise ValueError("Cloud assignments must not have a primary local_order")

        if self.fallback_target is None:
            if self.fallback_local_order is not None:
                raise ValueError("A fallback order requires a fallback target")
        elif self.fallback_target is not ExecutionTarget.LOCAL:
            raise ValueError("Only a local fallback is supported in this phase")
        elif self.fallback_local_order is None or self.fallback_local_order < 1:
            raise ValueError("A local fallback requires a positive fallback order")


@dataclass(frozen=True)
class ExecutionPlan:
    """Pure plan for a future executor; it contains no executable callables."""

    assignments: tuple[WorkerAssignment, ...]
    local_execution_order: tuple[WorkerKind, ...]
    cloud_parallelism_possible: bool
    planned_cloud_calls: int
    local_available_at_planning: bool

    def __post_init__(self) -> None:
        workers = tuple(assignment.worker for assignment in self.assignments)
        if len(set(workers)) != len(workers):
            raise ValueError("An ExecutionPlan may assign each worker only once")

        local_assignments = tuple(
            sorted(
                (
                    assignment
                    for assignment in self.assignments
                    if assignment.target is ExecutionTarget.LOCAL
                ),
                key=lambda assignment: assignment.local_order or 0,
            )
        )
        local_orders = tuple(
            assignment.local_order for assignment in local_assignments
        )
        if local_orders != tuple(range(1, len(local_assignments) + 1)):
            raise ValueError("Primary local assignments need contiguous unique orders")
        if self.local_execution_order != tuple(
            assignment.worker for assignment in local_assignments
        ):
            raise ValueError("local_execution_order must match primary local assignments")

        cloud_calls = sum(
            assignment.target in (ExecutionTarget.GROQ, ExecutionTarget.GEMINI)
            for assignment in self.assignments
        )
        if self.planned_cloud_calls != cloud_calls:
            raise ValueError("planned_cloud_calls must match cloud assignments")
        expected_parallelism = cloud_calls > 0 and len(self.assignments) > 1
        if self.cloud_parallelism_possible != expected_parallelism:
            raise ValueError("cloud_parallelism_possible does not match assignments")

    def assignment_for(self, worker: WorkerKind) -> WorkerAssignment:
        for assignment in self.assignments:
            if assignment.worker is worker:
                return assignment
        raise KeyError(worker)


class ExecutionPlanner:
    """Apply the fixed hybrid policy without executing or contacting providers."""

    def plan(
        self,
        capabilities: CapabilityRequest,
        availability: CloudAvailability,
    ) -> ExecutionPlan:
        workers = capabilities.requested_workers()
        if not workers:
            return ExecutionPlan(
                assignments=(),
                local_execution_order=(),
                cloud_parallelism_possible=False,
                planned_cloud_calls=0,
                local_available_at_planning=availability.local_available,
            )

        targets = self._primary_targets(workers, availability)
        primary_local_workers = tuple(
            worker for worker in workers if targets[worker] is ExecutionTarget.LOCAL
        )
        local_orders = {
            worker: index
            for index, worker in enumerate(primary_local_workers, start=1)
        }
        cloud_workers = tuple(
            worker for worker in workers if targets[worker] is not ExecutionTarget.LOCAL
        )
        fallback_orders = {
            worker: len(primary_local_workers) + index
            for index, worker in enumerate(cloud_workers, start=1)
        }

        assignments = tuple(
            self._assignment(
                worker,
                targets[worker],
                local_orders.get(worker),
                fallback_orders.get(worker),
                availability,
                len(workers),
            )
            for worker in workers
        )
        return ExecutionPlan(
            assignments=assignments,
            local_execution_order=primary_local_workers,
            cloud_parallelism_possible=bool(cloud_workers),
            planned_cloud_calls=len(cloud_workers),
            local_available_at_planning=availability.local_available,
        )

    create_plan = plan

    @staticmethod
    def _primary_targets(
        workers: tuple[WorkerKind, ...], availability: CloudAvailability
    ) -> dict[WorkerKind, ExecutionTarget]:
        targets = {worker: ExecutionTarget.LOCAL for worker in workers}
        if len(workers) == 1:
            return targets

        worker_set = set(workers)
        if worker_set == {WorkerKind.CODING, WorkerKind.REASONING}:
            if availability.groq_usable:
                targets[WorkerKind.REASONING] = ExecutionTarget.GROQ
        elif worker_set == {WorkerKind.CODING, WorkerKind.VISION}:
            if availability.gemini_usable:
                targets[WorkerKind.VISION] = ExecutionTarget.GEMINI
        elif worker_set == {WorkerKind.VISION, WorkerKind.REASONING}:
            if availability.groq_usable:
                targets[WorkerKind.REASONING] = ExecutionTarget.GROQ
        elif worker_set == set(_WORKER_PRIORITY):
            if availability.gemini_usable:
                targets[WorkerKind.VISION] = ExecutionTarget.GEMINI
            if availability.groq_usable:
                targets[WorkerKind.REASONING] = ExecutionTarget.GROQ
        return targets

    @staticmethod
    def _assignment(
        worker: WorkerKind,
        target: ExecutionTarget,
        local_order: int | None,
        fallback_order: int | None,
        availability: CloudAvailability,
        worker_count: int,
    ) -> WorkerAssignment:
        if target is ExecutionTarget.GROQ:
            return WorkerAssignment(
                worker=worker,
                target=target,
                local_order=None,
                reason="Groq is available with budget for parallel reasoning.",
                fallback_target=ExecutionTarget.LOCAL,
                fallback_local_order=fallback_order,
            )
        if target is ExecutionTarget.GEMINI:
            return WorkerAssignment(
                worker=worker,
                target=target,
                local_order=None,
                reason="Gemini is available with budget for parallel vision.",
                fallback_target=ExecutionTarget.LOCAL,
                fallback_local_order=fallback_order,
            )

        if worker_count == 1:
            reason = "Single specialist requests stay local by default."
        elif worker is WorkerKind.CODING:
            reason = "Coding has priority for the single local-heavy slot."
        elif worker is WorkerKind.VISION and worker_count == 2:
            reason = "Vision keeps the local slot when paired with reasoning."
        elif worker is WorkerKind.VISION:
            reason = "Gemini is unavailable or out of budget; vision is queued locally."
        else:
            reason = "Groq is unavailable or out of budget; reasoning is queued locally."

        if not availability.local_available:
            reason += " The local slot is busy, so this remains a queued local step."
        return WorkerAssignment(
            worker=worker,
            target=ExecutionTarget.LOCAL,
            local_order=local_order,
            reason=reason,
        )


__all__ = [
    "CapabilityRequest",
    "CloudAvailability",
    "ExecutionPlan",
    "ExecutionPlanner",
    "ExecutionTarget",
    "WorkerAssignment",
    "WorkerKind",
]