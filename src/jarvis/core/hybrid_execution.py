"""Bridge deterministic planning, generic execution, and explicit model routes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from jarvis.core.execution_executor import ExecutionExecutor, ExecutionResult, Handler
from jarvis.core.execution_planner import (
    CapabilityRequest,
    CloudAvailability,
    ExecutionPlan,
    ExecutionPlanner,
    ExecutionTarget,
    WorkerAssignment,
    WorkerKind,
)
from jarvis.core.model_router import ModelRouter


@dataclass(frozen=True)
class WorkerInput:
    """Input payload for one specialist; vision additionally requires image bytes."""

    prompt: str
    image_bytes: bytes | None = None


@dataclass(frozen=True)
class HybridExecutionResult:
    plan: ExecutionPlan
    execution: ExecutionResult


class HybridExecutionConfigurationError(ValueError):
    """Raised when requested inputs or a planner assignment are unsupported."""


class HybridExecution:
    """Connect the planner and executor without changing their policy boundaries."""

    def __init__(
        self,
        model_router: ModelRouter,
        planner: ExecutionPlanner | None = None,
    ) -> None:
        self._model_router = model_router
        self._planner = ExecutionPlanner() if planner is None else planner

    def execute(
        self,
        capabilities: CapabilityRequest,
        availability: CloudAvailability,
        worker_inputs: Mapping[WorkerKind, WorkerInput],
    ) -> HybridExecutionResult:
        self._validate_inputs(capabilities, worker_inputs)
        plan = self._planner.plan(capabilities, availability)
        local_handlers, cloud_handlers = self._build_handlers(plan, worker_inputs)
        execution = ExecutionExecutor(
            local_handlers=local_handlers,
            cloud_handlers=cloud_handlers,
        ).execute(plan)
        return HybridExecutionResult(plan=plan, execution=execution)

    @staticmethod
    def _validate_inputs(
        capabilities: CapabilityRequest,
        worker_inputs: Mapping[WorkerKind, WorkerInput],
    ) -> None:
        requested_workers = capabilities.requested_workers()
        expected = set(requested_workers)
        supplied = set(worker_inputs)
        missing = expected - supplied
        unexpected = supplied - expected
        if missing:
            names = ", ".join(worker.value for worker in sorted(missing, key=str))
            raise HybridExecutionConfigurationError(
                f"Missing WorkerInput for: {names}."
            )
        if unexpected:
            names = ", ".join(
                worker.value for worker in sorted(unexpected, key=str)
            )
            raise HybridExecutionConfigurationError(
                f"WorkerInput supplied for unrequested worker: {names}."
            )

        for worker in requested_workers:
            worker_input = worker_inputs[worker]
            if not isinstance(worker_input, WorkerInput):
                raise HybridExecutionConfigurationError(
                    f"WorkerInput required for {worker.value}."
                )
            if worker is WorkerKind.VISION and not worker_input.image_bytes:
                raise HybridExecutionConfigurationError(
                    "VISION requires non-empty image_bytes."
                )

    def _build_handlers(
        self,
        plan: ExecutionPlan,
        worker_inputs: Mapping[WorkerKind, WorkerInput],
    ) -> tuple[dict[WorkerKind, Handler], dict[ExecutionTarget, Handler]]:
        local_handlers = {
            assignment.worker: self._local_handler(
                assignment.worker,
                worker_inputs[assignment.worker],
            )
            for assignment in plan.assignments
        }
        cloud_handlers: dict[ExecutionTarget, Handler] = {}
        for assignment in plan.assignments:
            if assignment.target is ExecutionTarget.LOCAL:
                continue
            handler = self._cloud_handler(
                assignment,
                worker_inputs[assignment.worker],
            )
            existing = cloud_handlers.get(assignment.target)
            if existing is not None:
                raise HybridExecutionConfigurationError(
                    f"Multiple {assignment.target.value} worker assignments are unsupported."
                )
            cloud_handlers[assignment.target] = handler
        return local_handlers, cloud_handlers

    def _local_handler(self, worker: WorkerKind, worker_input: WorkerInput) -> Handler:
        if worker is WorkerKind.CODING:
            return lambda: self._model_router.run_local_coding(worker_input.prompt)
        if worker is WorkerKind.VISION:
            image_bytes = self._require_image_bytes(worker_input, "run_local_vision")
            return lambda: self._model_router.run_local_vision(
                worker_input.prompt,
                image_bytes,
            )
        if worker is WorkerKind.REASONING:
            return lambda: self._model_router.run_local_reasoning(worker_input.prompt)
        raise HybridExecutionConfigurationError(
            f"Unsupported local worker: {worker!r}."
        )

    def _cloud_handler(
        self,
        assignment: WorkerAssignment,
        worker_input: WorkerInput,
    ) -> Handler:
        if (
            assignment.worker is WorkerKind.REASONING
            and assignment.target is ExecutionTarget.GROQ
        ):
            return lambda: self._model_router.run_groq_reasoning(worker_input.prompt)
        if (
            assignment.worker is WorkerKind.VISION
            and assignment.target is ExecutionTarget.GEMINI
        ):
            image_bytes = self._require_image_bytes(worker_input, "run_gemini_vision")
            return lambda: self._model_router.run_gemini_vision(
                worker_input.prompt,
                image_bytes,
            )
        raise HybridExecutionConfigurationError(
            "Unsupported planned worker/target combination: "
            f"{assignment.worker.value}/{assignment.target.value}."
        )

    @staticmethod
    def _require_image_bytes(worker_input: WorkerInput, method_name: str) -> bytes:
        if not worker_input.image_bytes:
            raise HybridExecutionConfigurationError(
                f"{method_name} requires non-empty image_bytes."
            )
        return worker_input.image_bytes


__all__ = [
    "HybridExecution",
    "HybridExecutionConfigurationError",
    "HybridExecutionResult",
    "WorkerInput",
]