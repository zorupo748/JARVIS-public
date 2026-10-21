"""Multi-model step-by-step orchestrator package for JARVIS.

Coordinates complex user task decomposition into plans and guarantees strict
local GPU VRAM bounds alongside cloud Groq fallbacks.
"""

from jarvis.core.orchestrator.plan_executor import (
    MAX_CONCURRENT_LOCAL_MODELS,
    PlanExecutionResult,
    PlanExecutor,
    ROLE_TO_LOCAL_MODEL,
    StepExecutionResult,
)
from jarvis.core.orchestrator.task_plan import (
    PlanStatus,
    PlanValidationError,
    StepStatus,
    TaskPlan,
    TaskStep,
    create_sequential_plan,
    create_task_plan,
    es_peticion_compuesta,
    generar_plan_dinamico,
)

__all__ = [
    "MAX_CONCURRENT_LOCAL_MODELS",
    "PlanExecutionResult",
    "PlanExecutor",
    "PlanStatus",
    "PlanValidationError",
    "ROLE_TO_LOCAL_MODEL",
    "StepExecutionResult",
    "StepStatus",
    "TaskPlan",
    "TaskStep",
    "create_sequential_plan",
    "create_task_plan",
    "es_peticion_compuesta",
    "generar_plan_dinamico",
]
