"""Structured task planning and dependency decomposition for JARVIS multi-model orchestrator.

Defines the data structures and validation logic for complex multi-step plans,
supporting sequential tasks and directed acyclic graph (DAG) dependency workflows.
"""

from __future__ import annotations

import collections
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from jarvis.core.model_router import ModelRole


class StepStatus(str, Enum):
    """Lifecycle states of an individual task step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PlanStatus(str, Enum):
    """Lifecycle states of the complete task plan."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class PlanValidationError(ValueError):
    """Raised when a task plan has invalid structure, missing dependencies, or cycles."""


@dataclass
class TaskStep:
    """An individual execution unit within a TaskPlan.

    Attributes:
        step_id: Unique string identifier for the step within the plan.
        description: Human-readable specification of what this step achieves.
        required_role: Specialist AI role (e.g. ModelRole.DEEP_REASONING, ModelRole.CODING, ModelRole.VISION).
        tools_allowed: Whitelist of tool identifiers the step is authorized to invoke.
        expected_output: Criteria or pattern expected in the resulting output.
        dependencies: Step IDs that must successfully complete before this step is eligible.
        status: Current lifecycle state.
        result: Intermediate or final output produced by this step.
        error: Descriptive error message if execution failed.
        metadata: Arbitrary contextual parameters, inputs, or hints for execution.
    """

    step_id: str
    description: str
    required_role: ModelRole
    tools_allowed: list[str] = field(default_factory=list)
    expected_output: str = ""
    dependencies: list[str] = field(default_factory=list)
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.step_id or not isinstance(self.step_id, str):
            raise PlanValidationError("TaskStep.step_id must be a non-empty string.")
        if not self.description or not isinstance(self.description, str):
            raise PlanValidationError("TaskStep.description must be a non-empty string.")
        if not isinstance(self.required_role, ModelRole):
            raise PlanValidationError(
                f"TaskStep.required_role must be a ModelRole, got {type(self.required_role).__name__}."
            )
        self.step_id = self.step_id.strip()
        self.dependencies = [dep.strip() for dep in self.dependencies if dep and dep.strip()]
        self.tools_allowed = [tool.strip() for tool in self.tools_allowed if tool and tool.strip()]

    def is_ready(self, completed_step_ids: set[str]) -> bool:
        """Return True if step is pending and all its dependencies have completed."""
        if self.status != StepStatus.PENDING:
            return False
        return all(dep in completed_step_ids for dep in self.dependencies)

    def mark_running(self) -> None:
        """Mark step as currently executing."""
        self.status = StepStatus.RUNNING

    def mark_completed(self, result: Any) -> None:
        """Mark step as successfully completed with its computed result."""
        self.status = StepStatus.COMPLETED
        self.result = result
        self.error = None

    def mark_failed(self, error: str) -> None:
        """Mark step as failed with an error explanation."""
        self.status = StepStatus.FAILED
        self.error = str(error)

    def mark_skipped(self, reason: str | None = None) -> None:
        """Mark step as skipped (e.g. because an ancestor failed)."""
        self.status = StepStatus.SKIPPED
        if reason:
            self.error = reason

    def to_dict(self) -> dict[str, Any]:
        """Convert step into a serializable dictionary."""
        return {
            "step_id": self.step_id,
            "description": self.description,
            "required_role": self.required_role.value,
            "tools_allowed": list(self.tools_allowed),
            "expected_output": self.expected_output,
            "dependencies": list(self.dependencies),
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TaskStep:
        """Construct a TaskStep from serialized dictionary data."""
        role_val = data.get("required_role", ModelRole.DEEP_REASONING.value)
        if isinstance(role_val, ModelRole):
            role = role_val
        else:
            role = ModelRole(str(role_val))

        status_val = data.get("status", StepStatus.PENDING.value)
        status = StepStatus(str(status_val)) if isinstance(status_val, str) else status_val

        return cls(
            step_id=str(data["step_id"]),
            description=str(data["description"]),
            required_role=role,
            tools_allowed=list(data.get("tools_allowed", [])),
            expected_output=str(data.get("expected_output", "")),
            dependencies=list(data.get("dependencies", [])),
            status=status,
            result=data.get("result"),
            error=data.get("error"),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class TaskPlan:
    """Orchestration plan decomposing a user goal into ordered, dependent steps.

    Attributes:
        plan_id: Unique identifier for this task plan.
        user_request: Original user directive or query.
        steps: List of TaskStep instances forming the execution graph.
        status: Overall plan execution state.
        metadata: Extra plan-level parameters or telemetry.
    """

    plan_id: str
    user_request: str
    steps: list[TaskStep] = field(default_factory=list)
    status: PlanStatus = PlanStatus.NOT_STARTED
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.plan_id or not isinstance(self.plan_id, str):
            raise PlanValidationError("TaskPlan.plan_id must be a non-empty string.")
        if not self.user_request or not isinstance(self.user_request, str):
            raise PlanValidationError("TaskPlan.user_request must be a non-empty string.")
        self.plan_id = self.plan_id.strip()
        self.validate()

    def validate(self) -> None:
        """Verify step ID uniqueness, dependency references, and acyclic topology.

        Raises:
            PlanValidationError: If duplicates, missing dependencies, or cycles exist.
        """
        seen_ids: set[str] = set()
        for step in self.steps:
            if step.step_id in seen_ids:
                raise PlanValidationError(
                    f"Duplicate step_id detected in plan '{self.plan_id}': '{step.step_id}'."
                )
            seen_ids.add(step.step_id)

        # Check missing dependency references
        for step in self.steps:
            for dep in step.dependencies:
                if dep not in seen_ids:
                    raise PlanValidationError(
                        f"Step '{step.step_id}' depends on non-existent step '{dep}'."
                    )
                if dep == step.step_id:
                    raise PlanValidationError(
                        f"Step '{step.step_id}' cannot depend on itself (self-cycle)."
                    )

        # Check for circular dependencies via Kahn's algorithm (topological sort check)
        self.execution_order()

    def add_step(self, step: TaskStep) -> None:
        """Add a step to the plan and revalidate consistency."""
        self.steps.append(step)
        self.validate()

    def get_step(self, step_id: str) -> TaskStep:
        """Retrieve a step by its identifier.

        Raises:
            KeyError: If the step_id does not exist in this plan.
        """
        for step in self.steps:
            if step.step_id == step_id:
                return step
        raise KeyError(f"Step '{step_id}' not found in plan '{self.plan_id}'.")

    def get_ready_steps(self) -> list[TaskStep]:
        """Return all pending steps whose dependencies are fully completed."""
        completed_ids = {s.step_id for s in self.steps if s.status == StepStatus.COMPLETED}
        return [step for step in self.steps if step.is_ready(completed_ids)]

    def execution_order(self) -> list[TaskStep]:
        """Return a topologically sorted list of steps satisfying all dependencies.

        Raises:
            PlanValidationError: If a dependency cycle is present.
        """
        step_map = {s.step_id: s for s in self.steps}
        in_degree: dict[str, int] = {s.step_id: len(s.dependencies) for s in self.steps}
        dependents: dict[str, list[str]] = collections.defaultdict(list)

        for step in self.steps:
            for dep in step.dependencies:
                dependents[dep].append(step.step_id)

        queue = collections.deque([sid for sid, deg in in_degree.items() if deg == 0])
        ordered_steps: list[TaskStep] = []

        while queue:
            current_id = queue.popleft()
            ordered_steps.append(step_map[current_id])
            for dep_id in dependents[current_id]:
                in_degree[dep_id] -= 1
                if in_degree[dep_id] == 0:
                    queue.append(dep_id)

        if len(ordered_steps) != len(self.steps):
            unresolved = [sid for sid, deg in in_degree.items() if deg > 0]
            raise PlanValidationError(
                f"Circular dependency detected in plan '{self.plan_id}' involving steps: {unresolved}."
            )

        return ordered_steps

    def is_completed(self) -> bool:
        """Return True if all steps are completed."""
        return bool(self.steps) and all(s.status == StepStatus.COMPLETED for s in self.steps)

    def has_failed(self) -> bool:
        """Return True if any step in the plan has failed."""
        return any(s.status == StepStatus.FAILED for s in self.steps)

    def completed_steps(self) -> list[TaskStep]:
        """Return all completed steps."""
        return [s for s in self.steps if s.status == StepStatus.COMPLETED]

    def failed_steps(self) -> list[TaskStep]:
        """Return all failed steps."""
        return [s for s in self.steps if s.status == StepStatus.FAILED]

    def to_dict(self) -> dict[str, Any]:
        """Serialize plan and all steps to a dictionary."""
        return {
            "plan_id": self.plan_id,
            "user_request": self.user_request,
            "status": self.status.value,
            "steps": [s.to_dict() for s in self.steps],
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TaskPlan:
        """Deserialize a TaskPlan from dictionary data."""
        steps = [TaskStep.from_dict(s_data) for s_data in data.get("steps", [])]
        status_val = data.get("status", PlanStatus.NOT_STARTED.value)
        status = PlanStatus(str(status_val)) if isinstance(status_val, str) else status_val

        return cls(
            plan_id=str(data["plan_id"]),
            user_request=str(data["user_request"]),
            steps=steps,
            status=status,
            metadata=dict(data.get("metadata", {})),
        )


def create_task_plan(
    plan_id: str,
    user_request: str,
    steps: Sequence[TaskStep],
    metadata: Mapping[str, Any] | None = None,
) -> TaskPlan:
    """Convenience factory to construct and validate a TaskPlan."""
    return TaskPlan(
        plan_id=plan_id,
        user_request=user_request,
        steps=list(steps),
        metadata=dict(metadata or {}),
    )


def create_sequential_plan(
    plan_id: str,
    user_request: str,
    steps: Sequence[TaskStep],
    metadata: Mapping[str, Any] | None = None,
) -> TaskPlan:
    """Construct a linear sequential plan where step[i] automatically depends on step[i-1]."""
    steps_list = list(steps)
    for i in range(1, len(steps_list)):
        if not steps_list[i].dependencies:
            steps_list[i].dependencies = [steps_list[i - 1].step_id]

    return TaskPlan(
        plan_id=plan_id,
        user_request=user_request,
        steps=steps_list,
        metadata=dict(metadata or {}),
    )


def es_peticion_compuesta(texto: str) -> bool:
    """Detecta si una petición requiere descomposición, planificación u orquestación multi-paso."""
    if not texto or not isinstance(texto, str):
        return False

    t = texto.lower().strip()

    # Comandos explícitos de orquestación / descomposición
    palabras_clave_orquestador = (
        "paso a paso",
        "en pasos",
        "planifica",
        "planificar",
        "orquesta",
        "orquestar",
        "desglosa",
        "desglosar",
        "plan de acción",
        "plan de accion",
        "divide en pasos",
        "por etapas",
    )
    if any(k in t for k in palabras_clave_orquestador):
        return True

    # Peticiones compuestas con conectores secuenciales o multi-fase
    patrones_compuestos = (
        r"\b(?:primero|1º)\b.+?\b(?:luego|despu[eé]s|finalmente)\b",
        r"\b(?:busca|investiga)\b.+?\by\s+(?:analiza|resume|genera|programa|crea|diseña|formatea)\b",
        r"\b(?:analiza|eval[uú]a)\b.+?\by\s+(?:genera|programa|implementa|redacta|formatea)\b",
        r"\b(?:recopila|revisa)\b.+?\by\s+(?:analiza|resume|extrae|compara)\b",
    )
    for patron in patrones_compuestos:
        if re.search(patron, t, re.IGNORECASE):
            return True

    return False


def generar_plan_dinamico(
    user_request: str,
    available_tools: Sequence[str] | None = None,
) -> TaskPlan:
    """Genera un TaskPlan dinámico adaptado a los objetivos de la petición.

    Descompone peticiones compuestas en etapas coordinadas:
    1. Recopilación / Búsqueda web (si la tarea requiere información externa o búsqueda)
    2. Análisis técnico / Razonamiento profundo / Programación
    3. Síntesis final estructurada y formateada para voz y pantalla
    """
    req_lower = user_request.lower()
    plan_id = f"plan_{int(time.time() * 1000)}"
    steps: list[TaskStep] = []

    tools = list(available_tools or [])

    search_keywords = (
        "busca", "buscar", "investiga", "investigar", "noticia", "noticias",
        "precio", "precios", "resultado", "resultados", "en internet", "por internet",
        "en la web", "por la web", "consulta la red", "recopila informacion",
        "recopila información", "tiempo real",
    )
    needs_search = any(kw in req_lower for kw in search_keywords)

    coding_keywords = (
        "escribe codigo", "escribe código", "genera codigo", "genera código",
        "crea un script", "crea una función", "crea una funcion", "programa un",
        "programar un", "desarrolla", "desarrollar", "implementa", "implementar",
        "algoritmo", "escribir codigo", "escribir código", "script en", "código python",
        "codigo python",
    )
    needs_coding = any(kw in req_lower for kw in coding_keywords)

    if needs_search:
        step_search_tools = ["buscar_en_internet"] if "buscar_en_internet" in tools else []
        steps.append(
            TaskStep(
                step_id="step_recopilacion",
                description=f"Buscar y recopilar datos relevantes sobre: {user_request}",
                required_role=ModelRole.SPEECH,
                tools_allowed=step_search_tools,
                metadata=(
                    {"tool_name": "buscar_en_internet", "tool_args": {"query": user_request}}
                    if step_search_tools
                    else {}
                ),
            )
        )

        if needs_coding:
            steps.append(
                TaskStep(
                    step_id="step_analisis_tecnico",
                    description=f"Analizar los requerimientos técnicos para: {user_request}",
                    required_role=ModelRole.DEEP_REASONING,
                    dependencies=["step_recopilacion"],
                )
            )
            steps.append(
                TaskStep(
                    step_id="step_implementacion",
                    description=f"Implementar el código y la solución técnica para: {user_request}",
                    required_role=ModelRole.CODING,
                    dependencies=["step_analisis_tecnico"],
                )
            )
        else:
            steps.append(
                TaskStep(
                    step_id="step_analisis_profundo",
                    description=f"Analizar críticamente la información y sintetizar hallazgos para: {user_request}",
                    required_role=ModelRole.DEEP_REASONING,
                    dependencies=["step_recopilacion"],
                )
            )

        steps.append(
            TaskStep(
                step_id="step_sintesis_final",
                description="Sintetizar la respuesta final concisa y estructurada para el usuario",
                required_role=ModelRole.SPEECH,
                dependencies=[steps[-1].step_id],
            )
        )

    elif needs_coding:
        steps.append(
            TaskStep(
                step_id="step_diseno_arquitectura",
                description=f"Diseñar la arquitectura técnica y algoritmos para: {user_request}",
                required_role=ModelRole.DEEP_REASONING,
            )
        )
        steps.append(
            TaskStep(
                step_id="step_programacion",
                description=f"Escribir el código y componentes para: {user_request}",
                required_role=ModelRole.CODING,
                dependencies=["step_diseno_arquitectura"],
            )
        )
        steps.append(
            TaskStep(
                step_id="step_sintesis_explicacion",
                description="Explicar el código y formatear la entrega técnica para el usuario",
                required_role=ModelRole.SPEECH,
                dependencies=["step_programacion"],
            )
        )

    else:
        steps.append(
            TaskStep(
                step_id="step_descomposicion",
                description=f"Descomponer y analizar los factores clave para: {user_request}",
                required_role=ModelRole.DEEP_REASONING,
            )
        )
        steps.append(
            TaskStep(
                step_id="step_evaluacion",
                description="Evaluar alternativas, implicaciones y soluciones",
                required_role=ModelRole.DEEP_REASONING,
                dependencies=["step_descomposicion"],
            )
        )
        steps.append(
            TaskStep(
                step_id="step_sintesis_ejecutiva",
                description="Generar la conclusión y respuesta final clara y directa para el usuario",
                required_role=ModelRole.SPEECH,
                dependencies=["step_evaluacion"],
            )
        )

    return create_task_plan(
        plan_id=plan_id,
        user_request=user_request,
        steps=steps,
        metadata={"generated_dynamically": True},
    )


__all__ = [
    "PlanStatus",
    "PlanValidationError",
    "StepStatus",
    "TaskPlan",
    "TaskStep",
    "create_sequential_plan",
    "create_task_plan",
    "es_peticion_compuesta",
    "generar_plan_dinamico",
]
