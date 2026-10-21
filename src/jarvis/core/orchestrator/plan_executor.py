"""Step-by-step multi-model plan executor with strict hardware VRAM constraints.

Orchestrates sequential or DAG execution of TaskPlan steps, guaranteeing:
1. Max 2 active local heavy models in VRAM at any time.
2. LRU (Least Recently Used) automatic model eviction when capacity is reached.
3. Transparent fallback to Groq cloud API when VRAM is constrained or agile execution is preferred.
4. Intermediate step output validation against expected criteria.
5. Structured architectural error triage via SkillErrorHandler upon failure.
"""

from __future__ import annotations

import collections
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from jarvis.core.model_router import (
    MODEL_CODING_LOCAL,
    MODEL_ORCHESTRATOR_LOCAL,
    MODEL_REASONING_LOCAL,
    MODEL_VISION_LOCAL,
    ModelRole,
    ModelRouter,
)
from jarvis.core.orchestrator.task_plan import PlanStatus, StepStatus, TaskPlan, TaskStep
from jarvis.core.vram_manager import VramManager
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

# Default maximum number of heavy local models allowed resident in VRAM simultaneously
MAX_CONCURRENT_LOCAL_MODELS = 2

# Canonical mapping from architectural roles to Ollama model identifiers
ROLE_TO_LOCAL_MODEL: Mapping[ModelRole, str] = {
    ModelRole.SPEECH: MODEL_ORCHESTRATOR_LOCAL,
    ModelRole.CODING: MODEL_CODING_LOCAL,
    ModelRole.VISION: MODEL_VISION_LOCAL,
    ModelRole.DEEP_REASONING: MODEL_REASONING_LOCAL,
}


@dataclass
class StepExecutionResult:
    """Outcome and telemetry of a single step execution.

    Attributes:
        step_id: Identifier of the executed step.
        status: Final StepStatus.
        output: Resulting data or response content.
        error: Error message if execution or validation failed.
        model_used: Identifier of the local model or cloud provider utilized.
        used_groq: True if executed via Groq cloud instead of local VRAM.
        retries: Number of repair or retry attempts made.
        triage_summary: Executive summary produced by SkillErrorHandler if an error was triaged.
        elapsed_seconds: Total duration of step execution in seconds.
    """

    step_id: str
    status: StepStatus
    output: Any = None
    error: str | None = None
    model_used: str | None = None
    used_groq: bool = False
    retries: int = 0
    triage_summary: str | None = None
    elapsed_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return self.status == StepStatus.COMPLETED


@dataclass
class PlanExecutionResult:
    """Summary of complete plan execution."""

    plan_id: str
    status: PlanStatus
    step_results: dict[str, StepExecutionResult] = field(default_factory=dict)
    active_local_models: list[str] = field(default_factory=list)
    groq_fallbacks_used: int = 0
    total_elapsed_seconds: float = 0.0
    summary: str = ""

    @property
    def success(self) -> bool:
        return self.status == PlanStatus.COMPLETED


class PlanExecutor:
    """Executes a TaskPlan step-by-step under strict VRAM capacity limits."""

    def __init__(
        self,
        plan: TaskPlan,
        router: ModelRouter | Any,
        vram_manager: VramManager | None = None,
        error_handler: Any | None = None,
        tool_registry: Any | None = None,
        max_local_models: int = MAX_CONCURRENT_LOCAL_MODELS,
        prefer_groq_on_vram_limit: bool = False,
        max_retries_per_step: int = 2,
        cancel_token: Optional[Any] = None,
    ) -> None:
        """Initialize the plan executor.

        Args:
            plan: The TaskPlan to orchestrate.
            router: ModelRouter instance for dispatching prompts and managing Ollama/Groq.
            vram_manager: VramManager instance. If None, derived from router or instantiated.
            error_handler: Optional SkillErrorHandler for triage and executive summary creation.
            tool_registry: Optional ToolRegistry or adapter for tool dispatch. Defaults to ToolRegistry.
            max_local_models: Maximum concurrent local models allowed in VRAM (default: 2).
            prefer_groq_on_vram_limit: If True, immediately routes to Groq when VRAM has 2 models,
                rather than unleading the oldest model.
            max_retries_per_step: Maximum self-repair retry attempts per step if triaged as repairable.
            cancel_token: Optional threading.Event or object with is_set() for cooperative cancellation.
        """
        self.plan = plan
        self.router = router
        self.vram_manager = (
            vram_manager
            if vram_manager is not None
            else getattr(router, "vram_manager", None) or VramManager()
        )
        self.error_handler = error_handler
        self.tool_registry = tool_registry or ToolRegistry
        self.max_local_models = max(1, max_local_models)
        self.prefer_groq_on_vram_limit = prefer_groq_on_vram_limit
        self.max_retries_per_step = max_retries_per_step
        self._cancel_token = cancel_token
        self._cancelled = False

        # LRU tracker of active local models: model_id -> last_access_timestamp
        self._active_local_models: collections.OrderedDict[str, float] = collections.OrderedDict()
        self._groq_fallbacks_count = 0

    def cancel(self) -> None:
        """Solicita la cancelación inmediata y cooperativa de la ejecución del plan."""
        self._cancelled = True
        if self._cancel_token is not None and hasattr(self._cancel_token, "set"):
            self._cancel_token.set()

    @property
    def is_cancelled(self) -> bool:
        """Indica si el plan ha recibido una solicitud de interrupción o cancelación."""
        if self._cancelled:
            return True
        if self._cancel_token is not None:
            if hasattr(self._cancel_token, "is_set") and self._cancel_token.is_set():
                return True
        return False

    @property
    def active_local_models(self) -> list[str]:
        """Return the list of model IDs currently considered active in VRAM."""
        return list(self._active_local_models.keys())

    def _unload_local_model(self, model_id: str) -> bool:
        """Request the router or Ollama to unload a resident model to free VRAM."""
        logger.info("Unloading local model '%s' from VRAM to preserve budget...", model_id)
        unloaded = False
        if hasattr(self.router, "_unload_ollama_model"):
            try:
                unloaded = bool(self.router._unload_ollama_model(model_id))
            except Exception as exc:
                logger.warning("Failed to unload model '%s' via router: %s", model_id, exc)

        if hasattr(self.vram_manager, "clear_resident_model"):
            try:
                self.vram_manager.clear_resident_model(model_id)
            except Exception:
                pass

        if model_id in self._active_local_models:
            self._active_local_models.pop(model_id, None)

        return unloaded

    def ensure_vram_capacity(
        self,
        target_model: str,
        force_groq: bool = False,
    ) -> tuple[bool, str]:
        """Ensure VRAM constraint (<= max_local_models) before loading target_model.

        Returns:
            Tuple of (use_groq: bool, resolved_model: str).
            If use_groq is True, the caller should dispatch to Groq cloud API.
        """
        # If cloud execution is explicitly requested or target is already Groq
        if force_groq or target_model.lower().startswith("groq") or getattr(self.router, "gaming_mode", None) is True:
            self._groq_fallbacks_count += 1
            return True, "groq"

        # If model is already active, refresh LRU access order
        if target_model in self._active_local_models:
            self._active_local_models.move_to_end(target_model)
            self._active_local_models[target_model] = time.monotonic()
            if hasattr(self.vram_manager, "mark_model_resident"):
                try:
                    self.vram_manager.mark_model_resident(target_model)
                except Exception:
                    pass
            return False, target_model

        # If we have reached the maximum local capacity (e.g. 2 models)
        if len(self._active_local_models) >= self.max_local_models:
            # Policy 1: Prefer Groq for agility without unload latency
            if self.prefer_groq_on_vram_limit and getattr(self.router, "groq_api_key", None):
                logger.info(
                    "VRAM limit reached (%d models active: %s). Rerouting to Groq for agility.",
                    self.max_local_models,
                    list(self._active_local_models.keys()),
                )
                self._groq_fallbacks_count += 1
                return True, "groq"

            # Policy 2: Evict the least recently used (LRU) local model
            oldest_model, _ = next(iter(self._active_local_models.items()))
            logger.info(
                "VRAM limit reached (%d models active: %s). Evicting LRU model '%s' for '%s'.",
                self.max_local_models,
                list(self._active_local_models.keys()),
                oldest_model,
                target_model,
            )
            success = self._unload_local_model(oldest_model)

            # If unloading failed and Groq is available, fallback to Groq
            if not success and getattr(self.router, "groq_api_key", None):
                logger.warning(
                    "Eviction of '%s' was inconclusive; diverting step to Groq.", oldest_model
                )
                self._groq_fallbacks_count += 1
                return True, "groq"

        # Register the new model in the active LRU cache
        self._active_local_models[target_model] = time.monotonic()
        if hasattr(self.vram_manager, "mark_model_resident"):
            try:
                self.vram_manager.mark_model_resident(target_model)
            except Exception:
                pass

        return False, target_model

    def validate_step_output(self, step: TaskStep, output: Any) -> tuple[bool, str]:
        """Verify intermediate output satisfies the step's expected_output contract.

        Returns:
            Tuple of (is_valid: bool, feedback: str).
        """
        if output is None:
            return False, "La salida del paso es nula (None)."

        # Check for tool failure payloads
        if hasattr(output, "success") and not getattr(output, "success"):
            error_content = getattr(output, "content", "Fallo en ejecución de herramienta.")
            return False, f"La herramienta reportó un fallo: {error_content}"

        output_str = str(getattr(output, "content", output)).strip()
        if not output_str:
            return False, "La salida generada está vacía."

        expected = step.expected_output.strip()
        if not expected:
            return True, "Salida conforme (sin contrato específico)."

        expected_lower = expected.lower()

        # Check JSON format contract
        if "json" in expected_lower:
            match = re.search(r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```", output_str, re.DOTALL)
            candidate = match.group(1) if match else output_str
            try:
                json.loads(candidate)
            except Exception:
                start = min((pos for pos in (candidate.find("{"), candidate.find("[")) if pos != -1), default=-1)
                if start == -1:
                    return False, f"El paso requería formato JSON, pero no se encontró un objeto o lista JSON válido."
                try:
                    json.loads(candidate[start:])
                except Exception as exc:
                    return False, f"JSON mal formado en la salida del paso: {exc}"

        # Check code block requirement
        if "código" in expected_lower or "codigo" in expected_lower or "python" in expected_lower:
            if "```" not in output_str and "def " not in output_str and "class " not in output_str:
                return False, "El paso requería código generado, pero no se detectaron bloques de código."

        # Check keyword or substring matching
        match_keywords = step.metadata.get("expected_keywords")
        if match_keywords and isinstance(match_keywords, (list, tuple)):
            for kw in match_keywords:
                if str(kw).lower() not in output_str.lower():
                    return False, f"La salida no contiene el elemento requerido: '{kw}'."

        return True, "Salida validada correctamente."

    def _execute_tool_action(self, step: TaskStep) -> Any:
        """Dispatch an authorized tool invocation configured in step metadata."""
        tool_name = step.metadata.get("tool_name")
        if not tool_name:
            raise ValueError(f"Step '{step.step_id}' metadata lacks 'tool_name'.")

        if tool_name not in step.tools_allowed:
            raise PermissionError(
                f"Tool '{tool_name}' is forbidden for step '{step.step_id}'. "
                f"Authorized tools: {step.tools_allowed}"
            )

        tool_args = step.metadata.get("tool_args", {})
        logger.info("Executing authorized tool '%s' for step '%s'...", tool_name, step.step_id)

        if hasattr(self.tool_registry, "execute"):
            return self.tool_registry.execute(tool_name, **tool_args)
        elif callable(self.tool_registry):
            return self.tool_registry(tool_name, **tool_args)
        raise RuntimeError(f"Tool registry '{self.tool_registry}' does not support execution.")

    def _execute_inference_action(
        self,
        step: TaskStep,
        prompt: str,
        use_groq: bool,
    ) -> str:
        """Call either Groq cloud or the appropriate local specialist model."""
        if use_groq:
            logger.info("Dispatching step '%s' to Groq Cloud reasoning...", step.step_id)
            if hasattr(self.router, "run_groq_reasoning"):
                return self.router.run_groq_reasoning(prompt)
            elif hasattr(self.router, "_call_groq"):
                return self.router._call_groq(prompt)
            raise RuntimeError("ModelRouter lacks Groq execution capability.")

        logger.info(
            "Dispatching step '%s' to local role '%s'...", step.step_id, step.required_role.value
        )
        image_bytes = step.metadata.get("image_bytes")
        if step.required_role == ModelRole.VISION and not image_bytes:
            image_bytes = b"placeholder_image_bytes"

        if hasattr(self.router, "route"):
            return self.router.route(step.required_role, prompt, image_bytes=image_bytes)

        raise RuntimeError(f"Router '{self.router}' does not support the route() protocol.")

    def execute_step(self, step_id: str) -> StepExecutionResult:
        """Execute a single step, ensuring prerequisites, VRAM limits, and validation."""
        start_time = time.monotonic()
        step = self.plan.get_step(step_id)

        # 0. Verificación de cancelación previa
        if self.is_cancelled:
            msg = f"Paso '{step_id}' no ejecutado: plan cancelado por el usuario."
            step.mark_skipped(msg)
            return StepExecutionResult(
                step_id=step_id,
                status=StepStatus.SKIPPED,
                error=msg,
                elapsed_seconds=time.monotonic() - start_time,
            )

        # 1. Prerequisite verification
        completed_ids = {s.step_id for s in self.plan.steps if s.status == StepStatus.COMPLETED}
        if not step.is_ready(completed_ids):
            unmet = [dep for dep in step.dependencies if dep not in completed_ids]
            msg = f"Prerequisites not met for step '{step_id}'. Unmet dependencies: {unmet}"
            step.mark_skipped(msg)
            return StepExecutionResult(
                step_id=step_id,
                status=StepStatus.SKIPPED,
                error=msg,
                elapsed_seconds=time.monotonic() - start_time,
            )

        step.mark_running()

        # Build prompt or context
        dep_results = {dep: self.plan.get_step(dep).result for dep in step.dependencies}
        step_prompt = step.metadata.get("prompt")
        if not step_prompt:
            context_summary = "\n".join(
                f"- Resultado de '{dep}': {res}" for dep, res in dep_results.items()
            )
            step_prompt = (
                f"Objetivo general del usuario: {self.plan.user_request}\n"
                f"Paso a resolver: {step.description}\n"
                f"Contexto previo:\n{context_summary or '(Inicio de tarea)'}\n"
                f"Salida esperada: {step.expected_output or 'Respuesta coherente y precisa'}"
            )

        retries = 0
        last_error = ""
        triage_summary = None

        while retries <= self.max_retries_per_step:
            if self.is_cancelled:
                last_error = "Cancelado por el usuario durante la ejecución del paso."
                break

            try:
                # 2. VRAM capacity reservation
                target_local_model = ROLE_TO_LOCAL_MODEL.get(step.required_role, MODEL_ORCHESTRATOR_LOCAL)
                force_groq = step.metadata.get("force_groq", False)
                use_groq, model_used = self.ensure_vram_capacity(
                    target_local_model, force_groq=force_groq
                )

                # 3. Action dispatch: Tool or Model Inference
                if "tool_name" in step.metadata:
                    raw_output = self._execute_tool_action(step)
                else:
                    raw_output = self._execute_inference_action(step, step_prompt, use_groq)

                # 4. Output validation
                valid, val_msg = self.validate_step_output(step, raw_output)
                if not valid:
                    raise ValueError(f"Fallo de validación de salida: {val_msg}")

                # Success!
                step.mark_completed(raw_output)
                elapsed = time.monotonic() - start_time
                return StepExecutionResult(
                    step_id=step_id,
                    status=StepStatus.COMPLETED,
                    output=raw_output,
                    model_used=model_used,
                    used_groq=use_groq,
                    retries=retries,
                    elapsed_seconds=elapsed,
                )

            except Exception as exc:
                last_error = str(exc)
                logger.warning(
                    "Error executing step '%s' (attempt %d/%d): %s",
                    step_id,
                    retries + 1,
                    self.max_retries_per_step + 1,
                    exc,
                )

                # 5. Error Triage via SkillErrorHandler if available
                if self.error_handler is not None and hasattr(self.error_handler, "triage"):
                    try:
                        triage_decision = self.error_handler.triage(
                            error=exc,
                            phase=f"paso_{step_id}",
                            user_request=self.plan.user_request,
                            skill_name=step_id,
                        )
                        triage_summary = triage_decision.executive_summary
                        if triage_decision.can_repair and retries < self.max_retries_per_step:
                            retries += 1
                            step_prompt = (
                                f"{step_prompt}\n\n[REINTENTO AUTO-REPARACIÓN #{retries}]: "
                                f"El intento anterior falló con: {last_error}. "
                                f"Estrategia sugerida: {triage_decision.repair_strategy}. Corrige el fallo."
                            )
                            continue
                    except Exception as triage_exc:
                        logger.error("SkillErrorHandler triage invocation failed: %s", triage_exc)

                # If repair is not possible or retries exhausted, break out
                break

        # Step failure or cancellation
        if self.is_cancelled:
            step.mark_skipped("Cancelado a petición del usuario.")
            status = StepStatus.SKIPPED
        else:
            step.mark_failed(last_error)
            status = StepStatus.FAILED

        elapsed = time.monotonic() - start_time
        return StepExecutionResult(
            step_id=step_id,
            status=status,
            error=last_error,
            retries=retries,
            triage_summary=triage_summary,
            elapsed_seconds=elapsed,
        )

    def execute_plan(self) -> PlanExecutionResult:
        """Run the complete plan sequentially or topologically respecting dependencies."""
        start_plan_time = time.monotonic()
        self.plan.status = PlanStatus.IN_PROGRESS
        results: dict[str, StepExecutionResult] = {}

        try:
            topo_order = self.plan.execution_order()
        except Exception as exc:
            self.plan.status = PlanStatus.FAILED
            return PlanExecutionResult(
                plan_id=self.plan.plan_id,
                status=PlanStatus.FAILED,
                summary=f"Invalid plan topology: {exc}",
                total_elapsed_seconds=time.monotonic() - start_plan_time,
            )

        for step in topo_order:
            if self.is_cancelled or self.plan.status in (PlanStatus.FAILED, PlanStatus.ABORTED):
                if self.is_cancelled:
                    self.plan.status = PlanStatus.ABORTED
                skip_msg = "Plan cancelado a petición del usuario." if self.is_cancelled else "Aborted due to prior step failure."
                step.mark_skipped(skip_msg)
                results[step.step_id] = StepExecutionResult(
                    step_id=step.step_id,
                    status=StepStatus.SKIPPED,
                    error=skip_msg,
                )
                continue

            step_res = self.execute_step(step.step_id)
            results[step.step_id] = step_res

            if self.is_cancelled:
                self.plan.status = PlanStatus.ABORTED
                continue

            if not step_res.success:
                logger.error("Step '%s' failed. Aborting remaining dependent plan steps.", step.step_id)
                self.plan.status = PlanStatus.FAILED

        if self.is_cancelled or self.plan.status == PlanStatus.ABORTED:
            self.plan.status = PlanStatus.ABORTED
        elif self.plan.status != PlanStatus.FAILED:
            self.plan.status = PlanStatus.COMPLETED

        total_elapsed = time.monotonic() - start_plan_time
        if self.plan.status == PlanStatus.ABORTED:
            status_desc = "cancelado a petición del usuario"
        elif self.plan.is_completed():
            status_desc = "completado con éxito"
        else:
            status_desc = "fallido"

        summary_text = (
            f"Plan '{self.plan.plan_id}' {status_desc}. "
            f"Pasos completados: {len(self.plan.completed_steps())}/{len(self.plan.steps)}. "
            f"Modelos locales activos en VRAM: {self.active_local_models} (máximo permitido: {self.max_local_models}). "
            f"Fallbacks a Groq utilizados: {self._groq_fallbacks_count}."
        )

        return PlanExecutionResult(
            plan_id=self.plan.plan_id,
            status=self.plan.status,
            step_results=results,
            active_local_models=self.active_local_models,
            groq_fallbacks_used=self._groq_fallbacks_count,
            total_elapsed_seconds=total_elapsed,
            summary=summary_text,
        )


__all__ = [
    "MAX_CONCURRENT_LOCAL_MODELS",
    "PlanExecutionResult",
    "PlanExecutor",
    "ROLE_TO_LOCAL_MODEL",
    "StepExecutionResult",
]
