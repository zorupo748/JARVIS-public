"""Safe, one-shot repair preparation for verified dynamic-skill runtime failures."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from jarvis.core.dynamic_skill_state import DynamicSkillStateStore
from jarvis.core.safe_skill_deployment import (
    load_dynamic_skill_metadata,
    resolve_dynamic_skill_paths,
)
from jarvis.core.safe_skill_execution import (
    ExecutionFailureKind,
    SafeSkillExecutionResult,
)
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import IdentityContext, PolicyDecisionKind

if TYPE_CHECKING:
    from jarvis.core.safe_skill_pipeline import (
        InstallationPreparation,
        PendingSkillInstallation,
        SafeSkillPipeline,
    )

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_CAPTURED_RUNTIME_STREAM_CHARS = 8000


def _short_reason(reason: str, *, limit: int = 320) -> str:
    first_line = next((line.strip() for line in reason.splitlines() if line.strip()), "")
    if len(first_line) <= limit:
        return first_line
    return first_line[: limit - 1].rstrip() + "…"


@dataclass(frozen=True)
class DynamicSkillRepairContext:
    skill_name: str
    source_hash: str
    original_command: str
    runtime_error: str
    stdout: str
    stderr: str
    current_state: Mapping[str, object]
    source_code: str

    def to_authoring_context(self) -> str:
        state_json = json.dumps(
            dict(self.current_state),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        return f"""AUTOMATIC RUNTIME REPAIR CONTEXT
This is an installed skill that conceptually serves an existing user capability.
Preserve its name, declared dependencies, and unrelated existing behavior. Fix
the concrete runtime error only; do not add unrelated features. Preserve the
comando/optional estado ABI and central DynamicSkillStateStore contract. Initial
state may validly be {{}}; never assume a key exists, use .get(), membership
checks, or equivalent. Do not use globals or function attributes for persistence.
Return the complete corrected source through the normal authoring contract.

Skill: {self.skill_name}
Verified source SHA-256 that failed: {self.source_hash}
Original user command (verbatim): {self.original_command}
Exact runtime error: {self.runtime_error}

State passed to the failed execution:
{state_json}

Captured stdout (bounded):
{self.stdout}

Captured stderr (bounded):
{self.stderr}

--- INSTALLED SOURCE THAT FAILED ---
{self.source_code}
--- END INSTALLED SOURCE ---
"""


@dataclass(frozen=True)
class PreparedDynamicSkillRepair:
    context: DynamicSkillRepairContext | None
    pending_installation: PendingSkillInstallation | None
    installation_preparation: InstallationPreparation | None
    failure_reason: str | None = None

    @property
    def ready_for_confirmation(self) -> bool:
        return self.context is not None and self.pending_installation is not None


@dataclass(frozen=True)
class PendingDynamicSkillRepairRetry:
    skill_name: str
    failed_source_hash: str
    installed_source_hash: str
    original_command: str


class DynamicSkillRepairCoordinator:
    """Use the ordinary safe authoring/review and deployment preparation flows."""

    def __init__(
        self,
        pipeline: SafeSkillPipeline,
        *,
        dynamic_skills_dir: Path | str,
        state_store: DynamicSkillStateStore,
    ) -> None:
        self._pipeline = pipeline
        self._dynamic_skills_dir = Path(dynamic_skills_dir)
        self._state_store = state_store

    @staticmethod
    def is_repairable_failure(result: SafeSkillExecutionResult) -> bool:
        action = result.action
        if (
            result.executed
            or not result.allowed
            or not result.hash_verified
            or result.failure_kind is not ExecutionFailureKind.SKILL_EXCEPTION
            or not result.failure_reason
            or result.policy_decision is None
            or result.policy_decision.kind is not PolicyDecisionKind.ALLOW
            or action is None
            or action.action != "execute_dynamic_skill"
        ):
            return False
        skill_name = result.skill_name
        source_hash = action.metadata.get("source_hash")
        return bool(
            isinstance(skill_name, str)
            and action.metadata.get("skill_name") == skill_name
            and isinstance(source_hash, str)
            and _SHA256_PATTERN.fullmatch(source_hash)
            and action.target == f"dynamic/{skill_name}.py#sha256-{source_hash}"
        )

    def prepare_repair(
        self,
        execution_result: SafeSkillExecutionResult,
        *,
        original_command: str,
        identity: IdentityContext,
    ) -> PreparedDynamicSkillRepair:
        if not self.is_repairable_failure(execution_result):
            return PreparedDynamicSkillRepair(
                None,
                None,
                None,
                "El resultado no es un fallo interno reparable tras autorización.",
            )
        if not isinstance(original_command, str) or not original_command.strip():
            return PreparedDynamicSkillRepair(None, None, None, "No hay un comando original válido para reparar.")

        context, error = self._build_context(execution_result, original_command)
        if context is None:
            return PreparedDynamicSkillRepair(None, None, None, error)

        try:
            authoring_result = self._pipeline.author(
                original_command,
                existing_skill_name=context.skill_name,
                relevant_context=context.to_authoring_context(),
            )
        except Exception as exc:
            return PreparedDynamicSkillRepair(
                context,
                None,
                None,
                f"Falló el authoring seguro: {type(exc).__name__}: {exc}",
            )

        if not authoring_result.success or authoring_result.proposal is None:
            return PreparedDynamicSkillRepair(
                context,
                None,
                None,
                _short_reason(
                    authoring_result.failure_reason or "El authoring/review no aprobó una reparación."
                ),
            )
        if authoring_result.proposal.skill_name != context.skill_name:
            return PreparedDynamicSkillRepair(
                context,
                None,
                None,
                "El authoring propuso otro nombre; la reparación debe conservar la skill instalada.",
            )

        try:
            installation = self._pipeline.prepare_installation(
                authoring_result,
                original_user_request=original_command,
                identity=identity,
                replace_existing_source_hash=context.source_hash,
            )
        except Exception as exc:
            return PreparedDynamicSkillRepair(
                context,
                None,
                None,
                f"Falló la preparación segura del deployment: {type(exc).__name__}: {exc}",
            )

        if not installation.confirmation_required or installation.pending is None:
            decision = installation.deployment_result.decision
            reason = installation.deployment_result.failure_reason
            if not reason and decision is not None:
                reason = f"PolicyCore respondió {decision.kind.value}: {decision.reason.value}."
            return PreparedDynamicSkillRepair(
                context,
                None,
                installation,
                reason or "No se pudo preparar una instalación que requiera confirmación.",
            )

        return PreparedDynamicSkillRepair(
            context,
            installation.pending,
            installation,
        )

    def _build_context(
        self,
        result: SafeSkillExecutionResult,
        original_command: str,
    ) -> tuple[DynamicSkillRepairContext | None, str | None]:
        action = result.action
        if action is None or result.skill_name is None:
            return None, "Faltan los datos verificados de la ejecución fallida."
        source_hash = action.metadata.get("source_hash")
        if not isinstance(source_hash, str) or not _SHA256_PATTERN.fullmatch(source_hash):
            return None, "El hash del source fallido no es válido."

        try:
            paths = resolve_dynamic_skill_paths(self._dynamic_skills_dir, result.skill_name)
            metadata = load_dynamic_skill_metadata(self._dynamic_skills_dir, result.skill_name)
            source_bytes = paths.source.read_bytes()
            current_hash = hashlib.sha256(source_bytes).hexdigest()
            if (
                metadata.source_hash != source_hash
                or current_hash != source_hash
                or action.target != metadata.execution_target
            ):
                return None, "El artifact cambió después del fallo; se cancela la reparación automática."
            source_code = source_bytes.decode("utf-8")
        except (OSError, UnicodeError, ValueError) as exc:
            return None, f"No se pudo verificar el source instalado: {exc}"

        current_state = result.runtime_state
        if not isinstance(current_state, Mapping):
            current_state = {}
        try:
            safe_state = self._state_store.validate_state(current_state)
        except ValueError as exc:
            return None, f"El state proporcionado al runtime no es válido: {exc}"
        return (
            DynamicSkillRepairContext(
                skill_name=result.skill_name,
                source_hash=source_hash,
                original_command=original_command,
                runtime_error=result.failure_reason or "Error interno sin detalle.",
                stdout=(result.stdout or "")[-MAX_CAPTURED_RUNTIME_STREAM_CHARS:],
                stderr=(result.stderr or "")[-MAX_CAPTURED_RUNTIME_STREAM_CHARS:],
                current_state=safe_state,
                source_code=source_code,
            ),
            None,
        )


__all__ = [
    "DynamicSkillRepairContext",
    "DynamicSkillRepairCoordinator",
    "PendingDynamicSkillRepairRetry",
    "PreparedDynamicSkillRepair",
]