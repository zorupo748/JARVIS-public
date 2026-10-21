"""Policy-enforced dispatch for skills registered by the active JARVIS flow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import TYPE_CHECKING, Callable, Mapping

from .models import SecurityAction
from .policy_core import (
    AuthorizedTask,
    AuditRequirement,
    ConfirmationLedger,
    DecisionReason,
    DeterministicPolicyEvaluator,
    FreshConfirmation,
    IdentityContext,
    PolicyDecision,
    PolicyDecisionKind,
    PolicyRequest,
    SessionSkillAuthorization,
)

if TYPE_CHECKING:
    from jarvis.skills.base import SkillManager


SKILL_ACTIONS: Mapping[str, str] = MappingProxyType(
    {
        "buscar_en_internet": "buscar_en_internet",
        "buscar_en_internet_seguro": "buscar_en_internet_seguro",
        "secure_search": "secure_search",
        "secure_web_search": "secure_web_search",
        "seguimiento_paquete_1688track": "seguimiento_paquete_1688track",
        "consultar_seguimiento_1688track": "consultar_seguimiento_1688track",
        "tracking_1688track": "tracking_1688track",
        "estado_impresora": "estado_impresora",
        "listar_archivos": "listar_archivos",
        "subir_e_imprimir": "subir_e_imprimir",
        "parada_emergencia": "parada_emergencia",
        "tomar_captura_pantalla": "tomar_captura_pantalla",
        "analizar_codigo_activo": "analizar_codigo_activo",
        "leer_archivo_workspace": "leer_archivo_workspace",
        "listar_archivos_workspace": "listar_archivos_workspace",
        "guardar_hecho": "guardar_hecho",
    }
)

_TARGET_PARAMETER_NAMES = (
    "ruta_relativa",
    "ruta",
    "path",
    "file_path",
    "filename",
)


@dataclass(frozen=True)
class PendingConfirmation:
    """Details needed to ask for a new action-bound confirmation."""

    action_name: str
    target: str | None
    required_confirmations: int
    reason: DecisionReason


@dataclass(frozen=True)
class AuditEvent:
    """Small structured audit record emitted for policy-mandated events."""

    event_code: str
    action_name: str
    target: str | None
    user_id: str | None
    occurred_at: datetime


@dataclass(frozen=True)
class SkillDispatchResult:
    """Structured outcome; only ``executed`` results invoked a skill callable."""

    decision: PolicyDecision
    action: SecurityAction
    executed: bool
    result: object | None = None
    pending_confirmation: PendingConfirmation | None = None
    audit_events: tuple[AuditEvent, ...] = ()

    @property
    def message(self) -> str:
        if self.pending_confirmation is not None:
            return (
                "Se requiere una confirmacion fresca para "
                f"'{self.pending_confirmation.action_name}'."
            )
        if self.decision.kind is PolicyDecisionKind.REAUTHENTICATE:
            return "La accion requiere reautenticacion antes de continuar."
        if self.decision.kind is PolicyDecisionKind.DENY:
            return f"Accion denegada por la politica: {self.decision.reason.value}."
        return ""


class SkillDispatcher:
    """The only active-flow adapter allowed to invoke ``SkillManager.execute``."""

    def __init__(
        self,
        skills: "SkillManager",
        *,
        evaluator: DeterministicPolicyEvaluator | None = None,
        confirmation_ledger: ConfirmationLedger | None = None,
        skill_actions: Mapping[str, str] = SKILL_ACTIONS,
        audit_sink: Callable[[AuditEvent], None] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if evaluator is not None and confirmation_ledger is None:
            raise ValueError("An injected evaluator must share the confirmation ledger.")

        self._skills = skills
        self._confirmation_ledger = confirmation_ledger or ConfirmationLedger()
        self._evaluator = evaluator or DeterministicPolicyEvaluator(
            confirmation_ledger=self._confirmation_ledger
        )
        self._skill_actions = MappingProxyType(dict(skill_actions))
        self._audit_sink = audit_sink
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.audit_events: list[AuditEvent] = []

    def has_registered_action(self, skill_name: str) -> bool:
        """Return whether a skill is part of the closed, auditable dispatch map."""

        return skill_name in self._skill_actions

    def authorize_action(
        self,
        action: SecurityAction,
        *,
        identity: IdentityContext | None = None,
        confirmations: tuple[FreshConfirmation, ...] = (),
        continuation_task: AuthorizedTask | None = None,
        session_skill_authorization: SessionSkillAuthorization | None = None,
        scheduled: bool = False,
    ) -> SkillDispatchResult:
        """Evaluate one already-bound action without invoking ``SkillManager``.

        This is the policy-only half of the same dispatcher used by static
        skills. It authorizes an already verified artifact before an external
        runtime is allowed to receive control.
        """

        if not isinstance(action, SecurityAction):
            raise TypeError("action must be a SecurityAction")
        if scheduled:
            confirmations = ()
        context = identity or IdentityContext.unknown_voice()
        request = PolicyRequest(
            action=action,
            identity=context,
            confirmations=tuple(confirmations),
            continuation_task=continuation_task,
            session_skill_authorization=session_skill_authorization,
        )
        decision = self._evaluator.evaluate(request)
        if decision.kind is not PolicyDecisionKind.ALLOW:
            return self._not_executed(action, decision)
        if decision.confirmation_ids_to_consume and not self._confirmation_ledger.consume(decision):
            return self._not_executed(action, self._evaluator.evaluate(request))
        return SkillDispatchResult(
            decision=decision,
            action=action,
            executed=False,
            audit_events=self._record_audits(decision.audit_requirements, action, context),
        )
    def dispatch(
        self,
        skill_name: str,
        parameters: Mapping[str, object] | None = None,
        *,
        identity: IdentityContext | None = None,
        confirmations: tuple[FreshConfirmation, ...] = (),
        continuation_task: AuthorizedTask | None = None,
        session_skill_authorization: SessionSkillAuthorization | None = None,
        scheduled: bool = False,
    ) -> SkillDispatchResult:
        """Evaluate a known skill and invoke it only for an ALLOW decision."""

        safe_parameters = dict(parameters or {})

        # Una tarea programada nunca puede reutilizar confirmaciones interactivas.
        if scheduled:
            confirmations = ()

        context = identity or IdentityContext.unknown_voice()
        action_name = self._skill_actions.get(skill_name)
        action = self._build_action(skill_name, action_name, safe_parameters, scheduled)
        request = PolicyRequest(
            action=action,
            identity=context,
            confirmations=tuple(confirmations),
            continuation_task=continuation_task,
            session_skill_authorization=session_skill_authorization,
        )
        decision = self._evaluator.evaluate(request)

        if decision.kind is not PolicyDecisionKind.ALLOW:
            return self._not_executed(action, decision)

        if decision.confirmation_ids_to_consume and not self._confirmation_ledger.consume(decision):
            return self._not_executed(action, self._evaluator.evaluate(request))

        audit_events = self._record_audits(decision.audit_requirements, action, context)
        result = self._skills.execute(skill_name, **safe_parameters)
        return SkillDispatchResult(
            decision=decision,
            action=action,
            executed=True,
            result=result,
            audit_events=audit_events,
        )

    def _build_action(
        self,
        skill_name: str,
        action_name: str | None,
        parameters: Mapping[str, object],
        scheduled: bool,
    ) -> SecurityAction:
        target = self._normalize_target(skill_name, parameters)
        if action_name is None:
            action_name = f"unmapped_skill:{skill_name}"

        metadata = dict(parameters)
        if scheduled:
            metadata["scheduled"] = True
        return SecurityAction(
            action=action_name,
            description=f"Dispatch registered skill '{skill_name}'",
            target=target,
            metadata=metadata,
        )

    @staticmethod
    def _normalize_target(skill_name: str, parameters: Mapping[str, object]) -> str | None:
        if skill_name == "listar_archivos_workspace":
            return "workspace"

        raw_target = next(
            (
                parameters[name]
                for name in _TARGET_PARAMETER_NAMES
                if isinstance(parameters.get(name), str)
            ),
            None,
        )
        if not isinstance(raw_target, str):
            return None

        target = raw_target.strip().replace("\\", "/")
        if not target:
            return None
        if skill_name == "leer_archivo_workspace" and not target.startswith("workspace/"):
            return f"workspace/{target.lstrip('/')}"
        return target

    @staticmethod
    def _not_executed(
        action: SecurityAction,
        decision: PolicyDecision,
    ) -> SkillDispatchResult:
        pending = None
        if decision.kind is PolicyDecisionKind.REQUIRE_CONFIRMATION:
            pending = PendingConfirmation(
                action_name=decision.action_name,
                target=action.target,
                required_confirmations=decision.required_confirmations,
                reason=decision.reason,
            )
        return SkillDispatchResult(
            decision=decision,
            action=action,
            executed=False,
            pending_confirmation=pending,
        )

    def _record_audits(
        self,
        requirements: tuple[AuditRequirement, ...],
        action: SecurityAction,
        context: IdentityContext,
    ) -> tuple[AuditEvent, ...]:
        events = tuple(
            AuditEvent(
                event_code=requirement.event_code,
                action_name=requirement.action_name,
                target=action.target,
                user_id=context.user_id,
                occurred_at=self._now(),
            )
            for requirement in requirements
        )
        self.audit_events.extend(events)
        if self._audit_sink is not None:
            for event in events:
                self._audit_sink(event)
        return events


__all__ = [
    "AuditEvent",
    "PendingConfirmation",
    "SKILL_ACTIONS",
    "SkillDispatchResult",
    "SkillDispatcher",
]