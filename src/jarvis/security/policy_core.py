"""Pure, deterministic security-policy evaluation.

This module deliberately decides only. It does not import executors, models,
network clients, biometric providers, or persistence layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from types import MappingProxyType
from typing import TYPE_CHECKING, Callable, Mapping

if TYPE_CHECKING:
    from jarvis.identity.models import UserIdentity

from .levels import SecurityLevel
from .models import SecurityAction


DEFAULT_CONFIRMATION_TTL = timedelta(seconds=60)


class PresenceState(str, Enum):
    """What the future identity layer knows about people near JARVIS."""

    PRESENT = "present"
    ABSENT = "absent"
    OTHER_PERSON_PRESENT = "other_person_present"
    UNKNOWN = "unknown"


class VerifiedFactor(str, Enum):
    """Assertions from a future verifier; no biometric data is stored."""

    OWNER_VOICE = "owner_voice"
    OWNER_DEVICE = "owner_device"
    OWNER_SECRET = "owner_secret"
    OWNER_FACE = "owner_face"


class ActionEffect(str, Enum):
    CONVERSATION = "conversation"
    WEB_READ = "web_read"
    LOCAL_READ = "local_read"
    SENSITIVE_READ = "sensitive_read"
    CREATE = "create"
    MODIFY = "modify"
    EXECUTE = "execute"
    PHYSICAL = "physical"


class PolicyDecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CONFIRMATION = "require_confirmation"
    REAUTHENTICATE = "reauthenticate"


class DecisionReason(str, Enum):
    ALLOWED = "allowed"
    UNKNOWN_ACTION = "unknown_action"
    INSUFFICIENT_LEVEL = "insufficient_level"
    OWNER_VERIFICATION_REQUIRED = "owner_verification_required"
    PRESENCE_REQUIRED = "presence_required"
    TARGET_NOT_ALLOWED = "target_not_allowed"
    CONFIRMATION_REQUIRED = "confirmation_required"
    CONFIRMATION_INVALID = "confirmation_invalid"
    C_DRIVE_OWNER_FACTORS_REQUIRED = "c_drive_owner_factors_required"
    IDENTITY_ASSIGNMENT_REQUIRED = "identity_assignment_required"
    IDENTITY_ASSIGNMENT_FORBIDDEN = "identity_assignment_forbidden"
    NON_OWNER_LEVEL_CAP = "non_owner_level_cap"
    TASK_NOT_CONTINUABLE = "task_not_continuable"
    TASK_REAUTHENTICATION_REQUIRED = "task_reauthentication_required"


@dataclass(frozen=True)
class IdentityContext:
    """Identity facts supplied to policy evaluation, never a biometric record."""

    identity: UserIdentity | None = None
    presence: PresenceState = PresenceState.UNKNOWN
    verified_factors: frozenset[VerifiedFactor] = field(default_factory=frozenset)
    claimed_user_id: str | None = None

    @classmethod
    def unknown_voice(cls) -> "IdentityContext":
        """Unknown speakers are intentionally represented as level 0."""

        return cls(presence=PresenceState.PRESENT)

    @property
    def user_id(self) -> str | None:
        return self.identity.user_id if self.identity is not None else None

    @property
    def is_owner_identity(self) -> bool:
        """Use only the explicit ownership claim supplied with the identity."""

        return bool(self.identity and self.identity.is_owner)

    @property
    def is_verified_owner(self) -> bool:
        owner_identity_factors = {
            VerifiedFactor.OWNER_VOICE,
            VerifiedFactor.OWNER_DEVICE,
        }
        return self.is_owner_identity and bool(
            owner_identity_factors & self.verified_factors
        )
    @property
    def effective_level(self) -> SecurityLevel:
        """Never trust a non-owner identity with a level above 2."""

        if self.identity is None:
            return SecurityLevel.LEVEL_0

        level = self.identity.security_level
        if not isinstance(level, SecurityLevel):
            level = SecurityLevel.LEVEL_0

        if not self.is_owner_identity:
            return SecurityLevel(min(level.value, SecurityLevel.LEVEL_2.value))

        return level


@dataclass(frozen=True)
class FreshConfirmation:
    """A confirmation bound to one actor, action and target, with no reuse."""

    confirmation_id: str
    action_name: str
    user_id: str
    target: str | None
    confirmed_at: datetime
    consumed: bool = False

    def is_fresh_for(
        self,
        action: SecurityAction,
        user_id: str | None,
        now: datetime,
        ttl: timedelta = DEFAULT_CONFIRMATION_TTL,
    ) -> bool:
        if self.consumed or user_id is None:
            return False
        if self.action_name != action.action or self.user_id != user_id:
            return False
        if self.target != action.target:
            return False

        confirmed_at = _as_utc(self.confirmed_at)
        current = _as_utc(now)
        return timedelta(0) <= current - confirmed_at <= ttl

    def consume(self) -> "FreshConfirmation":
        """Return a consumed representation; persistence belongs to a later layer."""

        return FreshConfirmation(
            confirmation_id=self.confirmation_id,
            action_name=self.action_name,
            user_id=self.user_id,
            target=self.target,
            confirmed_at=self.confirmed_at,
            consumed=True,
        )


@dataclass(frozen=True)
class SessionSkillAuthorization:
    """In-memory approval for one verified dynamic-skill artifact and user."""

    skill_name: str
    source_hash: str
    user_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.skill_name, str) or not self.skill_name:
            raise ValueError("skill_name must be a non-empty string")
        if (
            not isinstance(self.source_hash, str)
            or len(self.source_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.source_hash)
        ):
            raise ValueError("source_hash must be a lowercase SHA-256 digest")
        if not isinstance(self.user_id, str) or not self.user_id:
            raise ValueError("user_id must be a non-empty string")

    def matches(self, action: SecurityAction, user_id: str | None) -> bool:
        return bool(
            action.action == "execute_dynamic_skill"
            and user_id == self.user_id
            and action.target == f"dynamic/{self.skill_name}.py#sha256-{self.source_hash}"
            and action.metadata.get("skill_name") == self.skill_name
            and action.metadata.get("source_hash") == self.source_hash
        )


class ConfirmationLedger:
    """In-memory consumption model for policy tests and a future adapter."""

    def __init__(self) -> None:
        self._consumed_ids: set[str] = set()

    def is_available(self, confirmation: FreshConfirmation) -> bool:
        return not confirmation.consumed and confirmation.confirmation_id not in self._consumed_ids

    def consume(self, decision: "PolicyDecision") -> bool:
        """Mark an allow decision's confirmations as consumed exactly once."""

        if decision.kind is not PolicyDecisionKind.ALLOW:
            return False
        if any(confirmation_id in self._consumed_ids for confirmation_id in decision.confirmation_ids_to_consume):
            return False

        self._consumed_ids.update(decision.confirmation_ids_to_consume)
        return True


@dataclass(frozen=True)
class AuthorizedTask:
    """A model of a task already approved by verified owner.

    It conveys no permission by itself: the policy still checks the task's
    action, scope and current presence state on every continuation.
    """

    task_id: str
    action_name: str
    authorized_for_user_id: str
    authorized_by_verified_owner: bool
    may_continue_without_presence: bool
    reauthentication_required: bool = False


@dataclass(frozen=True)
class ActionPolicy:
    """Static requirements for one known action identifier."""

    action_name: str
    required_level: SecurityLevel
    effect: ActionEffect
    requires_confirmation: bool = False
    confirmation_count: int = 0
    requires_owner: bool = False
    requires_presence: bool = False
    allowed_target_roots: tuple[str, ...] = ()
    audit_event_code: str | None = None
    allows_continuation: bool = False

    def __post_init__(self) -> None:
        if self.confirmation_count < 0:
            raise ValueError("confirmation_count no puede ser negativo")
        if self.requires_confirmation != (self.confirmation_count > 0):
            raise ValueError("La confirmación y su número de usos deben coincidir")


@dataclass(frozen=True)
class PolicyRequest:
    """Inputs for a deterministic decision, never generated prose."""

    action: SecurityAction
    identity: IdentityContext
    confirmations: tuple[FreshConfirmation, ...] = ()
    continuation_task: AuthorizedTask | None = None
    identity_assignment: UserIdentity | None = None
    session_skill_authorization: SessionSkillAuthorization | None = None


@dataclass(frozen=True)
class AuditRequirement:
    event_code: str
    action_name: str


@dataclass(frozen=True)
class PolicyDecision:
    kind: PolicyDecisionKind
    reason: DecisionReason
    action_name: str
    policy: ActionPolicy | None
    details: Mapping[str, object] = field(default_factory=dict)
    required_confirmations: int = 0
    confirmation_ids_to_consume: tuple[str, ...] = ()
    audit_requirements: tuple[AuditRequirement, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.kind is PolicyDecisionKind.ALLOW


def _policy(
    action_name: str,
    level: SecurityLevel,
    effect: ActionEffect,
    *,
    confirmations: int = 0,
    owner: bool = False,
    presence: bool = False,
    roots: tuple[str, ...] = (),
    audit_event: str | None = None,
    continuable: bool = False,
) -> ActionPolicy:
    return ActionPolicy(
        action_name=action_name,
        required_level=level,
        effect=effect,
        requires_confirmation=confirmations > 0,
        confirmation_count=confirmations,
        requires_owner=owner,
        requires_presence=presence,
        allowed_target_roots=roots,
        audit_event_code=audit_event,
        allows_continuation=continuable,
    )


_WORKSPACE_ROOTS = ("workspace",)
_WRITABLE_ROOTS = ("workspace", "data", "output")

_POLICIES = {
    # Level 0: the complete allowlist for unknown voices.
    "conversation": _policy("conversation", SecurityLevel.LEVEL_0, ActionEffect.CONVERSATION),
    "respond": _policy("respond", SecurityLevel.LEVEL_0, ActionEffect.CONVERSATION),
    "buscar_en_internet": _policy("buscar_en_internet", SecurityLevel.LEVEL_0, ActionEffect.WEB_READ),
    "web_search": _policy("web_search", SecurityLevel.LEVEL_0, ActionEffect.WEB_READ),
    "calculator": _policy("calculator", SecurityLevel.LEVEL_0, ActionEffect.CONVERSATION),
    "calcular": _policy("calcular", SecurityLevel.LEVEL_0, ActionEffect.CONVERSATION),

    # Level 1: bounded informational access.
    "secure_search": _policy("secure_search", SecurityLevel.LEVEL_1, ActionEffect.WEB_READ),
    "secure_web_search": _policy("secure_web_search", SecurityLevel.LEVEL_1, ActionEffect.WEB_READ),
    "buscar_en_internet_seguro": _policy("buscar_en_internet_seguro", SecurityLevel.LEVEL_1, ActionEffect.WEB_READ),
    "seguimiento_paquete_1688track": _policy(
        "seguimiento_paquete_1688track", SecurityLevel.LEVEL_1, ActionEffect.WEB_READ
    ),
    "consultar_seguimiento_1688track": _policy(
        "consultar_seguimiento_1688track", SecurityLevel.LEVEL_1, ActionEffect.WEB_READ
    ),
    "tracking_1688track": _policy("tracking_1688track", SecurityLevel.LEVEL_1, ActionEffect.WEB_READ),
    "estado_impresora": _policy("estado_impresora", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ),
    "listar_archivos": _policy("listar_archivos", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ),
    "leer_archivo_workspace": _policy(
        "leer_archivo_workspace", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ, roots=_WORKSPACE_ROOTS
    ),
    "listar_archivos_workspace": _policy(
        "listar_archivos_workspace", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ, roots=_WORKSPACE_ROOTS
    ),
    "file_read": _policy("file_read", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ),
    "tomar_captura_pantalla": _policy(
        "tomar_captura_pantalla", SecurityLevel.LEVEL_1, ActionEffect.SENSITIVE_READ
    ),
    "analizar_codigo_activo": _policy(
        "analizar_codigo_activo", SecurityLevel.LEVEL_1, ActionEffect.SENSITIVE_READ
    ),
    "printer_tool": _policy("printer_tool", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ),
    "printer_status": _policy("printer_status", SecurityLevel.LEVEL_1, ActionEffect.LOCAL_READ),

    # Level 2: non-protected creation and modification.
    "crear_archivo": _policy(
        "crear_archivo", SecurityLevel.LEVEL_2, ActionEffect.CREATE, roots=_WRITABLE_ROOTS
    ),
    "create_file": _policy(
        "create_file", SecurityLevel.LEVEL_2, ActionEffect.CREATE, roots=_WRITABLE_ROOTS
    ),
    "create_allowed_file": _policy(
        "create_allowed_file", SecurityLevel.LEVEL_2, ActionEffect.CREATE, roots=_WRITABLE_ROOTS
    ),
    "create_directory": _policy(
        "create_directory", SecurityLevel.LEVEL_2, ActionEffect.CREATE, roots=_WRITABLE_ROOTS
    ),
    "modificar_archivo": _policy(
        "modificar_archivo", SecurityLevel.LEVEL_2, ActionEffect.MODIFY,
        confirmations=1, roots=_WRITABLE_ROOTS,
    ),
    "modify_file": _policy(
        "modify_file", SecurityLevel.LEVEL_2, ActionEffect.MODIFY,
        confirmations=1, roots=_WRITABLE_ROOTS,
    ),
    "modify_allowed_file": _policy(
        "modify_allowed_file", SecurityLevel.LEVEL_2, ActionEffect.MODIFY,
        confirmations=1, roots=_WRITABLE_ROOTS,
    ),
    "file_write": _policy(
        "file_write", SecurityLevel.LEVEL_2, ActionEffect.MODIFY,
        confirmations=1, roots=_WRITABLE_ROOTS,
    ),

    # Level 3: protected information, deletion and controlled execution.
    "guardar_hecho": _policy(
        "guardar_hecho", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "guardar_memoria": _policy(
        "guardar_memoria", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "modificar_informacion": _policy(
        "modificar_informacion", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "modificar_archivo_protegido": _policy(
        "modificar_archivo_protegido", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "modify_protected_file": _policy(
        "modify_protected_file", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "eliminar_archivo": _policy(
        "eliminar_archivo", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True, roots=_WRITABLE_ROOTS,
    ),
    "delete_file": _policy(
        "delete_file", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True, roots=_WRITABLE_ROOTS,
    ),
    "delete_directory": _policy(
        "delete_directory", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True, roots=_WRITABLE_ROOTS,
    ),
    "shell_exec": _policy(
        "shell_exec", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "cmd_exec": _policy(
        "cmd_exec", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "execute_command": _policy(
        "execute_command", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "execute_tool": _policy(
        "execute_tool", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "abrir_programa": _policy(
        "abrir_programa", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "open_program": _policy(
        "open_program", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "blender_exec": _policy(
        "blender_exec", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "freecad_exec": _policy(
        "freecad_exec", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "stl_slicer": _policy(
        "stl_slicer", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "python_temporal": _policy(
        "python_temporal", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True,
    ),
    "asignar_identidad_nivel": _policy(
        "asignar_identidad_nivel", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),

    # Deployment only writes a reviewed proposal; activation remains a separate phase.
    "deploy_dynamic_skill": _policy(
        "deploy_dynamic_skill", SecurityLevel.LEVEL_3, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True, roots=("dynamic",),
    ),
    # Installed dynamic code is executable only under this owner-bound policy.
    "execute_dynamic_skill": _policy(
        "execute_dynamic_skill", SecurityLevel.LEVEL_3, ActionEffect.EXECUTE,
        confirmations=1, owner=True, presence=True, roots=("dynamic",),
    ),
    # Level 4: file management outside the ordinary scope and physical actions.
    "mover_archivo": _policy(
        "mover_archivo", SecurityLevel.LEVEL_4, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "move_file": _policy(
        "move_file", SecurityLevel.LEVEL_4, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "gestionar_archivos": _policy(
        "gestionar_archivos", SecurityLevel.LEVEL_4, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "manage_files": _policy(
        "manage_files", SecurityLevel.LEVEL_4, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "iniciar_impresion": _policy(
        "iniciar_impresion", SecurityLevel.LEVEL_4, ActionEffect.PHYSICAL,
        confirmations=1, owner=True, presence=True, continuable=True,
    ),
    "start_print": _policy(
        "start_print", SecurityLevel.LEVEL_4, ActionEffect.PHYSICAL,
        confirmations=1, owner=True, presence=True, continuable=True,
    ),
    "subir_e_imprimir": _policy(
        "subir_e_imprimir", SecurityLevel.LEVEL_4, ActionEffect.PHYSICAL,
        confirmations=1, owner=True, presence=True, continuable=True,
    ),
    "cambiar_temperaturas": _policy(
        "cambiar_temperaturas", SecurityLevel.LEVEL_4, ActionEffect.PHYSICAL,
        confirmations=1, owner=True, presence=True, continuable=True,
    ),
    "set_temperatures": _policy(
        "set_temperatures", SecurityLevel.LEVEL_4, ActionEffect.PHYSICAL,
        confirmations=1, owner=True, presence=True, continuable=True,
    ),

    # Safety operation: immediate, but an audit event is mandatory.
    "parada_emergencia": _policy(
        "parada_emergencia", SecurityLevel.LEVEL_0, ActionEffect.PHYSICAL,
        audit_event="klipper_emergency_stop_requested",
    ),
    "emergency_stop": _policy(
        "emergency_stop", SecurityLevel.LEVEL_0, ActionEffect.PHYSICAL,
        audit_event="klipper_emergency_stop_requested",
    ),
    "printer_emergency_stop": _policy(
        "printer_emergency_stop", SecurityLevel.LEVEL_0, ActionEffect.PHYSICAL,
        audit_event="klipper_emergency_stop_requested",
    ),

    # Compatibility actions. C: still invokes the stricter special rule below.
    "modify_any_user_file": _policy(
        "modify_any_user_file", SecurityLevel.LEVEL_5, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
    "delete_any_user_file": _policy(
        "delete_any_user_file", SecurityLevel.LEVEL_5, ActionEffect.MODIFY,
        confirmations=1, owner=True, presence=True,
    ),
}
ACTION_POLICIES: Mapping[str, ActionPolicy] = MappingProxyType(_POLICIES)


def get_action_policy(action_name: str) -> ActionPolicy | None:
    """Return a known policy only; unknown actions intentionally have none."""

    return ACTION_POLICIES.get(action_name)


class DeterministicPolicyEvaluator:
    """Fail-closed evaluator for known actions only."""

    def __init__(
        self,
        policies: Mapping[str, ActionPolicy] = ACTION_POLICIES,
        confirmation_ledger: ConfirmationLedger | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._policies = policies
        self._confirmation_ledger = confirmation_ledger
        self._now = now or (lambda: datetime.now(timezone.utc))

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Return a structured decision without invoking any external action."""

        policy = self._policies.get(request.action.action)
        if policy is None:
            return self._deny(request, None, DecisionReason.UNKNOWN_ACTION)

        if _is_c_drive_target(request.action.target) and policy.effect in {
            ActionEffect.LOCAL_READ,
            ActionEffect.CREATE,
            ActionEffect.MODIFY,
        }:
            return self._evaluate_c_drive(request, policy)

        continuation = self._evaluate_continuation(request, policy)
        if continuation is not None:
            return continuation

        level = request.identity.effective_level
        if level < policy.required_level:
            return self._deny(
                request,
                policy,
                DecisionReason.INSUFFICIENT_LEVEL,
                current_level=level.value,
                required_level=policy.required_level.value,
            )

        if policy.required_level >= SecurityLevel.LEVEL_3 or policy.requires_owner:
            if not request.identity.is_verified_owner:
                return self._deny(request, policy, DecisionReason.OWNER_VERIFICATION_REQUIRED)

        if (policy.required_level >= SecurityLevel.LEVEL_3 or policy.requires_presence) and request.identity.presence is not PresenceState.PRESENT:
            return self._deny(request, policy, DecisionReason.PRESENCE_REQUIRED)

        if policy.allowed_target_roots and not _target_is_within_roots(
            request.action.target,
            policy.allowed_target_roots,
        ):
            return self._deny(request, policy, DecisionReason.TARGET_NOT_ALLOWED)

        if policy.action_name == "asignar_identidad_nivel":
            assignment_decision = self._evaluate_identity_assignment(request, policy)
            if assignment_decision is not None:
                return assignment_decision

        return self._with_confirmations(request, policy)

    def _evaluate_continuation(
        self,
        request: PolicyRequest,
        policy: ActionPolicy,
    ) -> PolicyDecision | None:
        task = request.continuation_task
        if task is None:
            return None

        if (
            task.action_name != request.action.action
            or not task.authorized_by_verified_owner
            or not task.may_continue_without_presence
            or not policy.allows_continuation
        ):
            return self._deny(request, policy, DecisionReason.TASK_NOT_CONTINUABLE)

        if (
            task.reauthentication_required
            or request.identity.presence is PresenceState.OTHER_PERSON_PRESENT
            or (
                request.identity.user_id is not None
                and request.identity.user_id != task.authorized_for_user_id
            )
        ):
            return PolicyDecision(
                kind=PolicyDecisionKind.REAUTHENTICATE,
                reason=DecisionReason.TASK_REAUTHENTICATION_REQUIRED,
                action_name=request.action.action,
                policy=policy,
            )

        if request.identity.presence is PresenceState.ABSENT:
            return self._allow(request, policy)

        # A present person must be evaluated as a fresh request.
        return None

    def _evaluate_identity_assignment(
        self,
        request: PolicyRequest,
        policy: ActionPolicy,
    ) -> PolicyDecision | None:
        assignment = request.identity_assignment
        if assignment is None:
            return self._deny(request, policy, DecisionReason.IDENTITY_ASSIGNMENT_REQUIRED)

        requested_level = assignment.security_level
        if not isinstance(requested_level, SecurityLevel):
            return self._deny(request, policy, DecisionReason.IDENTITY_ASSIGNMENT_FORBIDDEN)

        is_owner_target = assignment.is_owner
        if not is_owner_target and requested_level >= SecurityLevel.LEVEL_3:
            return self._deny(
                request,
                policy,
                DecisionReason.NON_OWNER_LEVEL_CAP,
                requested_level=requested_level.value,
            )

        return None
    def _evaluate_c_drive(
        self,
        request: PolicyRequest,
        policy: ActionPolicy,
    ) -> PolicyDecision:
        level = request.identity.effective_level
        if level < SecurityLevel.LEVEL_5:
            return self._deny(
                request,
                policy,
                DecisionReason.INSUFFICIENT_LEVEL,
                current_level=level.value,
                required_level=SecurityLevel.LEVEL_5.value,
            )

        if request.identity.presence is not PresenceState.PRESENT:
            return self._deny(request, policy, DecisionReason.PRESENCE_REQUIRED)

        required_factors = {
            VerifiedFactor.OWNER_VOICE,
            VerifiedFactor.OWNER_SECRET,
            VerifiedFactor.OWNER_FACE,
        }
        if not request.identity.is_owner_identity or not required_factors.issubset(
            request.identity.verified_factors
        ):
            missing = sorted(factor.value for factor in required_factors - request.identity.verified_factors)
            return self._deny(
                request,
                policy,
                DecisionReason.C_DRIVE_OWNER_FACTORS_REQUIRED,
                missing_factors=tuple(missing),
            )

        confirmation_count = 2 if policy.effect is ActionEffect.LOCAL_READ else max(1, policy.confirmation_count)
        return self._with_confirmations(request, policy, confirmation_count)

    def _with_confirmations(
        self,
        request: PolicyRequest,
        policy: ActionPolicy,
        required_count: int | None = None,
    ) -> PolicyDecision:
        count = policy.confirmation_count if required_count is None else required_count
        if count == 0:
            return self._allow(request, policy)

        session_authorization = request.session_skill_authorization
        if session_authorization is not None:
            if (
                not isinstance(session_authorization, SessionSkillAuthorization)
                or not session_authorization.matches(request.action, request.identity.user_id)
            ):
                return self._deny(request, policy, DecisionReason.CONFIRMATION_INVALID)
            return self._allow(request, policy)

        now = self._now()
        valid = []
        invalid_supplied = False
        for confirmation in request.confirmations:
            available = (
                self._confirmation_ledger is None
                or self._confirmation_ledger.is_available(confirmation)
            )
            if available and confirmation.is_fresh_for(request.action, request.identity.user_id, now):
                valid.append(confirmation)
            else:
                invalid_supplied = True

        unique = []
        seen: set[str] = set()
        for confirmation in valid:
            if confirmation.confirmation_id not in seen:
                seen.add(confirmation.confirmation_id)
                unique.append(confirmation)

        if len(unique) < count:
            return PolicyDecision(
                kind=PolicyDecisionKind.REQUIRE_CONFIRMATION,
                reason=(DecisionReason.CONFIRMATION_INVALID if invalid_supplied else DecisionReason.CONFIRMATION_REQUIRED),
                action_name=request.action.action,
                policy=policy,
                required_confirmations=count,
            )

        return self._allow(
            request,
            policy,
            confirmation_ids=tuple(confirmation.confirmation_id for confirmation in unique[:count]),
        )

    @staticmethod
    def _deny(
        request: PolicyRequest,
        policy: ActionPolicy | None,
        reason: DecisionReason,
        **details: object,
    ) -> PolicyDecision:
        return PolicyDecision(
            kind=PolicyDecisionKind.DENY,
            reason=reason,
            action_name=request.action.action,
            policy=policy,
            details=MappingProxyType(dict(details)),
        )

    @staticmethod
    def _allow(
        request: PolicyRequest,
        policy: ActionPolicy,
        confirmation_ids: tuple[str, ...] = (),
    ) -> PolicyDecision:
        audits = ()
        if policy.audit_event_code is not None:
            audits = (AuditRequirement(policy.audit_event_code, request.action.action),)

        return PolicyDecision(
            kind=PolicyDecisionKind.ALLOW,
            reason=DecisionReason.ALLOWED,
            action_name=request.action.action,
            policy=policy,
            confirmation_ids_to_consume=confirmation_ids,
            audit_requirements=audits,
        )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _is_c_drive_target(target: str | None) -> bool:
    if target is None:
        return False
    normalized = target.strip().replace("/", "\\").casefold()
    return normalized.startswith("c:")


def _target_is_within_roots(target: str | None, roots: tuple[str, ...]) -> bool:
    """Pure path check: no filesystem probing and no traversal allowance."""

    if target is None:
        return False

    normalized = target.strip().replace("\\", "/")
    if not normalized or normalized.startswith("/") or ":" in normalized:
        return False

    parts = tuple(part for part in normalized.split("/") if part not in ("", "."))
    if not parts or ".." in parts:
        return False

    return parts[0] in roots


__all__ = [
    "ACTION_POLICIES",
    "ActionEffect",
    "ActionPolicy",
    "AuditRequirement",
    "AuthorizedTask",
    "ConfirmationLedger",
    "DecisionReason",
    "DeterministicPolicyEvaluator",
    "FreshConfirmation",
    "SessionSkillAuthorization",
    "IdentityContext",
    "PolicyDecision",
    "PolicyDecisionKind",
    "PolicyRequest",
    "PresenceState",
    "VerifiedFactor",
    "get_action_policy",
]