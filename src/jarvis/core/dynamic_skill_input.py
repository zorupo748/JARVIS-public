"""Validated input requests and process-local dynamic-skill continuations."""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Callable

from jarvis.core.dynamic_skill_state import (
    DynamicSkillStateStore, JARVIS_DATA_KEY, JARVIS_STATE_KEY,
    extract_dynamic_skill_envelope,
)
from jarvis.security.policy_core import PolicyDecisionKind

if TYPE_CHECKING:
    from jarvis.core.safe_skill_execution import SafeSkillExecutionResult
    from jarvis.core.safe_skill_pipeline import PendingSkillExecution, SafeSkillPipeline
    from jarvis.core.session_skill_grants import SessionSkillGrantStore
    from jarvis.security.policy_core import IdentityContext

JARVIS_INPUT_REQUEST_KEY = "__jarvis_input_request__"
MAX_INPUT_PROMPT_CHARS = 600
MAX_INPUT_VALUE_CHARS = 4096
MAX_INPUT_FIELDS = 4
MAX_INPUT_CONTINUATIONS = 3
INPUT_EXPIRY_SECONDS = 300
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESERVED_FIELDS = frozenset({
    "skill_name", "source_hash", "metadata", "module", "path", "dynamic_dir", "policy_action", "action",
    "comando", "estado", "entradas", "api_key", "api_token", "access_token", "auth_token",
    "password", "secret", "credential", "credentials", "authorization", "cookie",
})
_CANCEL_WORDS = frozenset({"cancelar", "cancela", "olvidalo"})


class DynamicSkillInputError(ValueError):
    """An input request is invalid; it grants no authority or callback."""


def _valid_field(field: object) -> bool:
    return isinstance(field, str) and bool(_IDENTIFIER.fullmatch(field)) and field not in _RESERVED_FIELDS


@dataclass(frozen=True)
class DynamicSkillInputRequest:
    field: str
    prompt: str
    kind: str = "text"

    def __post_init__(self) -> None:
        if not _valid_field(self.field):
            raise DynamicSkillInputError("Input request field must be a non-reserved lowercase identifier of at most 64 characters.")
        if not isinstance(self.prompt, str) or not 1 <= len(self.prompt.strip()) <= MAX_INPUT_PROMPT_CHARS:
            raise DynamicSkillInputError(f"Input request prompt must contain 1..{MAX_INPUT_PROMPT_CHARS} characters.")
        if any(unicodedata.category(c) in {"Cc", "Cf"} and c not in "\n\t" for c in self.prompt):
            raise DynamicSkillInputError("Input request prompt contains control characters.")
        if self.kind != "text":
            raise DynamicSkillInputError("Input request kind must be text.")
        object.__setattr__(self, "prompt", self.prompt.strip())

    @classmethod
    def from_mapping(cls, value: object) -> DynamicSkillInputRequest:
        if not isinstance(value, Mapping) or set(value) != {"field", "prompt", "kind"}:
            raise DynamicSkillInputError("Input request must contain exactly field, prompt and kind.")
        return cls(value["field"], value["prompt"], value["kind"])

    def as_mapping(self) -> dict[str, str]:
        return {"field": self.field, "prompt": self.prompt, "kind": self.kind}


def validate_dynamic_skill_entries(value: object) -> dict[str, str]:
    """Only bounded text answers; nested routing or executable objects are forbidden."""
    if not isinstance(value, Mapping) or len(value) > MAX_INPUT_FIELDS:
        raise DynamicSkillInputError(f"entradas must be an object with at most {MAX_INPUT_FIELDS} fields.")
    result = {}
    for field, answer in value.items():
        if not _valid_field(field) or not isinstance(answer, str) or not 1 <= len(answer) <= MAX_INPUT_VALUE_CHARS:
            raise DynamicSkillInputError("entradas must contain valid fields and bounded, non-empty text values.")
        result[field] = answer
    return result


def extract_dynamic_skill_result(
    result: object,
) -> tuple[object, Mapping[str, object] | None, DynamicSkillInputRequest | None]:
    """Preserve legacy state behavior; validate the entire new input envelope."""
    if not isinstance(result, Mapping) or not any(
        isinstance(key, str) and key.startswith("__jarvis_input") for key in result
    ):
        data, state = extract_dynamic_skill_envelope(result)
        return data, state, None
    allowed = {JARVIS_DATA_KEY, JARVIS_STATE_KEY, JARVIS_INPUT_REQUEST_KEY}
    if set(result) - allowed or JARVIS_DATA_KEY not in result or JARVIS_INPUT_REQUEST_KEY not in result:
        raise DynamicSkillInputError("Input envelope contains unknown fields or lacks required fields.")
    if result[JARVIS_DATA_KEY] is not None:
        raise DynamicSkillInputError("An input request must have null __jarvis_data__; it is not a final result.")
    request = DynamicSkillInputRequest.from_mapping(result[JARVIS_INPUT_REQUEST_KEY])
    try:
        state = DynamicSkillStateStore.validate_state(result[JARVIS_STATE_KEY]) if JARVIS_STATE_KEY in result else None
    except ValueError as exc:
        raise DynamicSkillInputError(f"Invalid input-request state: {exc}") from exc
    return None, state, request


@dataclass(frozen=True)
class PendingDynamicSkillInput:
    skill_name: str
    source_hash: str
    metadata_hash: str
    user_id: str | None
    input_request: DynamicSkillInputRequest
    original_command: str
    parameters: Mapping[str, object]
    state: Mapping[str, object]
    continuation_count: int
    expires_at: float

    def __post_init__(self) -> None:
        if (not all(isinstance(v, str) for v in (self.skill_name, self.source_hash, self.metadata_hash))
                or not _IDENTIFIER.fullmatch(self.skill_name) or not _SHA256.fullmatch(self.source_hash) or not _SHA256.fullmatch(self.metadata_hash)):
            raise DynamicSkillInputError("Pending input requires a verified skill and SHA-256 bindings.")
        object.__setattr__(self, "parameters", MappingProxyType(deepcopy(dict(self.parameters))))
        object.__setattr__(self, "state", MappingProxyType(deepcopy(dict(self.state))))


@dataclass(frozen=True)
class DynamicSkillInputTurn:
    handled: bool
    message: str | None = None
    execution_result: SafeSkillExecutionResult | None = None
    pending_execution: PendingSkillExecution | None = None
    skill_name: str | None = None
    original_command: str | None = None


class DynamicSkillInputSession:
    """One RAM-only wait; the next real answer stays outside intent/chat routing.

    A wait is data, never authorization. Every answer goes through the existing
    execution gateway with both expected artifact hashes and a current grant.
    Without a matching grant it can require a fresh execution confirmation.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self.pending: PendingDynamicSkillInput | None = None
        self._in_flight: PendingDynamicSkillInput | None = None

    @property
    def has_pending_interaction(self) -> bool:
        """Include an answered input still waiting for fresh confirmation."""
        return self.pending is not None or self._in_flight is not None

    def cancel(self) -> None:
        self.pending = None
        self._in_flight = None

    def accept_result(
        self, result: SafeSkillExecutionResult, *, original_command: str, user_id: str | None,
    ) -> str | None:
        """Return a direct input prompt, or None for ordinary result synthesis."""
        prior = self._in_flight
        self.cancel()
        request = result.input_request
        if request is None:
            return None
        action = result.action
        if not (result.executed and result.allowed and result.hash_verified and action
                and result.policy_decision and result.policy_decision.kind is PolicyDecisionKind.ALLOW):
            raise DynamicSkillInputError("Only a verified authorized execution may request input.")
        source_hash = action.metadata.get("source_hash")
        metadata_hash = action.metadata.get("deployment_metadata_hash")
        parameters = action.metadata.get("parameters", {})
        original_command = parameters.get("comando", original_command)
        if (action.action != "execute_dynamic_skill" or action.metadata.get("skill_name") != result.skill_name
                or action.target != f"dynamic/{result.skill_name}.py#sha256-{source_hash}"):
            raise DynamicSkillInputError("Input request is not bound to an authorized skill target.")
        count = 0
        if prior is not None:
            if (prior.skill_name, prior.source_hash, prior.metadata_hash, prior.user_id) != (
                result.skill_name, source_hash, metadata_hash, user_id
            ):
                return "La skill o la identidad cambió; he cancelado la solicitud de datos."
            count = prior.continuation_count
        if count >= MAX_INPUT_CONTINUATIONS:
            return f"La skill sigue pidiendo datos tras {MAX_INPUT_CONTINUATIONS} continuaciones. He cancelado esta solicitud."
        self.pending = PendingDynamicSkillInput(
            result.skill_name, source_hash, metadata_hash, user_id, request,
            original_command, parameters, result.runtime_state or {}, count,
            self._clock() + INPUT_EXPIRY_SECONDS,
        )
        return request.prompt

    def handle_message(
        self, text: str, *, pipeline: SafeSkillPipeline, grants: SessionSkillGrantStore,
        identity: IdentityContext,
    ) -> DynamicSkillInputTurn:
        pending = self.pending
        if pending is None:
            return DynamicSkillInputTurn(False)
        self.pending = None
        normalized = "".join(c for c in unicodedata.normalize("NFKD", text.strip().casefold()) if not unicodedata.combining(c))
        if normalized in _CANCEL_WORDS:
            self.cancel()
            return DynamicSkillInputTurn(True, "Solicitud de datos cancelada.")
        if text.strip() == "/skill" or text.strip().startswith("/skill "):
            # The existing explicit authoring command is an unambiguous new
            # directive. Other prose remains an answer until explicit cancel.
            self.cancel()
            return DynamicSkillInputTurn(False)
        if self._clock() >= pending.expires_at or identity.user_id != pending.user_id:
            self.cancel()
            return DynamicSkillInputTurn(True, "La solicitud de datos caducó o cambió la identidad. Vuelve a solicitar la skill.")
        parameters = deepcopy(dict(pending.parameters))
        entries = dict(parameters.get("entradas", {}))
        entries[pending.input_request.field] = text
        try:
            parameters["entradas"] = validate_dynamic_skill_entries(entries)
        except DynamicSkillInputError:
            self.cancel()
            return DynamicSkillInputTurn(True, "La respuesta no cumple los límites de input; he cancelado la solicitud.")
        parameters["comando"] = pending.original_command
        self._in_flight = PendingDynamicSkillInput(
            pending.skill_name, pending.source_hash, pending.metadata_hash, pending.user_id,
            pending.input_request, pending.original_command, parameters, pending.state,
            pending.continuation_count + 1, pending.expires_at,
        )
        result = pipeline.execute_installed(
            pending.skill_name, identity=identity, parameters=parameters,
            session_skill_authorization=grants.authorization_for(pending.skill_name, pending.source_hash, identity.user_id),
            expected_source_hash=pending.source_hash, expected_metadata_hash=pending.metadata_hash,
            expected_user_id=pending.user_id,
        )
        if result.policy_decision and result.policy_decision.kind is PolicyDecisionKind.REQUIRE_CONFIRMATION and result.action:
            from jarvis.core.safe_skill_pipeline import PendingSkillExecution
            return DynamicSkillInputTurn(
                True, "Necesito confirmación fresca para continuar con esa skill.", result,
                PendingSkillExecution(pending.skill_name, parameters, result.action,
                                      pending.source_hash, pending.metadata_hash, pending.user_id),
                pending.skill_name, pending.original_command,
            )
        if not result.executed:
            self.cancel()
        return DynamicSkillInputTurn(True, execution_result=result,
                                    skill_name=pending.skill_name, original_command=pending.original_command)
