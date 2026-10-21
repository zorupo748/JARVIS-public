"""Immutable authorization and intent records for future browser discovery.

Trusted infrastructure supplies non-secret local references and approved source
paths. Construction validates structure without establishing provenance,
execution, causality or research sufficiency. Targets and values stay opaque;
there is no resolver, serializer or comparison with collected evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from jarvis.core.browser_operation_contract import (
    BrowserOrigin,
    browser_origin_from_url,
    normalize_static_operation_path,
)

__all__ = (
    "BrowserDiscoveryAuthorization",
    "BrowserInteractionValueBinding",
    "BrowserInteractionStep",
    "BrowserInteractionPlan",
)

_INTERACTION_KINDS = frozenset({"click", "submit", "input_submit", "navigation"})
_EXPECTED_EFFECTS = frozenset({"navigation", "native_submission", "network_activity", "none"})
_SUBMISSION_EFFECTS = frozenset({"native_submission", "navigation", "network_activity"})
_CLICK_EFFECTS = frozenset({"navigation", "network_activity", "none"})
_LIMIT_FIELDS = (
    "max_duration_ms", "max_requests", "max_bytes", "max_redirects", "max_interactions",
    "max_dom_targets", "max_plan_steps", "max_candidates",
)
_MAX_ID_LENGTH = 128
_MAX_ORIGINS = 16
_MAX_BINDINGS = 32
_MAX_STEPS = 64
_MAX_STRUCTURAL_INTEGER = (1 << 63) - 1


def _plain_string(value: str, field_name: str) -> str:
    # Inspect the actual type, without consulting an input's __class__ property
    # or invoking overridden str methods. Discard mutable subclass state.
    if not issubclass(type(value), str):
        raise ValueError(f"{field_name} must be a string")
    return str.__str__(value)


def _normalize_id(value: str, field_name: str) -> str:
    normalized = _plain_string(value, field_name).strip()
    if not 1 <= len(normalized) <= _MAX_ID_LENGTH:
        raise ValueError(f"{field_name} must contain 1..128 characters after stripping")
    return normalized


def _require_enum(value: str, allowed: frozenset[str], field_name: str) -> str:
    canonical = _plain_string(value, field_name)
    if canonical not in allowed:
        raise ValueError(f"{field_name} must be a V1 enum value")
    return canonical


def _normalize_source_url(value: str) -> tuple[str, BrowserOrigin]:
    source = _plain_string(value, "source_url")
    if any(
        character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159
        or character == "\\"
        for character in source
    ):
        raise ValueError("source_url must not contain whitespace, controls or backslashes")
    # Discard values before parsing too, so URL-parser caches cannot retain them.
    source = source.partition("#")[0].partition("?")[0]
    origin = browser_origin_from_url(source)
    path = normalize_static_operation_path(urlsplit(source).path or "/")
    authority = origin.hostname
    default_port = 443 if origin.scheme == "https" else 80
    if origin.effective_port != default_port:
        authority = f"{authority}:{origin.effective_port}"
    return urlunsplit((origin.scheme, authority, path, "", "")), origin


def _require_positive_integer(value: int, field_name: str) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_STRUCTURAL_INTEGER:
        raise ValueError(f"{field_name} must be an integer in 1..9223372036854775807, not bool")


@dataclass(frozen=True, slots=True)
class BrowserDiscoveryAuthorization:
    """Declared collection permissions and maxima, without execution evidence.

    Multiple exact origins may be authorized for a future collector; this does
    not broaden the evaluator's V1 sufficiency policy. Limits are authorized
    maxima, not observed counters. Approving a source path and establishing
    trusted provenance belong to the infrastructure supplying this record.
    """

    authorization_id: str
    expected_session_id: str
    source_url: str
    allowed_origins: frozenset[BrowserOrigin]
    allowed_interaction_kinds: frozenset[str]
    max_duration_ms: int
    max_requests: int
    max_bytes: int
    max_redirects: int
    max_interactions: int
    max_dom_targets: int
    max_plan_steps: int
    max_candidates: int

    def __post_init__(self) -> None:
        authorization_id = _normalize_id(self.authorization_id, "authorization_id")
        session_id = _normalize_id(self.expected_session_id, "expected_session_id")
        source_url, source_origin = _normalize_source_url(self.source_url)
        if type(self.allowed_origins) is not frozenset:
            raise ValueError("allowed_origins must be exactly frozenset")
        if not 1 <= len(self.allowed_origins) <= _MAX_ORIGINS:
            raise ValueError("allowed_origins must contain 1..16 origins")
        origins: list[BrowserOrigin] = []
        for origin in self.allowed_origins:
            if type(origin) is not BrowserOrigin:
                raise ValueError("allowed_origins members must be exactly BrowserOrigin")
            # The existing BrowserOrigin accepts str subclasses; detach their
            # scalar content to preserve transitive immutability here as well.
            if type(origin.scheme) is not str or type(origin.hostname) is not str:
                origin = BrowserOrigin(
                    _plain_string(origin.scheme, "origin scheme"),
                    _plain_string(origin.hostname, "origin hostname"), origin.effective_port,
                )
            origins.append(origin)
        allowed_origins = frozenset(origins)
        if source_origin not in allowed_origins:
            raise ValueError("source_url origin must belong to allowed_origins")

        if type(self.allowed_interaction_kinds) is not frozenset:
            raise ValueError("allowed_interaction_kinds must be exactly frozenset")
        if not 1 <= len(self.allowed_interaction_kinds) <= len(_INTERACTION_KINDS):
            raise ValueError("allowed_interaction_kinds must contain 1..4 kinds")
        interaction_kinds = frozenset(
            _require_enum(kind, _INTERACTION_KINDS, "allowed_interaction_kinds")
            for kind in self.allowed_interaction_kinds
        )
        for field_name in _LIMIT_FIELDS:
            _require_positive_integer(getattr(self, field_name), field_name)

        object.__setattr__(self, "authorization_id", authorization_id)
        object.__setattr__(self, "expected_session_id", session_id)
        object.__setattr__(self, "source_url", source_url)
        object.__setattr__(self, "allowed_origins", allowed_origins)
        object.__setattr__(self, "allowed_interaction_kinds", interaction_kinds)


@dataclass(frozen=True, slots=True)
class BrowserInteractionValueBinding:
    """Opaque references to a future registered control and ephemeral value.

    Infrastructure must supply local, non-secret IDs, without embedding values,
    selectors or DOM text. This record cannot establish that provenance and
    never resolves either reference.
    """

    target_id: str
    value_ref: str

    def __post_init__(self) -> None:
        target_id = _normalize_id(self.target_id, "target_id")
        value_ref = _normalize_id(self.value_ref, "value_ref")
        object.__setattr__(self, "target_id", target_id)
        object.__setattr__(self, "value_ref", value_ref)


@dataclass(frozen=True, slots=True)
class BrowserInteractionStep:
    """An intended interaction with an operational expectation, never attribution.

    Binding targets must be locally unique; their existence and that of the
    activation target remain unchecked. Expectations neither demonstrate an
    action occurred nor cause later requests to be attributed to this step.
    """

    interaction_id: str
    interaction_kind: str
    activation_target_id: str
    value_bindings: tuple[BrowserInteractionValueBinding, ...]
    expected_effect: str

    def __post_init__(self) -> None:
        interaction_id = _normalize_id(self.interaction_id, "interaction_id")
        interaction_kind = _require_enum(self.interaction_kind, _INTERACTION_KINDS, "interaction_kind")
        activation_target_id = _normalize_id(self.activation_target_id, "activation_target_id")
        expected_effect = _require_enum(self.expected_effect, _EXPECTED_EFFECTS, "expected_effect")
        if type(self.value_bindings) is not tuple:
            raise ValueError("value_bindings must be exactly tuple")
        if len(self.value_bindings) > _MAX_BINDINGS:
            raise ValueError("value_bindings must contain at most 32 bindings")
        seen: set[str] = set()
        for binding in self.value_bindings:
            if type(binding) is not BrowserInteractionValueBinding:
                raise ValueError("value_bindings members must be exactly BrowserInteractionValueBinding")
            if binding.target_id in seen:
                raise ValueError("value_bindings target_id values must be unique")
            seen.add(binding.target_id)
        if interaction_kind in {"click", "navigation"} and self.value_bindings:
            raise ValueError("click and navigation require empty value_bindings")
        if interaction_kind == "input_submit" and not self.value_bindings:
            raise ValueError("input_submit requires at least one value binding")
        if interaction_kind == "navigation":
            if expected_effect != "navigation":
                raise ValueError("navigation requires expected_effect navigation")
        elif interaction_kind in {"submit", "input_submit"}:
            if expected_effect not in _SUBMISSION_EFFECTS:
                raise ValueError("submission requires a compatible expected_effect")
        elif expected_effect not in _CLICK_EFFECTS:
            raise ValueError("click requires a compatible expected_effect")

        object.__setattr__(self, "interaction_id", interaction_id)
        object.__setattr__(self, "interaction_kind", interaction_kind)
        object.__setattr__(self, "activation_target_id", activation_target_id)
        object.__setattr__(self, "expected_effect", expected_effect)


@dataclass(frozen=True, slots=True)
class BrowserInteractionPlan:
    """An ordered plan, independent of authorization and collection records.

    A future collector checks authorization/session identity, authorized kinds
    and the authorized step limit. This record only validates structure and
    local interaction-ID uniqueness; it executes and resolves nothing.
    """

    plan_id: str
    authorization_id: str
    session_id: str
    steps: tuple[BrowserInteractionStep, ...]

    def __post_init__(self) -> None:
        plan_id = _normalize_id(self.plan_id, "plan_id")
        authorization_id = _normalize_id(self.authorization_id, "authorization_id")
        session_id = _normalize_id(self.session_id, "session_id")
        if type(self.steps) is not tuple:
            raise ValueError("steps must be exactly tuple")
        if len(self.steps) > _MAX_STEPS:
            raise ValueError("steps must contain at most 64 interactions")
        seen: set[str] = set()
        for step in self.steps:
            if type(step) is not BrowserInteractionStep:
                raise ValueError("steps members must be exactly BrowserInteractionStep")
            if step.interaction_id in seen:
                raise ValueError("steps interaction_id values must be unique")
            seen.add(step.interaction_id)

        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "authorization_id", authorization_id)
        object.__setattr__(self, "session_id", session_id)
