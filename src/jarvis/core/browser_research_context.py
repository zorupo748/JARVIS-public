"""Immutable, data-only authorization context for future browser evaluation.

Construction validates structure, never trusted provenance, contract ownership
by a capability, observed execution or sufficiency. Trusted infrastructure must
supply non-secret identifiers and approve non-sensitive source paths.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from jarvis.core.browser_operation_contract import (
    BrowserOperationContract,
    BrowserOrigin,
    browser_origin_from_url,
    normalize_static_operation_path,
)

__all__ = [
    "BrowserAuthorizedInteraction",
    "BrowserResearchEvidenceLimits",
    "BrowserResearchEvaluationContext",
]

_INTERACTION_KINDS = frozenset({"submit", "click", "input_submit", "navigation"})
_CAPABILITY_REQUIREMENTS = frozenset({
    "ACCESS_PROCEDURE", "HTTP_STATUS", "RESPONSE_METADATA", "FUNCTIONAL_RESULT",
})
_DELIVERIES = frozenset({"network", "cache", "service_worker"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_ID_LENGTH = 128
_MAX_COLLECTION_ITEMS = 64
_MAX_STRUCTURAL_INTEGER = (1 << 63) - 1
_EVIDENCE_LIMIT_FIELDS = (
    "max_phases", "max_attributions", "max_exported_endpoint_observations",
    "max_exported_evidence_items", "max_exported_utf8_bytes",
)
_OPERATIONAL_MAXIMUM_FIELDS = (
    "max_duration_ms", "max_requests", "max_bytes", "max_redirects", "max_interactions",
)


def _normalize_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty local identifier")
    normalized = value.strip()
    if len(normalized) > _MAX_ID_LENGTH:
        raise ValueError(f"{field_name} must be <= 128 characters")
    return normalized


def _require_enum(value: str, allowed: frozenset[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _require_positive_integer(value: int, field_name: str) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_STRUCTURAL_INTEGER:
        raise ValueError(
            f"{field_name} must be an integer in 1..9223372036854775807, not bool"
        )


def _require_records(
    value: object, collection_type: type, record_type: type, field_name: str,
) -> None:
    if type(value) is not collection_type:
        raise ValueError(f"{field_name} must be exactly {collection_type.__name__}")
    if len(value) > _MAX_COLLECTION_ITEMS:
        raise ValueError(f"{field_name} must contain at most 64 items")
    if any(type(record) is not record_type for record in value):
        raise ValueError(f"{field_name} members must be exactly {record_type.__name__}")


def _normalize_source_url(value: str) -> tuple[str, BrowserOrigin]:
    if not isinstance(value, str) or any(
        character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159
        or character == "\\"
        for character in value
    ):
        raise ValueError(
            "source_url must be an absolute HTTP(S) URL without credentials, "
            "whitespace, control characters or backslashes"
        )
    origin = browser_origin_from_url(value)
    path = normalize_static_operation_path(urlsplit(value).path or "/")
    authority = origin.hostname
    if origin.effective_port != _DEFAULT_PORTS[origin.scheme]:
        authority = f"{authority}:{origin.effective_port}"
    return urlunsplit((origin.scheme, authority, path, "", "")), origin


@dataclass(frozen=True, slots=True)
class BrowserAuthorizedInteraction:
    """Authorization to attempt invoking a locally referenced operation contract.

    This neither establishes the reference's existence alone nor attributes all
    requests in an interaction phase to the contract, nor records execution.
    """

    interaction_id: str
    interaction_kind: str
    operation_contract_id: str

    def __post_init__(self) -> None:
        interaction_id = _normalize_id(self.interaction_id, "interaction_id")
        contract_id = _normalize_id(self.operation_contract_id, "operation_contract_id")
        _require_enum(self.interaction_kind, _INTERACTION_KINDS, "interaction_kind")
        object.__setattr__(self, "interaction_id", interaction_id)
        object.__setattr__(self, "operation_contract_id", contract_id)


@dataclass(frozen=True, slots=True)
class BrowserResearchEvidenceLimits:
    """Structural and export limits for a future evaluator to apply.

    These limits do not assess sufficiency, truncate, serialize or inspect
    research results. Their integer bound is representational, not policy.
    """

    max_phases: int
    max_attributions: int
    max_exported_endpoint_observations: int
    max_exported_evidence_items: int
    max_exported_utf8_bytes: int

    def __post_init__(self) -> None:
        for field_name in _EVIDENCE_LIMIT_FIELDS:
            _require_positive_integer(getattr(self, field_name), field_name)


@dataclass(frozen=True, slots=True)
class BrowserResearchEvaluationContext:
    """Explicit authorization and requirements, without evaluating any session.

    ACCESS_PROCEDURE requests structural access procedure evidence; HTTP_STATUS
    requests the operation's observed HTTP status; RESPONSE_METADATA requests
    declared response metadata such as MIME/format; FUNCTIONAL_RESULT requests
    the capability's actual semantic result. Representing any requirement does
    not establish that it is satisfied, including FUNCTIONAL_RESULT.

    Navigation and endpoint origins may differ; equality in each allowlist is
    exact. Contract membership in a capability belongs to an external trusted
    registry. Operational maxima authorize a future session, without comparing
    counters or limiting the number of registered interaction alternatives.
    """

    expected_session_id: str
    source_url: str
    capability_id: str
    capability_requirement: str
    allowed_navigation_origins: frozenset[BrowserOrigin]
    allowed_endpoint_origins: frozenset[BrowserOrigin]
    authorized_interactions: tuple[BrowserAuthorizedInteraction, ...]
    operation_contracts: tuple[BrowserOperationContract, ...]
    allowed_deliveries: frozenset[str]
    max_duration_ms: int
    max_requests: int
    max_bytes: int
    max_redirects: int
    max_interactions: int
    evidence_limits: BrowserResearchEvidenceLimits

    def __post_init__(self) -> None:
        session_id = _normalize_id(self.expected_session_id, "expected_session_id")
        capability_id = _normalize_id(self.capability_id, "capability_id")
        _require_enum(
            self.capability_requirement, _CAPABILITY_REQUIREMENTS, "capability_requirement",
        )
        source_url, source_origin = _normalize_source_url(self.source_url)
        for field_name in ("allowed_navigation_origins", "allowed_endpoint_origins"):
            _require_records(getattr(self, field_name), frozenset, BrowserOrigin, field_name)
        if not self.allowed_navigation_origins:
            raise ValueError("allowed_navigation_origins must not be empty")
        if source_origin not in self.allowed_navigation_origins:
            raise ValueError("source_url origin must belong to allowed_navigation_origins")
        _require_records(
            self.operation_contracts, tuple, BrowserOperationContract, "operation_contracts",
        )
        _require_records(
            self.authorized_interactions, tuple, BrowserAuthorizedInteraction,
            "authorized_interactions",
        )
        if self.operation_contracts and not self.allowed_endpoint_origins:
            raise ValueError("operation_contracts require non-empty allowed_endpoint_origins")
        if type(self.allowed_deliveries) is not frozenset or not self.allowed_deliveries:
            raise ValueError("allowed_deliveries must be exactly a non-empty frozenset")
        for delivery in self.allowed_deliveries:
            _require_enum(delivery, _DELIVERIES, "allowed_deliveries")
        for field_name in _OPERATIONAL_MAXIMUM_FIELDS:
            _require_positive_integer(getattr(self, field_name), field_name)
        if type(self.evidence_limits) is not BrowserResearchEvidenceLimits:
            raise ValueError("evidence_limits must be exactly BrowserResearchEvidenceLimits")

        contract_ids: set[str] = set()
        for contract in self.operation_contracts:
            if contract.contract_id in contract_ids:
                raise ValueError("contract_id values must be unique")
            contract_ids.add(contract.contract_id)
            if contract.authorized_origin not in self.allowed_endpoint_origins:
                raise ValueError("contract.authorized_origin must belong to allowed_endpoint_origins")
            if not contract.acceptable_deliveries.issubset(self.allowed_deliveries):
                raise ValueError("contract.acceptable_deliveries must be a subset of allowed_deliveries")

        interaction_ids: set[str] = set()
        for interaction in self.authorized_interactions:
            if interaction.interaction_id in interaction_ids:
                raise ValueError("interaction_id values must be unique")
            interaction_ids.add(interaction.interaction_id)
            if interaction.operation_contract_id not in contract_ids:
                raise ValueError("operation_contract_id must reference an existing operation_contract")

        object.__setattr__(self, "expected_session_id", session_id)
        object.__setattr__(self, "capability_id", capability_id)
        object.__setattr__(self, "source_url", source_url)
