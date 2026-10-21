"""Immutable discovery observations, without approval or semantic claims.

Infrastructure supplies non-secret local IDs, independently justified static
paths and the grouping of occurrences. Construction validates structure alone;
it cannot establish provenance, grouping correctness, causality, authorization
or functional success. These records remain internal and have no serializer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from jarvis.core.browser_exchange_evidence import derive_response_format
from jarvis.core.browser_operation_contract import (
    BrowserOrigin,
    normalize_static_operation_path,
)

__all__ = ("BrowserOperationCandidateOccurrence", "BrowserOperationCandidate")

_SEND_STATES = frozenset({"sent", "not_sent", "unknown"})
_RESPONSE_FORMATS = frozenset({"json", "html", "xml", "text", "binary", "unknown"})
_DELIVERIES = frozenset({"network", "cache", "service_worker", "unknown"})
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_PARAMETER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_MAX_ID_LENGTH = 128
_MAX_NAME_LENGTH = 64
_MAX_PARAMETER_NAMES = 64
_MAX_OCCURRENCES = 64


def _normalize_id(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a non-empty local identifier")
    normalized = str.strip(value)
    if not normalized or len(normalized) > _MAX_ID_LENGTH:
        raise ValueError(f"{field_name} must contain 1..128 characters after stripping")
    return normalized


def _require_enum(value: str, allowed: frozenset[str], field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a V1 enum string")
    # Preserve spelling while discarding any mutable state or overridden methods
    # of a str subclass. Only IDs are whitespace-normalized.
    canonical = str.__str__(value)
    if canonical not in allowed:
        raise ValueError(f"{field_name} must be a V1 enum string")
    return canonical


def _require_parameter_names(names: tuple[str, ...] | None, field_name: str) -> None:
    if names is None:
        return
    if type(names) is not tuple:
        raise ValueError(f"{field_name} must be exactly tuple or None")
    if len(names) > _MAX_PARAMETER_NAMES:
        raise ValueError(f"{field_name} must contain at most 64 names")
    seen: set[str] = set()
    for name in names:
        if (
            type(name) is not str
            or not 1 <= len(name) <= _MAX_NAME_LENGTH
            or _PARAMETER_NAME.fullmatch(name) is None
        ):
            raise ValueError(f"{field_name} must contain V1 ASCII names of 1..64 characters")
        if name in seen:
            raise ValueError(f"{field_name} must not contain duplicate names")
        seen.add(name)


@dataclass(frozen=True, slots=True)
class BrowserOperationCandidateOccurrence:
    """One locally referenced observation; response metadata is all-or-none.

    Missing response metadata is permitted even for a sent request. A response
    establishes only that it was observed for a sent request, without a body,
    completion claim, verified reference or interpretation of its HTTP status.
    """

    exchange_id: str
    phase_id: str
    interaction_id: str | None
    send_state: str
    response_status_code: int | None
    response_format: str | None
    response_content_type: str | None
    response_delivery: str | None

    def __post_init__(self) -> None:
        exchange_id = _normalize_id(self.exchange_id, "exchange_id")
        phase_id = _normalize_id(self.phase_id, "phase_id")
        interaction_id = (
            None if self.interaction_id is None
            else _normalize_id(self.interaction_id, "interaction_id")
        )
        send_state = _require_enum(self.send_state, _SEND_STATES, "send_state")
        response_fields = (
            self.response_status_code, self.response_format,
            self.response_content_type, self.response_delivery,
        )
        absent = tuple(value is None for value in response_fields)
        if any(absent) and not all(absent):
            raise ValueError("response metadata must be all present or all None")
        if not all(absent):
            if send_state != "sent":
                raise ValueError("observed response metadata requires send_state sent")
            if type(self.response_status_code) is not int or not 100 <= self.response_status_code <= 599:
                raise ValueError("response_status_code must be an integer in 100..599, not bool")
            response_format = _require_enum(
                self.response_format, _RESPONSE_FORMATS, "response_format",
            )
            response_delivery = _require_enum(
                self.response_delivery, _DELIVERIES, "response_delivery",
            )
            if not isinstance(self.response_content_type, str):
                raise ValueError("response_content_type must be a canonical MIME string")
            content_type = str.__str__(self.response_content_type)
            if (
                content_type != content_type.strip()
                or content_type != content_type.lower()
                or ";" in content_type
            ):
                raise ValueError("response_content_type must be lowercase MIME without parameters")
            if derive_response_format(content_type) != response_format:
                raise ValueError("response_format must match the declared MIME classification")
            object.__setattr__(self, "response_format", response_format)
            object.__setattr__(self, "response_content_type", content_type)
            object.__setattr__(self, "response_delivery", response_delivery)

        object.__setattr__(self, "exchange_id", exchange_id)
        object.__setattr__(self, "phase_id", phase_id)
        object.__setattr__(self, "interaction_id", interaction_id)
        object.__setattr__(self, "send_state", send_state)


@dataclass(frozen=True, slots=True)
class BrowserOperationCandidate:
    """Structural discovery facts grouped under an infrastructure-supplied ID.

    None parameter names denote unknown structure; () denotes known absence.
    Names are observed, without declaring constraints or requirements. None for
    static_path denotes insufficient independent evidence for an exportable
    static path, never absence of an HTTP path. Syntax validation cannot decide
    whether a path contains user values or whether occurrences belong together.
    Reference existence and any later promotion belong to other layers.
    """

    candidate_id: str
    session_id: str
    observed_method: str
    observed_origin: BrowserOrigin
    static_path: str | None
    observed_query_parameter_names: tuple[str, ...] | None
    observed_body_parameter_names: tuple[str, ...] | None
    occurrences: tuple[BrowserOperationCandidateOccurrence, ...]

    def __post_init__(self) -> None:
        candidate_id = _normalize_id(self.candidate_id, "candidate_id")
        session_id = _normalize_id(self.session_id, "session_id")
        observed_method = _require_enum(self.observed_method, _HTTP_METHODS, "observed_method")
        if type(self.observed_origin) is not BrowserOrigin:
            raise ValueError("observed_origin must be exactly BrowserOrigin")
        observed_origin = self.observed_origin
        # BrowserOrigin accepts str subclasses. Copy their scalar content so
        # this record cannot retain mutable state nested inside that origin.
        if type(observed_origin.scheme) is not str or type(observed_origin.hostname) is not str:
            observed_origin = BrowserOrigin(
                str.__str__(observed_origin.scheme), str.__str__(observed_origin.hostname),
                observed_origin.effective_port,
            )
        static_path = self.static_path
        if static_path is not None:
            if not isinstance(static_path, str):
                raise ValueError("static_path must be a V1 static path string or None")
            static_path = normalize_static_operation_path(str.__str__(static_path))
        for field_name in ("observed_query_parameter_names", "observed_body_parameter_names"):
            _require_parameter_names(getattr(self, field_name), field_name)
        if type(self.occurrences) is not tuple:
            raise ValueError("occurrences must be exactly tuple")
        if not 1 <= len(self.occurrences) <= _MAX_OCCURRENCES:
            raise ValueError("occurrences must contain 1..64 observations")
        seen: set[str] = set()
        for occurrence in self.occurrences:
            if type(occurrence) is not BrowserOperationCandidateOccurrence:
                raise ValueError("occurrences members must be exactly BrowserOperationCandidateOccurrence")
            if occurrence.exchange_id in seen:
                raise ValueError("occurrences exchange_id values must be unique")
            seen.add(occurrence.exchange_id)

        object.__setattr__(self, "candidate_id", candidate_id)
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "observed_method", observed_method)
        object.__setattr__(self, "observed_origin", observed_origin)
        object.__setattr__(self, "static_path", static_path)
