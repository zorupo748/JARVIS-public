"""Immutable, structural browser research phases and sessions.

These records neither collect traffic nor establish trusted provenance,
causality, relevance or research sufficiency. ``sent`` denotes dispatch within
the controlled browser lifecycle, not proof of physical network transmission;
response delivery remains described by the exchange's response metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from jarvis.core.browser_exchange_evidence import BrowserNetworkExchangeEvidence

__all__ = ["BrowserResearchPhaseEvidence", "BrowserResearchSessionEvidence"]

_PHASE_KINDS = frozenset({"baseline", "interaction"})
_PHASE_STATUSES = frozenset({"complete", "failed", "cancelled"})
_INTERACTION_KINDS = frozenset({"submit", "click", "input_submit", "navigation", "other"})
_INTERACTION_RESULTS = frozenset({"completed", "failed", "unknown"})
_SESSION_STATUSES = frozenset({
    "complete", "timeout", "request_limit", "byte_limit", "redirect_limit",
    "interaction_limit", "navigation_error", "interaction_error", "collection_error",
})
_COUNTER_FIELDS = (
    "duration_ms", "request_count", "observed_bytes", "redirect_count", "interaction_count",
)
_LIMIT_FIELDS = (
    "max_duration_ms", "max_requests", "max_bytes", "max_redirects", "max_interactions",
)
_LIMIT_TERMINATIONS = {
    "timeout": ("duration_ms", "max_duration_ms"),
    "request_limit": ("request_count", "max_requests"),
    "byte_limit": ("observed_bytes", "max_bytes"),
    "redirect_limit": ("redirect_count", "max_redirects"),
    "interaction_limit": ("interaction_count", "max_interactions"),
}
_MAX_ID_LENGTH = 128
_MAX_STRUCTURAL_INTEGER = (1 << 63) - 1  # Representation bound, not an operational budget.


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


def _require_integer(
    value: int, field_name: str, *, minimum: int = 0, maximum: int | None = None,
) -> None:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{field_name} must be an integer >= {minimum}, not bool")
    if maximum is not None and value > maximum:
        raise ValueError(f"{field_name} exceeds the signed 64-bit structural bound")


def _normalize_page_url(value: str, field_name: str) -> str:
    message = f"{field_name} must be an absolute HTTP(S) URL without credentials"
    if not isinstance(value, str) or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ):
        raise ValueError(message)
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
        _ = parsed.port
    except ValueError:
        raise ValueError(message) from None
    if not valid:
        raise ValueError(message)
    # Paths are preserved; determining sensitive paths is outside this layer.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


@dataclass(frozen=True, slots=True)
class BrowserResearchPhaseEvidence:
    """An inclusive observation interval, without a claim of interaction causality."""

    phase_id: str
    kind: str
    start_sequence: int
    end_sequence: int
    collection_status: str
    interaction_id: str | None
    interaction_kind: str | None
    interaction_result: str | None

    def __post_init__(self) -> None:
        phase_id = _normalize_id(self.phase_id, "phase_id")
        _require_enum(self.kind, _PHASE_KINDS, "kind")
        _require_enum(self.collection_status, _PHASE_STATUSES, "collection_status")
        _require_integer(self.start_sequence, "start_sequence")
        _require_integer(self.end_sequence, "end_sequence", minimum=self.start_sequence)
        interaction_id = self.interaction_id
        if self.kind == "baseline":
            if any(value is not None for value in (
                self.interaction_id, self.interaction_kind, self.interaction_result,
            )):
                raise ValueError("baseline requires all interaction fields to be None")
        else:
            interaction_id = _normalize_id(interaction_id, "interaction_id")
            _require_enum(self.interaction_kind, _INTERACTION_KINDS, "interaction_kind")
            _require_enum(self.interaction_result, _INTERACTION_RESULTS, "interaction_result")
        object.__setattr__(self, "phase_id", phase_id)
        object.__setattr__(self, "interaction_id", interaction_id)


@dataclass(frozen=True, slots=True)
class BrowserResearchSessionEvidence:
    """Collection metadata and reference integrity, without any sufficiency decision.

    Counters and budgets have a signed 64-bit structural maximum. Known byte
    totals include measured and estimated response sizes, omit unknown sizes,
    and do not imply that every response's size was observable.
    """

    session_id: str
    initial_page_url: str
    final_page_url: str | None
    initial_navigation_exchange_id: str | None
    collection_status: str
    duration_ms: int
    request_count: int
    observed_bytes: int
    redirect_count: int
    interaction_count: int
    max_duration_ms: int
    max_requests: int
    max_bytes: int
    max_redirects: int
    max_interactions: int
    lost_events: bool
    phases: tuple[BrowserResearchPhaseEvidence, ...]
    exchanges: tuple[BrowserNetworkExchangeEvidence, ...]

    def __post_init__(self) -> None:
        session_id = _normalize_id(self.session_id, "session_id")
        initial_url = _normalize_page_url(self.initial_page_url, "initial_page_url")
        final_url = (
            None if self.final_page_url is None
            else _normalize_page_url(self.final_page_url, "final_page_url")
        )
        _require_enum(self.collection_status, _SESSION_STATUSES, "collection_status")
        if type(self.lost_events) is not bool:
            raise ValueError("lost_events must be exactly bool")
        if self.collection_status == "complete" and self.lost_events:
            raise ValueError("collection_status=complete requires lost_events=False")
        for field_name in _COUNTER_FIELDS:
            _require_integer(
                getattr(self, field_name), field_name, maximum=_MAX_STRUCTURAL_INTEGER,
            )
        for field_name in _LIMIT_FIELDS:
            _require_integer(
                getattr(self, field_name), field_name,
                minimum=1, maximum=_MAX_STRUCTURAL_INTEGER,
            )
        for records, record_type, field_name in (
            (self.phases, BrowserResearchPhaseEvidence, "phases"),
            (self.exchanges, BrowserNetworkExchangeEvidence, "exchanges"),
        ):
            if type(records) is not tuple or any(type(record) is not record_type for record in records):
                raise ValueError(f"{field_name} must be a tuple of {record_type.__name__}")

        phases_by_id: dict[str, BrowserResearchPhaseEvidence] = {}
        previous_phase: BrowserResearchPhaseEvidence | None = None
        for phase in self.phases:
            if phase.phase_id in phases_by_id:
                raise ValueError("phase_id values must be unique")
            if previous_phase is not None:
                if phase.start_sequence < previous_phase.start_sequence:
                    raise ValueError("phases must be ordered by start_sequence")
                if phase.start_sequence <= previous_phase.end_sequence:
                    raise ValueError("phase intervals must not overlap")
            phases_by_id[phase.phase_id] = phase
            previous_phase = phase
        if self.collection_status == "complete" and any(
            phase.collection_status != "complete" for phase in self.phases
        ):
            raise ValueError("collection_status=complete requires every phase to be complete")

        exchanges_by_id: dict[str, BrowserNetworkExchangeEvidence] = {}
        start_sequences: set[int] = set()
        for exchange in self.exchanges:
            if exchange.exchange_id in exchanges_by_id:
                raise ValueError("exchange_id values must be unique")
            if exchange.start_sequence in start_sequences:
                raise ValueError("exchange start_sequence values must be unique")
            phase = phases_by_id.get(exchange.phase_id)
            if phase is None:
                raise ValueError("exchange.phase_id must reference an existing phase")
            if not phase.start_sequence <= exchange.start_sequence <= phase.end_sequence:
                raise ValueError("exchange.start_sequence must fall within its phase interval")
            exchanges_by_id[exchange.exchange_id] = exchange
            start_sequences.add(exchange.start_sequence)
        for exchange in self.exchanges:
            redirect_id = exchange.redirect_from_exchange_id
            if redirect_id is not None:
                predecessor = exchanges_by_id.get(redirect_id)
                if predecessor is None:
                    raise ValueError("redirect_from_exchange_id must reference an existing exchange")
                if predecessor.start_sequence >= exchange.start_sequence:
                    raise ValueError("redirect must reference an exchange with strictly earlier start_sequence")

        navigation_id = self.initial_navigation_exchange_id
        if navigation_id is not None:
            navigation_id = _normalize_id(navigation_id, "initial_navigation_exchange_id")
            navigation = exchanges_by_id.get(navigation_id)
            if navigation is None:
                raise ValueError("initial_navigation_exchange_id must reference an existing exchange")
            if phases_by_id[navigation.phase_id].kind != "baseline":
                raise ValueError("initial_navigation_exchange_id must belong to a baseline phase")

        expected_counts = {
            "request_count": len(self.exchanges),
            "interaction_count": sum(phase.kind == "interaction" for phase in self.phases),
            "redirect_count": sum(
                exchange.redirect_from_exchange_id is not None for exchange in self.exchanges
            ),
            "observed_bytes": sum(
                exchange.response.observed_bytes for exchange in self.exchanges
                if exchange.response is not None and exchange.response.observed_bytes is not None
            ),
        }
        for field_name, expected in expected_counts.items():
            if getattr(self, field_name) != expected:
                raise ValueError(f"{field_name} must equal the total represented by the evidence")
        if self.collection_status == "complete":
            for counter_name, maximum_name in _LIMIT_TERMINATIONS.values():
                if getattr(self, counter_name) > getattr(self, maximum_name):
                    raise ValueError(
                        f"collection_status=complete requires {counter_name} <= {maximum_name}"
                    )
        limit_fields = _LIMIT_TERMINATIONS.get(self.collection_status)
        if limit_fields is not None:
            counter_name, maximum_name = limit_fields
            if getattr(self, counter_name) < getattr(self, maximum_name):
                raise ValueError(f"{self.collection_status} requires {counter_name} >= {maximum_name}")

        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "initial_page_url", initial_url)
        object.__setattr__(self, "final_page_url", final_url)
        object.__setattr__(self, "initial_navigation_exchange_id", navigation_id)
