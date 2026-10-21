"""Immutable, data-only metadata for individual browser network exchanges.

These records validate structure, not provenance, capability relevance or
functional success. IDs must be non-secret identifiers assigned locally by
trusted infrastructure. No network access or response bodies are involved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from jarvis.core.browser_network_evidence import BrowserRequestEvidence

__all__ = [
    "BrowserResponseEvidence",
    "BrowserNetworkExchangeEvidence",
    "derive_response_format",
]

_MIME_TYPE = re.compile(r"[a-z0-9!#$%&'+.^_`|~-]+/[a-z0-9!#$%&'+.^_`|~-]+")
_RESPONSE_FORMATS = frozenset({"json", "html", "xml", "text", "binary", "unknown"})
_DELIVERIES = frozenset({"network", "cache", "service_worker", "unknown"})
_BYTES_KINDS = frozenset({"measured", "estimated", "unknown"})
_SEND_STATES = frozenset({"sent", "not_sent", "unknown"})
_COMPLETIONS = frozenset({"complete", "failed", "cancelled", "pending"})
_MAX_OBSERVED_BYTES = 1 << 40  # 1 TiB: a structural bound, not a collection budget.
_MAX_ID_LENGTH = 128


def _normalize_content_type(content_type: str) -> str:
    if not isinstance(content_type, str):
        raise ValueError("content_type must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in content_type):
        raise ValueError("content_type must not contain control characters or headers")
    if not content_type.strip():
        return ""
    mime = content_type.split(";", 1)[0].strip().lower()
    if _MIME_TYPE.fullmatch(mime) is None:
        raise ValueError("content_type must contain a MIME type/subtype")
    return mime


def derive_response_format(content_type: str) -> str:
    """Classify a normalized MIME declaration, without inspecting any body or URL."""
    mime = _normalize_content_type(content_type)
    if not mime:
        return "unknown"
    media_type, subtype = mime.split("/", 1)
    if mime in {"application/json", "text/json"} or (
        media_type == "application" and subtype.endswith("+json")
    ):
        return "json"
    if mime in {"text/html", "application/xhtml+xml"}:
        return "html"
    if mime in {"application/xml", "text/xml"} or (
        media_type == "application" and subtype.endswith("+xml")
    ):
        return "xml"
    if media_type == "text":
        return "text"
    if media_type in {"image", "audio", "video"} or mime == "application/octet-stream":
        return "binary"
    return "unknown"


def _normalize_response_url(response_url: str) -> str:
    if not isinstance(response_url, str) or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in response_url
    ):
        raise ValueError("response_url must be an absolute HTTP(S) URL without credentials")
    try:
        parsed = urlsplit(response_url)
        valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
        # Accessing port also rejects malformed and out-of-range port numbers.
        _ = parsed.port
    except ValueError:
        raise ValueError("response_url must be an absolute HTTP(S) URL without credentials") from None
    if not valid:
        raise ValueError("response_url must be an absolute HTTP(S) URL without credentials")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _require_enum(value: str, allowed: frozenset[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _normalize_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty local identifier")
    normalized = value.strip()
    if len(normalized) > _MAX_ID_LENGTH:
        raise ValueError(f"{field_name} must be <= 128 characters")
    return normalized


@dataclass(frozen=True, slots=True)
class BrowserResponseEvidence:
    """Sanitized HTTP response metadata; MIME classification is not body validation."""

    status_code: int
    content_type: str
    response_format: str
    response_url: str
    delivery: str
    observed_bytes: int | None
    observed_bytes_kind: str

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be an integer in 100..599, not bool")
        mime = _normalize_content_type(self.content_type)
        _require_enum(self.response_format, _RESPONSE_FORMATS, "response_format")
        if self.response_format != derive_response_format(mime):
            raise ValueError("response_format must match the format derived from content_type")
        _require_enum(self.delivery, _DELIVERIES, "delivery")
        _require_enum(self.observed_bytes_kind, _BYTES_KINDS, "observed_bytes_kind")
        if self.observed_bytes is None:
            if self.observed_bytes_kind != "unknown":
                raise ValueError("observed_bytes=None requires observed_bytes_kind=unknown")
        else:
            if type(self.observed_bytes) is not int or not 0 <= self.observed_bytes <= _MAX_OBSERVED_BYTES:
                raise ValueError("observed_bytes must be an integer in 0..1099511627776, not bool")
            if self.observed_bytes_kind not in {"measured", "estimated"}:
                raise ValueError("observed_bytes requires observed_bytes_kind=measured or estimated")
        safe_url = _normalize_response_url(self.response_url)
        object.__setattr__(self, "content_type", mime)
        object.__setattr__(self, "response_url", safe_url)


@dataclass(frozen=True, slots=True)
class BrowserNetworkExchangeEvidence:
    """One occurrence, with local structural references and no correlation heuristics.

    Request sanitization remains the responsibility of the existing request
    constructor. Phase/redirect existence and collection completeness belong
    to a future session contract, not this record.
    """

    exchange_id: str
    request: BrowserRequestEvidence
    send_state: str
    response: BrowserResponseEvidence | None
    completion: str
    phase_id: str
    start_sequence: int
    redirect_from_exchange_id: str | None

    def __post_init__(self) -> None:
        exchange_id = _normalize_id(self.exchange_id, "exchange_id")
        phase_id = _normalize_id(self.phase_id, "phase_id")
        if type(self.request) is not BrowserRequestEvidence:
            raise ValueError("request must be exactly BrowserRequestEvidence")
        if self.response is not None and not isinstance(self.response, BrowserResponseEvidence):
            raise ValueError("response must be BrowserResponseEvidence or None")
        _require_enum(self.send_state, _SEND_STATES, "send_state")
        _require_enum(self.completion, _COMPLETIONS, "completion")
        if type(self.start_sequence) is not int or self.start_sequence < 0:
            raise ValueError("start_sequence must be a non-negative integer, not bool")
        redirect_id = self.redirect_from_exchange_id
        if redirect_id is not None:
            redirect_id = _normalize_id(redirect_id, "redirect_from_exchange_id")
            if redirect_id == exchange_id:
                raise ValueError("redirect_from_exchange_id cannot equal exchange_id")
        if self.response is not None and self.send_state != "sent":
            raise ValueError("response requires send_state=sent")
        if self.completion == "complete" and (
            self.send_state != "sent" or self.response is None
        ):
            raise ValueError("completion=complete requires send_state=sent and a response")
        object.__setattr__(self, "exchange_id", exchange_id)
        object.__setattr__(self, "phase_id", phase_id)
        object.__setattr__(self, "redirect_from_exchange_id", redirect_id)
