"""Immutable, data-only contracts for previously approved browser operations.

Validation establishes structure, never trusted provenance or functional
success. Future infrastructure must supply contracts from its trusted registry.
Identifiers and static paths must be non-secret; only parameter names are
stored. Optional unknown constraints remain None, never wildcards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = [
    "BrowserOrigin",
    "browser_origin_from_url",
    "normalize_static_operation_path",
    "BrowserOperationContract",
]

_SCHEMES = frozenset({"http", "https"})
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_RESPONSE_FORMATS = frozenset({"json", "html", "xml", "text", "binary"})
_DELIVERIES = frozenset({"network", "cache", "service_worker"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NUMERIC_HOST_SUFFIX = re.compile(r"(?:[0-9]+|0x[0-9a-f]+)")
_URL_AUTHORITY = re.compile(r"[A-Za-z0-9.-]+(?::[0-9]+)?")
_STATIC_PATH = re.compile(r"/[A-Za-z0-9._~/-]*")
_PARAMETER_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_MAX_ID_LENGTH = 128
_MAX_HOSTNAME_LENGTH = 253
_MAX_NAME_LENGTH = 64
_MAX_PARAMETER_NAMES = 64


def _require_enum(value: str, allowed: frozenset[str], field_name: str) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(f"{field_name} must be one of: {', '.join(sorted(allowed))}")


def _require_hostname(hostname: str) -> None:
    if (
        not isinstance(hostname, str)
        or not hostname
        or len(hostname) > _MAX_HOSTNAME_LENGTH
        or not hostname.isascii()
        or hostname != hostname.lower()
    ):
        raise ValueError("hostname must be a canonical lowercase ASCII DNS hostname")
    labels = hostname.split(".")
    if any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("hostname must contain DNS labels of 1..63 characters")
    # Numeric terminal labels can be interpreted as IPv4, including shortened,
    # integer, octal and hexadecimal forms. V1 rejects these ambiguous hosts.
    if _NUMERIC_HOST_SUFFIX.fullmatch(labels[-1]) is not None:
        raise ValueError("hostname must be a DNS hostname, not an IP literal")


@dataclass(frozen=True, slots=True)
class BrowserOrigin:
    """A canonical HTTP(S) DNS origin; no DNS resolution or provenance claim."""

    scheme: str
    hostname: str
    effective_port: int

    def __post_init__(self) -> None:
        _require_enum(self.scheme, _SCHEMES, "scheme")
        _require_hostname(self.hostname)
        if type(self.effective_port) is not int or not 1 <= self.effective_port <= 65535:
            raise ValueError("effective_port must be an integer in 1..65535, not bool")

    def to_string(self) -> str:
        """Render the origin deterministically, always including its port."""
        return f"{self.scheme}://{self.hostname}:{self.effective_port}"


def browser_origin_from_url(url: str) -> BrowserOrigin:
    """Derive an origin from an absolute HTTP(S) URL, discarding other parts.

    Only ASCII DNS authorities are supported; Unicode hosts are not converted to
    IDNA. Structurally valid ASCII A-labels are accepted as DNS labels.
    """
    message = "url must be an absolute HTTP(S) URL with a DNS hostname and no credentials"
    if not isinstance(url, str) or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        or character == "\\"
        for character in url
    ):
        raise ValueError(message)
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in _SCHEMES
            or _URL_AUTHORITY.fullmatch(parsed.netloc) is None
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.hostname
        ):
            raise ValueError(message)
        port = parsed.port
    except ValueError:
        raise ValueError(message) from None
    return BrowserOrigin(
        scheme=parsed.scheme,
        hostname=parsed.hostname,
        effective_port=_DEFAULT_PORTS[parsed.scheme] if port is None else port,
    )


def normalize_static_operation_path(path: str) -> str:
    """Validate a V1 static path, preserving case and significant trailing slash.

    Only slash separators and ASCII unreserved segment characters are accepted.
    No decoding, whitespace stripping or dot-segment normalization is performed.
    """
    if not isinstance(path, str) or _STATIC_PATH.fullmatch(path) is None:
        raise ValueError("path must start with / and contain only V1 safe ASCII characters")
    if "//" in path or any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("path must not contain consecutive slashes or dot segments")
    return path


def _require_frozenset(
    value: object, field_name: str, *, allow_none: bool = False, nonempty: bool = False,
) -> None:
    if value is None and allow_none:
        return
    if type(value) is not frozenset:
        message = f"{field_name} must be exactly frozenset"
        raise ValueError(message + (" or None" if allow_none else ""))
    if nonempty and not value:
        raise ValueError(f"{field_name} must not be empty")


def _require_parameter_names(
    names: frozenset[str] | None, field_name: str, *, allow_none: bool = False,
) -> None:
    _require_frozenset(names, field_name, allow_none=allow_none)
    if names is None:
        return
    if len(names) > _MAX_PARAMETER_NAMES:
        raise ValueError(f"{field_name} must contain at most 64 names")
    if any(
        not isinstance(name, str)
        or len(name) > _MAX_NAME_LENGTH
        or _PARAMETER_NAME.fullmatch(name) is None
        for name in names
    ):
        raise ValueError(f"{field_name} must contain V1 ASCII parameter names of 1..64 characters")


def _require_enum_collection(
    values: frozenset[str] | None, allowed: frozenset[str], field_name: str,
    *, allow_none: bool = False,
) -> None:
    _require_frozenset(values, field_name, allow_none=allow_none, nonempty=True)
    if values is not None:
        for value in values:
            _require_enum(value, allowed, field_name)


@dataclass(frozen=True, slots=True)
class BrowserOperationContract:
    """Previously approved constraints, without traffic observation or inference.

    None denotes unknown constraints; empty expected parameter sets forbid all
    parameters at that location. Required names must be explicitly demonstrated
    and declared, never inferred from observation by this record. The two boolean
    requirements are independent and do not assert sufficiency.
    """

    contract_id: str
    http_method: str
    authorized_origin: BrowserOrigin
    expected_path: str
    expected_query_parameter_names: frozenset[str] | None
    expected_body_parameter_names: frozenset[str] | None
    demonstrated_required_query_parameter_names: frozenset[str]
    demonstrated_required_body_parameter_names: frozenset[str]
    acceptable_response_formats: frozenset[str] | None
    acceptable_http_statuses: frozenset[int] | None
    acceptable_deliveries: frozenset[str]
    requires_response_content: bool
    requires_functional_evidence: bool

    def __post_init__(self) -> None:
        if not isinstance(self.contract_id, str) or not self.contract_id.strip():
            raise ValueError("contract_id must be a non-empty local identifier")
        contract_id = self.contract_id.strip()
        if len(contract_id) > _MAX_ID_LENGTH:
            raise ValueError("contract_id must be <= 128 characters")
        _require_enum(self.http_method, _HTTP_METHODS, "http_method")
        if type(self.authorized_origin) is not BrowserOrigin:
            raise ValueError("authorized_origin must be exactly BrowserOrigin")
        normalize_static_operation_path(self.expected_path)
        for location in ("query", "body"):
            expected_field = f"expected_{location}_parameter_names"
            required_field = f"demonstrated_required_{location}_parameter_names"
            expected = getattr(self, expected_field)
            required = getattr(self, required_field)
            _require_parameter_names(expected, expected_field, allow_none=True)
            _require_parameter_names(required, required_field)
            if expected is None:
                if required:
                    raise ValueError(f"{required_field} must be empty when {expected_field} is None")
            elif not required.issubset(expected):
                raise ValueError(f"{required_field} must be a subset of {expected_field}")
        _require_enum_collection(
            self.acceptable_response_formats, _RESPONSE_FORMATS,
            "acceptable_response_formats", allow_none=True,
        )
        _require_frozenset(
            self.acceptable_http_statuses, "acceptable_http_statuses",
            allow_none=True, nonempty=True,
        )
        if self.acceptable_http_statuses is not None and any(
            type(status) is not int or not 100 <= status <= 599
            for status in self.acceptable_http_statuses
        ):
            raise ValueError("acceptable_http_statuses must contain integers in 100..599, not bool")
        _require_enum_collection(self.acceptable_deliveries, _DELIVERIES, "acceptable_deliveries")
        for field_name in ("requires_response_content", "requires_functional_evidence"):
            if type(getattr(self, field_name)) is not bool:
                raise ValueError(f"{field_name} must be exactly bool")
        object.__setattr__(self, "contract_id", contract_id)
