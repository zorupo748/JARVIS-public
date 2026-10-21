"""Pure pre-dispatch authorization against a supervisor-owned snapshot.

These constructible records are NOT credentials. The future supervisor must
obtain the snapshot from its trusted registry, supply monotonic time in the
same clock domain, and atomically reserve quotas/recheck revocation before
dispatch. It must also enforce the session deadline during execution. Never
expose snapshot construction or selection to an agent. Decisions are not
reusable dispatch tokens and grant no permission after their snapshot changes.

V1 grants one exact request template per permission: method, origin, static
path, and the complete ordered query tuple INCLUDING values and duplicates.
No decoding, sorting, wildcard, URL correlation or inferred required fields.
Operation/resource references are approved registry bindings, not proof that
an operation contract belongs to a capability. Sensitive templates stay in
memory and out of repr; this module supplies no persistence or serialization.

Byte quotas cover reserved HTTP response plaintext (transport max_response_bytes),
not physical network traffic. Counters include pending reservations and failed
attempts according to supervisor accounting, never only successful responses.
Validity ends exclusively at valid_until_ms. Authorization proves neither DNS
admission, connection, response, content, sufficiency nor network isolation.

Supervisor integration requirements (not implemented by this pure module):
- Authenticate the worker/session out of band. Select its registry snapshot
  and operation/resource binding from trusted ownership, not caller labels.
  Never accept agent-supplied snapshots, counters, revocation flags or time.
- Use one authoritative monotonic clock domain. A coherent but stale snapshot
  remains constructible; freshness and registry versions belong to the caller.
- Under synchronization, recheck current policy, evaluate and reserve one
  attempt plus its response ceiling before dispatch. Include every pending
  reservation, retries and failed attempts; do not reuse an allowed decision.
- Dispatch exactly the validated immutable request with the same response
  ceiling. Do not substitute a URL, decode queries again or change the binding.
  Release unused reservations only through authoritative outcome accounting.
- Enforce deadlines/revocation during execution and fail closed on missing or
  uncertain state. DNS acceptance budgets are not cancellation guarantees.
- Keep raw template values private and ephemeral; never send registry snapshots
  to the model, traces or logs. IDs must be local non-secret infrastructure IDs.

Response-byte quota is the sum of configured/reserved ceilings, not a promise
about bytes actually received: transport can read a detection byte beyond its
ceiling to reject oversized input, and DNS/TLS traffic is outside this model.
An actual-traffic budget requires separate supervisor accounting. No check
here authenticates domain ownership or bypasses the downstream SSRF/TLS gates.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields

from jarvis.core.browser_http_transport import BrowserHTTPRequest, BrowserHTTPTransportLimits

__all__ = (
    "BrowserRequestPermission", "BrowserRequestAuthorizationSnapshot",
    "BrowserRequestAuthorizationContext", "BrowserRequestAuthorizationDecision",
    "evaluate_browser_request_authorization",
)

_ERROR = "invalid browser request authorization input"
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_MAX_INT = (1 << 63) - 1
_KINDS = frozenset({"operation", "resource"})
_REASONS = frozenset({
    "allowed", "invalid_input", "session_mismatch", "session_revoked",
    "session_not_current", "unknown_permission", "binding_mismatch",
    "permission_revoked", "permission_not_current", "origin_mismatch",
    "method_mismatch", "path_mismatch", "query_mismatch", "request_limit",
    "response_limit", "byte_limit",
})


def _id(value: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(_ERROR)


def _integer(value: int, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= _MAX_INT:
        raise ValueError(_ERROR)


def _kind(value: str) -> None:
    if type(value) is not str or value not in _KINDS:
        raise ValueError(_ERROR)


def _validity(start: int, end: int, revoked: bool) -> None:
    _integer(start)
    _integer(end)
    if end <= start or type(revoked) is not bool:
        raise ValueError(_ERROR)


def _copy(record, expected_type):
    if type(record) is not expected_type:
        raise ValueError(_ERROR)
    return expected_type(**{item.name: getattr(record, item.name) for item in fields(expected_type)})


@dataclass(frozen=True, slots=True)
class BrowserRequestPermission:
    """One supervisor-granted exact operation or auxiliary-resource request."""

    permission_id: str
    session_id: str
    binding_kind: str
    binding_id: str
    request: BrowserHTTPRequest = field(repr=False)
    valid_from_ms: int
    valid_until_ms: int
    revoked: bool

    def __post_init__(self) -> None:
        for value in (self.permission_id, self.session_id, self.binding_id):
            _id(value)
        _kind(self.binding_kind)
        _validity(self.valid_from_ms, self.valid_until_ms, self.revoked)
        object.__setattr__(self, "request", _copy(self.request, BrowserHTTPRequest))


@dataclass(frozen=True, slots=True)
class BrowserRequestAuthorizationSnapshot:
    """Trusted session state, including already consumed/reserved quotas.

    Used counters may exceed maxima to represent exhausted state; evaluation
    denies it. Empty permissions mean no grants. Duplicate IDs are invalid.
    The supervisor must include all in-flight reservations in used counters.
    """

    session_id: str
    permissions: tuple[BrowserRequestPermission, ...] = field(repr=False)
    valid_from_ms: int
    valid_until_ms: int
    revoked: bool
    requests_used: int
    max_requests: int
    response_bytes_used: int
    max_total_response_bytes: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        _id(self.session_id)
        _validity(self.valid_from_ms, self.valid_until_ms, self.revoked)
        for value in (self.requests_used, self.response_bytes_used):
            _integer(value)
        for value in (self.max_requests, self.max_total_response_bytes, self.max_response_bytes):
            _integer(value, 1)
        BrowserHTTPTransportLimits(max_response_bytes=self.max_response_bytes)
        if type(self.permissions) is not tuple or len(self.permissions) > 64:
            raise ValueError(_ERROR)
        permissions = tuple(_copy(item, BrowserRequestPermission) for item in self.permissions)
        if (len({item.permission_id for item in permissions}) != len(permissions)
                or any(item.session_id != self.session_id for item in permissions)):
            raise ValueError(_ERROR)
        object.__setattr__(self, "permissions", permissions)


@dataclass(frozen=True, slots=True)
class BrowserRequestAuthorizationContext:
    """Proposed binding only; matching labels never authenticate a caller."""

    session_id: str
    permission_id: str
    binding_kind: str
    binding_id: str

    def __post_init__(self) -> None:
        for value in (self.session_id, self.permission_id, self.binding_id):
            _id(value)
        _kind(self.binding_kind)


@dataclass(frozen=True, slots=True)
class BrowserRequestAuthorizationDecision:
    allowed: bool
    reason: str

    def __post_init__(self) -> None:
        if (type(self.allowed) is not bool or type(self.reason) is not str
                or self.reason not in _REASONS
                or self.allowed != (self.reason == "allowed")):
            raise ValueError(_ERROR)


def evaluate_browser_request_authorization(
    request: BrowserHTTPRequest,
    snapshot: BrowserRequestAuthorizationSnapshot,
    context: BrowserRequestAuthorizationContext,
    *, now_ms: int, response_byte_budget: int,
) -> BrowserRequestAuthorizationDecision:
    """Deny malformed inputs and every missing/mismatched gate, without I/O.

    The supervisor must apply response_byte_budget as the transport's response
    ceiling and reserve one request plus that byte allowance atomically. This
    pure decision neither consumes quota nor authenticates snapshot provenance.
    It cannot stop use of stale state or direct calls to a separate transport.
    """
    def deny(reason: str) -> BrowserRequestAuthorizationDecision:
        return BrowserRequestAuthorizationDecision(False, reason)

    try:
        request = _copy(request, BrowserHTTPRequest)
        snapshot = _copy(snapshot, BrowserRequestAuthorizationSnapshot)
        context = _copy(context, BrowserRequestAuthorizationContext)
        _integer(now_ms)
        _integer(response_byte_budget, 1)
        BrowserHTTPTransportLimits(max_response_bytes=response_byte_budget)
    except (ValueError, AttributeError):
        # Constructor/data-contract failures only. Programming failures escape.
        return deny("invalid_input")

    if context.session_id != snapshot.session_id:
        return deny("session_mismatch")
    if snapshot.revoked:
        return deny("session_revoked")
    if not snapshot.valid_from_ms <= now_ms < snapshot.valid_until_ms:
        return deny("session_not_current")
    permission = next((item for item in snapshot.permissions
                       if item.permission_id == context.permission_id), None)
    if permission is None:
        return deny("unknown_permission")
    if (context.binding_kind != permission.binding_kind
            or context.binding_id != permission.binding_id):
        return deny("binding_mismatch")
    if permission.revoked:
        return deny("permission_revoked")
    if not permission.valid_from_ms <= now_ms < permission.valid_until_ms:
        return deny("permission_not_current")
    approved = permission.request
    if request.origin != approved.origin:
        return deny("origin_mismatch")
    if request.method != approved.method:
        return deny("method_mismatch")
    if request.static_path != approved.static_path:
        return deny("path_mismatch")
    if request.query_parameters != approved.query_parameters:
        return deny("query_mismatch")
    if snapshot.requests_used >= snapshot.max_requests:
        return deny("request_limit")
    if response_byte_budget > snapshot.max_response_bytes:
        return deny("response_limit")
    if snapshot.response_bytes_used + response_byte_budget > snapshot.max_total_response_bytes:
        return deny("byte_limit")
    return BrowserRequestAuthorizationDecision(True, "allowed")
