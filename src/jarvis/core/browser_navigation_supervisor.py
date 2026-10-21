"""Local, thread-safe authorization registry; no dispatch, IPC or network.

Bootstrap returns a client interface AND a separate administrative authority.
Only trusted infrastructure may hold the authority or supply its clock/snapshots.
Client calls accept registered opaque object handles, never caller snapshots,
quota counters or time. Handles use object identity, not a guessed local ID.
This is API separation, NOT protection against arbitrary Python reflection,
authentication of external clients, persistence or cross-process synchronization.

Evaluate/reserve, start, revoke and settle serialize under one lock. Every
accepted reservation permanently charges one attempt and its FULL response
ceiling, including cancellation, failure and revocation. No refunds or retries
under a reused request ID; terminal tombstones remain until close. This avoids
trusting caller byte counts or freeing uncertain in-flight resources. Bytes are
reserved HTTP ceilings, not measured traffic or a physical network budget.

start() rechecks policy/time and allows one local transition to ACTIVE. It is
not HTTP execution. Future dispatch must use authority.binding(), the exact
request/budget, and coordinate revocation/deadlines with a real transport. An
active reservation revoked/cancelled here does NOT stop an external operation.
The clock is infrastructure-owned, non-reentrant and must return monotonic
integer milliseconds; bad/throwing/backwards clocks invalidate the supervisor.
"""

from dataclasses import dataclass, field, fields, replace
from enum import Enum
import re
import threading

from jarvis.core.browser_http_transport import BrowserHTTPRequest
from jarvis.core.browser_request_authorization import (
    BrowserRequestAuthorizationSnapshot, BrowserRequestAuthorizationContext,
    evaluate_browser_request_authorization,
)


class NavigationReason(str, Enum):
    ALLOWED = "allowed"
    INVALID_INPUT = "invalid_input"
    UNKNOWN_SESSION = "unknown_session"
    UNKNOWN_RESERVATION = "unknown_reservation"
    DUPLICATE_SESSION = "duplicate_session"
    DUPLICATE_REQUEST = "duplicate_request"
    STATE_CONFLICT = "state_conflict"
    CLOCK_FAILED = "clock_failed"
    SUPERVISOR_FAILED = "supervisor_failed"
    REGISTRY_FULL = "registry_full"
    CLOSED = "closed"
    SESSION_MISMATCH = "session_mismatch"
    SESSION_REVOKED = "session_revoked"
    SESSION_NOT_CURRENT = "session_not_current"
    UNKNOWN_PERMISSION = "unknown_permission"
    BINDING_MISMATCH = "binding_mismatch"
    PERMISSION_REVOKED = "permission_revoked"
    PERMISSION_NOT_CURRENT = "permission_not_current"
    ORIGIN_MISMATCH = "origin_mismatch"
    METHOD_MISMATCH = "method_mismatch"
    PATH_MISMATCH = "path_mismatch"
    QUERY_MISMATCH = "query_mismatch"
    REQUEST_LIMIT = "request_limit"
    RESPONSE_LIMIT = "response_limit"
    BYTE_LIMIT = "byte_limit"


class ReservationState(str, Enum):
    RESERVED = "reserved"
    ACTIVE = "active"
    DISPATCHING = "dispatching"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    REVOKED = "revoked"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"


class NavigationSupervisorError(RuntimeError):
    def __init__(self, reason: NavigationReason):
        if type(reason) is not NavigationReason:
            raise ValueError("invalid supervisor error")
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class NavigationSessionHandle:
    def __repr__(self):
        return "NavigationSessionHandle(opaque)"


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class NavigationReservationHandle:
    def __repr__(self):
        return "NavigationReservationHandle(opaque)"


@dataclass(frozen=True, slots=True)
class NavigationResult:
    """accepted concerns the requested lifecycle action, not network success."""
    accepted: bool
    reason: NavigationReason
    reservation: NavigationReservationHandle | None = None
    state: ReservationState | None = None

    def __post_init__(self):
        if (type(self.accepted) is not bool or type(self.reason) is not NavigationReason
                or self.accepted != (self.reason is NavigationReason.ALLOWED)
                or (self.reservation is not None and type(self.reservation) is not NavigationReservationHandle)
                or (self.state is not None and type(self.state) is not ReservationState)):
            raise ValueError("invalid supervisor result")


@dataclass(frozen=True, slots=True)
class NavigationRequestBinding:
    request: BrowserHTTPRequest = field(repr=False)
    context: BrowserRequestAuthorizationContext = field(repr=False)
    response_byte_budget: int


@dataclass(frozen=True, slots=True)
class NavigationDispatchBinding(NavigationRequestBinding):
    remaining_validity_ms: int


@dataclass(frozen=True, slots=True)
class NavigationDispatchOutcome:
    """Bounded transport facts, never bodies, URLs or a cancellation claim."""
    transport_invoked: bool
    send_state: str
    tls_established: bool | None
    response_validated: bool
    http_status: int | None
    transport_failed: bool

    def __post_init__(self):
        if (any(type(v) is not bool for v in (self.transport_invoked, self.response_validated, self.transport_failed))
                or type(self.send_state) is not str or self.send_state not in {"not_sent", "unknown", "sent"}
                or (self.tls_established is not None and type(self.tls_established) is not bool)
                or (self.http_status is not None and (type(self.http_status) is not int or not 200 <= self.http_status <= 599))):
            raise ValueError("invalid dispatch outcome")
        if not self.transport_invoked and (self.send_state != "not_sent" or self.tls_established is not None
                                          or self.response_validated or self.http_status is not None or self.transport_failed):
            raise ValueError("invalid dispatch outcome")
        if self.transport_invoked and self.tls_established is None and self.send_state != "unknown":
            raise ValueError("invalid dispatch outcome")
        if self.response_validated != (self.http_status is not None) or (self.response_validated and (
                not self.transport_invoked or self.send_state != "sent" or self.tls_established is not True or self.transport_failed)):
            raise ValueError("invalid dispatch outcome")
        if self.tls_established is False and self.send_state != "not_sent":
            raise ValueError("invalid dispatch outcome")


@dataclass(slots=True, repr=False)
class _Session:
    snapshot: BrowserRequestAuthorizationSnapshot
    request_ids: set


@dataclass(slots=True, repr=False)
class _Reservation:
    session: NavigationSessionHandle
    binding: NavigationRequestBinding | None
    permission_id: str
    state: ReservationState = ReservationState.RESERVED
    dispatch_claimed: bool = False
    outcome: NavigationDispatchOutcome | None = None
    delivery_claimed: bool = False


def _copy(value, cls):
    if type(value) is not cls:
        raise ValueError("invalid navigation input")
    return cls(**{item.name: getattr(value, item.name) for item in fields(cls)})


_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_LIVE = frozenset({ReservationState.RESERVED, ReservationState.ACTIVE, ReservationState.DISPATCHING})


class BrowserNavigationSupervisor:
    __slots__ = ("_clock", "_lock", "_sessions", "_reservations", "_key",
                 "_closed", "_failed", "_failure_reason", "_last_time", "_max_sessions", "_max_reservations")

    def __init__(self, clock, *, max_sessions=64, max_reservations=4096):
        if not callable(clock) or any(type(n) is not int or not 1 <= n <= 4096
                                      for n in (max_sessions, max_reservations)):
            raise ValueError("invalid supervisor configuration")
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions, self._reservations = {}, {}
        self._key = object()
        self._closed = self._failed = False
        self._failure_reason = NavigationReason.CLOCK_FAILED
        self._last_time = None
        self._max_sessions, self._max_reservations = max_sessions, max_reservations

    def __repr__(self):
        return "BrowserNavigationSupervisor(local)"

    def _guard(self):
        return NavigationReason.CLOSED if self._closed else self._failure_reason if self._failed else None

    def _invalidate(self, reason):
        self._failed, self._failure_reason = True, reason
        for record in self._reservations.values():
            if record.state in _LIVE:
                self._terminal(record, ReservationState.INVALIDATED)

    def _now(self):
        try:
            now = self._clock()
            if (type(now) is not int or not 0 <= now < 2**63
                    or (self._last_time is not None and now < self._last_time)):
                raise ValueError("invalid clock")
        except Exception:
            # The supplied clock is an external trusted dependency. Its errors
            # are intentionally sanitized; supervisor programming bugs escape.
            self._invalidate(NavigationReason.CLOCK_FAILED)
            return None
        self._last_time = now
        return now

    @staticmethod
    def _terminal(record, state):
        record.state, record.binding = state, None

    def reserve(self, session, request_id, request, context, *, response_byte_budget):
        with self._lock:
            reason = self._guard()
            if reason:
                return NavigationResult(False, reason)
            if type(session) is not NavigationSessionHandle or session not in self._sessions:
                return NavigationResult(False, NavigationReason.UNKNOWN_SESSION)
            if type(request_id) is not str or _ID.fullmatch(request_id) is None:
                return NavigationResult(False, NavigationReason.INVALID_INPUT)
            state = self._sessions[session]
            if request_id in state.request_ids:
                return NavigationResult(False, NavigationReason.DUPLICATE_REQUEST)
            try:
                request = _copy(request, BrowserHTTPRequest)
                context = _copy(context, BrowserRequestAuthorizationContext)
            except (ValueError, AttributeError):
                return NavigationResult(False, NavigationReason.INVALID_INPUT)
            now = self._now()
            if now is None:
                return NavigationResult(False, NavigationReason.CLOCK_FAILED)
            decision = evaluate_browser_request_authorization(
                request, state.snapshot, context, now_ms=now, response_byte_budget=response_byte_budget)
            if not decision.allowed:
                return NavigationResult(False, NavigationReason(decision.reason))
            if len(self._reservations) >= self._max_reservations:
                return NavigationResult(False, NavigationReason.REGISTRY_FULL)
            new_snapshot = replace(state.snapshot, requests_used=state.snapshot.requests_used + 1,
                                   response_bytes_used=state.snapshot.response_bytes_used + response_byte_budget)
            handle = NavigationReservationHandle()
            record = _Reservation(session, NavigationRequestBinding(request, context, response_byte_budget), context.permission_id)
            # All validation succeeds before accounting; both charge and grant
            # are invisible to other threads until this critical section exits.
            try:
                # Charge first. Any interruption during commit invalidates the
                # registry and propagates; it never enables further approvals
                # using partial accounting or rolls uncertain charges back.
                state.snapshot = new_snapshot
                state.request_ids.add(request_id)
                self._reservations[handle] = record
            except BaseException:
                self._invalidate(NavigationReason.SUPERVISOR_FAILED)
                raise
            return NavigationResult(True, NavigationReason.ALLOWED, handle, record.state)

    def _refresh(self, record):
        now = self._now()
        if now is None:
            return NavigationReason.CLOCK_FAILED
        state, binding = self._sessions[record.session], record.binding
        # Own reservation has already consumed quota. Subtract ONLY that charge
        # for policy revalidation, without changing actual registry accounting.
        probe = replace(state.snapshot, requests_used=state.snapshot.requests_used - 1,
                        response_bytes_used=state.snapshot.response_bytes_used - binding.response_byte_budget)
        decision = evaluate_browser_request_authorization(
            binding.request, probe, binding.context, now_ms=now,
            response_byte_budget=binding.response_byte_budget)
        if not decision.allowed:
            reason = NavigationReason(decision.reason)
            self._terminal(record, ReservationState.EXPIRED if reason in {
                NavigationReason.SESSION_NOT_CURRENT, NavigationReason.PERMISSION_NOT_CURRENT
            } else ReservationState.REVOKED)
            return reason
        return None

    def _lookup(self, reservation):
        return self._reservations.get(reservation) if type(reservation) is NavigationReservationHandle else None

    def start(self, reservation):
        with self._lock:
            reason = self._guard()
            record = self._lookup(reservation)
            if reason or record is None:
                return NavigationResult(False, reason or NavigationReason.UNKNOWN_RESERVATION)
            if record.state is not ReservationState.RESERVED:
                return NavigationResult(False, NavigationReason.STATE_CONFLICT, reservation, record.state)
            reason = self._refresh(record)
            if reason:
                return NavigationResult(False, reason, reservation, record.state)
            record.state = ReservationState.ACTIVE
            return NavigationResult(True, NavigationReason.ALLOWED, reservation, record.state)

    def inspect(self, reservation):
        with self._lock:
            if self._closed:
                return NavigationResult(False, NavigationReason.CLOSED)
            record = self._lookup(reservation)
            if record is None:
                return NavigationResult(False, NavigationReason.UNKNOWN_RESERVATION)
            reason = self._refresh(record) if record.state in _LIVE else None
            return NavigationResult(reason is None, reason or NavigationReason.ALLOWED, reservation, record.state)

    def finish(self, reservation):
        return self._settle(reservation, ReservationState.COMPLETED)

    def cancel(self, reservation):
        return self._settle(reservation, ReservationState.CANCELLED)

    def _settle(self, reservation, target):
        with self._lock:
            if self._closed:
                return NavigationResult(False, NavigationReason.CLOSED)
            record = self._lookup(reservation)
            if record is None:
                return NavigationResult(False, NavigationReason.UNKNOWN_RESERVATION)
            allowed = record.state is ReservationState.ACTIVE if target is ReservationState.COMPLETED else record.state in _LIVE
            if not allowed:
                return NavigationResult(False, NavigationReason.STATE_CONFLICT, reservation, record.state)
            if target is ReservationState.COMPLETED:
                reason = self._refresh(record)
                if reason:
                    return NavigationResult(False, reason, reservation, record.state)
            self._terminal(record, target)
            return NavigationResult(True, NavigationReason.ALLOWED, reservation, record.state)

    def close(self):
        with self._lock:
            for record in self._reservations.values():
                if record.state in _LIVE:
                    self._terminal(record, ReservationState.INVALIDATED)
            self._sessions.clear()
            self._reservations.clear()
            self._closed = True


class BrowserNavigationAuthority:
    """Infrastructure-only enrollment/revocation/binding access; keep private."""
    __slots__ = ("_supervisor", "_key")

    def __init__(self, supervisor, key):
        self._supervisor, self._key = supervisor, key

    def __repr__(self):
        return "BrowserNavigationAuthority(private)"

    def _check(self):
        if self._key is not self._supervisor._key:
            raise NavigationSupervisorError(NavigationReason.INVALID_INPUT)

    def register_session(self, snapshot):
        self._check()
        owner = self._supervisor
        with owner._lock:
            if owner._guard():
                raise NavigationSupervisorError(owner._guard())
            try:
                snapshot = _copy(snapshot, BrowserRequestAuthorizationSnapshot)
            except (ValueError, AttributeError):
                raise NavigationSupervisorError(NavigationReason.INVALID_INPUT) from None
            if any(item.snapshot.session_id == snapshot.session_id for item in owner._sessions.values()):
                raise NavigationSupervisorError(NavigationReason.DUPLICATE_SESSION)
            if len(owner._sessions) >= owner._max_sessions:
                raise NavigationSupervisorError(NavigationReason.REGISTRY_FULL)
            handle = NavigationSessionHandle()
            owner._sessions[handle] = _Session(snapshot, set())
            return handle

    def revoke_session(self, session):
        self._revoke(session, None)

    def revoke_permission(self, session, permission_id):
        if type(permission_id) is not str or _ID.fullmatch(permission_id) is None:
            raise NavigationSupervisorError(NavigationReason.INVALID_INPUT)
        self._revoke(session, permission_id)

    def _revoke(self, session, permission_id):
        self._check()
        owner = self._supervisor
        with owner._lock:
            if owner._closed:
                raise NavigationSupervisorError(NavigationReason.CLOSED)
            if type(session) is not NavigationSessionHandle or session not in owner._sessions:
                raise NavigationSupervisorError(NavigationReason.UNKNOWN_SESSION)
            record = owner._sessions[session]
            snapshot = record.snapshot
            if permission_id is None:
                snapshot = replace(snapshot, revoked=True)
            else:
                if not any(p.permission_id == permission_id for p in snapshot.permissions):
                    raise NavigationSupervisorError(NavigationReason.UNKNOWN_PERMISSION)
                snapshot = replace(snapshot, permissions=tuple(
                    replace(p, revoked=True) if p.permission_id == permission_id else p for p in snapshot.permissions))
            record.snapshot = snapshot
            for reservation in owner._reservations.values():
                if reservation.session is session and reservation.state in _LIVE and (
                        permission_id is None or reservation.permission_id == permission_id):
                    owner._terminal(reservation, ReservationState.REVOKED)

    def binding(self, reservation):
        self._check()
        owner = self._supervisor
        with owner._lock:
            if owner._guard():
                raise NavigationSupervisorError(owner._guard())
            record = owner._lookup(reservation)
            if record is None:
                raise NavigationSupervisorError(NavigationReason.UNKNOWN_RESERVATION)
            if record.state is not ReservationState.ACTIVE:
                raise NavigationSupervisorError(NavigationReason.STATE_CONFLICT)
            reason = owner._refresh(record)
            if reason:
                raise NavigationSupervisorError(reason)
            binding = record.binding
            return NavigationRequestBinding(_copy(binding.request, BrowserHTTPRequest),
                                            _copy(binding.context, BrowserRequestAuthorizationContext), binding.response_byte_budget)

    def claim_dispatch(self, reservation):
        """Single dispatch commitment, linearized with revocation under the lock.

        Later revocation invalidates result release but cannot interrupt I/O.
        No callback runs under the lock. This cannot make physical socket send
        atomic with registry state or contain arbitrary Python transport calls.
        """
        self._check()
        owner = self._supervisor
        with owner._lock:
            if owner._guard():
                raise NavigationSupervisorError(owner._guard())
            record = owner._lookup(reservation)
            if record is None:
                raise NavigationSupervisorError(NavigationReason.UNKNOWN_RESERVATION)
            if record.state is not ReservationState.ACTIVE or record.dispatch_claimed:
                raise NavigationSupervisorError(NavigationReason.STATE_CONFLICT)
            reason = owner._refresh(record)
            if reason:
                raise NavigationSupervisorError(reason)
            binding = record.binding
            snapshot = owner._sessions[record.session].snapshot
            permission = next(p for p in snapshot.permissions if p.permission_id == record.permission_id)
            result = NavigationDispatchBinding(_copy(binding.request, BrowserHTTPRequest),
                _copy(binding.context, BrowserRequestAuthorizationContext), binding.response_byte_budget,
                min(snapshot.valid_until_ms, permission.valid_until_ms) - owner._last_time)
            record.dispatch_claimed = True
            record.state = ReservationState.DISPATCHING
            return result

    def record_dispatch_outcome(self, reservation, outcome):
        """Record once and settle even revoked work; no quota refunds.

        Revocation/cancellation never becomes COMPLETED. A validated response
        after revocation remains an observed fact, not permission to release it.
        """
        self._check()
        owner = self._supervisor
        with owner._lock:
            if owner._closed:
                return NavigationResult(False, NavigationReason.CLOSED)
            record = owner._lookup(reservation)
            if record is None:
                return NavigationResult(False, NavigationReason.UNKNOWN_RESERVATION)
            try:
                outcome = _copy(outcome, NavigationDispatchOutcome)
            except (ValueError, AttributeError):
                raise NavigationSupervisorError(NavigationReason.INVALID_INPUT) from None
            if record.outcome is not None or (outcome.transport_invoked and not record.dispatch_claimed):
                return NavigationResult(False, NavigationReason.STATE_CONFLICT, reservation, record.state)
            record.outcome = outcome
            if record.state is ReservationState.DISPATCHING:
                reason = owner._guard() or owner._refresh(record)
                if reason:
                    return NavigationResult(False, reason, reservation, record.state)
                owner._terminal(record, ReservationState.COMPLETED)
                return NavigationResult(True, NavigationReason.ALLOWED, reservation, record.state)
            if record.state in {ReservationState.RESERVED, ReservationState.ACTIVE}:
                owner._terminal(record, ReservationState.CANCELLED)
            return NavigationResult(False, NavigationReason.STATE_CONFLICT, reservation, record.state)

    def dispatch_outcome(self, reservation):
        self._check()
        owner = self._supervisor
        with owner._lock:
            record = owner._lookup(reservation)
            if record is None:
                raise NavigationSupervisorError(NavigationReason.UNKNOWN_RESERVATION)
            return record.outcome

    def authorize_delivery(self, reservation):
        """Trusted delivery commitment, not cancellation or revocation-proof IPC.

        Revalidate after HTTP settlement. A later revocation cannot withdraw
        bytes already handed to a consumer; this check does not hold a lock
        over external delivery callbacks.
        """
        self._check()
        owner = self._supervisor
        with owner._lock:
            if owner._guard():
                return False
            record = owner._lookup(reservation)
            if (record is None or record.delivery_claimed or record.state is not ReservationState.COMPLETED
                    or record.outcome is None or not record.outcome.response_validated):
                return False
            now = owner._now()
            if now is None:
                return False
            snapshot = owner._sessions[record.session].snapshot
            permission = next((p for p in snapshot.permissions if p.permission_id == record.permission_id), None)
            allowed = bool(not snapshot.revoked and snapshot.valid_from_ms <= now < snapshot.valid_until_ms
                        and permission is not None and not permission.revoked
                        and permission.valid_from_ms <= now < permission.valid_until_ms)
            if allowed:
                record.delivery_claimed = True
            return allowed


def create_browser_navigation_supervisor(*, clock, max_sessions=64, max_reservations=4096):
    """Trusted bootstrap only. Never give the administrative result to an agent."""
    owner = BrowserNavigationSupervisor(clock, max_sessions=max_sessions, max_reservations=max_reservations)
    return owner, BrowserNavigationAuthority(owner, owner._key)
