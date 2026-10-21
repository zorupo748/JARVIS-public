"""In-process trusted gateway; no server, Chromium, IPC or alternate client.

Bootstrap owns supervisor/authority/configuration. A dispatch caller supplies
only an opaque session handle, local attempt ID, structured request/context and
requested response ceiling. It cannot supply policy, DNS, sockets or executor.
Tests patch the known transport function; production has no executor injection.

The supervisor's single claim_dispatch is the commitment linearized against
revocation, immediately preceding transport invocation. A later revocation may
occur BEFORE physical network send; there is no interruptible transport here.
It prevents result-body release and is never represented as confirmed I/O
cancellation. Transport facts are recorded separately from lifecycle state.
DNS and establishment/post-handoff budgets are not a hard session deadline.
Final expiry checks withhold payloads; no guarantee of timely I/O abortion.

No automatic retry, redirect or refund. One approved dispatch consumes its full
reservation even on error. Bodies remain in-memory/repr-hidden, never recorded
in the supervisor. Python objects/API separation are not external authentication
or protection from arbitrary reflective Python code in the trusted process.
"""

from dataclasses import dataclass, field, fields, replace
from enum import Enum
import uuid

from jarvis.core.browser_http_transport import (
    BrowserHTTPRequest, BrowserHTTPTransportLimits, BrowserHTTPResponse,
    BrowserHTTPExchangeResult, execute_browser_http_request,
)
from jarvis.core.browser_https_broker import BrowserHTTPSBrokerLimits
from jarvis.core.browser_navigation_supervisor import (
    BrowserNavigationSupervisor, BrowserNavigationAuthority, NavigationSupervisorError,
    NavigationReason, NavigationResult, NavigationDispatchOutcome,
)


class HTTPDispatchStatus(str, Enum):
    REJECTED = "rejected"
    NOT_SENT = "not_sent"
    SEND_UNKNOWN = "send_unknown"
    RESPONSE_VALIDATED = "response_validated"
    ERROR = "error"


class HTTPDispatchReason(str, Enum):
    AUTHORIZATION_REJECTED = "authorization_rejected"
    SUPERVISOR_REJECTED = "supervisor_rejected"
    RESPONSE_VALIDATED = "response_validated"
    TRANSPORT_ERROR = "transport_error"
    TRANSPORT_EXCEPTION = "transport_exception"
    INVALID_TRANSPORT_RESULT = "invalid_transport_result"
    INVALID_DISPATCH_BINDING = "invalid_dispatch_binding"


class HTTPDispatchError(RuntimeError):
    """Unexpected integration failure, sanitized and distinct from HTTP results."""
    def __init__(self, reason):
        if type(reason) is not HTTPDispatchReason:
            raise ValueError("invalid dispatch error")
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class HTTPDispatchResult:
    status: HTTPDispatchStatus
    reason: HTTPDispatchReason
    lifecycle: NavigationResult
    observation: NavigationDispatchOutcome
    exchange: BrowserHTTPExchangeResult | None = field(default=None, repr=False)
    response_released: bool = False


def _copy(value, cls):
    if type(value) is not cls:
        raise ValueError("invalid gateway input")
    return cls(**{item.name: getattr(value, item.name) for item in fields(cls)})


_NOT_INVOKED = NavigationDispatchOutcome(False, "not_sent", None, False, None, False)
_UNKNOWN = NavigationDispatchOutcome(True, "unknown", None, False, None, True)


class BrowserHTTPDispatchGateway:
    """Infrastructure-created interface; administrative authority stays private."""
    __slots__ = ("_supervisor", "_authority", "_limits", "_broker_limits")

    def __init__(self, supervisor, authority, *, limits=BrowserHTTPTransportLimits(),
                 broker_limits=BrowserHTTPSBrokerLimits()):
        if (type(supervisor) is not BrowserNavigationSupervisor or type(authority) is not BrowserNavigationAuthority
                or authority._supervisor is not supervisor):
            raise ValueError("invalid gateway infrastructure")
        authority._check()
        self._supervisor, self._authority = supervisor, authority
        self._limits = _copy(limits, BrowserHTTPTransportLimits)
        self._broker_limits = _copy(broker_limits, BrowserHTTPSBrokerLimits)

    def __repr__(self):
        return "BrowserHTTPDispatchGateway(trusted_local)"

    def dispatch(self, session, request_id, request, context, *, response_byte_budget):
        reserved = self._supervisor.reserve(session, request_id, request, context,
                                            response_byte_budget=response_byte_budget)
        if not reserved.accepted:
            return HTTPDispatchResult(HTTPDispatchStatus.REJECTED, HTTPDispatchReason.AUTHORIZATION_REJECTED,
                                      reserved, _NOT_INVOKED)
        token = reserved.reservation
        observation, exchange = _NOT_INVOKED, None
        status, reason = HTTPDispatchStatus.REJECTED, HTTPDispatchReason.SUPERVISOR_REJECTED
        rejection = None
        invoked = False
        settlement = None
        try:
            started = self._supervisor.start(token)
            if not started.accepted:
                rejection = started
            else:
                prepared = self._authority.binding(token)
                ceiling = min(prepared.response_byte_budget, self._limits.max_response_bytes)
                limits = replace(self._limits, max_response_bytes=ceiling,
                                 max_body_bytes=min(self._limits.max_body_bytes, ceiling))
                # Fresh non-secret infrastructure IDs, not request-supplied DNS
                # snapshots or authorization credentials. Keep actual binding IDs.
                resolution_id = "resolution-" + uuid.uuid4().hex
                authorization_id = "authorization-" + uuid.uuid4().hex
                claimed = self._authority.claim_dispatch(token)
                if (claimed.request != prepared.request or claimed.context != prepared.context
                        or claimed.response_byte_budget != prepared.response_byte_budget):
                    raise HTTPDispatchError(HTTPDispatchReason.INVALID_DISPATCH_BINDING)
                remaining = claimed.remaining_validity_ms
                limits = replace(limits, io_timeout_ms=min(limits.io_timeout_ms, remaining),
                                 exchange_budget_ms=min(limits.exchange_budget_ms, remaining))
                broker_limits = replace(self._broker_limits,
                    establishment_budget_ms=min(self._broker_limits.establishment_budget_ms, remaining))
                invoked, observation = True, _UNKNOWN
                raw = execute_browser_http_request(
                    claimed.request, frozenset({claimed.request.origin}),
                    resolution_id=resolution_id, authorization_id=authorization_id,
                    session_id=claimed.context.session_id, operation_id=claimed.context.binding_id,
                    limits=limits, broker_limits=broker_limits,
                )
                try:
                    exchange = _copy(raw, BrowserHTTPExchangeResult)
                    if exchange.response is not None:
                        response = _copy(exchange.response, BrowserHTTPResponse)
                        if response.wire_bytes > ceiling or len(response.body) > limits.max_body_bytes:
                            raise ValueError("invalid transport response limits")
                        exchange = replace(exchange, response=response)
                except (ValueError, AttributeError):
                    exchange = None
                    raise HTTPDispatchError(HTTPDispatchReason.INVALID_TRANSPORT_RESULT) from None
                observation = NavigationDispatchOutcome(
                    True, exchange.request_send_state, exchange.tls_established, exchange.response_validated,
                    exchange.response.status_code if exchange.response_validated else None,
                    exchange.error_code is not None,
                )
                if exchange.response_validated:
                    status, reason = HTTPDispatchStatus.RESPONSE_VALIDATED, HTTPDispatchReason.RESPONSE_VALIDATED
                else:
                    status = (HTTPDispatchStatus.NOT_SENT if exchange.request_send_state == "not_sent" else
                              HTTPDispatchStatus.SEND_UNKNOWN if exchange.request_send_state == "unknown" else HTTPDispatchStatus.ERROR)
                    reason = HTTPDispatchReason.TRANSPORT_ERROR
        except NavigationSupervisorError as error:
            if invoked:
                raise HTTPDispatchError(HTTPDispatchReason.TRANSPORT_EXCEPTION) from None
            rejection = NavigationResult(False, error.reason, token)
        except OSError:
            # The known transport normally returns expected I/O failures. An
            # unexpected raised I/O error leaves stages unknown, not a response.
            observation = _UNKNOWN if invoked else _NOT_INVOKED
            status = HTTPDispatchStatus.SEND_UNKNOWN if invoked else HTTPDispatchStatus.NOT_SENT
            reason = HTTPDispatchReason.TRANSPORT_EXCEPTION
        except HTTPDispatchError:
            raise
        except Exception:
            raise HTTPDispatchError(HTTPDispatchReason.TRANSPORT_EXCEPTION) from None
        finally:
            try:
                settlement = self._authority.record_dispatch_outcome(token, observation)
            except BaseException:
                self._supervisor.cancel(token)
                raise
        lifecycle = (NavigationResult(False, rejection.reason, token, settlement.state)
                     if rejection is not None else settlement)
        release = bool(exchange is not None and exchange.response_validated and settlement.accepted)
        if exchange is not None and exchange.response_validated and not release:
            exchange = None  # Keep facts but do not release a revoked/expired payload.
        return HTTPDispatchResult(status, reason, lifecycle, observation, exchange, release)
