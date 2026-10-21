"""One direct, pinned TCP/TLS connection; no HTTP or browser integration.

The context manager resolves through the known DNS API exactly once. Caller
inputs cannot supply a resolver, socket, SSL context or constructed admission.
Python records remain structural data, never unforgeable credentials. A future
trusted registry must own the allowlist, local IDs and operation permissions.

Only one broker context may be active per process, without queuing. A rejected
snapshot opens no socket. One numeric IP is attempted, without retry/fallback,
proxy lookup, redirect handling or other connections. The connected socket's
peer is compared before TLS and again after the verified handshake. The caller
borrows the live SSLSocket only within the context; it is always closed on exit.
This does not constrain arbitrary Python callers or other network paths. No
Chromium/Playwright protection or process-wide egress containment is claimed.

TCP and TLS handshake have separate socket timeouts capped by a monotonic
post-DNS establishment budget. Late establishment is rejected. This is NOT a
hard total return-time guarantee: synchronous DNS, CA loading, scheduling and
cleanup cannot be interrupted portably. The budget ends at handoff and does
not bound caller work or context lifetime. DNS limits retain their documented
post-return semantics; a stuck DNS call can occupy the broker slot indefinitely.

TLS uses system roots and PROTOCOL_TLS_CLIENT with hostname verification and
CERT_REQUIRED, minimum TLS 1.2. No context/CA/keylogger is supplied by input.
SSLContext construction avoids create_default_context's SSLKEYLOGFILE behavior;
no TLS key logging is enabled. Deployment controls the OS trust store and its
configuration. No certificate-revocation or DNS authentication guarantee is
added. Errors are fixed codes without addresses, certificate details or logs.

Ragged TLS EOF is not suppressed: application protocols can distinguish a
verified TLS close_notify from a transport drop when using close-delimited data.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_network_policy import evaluate_browser_network_resolution
from jarvis.core.browser_dns_resolver import (
    BrowserDNSResolutionLimits, BrowserDNSResolutionResult, resolve_browser_dns,
)
from jarvis.core.browser_egress_contract import (
    BrowserAdmittedResolution, BrowserConnectionAuthorization,
    evaluate_browser_egress_destination,
)

__all__ = ("BrowserHTTPSBrokerLimits", "BrowserHTTPSBrokerError", "open_browser_https_connection")

_CODES = frozenset({
    "invalid_input", "dns_failed", "resolution_denied", "destination_denied",
    "peer_mismatch", "tcp_failed", "tls_failed", "timeout", "budget_exceeded",
    "broker_busy", "cleanup_failed",
})
_SLOT = threading.BoundedSemaphore(1)


class BrowserHTTPSBrokerError(RuntimeError):
    """A fixed failure code, without underlying exception text."""

    __slots__ = ()

    def __init__(self, code: str) -> None:
        if type(code) is not str or code not in _CODES:
            raise ValueError("invalid HTTPS broker error code")
        super().__init__(code)


def _limits(limits: BrowserHTTPSBrokerLimits) -> None:
    if type(limits) is not BrowserHTTPSBrokerLimits:
        raise ValueError("invalid HTTPS broker limits")
    for value in (limits.tcp_timeout_ms, limits.tls_timeout_ms, limits.establishment_budget_ms):
        if type(value) is not int or not 1 <= value <= 60_000:
            raise ValueError("invalid HTTPS broker limits")
    if type(limits.dns_limits) is not BrowserDNSResolutionLimits:
        raise ValueError("invalid HTTPS broker limits")
    BrowserDNSResolutionLimits(limits.dns_limits.max_records, limits.dns_limits.max_elapsed_ms)


@dataclass(frozen=True, slots=True)
class BrowserHTTPSBrokerLimits:
    """Finite stage timeouts and post-DNS establishment acceptance budget."""

    tcp_timeout_ms: int = 5_000
    tls_timeout_ms: int = 5_000
    establishment_budget_ms: int = 10_000
    dns_limits: BrowserDNSResolutionLimits = BrowserDNSResolutionLimits()

    def __post_init__(self) -> None:
        try:
            _limits(self)
        except (ValueError, AttributeError):
            raise ValueError("invalid HTTPS broker limits") from None


def _remaining_timeout(deadline: int, stage_ms: int) -> float:
    remaining = deadline - time.monotonic_ns()
    if remaining <= 0:
        raise BrowserHTTPSBrokerError("budget_exceeded")
    return min(remaining / 1_000_000_000, stage_ms / 1_000)


def _policy_allows(auth: BrowserConnectionAuthorization, ip: str, port: int) -> bool:
    return evaluate_browser_egress_destination(
        auth, resolution_id=auth.resolution.resolution_id,
        authorization_id=auth.authorization_id, session_id=auth.session_id,
        operation_id=auth.operation_id, origin=auth.resolution.admission.origin,
        port=port, selected_ip_address=ip,
    ).policy_allowed is True


def _check_peer(
    transport: socket.socket, auth: BrowserConnectionAuthorization, selected_ip: str,
    version: int,
) -> None:
    peer = transport.getpeername()  # Actual OS socket, not requested parameters.
    expected_length = 2 if version == 4 else 4
    if type(peer) is not tuple or len(peer) != expected_length:
        raise BrowserHTTPSBrokerError("peer_mismatch")
    ip, port = peer[:2]
    if (type(ip) is not str or len(ip) > 64
            or type(port) is not int or port != 443 or "%" in ip):
        raise BrowserHTTPSBrokerError("peer_mismatch")
    if version == 6 and any(type(value) is not int or value != 0 for value in peer[2:]):
        raise BrowserHTTPSBrokerError("peer_mismatch")
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise BrowserHTTPSBrokerError("peer_mismatch") from None
    canonical = str(address)
    if (address.version != version or canonical != selected_ip
            or not _policy_allows(auth, canonical, port)):
        raise BrowserHTTPSBrokerError("peer_mismatch")


def _check_tls(context: ssl.SSLContext) -> None:
    if (context.check_hostname is not True
            or context.verify_mode != ssl.CERT_REQUIRED
            or context.protocol != ssl.PROTOCOL_TLS_CLIENT
            or context.minimum_version < ssl.TLSVersion.TLSv1_2
            or context.keylog_filename is not None):
        raise BrowserHTTPSBrokerError("tls_failed")


def _create_tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    _check_tls(context)
    return context


def _close_resources(tls: ssl.SSLSocket | None, tcp: socket.socket | None) -> bool:
    failed = False
    # wrap_socket transfers the descriptor to SSLSocket. Closing the detached
    # original is harmless, and also covers failures before/inside wrapping.
    for transport in (tls, tcp):
        if transport is not None:
            try:
                transport.close()
            except Exception:
                failed = True
    return not failed


def _origin(value: BrowserOrigin) -> BrowserOrigin:
    if type(value) is not BrowserOrigin:
        raise ValueError("invalid HTTPS broker origin")
    if (type(value.scheme) is not str or type(value.hostname) is not str
            or type(value.effective_port) is not int):
        raise ValueError("invalid HTTPS broker origin")
    return BrowserOrigin(value.scheme, value.hostname, value.effective_port)


@contextmanager
def open_browser_https_connection(
    origin: BrowserOrigin,
    allowed_origins: frozenset[BrowserOrigin],
    *, resolution_id: str, authorization_id: str, session_id: str,
    operation_id: str, selected_ip_address: str | None = None,
    limits: BrowserHTTPSBrokerLimits = BrowserHTTPSBrokerLimits(),
) -> Iterator[ssl.SSLSocket]:
    """Borrow one verified TLS socket, closed on normal/error context exit.

    Local IDs must be non-secret and satisfy the existing egress contract. The
    first admitted IP is used unless a canonical snapshot member is explicitly
    selected. No input can inject infrastructure or pre-authorize a connection.
    Caller exceptions propagate after cleanup; infrastructure failures are
    sanitized. Socket methods used by the caller are outside this broker's
    connection-establishment budget and application-protocol scope.
    """
    try:
        origin = _origin(origin)
        if type(allowed_origins) is not frozenset or not 1 <= len(allowed_origins) <= 16:
            raise ValueError("invalid HTTPS broker allowlist")
        allowed_origins = frozenset(_origin(item) for item in allowed_origins)
        _limits(limits)
        if selected_ip_address is not None and (
            type(selected_ip_address) is not str or len(selected_ip_address) > 64
        ):
            raise ValueError("invalid HTTPS broker address")
        if any(type(value) is not str for value in
               (resolution_id, authorization_id, session_id, operation_id)):
            raise ValueError("invalid HTTPS broker identifier")
        preflight = evaluate_browser_network_resolution(origin, allowed_origins, ())
    except Exception:
        raise BrowserHTTPSBrokerError("invalid_input") from None
    if preflight.reason != "empty_resolution":
        raise BrowserHTTPSBrokerError("resolution_denied")
    if not _SLOT.acquire(blocking=False):
        raise BrowserHTTPSBrokerError("broker_busy")
    tcp = None
    tls = None
    phase = "dns_failed"
    try:
        try:
            result = resolve_browser_dns(origin, allowed_origins, limits=limits.dns_limits)
            if type(result) is not BrowserDNSResolutionResult:
                raise BrowserHTTPSBrokerError("dns_failed")
            result = BrowserDNSResolutionResult(result.origin, result.admission, result.infrastructure_error)
            if result.origin != origin or result.infrastructure_error is not None:
                raise BrowserHTTPSBrokerError("dns_failed")
            if result.status != "admitted":
                raise BrowserHTTPSBrokerError("resolution_denied")
            decision = result.admission
            repeated = evaluate_browser_network_resolution(
                origin, allowed_origins, decision.admitted_ip_addresses,
            )
            if repeated != decision:
                raise BrowserHTTPSBrokerError("resolution_denied")
            phase = "invalid_input"
            snapshot = BrowserAdmittedResolution(resolution_id, decision)
            auth = BrowserConnectionAuthorization(snapshot, authorization_id, session_id, operation_id)
            ip = decision.admitted_ip_addresses[0] if selected_ip_address is None else selected_ip_address
            if not _policy_allows(auth, ip, 443):
                raise BrowserHTTPSBrokerError("destination_denied")
            address = ipaddress.ip_address(ip)
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            destination = (ip, 443) if address.version == 4 else (ip, 443, 0, 0)
            deadline = time.monotonic_ns() + limits.establishment_budget_ms * 1_000_000
            phase = "tls_failed"
            context = _create_tls_context()
            _check_tls(context)
            phase = "tcp_failed"
            _remaining_timeout(deadline, limits.tcp_timeout_ms)
            tcp = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            tcp.settimeout(_remaining_timeout(deadline, limits.tcp_timeout_ms))
            tcp.connect(destination)  # Canonical numeric IP: no hostname lookup.
            _check_peer(tcp, auth, ip, address.version)
            phase = "tls_failed"
            tcp.settimeout(_remaining_timeout(deadline, limits.tls_timeout_ms))
            tls = context.wrap_socket(
                tcp, server_hostname=origin.hostname, do_handshake_on_connect=False,
                suppress_ragged_eofs=False,
            )
            tls.settimeout(_remaining_timeout(deadline, limits.tls_timeout_ms))
            if tls.context is not context or tls.server_hostname != origin.hostname:
                raise BrowserHTTPSBrokerError("tls_failed")
            _check_tls(tls.context)
            tls.do_handshake()
            _check_tls(tls.context)
            _check_peer(tls, auth, ip, address.version)
            _remaining_timeout(deadline, limits.tls_timeout_ms)
        except BrowserHTTPSBrokerError:
            raise
        except TimeoutError:
            raise BrowserHTTPSBrokerError("timeout") from None
        except Exception:
            raise BrowserHTTPSBrokerError(phase) from None
        yield tls
    finally:
        try:
            if not _close_resources(tls, tcp):
                raise BrowserHTTPSBrokerError("cleanup_failed")
        finally:
            _SLOT.release()
