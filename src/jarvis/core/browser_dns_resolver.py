"""OS name resolution plus whole-snapshot SSRF admission for browser origins.

Uses the standard socket API on Linux and Windows. The OS may consult DNS,
cache, hosts files or other configured name services; this is not authenticated
DNS and is not evidence of a connection, TLS validation or effective pinning.
Results are constructible Python data, not provenance credentials. Infrastructure
must label admitted snapshots through BrowserAdmittedResolution and enforce
numeric-address pinning at the future transport boundary.

getaddrinfo has no portable timeout/cancellation parameter. max_elapsed_ms is
an acceptance budget checked after it returns and after admission, NOT a bound
on blocking time. No worker threads/processes, signal alarms or global socket
timeouts are created. A single nonblocking semaphore limits concurrent calls
through this module per process; contention is rejected without queuing. A hung
system resolver can occupy that slot indefinitely. Native resolver memory,
internal retries and DNS packet counts cannot be bounded here.

At most 64 returned records are processed; smaller caller limits are supported.
Oversized/malformed responses are rejected as a whole, never truncated. Address
strings and canonical-name fields are bounded before parsing. Duplicates are
preserved and rejected by the existing policy. Flags do not request address
configuration filtering or IPv4-mapped synthesis. Only the complete returned
snapshot is evaluated; it need not contain every address published by DNS.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass

from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_network_policy import (
    BrowserNetworkAdmissionDecision,
    evaluate_browser_network_resolution,
)

__all__ = ("BrowserDNSResolutionLimits", "BrowserDNSResolutionResult", "resolve_browser_dns")

_ERROR = "invalid browser DNS resolver input"
_INFRASTRUCTURE_ERRORS = frozenset({
    "dns_error", "resolver_error", "resolver_timeout", "elapsed_budget_exceeded",
    "resource_limit", "malformed_response", "resolver_busy",
})
_SLOT = threading.BoundedSemaphore(1)


def _origin(value: BrowserOrigin) -> BrowserOrigin:
    if type(value) is not BrowserOrigin:
        raise ValueError(_ERROR)
    if (type(value.scheme) is not str or type(value.hostname) is not str
            or type(value.effective_port) is not int):
        raise ValueError(_ERROR)
    return BrowserOrigin(value.scheme, value.hostname, value.effective_port)


def _limits(value: BrowserDNSResolutionLimits) -> None:
    if type(value) is not BrowserDNSResolutionLimits:
        raise ValueError(_ERROR)
    if type(value.max_records) is not int or not 1 <= value.max_records <= 64:
        raise ValueError(_ERROR)
    if type(value.max_elapsed_ms) is not int or not 1 <= value.max_elapsed_ms <= 60_000:
        raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class BrowserDNSResolutionLimits:
    """Response-processing limits and post-return elapsed acceptance budget."""

    max_records: int = 64
    max_elapsed_ms: int = 5_000

    def __post_init__(self) -> None:
        _limits(self)


@dataclass(frozen=True, slots=True)
class BrowserDNSResolutionResult:
    """Either one complete policy decision or one sanitized infrastructure error.

    Denials keep no rejected addresses. Infrastructure failures have no admission
    decision, preventing accidental use of a partially evaluated public subset.
    Construction validates coherence only; status does not authenticate origin
    approval or resolver provenance. Invalid API inputs raise constant ValueError
    before any resolution instead of manufacturing a DNS result.
    """

    origin: BrowserOrigin
    admission: BrowserNetworkAdmissionDecision | None
    infrastructure_error: str | None

    def __post_init__(self) -> None:
        try:
            origin = _origin(self.origin)
            if self.infrastructure_error is not None:
                if (type(self.infrastructure_error) is not str
                        or self.infrastructure_error not in _INFRASTRUCTURE_ERRORS
                        or self.admission is not None):
                    raise ValueError(_ERROR)
            else:
                decision = self.admission
                if type(decision) is not BrowserNetworkAdmissionDecision:
                    raise ValueError(_ERROR)
                _origin(decision.origin)
                if type(decision.reason) is not str:
                    raise ValueError(_ERROR)
                BrowserNetworkAdmissionDecision(
                    decision.origin, decision.admitted, decision.reason,
                    decision.admitted_ip_addresses,
                )
                if decision.origin != origin:
                    raise ValueError(_ERROR)
        except (ValueError, AttributeError):
            raise ValueError(_ERROR) from None
        object.__setattr__(self, "origin", origin)

    @property
    def status(self) -> str:
        if self.infrastructure_error is not None:
            return "infrastructure_error"
        return "admitted" if self.admission.admitted else "rejected"


class _ResponseFailure(Exception):
    """Internal fixed error code, never address/exception details."""


def _addresses(records: list, maximum: int) -> tuple[str, ...]:
    if type(records) is not list:
        raise _ResponseFailure("malformed_response")
    if len(records) > maximum:
        raise _ResponseFailure("resource_limit")
    addresses: list[str] = []
    for record in records:
        if type(record) is not tuple or len(record) != 5:
            raise _ResponseFailure("malformed_response")
        family, kind, protocol, canonical_name, sockaddr = record
        if (type(family) not in (int, socket.AddressFamily)
                or family not in (socket.AF_INET, socket.AF_INET6)
                or type(kind) not in (int, socket.SocketKind)
                or kind != socket.SOCK_STREAM
                or type(protocol) is not int or protocol != socket.IPPROTO_TCP
                or type(canonical_name) is not str
                or type(sockaddr) is not tuple):
            raise _ResponseFailure("malformed_response")
        if len(canonical_name) > 253:
            raise _ResponseFailure("resource_limit")
        expected_length = 2 if family == socket.AF_INET else 4
        if len(sockaddr) != expected_length:
            raise _ResponseFailure("malformed_response")
        address, port = sockaddr[:2]
        if type(address) is not str or type(port) is not int or port != 443:
            raise _ResponseFailure("malformed_response")
        if len(address) > 64:
            raise _ResponseFailure("resource_limit")
        if family == socket.AF_INET6 and any(
            type(value) is not int or value != 0 for value in sockaddr[2:]
        ):
            # Do not discard nonzero flow/scope metadata to create permission.
            raise _ResponseFailure("malformed_response")
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            # Invalid address text belongs to the whole-snapshot policy. Retain
            # it until that policy rejects it, without exposing it in results.
            pass
        else:
            if parsed.version != (4 if family == socket.AF_INET else 6):
                raise _ResponseFailure("malformed_response")
        addresses.append(address)
    return tuple(addresses)


def resolve_browser_dns(
    origin: BrowserOrigin,
    allowed_origins: frozenset[BrowserOrigin],
    *, limits: BrowserDNSResolutionLimits = BrowserDNSResolutionLimits(),
) -> BrowserDNSResolutionResult:
    """Resolve once after exact HTTPS/443 approval; admit all IPs or none.

    No input-supplied resolver/callback is accepted. OSError/DNS failures and
    unexpected resolver exceptions become fixed infrastructure codes. Process
    control exceptions (KeyboardInterrupt/SystemExit) propagate, releasing the
    slot. There is no retry, hostname re-resolution, connection or logging.
    """
    try:
        origin = _origin(origin)
        _limits(limits)
        if type(allowed_origins) is not frozenset or not 1 <= len(allowed_origins) <= 16:
            raise ValueError(_ERROR)
        allowed_origins = frozenset(_origin(item) for item in allowed_origins)
        preflight = evaluate_browser_network_resolution(origin, allowed_origins, ())
    except (ValueError, AttributeError):
        raise ValueError(_ERROR) from None
    if preflight.reason != "empty_resolution":
        return BrowserDNSResolutionResult(origin, preflight, None)
    if not _SLOT.acquire(blocking=False):
        return BrowserDNSResolutionResult(origin, None, "resolver_busy")
    try:
        started = time.monotonic_ns()
        try:
            records = socket.getaddrinfo(
                origin.hostname, 443, family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=0,
            )
        except TimeoutError:
            return BrowserDNSResolutionResult(origin, None, "resolver_timeout")
        except OSError:
            return BrowserDNSResolutionResult(origin, None, "dns_error")
        except MemoryError:
            return BrowserDNSResolutionResult(origin, None, "resource_limit")
        except Exception:
            return BrowserDNSResolutionResult(origin, None, "resolver_error")
        if time.monotonic_ns() - started > limits.max_elapsed_ms * 1_000_000:
            return BrowserDNSResolutionResult(origin, None, "elapsed_budget_exceeded")
        try:
            addresses = _addresses(records, limits.max_records)
            decision = evaluate_browser_network_resolution(origin, allowed_origins, addresses)
            result = BrowserDNSResolutionResult(origin, decision, None)
        except _ResponseFailure as failure:
            return BrowserDNSResolutionResult(origin, None, failure.args[0])
        except MemoryError:
            return BrowserDNSResolutionResult(origin, None, "resource_limit")
        if time.monotonic_ns() - started > limits.max_elapsed_ms * 1_000_000:
            return BrowserDNSResolutionResult(origin, None, "elapsed_budget_exceeded")
        return result
    finally:
        _SLOT.release()
