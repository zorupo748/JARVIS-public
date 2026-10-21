"""Pure, fail-closed admission of an infrastructure-supplied DNS snapshot.

Admission applies only to this resolution snapshot. No DNS lookup or connection
is made, and DNS rebinding is not solved here. A future egress broker must pin
and revalidate the admitted addresses for the actual connection. Construction
and evaluation establish neither infrastructure provenance nor execution.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from jarvis.core.browser_operation_contract import BrowserOrigin

__all__ = ("BrowserNetworkAdmissionDecision", "evaluate_browser_network_resolution")

_REASONS = frozenset({
    "allowed", "origin_not_allowed", "https_required", "port_443_required",
    "empty_resolution", "invalid_address", "duplicate_address",
    "ipv4_mapped_address", "non_global_address",
})
_MAX_ORIGINS = 16
_MAX_ADDRESSES = 64


def _plain_string(value: str, field_name: str) -> str:
    if not issubclass(type(value), str):
        raise ValueError(f"{field_name} must be a string")
    return str.__str__(value)


def _detach_origin(origin: BrowserOrigin, field_name: str) -> BrowserOrigin:
    if type(origin) is not BrowserOrigin:
        raise ValueError(f"{field_name} must be exactly BrowserOrigin")
    if type(origin.scheme) is str and type(origin.hostname) is str:
        return origin
    return BrowserOrigin(
        _plain_string(origin.scheme, "origin scheme"),
        _plain_string(origin.hostname, "origin hostname"), origin.effective_port,
    )


def _require_address_tuple(values: tuple[str, ...], field_name: str) -> None:
    if type(values) is not tuple:
        raise ValueError(f"{field_name} must be exactly tuple")
    if len(values) > _MAX_ADDRESSES:
        raise ValueError(f"{field_name} must contain at most 64 addresses")
    if any(type(value) is not str for value in values):
        raise ValueError(f"{field_name} members must be exactly str")


def _is_admissible(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_global is True
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
        and not (address.version == 6 and address.is_site_local)
    )


def _admit_addresses(values: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    canonical: list[str] = []
    for value in values:
        if "%" in value:
            return "invalid_address", ()
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return "invalid_address", ()
        addresses.append(address)
        canonical.append(str(address))

    # Parse the whole snapshot before applying these gates. A later syntax
    # error takes precedence over an earlier duplicate or blocked address.
    if len(set(canonical)) != len(canonical):
        return "duplicate_address", ()
    if any(address.version == 6 and address.ipv4_mapped is not None for address in addresses):
        return "ipv4_mapped_address", ()
    if any(not _is_admissible(address) for address in addresses):
        return "non_global_address", ()
    return "allowed", tuple(canonical)


@dataclass(frozen=True, slots=True)
class BrowserNetworkAdmissionDecision:
    """A bounded snapshot decision; denials retain no rejected IP addresses.

    Direct construction validates coherence and canonical admissible addresses,
    without proving that an allowlist or a DNS resolver supplied the record.
    """

    origin: BrowserOrigin
    admitted: bool
    reason: str
    admitted_ip_addresses: tuple[str, ...]

    def __post_init__(self) -> None:
        origin = _detach_origin(self.origin, "origin")
        if type(self.admitted) is not bool:
            raise ValueError("admitted must be exactly bool")
        reason = _plain_string(self.reason, "reason")
        if reason not in _REASONS:
            raise ValueError("reason must be a V1 admission reason")
        _require_address_tuple(self.admitted_ip_addresses, "admitted_ip_addresses")
        if self.admitted:
            if reason != "allowed" or not self.admitted_ip_addresses:
                raise ValueError("admitted decisions require reason allowed and 1..64 addresses")
            if origin.scheme != "https" or origin.effective_port != 443:
                raise ValueError("admitted decisions require HTTPS on port 443")
            address_reason, canonical = _admit_addresses(self.admitted_ip_addresses)
            if address_reason != "allowed" or canonical != self.admitted_ip_addresses:
                raise ValueError("admitted_ip_addresses must be unique canonical admissible IPs")
        elif reason == "allowed" or self.admitted_ip_addresses:
            raise ValueError("denied decisions require a denial reason and no addresses")
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "reason", reason)


def evaluate_browser_network_resolution(
    origin: BrowserOrigin,
    allowed_origins: frozenset[BrowserOrigin],
    resolved_ip_addresses: tuple[str, ...],
) -> BrowserNetworkAdmissionDecision:
    """Admit every address together or deny the entire supplied snapshot.

    Structural API errors raise ValueError with fixed messages. Policy reasons
    follow allowlist, HTTPS, port, empty resolution, syntax, duplicate, mapped,
    then global-address gates, independently of input address ordering.
    """
    origin = _detach_origin(origin, "origin")
    if type(allowed_origins) is not frozenset:
        raise ValueError("allowed_origins must be exactly frozenset")
    if not 1 <= len(allowed_origins) <= _MAX_ORIGINS:
        raise ValueError("allowed_origins must contain 1..16 origins")
    allowed_origins = frozenset(
        _detach_origin(item, "allowed_origins member") for item in allowed_origins
    )
    _require_address_tuple(resolved_ip_addresses, "resolved_ip_addresses")

    if origin not in allowed_origins:
        return BrowserNetworkAdmissionDecision(origin, False, "origin_not_allowed", ())
    if origin.scheme != "https":
        return BrowserNetworkAdmissionDecision(origin, False, "https_required", ())
    if origin.effective_port != 443:
        return BrowserNetworkAdmissionDecision(origin, False, "port_443_required", ())
    if not resolved_ip_addresses:
        return BrowserNetworkAdmissionDecision(origin, False, "empty_resolution", ())
    reason, canonical = _admit_addresses(resolved_ip_addresses)
    return BrowserNetworkAdmissionDecision(origin, reason == "allowed", reason, canonical)
