"""Pure structural policy for future DNS pinning; no transport evidence.

A supplied admission record is revalidated through the existing policy API.
Neither direct construction nor that reevaluation proves a DNS lookup occurred
or authenticates an allowlist. Infrastructure must establish provenance,
expiry, registry-wide ID uniqueness, session ownership and authorization use.

The complete admitted snapshot is retained, never narrowed to a public subset.
Destination evaluation compares caller-supplied data only. Future egress must
connect to a pinned numeric address, preserve the HTTPS origin for TLS/HTTP,
and independently enforce/check the real socket destination. Resolving the
hostname again after admission does not enforce this contract.

IDs are opaque, non-secret local labels (1..128 ASCII letters/digits/_/-),
without normalization. The four labels within an authorization are distinct;
there is no global registry, freshness or single-use guarantee here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_network_policy import (
    BrowserNetworkAdmissionDecision,
    evaluate_browser_network_resolution,
)

__all__ = (
    "BrowserAdmittedResolution", "BrowserConnectionAuthorization",
    "BrowserEgressDestinationDecision", "authorize_browser_connection",
    "evaluate_browser_egress_destination",
)

_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_ERROR = "invalid browser egress contract"


def _require_id(value: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(_ERROR)


def _require_origin(origin: BrowserOrigin) -> None:
    if type(origin) is not BrowserOrigin:
        raise ValueError(_ERROR)
    if (type(origin.scheme) is not str or type(origin.hostname) is not str
            or type(origin.effective_port) is not int):
        raise ValueError(_ERROR)
    # Reuse the known constructor, including its hostname and port validation.
    BrowserOrigin(origin.scheme, origin.hostname, origin.effective_port)


def _require_admission(decision: BrowserNetworkAdmissionDecision) -> None:
    if type(decision) is not BrowserNetworkAdmissionDecision:
        raise ValueError(_ERROR)
    _require_origin(decision.origin)
    if type(decision.admitted) is not bool or type(decision.reason) is not str:
        raise ValueError(_ERROR)
    # Known constructor rechecks coherence and canonical addresses even for a
    # record fabricated with object.__new__ or modified with object.__setattr__.
    BrowserNetworkAdmissionDecision(
        decision.origin, decision.admitted, decision.reason,
        decision.admitted_ip_addresses,
    )
    if decision.admitted is not True:
        raise ValueError(_ERROR)
    repeated = evaluate_browser_network_resolution(
        decision.origin, frozenset({decision.origin}), decision.admitted_ip_addresses,
    )
    if repeated != decision:
        raise ValueError(_ERROR)


def _require_resolution(resolution: BrowserAdmittedResolution) -> None:
    if type(resolution) is not BrowserAdmittedResolution:
        raise ValueError(_ERROR)
    _require_id(resolution.resolution_id)
    _require_admission(resolution.admission)


def _require_authorization(authorization: BrowserConnectionAuthorization) -> None:
    if type(authorization) is not BrowserConnectionAuthorization:
        raise ValueError(_ERROR)
    _require_resolution(authorization.resolution)
    labels = (authorization.resolution.resolution_id, authorization.authorization_id,
              authorization.session_id, authorization.operation_id)
    for label in labels:
        _require_id(label)
    if len(set(labels)) != len(labels):
        raise ValueError(_ERROR)


@dataclass(frozen=True, slots=True)
class BrowserAdmittedResolution:
    """Locally labelled admitted snapshot, without resolver provenance."""

    resolution_id: str
    admission: BrowserNetworkAdmissionDecision

    def __post_init__(self) -> None:
        try:
            _require_id(self.resolution_id)
            _require_admission(self.admission)
        except (ValueError, AttributeError):
            raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True)
class BrowserConnectionAuthorization:
    """Structural permission to attempt a pinned connection for one context.

    Origin, port and the entire immutable IP tuple are bound through resolution.
    This record is data, not an unforgeable credential or execution evidence.
    """

    resolution: BrowserAdmittedResolution
    authorization_id: str
    session_id: str
    operation_id: str

    def __post_init__(self) -> None:
        try:
            _require_authorization(self)
        except (ValueError, AttributeError):
            raise ValueError(_ERROR) from None


def authorize_browser_connection(
    resolution: BrowserAdmittedResolution,
    authorization_id: str,
    session_id: str,
    operation_id: str,
) -> BrowserConnectionAuthorization:
    """Derive structural permission solely from a coherent admitted snapshot."""
    return BrowserConnectionAuthorization(resolution, authorization_id, session_id, operation_id)


@dataclass(frozen=True, slots=True)
class BrowserEgressDestinationDecision:
    """Policy comparison of a declared selection, never a measured socket peer.

    Mismatched identifiers, origins, ports and addresses are denied. Malformed
    structural types/IDs raise a constant ValueError. A noncanonical address is
    denied rather than normalized into permission. policy_allowed is derived,
    cannot be supplied, and never means a connection occurred.
    """

    authorization: BrowserConnectionAuthorization
    resolution_id: str
    authorization_id: str
    session_id: str
    operation_id: str
    origin: BrowserOrigin
    port: int
    selected_ip_address: str
    policy_allowed: bool = field(init=False)

    def __post_init__(self) -> None:
        try:
            _require_authorization(self.authorization)
            for label in (self.resolution_id, self.authorization_id,
                          self.session_id, self.operation_id):
                _require_id(label)
            _require_origin(self.origin)
            if type(self.port) is not int or not 1 <= self.port <= 65535:
                raise ValueError(_ERROR)
            if type(self.selected_ip_address) is not str:
                raise ValueError(_ERROR)
            auth = self.authorization
            admission = auth.resolution.admission
            selected = evaluate_browser_network_resolution(
                self.origin, frozenset({admission.origin}), (self.selected_ip_address,),
            )
            allowed = (
                self.resolution_id == auth.resolution.resolution_id
                and self.authorization_id == auth.authorization_id
                and self.session_id == auth.session_id
                and self.operation_id == auth.operation_id
                and self.origin == admission.origin
                and self.port == admission.origin.effective_port
                and selected.admitted is True
                and selected.admitted_ip_addresses == (self.selected_ip_address,)
                and self.selected_ip_address in admission.admitted_ip_addresses
            )
        except (ValueError, AttributeError):
            raise ValueError(_ERROR) from None
        object.__setattr__(self, "policy_allowed", allowed)


def evaluate_browser_egress_destination(
    authorization: BrowserConnectionAuthorization, *,
    resolution_id: str, authorization_id: str, session_id: str,
    operation_id: str, origin: BrowserOrigin, port: int,
    selected_ip_address: str,
) -> BrowserEgressDestinationDecision:
    """Compare supplied selection/context with the complete pinned snapshot."""
    return BrowserEgressDestinationDecision(
        authorization, resolution_id, authorization_id, session_id, operation_id,
        origin, port, selected_ip_address,
    )
