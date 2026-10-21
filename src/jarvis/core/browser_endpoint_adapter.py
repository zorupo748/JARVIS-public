"""Adapter to convert BrowserRequestEvidence to ExternalEndpointObservation.

This module provides a pure, dependency-free conversion from a
:class:`~jarvis.core.browser_network_evidence.BrowserRequestEvidence` instance to an
:class:`~jarvis.core.external_source_research.ExternalEndpointObservation`.

The conversion follows exactly the contract described in the task:

* `endpoint` → ``evidence.endpoint_url``
* `http_method` → ``evidence.method``
* `consulted` → ``evidence.consulted``
* `parameters` → ``evidence.query_parameter_names`` merged with
  ``evidence.body_parameter_names`` preserving first‑appearance order and
  removing duplicates.
* `context` → ``evidence.page_url``
* `observation_type` → ``"browser_network_request"``
* `url_kind` → ``"absolute"``
* `source_asset` → ``evidence.source_asset`` if not ``None`` else ``evidence.page_url``

The adapter never mutates its input and does not add any additional
metadata.  It is intentionally simple and deterministic.
"""

from __future__ import annotations

from jarvis.core.browser_network_evidence import BrowserRequestEvidence
from jarvis.core.external_source_research import ExternalEndpointObservation

__all__ = ["browser_request_evidence_to_endpoint_observation"]


def browser_request_evidence_to_endpoint_observation(
    evidence: BrowserRequestEvidence,
) -> ExternalEndpointObservation:
    """Create a new :class:`ExternalEndpointObservation` from *evidence*.

    Parameters
    ----------
    evidence:
        The :class:`BrowserRequestEvidence` instance to convert.

    Returns
    -------
    ExternalEndpointObservation
        A new observation containing only the fields required by the
        trusted research contract.
    """

    # Combine query and body parameter names.
    seen: set[str] = set()
    parameters: list[str] = []
    for name in evidence.query_parameter_names:
        if name not in seen:
            seen.add(name)
            parameters.append(name)
    for name in evidence.body_parameter_names:
        if name not in seen:
            seen.add(name)
            parameters.append(name)

    # Determine source_asset: if evidence.source_asset is None, fall back to page_url.
    source_asset = evidence.source_asset if evidence.source_asset is not None else evidence.page_url

    return ExternalEndpointObservation(
        endpoint=evidence.endpoint_url,
        source_asset=source_asset,
        context=evidence.page_url,
        observation_type="browser_network_request",
        url_kind="absolute",
        http_method=evidence.method,
        parameters=tuple(parameters),
        consulted=evidence.consulted,
    )
