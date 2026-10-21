"""Pure, fail-closed V1 evaluation of structural browser research evidence.

Inputs must come from trusted infrastructure. This evaluator proves only the
declared structural operation and response metadata, never body semantics or
physical traffic outside the session model. It performs no collection or I/O.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from jarvis.core.browser_attribution_evidence import BrowserCapabilityAttributionEvidence
from jarvis.core.browser_endpoint_adapter import browser_request_evidence_to_endpoint_observation
from jarvis.core.browser_network_evidence import BrowserRequestEvidence
from jarvis.core.browser_operation_contract import (
    BrowserOperationContract,
    browser_origin_from_url,
    normalize_static_operation_path,
)
from jarvis.core.browser_research_context import BrowserResearchEvaluationContext
from jarvis.core.browser_session_evidence import BrowserResearchSessionEvidence
from jarvis.core.external_source_research import (
    ExternalSourceResearchResult,
    validate_research_result,
)

__all__ = ("evaluate_browser_research",)

_GLOBAL_FAILURE = "browser_v1_global_requirements_not_met"
_ATTRIBUTION_FAILURE = "browser_v1_unique_attribution_not_established"
_CONTRACT_FAILURE = "browser_v1_contract_requirements_not_met"
_BASIS_FAILURE = "browser_v1_attribution_basis_not_established"
_REQUEST_FAILURE = "browser_v1_request_signature_not_established"
_AMBIGUITY_FAILURE = "browser_v1_operation_occurrence_ambiguous"
_RESPONSE_FAILURE = "browser_v1_response_requirements_not_met"
_SEMANTIC_FAILURE = "browser_v1_functional_evidence_unavailable"
_EXPORT_FAILURE = "browser_v1_export_requirements_not_met"
_RESULT_FAILURE = "browser_v1_result_validation_failed"
_SUFFICIENT_NOTES = (
    "browser_v1_attributed_operation",
    "response_format_is_declared_mime_not_body_validation",
    "top_level_http_metadata_describes_initial_navigation",
)
_MAX_PARAMETER_NAMES = 64
_MAX_PARAMETER_NAME_LENGTH = 64
_BUDGET_FIELDS = (
    ("max_duration_ms", "duration_ms"),
    ("max_requests", "request_count"),
    ("max_bytes", "observed_bytes"),
    ("max_redirects", "redirect_count"),
    ("max_interactions", "interaction_count"),
)


def _insufficient(
    context: BrowserResearchEvaluationContext, code: str, confidence: float,
) -> ExternalSourceResearchResult:
    return ExternalSourceResearchResult(
        source=context.source_url,
        access_method="",
        observed_endpoints=(),
        response_format="",
        required_parameters=(),
        notes=(code,),
        confidence=confidence,
        research_status="insufficient_research",
        final_url="",
        http_status=None,
        content_type="",
        page_kind="unknown",
        evidence=(),
        observed_assets=(),
        endpoint_observations=(),
    )


def _is_sanitized_http_url(value: str) -> bool:
    """Check exportable request URLs, including directly constructed records."""
    if not isinstance(value, str) or any(
        character.isspace() or ord(character) < 32 or 127 <= ord(character) <= 159
        or character == "\\"
        for character in value
    ):
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and "?" not in value
        and "#" not in value
    )


def _has_canonical_parameter_names(names: object) -> bool:
    """Reject malformed direct evidence without normalization or callbacks."""
    if type(names) is not tuple or len(names) > _MAX_PARAMETER_NAMES:
        return False
    if any(
        type(name) is not str
        or not name
        or len(name) > _MAX_PARAMETER_NAME_LENGTH
        or name != name.strip()
        for name in names
    ):
        return False
    return len(set(names)) == len(names)


def _request_matches_contract(
    request: BrowserRequestEvidence, contract: BrowserOperationContract,
) -> bool:
    """Match the complete known signature, without values or URL heuristics."""
    if (
        request.method != contract.http_method
        or not _has_canonical_parameter_names(request.query_parameter_names)
        or not _has_canonical_parameter_names(request.body_parameter_names)
    ):
        return False
    try:
        origin = browser_origin_from_url(request.endpoint_url)
        path = normalize_static_operation_path(urlsplit(request.endpoint_url).path)
    except ValueError:
        # Requests support broader URL syntax than V1 operation contracts.
        return False
    if origin != contract.authorized_origin or path != contract.expected_path:
        return False
    observed_query = set(request.query_parameter_names)
    observed_body = set(request.body_parameter_names)
    return (
        contract.expected_query_parameter_names is not None
        and contract.expected_body_parameter_names is not None
        and contract.demonstrated_required_query_parameter_names
        <= observed_query <= contract.expected_query_parameter_names
        and contract.demonstrated_required_body_parameter_names
        <= observed_body <= contract.expected_body_parameter_names
    )


def evaluate_browser_research(
    context: BrowserResearchEvaluationContext,
    session: BrowserResearchSessionEvidence,
    attributions: tuple[BrowserCapabilityAttributionEvidence, ...],
) -> ExternalSourceResearchResult:
    """Return V1 sufficiency only after every authorization/evidence/export gate.

    Wrong public input types raise ValueError, including subclasses. Expected
    evidence/policy failures return a bounded result with fixed safe notes.
    Confidence is a gate level, not a probability or an accumulation of points.
    """
    if type(context) is not BrowserResearchEvaluationContext:
        raise ValueError("context must be exactly BrowserResearchEvaluationContext")
    if type(session) is not BrowserResearchSessionEvidence:
        raise ValueError("session must be exactly BrowserResearchSessionEvidence")
    if type(attributions) is not tuple or any(
        type(item) is not BrowserCapabilityAttributionEvidence for item in attributions
    ):
        raise ValueError("attributions must be exactly tuple of BrowserCapabilityAttributionEvidence")

    if (
        session.session_id != context.expected_session_id
        or session.initial_page_url != context.source_url
        or session.collection_status != "complete"
        or session.lost_events is not False
        or any(phase.collection_status != "complete" for phase in session.phases)
        or len(session.phases) > context.evidence_limits.max_phases
        or len(attributions) > context.evidence_limits.max_attributions
        or any(
            getattr(session, maximum) > getattr(context, maximum)
            or getattr(session, counter) > getattr(context, maximum)
            for maximum, counter in _BUDGET_FIELDS
        )
    ):
        return _insufficient(context, _GLOBAL_FAILURE, 0.00)

    source_origin = browser_origin_from_url(context.source_url)
    same_origin = frozenset({source_origin})
    if (
        source_origin.scheme != "https"
        or context.allowed_navigation_origins != same_origin
        or context.allowed_endpoint_origins != same_origin
        or session.redirect_count != 0
        or any(exchange.redirect_from_exchange_id is not None for exchange in session.exchanges)
        or session.final_page_url is None
    ):
        return _insufficient(context, _GLOBAL_FAILURE, 0.00)
    try:
        final_origin = browser_origin_from_url(session.final_page_url)
    except ValueError:
        return _insufficient(context, _GLOBAL_FAILURE, 0.00)
    if final_origin != source_origin:
        return _insufficient(context, _GLOBAL_FAILURE, 0.00)

    interactions_by_id = {
        interaction.interaction_id: interaction for interaction in context.authorized_interactions
    }
    phases_by_id = {phase.phase_id: phase for phase in session.phases}
    for phase in session.phases:
        if phase.kind == "interaction":
            authorized = interactions_by_id.get(phase.interaction_id)
            if (
                authorized is None
                or phase.interaction_kind == "other"
                or phase.interaction_kind != authorized.interaction_kind
                or phase.interaction_result != "completed"
            ):
                return _insufficient(context, _GLOBAL_FAILURE, 0.00)

    # Known totals omit unknown sizes and include estimates. Require a measured
    # size for every dispatched request before treating that total as a proof.
    for exchange in session.exchanges:
        if exchange.send_state == "unknown" or (
            exchange.send_state == "sent" and (
                exchange.response is None
                or exchange.response.observed_bytes is None
                or exchange.response.observed_bytes_kind != "measured"
            )
        ):
            return _insufficient(context, _GLOBAL_FAILURE, 0.00)

    exchanges_by_id = {exchange.exchange_id: exchange for exchange in session.exchanges}
    navigation = exchanges_by_id.get(session.initial_navigation_exchange_id)
    if navigation is None:
        return _insufficient(context, _GLOBAL_FAILURE, 0.00)
    navigation_phase = phases_by_id.get(navigation.phase_id)
    navigation_response = navigation.response
    if (
        navigation_phase is None
        or navigation_phase.kind != "baseline"
        or navigation.send_state != "sent"
        or navigation.completion != "complete"
        or navigation_response is None
        or navigation.request.method != "GET"
        or navigation.request.endpoint_url != context.source_url
        or navigation_response.response_url != context.source_url
        or navigation_response.delivery != "network"
        or not 200 <= navigation_response.status_code <= 299
    ):
        return _insufficient(context, _GLOBAL_FAILURE, 0.00)

    if len(attributions) != 1:
        return _insufficient(context, _ATTRIBUTION_FAILURE, 0.40)
    attribution = attributions[0]
    if attribution.session_id != session.session_id or len(attribution.exchange_path) != 1:
        return _insufficient(context, _ATTRIBUTION_FAILURE, 0.40)
    contract = next(
        (item for item in context.operation_contracts
         if item.contract_id == attribution.operation_contract_id), None,
    )
    exchange = exchanges_by_id.get(attribution.exchange_path[0])
    if contract is None or exchange is None:
        return _insufficient(context, _ATTRIBUTION_FAILURE, 0.40)

    if (
        contract.expected_query_parameter_names is None
        or contract.expected_body_parameter_names is None
        or contract.acceptable_response_formats is None
        or contract.acceptable_http_statuses is None
        or contract.requires_functional_evidence
        or contract.authorized_origin != source_origin
        or "network" not in contract.acceptable_deliveries
    ):
        return _insufficient(context, _CONTRACT_FAILURE, 0.60)

    selected_phase = phases_by_id.get(exchange.phase_id)
    basis = attribution.attribution_basis
    if basis == "INITIAL_NAVIGATION":
        if (
            attribution.interaction_id is not None
            or exchange.exchange_id != session.initial_navigation_exchange_id
            or selected_phase is None
            or selected_phase.kind != "baseline"
        ):
            return _insufficient(context, _BASIS_FAILURE, 0.60)
    else:
        authorized = interactions_by_id.get(attribution.interaction_id)
        if (
            authorized is None
            or authorized.operation_contract_id != contract.contract_id
            or (
                basis == "CONTROLLED_NAVIGATION"
                and authorized.interaction_kind != "navigation"
            )
            or (
                basis == "CONTROLLED_SUBMISSION"
                and authorized.interaction_kind not in {"submit", "input_submit"}
            )
            or basis not in {
                "CONTROLLED_NAVIGATION", "CONTROLLED_SUBMISSION", "OBSERVED_OPERATION_DISPATCH",
            }
            or authorized.interaction_kind not in {"submit", "click", "input_submit", "navigation"}
        ):
            return _insufficient(context, _BASIS_FAILURE, 0.60)
        interaction_phases = tuple(
            phase for phase in session.phases if phase.interaction_id == attribution.interaction_id
        )
        if len(interaction_phases) != 1:
            return _insufficient(context, _BASIS_FAILURE, 0.60)
        phase = interaction_phases[0]
        if (
            phase.kind != "interaction"
            or phase.interaction_kind != authorized.interaction_kind
            or phase.interaction_result != "completed"
            or exchange.phase_id != phase.phase_id
        ):
            return _insufficient(context, _BASIS_FAILURE, 0.60)

    response = exchange.response
    if (
        exchange.send_state != "sent"
        or exchange.completion != "complete"
        or response is None
        or exchange.redirect_from_exchange_id is not None
        or not _is_sanitized_http_url(exchange.request.endpoint_url)
        or not _request_matches_contract(exchange.request, contract)
    ):
        return _insufficient(context, _REQUEST_FAILURE, 0.60)

    # Count occurrences across every phase and send state. Hidden values and
    # retries cannot establish equivalence; tuple ordering does not attribute.
    if sum(_request_matches_contract(item.request, contract) for item in session.exchanges) != 1:
        return _insufficient(context, _AMBIGUITY_FAILURE, 0.60)

    if (
        response.response_url != exchange.request.endpoint_url
        or response.delivery != "network"
        or "network" not in context.allowed_deliveries
        or "network" not in contract.acceptable_deliveries
        or response.status_code not in contract.acceptable_http_statuses
        or not 200 <= response.status_code <= 299
        or response.response_format == "unknown"
        or response.response_format not in contract.acceptable_response_formats
        or not response.content_type
        or (contract.requires_response_content and (
            response.observed_bytes_kind != "measured"
            or response.observed_bytes is None
            or response.observed_bytes <= 0
        ))
    ):
        return _insufficient(context, _RESPONSE_FAILURE, 0.60)
    if context.capability_requirement == "FUNCTIONAL_RESULT":
        return _insufficient(context, _SEMANTIC_FAILURE, 0.60)

    # BrowserRequestEvidence also allows direct construction without validation.
    # The existing adapter exports these URLs unchanged; require sanitized,
    # same-origin page/asset URLs for the selected request only.
    request = exchange.request
    if not _is_sanitized_http_url(request.page_url) or (
        request.source_asset is not None and not _is_sanitized_http_url(request.source_asset)
    ):
        return _insufficient(context, _EXPORT_FAILURE, 0.60)
    try:
        page_origin = browser_origin_from_url(request.page_url)
        asset_origin = (
            None if request.source_asset is None
            else browser_origin_from_url(request.source_asset)
        )
    except ValueError:
        return _insufficient(context, _EXPORT_FAILURE, 0.60)
    if page_origin != source_origin or (asset_origin is not None and asset_origin != source_origin):
        return _insufficient(context, _EXPORT_FAILURE, 0.60)

    observed_endpoints = (request.endpoint_url,)
    required_parameters = tuple(sorted(
        contract.demonstrated_required_query_parameter_names
        | contract.demonstrated_required_body_parameter_names
    ))
    evidence = (
        f"session_id:{session.session_id}",
        f"contract_id:{contract.contract_id}",
        f"exchange_id:{exchange.exchange_id}",
        f"attribution_basis:{basis}",
        f"operation_http_status:{response.status_code}",
        f"operation_content_type:{response.content_type}",
    )
    endpoint_observations = (browser_request_evidence_to_endpoint_observation(request),)
    observed_assets = ()
    limits = context.evidence_limits
    exported_items = (
        len(observed_endpoints) + len(endpoint_observations) + len(required_parameters)
        + len(_SUFFICIENT_NOTES) + len(evidence) + len(observed_assets)
    )
    if (
        len(endpoint_observations) > limits.max_exported_endpoint_observations
        or exported_items > limits.max_exported_evidence_items
    ):
        return _insufficient(context, _EXPORT_FAILURE, 0.60)

    result = ExternalSourceResearchResult(
        source=context.source_url,
        access_method=f"Browser-observed {request.method} {request.endpoint_url}",
        observed_endpoints=observed_endpoints,
        response_format=response.response_format,
        required_parameters=required_parameters,
        notes=_SUFFICIENT_NOTES,
        confidence=0.80,
        research_status="sufficient",
        final_url=session.final_page_url,
        http_status=navigation_response.status_code,
        content_type=navigation_response.content_type,
        page_kind="unknown",
        evidence=evidence,
        observed_assets=observed_assets,
        endpoint_observations=endpoint_observations,
    )
    if len(result.to_prompt_context().encode("utf-8")) > limits.max_exported_utf8_bytes:
        return _insufficient(context, _EXPORT_FAILURE, 0.60)
    if not result.sufficient:
        return _insufficient(context, _RESULT_FAILURE, 0.60)
    try:
        validate_research_result(result)
    except (TypeError, ValueError):
        # These are the validator's explicit data-contract failures. Unexpected
        # programming errors propagate instead of disguising bugs as evidence.
        return _insufficient(context, _RESULT_FAILURE, 0.60)
    return result
