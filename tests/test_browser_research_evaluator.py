import copy
import unittest
from contextlib import ExitStack
from dataclasses import fields, replace
from unittest.mock import Mock, PropertyMock, patch

from jarvis.core import browser_research_evaluator as evaluator
from jarvis.core.browser_attribution_evidence import BrowserCapabilityAttributionEvidence
from jarvis.core.browser_endpoint_adapter import browser_request_evidence_to_endpoint_observation
from jarvis.core.browser_exchange_evidence import (
    BrowserNetworkExchangeEvidence,
    BrowserResponseEvidence,
)
from jarvis.core.browser_network_evidence import BrowserRequestEvidence, build_browser_request_evidence
from jarvis.core.browser_operation_contract import BrowserOperationContract, browser_origin_from_url
from jarvis.core.browser_research_context import (
    BrowserAuthorizedInteraction,
    BrowserResearchEvaluationContext,
    BrowserResearchEvidenceLimits,
)
from jarvis.core.browser_session_evidence import (
    BrowserResearchPhaseEvidence,
    BrowserResearchSessionEvidence,
)
from jarvis.core.external_source_research import ExternalSourceResearchResult, validate_research_result


def make_request(url="https://example.com/api/query", method="POST", **overrides):
    values = dict(
        page_url="https://example.com/page?token=PAGE_SECRET#PAGE_FRAGMENT_SECRET",
        request_url=url + "?zeta=QUERY_SECRET&shared=SHARED_SECRET&optional=OPTIONAL_SECRET",
        method=method,
        body_parameter_names=("beta", "shared", "body_optional"),
        source_asset="https://example.com/app.js?key=ASSET_SECRET#ASSET_FRAGMENT_SECRET",
        consulted=True,
    )
    values.update(overrides)
    return build_browser_request_evidence(**values)


def make_response(url="https://example.com/api/query", **overrides):
    values = dict(
        status_code=202, content_type="application/json", response_format="json",
        response_url=url + "?token=RESPONSE_SECRET#RESPONSE_FRAGMENT_SECRET",
        delivery="network", observed_bytes=7, observed_bytes_kind="measured",
    )
    values.update(overrides)
    return BrowserResponseEvidence(**values)


def make_contract(origin=None, **overrides):
    values = dict(
        contract_id="contract-1", http_method="POST",
        authorized_origin=origin or browser_origin_from_url("https://example.com/"),
        expected_path="/api/query",
        expected_query_parameter_names=frozenset({"zeta", "shared", "optional"}),
        expected_body_parameter_names=frozenset({"beta", "shared", "body_optional"}),
        demonstrated_required_query_parameter_names=frozenset({"zeta", "shared"}),
        demonstrated_required_body_parameter_names=frozenset({"beta", "shared"}),
        acceptable_response_formats=frozenset({"json"}),
        acceptable_http_statuses=frozenset({202}),
        acceptable_deliveries=frozenset({"network"}),
        requires_response_content=True, requires_functional_evidence=False,
    )
    values.update(overrides)
    return BrowserOperationContract(**values)


def rebuild_session(session, **overrides):
    """Update evidence with consistent counters through the public constructor."""
    phases = overrides.get("phases", session.phases)
    exchanges = overrides.get("exchanges", session.exchanges)
    values = dict(
        request_count=len(exchanges),
        observed_bytes=sum(
            exchange.response.observed_bytes for exchange in exchanges
            if exchange.response is not None and exchange.response.observed_bytes is not None
        ),
        redirect_count=sum(exchange.redirect_from_exchange_id is not None for exchange in exchanges),
        interaction_count=sum(phase.kind == "interaction" for phase in phases),
    )
    values.update(overrides)
    return replace(session, **values)


def unchecked_copy(record, **overrides):
    """TEST ONLY: exercise defensive gates precluded by validated constructors.

    This creates a separate record without mutating any production input. Tests
    using it explicitly distinguish impossible structural states from ordinary
    valid evidence that the evaluator must reject without raising.
    """
    result = object.__new__(type(record))
    for field in fields(record):
        object.__setattr__(result, field.name, overrides.get(field.name, getattr(record, field.name)))
    return result


def make_fixture(basis="CONTROLLED_SUBMISSION", kind="submit", scheme="https"):
    source = f"{scheme}://example.com/page"
    endpoint = f"{scheme}://example.com/api/query"
    origin = browser_origin_from_url(source)
    baseline = BrowserResearchPhaseEvidence("baseline-1", "baseline", 0, 9, "complete", None, None, None)
    navigation_request = make_request(
        source, "GET", page_url=source, request_url=source + "?page_token=NAVIGATION_SECRET",
        body_parameter_names=(), source_asset=None,
    )
    navigation_response = make_response(
        source, status_code=201, content_type="text/plain", response_format="text", observed_bytes=12,
    )
    navigation = BrowserNetworkExchangeEvidence(
        "navigation-1", navigation_request, "sent", navigation_response, "complete", "baseline-1", 1, None,
    )
    if basis == "INITIAL_NAVIGATION":
        contract = make_contract(
            origin, http_method="GET", expected_path="/page",
            expected_query_parameter_names=frozenset({"page_token"}),
            expected_body_parameter_names=frozenset(),
            demonstrated_required_query_parameter_names=frozenset(),
            demonstrated_required_body_parameter_names=frozenset(),
            acceptable_response_formats=frozenset({"text"}), acceptable_http_statuses=frozenset({201}),
        )
        phases, exchanges, interactions = (baseline,), (navigation,), ()
        interaction_id, selected_id = None, "navigation-1"
    else:
        contract = make_contract(origin, http_method="GET" if kind == "navigation" else "POST")
        phase = BrowserResearchPhaseEvidence(
            "interaction-phase-1", "interaction", 10, 19, "complete", "interaction-1", kind, "completed",
        )
        request = make_request(endpoint, contract.http_method, page_url=source)
        operation = BrowserNetworkExchangeEvidence(
            "operation-1", request, "sent", make_response(endpoint), "complete", "interaction-phase-1", 11, None,
        )
        phases, exchanges = (baseline, phase), (navigation, operation)
        interactions = (BrowserAuthorizedInteraction("interaction-1", kind, contract.contract_id),)
        interaction_id, selected_id = "interaction-1", "operation-1"
    context = BrowserResearchEvaluationContext(
        expected_session_id="session-1", source_url=source + "?key=SOURCE_SECRET#SOURCE_FRAGMENT_SECRET",
        capability_id="capability-1", capability_requirement="ACCESS_PROCEDURE",
        allowed_navigation_origins=frozenset({origin}), allowed_endpoint_origins=frozenset({origin}),
        authorized_interactions=interactions, operation_contracts=(contract,), allowed_deliveries=frozenset({"network"}),
        max_duration_ms=100, max_requests=10, max_bytes=1000, max_redirects=3, max_interactions=3,
        evidence_limits=BrowserResearchEvidenceLimits(4, 4, 1, 32, 8192),
    )
    session = BrowserResearchSessionEvidence(
        session_id="session-1", initial_page_url=source,
        final_page_url=f"{scheme}://example.com/result?key=FINAL_SECRET#FINAL_FRAGMENT_SECRET",
        initial_navigation_exchange_id="navigation-1", collection_status="complete", duration_ms=40,
        request_count=len(exchanges), observed_bytes=sum(item.response.observed_bytes for item in exchanges),
        redirect_count=0, interaction_count=len(interactions),
        max_duration_ms=100, max_requests=10, max_bytes=1000, max_redirects=3, max_interactions=3,
        lost_events=False, phases=phases, exchanges=exchanges,
    )
    attribution = BrowserCapabilityAttributionEvidence(
        "session-1", (selected_id,), interaction_id, contract.contract_id, basis,
    )
    return context, session, (attribution,)


class BrowserResearchEvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.context, self.session, self.attributions = make_fixture()

    def evaluate(self, context=None, session=None, attributions=None):
        return evaluator.evaluate_browser_research(
            self.context if context is None else context,
            self.session if session is None else session,
            self.attributions if attributions is None else attributions,
        )

    def assert_insufficient(self, result, confidence):
        self.assertIs(type(result), ExternalSourceResearchResult)
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertFalse(result.sufficient)
        self.assertEqual(result.confidence, confidence)
        self.assertEqual(len(result.notes), 1)
        self.assertRegex(result.notes[0], r"^browser_v1_[a-z_]+$")
        expected = ExternalSourceResearchResult(
            source=self.context.source_url, access_method="", observed_endpoints=(), response_format="",
            required_parameters=(), notes=result.notes, confidence=confidence,
            research_status="insufficient_research", final_url="", http_status=None,
            content_type="", page_kind="unknown", evidence=(), observed_assets=(), endpoint_observations=(),
        )
        self.assertEqual(result, expected)

    def with_operation(self, **overrides):
        navigation, operation = self.session.exchanges
        return rebuild_session(self.session, exchanges=(navigation, replace(operation, **overrides)))

    def with_response(self, **overrides):
        return self.with_operation(response=replace(self.session.exchanges[1].response, **overrides))

    def with_request(self, **overrides):
        return self.with_operation(request=replace(self.session.exchanges[1].request, **overrides))

    def with_contract(self, **overrides):
        return replace(self.context, operation_contracts=(replace(self.context.operation_contracts[0], **overrides),))

    def with_phase(self, **overrides):
        return rebuild_session(self.session, phases=(self.session.phases[0], replace(self.session.phases[1], **overrides)))

    def with_limits(self, **overrides):
        return replace(self.context, evidence_limits=replace(self.context.evidence_limits, **overrides))

    def test_wrong_context_type(self):
        for value in (None, {}, object(), self.session):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                evaluator.evaluate_browser_research(value, self.session, self.attributions)

    def test_wrong_session_type(self):
        for value in (None, {}, object(), self.context):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                evaluator.evaluate_browser_research(self.context, value, self.attributions)

    def test_attributions_must_be_exact_tuple(self):
        class TupleSubclass(tuple):
            pass

        for value in (None, list(self.attributions), {}, TupleSubclass(self.attributions)):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                evaluator.evaluate_browser_research(self.context, self.session, value)

    def test_wrong_attribution_member_type(self):
        for value in (None, {}, self.context, object()):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.evaluate(attributions=(value,))

    def test_record_subclasses_are_rejected_without_callbacks(self):
        records = (self.context, self.session, self.attributions[0])
        for index, record in enumerate(records):
            subclass = type("UntrustedSubclass", (type(record),), {})
            value = subclass(**{field.name: getattr(record, field.name) for field in fields(record)})
            arguments = [self.context, self.session, self.attributions]
            arguments[index] = (value,) if index == 2 else value
            with self.subTest(index=index), self.assertRaises(ValueError):
                evaluator.evaluate_browser_research(*arguments)

    def test_public_types_are_checked_before_evidence_gates(self):
        bad_session = replace(self.session, session_id="different")
        with self.assertRaises(ValueError):
            self.evaluate(session=bad_session, attributions=(object(),))

    def test_positive_result_has_exact_safe_fields_and_navigation_metadata(self):
        result = self.evaluate()
        request = self.session.exchanges[1].request
        self.assertEqual(result, ExternalSourceResearchResult(
            source=self.context.source_url,
            access_method="Browser-observed POST https://example.com/api/query",
            observed_endpoints=(request.endpoint_url,), response_format="json",
            required_parameters=("beta", "shared", "zeta"),
            notes=("browser_v1_attributed_operation", "response_format_is_declared_mime_not_body_validation",
                   "top_level_http_metadata_describes_initial_navigation"),
            confidence=0.80, research_status="sufficient", final_url="https://example.com/result",
            http_status=201, content_type="text/plain", page_kind="unknown",
            evidence=("session_id:session-1", "contract_id:contract-1", "exchange_id:operation-1",
                      "attribution_basis:CONTROLLED_SUBMISSION", "operation_http_status:202",
                      "operation_content_type:application/json"),
            observed_assets=(), endpoint_observations=(browser_request_evidence_to_endpoint_observation(request),),
        ))
        self.assertTrue(result.sufficient)
        self.assertIs(validate_research_result(result), result)
        self.assertNotEqual(result.http_status, self.session.exchanges[1].response.status_code)
        self.assertNotEqual(result.content_type, self.session.exchanges[1].response.content_type)

    def test_session_identity_mismatch(self):
        self.assert_insufficient(self.evaluate(session=replace(self.session, session_id="session-2")), 0.00)

    def test_initial_page_must_match_exactly_even_for_equivalent_origin(self):
        for url in ("https://example.com/other", "https://example.com:443/page", "https://EXAMPLE.COM/page"):
            with self.subTest(url=url):
                self.assert_insufficient(self.evaluate(session=replace(self.session, initial_page_url=url)), 0.00)

    def test_incomplete_collection_and_lost_events(self):
        for status, lost_events in (("collection_error", False), ("collection_error", True), ("navigation_error", False)):
            with self.subTest(status=status, lost_events=lost_events):
                session = replace(self.session, collection_status=status, lost_events=lost_events)
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_constructor_precluded_complete_collection_defenses(self):
        with self.assertRaises(ValueError):
            replace(self.session, lost_events=True)
        self.assert_insufficient(self.evaluate(session=unchecked_copy(self.session, lost_events=True)), 0.00)
        for status in ("failed", "cancelled"):
            phases = (replace(self.session.phases[0], collection_status=status), self.session.phases[1])
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    rebuild_session(self.session, phases=phases)
                self.assert_insufficient(self.evaluate(session=unchecked_copy(self.session, phases=phases)), 0.00)

    def test_phase_and_attribution_collection_limits(self):
        self.assert_insufficient(self.evaluate(context=self.with_limits(max_phases=1)), 0.00)
        self.assert_insufficient(self.evaluate(
            context=self.with_limits(max_attributions=1), attributions=self.attributions * 2,
        ), 0.00)
        self.assertTrue(self.evaluate(context=self.with_limits(max_phases=2, max_attributions=1)).sufficient)

    def test_every_effective_session_maximum_is_authorized(self):
        for maximum in ("max_duration_ms", "max_requests", "max_bytes", "max_redirects", "max_interactions"):
            with self.subTest(maximum=maximum):
                session = replace(self.session, **{maximum: getattr(self.context, maximum) + 1})
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_every_actual_counter_is_checked_independently(self):
        # Complete sessions cannot exceed their own budgets at construction.
        for maximum, counter in (
            ("max_duration_ms", "duration_ms"), ("max_requests", "request_count"),
            ("max_bytes", "observed_bytes"), ("max_redirects", "redirect_count"),
            ("max_interactions", "interaction_count"),
        ):
            with self.subTest(counter=counter):
                session = unchecked_copy(self.session, **{counter: getattr(self.context, maximum) + 1})
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_actual_counters_at_context_limits_are_allowed(self):
        context = replace(self.context, max_duration_ms=40, max_requests=2, max_bytes=19, max_interactions=1)
        session = replace(self.session, max_duration_ms=40, max_requests=2, max_bytes=19, max_interactions=1)
        self.assertTrue(self.evaluate(context=context, session=session).sufficient)

    def test_http_source_is_insufficient(self):
        context, session, attributions = make_fixture(scheme="http")
        result = evaluator.evaluate_browser_research(context, session, attributions)
        self.assertEqual(result.source, context.source_url)
        self.assertEqual(result.confidence, 0.00)
        self.assertFalse(result.sufficient)
        self.assertEqual(result.research_status, "insufficient_research")

    def test_v1_allowlists_must_each_be_exact_single_source_origin(self):
        other = browser_origin_from_url("https://other.example.com/")
        for name in ("allowed_navigation_origins", "allowed_endpoint_origins"):
            with self.subTest(name=name):
                context = replace(self.context, **{name: getattr(self.context, name) | {other}})
                self.assert_insufficient(self.evaluate(context=context), 0.00)

    def test_redirect_count_and_exchange_reference_fail_closed(self):
        navigation, operation = self.session.exchanges
        operation = replace(operation, redirect_from_exchange_id=navigation.exchange_id)
        session = rebuild_session(self.session, exchanges=(navigation, operation))
        self.assert_insufficient(self.evaluate(session=session), 0.00)
        # Isolate both gates; the session constructor otherwise enforces equality.
        self.assert_insufficient(self.evaluate(session=unchecked_copy(self.session, redirect_count=1)), 0.00)
        self.assert_insufficient(self.evaluate(session=unchecked_copy(session, redirect_count=0)), 0.00)

    def test_final_page_is_required_and_same_origin(self):
        for url in (None, "https://other.example.com/result", "http://example.com/result", "https://example.com:444/result"):
            with self.subTest(url=url):
                self.assert_insufficient(self.evaluate(session=replace(self.session, final_page_url=url)), 0.00)

    def test_final_page_unsupported_origin_syntax_is_insufficient(self):
        # The session URL contract is broader than BrowserOrigin's DNS subset.
        for url in ("https://127.0.0.1/result", "https://[::1]/result"):
            with self.subTest(url=url):
                self.assert_insufficient(self.evaluate(session=replace(self.session, final_page_url=url)), 0.00)

    def test_observed_interaction_must_be_authorized(self):
        self.assert_insufficient(self.evaluate(context=replace(self.context, authorized_interactions=())), 0.00)

    def test_observed_interaction_kind_and_result_must_match(self):
        for overrides in (
            {"interaction_kind": "click"}, {"interaction_kind": "other"},
            {"interaction_result": "failed"}, {"interaction_result": "unknown"},
        ):
            with self.subTest(overrides=overrides):
                self.assert_insufficient(self.evaluate(session=self.with_phase(**overrides)), 0.00)

    def test_unexecuted_authorized_interactions_are_valid(self):
        unused = BrowserAuthorizedInteraction("unused", "click", "contract-1")
        context = replace(self.context, authorized_interactions=self.context.authorized_interactions + (unused,))
        self.assertTrue(self.evaluate(context=context).sufficient)

    def test_sent_bytes_must_be_known_measured_for_every_exchange(self):
        for index in (0, 1):
            for size, kind in ((7, "estimated"), (None, "unknown")):
                with self.subTest(index=index, size=size, kind=kind):
                    exchanges = list(self.session.exchanges)
                    exchanges[index] = replace(exchanges[index], response=replace(
                        exchanges[index].response, observed_bytes=size, observed_bytes_kind=kind,
                    ))
                    self.assert_insufficient(self.evaluate(session=rebuild_session(self.session, exchanges=tuple(exchanges))), 0.00)

    def test_unknown_send_and_sent_without_response_are_global_failures(self):
        for state in ("unknown", "sent"):
            with self.subTest(state=state):
                session = self.with_operation(send_state=state, response=None, completion="pending")
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_nonmatching_not_sent_exchange_without_response_is_allowed(self):
        operation = self.session.exchanges[1]
        unsent = replace(
            operation, exchange_id="unsent", start_sequence=12,
            request=make_request("https://example.com/analytics"), send_state="not_sent",
            response=None, completion="cancelled",
        )
        session = rebuild_session(self.session, exchanges=self.session.exchanges + (unsent,))
        self.assertEqual(session.observed_bytes, self.session.observed_bytes)
        self.assertTrue(self.evaluate(session=session).sufficient)

    def test_initial_navigation_reference_required(self):
        self.assert_insufficient(self.evaluate(session=replace(self.session, initial_navigation_exchange_id=None)), 0.00)

    def test_constructor_precluded_initial_navigation_reference_defenses(self):
        for identifier in ("missing", "operation-1"):
            with self.subTest(identifier=identifier):
                with self.assertRaises(ValueError):
                    replace(self.session, initial_navigation_exchange_id=identifier)
                session = unchecked_copy(self.session, initial_navigation_exchange_id=identifier)
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_initial_navigation_sent_complete_and_response_requirements(self):
        navigation, operation = self.session.exchanges
        for overrides in (
            {"send_state": "not_sent", "response": None, "completion": "cancelled"},
            {"send_state": "sent", "response": None, "completion": "failed"},
            {"completion": "failed"}, {"completion": "pending"}, {"completion": "cancelled"},
        ):
            with self.subTest(overrides=overrides):
                session = rebuild_session(self.session, exchanges=(replace(navigation, **overrides), operation))
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_initial_navigation_request_method_and_exact_endpoint(self):
        navigation, operation = self.session.exchanges
        for overrides in (
            {"method": "POST"}, {"endpoint_url": "https://example.com/other"},
            {"endpoint_url": "https://example.com:443/page"},
        ):
            with self.subTest(overrides=overrides):
                request = replace(navigation.request, **overrides)
                session = rebuild_session(self.session, exchanges=(replace(navigation, request=request), operation))
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_initial_navigation_response_exact_url_network_and_2xx(self):
        navigation, operation = self.session.exchanges
        for overrides in (
            {"response_url": "https://example.com/other"},
            {"response_url": "https://example.com:443/page"},
            {"delivery": "cache"}, {"delivery": "service_worker"}, {"delivery": "unknown"},
            {"status_code": 199}, {"status_code": 300}, {"status_code": 500},
        ):
            with self.subTest(overrides=overrides):
                response = replace(navigation.response, **overrides)
                session = rebuild_session(self.session, exchanges=(replace(navigation, response=response), operation))
                self.assert_insufficient(self.evaluate(session=session), 0.00)

    def test_navigation_page_need_not_be_html_or_have_known_format(self):
        navigation, operation = self.session.exchanges
        response = replace(navigation.response, content_type="", response_format="unknown")
        session = rebuild_session(self.session, exchanges=(replace(navigation, response=response), operation))
        result = self.evaluate(session=session)
        self.assertTrue(result.sufficient)
        self.assertEqual(result.content_type, "")
        self.assertEqual(result.response_format, "json")
        self.assertEqual(result.page_kind, "unknown")

    def test_zero_and_multiple_attributions_are_not_unique(self):
        for attributions in ((), self.attributions * 2):
            with self.subTest(count=len(attributions)):
                self.assert_insufficient(self.evaluate(attributions=attributions), 0.40)

    def test_unusable_attribution_structural_references(self):
        for overrides in (
            {"session_id": "other-session"}, {"exchange_path": ("operation-1", "navigation-1")},
            {"operation_contract_id": "missing"}, {"exchange_path": ("missing",)},
        ):
            with self.subTest(overrides=overrides):
                attribution = replace(self.attributions[0], **overrides)
                self.assert_insufficient(self.evaluate(attributions=(attribution,)), 0.40)

    def test_every_unknown_contract_constraint_is_insufficient(self):
        for name in (
            "expected_query_parameter_names", "expected_body_parameter_names",
            "acceptable_response_formats", "acceptable_http_statuses",
        ):
            overrides = {name: None}
            if "parameter_names" in name:
                overrides[name.replace("expected_", "demonstrated_required_")] = frozenset()
            with self.subTest(name=name):
                self.assert_insufficient(self.evaluate(context=self.with_contract(**overrides)), 0.60)

    def test_contract_functional_evidence_always_insufficient(self):
        self.assert_insufficient(self.evaluate(context=self.with_contract(requires_functional_evidence=True)), 0.60)

    def test_cross_origin_contract_fails_v1_even_when_context_authorizes_it(self):
        other = browser_origin_from_url("https://api.example.com/")
        contract = replace(self.context.operation_contracts[0], authorized_origin=other)
        context = replace(
            self.context, operation_contracts=(contract,),
            allowed_endpoint_origins=self.context.allowed_endpoint_origins | {other},
        )
        self.assert_insufficient(self.evaluate(context=context), 0.00)

    def test_network_must_be_authorized_by_contract_and_context(self):
        for delivery in ("cache", "service_worker"):
            contract = replace(self.context.operation_contracts[0], acceptable_deliveries=frozenset({delivery}))
            context = replace(self.context, allowed_deliveries=frozenset({delivery}), operation_contracts=(contract,))
            with self.subTest(delivery=delivery):
                self.assert_insufficient(self.evaluate(context=context), 0.60)
        # Context forbidding a delivery its registered contract permits cannot
        # be constructed, but the evaluator still checks this independent gate.
        context = unchecked_copy(self.context, allowed_deliveries=frozenset({"cache"}))
        self.assert_insufficient(self.evaluate(context=context), 0.60)

    def test_all_supported_positive_attribution_bases(self):
        cases = (
            ("INITIAL_NAVIGATION", "submit"), ("CONTROLLED_NAVIGATION", "navigation"),
            ("CONTROLLED_SUBMISSION", "submit"), ("CONTROLLED_SUBMISSION", "input_submit"),
            ("OBSERVED_OPERATION_DISPATCH", "submit"), ("OBSERVED_OPERATION_DISPATCH", "click"),
            ("OBSERVED_OPERATION_DISPATCH", "input_submit"), ("OBSERVED_OPERATION_DISPATCH", "navigation"),
        )
        for basis, kind in cases:
            with self.subTest(basis=basis, kind=kind):
                result = evaluator.evaluate_browser_research(*make_fixture(basis=basis, kind=kind))
                self.assertTrue(result.sufficient)
                self.assertEqual(result.confidence, 0.80)
                self.assertIn(f"attribution_basis:{basis}", result.evidence)
                status, content_type = (201, "text/plain") if basis == "INITIAL_NAVIGATION" else (202, "application/json")
                self.assertEqual(result.evidence[-2:], (
                    f"operation_http_status:{status}", f"operation_content_type:{content_type}",
                ))

    def test_initial_navigation_basis_rejects_other_exchange(self):
        attribution = replace(self.attributions[0], attribution_basis="INITIAL_NAVIGATION", interaction_id=None)
        self.assert_insufficient(self.evaluate(attributions=(attribution,)), 0.60)

    def test_basis_kind_compatibility(self):
        for basis, kind in (
            ("CONTROLLED_NAVIGATION", "submit"), ("CONTROLLED_NAVIGATION", "click"),
            ("CONTROLLED_SUBMISSION", "click"), ("CONTROLLED_SUBMISSION", "navigation"),
        ):
            with self.subTest(basis=basis, kind=kind):
                context, session, attributions = make_fixture(basis=basis, kind=kind)
                self.assert_insufficient(self.evaluate(context, session, attributions), 0.60)

    def test_attributed_interaction_must_exist_and_reference_same_contract(self):
        attribution = replace(self.attributions[0], interaction_id="missing")
        self.assert_insufficient(self.evaluate(attributions=(attribution,)), 0.60)
        other_contract = replace(self.context.operation_contracts[0], contract_id="contract-2")
        interaction = replace(self.context.authorized_interactions[0], operation_contract_id="contract-2")
        context = replace(
            self.context, operation_contracts=self.context.operation_contracts + (other_contract,),
            authorized_interactions=(interaction,),
        )
        self.assert_insufficient(self.evaluate(context=context), 0.60)

    def test_attributed_interaction_requires_exactly_one_observed_phase(self):
        other = BrowserAuthorizedInteraction("unused", "submit", "contract-1")
        context = replace(self.context, authorized_interactions=self.context.authorized_interactions + (other,))
        attribution = replace(self.attributions[0], interaction_id="unused")
        self.assert_insufficient(self.evaluate(context=context, attributions=(attribution,)), 0.60)
        duplicate = replace(self.session.phases[1], phase_id="interaction-phase-2", start_sequence=20, end_sequence=29)
        session = rebuild_session(self.session, phases=self.session.phases + (duplicate,))
        self.assert_insufficient(self.evaluate(session=session), 0.60)

    def test_selected_exchange_must_belong_to_attributed_phase(self):
        session = self.with_operation(phase_id="baseline-1", start_sequence=2)
        self.assert_insufficient(self.evaluate(session=session), 0.60)

    def test_selected_exchange_must_be_sent_complete_with_response(self):
        for overrides, confidence in (
            ({"send_state": "not_sent", "response": None, "completion": "cancelled"}, 0.60),
            ({"send_state": "sent", "response": None, "completion": "pending"}, 0.00),
            ({"completion": "failed"}, 0.60), ({"completion": "cancelled"}, 0.60),
            ({"completion": "pending"}, 0.60),
        ):
            with self.subTest(overrides=overrides):
                self.assert_insufficient(self.evaluate(session=self.with_operation(**overrides)), confidence)

    def test_request_method_origin_and_path_match_exactly(self):
        for overrides in (
            {"method": "GET"}, {"endpoint_url": "https://other.example.com/api/query"},
            {"endpoint_url": "http://example.com/api/query"},
            {"endpoint_url": "https://example.com:444/api/query"},
            {"endpoint_url": "https://example.com/api/other"},
            {"endpoint_url": "https://example.com/api/Query"},
            {"endpoint_url": "https://example.com/api/query/"},
        ):
            with self.subTest(overrides=overrides):
                self.assert_insufficient(self.evaluate(session=self.with_request(**overrides)), 0.60)

    def test_dynamic_or_ambiguous_request_paths_fail_closed(self):
        for url in (
            "https://example.com/api/{query}", "https://example.com/api/:query",
            "https://example.com/api/%71uery", "https://example.com/api/../api/query",
            "https://example.com/api//query", "https://example.com/api/query;param",
            "https://example.com", "https://127.0.0.1/api/query",
        ):
            with self.subTest(url=url):
                request = make_request(url)
                self.assert_insufficient(self.evaluate(session=self.with_operation(request=request)), 0.60)

    def test_parameter_signature_requires_demonstrated_names_and_forbids_extras(self):
        for overrides in (
            {"query_parameter_names": ("shared", "optional")},
            {"query_parameter_names": ("zeta", "shared", "unexpected")},
            {"body_parameter_names": ("shared", "body_optional")},
            {"body_parameter_names": ("beta", "shared", "unexpected")},
        ):
            with self.subTest(overrides=overrides):
                self.assert_insufficient(self.evaluate(session=self.with_request(**overrides)), 0.60)

    def test_optional_parameters_may_be_absent_and_are_never_exported_as_required(self):
        session = self.with_request(query_parameter_names=("shared", "zeta"), body_parameter_names=("shared", "beta"))
        result = self.evaluate(session=session)
        self.assertTrue(result.sufficient)
        self.assertEqual(result.required_parameters, ("beta", "shared", "zeta"))
        self.assertEqual(result.endpoint_observations[0].parameters, ("shared", "zeta", "beta"))
        self.assertEqual(self.evaluate().required_parameters, result.required_parameters)

    def test_direct_request_malformed_parameter_names_are_insufficient_without_exceptions(self):
        class UntrustedTuple(tuple):
            def __iter__(self):
                raise AssertionError("tuple subclass callback executed")

        class UntrustedName(str):
            def __hash__(self):
                raise AssertionError("string subclass hash executed")

            def strip(self):
                raise AssertionError("string subclass strip executed")

        original = self.session.exchanges[1].request
        for location in ("query_parameter_names", "body_parameter_names"):
            names = getattr(original, location)
            cases = (
                ("list", list(names)),
                ("unhashable_member", ([],)),
                ("non_string_member", (7,)),
                ("empty_name", names + ("",)),
                ("leading_whitespace", (" " + names[0],) + names[1:]),
                ("trailing_whitespace", (names[0] + " ",) + names[1:]),
                ("name_too_long", names + ("x" * 65,)),
                ("too_many_names", names + tuple(f"extra_{index}" for index in range(62))),
                ("duplicate", names + (names[0],)),
                ("none", None),
                ("tuple_subclass", UntrustedTuple(names)),
                ("string_subclass", (UntrustedName(names[0]),) + names[1:]),
            )
            for label, malformed in cases:
                with self.subTest(location=location, case=label):
                    values = {field.name: getattr(original, field.name) for field in fields(original)}
                    values[location] = malformed
                    request = BrowserRequestEvidence(**values)
                    result = self.evaluate(session=self.with_operation(request=request))
                    self.assert_insufficient(result, 0.60)
                    self.assertIs(getattr(request, location), malformed)

    def test_direct_request_canonical_parameter_limits_are_inclusive(self):
        query = ("zeta", "shared", "q" * 64) + tuple(f"query_{index}" for index in range(61))
        body = ("beta", "shared", "b" * 64) + tuple(f"body_{index}" for index in range(61))
        self.assertEqual(len(query), 64)
        self.assertEqual(len(body), 64)
        context = self.with_contract(
            expected_query_parameter_names=frozenset(query), expected_body_parameter_names=frozenset(body),
        )
        original = self.session.exchanges[1].request
        values = {field.name: getattr(original, field.name) for field in fields(original)}
        values.update(query_parameter_names=query, body_parameter_names=body)
        request = BrowserRequestEvidence(**values)
        result = self.evaluate(context=context, session=self.with_operation(request=request))
        self.assertTrue(result.sufficient)
        self.assertEqual(result.required_parameters, ("beta", "shared", "zeta"))

    def test_empty_known_parameter_signatures_are_valid(self):
        context = self.with_contract(
            expected_query_parameter_names=frozenset(), expected_body_parameter_names=frozenset(),
            demonstrated_required_query_parameter_names=frozenset(), demonstrated_required_body_parameter_names=frozenset(),
        )
        session = self.with_request(query_parameter_names=(), body_parameter_names=())
        result = self.evaluate(context=context, session=session)
        self.assertTrue(result.sufficient)
        self.assertEqual(result.required_parameters, ())

    def test_same_effective_origin_port_is_valid_for_operation(self):
        url = "https://EXAMPLE.COM:443/api/query"
        operation = self.session.exchanges[1]
        request = replace(operation.request, endpoint_url=url)
        response = replace(operation.response, response_url=url)
        self.assertTrue(self.evaluate(session=self.with_operation(request=request, response=response)).sufficient)

    def test_second_matching_occurrence_anywhere_in_session_is_ambiguous(self):
        operation = self.session.exchanges[1]
        variants = (
            {}, {"phase_id": "baseline-1", "start_sequence": 2},
            {"completion": "failed"},
            {"send_state": "not_sent", "response": None, "completion": "cancelled"},
            {"request": make_request(request_url="https://example.com/api/query?shared=OTHER&zeta=DIFFERENT")},
            {"request": replace(operation.request, endpoint_url="https://EXAMPLE.COM:443/api/query")},
            # Unsanitized direct construction must not hide a second occurrence
            # from structural matching, even though it cannot itself be exported.
            {"request": replace(operation.request, endpoint_url="https://example.com/api/query?token=RAW_SECRET")},
        )
        for overrides in variants:
            values = dict(exchange_id="retry-1", start_sequence=12)
            values.update(overrides)
            duplicate = replace(operation, **values)
            with self.subTest(overrides=overrides):
                session = rebuild_session(self.session, exchanges=self.session.exchanges + (duplicate,))
                self.assert_insufficient(self.evaluate(session=session), 0.60)

    def test_nonmatching_analytics_traffic_does_not_invalidate_operation(self):
        for url in ("https://example.com/analytics", "https://metrics.example.com/analytics"):
            analytics = replace(
                self.session.exchanges[1], exchange_id="analytics", start_sequence=12,
                request=make_request(
                    url, page_url="https://unrelated.example.com/other",
                    source_asset="https://assets.example.com/script.js",
                ), response=make_response(url),
            )
            with self.subTest(url=url):
                session = rebuild_session(self.session, exchanges=self.session.exchanges + (analytics,))
                self.assertTrue(self.evaluate(session=session).sufficient)

    def test_nonmatching_request_at_same_url_is_not_collapsed_into_candidate(self):
        operation = self.session.exchanges[1]
        for request in (
            replace(operation.request, method="GET"),
            replace(operation.request, query_parameter_names=("shared",)),
            replace(operation.request, body_parameter_names=("beta", "shared", "unexpected")),
        ):
            other = replace(operation, exchange_id="other", start_sequence=12, request=request)
            with self.subTest(request=request):
                session = rebuild_session(self.session, exchanges=self.session.exchanges + (other,))
                self.assertTrue(self.evaluate(session=session).sufficient)

    def test_exchange_tuple_order_has_no_attribution_meaning(self):
        session = rebuild_session(self.session, exchanges=tuple(reversed(self.session.exchanges)))
        self.assertEqual(self.evaluate(session=session), self.evaluate())

    def test_operation_response_url_must_match_request_exactly(self):
        for url in ("https://example.com/other", "https://example.com:443/api/query", "https://EXAMPLE.COM/api/query"):
            with self.subTest(url=url):
                self.assert_insufficient(self.evaluate(session=self.with_response(response_url=url)), 0.60)

    def test_operation_delivery_must_be_network_even_if_other_deliveries_allowed(self):
        deliveries = frozenset({"network", "cache", "service_worker"})
        contract = replace(self.context.operation_contracts[0], acceptable_deliveries=deliveries)
        context = replace(self.context, allowed_deliveries=deliveries, operation_contracts=(contract,))
        for delivery in ("cache", "service_worker", "unknown"):
            with self.subTest(delivery=delivery):
                self.assert_insufficient(self.evaluate(context=context, session=self.with_response(delivery=delivery)), 0.60)

    def test_http_status_requires_contract_membership_and_v1_2xx(self):
        self.assert_insufficient(self.evaluate(session=self.with_response(status_code=200)), 0.60)
        for status in (199, 300, 400, 500):
            with self.subTest(status=status):
                context = self.with_contract(acceptable_http_statuses=frozenset({status}))
                self.assert_insufficient(self.evaluate(context=context, session=self.with_response(status_code=status)), 0.60)
        for status in (200, 299):
            with self.subTest(boundary=status):
                context = self.with_contract(acceptable_http_statuses=frozenset({status}))
                self.assertTrue(self.evaluate(context=context, session=self.with_response(status_code=status)).sufficient)

    def test_unknown_format_unacceptable_format_and_empty_mime(self):
        for overrides in (
            {"content_type": "application/x-custom", "response_format": "unknown"},
            {"content_type": "text/plain", "response_format": "text"},
            {"content_type": "", "response_format": "unknown"},
        ):
            with self.subTest(overrides=overrides):
                self.assert_insufficient(self.evaluate(session=self.with_response(**overrides)), 0.60)

    def test_response_content_requirement_is_positive_measured_size(self):
        self.assert_insufficient(self.evaluate(session=self.with_response(observed_bytes=0)), 0.60)
        self.assertTrue(self.evaluate(session=self.with_response(observed_bytes=1)).sufficient)
        context = self.with_contract(requires_response_content=False)
        self.assertTrue(self.evaluate(context=context, session=self.with_response(observed_bytes=0)).sufficient)

    def test_capability_requirements_preserve_operation_metadata_without_functional_claims(self):
        for requirement in ("ACCESS_PROCEDURE", "HTTP_STATUS", "RESPONSE_METADATA", "FUNCTIONAL_RESULT"):
            context = replace(self.context, capability_requirement=requirement)
            with self.subTest(requirement=requirement):
                result = self.evaluate(context=context)
                if requirement == "FUNCTIONAL_RESULT":
                    self.assert_insufficient(result, 0.60)
                else:
                    self.assertTrue(result.sufficient)
                    self.assertEqual(result.confidence, 0.80)
                    self.assertEqual(result.http_status, 201)
                    self.assertEqual(result.content_type, "text/plain")
                    self.assertEqual(result.final_url, self.session.final_page_url)
                    self.assertIn("operation_http_status:202", result.evidence)
                    self.assertIn("operation_content_type:application/json", result.evidence)
                    self.assertEqual(result.response_format, "json")
                    self.assertIn("top_level_http_metadata_describes_initial_navigation", result.notes)

    def test_no_query_fragment_or_body_values_in_result_exports(self):
        # No response body or body values can be supplied to these evidence
        # records. Only body parameter names exist; fixtures use the raw URL
        # constructors to exercise sanitization of every exported URL source.
        result = self.evaluate()
        for secret in (
            "QUERY_SECRET", "SHARED_SECRET", "OPTIONAL_SECRET", "PAGE_SECRET", "PAGE_FRAGMENT_SECRET",
            "ASSET_SECRET", "ASSET_FRAGMENT_SECRET", "RESPONSE_SECRET", "RESPONSE_FRAGMENT_SECRET",
            "SOURCE_SECRET", "SOURCE_FRAGMENT_SECRET", "FINAL_SECRET", "FINAL_FRAGMENT_SECRET", "NAVIGATION_SECRET",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, repr(result))
                self.assertNotIn(secret, result.to_prompt_context())
        self.assertNotIn("body", {field.name for field in fields(self.session.exchanges[1].response)})
        self.assertNotIn("body_values", {field.name for field in fields(self.session.exchanges[1].request)})

    def test_direct_unsanitized_request_urls_are_not_exported(self):
        for name, url in (
            ("endpoint_url", "https://example.com/api/query?token=RAW_SECRET"),
            ("endpoint_url", "https://example.com/api/query#RAW_SECRET"),
            ("endpoint_url", "https://user:RAW_SECRET@example.com/api/query"),
            ("page_url", "https://example.com/page?token=RAW_SECRET"),
            ("source_asset", "https://example.com/app.js?token=RAW_SECRET"),
        ):
            with self.subTest(name=name, url=url):
                result = self.evaluate(session=self.with_request(**{name: url}))
                self.assert_insufficient(result, 0.60)
                self.assertNotIn("RAW_SECRET", repr(result))
                self.assertNotIn("RAW_SECRET", result.to_prompt_context())

    def test_selected_request_page_and_asset_must_have_source_origin(self):
        for location in ("page_url", "source_asset"):
            for url in (
                "https://other.example.com/other", "http://example.com/other",
                "https://example.com:444/other", "https://127.0.0.1/other",
            ):
                with self.subTest(location=location, url=url):
                    self.assert_insufficient(self.evaluate(session=self.with_request(**{location: url})), 0.60)

    def test_selected_request_same_origin_other_paths_and_no_asset_are_allowed(self):
        for overrides in (
            {"page_url": "https://example.com/other/page", "source_asset": "https://example.com/other/app.js"},
            {"page_url": "https://EXAMPLE.COM:443/other/page", "source_asset": "https://EXAMPLE.COM:443/other/app.js"},
            {"source_asset": None},
        ):
            with self.subTest(overrides=overrides):
                session = self.with_request(**overrides)
                result = self.evaluate(session=session)
                self.assertTrue(result.sufficient)
                self.assertEqual(result.endpoint_observations, (
                    browser_request_evidence_to_endpoint_observation(session.exchanges[1].request),
                ))

    def test_exactly_one_observation_comes_from_existing_adapter(self):
        with patch.object(evaluator, "browser_request_evidence_to_endpoint_observation", wraps=browser_request_evidence_to_endpoint_observation) as adapter:
            result = self.evaluate()
        adapter.assert_called_once_with(self.session.exchanges[1].request)
        self.assertEqual(len(result.endpoint_observations), 1)
        self.assertEqual(result.observed_assets, ())

    def test_endpoint_observation_limit_constructor_boundary_and_defensive_gate(self):
        # A positive integer limit always accommodates V1's one observation.
        with self.assertRaises(ValueError):
            replace(self.context.evidence_limits, max_exported_endpoint_observations=0)
        limits = unchecked_copy(self.context.evidence_limits, max_exported_endpoint_observations=0)
        self.assert_insufficient(self.evaluate(context=unchecked_copy(self.context, evidence_limits=limits)), 0.60)
        self.assertTrue(self.evaluate(context=self.with_limits(max_exported_endpoint_observations=1)).sufficient)

    def test_exported_item_limit_exact_formula_and_no_truncation(self):
        result = self.evaluate()
        count = sum(len(getattr(result, name)) for name in (
            "observed_endpoints", "endpoint_observations", "required_parameters", "notes", "evidence", "observed_assets",
        ))
        self.assertEqual(count, 14)
        self.assertEqual(self.evaluate(context=self.with_limits(max_exported_evidence_items=count)), result)
        self.assert_insufficient(self.evaluate(context=self.with_limits(max_exported_evidence_items=count - 1)), 0.60)
        self.assert_insufficient(self.evaluate(context=self.with_limits(max_exported_evidence_items=11)), 0.60)
        self.assert_insufficient(self.evaluate(context=self.with_limits(max_exported_evidence_items=1)), 0.60)

    def test_export_utf8_limit_exact_serialized_bytes_and_no_truncation(self):
        # Local non-secret IDs can contain Unicode: count bytes, not characters.
        identifier = "sesión-猫"
        context = replace(self.context, expected_session_id=identifier)
        session = replace(self.session, session_id=identifier)
        attributions = (replace(self.attributions[0], session_id=identifier),)
        result = self.evaluate(context, session, attributions)
        size = len(result.to_prompt_context().encode("utf-8"))
        self.assertGreater(size, len(result.to_prompt_context()))
        exact_context = replace(context, evidence_limits=replace(context.evidence_limits, max_exported_utf8_bytes=size))
        self.assertEqual(self.evaluate(exact_context, session, attributions), result)
        for limit in (size - 1, len(result.to_prompt_context()), 1):
            limited = replace(context, evidence_limits=replace(context.evidence_limits, max_exported_utf8_bytes=limit))
            with self.subTest(limit=limit):
                self.assert_insufficient(self.evaluate(limited, session, attributions), 0.60)

    def test_final_sufficient_property_is_checked(self):
        with patch.object(ExternalSourceResearchResult, "sufficient", new_callable=PropertyMock, return_value=False):
            result = self.evaluate()
        self.assert_insufficient(result, 0.60)

    def test_final_validator_is_called_and_expected_failures_close(self):
        with patch.object(evaluator, "validate_research_result", wraps=validate_research_result) as validator:
            result = self.evaluate()
        validator.assert_called_once_with(result)
        for error in (ValueError("RAW_SECRET"), TypeError("RAW_SECRET")):
            with self.subTest(error=type(error).__name__):
                with patch.object(evaluator, "validate_research_result", side_effect=error):
                    result = self.evaluate()
                self.assert_insufficient(result, 0.60)
                self.assertNotIn("RAW_SECRET", result.to_prompt_context())

    def test_unexpected_programming_errors_are_not_swallowed(self):
        for target in ("validate_research_result", "browser_request_evidence_to_endpoint_observation"):
            with self.subTest(target=target):
                with patch.object(evaluator, target, side_effect=RuntimeError("programming bug")):
                    with self.assertRaisesRegex(RuntimeError, "programming bug"):
                        self.evaluate()

    def test_evaluation_has_no_network_dns_filesystem_or_process_effects(self):
        targets = (
            "urllib.request.urlopen", "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
            "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex", "socket.create_connection",
            "socket.socket", "builtins.open", "pathlib.Path.open", "os.open", "os.stat", "os.listdir",
            "subprocess.Popen",
        )
        insufficient_context = replace(self.context, capability_requirement="FUNCTIONAL_RESULT")
        with ExitStack() as stack:
            blocked = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            self.assertTrue(self.evaluate().sufficient)
            self.assert_insufficient(self.evaluate(context=insufficient_context), 0.60)
            self.assert_insufficient(self.evaluate(attributions=()), 0.40)
            self.assert_insufficient(self.evaluate(session=replace(self.session, session_id="other")), 0.00)
            for mocked in blocked:
                mocked.assert_not_called()

    def test_callbacks_are_rejected_without_invocation(self):
        callback = Mock(side_effect=AssertionError("callback executed"))
        for arguments in (
            (callback, self.session, self.attributions), (self.context, callback, self.attributions),
            (self.context, self.session, callback), (self.context, self.session, (callback,)),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                evaluator.evaluate_browser_research(*arguments)
        callback.assert_not_called()

    def test_inputs_are_not_mutated_and_output_is_deterministic(self):
        original = (self.context, self.session, self.attributions)
        snapshot = copy.deepcopy(original)
        first = self.evaluate()
        for _ in range(3):
            result = self.evaluate()
            self.assertEqual(result, first)
            self.assertEqual(result.to_prompt_context(), first.to_prompt_context())
            self.assertEqual(original, snapshot)
        failed_context = replace(self.context, capability_requirement="FUNCTIONAL_RESULT")
        failed_snapshot = copy.deepcopy((failed_context, self.session, self.attributions))
        failure = self.evaluate(context=failed_context)
        self.assertEqual(self.evaluate(context=failed_context), failure)
        self.assertEqual((failed_context, self.session, self.attributions), failed_snapshot)


if __name__ == "__main__":
    unittest.main()
