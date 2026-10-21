import unittest
from dataclasses import FrozenInstanceError, fields, replace

from jarvis.core.browser_exchange_evidence import (
    BrowserNetworkExchangeEvidence,
    BrowserResponseEvidence,
)
from jarvis.core.browser_network_evidence import build_browser_request_evidence
from jarvis.core.browser_session_evidence import (
    BrowserResearchPhaseEvidence,
    BrowserResearchSessionEvidence,
)


COUNTER_FIELDS = (
    "duration_ms", "request_count", "observed_bytes", "redirect_count", "interaction_count",
)
LIMIT_FIELDS = (
    "max_duration_ms", "max_requests", "max_bytes", "max_redirects", "max_interactions",
)


def make_phase(**overrides):
    values = {
        "phase_id": "baseline-1",
        "kind": "baseline",
        "start_sequence": 0,
        "end_sequence": 9,
        "collection_status": "complete",
        "interaction_id": None,
        "interaction_kind": None,
        "interaction_result": None,
    }
    if overrides.get("kind") == "interaction":
        values.update(
            phase_id="interaction-phase-1", start_sequence=10, end_sequence=19,
            interaction_id="interaction-1", interaction_kind="submit",
            interaction_result="completed",
        )
    values.update(overrides)
    return BrowserResearchPhaseEvidence(**values)


def make_response(**overrides):
    values = {
        "status_code": 200,
        "content_type": "application/json",
        "response_format": "json",
        "response_url": "https://api.example.com/query?token=RESPONSE_SECRET#x",
        "delivery": "network",
        "observed_bytes": 7,
        "observed_bytes_kind": "measured",
    }
    values.update(overrides)
    return BrowserResponseEvidence(**values)


def make_exchange(**overrides):
    values = {
        "exchange_id": "exchange-1",
        "request": build_browser_request_evidence(
            page_url="https://example.com/page?token=PAGE_SECRET#x",
            request_url="https://api.example.com/query?token=REQUEST_SECRET#x",
            method="GET", consulted=True,
        ),
        "send_state": "sent",
        "response": make_response(),
        "completion": "complete",
        "phase_id": "baseline-1",
        "start_sequence": 1,
        "redirect_from_exchange_id": None,
    }
    values.update(overrides)
    return BrowserNetworkExchangeEvidence(**values)


def make_session(phases=None, exchanges=None, **overrides):
    phases = (make_phase(),) if phases is None else phases
    exchanges = (make_exchange(),) if exchanges is None else exchanges
    values = {
        "session_id": "session-1",
        "initial_page_url": "https://example.com/page",
        "final_page_url": "https://example.com/result",
        "initial_navigation_exchange_id": "exchange-1",
        "collection_status": "complete",
        "duration_ms": 20,
        "request_count": len(exchanges),
        "observed_bytes": sum(
            exchange.response.observed_bytes for exchange in exchanges
            if exchange.response is not None and exchange.response.observed_bytes is not None
        ),
        "redirect_count": sum(exchange.redirect_from_exchange_id is not None for exchange in exchanges),
        "interaction_count": sum(phase.kind == "interaction" for phase in phases),
        "max_duration_ms": 100,
        "max_requests": 10,
        "max_bytes": 100,
        "max_redirects": 10,
        "max_interactions": 10,
        "lost_events": False,
        "phases": phases,
        "exchanges": exchanges,
    }
    values.update(overrides)
    return BrowserResearchSessionEvidence(**values)


def redirected_exchanges():
    return (
        make_exchange(response=make_response(status_code=302)),
        make_exchange(exchange_id="exchange-2", start_sequence=2, redirect_from_exchange_id="exchange-1"),
    )


class BrowserResearchPhaseEvidenceTests(unittest.TestCase):
    def test_valid_baseline(self):
        phase = make_phase()
        self.assertEqual(phase.kind, "baseline")
        self.assertIsNone(phase.interaction_id)
        self.assertIsNone(phase.interaction_kind)
        self.assertIsNone(phase.interaction_result)

    def test_valid_interaction_and_all_structural_kinds(self):
        for kind in ("submit", "click", "input_submit", "navigation", "other"):
            with self.subTest(kind=kind):
                phase = make_phase(kind="interaction", interaction_kind=kind)
                self.assertEqual(phase.interaction_kind, kind)
                self.assertEqual(phase.interaction_result, "completed")

    def test_baseline_rejects_each_interaction_field(self):
        for field_name, value in (
            ("interaction_id", "interaction-1"),
            ("interaction_kind", "submit"),
            ("interaction_result", "completed"),
        ):
            with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                make_phase(**{field_name: value})

    def test_interaction_requires_non_empty_bounded_id(self):
        for identifier in (None, "", "   ", 123, "a" * 129):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_phase(kind="interaction", interaction_id=identifier)

    def test_interaction_kind_is_a_closed_enum(self):
        for kind in (None, "script", "selector", "SUBMIT", [], ""):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_phase(kind="interaction", interaction_kind=kind)

    def test_interaction_result_is_a_closed_enum(self):
        for result in ("completed", "failed", "unknown"):
            with self.subTest(result=result):
                self.assertEqual(make_phase(kind="interaction", interaction_result=result).interaction_result, result)
        for result in (None, "success", [], ""):
            with self.subTest(result=result), self.assertRaises(ValueError):
                make_phase(kind="interaction", interaction_result=result)

    def test_end_sequence_before_start_is_rejected(self):
        with self.assertRaises(ValueError):
            make_phase(start_sequence=5, end_sequence=4)

    def test_sequences_require_non_negative_real_integers(self):
        for field_name in ("start_sequence", "end_sequence"):
            for value in (True, False, -1, 1.0, "1", None):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_phase(**{field_name: value})

    def test_empty_long_or_non_string_phase_ids_are_rejected(self):
        for identifier in ("", "   ", "a" * 129, None, 123):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_phase(phase_id=identifier)

    def test_ids_are_normalized_and_maximum_length_is_allowed(self):
        phase = make_phase(kind="interaction", phase_id=" p ", interaction_id=" i ")
        self.assertEqual(phase.phase_id, "p")
        self.assertEqual(phase.interaction_id, "i")
        self.assertEqual(make_phase(phase_id="a" * 128).phase_id, "a" * 128)
        self.assertEqual(make_phase(kind="interaction", interaction_id="a" * 128).interaction_id, "a" * 128)

    def test_kind_and_collection_status_are_closed_enums(self):
        for field_name in ("kind", "collection_status"):
            for value in ("invalid", None, []):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_phase(**{field_name: value})
        for status in ("complete", "failed", "cancelled"):
            with self.subTest(status=status):
                self.assertEqual(make_phase(collection_status=status).collection_status, status)

    def test_single_sequence_phase_is_valid(self):
        self.assertEqual(make_phase(start_sequence=0, end_sequence=0).end_sequence, 0)

    def test_phase_is_frozen_and_has_slots(self):
        phase = make_phase()
        with self.assertRaises(FrozenInstanceError):
            phase.kind = "interaction"
        self.assertFalse(hasattr(phase, "__dict__"))

    def test_phase_has_only_the_requested_structural_fields(self):
        self.assertEqual(
            {field.name for field in fields(BrowserResearchPhaseEvidence)},
            {"phase_id", "kind", "start_sequence", "end_sequence", "collection_status",
             "interaction_id", "interaction_kind", "interaction_result"},
        )


class BrowserResearchSessionEvidenceTests(unittest.TestCase):
    def test_valid_complete_session(self):
        session = make_session()
        self.assertEqual(session.collection_status, "complete")
        self.assertEqual(session.request_count, 1)
        self.assertEqual(session.observed_bytes, 7)
        self.assertFalse(session.lost_events)

    def test_initial_page_url_is_sanitized(self):
        session = make_session(initial_page_url="https://example.com:8443/page?token=SUPER_SECRET#x")
        self.assertEqual(session.initial_page_url, "https://example.com:8443/page")

    def test_final_page_url_is_sanitized(self):
        session = make_session(final_page_url="https://example.com:8443/result?token=SUPER_SECRET#x")
        self.assertEqual(session.final_page_url, "https://example.com:8443/result")

    def test_both_page_urls_reject_credentials(self):
        for field_name in ("initial_page_url", "final_page_url"):
            for url in ("https://user:pass@example.com/", "https://user@example.com/", "https://@example.com/"):
                with self.subTest(field_name=field_name, url=url), self.assertRaises(ValueError):
                    make_session(**{field_name: url})

    def test_both_page_urls_reject_relative_or_malformed_urls(self):
        for field_name in ("initial_page_url", "final_page_url"):
            for url in ("/page", "//example.com/page", "file:///page", "https:///page", "https://example.com:99999/", "https://example.com/\npage", 123):
                with self.subTest(field_name=field_name, url=url), self.assertRaises(ValueError):
                    make_session(**{field_name: url})
        with self.assertRaises(ValueError):
            make_session(initial_page_url=None)

    def test_optional_final_url_and_navigation_reference(self):
        session = make_session(final_page_url=None, initial_navigation_exchange_id=None)
        self.assertIsNone(session.final_page_url)
        self.assertIsNone(session.initial_navigation_exchange_id)

    def test_query_secrets_are_absent_from_entire_repr(self):
        session = make_session(
            initial_page_url="https://example.com/page?token=SUPER_SECRET#x",
            final_page_url="https://example.com/result?key=FINAL_SECRET#x",
        )
        for secret in ("SUPER_SECRET", "FINAL_SECRET", "PAGE_SECRET", "REQUEST_SECRET", "RESPONSE_SECRET"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, repr(session))

    def test_paths_are_preserved_without_secret_heuristics(self):
        session = make_session(initial_page_url="https://example.com/private/token/path?x=1")
        self.assertEqual(session.initial_page_url, "https://example.com/private/token/path")

    def test_invalid_collection_status_is_rejected(self):
        for status in ("failed", "success", None, []):
            with self.subTest(status=status), self.assertRaises(ValueError):
                make_session(collection_status=status)

    def test_complete_rejects_lost_events(self):
        with self.assertRaisesRegex(ValueError, "lost_events"):
            make_session(lost_events=True)

    def test_lost_events_requires_exact_bool(self):
        for value in (None, 0, 1, "false", []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_session(lost_events=value)

    def test_incomplete_session_can_report_lost_events(self):
        session = make_session(collection_status="collection_error", lost_events=True)
        self.assertTrue(session.lost_events)

    def test_session_id_is_normalized_and_bounded(self):
        self.assertEqual(make_session(session_id=" session-1 ").session_id, "session-1")
        self.assertEqual(make_session(session_id="a" * 128).session_id, "a" * 128)
        for identifier in ("", "   ", "a" * 129, None, 123):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_session(session_id=identifier)

    def test_duplicate_phase_ids_are_rejected(self):
        phases = (make_phase(), make_phase(phase_id=" baseline-1 ", start_sequence=20, end_sequence=29))
        with self.assertRaisesRegex(ValueError, "phase_id values must be unique"):
            make_session(phases=phases)

    def test_duplicate_exchange_ids_are_rejected(self):
        exchanges = (make_exchange(), make_exchange(start_sequence=2))
        with self.assertRaisesRegex(ValueError, "exchange_id values must be unique"):
            make_session(exchanges=exchanges)

    def test_duplicate_exchange_start_sequences_are_rejected(self):
        exchanges = (make_exchange(), make_exchange(exchange_id="exchange-2"))
        with self.assertRaisesRegex(ValueError, "start_sequence values must be unique"):
            make_session(exchanges=exchanges)

    def test_unknown_exchange_phase_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "existing phase"):
            make_session(exchanges=(make_exchange(phase_id="unknown-phase"),))

    def test_exchange_outside_phase_interval_is_rejected(self):
        for sequence in (1, 10):
            with self.subTest(sequence=sequence), self.assertRaisesRegex(ValueError, "phase interval"):
                make_session(phases=(make_phase(start_sequence=2),), exchanges=(make_exchange(start_sequence=sequence),))

    def test_phase_interval_boundaries_are_inclusive(self):
        exchanges = (make_exchange(start_sequence=0), make_exchange(exchange_id="exchange-2", start_sequence=9))
        self.assertEqual(make_session(exchanges=exchanges).request_count, 2)

    def test_overlapping_phases_including_shared_boundary_are_rejected(self):
        for start in (3, 9):
            phases = (make_phase(), make_phase(phase_id="baseline-2", start_sequence=start, end_sequence=19))
            with self.subTest(start=start), self.assertRaisesRegex(ValueError, "overlap"):
                make_session(phases=phases)

    def test_out_of_order_phases_are_rejected(self):
        phases = (make_phase(start_sequence=10, end_sequence=19), make_phase(phase_id="baseline-2"))
        with self.assertRaisesRegex(ValueError, "ordered"):
            make_session(phases=phases, exchanges=(make_exchange(start_sequence=11),))

    def test_gaps_between_phases_are_allowed(self):
        phases = (make_phase(), make_phase(phase_id="baseline-2", start_sequence=20, end_sequence=29))
        self.assertEqual(len(make_session(phases=phases).phases), 2)

    def test_redirect_to_unknown_exchange_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "existing exchange"):
            make_session(exchanges=(make_exchange(redirect_from_exchange_id="unknown-exchange"),))

    def test_redirect_to_later_exchange_is_rejected(self):
        exchanges = (
            make_exchange(redirect_from_exchange_id="exchange-2"),
            make_exchange(exchange_id="exchange-2", start_sequence=2),
        )
        with self.assertRaisesRegex(ValueError, "strictly earlier"):
            make_session(exchanges=exchanges)

    def test_redirect_to_earlier_exchange_uses_sequence_not_tuple_order(self):
        session = make_session(exchanges=tuple(reversed(redirected_exchanges())))
        self.assertEqual(session.redirect_count, 1)
        self.assertEqual(session.exchanges[0].redirect_from_exchange_id, "exchange-1")

    def test_redirect_cycle_is_rejected(self):
        first, second = redirected_exchanges()
        with self.assertRaisesRegex(ValueError, "strictly earlier"):
            make_session(exchanges=(replace(first, redirect_from_exchange_id="exchange-2"), second))

    def test_unknown_initial_navigation_exchange_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "initial_navigation_exchange_id"):
            make_session(initial_navigation_exchange_id="unknown-exchange")

    def test_initial_navigation_cannot_belong_to_interaction(self):
        phases = (make_phase(), make_phase(kind="interaction"))
        exchanges = (make_exchange(), make_exchange(exchange_id="interaction-exchange", phase_id="interaction-phase-1", start_sequence=11))
        with self.assertRaisesRegex(ValueError, "baseline phase"):
            make_session(phases=phases, exchanges=exchanges, initial_navigation_exchange_id="interaction-exchange")

    def test_navigation_reference_is_normalized_and_validated(self):
        self.assertEqual(make_session(initial_navigation_exchange_id=" exchange-1 ").initial_navigation_exchange_id, "exchange-1")
        for identifier in ("", "   ", "a" * 129, 123, []):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_session(initial_navigation_exchange_id=identifier)

    def test_phase_without_exchanges_is_allowed(self):
        session = make_session(exchanges=(), initial_navigation_exchange_id=None)
        self.assertEqual(len(session.phases), 1)
        self.assertEqual(session.request_count, 0)

    def test_empty_session_has_zero_counters_without_sufficiency(self):
        session = make_session(phases=(), exchanges=(), initial_navigation_exchange_id=None, duration_ms=0)
        self.assertEqual(session.request_count, 0)
        self.assertEqual(session.observed_bytes, 0)
        self.assertFalse(hasattr(session, "sufficient"))

    def test_incorrect_request_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "request_count"):
            make_session(request_count=2)

    def test_incorrect_interaction_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "interaction_count"):
            make_session(interaction_count=1)

    def test_incorrect_redirect_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "redirect_count"):
            make_session(redirect_count=1)

    def test_incorrect_observed_bytes_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "observed_bytes"):
            make_session(observed_bytes=8)

    def test_unknown_response_sizes_do_not_invent_bytes(self):
        response = make_response(observed_bytes=None, observed_bytes_kind="unknown")
        session = make_session(exchanges=(make_exchange(response=response),))
        self.assertEqual(session.observed_bytes, 0)

    def test_known_measured_and_estimated_bytes_are_summed(self):
        exchanges = (
            make_exchange(response=make_response(observed_bytes=3)),
            make_exchange(exchange_id="exchange-2", start_sequence=2, response=make_response(observed_bytes=6, observed_bytes_kind="estimated")),
            make_exchange(exchange_id="exchange-3", start_sequence=3, response=make_response(observed_bytes=None, observed_bytes_kind="unknown")),
            make_exchange(exchange_id="exchange-4", start_sequence=4, response=None, completion="pending"),
        )
        session = make_session(exchanges=exchanges)
        self.assertEqual(session.observed_bytes, 9)

    def test_request_limit_is_coherent_at_or_above_maximum(self):
        exchanges = (make_exchange(), make_exchange(exchange_id="exchange-2", start_sequence=2))
        for maximum in (1, 2):
            with self.subTest(maximum=maximum):
                self.assertEqual(make_session(exchanges=exchanges, collection_status="request_limit", max_requests=maximum).request_count, 2)

    def test_incoherent_request_limit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "request_limit"):
            make_session(collection_status="request_limit", max_requests=2)

    def test_byte_limit_is_coherent(self):
        self.assertEqual(make_session(collection_status="byte_limit", max_bytes=7).observed_bytes, 7)

    def test_incoherent_byte_limit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "byte_limit"):
            make_session(collection_status="byte_limit", max_bytes=8)

    def test_redirect_limit_is_coherent(self):
        session = make_session(exchanges=redirected_exchanges(), collection_status="redirect_limit", max_redirects=1)
        self.assertEqual(session.redirect_count, 1)

    def test_incoherent_redirect_limit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "redirect_limit"):
            make_session(collection_status="redirect_limit", max_redirects=1)

    def test_interaction_limit_is_coherent(self):
        phases = (make_phase(), make_phase(kind="interaction"))
        session = make_session(phases=phases, collection_status="interaction_limit", max_interactions=1)
        self.assertEqual(session.interaction_count, 1)

    def test_incoherent_interaction_limit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "interaction_limit"):
            make_session(collection_status="interaction_limit", max_interactions=1)

    def test_timeout_is_coherent(self):
        self.assertEqual(make_session(collection_status="timeout", max_duration_ms=20).duration_ms, 20)

    def test_incoherent_timeout_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "timeout"):
            make_session(collection_status="timeout", max_duration_ms=21)

    def test_reaching_limits_does_not_infer_termination(self):
        exchanges = (make_exchange(), make_exchange(exchange_id="exchange-2", start_sequence=2))
        session = make_session(exchanges=exchanges, max_duration_ms=20, max_requests=2, max_bytes=14)
        self.assertEqual(session.collection_status, "complete")
        self.assertEqual(session.request_count, session.max_requests)
        self.assertEqual(session.observed_bytes, session.max_bytes)

    def test_complete_can_reach_every_effective_limit_exactly(self):
        phases = (make_phase(), make_phase(kind="interaction"))
        exchanges = redirected_exchanges() + (
            make_exchange(exchange_id="exchange-3", phase_id="interaction-phase-1", start_sequence=11),
        )
        session = make_session(
            phases=phases, exchanges=exchanges, max_duration_ms=20,
            max_requests=3, max_bytes=21, max_redirects=1, max_interactions=1,
        )
        self.assertEqual(session.collection_status, "complete")
        for counter_name, maximum_name in zip(COUNTER_FIELDS, LIMIT_FIELDS):
            with self.subTest(counter_name=counter_name):
                self.assertEqual(getattr(session, counter_name), getattr(session, maximum_name))

    def test_complete_rejects_duration_above_effective_limit(self):
        with self.assertRaisesRegex(ValueError, "duration_ms <= max_duration_ms"):
            make_session(max_duration_ms=19)

    def test_complete_rejects_requests_above_effective_limit(self):
        exchanges = (make_exchange(), make_exchange(exchange_id="exchange-2", start_sequence=2))
        with self.assertRaisesRegex(ValueError, "request_count <= max_requests"):
            make_session(exchanges=exchanges, max_requests=1)

    def test_complete_rejects_bytes_above_effective_limit(self):
        with self.assertRaisesRegex(ValueError, "observed_bytes <= max_bytes"):
            make_session(max_bytes=6)

    def test_complete_rejects_redirects_above_effective_limit(self):
        exchanges = redirected_exchanges() + (
            make_exchange(exchange_id="exchange-3", start_sequence=3, redirect_from_exchange_id="exchange-2"),
        )
        with self.assertRaisesRegex(ValueError, "redirect_count <= max_redirects"):
            make_session(exchanges=exchanges, max_redirects=1)

    def test_complete_rejects_interactions_above_effective_limit(self):
        phases = (
            make_phase(), make_phase(kind="interaction"),
            make_phase(
                kind="interaction", phase_id="interaction-phase-2", interaction_id="interaction-2",
                start_sequence=20, end_sequence=29,
            ),
        )
        with self.assertRaisesRegex(ValueError, "interaction_count <= max_interactions"):
            make_session(phases=phases, max_interactions=1)

    def test_complete_requires_all_phases_complete(self):
        for status in ("failed", "cancelled"):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "every phase"):
                make_session(phases=(make_phase(collection_status=status),))

    def test_incomplete_session_retains_partial_evidence(self):
        for status in ("navigation_error", "interaction_error", "collection_error"):
            for phase_status in ("failed", "cancelled"):
                exchange = make_exchange(response=None, completion="failed")
                session = make_session(
                    phases=(make_phase(collection_status=phase_status),), exchanges=(exchange,),
                    collection_status=status, lost_events=True,
                )
                with self.subTest(status=status, phase_status=phase_status):
                    self.assertIs(session.exchanges[0], exchange)
                    self.assertEqual(session.observed_bytes, 0)

    def test_bool_and_non_integer_numeric_fields_are_rejected(self):
        for field_name in COUNTER_FIELDS + LIMIT_FIELDS:
            for value in (True, False, 1.0, "1", None):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_session(**{field_name: value})

    def test_counters_cannot_be_negative(self):
        for field_name in COUNTER_FIELDS:
            with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                make_session(**{field_name: -1})

    def test_maximums_must_be_positive(self):
        for field_name in LIMIT_FIELDS:
            session = make_session(
                exchanges=(), initial_navigation_exchange_id=None, duration_ms=0,
                **{field_name: 1},
            )
            self.assertEqual(getattr(session, field_name), 1)
            for value in (0, -1):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_session(**{field_name: value})

    def test_numeric_structural_bound_is_not_an_operational_policy(self):
        bound = (1 << 63) - 1
        for field_name in COUNTER_FIELDS + LIMIT_FIELDS:
            with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                make_session(**{field_name: bound + 1})
        session = make_session(duration_ms=bound, **{field_name: bound for field_name in LIMIT_FIELDS})
        self.assertEqual(session.duration_ms, bound)
        self.assertEqual(session.max_requests, bound)

    def test_collections_require_tuples_of_the_exact_record_types(self):
        session = make_session()
        for field_name, values in (
            ("phases", [make_phase()]), ("phases", (object(),)), ("phases", None),
            ("exchanges", [make_exchange()]), ("exchanges", (object(),)), ("exchanges", None),
        ):
            with self.subTest(field_name=field_name, values_type=type(values).__name__), self.assertRaises(ValueError):
                replace(session, **{field_name: values})

    def test_session_is_frozen_and_has_slots(self):
        session = make_session()
        with self.assertRaises(FrozenInstanceError):
            session.collection_status = "collection_error"
        self.assertFalse(hasattr(session, "__dict__"))

    def test_records_do_not_expose_trust_or_sufficiency_fields(self):
        forbidden = (
            "trusted", "verified", "provenance_verified", "confidence", "research_status",
            "sufficient", "capability_relevant", "cookies", "Authorization", "headers", "bodies",
            "selectors", "input_text", "raw_error", "to_mapping",
        )
        for record in (make_phase(), make_phase(kind="interaction"), make_session()):
            for name in forbidden:
                with self.subTest(record_type=type(record).__name__, name=name):
                    self.assertFalse(hasattr(record, name))

    def test_session_has_exactly_the_requested_fields(self):
        self.assertEqual(
            {field.name for field in fields(BrowserResearchSessionEvidence)},
            {"session_id", "initial_page_url", "final_page_url", "initial_navigation_exchange_id",
             "collection_status", "duration_ms", "request_count", "observed_bytes", "redirect_count",
             "interaction_count", "max_duration_ms", "max_requests", "max_bytes", "max_redirects",
             "max_interactions", "lost_events", "phases", "exchanges"},
        )

    def test_identical_requests_remain_separate_exchanges(self):
        first = make_exchange()
        second = make_exchange(exchange_id="exchange-2", start_sequence=2, request=first.request)
        session = make_session(exchanges=(first, second))
        self.assertEqual(session.request_count, 2)
        self.assertIs(session.exchanges[0].request, session.exchanges[1].request)
        self.assertNotEqual(session.exchanges[0].exchange_id, session.exchanges[1].exchange_id)

    def test_sent_does_not_require_physical_network_delivery(self):
        for delivery in ("cache", "service_worker", "unknown"):
            with self.subTest(delivery=delivery):
                exchange = make_exchange(response=make_response(delivery=delivery))
                self.assertEqual(make_session(exchanges=(exchange,)).exchanges[0].send_state, "sent")

    def test_construction_does_not_mutate_existing_records(self):
        phase = make_phase()
        exchange = make_exchange()
        original_phase, original_exchange = replace(phase), replace(exchange)
        session = make_session(phases=(phase,), exchanges=(exchange,))
        self.assertIs(session.phases[0], phase)
        self.assertIs(session.exchanges[0], exchange)
        self.assertEqual(phase, original_phase)
        self.assertEqual(exchange, original_exchange)


if __name__ == "__main__":
    unittest.main()
