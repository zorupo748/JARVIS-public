import http.client
import io
import os
import socket
import unittest
import urllib.request
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from itertools import product
from pathlib import Path
from unittest.mock import Mock, patch

from jarvis.core import browser_operation_candidate as candidate_module
from jarvis.core.browser_operation_candidate import (
    BrowserOperationCandidate,
    BrowserOperationCandidateOccurrence,
)
from jarvis.core.browser_operation_contract import BrowserOrigin


OCCURRENCE_FIELDS = (
    "exchange_id", "phase_id", "interaction_id", "send_state",
    "response_status_code", "response_format", "response_content_type", "response_delivery",
)
CANDIDATE_FIELDS = (
    "candidate_id", "session_id", "observed_method", "observed_origin", "static_path",
    "observed_query_parameter_names", "observed_body_parameter_names", "occurrences",
)
RESPONSE_FIELDS = OCCURRENCE_FIELDS[4:]
PARAMETER_FIELDS = CANDIDATE_FIELDS[5:7]
MIME_CASES = (
    ("json", "application/json"),
    ("json", "text/json"),
    ("json", "application/problem+json"),
    ("html", "text/html"),
    ("html", "application/xhtml+xml"),
    ("xml", "application/xml"),
    ("xml", "text/xml"),
    ("xml", "application/soap+xml"),
    ("text", "text/plain"),
    ("text", "text/csv"),
    ("binary", "application/octet-stream"),
    ("binary", "image/png"),
    ("binary", "audio/mpeg"),
    ("binary", "video/mp4"),
    ("unknown", "application/x-custom"),
    ("unknown", ""),
)


def make_occurrence(**overrides):
    values = {
        "exchange_id": "exchange-1",
        "phase_id": "phase-1",
        "interaction_id": None,
        "send_state": "sent",
        "response_status_code": 200,
        "response_format": "json",
        "response_content_type": "application/json",
        "response_delivery": "network",
    }
    values.update(overrides)
    return BrowserOperationCandidateOccurrence(**values)


def make_candidate(**overrides):
    values = {
        "candidate_id": "candidate-1",
        "session_id": "session-1",
        "observed_method": "GET",
        "observed_origin": BrowserOrigin("https", "example.com", 443),
        "static_path": None,
        "observed_query_parameter_names": None,
        "observed_body_parameter_names": None,
        "occurrences": (make_occurrence(),),
    }
    values.update(overrides)
    return BrowserOperationCandidate(**values)


class TupleSubclass(tuple):
    pass


class IntSubclass(int):
    pass


class MutableString(str):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class OccurrenceSubclass(BrowserOperationCandidateOccurrence):
    __slots__ = ()


class CallbackString(str):
    """Scalar string with mutable state and methods that must never be invoked."""

    def __new__(cls, value):
        instance = super().__new__(cls, value)
        instance.mutable = []
        return instance

    def unexpected(self, *args, **kwargs):
        raise AssertionError("input callback executed")

    strip = lower = __str__ = __len__ = __iter__ = __eq__ = __hash__ = unexpected


class BrowserOperationCandidateOccurrenceTests(unittest.TestCase):
    def test_sent_with_response_preserves_all_observed_metadata(self):
        occurrence = make_occurrence(interaction_id="interaction-1", response_status_code=404)
        self.assertEqual(
            tuple(getattr(occurrence, name) for name in OCCURRENCE_FIELDS),
            ("exchange-1", "phase-1", "interaction-1", "sent", 404, "json", "application/json", "network"),
        )

    def test_all_send_states_permit_absent_response(self):
        for send_state in ("sent", "not_sent", "unknown"):
            with self.subTest(send_state=send_state):
                occurrence = make_occurrence(
                    send_state=send_state, **dict.fromkeys(RESPONSE_FIELDS),
                )
                self.assertEqual(occurrence.send_state, send_state)
                self.assertTrue(all(getattr(occurrence, name) is None for name in RESPONSE_FIELDS))

    def test_response_requires_sent(self):
        for send_state in ("not_sent", "unknown"):
            with self.subTest(send_state=send_state), self.assertRaises(ValueError):
                make_occurrence(send_state=send_state)

    def test_every_partial_response_group_is_rejected(self):
        for absent in product((False, True), repeat=4):
            if all(absent) or not any(absent):
                continue
            overrides = {name: None for name, missing in zip(RESPONSE_FIELDS, absent) if missing}
            with self.subTest(absent=absent), self.assertRaises(ValueError):
                make_occurrence(**overrides)

    def test_status_boundaries_and_non_success_statuses_are_observations(self):
        for status in (100, 199, 200, 299, 302, 404, 500, 599):
            with self.subTest(status=status):
                self.assertEqual(make_occurrence(response_status_code=status).response_status_code, status)

    def test_status_requires_exact_int_and_range(self):
        for status in (99, 600, -1, True, False, 200.0, "200", [], IntSubclass(200)):
            with self.subTest(status=status), self.assertRaises(ValueError):
                make_occurrence(response_status_code=status)

    def test_valid_mime_classifications_include_unknown(self):
        for response_format, mime in MIME_CASES:
            with self.subTest(response_format=response_format, mime=mime):
                occurrence = make_occurrence(
                    response_format=response_format, response_content_type=mime,
                )
                self.assertEqual(occurrence.response_format, response_format)
                self.assertEqual(occurrence.response_content_type, mime)

    def test_format_enum_is_closed_and_not_normalized(self):
        for response_format in ("JSON", " json ", "yaml", "", 1, [], True):
            with self.subTest(response_format=response_format), self.assertRaises(ValueError):
                make_occurrence(response_format=response_format)

    def test_format_must_match_mime(self):
        for response_format in ("html", "xml", "text", "binary", "unknown"):
            with self.subTest(response_format=response_format), self.assertRaises(ValueError):
                make_occurrence(response_format=response_format)

    def test_content_type_must_arrive_canonical(self):
        for mime in (
            "Application/JSON", "application/JSON", " application/json", "application/json ",
            "\tapplication/json", "application/json; charset=utf-8", "application/json;",
        ):
            with self.subTest(mime=mime), self.assertRaises(ValueError):
                make_occurrence(response_content_type=mime)

    def test_malformed_content_types_and_controls_are_rejected(self):
        for mime in (
            "json", "application/", "/json", "application/*", "application/json/extra",
            "application/json,text/html", "content-type: application/json", "application/j son",
            "application/j\x00son", "application/j\x7fson", "application/json\r\nsecret",
            "application/jéson", 1, [], True,
        ):
            with self.subTest(mime=mime), self.assertRaises(ValueError):
                make_occurrence(response_content_type=mime)

    def test_empty_content_type_requires_unknown_format(self):
        for response_format in ("json", "html", "xml", "text", "binary"):
            with self.subTest(response_format=response_format), self.assertRaises(ValueError):
                make_occurrence(response_format=response_format, response_content_type="")
        for mime in (" ", "\t", ";", "application/x-custom; version=1"):
            with self.subTest(mime=mime), self.assertRaises(ValueError):
                make_occurrence(response_format="unknown", response_content_type=mime)

    def test_delivery_enum_preserves_all_observed_deliveries(self):
        for delivery in ("network", "cache", "service_worker", "unknown"):
            with self.subTest(delivery=delivery):
                self.assertEqual(make_occurrence(response_delivery=delivery).response_delivery, delivery)

    def test_delivery_enum_is_closed_and_not_normalized(self):
        for delivery in ("NETWORK", " network ", "local", "", 1, [], True):
            with self.subTest(delivery=delivery), self.assertRaises(ValueError):
                make_occurrence(response_delivery=delivery)

    def test_send_state_enum_is_closed_and_not_normalized(self):
        for send_state in ("SENT", " sent ", "pending", "", None, 1, [], True):
            with self.subTest(send_state=send_state), self.assertRaises(ValueError):
                make_occurrence(send_state=send_state)

    def test_id_validation_and_length_limit(self):
        for field_name in ("exchange_id", "phase_id", "interaction_id"):
            for value in ("", " \t\n", "x" * 129, 1, [], True):
                with self.subTest(field=field_name, value=value), self.assertRaises(ValueError):
                    make_occurrence(**{field_name: value})
            with self.subTest(field=field_name, boundary=128):
                self.assertEqual(getattr(make_occurrence(**{field_name: "x" * 128}), field_name), "x" * 128)
        for field_name in ("exchange_id", "phase_id"):
            with self.subTest(field=field_name, value=None), self.assertRaises(ValueError):
                make_occurrence(**{field_name: None})

    def test_ids_are_stripped_without_a_restricted_alphabet(self):
        occurrence = make_occurrence(
            exchange_id=" \tintercambio local:ñ/1 \n", phase_id=" fase: α ",
            interaction_id="  interacción local/1  ",
        )
        self.assertEqual(occurrence.exchange_id, "intercambio local:ñ/1")
        self.assertEqual(occurrence.phase_id, "fase: α")
        self.assertEqual(occurrence.interaction_id, "interacción local/1")
        self.assertEqual(make_occurrence(exchange_id=" " + "x" * 128 + " ").exchange_id, "x" * 128)
        self.assertIsNone(make_occurrence().interaction_id)

    def test_frozen_slots_and_exact_fields(self):
        occurrence = make_occurrence()
        self.assertEqual(tuple(field.name for field in fields(occurrence)), OCCURRENCE_FIELDS)
        self.assertEqual(BrowserOperationCandidateOccurrence.__slots__, OCCURRENCE_FIELDS)
        self.assertFalse(hasattr(occurrence, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            occurrence.exchange_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            del occurrence.response_status_code
        with self.assertRaises((AttributeError, TypeError)):
            occurrence.extra = "new"


class BrowserOperationCandidateTests(unittest.TestCase):
    def test_minimal_candidate_keeps_unknown_structure(self):
        candidate = make_candidate()
        self.assertEqual(candidate.candidate_id, "candidate-1")
        self.assertEqual(candidate.session_id, "session-1")
        self.assertEqual(candidate.observed_method, "GET")
        self.assertEqual(candidate.observed_origin, BrowserOrigin("https", "example.com", 443))
        self.assertIsNone(candidate.static_path)
        self.assertIsNone(candidate.observed_query_parameter_names)
        self.assertIsNone(candidate.observed_body_parameter_names)
        self.assertEqual(candidate.occurrences, (make_occurrence(),))

    def test_candidate_and_session_id_validation(self):
        for field_name in ("candidate_id", "session_id"):
            for value in (None, "", " \t\n", "x" * 129, 1, [], True):
                with self.subTest(field=field_name, value=value), self.assertRaises(ValueError):
                    make_candidate(**{field_name: value})
            with self.subTest(field=field_name, boundary=128):
                self.assertEqual(getattr(make_candidate(**{field_name: " x" + "x" * 127 + " "}), field_name), "x" * 128)

    def test_candidate_ids_are_stripped_without_alphabet_restrictions(self):
        candidate = make_candidate(candidate_id=" candidato local:ñ/1 ", session_id=" sesión local:α ")
        self.assertEqual(candidate.candidate_id, "candidato local:ñ/1")
        self.assertEqual(candidate.session_id, "sesión local:α")

    def test_all_methods_are_observable(self):
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                self.assertEqual(make_candidate(observed_method=method).observed_method, method)

    def test_method_enum_is_closed_and_not_normalized(self):
        for method in ("get", "Post", " GET ", "TRACE", "CONNECT", "", None, 1, [], True):
            with self.subTest(method=method), self.assertRaises(ValueError):
                make_candidate(observed_method=method)

    def test_origin_requires_exact_existing_type(self):
        for origin in (
            None, "https://example.com", "https://example.com/path", {},
            ("https", "example.com", 443), OriginSubclass("https", "example.com", 443),
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_candidate(observed_origin=origin)

    def test_origin_is_observed_without_https_or_same_origin_policy(self):
        origin = BrowserOrigin("http", "api.other.example", 8080)
        candidate = make_candidate(observed_origin=origin)
        self.assertIs(candidate.observed_origin, origin)

    def test_static_paths_are_preserved_exactly(self):
        for static_path in ("/", "/api", "/API/Search/", "/v1/a_b-c.d~e", "/123456"):
            with self.subTest(static_path=static_path):
                self.assertEqual(make_candidate(static_path=static_path).static_path, static_path)
        self.assertIsNone(make_candidate(static_path=None).static_path)

    def test_invalid_static_paths_are_rejected_without_normalization(self):
        for static_path in (
            "", "api", "//api", "/a//b", "/.", "/..", "/a/../b", "/a/./b",
            " /api", "/api ", "/api?token=secret", "/api#fragment", "/a%2fb",
            "/a;b", "/a\\b", "/é", "/a\n", "https://example.com/api", 1, [], True,
        ):
            with self.subTest(static_path=static_path), self.assertRaises(ValueError):
                make_candidate(static_path=static_path)

    def test_unknown_and_known_empty_parameter_structures_remain_distinct(self):
        for field_name in PARAMETER_FIELDS:
            with self.subTest(field=field_name):
                unknown = make_candidate(**{field_name: None})
                absent = make_candidate(**{field_name: ()})
                self.assertIsNone(getattr(unknown, field_name))
                self.assertEqual(getattr(absent, field_name), ())
                self.assertNotEqual(unknown, absent)

    def test_parameter_collections_require_exact_tuple(self):
        for field_name in PARAMETER_FIELDS:
            for names in (["name"], {"name"}, frozenset({"name"}), "name", {}, TupleSubclass(("name",))):
                with self.subTest(field=field_name, names=names), self.assertRaises(ValueError):
                    make_candidate(**{field_name: names})

    def test_parameter_members_require_exact_str(self):
        for field_name in PARAMETER_FIELDS:
            for name in (None, 1, True, [], b"name", CallbackString("name")):
                with self.subTest(field=field_name, name=name), self.assertRaises(ValueError):
                    make_candidate(**{field_name: (name,)})

    def test_parameter_names_require_alphabet_and_existing_stripping(self):
        for field_name in PARAMETER_FIELDS:
            for name in (
                "", " ", " name", "name ", "\tname", "name\n", "1name", "-name",
                "name.with.dot", "name/value", "name:value", "name value", "naïve", "name\x00",
            ):
                with self.subTest(field=field_name, name=name), self.assertRaises(ValueError):
                    make_candidate(**{field_name: (name,)})

    def test_parameter_name_length_boundary(self):
        for field_name in PARAMETER_FIELDS:
            with self.subTest(field=field_name):
                names = ("n" * 64,)
                self.assertEqual(getattr(make_candidate(**{field_name: names}), field_name), names)
                with self.assertRaises(ValueError):
                    make_candidate(**{field_name: ("n" * 65,)})

    def test_parameter_count_boundary(self):
        for field_name in PARAMETER_FIELDS:
            with self.subTest(field=field_name):
                names = tuple(f"name_{index}" for index in range(64))
                self.assertEqual(getattr(make_candidate(**{field_name: names}), field_name), names)
                with self.assertRaises(ValueError):
                    make_candidate(**{field_name: names + ("name_64",)})

    def test_duplicate_parameter_names_are_rejected(self):
        for field_name in PARAMETER_FIELDS:
            with self.subTest(field=field_name), self.assertRaises(ValueError):
                make_candidate(**{field_name: ("name", "other", "name")})

    def test_parameter_order_and_case_are_preserved_at_each_location(self):
        names = ("z", "Name", "name", "_", "a-b", "a_1")
        candidate = make_candidate(
            observed_query_parameter_names=names, observed_body_parameter_names=names,
        )
        self.assertIs(candidate.observed_query_parameter_names, names)
        self.assertIs(candidate.observed_body_parameter_names, names)

    def test_occurrences_require_exact_nonempty_tuple(self):
        occurrence = make_occurrence()
        for occurrences in (
            None, (), [occurrence], {occurrence}, frozenset({occurrence}),
            {"exchange-1": occurrence}, TupleSubclass((occurrence,)),
        ):
            with self.subTest(occurrences=occurrences), self.assertRaises(ValueError):
                make_candidate(occurrences=occurrences)

    def test_occurrence_members_require_exact_type(self):
        subclass = OccurrenceSubclass(**{
            name: getattr(make_occurrence(), name) for name in OCCURRENCE_FIELDS
        })
        for occurrence in (None, {}, "exchange-1", 1, subclass):
            with self.subTest(occurrence=occurrence), self.assertRaises(ValueError):
                make_candidate(occurrences=(occurrence,))

    def test_occurrence_count_boundary(self):
        occurrences = tuple(make_occurrence(exchange_id=f"exchange-{index}") for index in range(64))
        self.assertIs(make_candidate(occurrences=occurrences).occurrences, occurrences)
        with self.assertRaises(ValueError):
            make_candidate(occurrences=occurrences + (make_occurrence(exchange_id="exchange-64"),))

    def test_exchange_ids_must_be_unique_after_occurrence_stripping(self):
        for repeated in (make_occurrence(), make_occurrence(exchange_id=" exchange-1 ", phase_id="other")):
            with self.subTest(repeated=repeated), self.assertRaises(ValueError):
                make_candidate(occurrences=(make_occurrence(), repeated))

    def test_occurrences_may_have_different_responses_and_interactions(self):
        occurrences = (
            make_occurrence(exchange_id="exchange-3", phase_id="unregistered-phase", interaction_id="local-b"),
            make_occurrence(
                exchange_id="exchange-1", phase_id="another-phase", interaction_id="local-a",
                response_status_code=503, response_format="text", response_content_type="text/plain",
                response_delivery="cache",
            ),
            make_occurrence(
                exchange_id="exchange-2", send_state="unknown", **dict.fromkeys(RESPONSE_FIELDS),
            ),
        )
        candidate = make_candidate(session_id="unregistered-session", occurrences=occurrences)
        self.assertIs(candidate.occurrences, occurrences)
        self.assertEqual(tuple(item.exchange_id for item in candidate.occurrences), ("exchange-3", "exchange-1", "exchange-2"))
        self.assertEqual(tuple(item.interaction_id for item in candidate.occurrences), ("local-b", "local-a", None))

    def test_frozen_slots_and_exact_fields(self):
        candidate = make_candidate()
        self.assertEqual(tuple(field.name for field in fields(candidate)), CANDIDATE_FIELDS)
        self.assertEqual(BrowserOperationCandidate.__slots__, CANDIDATE_FIELDS)
        self.assertFalse(hasattr(candidate, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            candidate.candidate_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            del candidate.occurrences
        with self.assertRaises((AttributeError, TypeError)):
            candidate.extra = "new"
        with self.assertRaises(FrozenInstanceError):
            candidate.observed_origin.hostname = "changed.example"
        with self.assertRaises(FrozenInstanceError):
            candidate.occurrences[0].exchange_id = "changed"


class BrowserOperationCandidateSafetyTests(unittest.TestCase):
    def test_no_semantic_authorization_or_sensitive_fields(self):
        forbidden = (
            "trusted", "verified", "approved", "promoted", "confidence", "sufficient",
            "research_status", "capability_id", "capability_relevant", "contract_id",
            "required_parameters", "expected_parameters", "demonstrated_required", "allowed",
            "functional_result", "success", "completion", "query_values", "body_values",
            "request_body", "response_body", "headers", "authorization", "cookies", "tokens",
            "tracking_codes", "passwords", "dom_selectors", "text_input", "raw_path", "raw_url",
            "source_url", "endpoint_url", "callback", "code", "regex", "timestamps",
            "stack_traces", "error_messages",
        )
        for record in (make_occurrence(), make_candidate()):
            for name in forbidden:
                with self.subTest(record=type(record).__name__, field=name):
                    self.assertFalse(hasattr(record, name))
                    with self.assertRaises(TypeError):
                        replace(record, **{name: "FORBIDDEN_SECRET"})

    def test_no_public_serializers_or_persistence_or_promotion(self):
        for record in (make_occurrence(), make_candidate()):
            for name in (
                "to_prompt_context", "to_mapping", "to_json", "from_json", "serialize",
                "save", "load", "register", "promote",
            ):
                with self.subTest(record=type(record).__name__, method=name):
                    self.assertFalse(hasattr(record, name))
        self.assertEqual(
            candidate_module.__all__,
            ("BrowserOperationCandidateOccurrence", "BrowserOperationCandidate"),
        )

    def test_construction_does_not_access_network_dns_or_filesystem(self):
        targets = (
            (socket, "getaddrinfo"), (socket, "gethostbyname"), (socket, "gethostbyname_ex"),
            (socket, "socket"), (socket, "create_connection"), (urllib.request, "urlopen"),
            (http.client.HTTPConnection, "connect"), (http.client.HTTPSConnection, "connect"),
            (io, "open"), (os, "open"), (os, "stat"), (Path, "read_text"), (Path, "write_text"),
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch.object(owner, name, side_effect=AssertionError("I/O executed"))) for owner, name in targets]
            guards.append(stack.enter_context(patch("builtins.open", side_effect=AssertionError("I/O executed"))))
            candidate = make_candidate(static_path="/api/search", observed_query_parameter_names=("q",))
            self.assertEqual(candidate.occurrences[0].response_format, "json")
            with self.assertRaises(ValueError):
                replace(candidate, static_path="/api?secret=value")
            for guard in guards:
                guard.assert_not_called()

    def test_callback_objects_are_rejected_without_execution(self):
        callback = Mock(side_effect=AssertionError("callback executed"))
        for field_name in OCCURRENCE_FIELDS:
            with self.subTest(record="occurrence", field=field_name), self.assertRaises(ValueError):
                make_occurrence(**{field_name: callback})
        for field_name in CANDIDATE_FIELDS:
            with self.subTest(record="candidate", field=field_name), self.assertRaises(ValueError):
                make_candidate(**{field_name: callback})
        callback.assert_not_called()
        with self.assertRaises(TypeError):
            make_candidate(callback=callback)
        callback.assert_not_called()

    def test_scalar_string_subclasses_are_copied_without_callbacks(self):
        occurrence = make_occurrence(**{
            name: CallbackString(value)
            for name, value in (
                ("exchange_id", " exchange-1 "), ("phase_id", " phase-1 "),
                ("interaction_id", " interaction-1 "), ("send_state", "sent"),
                ("response_format", "json"), ("response_content_type", "application/json"),
                ("response_delivery", "network"),
            )
        })
        candidate = make_candidate(
            candidate_id=CallbackString(" candidate-1 "), session_id=CallbackString(" session-1 "),
            observed_method=CallbackString("GET"), static_path=CallbackString("/api"),
            occurrences=(occurrence,),
        )
        for record, names in (
            (occurrence, tuple(name for name in OCCURRENCE_FIELDS if name != "response_status_code")),
            (candidate, ("candidate_id", "session_id", "observed_method", "static_path")),
        ):
            for name in names:
                with self.subTest(record=type(record).__name__, field=name):
                    self.assertIs(type(getattr(record, name)), str)
        self.assertEqual(candidate.candidate_id, "candidate-1")
        self.assertEqual(occurrence.interaction_id, "interaction-1")
        self.assertIsInstance(hash(candidate), int)

    def test_origin_string_subclasses_cannot_retain_mutable_state(self):
        scheme = MutableString("https")
        hostname = MutableString("example.com")
        scheme.state = []
        hostname.state = []
        origin = BrowserOrigin(scheme, hostname, 443)
        candidate = make_candidate(observed_origin=origin)
        self.assertIs(type(candidate.observed_origin), BrowserOrigin)
        self.assertIs(type(candidate.observed_origin.scheme), str)
        self.assertIs(type(candidate.observed_origin.hostname), str)
        self.assertEqual(candidate.observed_origin, BrowserOrigin("https", "example.com", 443))
        scheme.state.append("later change")
        hostname.state.append("later change")
        self.assertFalse(hasattr(candidate.observed_origin.scheme, "state"))
        self.assertFalse(hasattr(candidate.observed_origin.hostname, "state"))
        self.assertIs(origin.scheme, scheme)
        self.assertIs(origin.hostname, hostname)

    def test_dataclasses_replace_revalidates_both_records(self):
        occurrence = make_occurrence()
        candidate = make_candidate()
        for overrides in (
            {"exchange_id": ""}, {"send_state": "not_sent"}, {"response_status_code": True},
            {"response_format": None}, {"response_content_type": "APPLICATION/JSON"},
        ):
            with self.subTest(record="occurrence", fields=tuple(overrides)), self.assertRaises(ValueError):
                replace(occurrence, **overrides)
        for overrides in (
            {"candidate_id": ""}, {"observed_method": "get"}, {"static_path": "/../api"},
            {"observed_query_parameter_names": ["q"]}, {"occurrences": ()},
            {"occurrences": (occurrence, occurrence)},
        ):
            with self.subTest(record="candidate", fields=tuple(overrides)), self.assertRaises(ValueError):
                replace(candidate, **overrides)
        self.assertEqual(replace(occurrence, exchange_id=" exchange-2 ").exchange_id, "exchange-2")
        self.assertEqual(replace(candidate, candidate_id=" candidate-2 ").candidate_id, "candidate-2")

    def test_equivalent_input_has_equal_objects_and_hashes(self):
        for factory in (make_occurrence, make_candidate):
            with self.subTest(record=factory.__name__):
                first, second = factory(), factory()
                self.assertIsNot(first, second)
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))
                self.assertEqual(len({first, second}), 1)

    def test_construction_does_not_mutate_existing_collections(self):
        query = ("z", "a")
        body = ("body_name",)
        occurrences = (make_occurrence(exchange_id="exchange-2"), make_occurrence())
        before = (query, body, occurrences, tuple(hash(item) for item in occurrences))
        candidate = make_candidate(
            observed_query_parameter_names=query, observed_body_parameter_names=body, occurrences=occurrences,
        )
        self.assertIs(candidate.observed_query_parameter_names, query)
        self.assertIs(candidate.observed_body_parameter_names, body)
        self.assertIs(candidate.occurrences, occurrences)
        self.assertEqual((query, body, occurrences, tuple(hash(item) for item in occurrences)), before)
        invalid_names = ["z", "a"]
        with self.assertRaises(ValueError):
            make_candidate(observed_query_parameter_names=invalid_names)
        self.assertEqual(invalid_names, ["z", "a"])

    def test_occurrence_count_does_not_create_confidence_or_success(self):
        for count in (1, 64):
            with self.subTest(count=count):
                candidate = make_candidate(occurrences=tuple(
                    make_occurrence(exchange_id=f"exchange-{index}") for index in range(count)
                ))
                self.assertEqual(len(candidate.occurrences), count)
                for name in ("confidence", "sufficient", "success", "functional_result"):
                    self.assertFalse(hasattr(candidate, name))

    def test_rejected_values_do_not_leak_into_validation_messages(self):
        secret = "DO_NOT_EXPORT_SECRET"
        for factory, overrides in (
            (make_occurrence, {"send_state": secret}),
            (make_occurrence, {"response_content_type": "application/json; token=" + secret}),
            (make_candidate, {"static_path": "/api?token=" + secret}),
            (make_candidate, {"observed_query_parameter_names": ("invalid=" + secret,)}),
        ):
            with self.subTest(factory=factory.__name__, fields=tuple(overrides)):
                with self.assertRaises(ValueError) as caught:
                    factory(**overrides)
                self.assertNotIn(secret, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
