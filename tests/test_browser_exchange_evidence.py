import unittest
from dataclasses import FrozenInstanceError, fields, replace

from jarvis.core.browser_exchange_evidence import (
    BrowserNetworkExchangeEvidence,
    BrowserResponseEvidence,
    derive_response_format,
)
from jarvis.core.browser_network_evidence import (
    BrowserRequestEvidence,
    build_browser_request_evidence,
)


def make_response(**overrides):
    values = {
        "status_code": 200,
        "content_type": "application/json",
        "response_format": "json",
        "response_url": "https://api.example.com/track",
        "delivery": "network",
        "observed_bytes": None,
        "observed_bytes_kind": "unknown",
    }
    values.update(overrides)
    return BrowserResponseEvidence(**values)


def make_request():
    return build_browser_request_evidence(
        page_url="https://example.com/",
        request_url="https://api.example.com/track?token=SUPER_SECRET#x",
        method="GET",
        consulted=True,
    )


def make_exchange(**overrides):
    values = {
        "exchange_id": "exchange-1",
        "request": make_request(),
        "send_state": "sent",
        "response": make_response(),
        "completion": "complete",
        "phase_id": "phase-1",
        "start_sequence": 0,
        "redirect_from_exchange_id": None,
    }
    values.update(overrides)
    return BrowserNetworkExchangeEvidence(**values)


class BrowserResponseEvidenceTests(unittest.TestCase):
    def test_json_charset_is_normalized_on_direct_construction(self):
        response = make_response(content_type=" Application/JSON; charset=utf-8 ")
        self.assertEqual(response.content_type, "application/json")
        self.assertEqual(response.response_format, "json")
        self.assertNotIn("charset", repr(response))

    def test_problem_json_and_text_json(self):
        for mime in ("application/problem+json", "text/json", "application/vnd.api+json"):
            with self.subTest(mime=mime):
                self.assertEqual(derive_response_format(mime), "json")
                self.assertEqual(make_response(content_type=mime).response_format, "json")

    def test_html_including_xhtml(self):
        for mime in ("text/html", "application/xhtml+xml"):
            with self.subTest(mime=mime):
                self.assertEqual(derive_response_format(mime), "html")
                self.assertEqual(make_response(content_type=mime, response_format="html").response_format, "html")

    def test_xml_including_structured_suffix(self):
        for mime in ("application/xml", "text/xml", "application/soap+xml"):
            with self.subTest(mime=mime):
                self.assertEqual(derive_response_format(mime), "xml")
                self.assertEqual(make_response(content_type=mime, response_format="xml").response_format, "xml")

    def test_text_plain_and_other_text(self):
        for mime in ("text/plain", "text/csv"):
            with self.subTest(mime=mime):
                self.assertEqual(derive_response_format(mime), "text")
                self.assertEqual(make_response(content_type=mime, response_format="text").response_format, "text")

    def test_binary_mime_types(self):
        for mime in ("image/png", "audio/mpeg", "video/mp4", "application/octet-stream"):
            with self.subTest(mime=mime):
                self.assertEqual(derive_response_format(mime), "binary")
                self.assertEqual(make_response(content_type=mime, response_format="binary").response_format, "binary")

    def test_unknown_and_unobservable_content_type(self):
        for mime in ("application/x-custom", "", "   "):
            with self.subTest(mime=mime):
                self.assertEqual(derive_response_format(mime), "unknown")
                response = make_response(content_type=mime, response_format="unknown")
                self.assertEqual(response.content_type, mime.strip())

    def test_public_derivation_normalizes_parameters(self):
        self.assertEqual(derive_response_format(" APPLICATION/PROBLEM+JSON; charset=utf-8"), "json")

    def test_url_extension_does_not_determine_format(self):
        response = make_response(
            content_type="", response_format="unknown", response_url="https://api.example.com/data.json"
        )
        self.assertEqual(response.response_format, "unknown")

    def test_malformed_content_type_is_rejected_directly(self):
        for mime in ("Content-Type: application/json", "application/json, text/html", "json", ";charset=utf-8", "application/*", "application/json\r\nSet-Cookie: secret", None, 123):
            with self.subTest(mime=mime), self.assertRaises(ValueError):
                make_response(content_type=mime)

    def test_response_format_is_a_closed_enum_and_must_match_mime(self):
        for response_format in ("invalid", "JSON", "html", "unknown", None, []):
            with self.subTest(response_format=response_format), self.assertRaises(ValueError):
                make_response(response_format=response_format)

    def test_status_99_is_rejected(self):
        with self.assertRaises(ValueError):
            make_response(status_code=99)

    def test_status_600_is_rejected(self):
        with self.assertRaises(ValueError):
            make_response(status_code=600)

    def test_bool_and_non_integer_status_are_rejected(self):
        for status in (True, False, 200.0, "200", None):
            with self.subTest(status=status), self.assertRaises(ValueError):
                make_response(status_code=status)

    def test_status_boundaries_are_allowed_without_success_judgment(self):
        for status in (100, 302, 404, 500, 599):
            with self.subTest(status=status):
                self.assertEqual(make_response(status_code=status).status_code, status)

    def test_response_url_removes_query_fragment_and_secret_from_repr(self):
        response = make_response(response_url="https://api.example.com/track?token=SUPER_SECRET#x")
        self.assertEqual(response.response_url, "https://api.example.com/track")
        self.assertNotIn("SUPER_SECRET", repr(response))
        self.assertNotIn("SUPER_SECRET", repr(make_exchange(response=response)))

    def test_response_url_preserves_host_port_and_path(self):
        response = make_response(response_url="https://API.example.com:8443/a%2Fb?token=secret#x")
        self.assertEqual(response.response_url, "https://API.example.com:8443/a%2Fb")

    def test_response_url_with_credentials_is_rejected(self):
        for url in ("https://user:pass@example.com/", "https://user@example.com/", "https://@example.com/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                make_response(response_url=url)

    def test_relative_and_malformed_response_urls_are_rejected(self):
        for url in ("/track", "//example.com/track", "file:///track", "https:///track", "https://:80/", "https://example.com:99999/", "https://example.com/\ntrack", None, 123):
            with self.subTest(url=url), self.assertRaises(ValueError):
                make_response(response_url=url)

    def test_delivery_is_a_closed_enum(self):
        for delivery in ("network", "cache", "service_worker", "unknown"):
            with self.subTest(delivery=delivery):
                self.assertEqual(make_response(delivery=delivery).delivery, delivery)
        for delivery in ("invalid", "NETWORK", None, []):
            with self.subTest(delivery=delivery), self.assertRaises(ValueError):
                make_response(delivery=delivery)

    def test_negative_observed_bytes_are_rejected(self):
        with self.assertRaises(ValueError):
            make_response(observed_bytes=-1, observed_bytes_kind="measured")

    def test_bool_and_non_integer_observed_bytes_are_rejected(self):
        for size in (True, False, 1.0, "1"):
            with self.subTest(size=size), self.assertRaises(ValueError):
                make_response(observed_bytes=size, observed_bytes_kind="measured")

    def test_observed_bytes_have_a_structural_bound(self):
        self.assertEqual(make_response(observed_bytes=1 << 40, observed_bytes_kind="measured").observed_bytes, 1 << 40)
        with self.assertRaises(ValueError):
            make_response(observed_bytes=(1 << 40) + 1, observed_bytes_kind="measured")

    def test_bytes_none_requires_unknown_kind(self):
        self.assertIsNone(make_response().observed_bytes)
        for kind in ("measured", "estimated", "invalid", None, []):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_response(observed_bytes=None, observed_bytes_kind=kind)

    def test_bytes_present_require_measured_or_estimated(self):
        for kind in ("measured", "estimated"):
            with self.subTest(kind=kind):
                self.assertEqual(make_response(observed_bytes=0, observed_bytes_kind=kind).observed_bytes, 0)
        for kind in ("unknown", "invalid", None, []):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_response(observed_bytes=10, observed_bytes_kind=kind)

    def test_response_contains_only_the_seven_safe_fields(self):
        self.assertEqual(
            {field.name for field in fields(BrowserResponseEvidence)},
            {"status_code", "content_type", "response_format", "response_url", "delivery", "observed_bytes", "observed_bytes_kind"},
        )
        response = make_response()
        for name in ("body", "headers", "set_cookie", "cookies", "Authorization", "authorization", "to_mapping"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(response, name))

    def test_response_is_frozen(self):
        with self.assertRaises(FrozenInstanceError):
            make_response().status_code = 500


class BrowserNetworkExchangeEvidenceTests(unittest.TestCase):
    def test_valid_complete_exchange(self):
        exchange = make_exchange()
        self.assertEqual(exchange.send_state, "sent")
        self.assertEqual(exchange.completion, "complete")
        self.assertIsInstance(exchange.response, BrowserResponseEvidence)

    def test_identical_requests_can_have_distinct_exchanges(self):
        request = make_request()
        first = make_exchange(request=request)
        second = make_exchange(request=request, exchange_id="exchange-2", response=make_response(status_code=500))
        self.assertIs(first.request, second.request)
        self.assertNotEqual(first.exchange_id, second.exchange_id)
        self.assertEqual(first.response.status_code, 200)
        self.assertEqual(second.response.status_code, 500)

    def test_response_requires_sent_including_not_sent(self):
        for send_state in ("not_sent", "unknown"):
            with self.subTest(send_state=send_state), self.assertRaises(ValueError):
                make_exchange(send_state=send_state, completion="failed")

    def test_complete_without_response_is_rejected(self):
        with self.assertRaises(ValueError):
            make_exchange(response=None)

    def test_complete_without_sent_is_rejected(self):
        for send_state in ("not_sent", "unknown"):
            with self.subTest(send_state=send_state), self.assertRaises(ValueError):
                make_exchange(send_state=send_state, response=None)

    def test_incomplete_states_do_not_invent_response_or_success(self):
        for completion in ("failed", "cancelled", "pending"):
            for send_state in ("sent", "not_sent", "unknown"):
                with self.subTest(completion=completion, send_state=send_state):
                    self.assertIsNone(make_exchange(completion=completion, send_state=send_state, response=None).response)
            with self.subTest(completion=completion):
                self.assertIsNotNone(make_exchange(completion=completion).response)

    def test_empty_and_non_string_exchange_ids_are_rejected(self):
        for identifier in ("", "   ", None, 123):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_exchange(exchange_id=identifier)

    def test_empty_and_non_string_phase_ids_are_rejected(self):
        for identifier in ("", "   ", None, 123):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_exchange(phase_id=identifier)

    def test_identifier_lengths_are_bounded(self):
        for name in ("exchange_id", "phase_id", "redirect_from_exchange_id"):
            with self.subTest(name=name):
                self.assertEqual(getattr(make_exchange(**{name: "a" * 128}), name), "a" * 128)
                with self.assertRaises(ValueError):
                    make_exchange(**{name: "a" * 129})

    def test_identifiers_are_stripped(self):
        exchange = make_exchange(exchange_id=" exchange-1 ", phase_id=" phase-1 ", redirect_from_exchange_id=" predecessor ")
        self.assertEqual(exchange.exchange_id, "exchange-1")
        self.assertEqual(exchange.phase_id, "phase-1")
        self.assertEqual(exchange.redirect_from_exchange_id, "predecessor")

    def test_negative_start_sequence_is_rejected(self):
        with self.assertRaises(ValueError):
            make_exchange(start_sequence=-1)

    def test_bool_and_non_integer_start_sequence_are_rejected(self):
        for sequence in (True, False, 0.0, "0", None):
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                make_exchange(start_sequence=sequence)

    def test_self_redirect_is_rejected_after_normalization(self):
        with self.assertRaises(ValueError):
            make_exchange(redirect_from_exchange_id=" exchange-1 ")

    def test_empty_or_non_string_redirect_reference_is_rejected(self):
        for identifier in ("", "   ", 123):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_exchange(redirect_from_exchange_id=identifier)

    def test_unknown_redirect_reference_is_allowed_without_url_correlation(self):
        exchange = make_exchange(redirect_from_exchange_id="unseen-predecessor")
        self.assertEqual(exchange.redirect_from_exchange_id, "unseen-predecessor")

    def test_unknown_phase_reference_is_allowed(self):
        self.assertEqual(make_exchange(phase_id="unseen-phase").phase_id, "unseen-phase")

    def test_request_must_be_exactly_browser_request_evidence(self):
        class RequestSubclass(BrowserRequestEvidence):
            pass

        original = make_request()
        subclass = RequestSubclass(**{field.name: getattr(original, field.name) for field in fields(original)})
        for request in (None, {}, object(), subclass):
            with self.subTest(request_type=type(request).__name__), self.assertRaises(ValueError):
                make_exchange(request=request)

    def test_response_type_is_validated(self):
        for response in ({}, object(), make_request()):
            with self.subTest(response_type=type(response).__name__), self.assertRaises(ValueError):
                make_exchange(response=response)

    def test_send_state_and_completion_are_closed_enums(self):
        for name in ("send_state", "completion"):
            for value in ("invalid", None, []):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    make_exchange(**{name: value})

    def test_exchange_is_frozen_and_does_not_mutate_request(self):
        request = make_request()
        original = replace(request)
        exchange = make_exchange(request=request)
        with self.assertRaises(FrozenInstanceError):
            exchange.exchange_id = "another-id"
        self.assertIs(exchange.request, request)
        self.assertEqual(request, original)

    def test_only_structural_fields_and_no_sufficiency_logic(self):
        self.assertEqual(
            {field.name for field in fields(BrowserNetworkExchangeEvidence)},
            {"exchange_id", "request", "send_state", "response", "completion", "phase_id", "start_sequence", "redirect_from_exchange_id"},
        )
        for evidence in (make_response(), make_exchange()):
            for name in ("confidence", "research_status", "sufficient", "trusted", "trusted_provenance", "provenance_verified", "to_mapping"):
                with self.subTest(evidence_type=type(evidence).__name__, name=name):
                    self.assertFalse(hasattr(evidence, name))


if __name__ == "__main__":
    unittest.main()
