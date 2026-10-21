import unittest
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

from jarvis.core.browser_operation_contract import (
    BrowserOperationContract,
    BrowserOrigin,
    browser_origin_from_url,
    normalize_static_operation_path,
)


EXPECTED_PARAMETER_FIELDS = (
    "expected_query_parameter_names", "expected_body_parameter_names",
)
REQUIRED_PARAMETER_FIELDS = (
    "demonstrated_required_query_parameter_names",
    "demonstrated_required_body_parameter_names",
)
PARAMETER_FIELDS = EXPECTED_PARAMETER_FIELDS + REQUIRED_PARAMETER_FIELDS
COLLECTION_FIELDS = PARAMETER_FIELDS + (
    "acceptable_response_formats", "acceptable_http_statuses", "acceptable_deliveries",
)
OPTIONAL_FIELDS = EXPECTED_PARAMETER_FIELDS + (
    "acceptable_response_formats", "acceptable_http_statuses",
)
CONTRACT_FIELDS = (
    "contract_id", "http_method", "authorized_origin", "expected_path",
    "expected_query_parameter_names", "expected_body_parameter_names",
    "demonstrated_required_query_parameter_names",
    "demonstrated_required_body_parameter_names", "acceptable_response_formats",
    "acceptable_http_statuses", "acceptable_deliveries", "requires_response_content",
    "requires_functional_evidence",
)


def make_contract(**overrides):
    values = {
        "contract_id": "operation-1",
        "http_method": "GET",
        "authorized_origin": BrowserOrigin("https", "example.com", 443),
        "expected_path": "/",
        "expected_query_parameter_names": None,
        "expected_body_parameter_names": None,
        "demonstrated_required_query_parameter_names": frozenset(),
        "demonstrated_required_body_parameter_names": frozenset(),
        "acceptable_response_formats": None,
        "acceptable_http_statuses": None,
        "acceptable_deliveries": frozenset({"network"}),
        "requires_response_content": False,
        "requires_functional_evidence": False,
    }
    values.update(overrides)
    return BrowserOperationContract(**values)


class BrowserOriginTests(unittest.TestCase):
    def test_https_default_port(self):
        self.assertEqual(
            browser_origin_from_url("https://example.com"),
            BrowserOrigin("https", "example.com", 443),
        )

    def test_http_default_port(self):
        self.assertEqual(
            browser_origin_from_url("http://example.com"),
            BrowserOrigin("http", "example.com", 80),
        )

    def test_explicit_ports_are_preserved(self):
        for scheme, port in (("https", 8443), ("http", 8080), ("https", 80), ("http", 443)):
            with self.subTest(scheme=scheme, port=port):
                self.assertEqual(
                    browser_origin_from_url(f"{scheme}://example.com:{port}/api").effective_port,
                    port,
                )

    def test_url_hostname_is_canonicalized_to_lowercase(self):
        origin = browser_origin_from_url("https://API.Example.COM/status")
        self.assertEqual(origin.hostname, "api.example.com")

    def test_url_scheme_is_canonicalized_to_lowercase(self):
        self.assertEqual(browser_origin_from_url("HTTPS://example.com").scheme, "https")

    def test_direct_hostname_must_already_be_lowercase(self):
        for hostname in ("Example.com", "EXAMPLE.COM", "XN--BCHER-KVA.example"):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                BrowserOrigin("https", hostname, 443)

    def test_credentials_are_rejected(self):
        for authority in (
            "user:password@example.com", "user@example.com", ":password@example.com",
            "@example.com", "user%40name:password@example.com",
        ):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                browser_origin_from_url(f"https://{authority}/")

    def test_non_http_schemes_are_rejected(self):
        for url in ("ftp://example.com/", "file:///tmp/data", "javascript:alert(1)", "ws://example.com/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                browser_origin_from_url(url)

    def test_direct_scheme_is_closed_and_canonical(self):
        for scheme in ("HTTPS", "Http", "ftp", "", " https ", None, 1, []):
            with self.subTest(scheme=scheme), self.assertRaises(ValueError):
                BrowserOrigin(scheme, "example.com", 443)

    def test_relative_urls_are_rejected(self):
        for url in ("/api/status", "//example.com/api", "example.com/api", "?q=1", "#fragment", ""):
            with self.subTest(url=url), self.assertRaises(ValueError):
                browser_origin_from_url(url)

    def test_missing_or_malformed_authorities_are_rejected(self):
        for url in (
            "https:///api", "https:/example.com", "https:example.com", "https://",
            "https://:443/", "https://[example.com]/", "https://[::1", "https:////example.com",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                browser_origin_from_url(url)

    def test_ipv4_literals_are_rejected_directly_and_from_urls(self):
        for hostname in ("127.0.0.1", "192.168.1.1", "0.0.0.0", "255.255.255.255"):
            with self.subTest(hostname=hostname):
                with self.assertRaises(ValueError):
                    BrowserOrigin("https", hostname, 443)
                with self.assertRaises(ValueError):
                    browser_origin_from_url(f"https://{hostname}/")

    def test_ambiguous_numeric_hosts_are_rejected(self):
        for hostname in ("127.1", "2130706433", "0177.0.0.1", "0x7f000001", "example.123"):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                browser_origin_from_url(f"https://{hostname}/")

    def test_ipv6_literals_are_rejected_directly_and_from_urls(self):
        for hostname in ("::1", "2001:db8::1", "::ffff:192.0.2.1", "fe80::1%eth0"):
            with self.subTest(hostname=hostname):
                with self.assertRaises(ValueError):
                    BrowserOrigin("https", hostname, 443)
                with self.assertRaises(ValueError):
                    browser_origin_from_url(f"https://[{hostname}]/")

    def test_trailing_dot_is_rejected(self):
        with self.assertRaises(ValueError):
            BrowserOrigin("https", "example.com.", 443)
        with self.assertRaises(ValueError):
            browser_origin_from_url("https://example.com./")

    def test_wildcards_are_rejected(self):
        for hostname in ("*.example.com", "exa*mple.com", "*"):
            with self.subTest(hostname=hostname):
                with self.assertRaises(ValueError):
                    BrowserOrigin("https", hostname, 443)
                with self.assertRaises(ValueError):
                    browser_origin_from_url(f"https://{hostname}/")

    def test_empty_hostname_or_labels_are_rejected(self):
        for hostname in ("", ".", ".example.com", "example..com", "example.com.."):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                BrowserOrigin("https", hostname, 443)
        for hostname in (".example.com", "example..com"):
            with self.subTest(url_hostname=hostname), self.assertRaises(ValueError):
                browser_origin_from_url(f"https://{hostname}/")

    def test_hostname_rejects_delimiters_and_non_dns_structure(self):
        for hostname in (
            "example.com:443", "https://example.com", "user@example.com", "example.com/api",
            "example.com?x=1", "example.com#x", "example_com", "-example.com", "example-.com",
            "example.com;other", "example%2ecom", "example\\com",
        ):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                BrowserOrigin("https", hostname, 443)

    def test_hostname_rejects_whitespace_and_controls(self):
        for character in (" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f"):
            hostname = f"exa{character}mple.com"
            with self.subTest(character=repr(character)):
                with self.assertRaises(ValueError):
                    BrowserOrigin("https", hostname, 443)
                with self.assertRaises(ValueError):
                    browser_origin_from_url(f"https://{hostname}/")

    def test_unicode_hostnames_are_rejected_without_idna_conversion(self):
        for hostname in ("bücher.example", "ejemplo.рф", "ｅxample.com", "example。com"):
            with self.subTest(hostname=hostname):
                with self.assertRaises(ValueError):
                    BrowserOrigin("https", hostname, 443)
                with self.assertRaises(ValueError):
                    browser_origin_from_url(f"https://{hostname}/")

    def test_structurally_valid_ascii_punycode_labels_are_accepted(self):
        hostname = "xn--bcher-kva.example"
        self.assertEqual(BrowserOrigin("https", hostname, 443).hostname, hostname)
        self.assertEqual(browser_origin_from_url(f"https://{hostname}/").hostname, hostname)
        with self.assertRaises(ValueError):
            BrowserOrigin("https", "xn--.example", 443)

    def test_valid_dns_labels_include_digits_and_internal_hyphens(self):
        for hostname in ("localhost", "api-2.example.com", "123.example", "a.b", "a"):
            with self.subTest(hostname=hostname):
                self.assertEqual(BrowserOrigin("http", hostname, 8080).hostname, hostname)

    def test_dns_label_length_boundaries(self):
        self.assertEqual(BrowserOrigin("https", "a" * 63 + ".example", 443).hostname, "a" * 63 + ".example")
        with self.assertRaises(ValueError):
            BrowserOrigin("https", "a" * 64 + ".example", 443)

    def test_dns_hostname_length_boundaries(self):
        hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        self.assertEqual(len(hostname), 253)
        self.assertEqual(BrowserOrigin("https", hostname, 443).hostname, hostname)
        with self.assertRaises(ValueError):
            BrowserOrigin("https", hostname + "d", 443)

    def test_hostname_requires_a_string(self):
        for hostname in (None, 123, b"example.com", [], True):
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                BrowserOrigin("https", hostname, 443)

    def test_url_requires_a_string(self):
        for url in (None, 123, b"https://example.com", [], True):
            with self.subTest(url=url), self.assertRaises(ValueError):
                browser_origin_from_url(url)

    def test_invalid_url_ports_are_rejected(self):
        for port in ("0", "65536", "-1", "abc", "1.5", "", "+443", "0xff", "True"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                browser_origin_from_url(f"https://example.com:{port}/")

    def test_invalid_direct_ports_are_rejected(self):
        for port in (0, -1, 65536, 443.0, "443", None, []):
            with self.subTest(port=port), self.assertRaises(ValueError):
                BrowserOrigin("https", "example.com", port)

    def test_bool_is_rejected_as_a_port(self):
        for port in (True, False):
            with self.subTest(port=port), self.assertRaises(ValueError):
                BrowserOrigin("https", "example.com", port)

    def test_integer_subclasses_are_rejected_as_ports(self):
        class IntegerSubclass(int):
            pass

        with self.assertRaises(ValueError):
            BrowserOrigin("https", "example.com", IntegerSubclass(443))

    def test_port_boundaries_and_leading_zero_url_port(self):
        for port in (1, 65535):
            with self.subTest(port=port):
                self.assertEqual(BrowserOrigin("https", "example.com", port).effective_port, port)
                self.assertEqual(browser_origin_from_url(f"https://example.com:{port}/").effective_port, port)
        self.assertEqual(browser_origin_from_url("https://example.com:00443/").effective_port, 443)

    def test_to_string_always_includes_the_effective_port(self):
        for url, rendered in (
            ("https://example.com", "https://example.com:443"),
            ("http://example.com", "http://example.com:80"),
            ("https://example.com:8443", "https://example.com:8443"),
        ):
            with self.subTest(url=url):
                origin = browser_origin_from_url(url)
                self.assertEqual(origin.to_string(), rendered)
                self.assertEqual(browser_origin_from_url(rendered), origin)

    def test_path_query_and_fragment_do_not_affect_the_origin(self):
        expected = BrowserOrigin("https", "example.com", 443)
        for suffix in ("", "/", "/api/v1", "/a%2Fb?q=VALUE#FRAGMENT", "/ruta/á?x=ñ#sección"):
            with self.subTest(suffix=suffix):
                origin = browser_origin_from_url("https://example.com" + suffix)
                self.assertEqual(origin, expected)
                self.assertNotIn("VALUE", repr(origin))
                self.assertNotIn("FRAGMENT", repr(origin))

    def test_url_parser_cannot_silently_strip_controls_or_whitespace(self):
        for url in (
            " https://example.com", "\x00https://example.com", "https://exa\tmple.com",
            "https://example.com/\napi", "https://example.com/api ", "https://example.com/\x7f",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                browser_origin_from_url(url)

    def test_url_backslashes_and_encoded_authorities_are_rejected(self):
        for url in (
            "https://example.com\\other.example/", "https://example.com/\\api",
            "https://example%2ecom/", "https://example.com%3a443/",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                browser_origin_from_url(url)

    def test_invalid_url_errors_do_not_echo_secret_values(self):
        url = "https://user:DUMMY_PASSWORD@example.com/?token=DUMMY_TOKEN#DUMMY_FRAGMENT"
        with self.assertRaises(ValueError) as raised:
            browser_origin_from_url(url)
        for marker in ("DUMMY_PASSWORD", "DUMMY_TOKEN", "DUMMY_FRAGMENT"):
            self.assertNotIn(marker, str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_origin_construction_does_not_resolve_dns(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")) as lookup:
            self.assertEqual(
                browser_origin_from_url("https://does-not-exist.invalid/").hostname,
                "does-not-exist.invalid",
            )
            lookup.assert_not_called()

    def test_origin_is_frozen_and_has_slots(self):
        origin = BrowserOrigin("https", "example.com", 443)
        for field_name, value in (("scheme", "http"), ("hostname", "other.example"), ("effective_port", 80)):
            with self.subTest(field_name=field_name), self.assertRaises(FrozenInstanceError):
                setattr(origin, field_name, value)
        with self.assertRaises(FrozenInstanceError):
            del origin.hostname
        self.assertFalse(hasattr(origin, "__dict__"))

    def test_origin_has_exactly_the_requested_fields(self):
        expected = ("scheme", "hostname", "effective_port")
        self.assertEqual(tuple(field.name for field in fields(BrowserOrigin)), expected)
        self.assertEqual(BrowserOrigin.__slots__, expected)


class StaticOperationPathTests(unittest.TestCase):
    def test_root_path_is_valid(self):
        self.assertEqual(normalize_static_operation_path("/"), "/")

    def test_normal_static_path_is_valid(self):
        self.assertEqual(normalize_static_operation_path("/api/v1/status"), "/api/v1/status")

    def test_trailing_slash_is_preserved_and_significant(self):
        self.assertEqual(normalize_static_operation_path("/api/status/"), "/api/status/")
        self.assertNotEqual(normalize_static_operation_path("/api/status/"), normalize_static_operation_path("/api/status"))

    def test_case_is_preserved(self):
        self.assertEqual(normalize_static_operation_path("/API/Status"), "/API/Status")
        self.assertNotEqual(normalize_static_operation_path("/API/Status"), normalize_static_operation_path("/api/status"))

    def test_dots_inside_normal_segments_are_allowed(self):
        for path in ("/api/v1.0/status", "/.hidden", "/status.json", "/...", "/a..b", "/..name"):
            with self.subTest(path=path):
                self.assertEqual(normalize_static_operation_path(path), path)

    def test_whole_dot_segments_are_rejected(self):
        for path in ("/.", "/./", "/api/./status", "/api/."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_whole_dot_dot_segments_are_rejected(self):
        for path in ("/..", "/../", "/api/../status", "/api/.."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_query_is_rejected(self):
        for path in ("/api?x=1", "/api?", "/?x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_fragment_is_rejected(self):
        for path in ("/api#section", "/api#", "/#x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_percent_encoding_is_rejected(self):
        for path in ("/api%2Fstatus", "/%2e", "/%2E%2e", "/%41", "/%", "/%252f"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_backslashes_are_rejected(self):
        for path in ("/api\\status", "\\api", "/\\", "/api\\..\\status"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_consecutive_slashes_are_rejected(self):
        for path in ("//", "//api", "/api//status", "/api//", "/api///status"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_whitespace_and_all_ascii_controls_are_rejected(self):
        for character in tuple(chr(value) for value in range(33)) + ("\x7f",):
            with self.subTest(character=repr(character)), self.assertRaises(ValueError):
                normalize_static_operation_path(f"/api{character}status")
        for path in (" /api", "/api ", "/api\n"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_non_ascii_characters_are_rejected(self):
        for character in ("á", "ñ", "α", " ", "​", "／", chr(0x1F600)):
            with self.subTest(character=character), self.assertRaises(ValueError):
                normalize_static_operation_path("/api/" + character)

    def test_delimiters_outside_the_v1_subset_are_rejected(self):
        for character in ":@;=+,$&!()*'\"[]{}<>|^`":
            with self.subTest(character=character), self.assertRaises(ValueError):
                normalize_static_operation_path(f"/api{character}status")

    def test_missing_initial_slash_is_rejected(self):
        for path in ("", "api/status", ".", "..", "https://example.com/api"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_path_requires_a_string(self):
        for path in (None, 1, b"/api", [], True):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalize_static_operation_path(path)

    def test_all_unreserved_ascii_characters_are_accepted_inside_segments(self):
        segment = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        self.assertEqual(normalize_static_operation_path("/" + segment + "/"), "/" + segment + "/")

    def test_validation_is_idempotent(self):
        for path in ("/", "/API/v1.0/~status_2-OK/"):
            with self.subTest(path=path):
                self.assertEqual(normalize_static_operation_path(normalize_static_operation_path(path)), path)


class BrowserOperationContractTests(unittest.TestCase):
    def test_minimal_valid_contract(self):
        contract = make_contract()
        self.assertEqual(contract.contract_id, "operation-1")
        self.assertEqual(contract.http_method, "GET")
        self.assertEqual(contract.authorized_origin, BrowserOrigin("https", "example.com", 443))
        self.assertEqual(contract.expected_path, "/")
        self.assertEqual(contract.acceptable_deliveries, frozenset({"network"}))
        self.assertFalse(contract.requires_response_content)
        self.assertFalse(contract.requires_functional_evidence)

    def test_empty_long_or_non_string_contract_id_is_rejected(self):
        for identifier in ("", "   ", "\t\n", "a" * 129, None, 1, b"operation-1", []):
            with self.subTest(identifier=identifier), self.assertRaises(ValueError):
                make_contract(contract_id=identifier)

    def test_contract_id_is_stripped_and_maximum_length_is_valid(self):
        self.assertEqual(make_contract(contract_id=" \t operation-1 \n").contract_id, "operation-1")
        self.assertEqual(make_contract(contract_id=" " + "a" * 128 + " ").contract_id, "a" * 128)

    def test_all_canonical_http_methods_are_valid(self):
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                self.assertEqual(make_contract(http_method=method).http_method, method)

    def test_invalid_lowercase_or_noncanonical_methods_are_rejected(self):
        for method in ("get", "post", "Get", " GET ", "CONNECT", "TRACE", "", None, 1, []):
            with self.subTest(method=method), self.assertRaises(ValueError):
                make_contract(http_method=method)

    def test_authorized_origin_requires_the_record_type(self):
        for origin in (None, "https://example.com:443", {"hostname": "example.com"}, object(), 1):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_contract(authorized_origin=origin)

    def test_authorized_origin_subclasses_are_rejected(self):
        class OriginSubclass(BrowserOrigin):
            pass

        with self.assertRaises(ValueError):
            make_contract(authorized_origin=OriginSubclass("https", "example.com", 443))

    def test_authorized_origin_with_nondefault_port_is_preserved(self):
        origin = BrowserOrigin("http", "api.example.com", 8443)
        self.assertIs(make_contract(authorized_origin=origin).authorized_origin, origin)

    def test_expected_path_is_validated_on_direct_construction(self):
        for path in (
            "api", "", "/api?x=1", "/api#x", "/%2f", "/api\\status", "/api//status",
            "/api/./status", "/api/../status", "/api:status", "/api status", "/á", None, [],
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                make_contract(expected_path=path)

    def test_expected_path_preserves_case_dots_and_trailing_slash(self):
        path = "/API/v1.0/Status/"
        self.assertEqual(make_contract(expected_path=path).expected_path, path)
        self.assertNotEqual(make_contract(expected_path=path), make_contract(expected_path=path[:-1]))

    def test_collections_require_exact_frozensets(self):
        for field_name in COLLECTION_FIELDS:
            item = {
                "acceptable_response_formats": "json", "acceptable_http_statuses": 200,
                "acceptable_deliveries": "network",
            }.get(field_name, "q")
            for value in ([], set(), (), {}, "name", 1, [item], {item}, (item,)):
                with self.subTest(field_name=field_name, value=value):
                    with self.assertRaisesRegex(ValueError, "must be exactly frozenset"):
                        make_contract(**{field_name: value})

    def test_frozenset_subclasses_are_rejected(self):
        class FrozenSetSubclass(frozenset):
            pass

        for field_name in COLLECTION_FIELDS:
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, "must be exactly frozenset"):
                    make_contract(**{field_name: FrozenSetSubclass()})

    def test_none_is_preserved_for_all_optional_constraints(self):
        contract = make_contract()
        for field_name in OPTIONAL_FIELDS:
            with self.subTest(field_name=field_name):
                self.assertIsNone(getattr(contract, field_name))

    def test_required_names_and_deliveries_cannot_be_none(self):
        for field_name in REQUIRED_PARAMETER_FIELDS + ("acceptable_deliveries",):
            with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                make_contract(**{field_name: None})

    def test_empty_expected_parameter_sets_are_distinct_from_unknown(self):
        contract = make_contract(**{field_name: frozenset() for field_name in EXPECTED_PARAMETER_FIELDS})
        for field_name in EXPECTED_PARAMETER_FIELDS:
            with self.subTest(field_name=field_name):
                self.assertEqual(getattr(contract, field_name), frozenset())
                self.assertIsNotNone(getattr(contract, field_name))
        self.assertNotEqual(contract, make_contract())

    def test_empty_expected_parameter_sets_cannot_have_required_names(self):
        for expected_field, required_field in zip(EXPECTED_PARAMETER_FIELDS, REQUIRED_PARAMETER_FIELDS):
            with self.subTest(location=expected_field), self.assertRaises(ValueError):
                make_contract(**{expected_field: frozenset(), required_field: frozenset({"q"})})

    def test_all_valid_parameter_name_characters_are_accepted(self):
        names = frozenset({"q", "_", "A", "Query_2", "body-name", "_A0-b_c"})
        for expected_field, required_field in zip(EXPECTED_PARAMETER_FIELDS, REQUIRED_PARAMETER_FIELDS):
            with self.subTest(location=expected_field):
                contract = make_contract(**{expected_field: names, required_field: names})
                self.assertEqual(getattr(contract, expected_field), names)
                self.assertEqual(getattr(contract, required_field), names)

    def test_invalid_parameter_names_are_rejected_in_every_location(self):
        for field_name in PARAMETER_FIELDS:
            for name in (
                "", "1name", "-name", "name.value", "name/value", "name:value", "name=value",
                "name[]", " name", "name ", "name\n", "na me", "name%20", "name+value", "ñame",
                "naïve", "*", None, 1, True, b"name",
            ):
                with self.subTest(field_name=field_name, name=name):
                    with self.assertRaisesRegex(ValueError, f"{field_name} must contain V1 ASCII parameter names"):
                        make_contract(**{field_name: frozenset({name})})

    def test_more_than_64_parameter_names_are_rejected(self):
        names = frozenset(f"parameter_{number}" for number in range(65))
        for field_name in PARAMETER_FIELDS:
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, f"{field_name} must contain at most 64 names"):
                    make_contract(**{field_name: names})

    def test_exactly_64_parameter_names_per_location_are_valid(self):
        query_names = frozenset(f"query_{number}" for number in range(64))
        body_names = frozenset(f"body_{number}" for number in range(64))
        contract = make_contract(
            expected_query_parameter_names=query_names,
            expected_body_parameter_names=body_names,
            demonstrated_required_query_parameter_names=query_names,
            demonstrated_required_body_parameter_names=body_names,
        )
        self.assertEqual(len(contract.expected_query_parameter_names), 64)
        self.assertEqual(len(contract.expected_body_parameter_names), 64)

    def test_parameter_names_longer_than_64_characters_are_rejected(self):
        for field_name in PARAMETER_FIELDS:
            with self.subTest(field_name=field_name):
                with self.assertRaisesRegex(ValueError, f"{field_name} must contain V1 ASCII parameter names"):
                    make_contract(**{field_name: frozenset({"a" * 65})})

    def test_parameter_names_of_exactly_64_characters_are_valid(self):
        names = frozenset({"a" * 64})
        contract = make_contract(**{field_name: names for field_name in PARAMETER_FIELDS})
        for field_name in PARAMETER_FIELDS:
            self.assertEqual(getattr(contract, field_name), names)

    def test_required_parameter_subset_is_valid_in_each_location(self):
        for expected_field, required_field in zip(EXPECTED_PARAMETER_FIELDS, REQUIRED_PARAMETER_FIELDS):
            with self.subTest(location=expected_field):
                contract = make_contract(**{
                    expected_field: frozenset({"q", "optional"}),
                    required_field: frozenset({"q"}),
                })
                self.assertEqual(getattr(contract, required_field), frozenset({"q"}))

    def test_required_parameters_outside_expected_are_rejected(self):
        for expected_field, required_field in zip(EXPECTED_PARAMETER_FIELDS, REQUIRED_PARAMETER_FIELDS):
            with self.subTest(location=expected_field), self.assertRaises(ValueError):
                make_contract(**{expected_field: frozenset({"q"}), required_field: frozenset({"other"})})

    def test_nonempty_required_parameters_with_unknown_expected_are_rejected(self):
        for required_field in REQUIRED_PARAMETER_FIELDS:
            with self.subTest(field_name=required_field), self.assertRaises(ValueError):
                make_contract(**{required_field: frozenset({"q"})})

    def test_query_and_body_constraints_are_independent(self):
        contract = make_contract(
            expected_query_parameter_names=frozenset({"q"}),
            demonstrated_required_query_parameter_names=frozenset({"q"}),
            expected_body_parameter_names=None,
        )
        self.assertIsNone(contract.expected_body_parameter_names)
        self.assertEqual(contract.demonstrated_required_body_parameter_names, frozenset())
        with self.assertRaises(ValueError):
            replace(contract, demonstrated_required_body_parameter_names=frozenset({"q"}))

    def test_expected_names_do_not_automatically_become_required(self):
        names = frozenset({"q", "optional"})
        contract = make_contract(expected_query_parameter_names=names, expected_body_parameter_names=names)
        for field_name in REQUIRED_PARAMETER_FIELDS:
            self.assertEqual(getattr(contract, field_name), frozenset())

    def test_all_allowed_response_formats_are_valid(self):
        formats = frozenset({"json", "html", "xml", "text", "binary"})
        self.assertEqual(make_contract(acceptable_response_formats=formats).acceptable_response_formats, formats)
        for response_format in formats:
            with self.subTest(response_format=response_format):
                self.assertEqual(
                    make_contract(acceptable_response_formats=frozenset({response_format})).acceptable_response_formats,
                    frozenset({response_format}),
                )

    def test_unknown_and_invalid_response_formats_are_rejected(self):
        for response_format in ("unknown", "JSON", "application/json", " json ", "", None, 1, True):
            with self.subTest(response_format=response_format), self.assertRaises(ValueError):
                make_contract(acceptable_response_formats=frozenset({"json", response_format}))

    def test_empty_response_formats_are_rejected(self):
        with self.assertRaises(ValueError):
            make_contract(acceptable_response_formats=frozenset())

    def test_http_statuses_include_both_boundaries(self):
        statuses = frozenset({100, 200, 204, 302, 400, 500, 599})
        self.assertEqual(make_contract(acceptable_http_statuses=statuses).acceptable_http_statuses, statuses)

    def test_bool_http_statuses_are_rejected(self):
        for value in (True, False):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_contract(acceptable_http_statuses=frozenset({200, value}))

    def test_out_of_range_http_statuses_are_rejected(self):
        for value in (-1, 0, 99, 600, 1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_contract(acceptable_http_statuses=frozenset({200, value}))

    def test_non_integer_http_statuses_are_rejected(self):
        for value in (200.0, "200", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_contract(acceptable_http_statuses=frozenset({value}))

    def test_integer_subclasses_are_rejected_as_http_statuses(self):
        class IntegerSubclass(int):
            pass

        with self.assertRaises(ValueError):
            make_contract(acceptable_http_statuses=frozenset({IntegerSubclass(200)}))

    def test_empty_http_statuses_are_rejected(self):
        with self.assertRaises(ValueError):
            make_contract(acceptable_http_statuses=frozenset())

    def test_all_allowed_deliveries_are_valid(self):
        deliveries = frozenset({"network", "cache", "service_worker"})
        self.assertEqual(make_contract(acceptable_deliveries=deliveries).acceptable_deliveries, deliveries)
        for delivery in deliveries:
            with self.subTest(delivery=delivery):
                self.assertEqual(make_contract(acceptable_deliveries=frozenset({delivery})).acceptable_deliveries, frozenset({delivery}))

    def test_unknown_and_invalid_deliveries_are_rejected(self):
        for delivery in ("unknown", "NETWORK", "service-worker", " network ", "", None, 1, True):
            with self.subTest(delivery=delivery), self.assertRaises(ValueError):
                make_contract(acceptable_deliveries=frozenset({"network", delivery}))

    def test_empty_deliveries_are_rejected(self):
        with self.assertRaises(ValueError):
            make_contract(acceptable_deliveries=frozenset())

    def test_both_flags_require_exact_bool(self):
        for field_name in ("requires_response_content", "requires_functional_evidence"):
            for value in (0, 1, 0.0, 1.0, "true", "false", None, [], object()):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_contract(**{field_name: value})

    def test_both_flags_are_independent_in_all_combinations(self):
        for content in (False, True):
            for functional in (False, True):
                with self.subTest(content=content, functional=functional):
                    contract = make_contract(
                        requires_response_content=content,
                        requires_functional_evidence=functional,
                    )
                    self.assertIs(contract.requires_response_content, content)
                    self.assertIs(contract.requires_functional_evidence, functional)
                    for field_name in OPTIONAL_FIELDS:
                        self.assertIsNone(getattr(contract, field_name))
                    self.assertFalse(hasattr(contract, "sufficient"))

    def test_functional_requirement_does_not_add_fields_or_trust(self):
        contract = make_contract(requires_functional_evidence=True)
        self.assertEqual(tuple(field.name for field in fields(contract)), CONTRACT_FIELDS)
        for name in ("sufficient", "confidence", "research_status", "trusted", "verified"):
            self.assertFalse(hasattr(contract, name))

    def test_contract_is_frozen_and_has_slots(self):
        contract = make_contract()
        replacements = {
            "contract_id": "operation-2", "http_method": "POST",
            "authorized_origin": BrowserOrigin("http", "other.example", 8080),
            "expected_path": "/other", "expected_query_parameter_names": frozenset(),
            "expected_body_parameter_names": frozenset(),
            "demonstrated_required_query_parameter_names": frozenset({"q"}),
            "demonstrated_required_body_parameter_names": frozenset({"body"}),
            "acceptable_response_formats": frozenset({"json"}),
            "acceptable_http_statuses": frozenset({200}),
            "acceptable_deliveries": frozenset({"cache"}),
            "requires_response_content": True, "requires_functional_evidence": True,
        }
        for field_name, value in replacements.items():
            with self.subTest(field_name=field_name), self.assertRaises(FrozenInstanceError):
                setattr(contract, field_name, value)
        with self.assertRaises(FrozenInstanceError):
            del contract.contract_id
        self.assertFalse(hasattr(contract, "__dict__"))
        self.assertEqual(BrowserOperationContract.__slots__, CONTRACT_FIELDS)

    def test_contract_has_exactly_the_requested_fields(self):
        self.assertEqual(tuple(field.name for field in fields(BrowserOperationContract)), CONTRACT_FIELDS)

    def test_records_do_not_expose_provenance_or_sufficiency(self):
        for record in (make_contract(), BrowserOrigin("https", "example.com", 443)):
            for name in ("trusted", "verified", "provenance_verified", "confidence", "sufficient", "research_status"):
                with self.subTest(record_type=type(record).__name__, name=name):
                    self.assertFalse(hasattr(record, name))

    def test_records_do_not_expose_sensitive_values_code_or_callbacks(self):
        forbidden = (
            "query_parameter_values", "body_parameter_values", "parameter_values", "body", "bodies",
            "response_content", "headers", "cookies", "Authorization", "authorization", "password",
            "code", "script", "regex", "callback", "callbacks", "collector", "provider", "evaluate",
        )
        for record in (make_contract(), BrowserOrigin("https", "example.com", 443)):
            for name in forbidden:
                with self.subTest(record_type=type(record).__name__, name=name):
                    self.assertFalse(hasattr(record, name))

    def test_unrequested_sensitive_or_executable_fields_cannot_be_supplied(self):
        for field_name, value in (
            ("headers", {"Authorization": "DUMMY_SECRET"}), ("cookies", {"session": "DUMMY_SECRET"}),
            ("body", "DUMMY_BODY"), ("query_parameter_values", {"q": "DUMMY_VALUE"}),
            ("code", "print('example')"), ("regex", ".*"), ("callback", lambda: None),
            ("trusted", True), ("confidence", 1.0), ("sufficient", True), ("research_status", "sufficient"),
        ):
            with self.subTest(field_name=field_name), self.assertRaises(TypeError):
                make_contract(**{field_name: value})

    def test_existing_origin_and_collections_are_preserved(self):
        origin = BrowserOrigin("https", "example.com", 8443)
        names = frozenset({"q"})
        formats = frozenset({"json"})
        statuses = frozenset({200})
        deliveries = frozenset({"network"})
        contract = make_contract(
            authorized_origin=origin, acceptable_response_formats=formats,
            acceptable_http_statuses=statuses, acceptable_deliveries=deliveries,
            **{field_name: names for field_name in PARAMETER_FIELDS},
        )
        self.assertIs(contract.authorized_origin, origin)
        self.assertIs(contract.acceptable_response_formats, formats)
        self.assertIs(contract.acceptable_http_statuses, statuses)
        self.assertIs(contract.acceptable_deliveries, deliveries)
        for field_name in PARAMETER_FIELDS:
            self.assertIs(getattr(contract, field_name), names)

    def test_dataclass_replace_also_runs_validation(self):
        with self.assertRaises(ValueError):
            replace(make_contract(), http_method="get")
        with self.assertRaises(ValueError):
            replace(BrowserOrigin("https", "example.com", 443), effective_port=True)


if __name__ == "__main__":
    unittest.main()
