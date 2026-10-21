import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock, patch

from jarvis.core.browser_operation_contract import BrowserOperationContract, BrowserOrigin
from jarvis.core.browser_research_context import (
    BrowserAuthorizedInteraction,
    BrowserResearchEvaluationContext,
    BrowserResearchEvidenceLimits,
)


INTERACTION_FIELDS = ("interaction_id", "interaction_kind", "operation_contract_id")
EVIDENCE_LIMIT_FIELDS = (
    "max_phases", "max_attributions", "max_exported_endpoint_observations",
    "max_exported_evidence_items", "max_exported_utf8_bytes",
)
OPERATIONAL_MAXIMUM_FIELDS = (
    "max_duration_ms", "max_requests", "max_bytes", "max_redirects", "max_interactions",
)
CONTEXT_FIELDS = (
    "expected_session_id", "source_url", "capability_id", "capability_requirement",
    "allowed_navigation_origins", "allowed_endpoint_origins", "authorized_interactions",
    "operation_contracts", "allowed_deliveries", *OPERATIONAL_MAXIMUM_FIELDS, "evidence_limits",
)
STRUCTURAL_MAXIMUM = (1 << 63) - 1
FORBIDDEN_FIELDS = (
    "trusted", "verified", "provenance_verified", "confidence", "research_status",
    "sufficient", "capability_relevant", "cookies", "Authorization", "authorization",
    "headers", "body", "bodies", "parameter_values", "selector", "selectors", "text",
    "input_text", "input_values", "script", "code", "callback", "callbacks", "regex",
    "raw_error", "request", "interaction_result", "to_mapping", "to_prompt_context",
)


class IntegerSubclass(int):
    pass


class TupleSubclass(tuple):
    pass


class FrozenSetSubclass(frozenset):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class ContractSubclass(BrowserOperationContract):
    __slots__ = ()


class InteractionSubclass(BrowserAuthorizedInteraction):
    __slots__ = ()


class LimitsSubclass(BrowserResearchEvidenceLimits):
    __slots__ = ()


def record_values(record):
    return {field.name: getattr(record, field.name) for field in fields(record)}


def assert_frozen_slots(test_case, record):
    test_case.assertTrue(type(record).__dataclass_params__.frozen)
    test_case.assertFalse(hasattr(record, "__dict__"))
    for field in fields(record):
        with test_case.subTest(field_name=field.name):
            with test_case.assertRaises(FrozenInstanceError):
                setattr(record, field.name, getattr(record, field.name))
            with test_case.assertRaises(FrozenInstanceError):
                delattr(record, field.name)
    with test_case.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
        record.extra_attribute = "value"


def make_interaction(**overrides):
    values = {
        "interaction_id": "interaction-1",
        "interaction_kind": "submit",
        "operation_contract_id": "operation-1",
    }
    values.update(overrides)
    return BrowserAuthorizedInteraction(**values)


def make_limits(**overrides):
    values = {
        "max_phases": 8,
        "max_attributions": 16,
        "max_exported_endpoint_observations": 32,
        "max_exported_evidence_items": 64,
        "max_exported_utf8_bytes": 4096,
    }
    values.update(overrides)
    return BrowserResearchEvidenceLimits(**values)


def make_contract(**overrides):
    values = {
        "contract_id": "operation-1",
        "http_method": "GET",
        "authorized_origin": BrowserOrigin("https", "example.com", 443),
        "expected_path": "/api/status",
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


def make_context(**overrides):
    values = {
        "expected_session_id": "session-1",
        "source_url": "https://example.com/",
        "capability_id": "capability-1",
        "capability_requirement": "ACCESS_PROCEDURE",
        "allowed_navigation_origins": frozenset({BrowserOrigin("https", "example.com", 443)}),
        "allowed_endpoint_origins": frozenset(),
        "authorized_interactions": (),
        "operation_contracts": (),
        "allowed_deliveries": frozenset({"network"}),
        "max_duration_ms": 1000,
        "max_requests": 10,
        "max_bytes": 1024,
        "max_redirects": 5,
        "max_interactions": 5,
        "evidence_limits": make_limits(),
    }
    values.update(overrides)
    return BrowserResearchEvaluationContext(**values)


def make_authorized_context(**overrides):
    contract = make_contract()
    values = {
        "operation_contracts": (contract,),
        "authorized_interactions": (make_interaction(),),
        "allowed_endpoint_origins": frozenset({contract.authorized_origin}),
    }
    values.update(overrides)
    return make_context(**values)


class BrowserAuthorizedInteractionTests(unittest.TestCase):
    def test_submit_is_valid(self):
        self.assertEqual(make_interaction().interaction_kind, "submit")

    def test_click_is_valid(self):
        self.assertEqual(make_interaction(interaction_kind="click").interaction_kind, "click")

    def test_input_submit_is_valid(self):
        self.assertEqual(
            make_interaction(interaction_kind="input_submit").interaction_kind, "input_submit",
        )

    def test_navigation_is_valid(self):
        self.assertEqual(
            make_interaction(interaction_kind="navigation").interaction_kind, "navigation",
        )

    def test_other_is_rejected(self):
        with self.assertRaises(ValueError):
            make_interaction(interaction_kind="other")

    def test_interaction_kind_is_closed_and_not_normalized(self):
        for kind in ("Submit", "SUBMIT", "submit_other", " submit ", "input-submit", "", None, 1, [], {}):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_interaction(interaction_kind=kind)

    def test_ids_are_nonempty_strings_and_bounded_after_stripping(self):
        for field_name in ("interaction_id", "operation_contract_id"):
            for value in ("", " \t\n ", "a" * 129, None, 1, True, b"id", [], {}):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_interaction(**{field_name: value})
            with self.subTest(field_name=field_name):
                record = make_interaction(**{field_name: " " + "a" * 128 + " "})
                self.assertEqual(getattr(record, field_name), "a" * 128)

    def test_both_ids_are_stripped_without_restricting_the_alphabet(self):
        interaction = make_interaction(
            interaction_id="  interaccion / ñ: #1  ", operation_contract_id=" \tcontrato: / #2\n",
        )
        self.assertEqual(interaction.interaction_id, "interaccion / ñ: #1")
        self.assertEqual(interaction.operation_contract_id, "contrato: / #2")

    def test_standalone_contract_reference_does_not_require_a_registry(self):
        interaction = make_interaction(operation_contract_id="unregistered-contract")
        self.assertEqual(interaction.operation_contract_id, "unregistered-contract")

    def test_frozen_and_slots(self):
        assert_frozen_slots(self, make_interaction())

    def test_fields_are_exact(self):
        self.assertEqual(tuple(field.name for field in fields(BrowserAuthorizedInteraction)), INTERACTION_FIELDS)
        self.assertEqual(BrowserAuthorizedInteraction.__slots__, INTERACTION_FIELDS)

    def test_no_sensitive_trust_or_execution_fields(self):
        interaction = make_interaction()
        for field_name in FORBIDDEN_FIELDS + ("url", "URL", "executed"):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(interaction, field_name))


class BrowserResearchEvidenceLimitsTests(unittest.TestCase):
    def test_valid_limits_preserve_each_value(self):
        values = dict(zip(EVIDENCE_LIMIT_FIELDS, (2, 3, 4, 5, 6)))
        self.assertEqual(record_values(make_limits(**values)), values)

    def test_inclusive_integer_boundaries_for_every_field(self):
        for field_name in EVIDENCE_LIMIT_FIELDS:
            for value in (1, STRUCTURAL_MAXIMUM):
                with self.subTest(field_name=field_name, value=value):
                    self.assertEqual(getattr(make_limits(**{field_name: value}), field_name), value)

    def test_zero_negative_and_above_bound_rejected_for_every_field(self):
        for field_name in EVIDENCE_LIMIT_FIELDS:
            for value in (0, -1, STRUCTURAL_MAXIMUM + 1):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_limits(**{field_name: value})

    def test_bool_and_non_exact_integers_rejected_for_every_field(self):
        for field_name in EVIDENCE_LIMIT_FIELDS:
            for value in (True, False, 1.0, "1", None, [], {}, IntegerSubclass(1)):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_limits(**{field_name: value})

    def test_frozen_and_slots(self):
        assert_frozen_slots(self, make_limits())

    def test_fields_are_exact(self):
        self.assertEqual(tuple(field.name for field in fields(BrowserResearchEvidenceLimits)), EVIDENCE_LIMIT_FIELDS)
        self.assertEqual(BrowserResearchEvidenceLimits.__slots__, EVIDENCE_LIMIT_FIELDS)

    def test_no_sensitive_trust_or_export_behavior(self):
        limits = make_limits()
        for field_name in FORBIDDEN_FIELDS + ("truncate", "serialize", "evaluate"):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(limits, field_name))


class BrowserResearchEvaluationContextTests(unittest.TestCase):
    def test_minimal_context_without_contracts_or_interactions(self):
        context = make_context()
        self.assertEqual(context.expected_session_id, "session-1")
        self.assertEqual(context.capability_id, "capability-1")
        self.assertEqual(context.source_url, "https://example.com/")
        self.assertEqual(context.operation_contracts, ())
        self.assertEqual(context.authorized_interactions, ())
        self.assertEqual(context.allowed_endpoint_origins, frozenset())

    def test_context_with_contract_and_interaction(self):
        contract = make_contract()
        interaction = make_interaction()
        context = make_authorized_context(
            operation_contracts=(contract,), authorized_interactions=(interaction,),
        )
        self.assertIs(context.operation_contracts[0], contract)
        self.assertIs(context.authorized_interactions[0], interaction)

    def test_session_and_capability_ids_are_nonempty_strings_and_bounded(self):
        for field_name in ("expected_session_id", "capability_id"):
            for value in ("", " \t\n ", "a" * 129, None, 1, True, b"id", [], {}):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_context(**{field_name: value})
            context = make_context(**{field_name: " " + "a" * 128 + " "})
            self.assertEqual(getattr(context, field_name), "a" * 128)

    def test_ids_are_stripped_without_a_restrictive_alphabet(self):
        context = make_context(expected_session_id="  sesión / #1  ", capability_id="  capacidad: / ñ  ")
        self.assertEqual(context.expected_session_id, "sesión / #1")
        self.assertEqual(context.capability_id, "capacidad: / ñ")

    def test_all_four_capability_requirements_are_representable(self):
        for requirement in ("ACCESS_PROCEDURE", "HTTP_STATUS", "RESPONSE_METADATA", "FUNCTIONAL_RESULT"):
            with self.subTest(requirement=requirement):
                context = make_context(capability_requirement=requirement)
                self.assertEqual(context.capability_requirement, requirement)
                self.assertFalse(hasattr(context, "sufficient"))

    def test_functional_requirement_does_not_assess_contract_evidence(self):
        contract = make_contract(requires_response_content=True, requires_functional_evidence=True)
        context = make_authorized_context(
            operation_contracts=(contract,), capability_requirement="FUNCTIONAL_RESULT",
        )
        self.assertIs(context.operation_contracts[0], contract)
        self.assertEqual(context.capability_requirement, "FUNCTIONAL_RESULT")

    def test_capability_requirement_is_closed_and_not_normalized(self):
        for requirement in ("access_procedure", "HTTP_STATUS ", "FUNCTIONAL", "unknown", "", None, 1, [], {}):
            with self.subTest(requirement=requirement), self.assertRaises(ValueError):
                make_context(capability_requirement=requirement)

    def test_source_url_canonicalizes_scheme_and_hostname(self):
        context = make_context(source_url="HTTPS://ExAmPlE.COM/api")
        self.assertEqual(context.source_url, "https://example.com/api")

    def test_source_url_discards_query_and_fragment_without_retaining_secrets(self):
        context = make_context(source_url="https://example.com/api?token=DUMMY_SECRET#DUMMY_FRAGMENT")
        self.assertEqual(context.source_url, "https://example.com/api")
        for marker in ("DUMMY_SECRET", "DUMMY_FRAGMENT", "token="):
            self.assertNotIn(marker, repr(context))
            self.assertNotIn(marker, repr(record_values(context)))

    def test_empty_path_becomes_root(self):
        for source in ("https://Example.COM", "https://example.com?token=VALUE#fragment"):
            with self.subTest(source=source):
                self.assertEqual(make_context(source_url=source).source_url, "https://example.com/")

    def test_default_ports_are_omitted_for_both_schemes(self):
        for scheme, port in (("https", 443), ("http", 80)):
            for port_text in (str(port), "00" + str(port)):
                with self.subTest(scheme=scheme, port_text=port_text):
                    context = make_context(
                        source_url=f"{scheme}://Example.COM:{port_text}/api?token=VALUE#x",
                        allowed_navigation_origins=frozenset({BrowserOrigin(scheme, "example.com", port)}),
                    )
                    self.assertEqual(context.source_url, f"{scheme}://example.com/api")

    def test_nondefault_ports_are_preserved(self):
        for scheme, port in (("https", 8443), ("http", 8080), ("https", 80), ("http", 443), ("https", 65535)):
            with self.subTest(scheme=scheme, port=port):
                context = make_context(
                    source_url=f"{scheme.upper()}://Example.COM:{port}/api",
                    allowed_navigation_origins=frozenset({BrowserOrigin(scheme, "example.com", port)}),
                )
                self.assertEqual(context.source_url, f"{scheme}://example.com:{port}/api")

    def test_static_path_case_and_trailing_slash_are_preserved(self):
        context = make_context(source_url="https://example.com/API/v1.0/status/")
        self.assertEqual(context.source_url, "https://example.com/API/v1.0/status/")

    def test_sensitive_path_heuristics_are_not_applied(self):
        context = make_context(source_url="https://example.com/private/token/path?token=VALUE")
        self.assertEqual(context.source_url, "https://example.com/private/token/path")

    def test_credentials_are_rejected(self):
        for authority in ("user:password@example.com", "user@example.com", "@example.com", ":password@example.com"):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                make_context(source_url=f"https://{authority}/api")

    def test_relative_and_non_http_or_malformed_urls_are_rejected(self):
        for source in (
            "", "/api", "//example.com/api", "example.com/api", "?q=1", "#fragment",
            "ftp://example.com/api", "file:///api", "javascript:alert(1)",
            "https:///api", "https://", "https://[example.com]/",
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                make_context(source_url=source)

    def test_source_url_requires_a_string(self):
        for source in (None, 1, True, b"https://example.com", [], {}):
            with self.subTest(source=source), self.assertRaises(ValueError):
                make_context(source_url=source)

    def test_ip_literals_and_ambiguous_numeric_hosts_are_rejected(self):
        for host in ("127.0.0.1", "[::1]", "127.1", "2130706433", "0x7f000001", "example.123"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                make_context(source_url=f"https://{host}/api")

    def test_non_dns_hostnames_are_rejected(self):
        for host in ("*.example.com", "example.com.", "example..com", "example_com", "bücher.example", "example%2ecom"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                make_context(source_url=f"https://{host}/api")

    def test_nonstatic_v1_paths_are_rejected(self):
        for path in ("/api%2Fstatus", "/%2e", "/api//status", "/api/./status", "/api/../status", "/{id}", "/:id", "/api;status", "/café", "/[a-z]"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                make_context(source_url="https://example.com" + path)

    def test_whitespace_and_controls_are_rejected_before_query_discarding(self):
        characters = tuple(chr(value) for value in range(33)) + ("\x7f", "\x80", "\x9f", "\u00a0", "\u2003")
        for character in characters:
            with self.subTest(character=repr(character)), self.assertRaises(ValueError):
                make_context(source_url=f"https://example.com/api?token=a{character}b")
        for source in (" https://example.com/", "https://exa\tmple.com/", "https://example.com/\napi", "https://example.com/api "):
            with self.subTest(source=source), self.assertRaises(ValueError):
                make_context(source_url=source)

    def test_backslashes_are_rejected_everywhere_in_the_source_url(self):
        for source in (
            "https://example.com\\other.example/api", "https://example.com/api\\status",
            "https://example.com/api?token=a\\b", "https://example.com/api#x\\y",
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                make_context(source_url=source)

    def test_malformed_and_out_of_range_ports_are_rejected(self):
        for port in ("", "0", "65536", "-1", "abc", "+443", "443.0"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                make_context(source_url=f"https://example.com:{port}/")

    def test_rejected_url_errors_do_not_echo_secrets(self):
        for source in (
            "https://user:DUMMY_PASSWORD@example.com/api?token=DUMMY_SECRET#DUMMY_FRAGMENT",
            "https://example.com/api%2Fstatus?token=DUMMY_SECRET#DUMMY_FRAGMENT",
        ):
            with self.subTest(source=source):
                with self.assertRaises(ValueError) as raised:
                    make_context(source_url=source)
                for marker in ("DUMMY_PASSWORD", "DUMMY_SECRET", "DUMMY_FRAGMENT"):
                    self.assertNotIn(marker, str(raised.exception))
                self.assertIsNone(raised.exception.__cause__)

    def test_source_origin_requires_exact_navigation_allowlist_membership(self):
        for origin in (
            BrowserOrigin("https", "other.example", 443),
            BrowserOrigin("https", "api.example.com", 443),
            BrowserOrigin("https", "ample.com", 443),
            BrowserOrigin("http", "example.com", 80),
            BrowserOrigin("https", "example.com", 8443),
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_context(allowed_navigation_origins=frozenset({origin}))
        with self.assertRaises(ValueError):
            make_context(source_url="https://sub.example.com/api")

    def test_origin_collections_require_exact_frozensets(self):
        origin = BrowserOrigin("https", "example.com", 443)
        for field_name in ("allowed_navigation_origins", "allowed_endpoint_origins"):
            for collection in ([origin], {origin}, (origin,), {"origin": origin}, None, FrozenSetSubclass({origin})):
                with self.subTest(field_name=field_name, collection_type=type(collection).__name__), self.assertRaises(ValueError):
                    make_context(**{field_name: collection})

    def test_origin_collection_members_require_exact_browser_origins(self):
        subclass = OriginSubclass("https", "example.com", 443)
        for field_name in ("allowed_navigation_origins", "allowed_endpoint_origins"):
            for member in ("https://example.com", None, object(), subclass):
                with self.subTest(field_name=field_name, member_type=type(member).__name__), self.assertRaises(ValueError):
                    make_context(**{field_name: frozenset({member})})

    def test_empty_navigation_allowlist_is_rejected(self):
        with self.assertRaises(ValueError):
            make_context(allowed_navigation_origins=frozenset())

    def test_empty_endpoint_allowlist_is_allowed_without_contracts(self):
        self.assertEqual(make_context(allowed_endpoint_origins=frozenset()).allowed_endpoint_origins, frozenset())

    def test_empty_endpoint_allowlist_is_rejected_with_contracts(self):
        with self.assertRaises(ValueError):
            make_authorized_context(allowed_endpoint_origins=frozenset())

    def test_nonempty_endpoint_allowlist_is_allowed_without_contracts(self):
        origins = frozenset({BrowserOrigin("http", "api.other.example", 8080)})
        context = make_context(allowed_endpoint_origins=origins)
        self.assertIs(context.allowed_endpoint_origins, origins)

    def test_origin_collection_structural_boundaries(self):
        source_origin = BrowserOrigin("https", "example.com", 443)
        for field_name in ("allowed_navigation_origins", "allowed_endpoint_origins"):
            for count in (64, 65):
                origins = frozenset({source_origin} | {
                    BrowserOrigin("https", f"host-{index}.example", 443) for index in range(count - 1)
                })
                with self.subTest(field_name=field_name, count=count):
                    if count == 64:
                        self.assertEqual(len(getattr(make_context(**{field_name: origins}), field_name)), 64)
                    else:
                        with self.assertRaises(ValueError):
                            make_context(**{field_name: origins})

    def test_navigation_and_endpoint_origins_may_differ(self):
        endpoint = BrowserOrigin("http", "api.other.example", 8080)
        contract = make_contract(authorized_origin=endpoint)
        context = make_authorized_context(
            operation_contracts=(contract,), allowed_endpoint_origins=frozenset({endpoint}),
        )
        self.assertNotEqual(context.allowed_navigation_origins, context.allowed_endpoint_origins)
        self.assertIs(context.operation_contracts[0], contract)

    def test_contracts_require_an_exact_tuple(self):
        contract = make_contract()
        for collection in ([contract], {contract}, {"contract": contract}, frozenset({contract}), None, TupleSubclass((contract,))):
            with self.subTest(collection_type=type(collection).__name__), self.assertRaises(ValueError):
                make_authorized_context(operation_contracts=collection)

    def test_contract_members_require_exact_operation_contracts(self):
        subclass = ContractSubclass(**record_values(make_contract()))
        for member in (None, {}, "operation-1", object(), subclass):
            with self.subTest(member_type=type(member).__name__), self.assertRaises(ValueError):
                make_authorized_context(operation_contracts=(member,))

    def test_duplicate_normalized_contract_ids_are_rejected(self):
        contracts = (make_contract(), make_contract(contract_id=" operation-1 ", expected_path="/different"))
        with self.assertRaisesRegex(ValueError, "contract_id values must be unique"):
            make_authorized_context(operation_contracts=contracts)

    def test_contract_origin_requires_exact_endpoint_allowlist_membership(self):
        for origin in (
            BrowserOrigin("https", "other.example", 443),
            BrowserOrigin("https", "api.example.com", 443),
            BrowserOrigin("http", "example.com", 80),
            BrowserOrigin("https", "example.com", 8443),
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_authorized_context(operation_contracts=(make_contract(authorized_origin=origin),))

    def test_contract_deliveries_must_be_a_subset_of_allowed_deliveries(self):
        for deliveries in (frozenset({"cache"}), frozenset({"service_worker"}), frozenset({"network", "cache"})):
            with self.subTest(deliveries=deliveries), self.assertRaises(ValueError):
                make_authorized_context(operation_contracts=(make_contract(acceptable_deliveries=deliveries),))
        context = make_authorized_context(allowed_deliveries=frozenset({"network", "cache", "service_worker"}))
        self.assertEqual(context.operation_contracts[0].acceptable_deliveries, frozenset({"network"}))

    def test_contract_structural_boundaries(self):
        for count in (64, 65):
            contracts = tuple(make_contract(contract_id=f"operation-{index}") for index in range(count))
            with self.subTest(count=count):
                if count == 64:
                    context = make_authorized_context(operation_contracts=contracts)
                    self.assertIs(context.operation_contracts, contracts)
                    self.assertEqual(len(context.operation_contracts), 64)
                else:
                    with self.assertRaises(ValueError):
                        make_authorized_context(operation_contracts=contracts)

    def test_contracts_do_not_need_authorized_interactions(self):
        context = make_authorized_context(authorized_interactions=())
        self.assertEqual(context.authorized_interactions, ())
        self.assertEqual(len(context.operation_contracts), 1)

    def test_interactions_require_an_exact_tuple(self):
        interaction = make_interaction()
        for collection in ([interaction], {interaction}, {"interaction": interaction}, frozenset({interaction}), None, TupleSubclass((interaction,))):
            with self.subTest(collection_type=type(collection).__name__), self.assertRaises(ValueError):
                make_authorized_context(authorized_interactions=collection)

    def test_interaction_members_require_exact_authorized_interactions(self):
        subclass = InteractionSubclass(**record_values(make_interaction()))
        for member in (None, {}, "interaction-1", object(), subclass):
            with self.subTest(member_type=type(member).__name__), self.assertRaises(ValueError):
                make_authorized_context(authorized_interactions=(member,))

    def test_duplicate_normalized_interaction_ids_are_rejected(self):
        interactions = (make_interaction(), make_interaction(interaction_id=" interaction-1 ", interaction_kind="click"))
        with self.assertRaisesRegex(ValueError, "interaction_id values must be unique"):
            make_authorized_context(authorized_interactions=interactions)

    def test_duplicate_interaction_id_cannot_reference_two_contracts(self):
        contracts = (make_contract(), make_contract(contract_id="operation-2"))
        interactions = (make_interaction(), make_interaction(operation_contract_id="operation-2"))
        with self.assertRaisesRegex(ValueError, "interaction_id values must be unique"):
            make_authorized_context(operation_contracts=contracts, authorized_interactions=interactions)

    def test_interaction_reference_must_exist_exactly_in_the_context(self):
        for contract_id in ("operation-2", "Operation-1", "operation"):
            with self.subTest(contract_id=contract_id), self.assertRaises(ValueError):
                make_authorized_context(authorized_interactions=(make_interaction(operation_contract_id=contract_id),))
        with self.assertRaises(ValueError):
            make_context(authorized_interactions=(make_interaction(),))

    def test_multiple_distinct_interactions_can_reference_one_contract(self):
        interactions = tuple(make_interaction(interaction_id=f"interaction-{index}", interaction_kind=kind)
                             for index, kind in enumerate(("submit", "click", "input_submit", "navigation")))
        context = make_authorized_context(authorized_interactions=interactions)
        self.assertIs(context.authorized_interactions, interactions)
        self.assertEqual(len(context.operation_contracts), 1)

    def test_interaction_structural_boundaries(self):
        for count in (64, 65):
            interactions = tuple(make_interaction(interaction_id=f"interaction-{index}") for index in range(count))
            with self.subTest(count=count):
                if count == 64:
                    context = make_authorized_context(authorized_interactions=interactions)
                    self.assertIs(context.authorized_interactions, interactions)
                    self.assertEqual(len(context.authorized_interactions), 64)
                else:
                    with self.assertRaises(ValueError):
                        make_authorized_context(authorized_interactions=interactions)

    def test_record_order_is_preserved_and_contract_references_are_normalized(self):
        contracts = (make_contract(contract_id="operation-2"), make_contract())
        interactions = (
            make_interaction(interaction_id="interaction-2", operation_contract_id=" operation-2 "),
            make_interaction(operation_contract_id=" operation-1 "),
        )
        context = make_authorized_context(operation_contracts=contracts, authorized_interactions=interactions)
        self.assertIs(context.operation_contracts, contracts)
        self.assertIs(context.authorized_interactions, interactions)
        self.assertEqual(context.authorized_interactions[0].operation_contract_id, "operation-2")

    def test_allowed_deliveries_require_an_exact_frozenset(self):
        for collection in (["network"], {"network"}, ("network",), {"network": True}, None, FrozenSetSubclass({"network"})):
            with self.subTest(collection_type=type(collection).__name__), self.assertRaises(ValueError):
                make_context(allowed_deliveries=collection)

    def test_empty_allowed_deliveries_are_rejected(self):
        with self.assertRaises(ValueError):
            make_context(allowed_deliveries=frozenset())

    def test_unknown_and_invalid_deliveries_are_rejected(self):
        for delivery in ("unknown", "NETWORK", " network ", "disk", "", None, 1, True):
            with self.subTest(delivery=delivery), self.assertRaises(ValueError):
                make_context(allowed_deliveries=frozenset({delivery}))

    def test_network_cache_and_service_worker_are_accepted_without_network_only_policy(self):
        for delivery in ("network", "cache", "service_worker"):
            deliveries = frozenset({delivery})
            contract = make_contract(acceptable_deliveries=deliveries)
            with self.subTest(delivery=delivery):
                context = make_authorized_context(operation_contracts=(contract,), allowed_deliveries=deliveries)
                self.assertIs(context.allowed_deliveries, deliveries)
                self.assertIs(context.operation_contracts[0], contract)

    def test_operational_maxima_preserve_distinct_positive_values(self):
        values = dict(zip(OPERATIONAL_MAXIMUM_FIELDS, (2, 3, 4, 5, 6)))
        context = make_context(**values)
        for field_name, value in values.items():
            self.assertEqual(getattr(context, field_name), value)

    def test_operational_integer_boundaries_for_every_field(self):
        for field_name in OPERATIONAL_MAXIMUM_FIELDS:
            for value in (1, STRUCTURAL_MAXIMUM):
                with self.subTest(field_name=field_name, value=value):
                    self.assertEqual(getattr(make_context(**{field_name: value}), field_name), value)

    def test_operational_zero_negative_and_above_bound_rejected_for_every_field(self):
        for field_name in OPERATIONAL_MAXIMUM_FIELDS:
            for value in (0, -1, STRUCTURAL_MAXIMUM + 1):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_context(**{field_name: value})

    def test_operational_bool_and_non_exact_integers_rejected_for_every_field(self):
        for field_name in OPERATIONAL_MAXIMUM_FIELDS:
            for value in (True, False, 1.0, "1", None, [], {}, IntegerSubclass(1)):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_context(**{field_name: value})

    def test_evidence_limits_require_the_exact_record_type(self):
        limits = make_limits()
        self.assertIs(make_context(evidence_limits=limits).evidence_limits, limits)
        for value in (record_values(limits), None, [], (), object(), LimitsSubclass(**record_values(limits))):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                make_context(evidence_limits=value)

    def test_limits_do_not_truncate_or_compare_authorized_alternatives_to_execution_maxima(self):
        contracts = (make_contract(), make_contract(contract_id="operation-2"))
        interactions = (make_interaction(), make_interaction(interaction_id="interaction-2", operation_contract_id="operation-2"))
        limits = make_limits(**{field_name: 1 for field_name in EVIDENCE_LIMIT_FIELDS})
        context = make_authorized_context(
            operation_contracts=contracts, authorized_interactions=interactions,
            evidence_limits=limits, **{field_name: 1 for field_name in OPERATIONAL_MAXIMUM_FIELDS},
        )
        self.assertIs(context.operation_contracts, contracts)
        self.assertIs(context.authorized_interactions, interactions)
        self.assertIs(context.evidence_limits, limits)
        self.assertEqual(len(context.authorized_interactions), 2)

    def test_frozen_and_slots(self):
        assert_frozen_slots(self, make_authorized_context())

    def test_fields_are_exact(self):
        self.assertEqual(tuple(field.name for field in fields(BrowserResearchEvaluationContext)), CONTEXT_FIELDS)
        self.assertEqual(BrowserResearchEvaluationContext.__slots__, CONTEXT_FIELDS)

    def test_no_sensitive_trust_sufficiency_or_session_evidence_fields(self):
        context = make_context()
        for field_name in FORBIDDEN_FIELDS + ("session_evidence", "exchanges", "phases", "evaluate"):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(context, field_name))

    def test_callables_are_rejected_as_data_without_being_executed(self):
        callback = Mock(side_effect=AssertionError("callback executed"))
        for field_name in CONTEXT_FIELDS:
            with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                make_context(**{field_name: callback})
        callback.assert_not_called()

    def test_construction_performs_no_dns_network_or_filesystem_calls(self):
        targets = (
            "urllib.request.urlopen", "http.client.HTTPConnection.connect",
            "http.client.HTTPSConnection.connect", "socket.getaddrinfo",
            "socket.gethostbyname", "socket.gethostbyname_ex", "socket.create_connection",
            "socket.socket", "pathlib.Path.open", "builtins.open",
        )
        with ExitStack() as stack:
            blocked = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            origin = BrowserOrigin("https", "does-not-exist.invalid", 443)
            contract = make_contract(authorized_origin=origin)
            context = make_authorized_context(
                source_url="HTTPS://DOES-NOT-EXIST.INVALID/api?token=VALUE#fragment",
                allowed_navigation_origins=frozenset({origin}),
                allowed_endpoint_origins=frozenset({origin}), operation_contracts=(contract,),
            )
            self.assertEqual(context.source_url, "https://does-not-exist.invalid/api")
            for mocked in blocked:
                mocked.assert_not_called()

    def test_construction_preserves_existing_records_and_collections(self):
        origin = BrowserOrigin("https", "example.com", 443)
        contract = make_contract(authorized_origin=origin)
        interaction = make_interaction()
        limits = make_limits()
        navigation = frozenset({origin})
        endpoints = frozenset({origin})
        contracts = (contract,)
        interactions = (interaction,)
        deliveries = frozenset({"network"})
        originals = tuple(record_values(record) for record in (origin, contract, interaction, limits))
        context = make_context(
            expected_session_id=" session-1 ", source_url="https://Example.COM?token=VALUE#x",
            allowed_navigation_origins=navigation, allowed_endpoint_origins=endpoints,
            operation_contracts=contracts, authorized_interactions=interactions,
            allowed_deliveries=deliveries, evidence_limits=limits,
        )
        for field_name, original in (
            ("allowed_navigation_origins", navigation), ("allowed_endpoint_origins", endpoints),
            ("operation_contracts", contracts), ("authorized_interactions", interactions),
            ("allowed_deliveries", deliveries), ("evidence_limits", limits),
        ):
            self.assertIs(getattr(context, field_name), original)
        self.assertIs(context.operation_contracts[0], contract)
        self.assertIs(context.authorized_interactions[0], interaction)
        self.assertEqual(tuple(record_values(record) for record in (origin, contract, interaction, limits)), originals)
        with self.assertRaises(FrozenInstanceError):
            context.authorized_interactions[0].interaction_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            context.evidence_limits.max_phases = 1

    def test_invalid_construction_does_not_mutate_existing_records(self):
        context = make_authorized_context()
        before = record_values(context)
        contracts_before = record_values(context.operation_contracts[0])
        interactions_before = record_values(context.authorized_interactions[0])
        with self.assertRaises(ValueError):
            replace(context, allowed_endpoint_origins=frozenset())
        self.assertEqual(record_values(context), before)
        self.assertEqual(record_values(context.operation_contracts[0]), contracts_before)
        self.assertEqual(record_values(context.authorized_interactions[0]), interactions_before)


if __name__ == "__main__":
    unittest.main()
