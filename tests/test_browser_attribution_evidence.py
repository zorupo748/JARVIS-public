import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from typing import get_type_hints
from unittest.mock import Mock, patch

from jarvis.core.browser_attribution_evidence import BrowserCapabilityAttributionEvidence


ATTRIBUTION_FIELDS = (
    "session_id", "exchange_path", "interaction_id", "operation_contract_id",
    "attribution_basis",
)
ID_FIELDS = ("session_id", "operation_contract_id", "interaction_id")
CONTROLLED_BASES = (
    "CONTROLLED_NAVIGATION", "CONTROLLED_SUBMISSION", "OBSERVED_OPERATION_DISPATCH",
)
ALL_BASES = ("INITIAL_NAVIGATION", *CONTROLLED_BASES)
FORBIDDEN_FIELDS = (
    "url", "page_url", "endpoint_url", "method", "http_method", "parameters",
    "parameter_names", "parameter_values", "values", "cookies", "Authorization",
    "authorization", "headers", "body", "response", "selector", "selectors",
    "input_text", "code", "script", "callback", "callbacks", "raw_message",
    "raw_messages", "timestamp", "timestamps", "confidence", "sufficient",
    "research_status", "trusted", "verified", "capability_relevant",
    "session_evidence", "interaction_kind", "phase_id", "start_sequence",
    "redirect_from_exchange_id", "evaluate", "collect", "to_mapping",
)


class TupleSubclass(tuple):
    pass


class StringSubclass(str):
    pass


def make_attribution(**overrides):
    values = {
        "session_id": "session-1",
        "exchange_path": ("exchange-1",),
        "interaction_id": "interaction-1",
        "operation_contract_id": "operation-1",
        "attribution_basis": "CONTROLLED_NAVIGATION",
    }
    values.update(overrides)
    return BrowserCapabilityAttributionEvidence(**values)


class BrowserCapabilityAttributionEvidenceTests(unittest.TestCase):
    def test_initial_navigation_accepts_no_interaction(self):
        record = make_attribution(attribution_basis="INITIAL_NAVIGATION", interaction_id=None)
        self.assertEqual(record.attribution_basis, "INITIAL_NAVIGATION")
        self.assertIsNone(record.interaction_id)

    def test_controlled_navigation_is_valid(self):
        record = make_attribution(attribution_basis="CONTROLLED_NAVIGATION")
        self.assertEqual(record.attribution_basis, "CONTROLLED_NAVIGATION")
        self.assertEqual(record.interaction_id, "interaction-1")

    def test_controlled_submission_is_valid(self):
        record = make_attribution(attribution_basis="CONTROLLED_SUBMISSION")
        self.assertEqual(record.attribution_basis, "CONTROLLED_SUBMISSION")
        self.assertEqual(record.interaction_id, "interaction-1")

    def test_observed_operation_dispatch_is_valid(self):
        record = make_attribution(attribution_basis="OBSERVED_OPERATION_DISPATCH")
        self.assertEqual(record.attribution_basis, "OBSERVED_OPERATION_DISPATCH")
        self.assertEqual(record.interaction_id, "interaction-1")

    def test_invalid_basis_is_rejected(self):
        for basis in ("", " ", "UNKNOWN", "NAVIGATION", None, True, 1, b"INITIAL_NAVIGATION", [], {}):
            with self.subTest(basis=basis), self.assertRaises(ValueError):
                make_attribution(attribution_basis=basis)

    def test_lowercase_mixed_case_and_padded_bases_are_rejected(self):
        for basis in ALL_BASES:
            for variant in (basis.lower(), basis.title(), " " + basis, basis + "\t"):
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    make_attribution(attribution_basis=variant)

    def test_heuristic_bases_are_rejected(self):
        for basis in (
            "TEMPORAL_ONLY", "AFTER_CLICK", "UNIQUE_CANDIDATE", "PARAMETER_MATCH",
            "NAME_MATCH", "BASELINE_DIFFERENCE",
        ):
            for variant in (basis, basis.lower()):
                with self.subTest(basis=variant), self.assertRaises(ValueError):
                    make_attribution(attribution_basis=variant)

    def test_initial_navigation_rejects_an_interaction(self):
        with self.assertRaisesRegex(ValueError, "INITIAL_NAVIGATION requires interaction_id=None"):
            make_attribution(attribution_basis="INITIAL_NAVIGATION")

    def test_all_controlled_bases_require_an_interaction(self):
        for basis in CONTROLLED_BASES:
            with self.subTest(basis=basis), self.assertRaisesRegex(ValueError, "requires interaction_id"):
                make_attribution(attribution_basis=basis, interaction_id=None)

    def test_empty_ids_are_rejected_for_every_id_field(self):
        for field_name in ID_FIELDS:
            for value in ("", " ", "\t\r\n", "\u2003\u00a0"):
                with self.subTest(field_name=field_name, value=value), self.assertRaises(ValueError):
                    make_attribution(**{field_name: value})

    def test_oversized_ids_are_rejected_for_every_id_field(self):
        for field_name in ID_FIELDS:
            for value in ("x" * 129, " " + "x" * 129 + " "):
                with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                    make_attribution(**{field_name: value})

    def test_ids_require_strings(self):
        for field_name in ID_FIELDS:
            for value in (None, True, False, 0, 1.0, b"id", [], (), {}, object()):
                with self.subTest(field_name=field_name, value_type=type(value).__name__), self.assertRaises(ValueError):
                    make_attribution(**{field_name: value})

    def test_id_length_boundaries_apply_after_stripping(self):
        for field_name in ID_FIELDS:
            for length in (1, 128):
                value = "x" * length
                with self.subTest(field_name=field_name, length=length):
                    record = make_attribution(**{field_name: "\t " + value + " \n"})
                    self.assertEqual(getattr(record, field_name), value)

    def test_all_ids_are_stripped(self):
        record = make_attribution(
            session_id="\t session-1 \n",
            operation_contract_id=" operation-1 ",
            interaction_id="\u2003interaction-1\u00a0",
            exchange_path=(" exchange-1 ", "\texchange-2\n"),
        )
        self.assertEqual(record.session_id, "session-1")
        self.assertEqual(record.operation_contract_id, "operation-1")
        self.assertEqual(record.interaction_id, "interaction-1")
        self.assertEqual(record.exchange_path, ("exchange-1", "exchange-2"))

    def test_ids_do_not_impose_an_additional_alphabet(self):
        value = "local \u00f1 /:@[]?=+#\tidentifier"
        record = make_attribution(**{field_name: value for field_name in ID_FIELDS}, exchange_path=(value,))
        for field_name in ID_FIELDS:
            with self.subTest(field_name=field_name):
                self.assertEqual(getattr(record, field_name), value)
        self.assertEqual(record.exchange_path, (value,))

    def test_scalar_string_subclasses_become_plain_immutable_strings(self):
        for field_name in (*ID_FIELDS, "attribution_basis"):
            value = StringSubclass("CONTROLLED_NAVIGATION" if field_name == "attribution_basis" else " local-id ")
            value.mutable_data = []
            with self.subTest(field_name=field_name):
                record = make_attribution(**{field_name: value})
                stored = getattr(record, field_name)
                self.assertIs(type(stored), str)
                self.assertEqual(stored, str.strip(value))
                self.assertFalse(hasattr(stored, "mutable_data"))

    def test_single_exchange_path_is_valid(self):
        self.assertEqual(make_attribution().exchange_path, ("exchange-1",))

    def test_multiple_exchanges_are_structurally_valid_for_every_basis(self):
        path = ("exchange-1", "exchange-2", "exchange-3")
        for basis in ALL_BASES:
            with self.subTest(basis=basis):
                record = make_attribution(
                    attribution_basis=basis, exchange_path=path,
                    interaction_id=None if basis == "INITIAL_NAVIGATION" else "interaction-1",
                )
                self.assertEqual(record.exchange_path, path)

    def test_empty_exchange_path_is_rejected(self):
        with self.assertRaises(ValueError):
            make_attribution(exchange_path=())

    def test_exchange_path_requires_an_exact_tuple(self):
        for path in (
            ["exchange-1"], {"exchange-1"}, frozenset({"exchange-1"}),
            TupleSubclass(("exchange-1",)), {"exchange-1": True}, "exchange-1",
            b"exchange-1", None, True, 1, iter(("exchange-1",)),
            (value for value in ("exchange-1",)),
        ):
            with self.subTest(path_type=type(path).__name__), self.assertRaisesRegex(ValueError, "exactly tuple"):
                make_attribution(exchange_path=path)

    def test_exchange_members_require_exact_strings(self):
        for value in (None, True, False, 0, 1.0, b"exchange-1", [], (), {}, object(), StringSubclass("exchange-1")):
            with self.subTest(member_type=type(value).__name__), self.assertRaisesRegex(ValueError, "exactly str"):
                make_attribution(exchange_path=("exchange-1", value))

    def test_empty_exchange_ids_are_rejected(self):
        for value in ("", " ", "\t\n", "\u2003\u00a0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_attribution(exchange_path=(value,))

    def test_exchange_id_length_boundaries_apply_after_stripping(self):
        for length in (1, 128, 129):
            value = "x" * length
            with self.subTest(length=length):
                if length <= 128:
                    self.assertEqual(make_attribution(exchange_path=(" " + value + " ",)).exchange_path, (value,))
                else:
                    with self.assertRaises(ValueError):
                        make_attribution(exchange_path=(value,))

    def test_duplicate_exchange_ids_are_rejected_after_stripping(self):
        for path in (
            ("exchange-1", "exchange-1"),
            (" exchange-1", "exchange-1\t"),
            ("exchange-1", "exchange-2", "\u2003exchange-1\u00a0"),
        ):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unique"):
                make_attribution(exchange_path=path)

    def test_case_distinct_exchange_ids_remain_distinct(self):
        path = ("exchange-1", "Exchange-1", "EXCHANGE-1")
        self.assertEqual(make_attribution(exchange_path=path).exchange_path, path)

    def test_sixty_four_exchanges_are_permitted(self):
        path = tuple(f"exchange-{index}" for index in range(64))
        self.assertEqual(make_attribution(exchange_path=path).exchange_path, path)

    def test_sixty_five_exchanges_are_rejected(self):
        path = tuple(f"exchange-{index}" for index in range(65))
        with self.assertRaisesRegex(ValueError, "1..64"):
            make_attribution(exchange_path=path)

    def test_path_order_is_preserved_without_sorting_or_sequence_inference(self):
        path = (" exchange-9 ", "exchange-2", " exchange-1 ")
        self.assertEqual(make_attribution(exchange_path=path).exchange_path, ("exchange-9", "exchange-2", "exchange-1"))
        self.assertEqual(path, (" exchange-9 ", "exchange-2", " exchange-1 "))

    def test_unregistered_references_need_no_session_context_or_records(self):
        record = make_attribution(
            session_id="unregistered-session", operation_contract_id="unregistered-operation",
            interaction_id="unregistered-interaction", exchange_path=("unregistered-exchange",),
        )
        self.assertEqual(record.session_id, "unregistered-session")
        self.assertEqual(record.operation_contract_id, "unregistered-operation")
        self.assertEqual(record.interaction_id, "unregistered-interaction")
        self.assertEqual(record.exchange_path, ("unregistered-exchange",))

    def test_multiexchange_path_needs_no_redirect_phase_or_completeness_metadata(self):
        path = ("unlinked-exchange-9", "unlinked-exchange-1", "unlinked-exchange-5")
        record = make_attribution(exchange_path=path)
        self.assertEqual(record.exchange_path, path)
        for field_name in ("redirect_count", "phases", "collection_status", "completion"):
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(record, field_name))

    def test_construction_does_not_parse_or_correlate_urls(self):
        with patch("urllib.parse.urlsplit", side_effect=AssertionError("URL parsed")) as split:
            with patch("urllib.parse.urlunsplit", side_effect=AssertionError("URL rendered")) as unsplit:
                first = make_attribution()
                second = make_attribution(operation_contract_id="another-operation", interaction_id="another-interaction")
        self.assertEqual(first.exchange_path, second.exchange_path)
        self.assertNotEqual(first.operation_contract_id, second.operation_contract_id)
        split.assert_not_called()
        unsplit.assert_not_called()

    def test_fields_slots_and_annotations_are_exact(self):
        self.assertEqual(tuple(field.name for field in fields(BrowserCapabilityAttributionEvidence)), ATTRIBUTION_FIELDS)
        self.assertEqual(BrowserCapabilityAttributionEvidence.__slots__, ATTRIBUTION_FIELDS)
        self.assertEqual(get_type_hints(BrowserCapabilityAttributionEvidence), {
            "session_id": str,
            "exchange_path": tuple[str, ...],
            "interaction_id": str | None,
            "operation_contract_id": str,
            "attribution_basis": str,
        })

    def test_record_is_frozen_and_has_no_instance_dictionary(self):
        record = make_attribution()
        self.assertTrue(BrowserCapabilityAttributionEvidence.__dataclass_params__.frozen)
        self.assertFalse(hasattr(record, "__dict__"))
        for field_name in ATTRIBUTION_FIELDS:
            with self.subTest(field_name=field_name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(record, field_name, getattr(record, field_name))
                with self.assertRaises(FrozenInstanceError):
                    delattr(record, field_name)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            record.extra_attribute = "value"

    def test_exchange_path_is_transitively_immutable(self):
        record = make_attribution(exchange_path=("exchange-1", "exchange-2"))
        self.assertIs(type(record.exchange_path), tuple)
        self.assertTrue(all(type(value) is str for value in record.exchange_path))
        with self.assertRaises(TypeError):
            record.exchange_path[0] = "changed"
        self.assertEqual(record, make_attribution(exchange_path=("exchange-1", "exchange-2")))
        self.assertEqual(hash(record), hash(make_attribution(exchange_path=("exchange-1", "exchange-2"))))

    def test_sensitive_trust_sufficiency_and_execution_attributes_are_absent(self):
        record = make_attribution()
        for field_name in FORBIDDEN_FIELDS:
            with self.subTest(field_name=field_name):
                self.assertFalse(hasattr(record, field_name))
                with self.assertRaises(TypeError):
                    make_attribution(**{field_name: "unrequested-data"})

    def test_callables_are_rejected_without_execution(self):
        callback = Mock(side_effect=AssertionError("callback executed"))
        for field_name in ATTRIBUTION_FIELDS:
            with self.subTest(field_name=field_name), self.assertRaises(ValueError):
                make_attribution(**{field_name: callback})
        with self.assertRaises(ValueError):
            make_attribution(exchange_path=(callback,))
        callback.assert_not_called()

    def test_construction_performs_no_network_dns_or_filesystem_calls(self):
        targets = (
            "urllib.request.urlopen", "http.client.HTTPConnection.connect",
            "http.client.HTTPSConnection.connect", "socket.getaddrinfo",
            "socket.gethostbyname", "socket.gethostbyname_ex", "socket.create_connection",
            "socket.socket", "pathlib.Path.open", "pathlib.Path.read_text",
            "pathlib.Path.write_text", "pathlib.Path.stat", "builtins.open",
        )
        with ExitStack() as stack:
            blocked = [stack.enter_context(patch(target, side_effect=AssertionError(target))) for target in targets]
            for basis in ALL_BASES:
                with self.subTest(basis=basis):
                    record = make_attribution(
                        attribution_basis=basis,
                        interaction_id=None if basis == "INITIAL_NAVIGATION" else "interaction-1",
                    )
                    self.assertEqual(record.attribution_basis, basis)
            for mocked in blocked:
                mocked.assert_not_called()

    def test_replace_revalidates_structure_and_interaction_rules(self):
        record = make_attribution()
        invalid_changes = (
            {"session_id": ""}, {"operation_contract_id": "x" * 129},
            {"interaction_id": " "}, {"interaction_id": None},
            {"exchange_path": ()}, {"exchange_path": ["exchange-1"]},
            {"exchange_path": ("exchange-1", " exchange-1 ")},
            {"exchange_path": tuple(f"exchange-{index}" for index in range(65))},
            {"attribution_basis": "AFTER_CLICK"}, {"attribution_basis": "INITIAL_NAVIGATION"},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(record, **changes)
        self.assertEqual(record, make_attribution())
        initial = replace(record, attribution_basis="INITIAL_NAVIGATION", interaction_id=None)
        with self.assertRaises(ValueError):
            replace(initial, attribution_basis="OBSERVED_OPERATION_DISPATCH")

    def test_replace_normalizes_ids_and_preserves_the_original(self):
        original = make_attribution()
        updated = replace(
            original, session_id=" session-2 ", operation_contract_id=" operation-2 ",
            interaction_id=" interaction-2 ", exchange_path=(" exchange-2 ", " exchange-3 "),
            attribution_basis="CONTROLLED_SUBMISSION",
        )
        self.assertEqual(updated, make_attribution(
            session_id="session-2", operation_contract_id="operation-2", interaction_id="interaction-2",
            exchange_path=("exchange-2", "exchange-3"), attribution_basis="CONTROLLED_SUBMISSION",
        ))
        self.assertEqual(original, make_attribution())


if __name__ == "__main__":
    unittest.main()
