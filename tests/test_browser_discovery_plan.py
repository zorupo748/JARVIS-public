import http.client
import io
import os
import socket
import unittest
import urllib.request
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from unittest.mock import Mock, patch

from jarvis.core import browser_discovery_plan as discovery_module
from jarvis.core.browser_discovery_plan import (
    BrowserDiscoveryAuthorization,
    BrowserInteractionPlan,
    BrowserInteractionStep,
    BrowserInteractionValueBinding,
)
from jarvis.core.browser_operation_contract import BrowserOrigin, browser_origin_from_url


AUTHORIZATION_FIELDS = (
    "authorization_id", "expected_session_id", "source_url", "allowed_origins",
    "allowed_interaction_kinds", "max_duration_ms", "max_requests", "max_bytes",
    "max_redirects", "max_interactions", "max_dom_targets", "max_plan_steps", "max_candidates",
)
BINDING_FIELDS = ("target_id", "value_ref")
STEP_FIELDS = (
    "interaction_id", "interaction_kind", "activation_target_id", "value_bindings", "expected_effect",
)
PLAN_FIELDS = ("plan_id", "authorization_id", "session_id", "steps")
LIMIT_FIELDS = AUTHORIZATION_FIELDS[5:]
KINDS = ("click", "submit", "input_submit", "navigation")
EFFECTS = ("navigation", "native_submission", "network_activity", "none")


def make_authorization(**overrides):
    values = {
        "authorization_id": "authorization-1",
        "expected_session_id": "session-1",
        "source_url": "https://example.com/",
        "allowed_origins": frozenset({BrowserOrigin("https", "example.com", 443)}),
        "allowed_interaction_kinds": frozenset({"click"}),
        **dict.fromkeys(LIMIT_FIELDS, 1),
    }
    values.update(overrides)
    return BrowserDiscoveryAuthorization(**values)


def make_binding(**overrides):
    values = {"target_id": "target-1", "value_ref": "value-1"}
    values.update(overrides)
    return BrowserInteractionValueBinding(**values)


def make_step(**overrides):
    values = {
        "interaction_id": "interaction-1",
        "interaction_kind": "click",
        "activation_target_id": "activation-1",
        "value_bindings": (),
        "expected_effect": "none",
    }
    values.update(overrides)
    return BrowserInteractionStep(**values)


def make_plan(**overrides):
    values = {
        "plan_id": "plan-1", "authorization_id": "authorization-1", "session_id": "session-1",
        "steps": (),
    }
    values.update(overrides)
    return BrowserInteractionPlan(**values)


RECORD_CASES = (
    (make_authorization, AUTHORIZATION_FIELDS, AUTHORIZATION_FIELDS[:2]),
    (make_binding, BINDING_FIELDS, BINDING_FIELDS),
    (make_step, STEP_FIELDS, ("interaction_id", "activation_target_id")),
    (make_plan, PLAN_FIELDS, PLAN_FIELDS[:3]),
)


class TupleSubclass(tuple):
    pass


class FrozensetSubclass(frozenset):
    pass


class IntSubclass(int):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class BindingSubclass(BrowserInteractionValueBinding):
    __slots__ = ()


class StepSubclass(BrowserInteractionStep):
    __slots__ = ()


class MutableString(str):
    pass


class CallbackString(str):
    def __new__(cls, value):
        instance = super().__new__(cls, value)
        instance.state = []
        return instance

    def unexpected(self, *args, **kwargs):
        raise AssertionError("overridden string callback executed")

    strip = lower = upper = __str__ = __len__ = __iter__ = __eq__ = __hash__ = unexpected


class CallbackObject:
    @property
    def __class__(self):
        raise AssertionError("input __class__ callback executed")

    def unexpected(self, *args, **kwargs):
        raise AssertionError("input callback executed")

    __call__ = __str__ = __iter__ = __len__ = __eq__ = __hash__ = unexpected


class BrowserDiscoveryRecordStructureTests(unittest.TestCase):
    def test_ids_are_stripped_without_restricting_the_alphabet(self):
        for factory, _, id_fields in RECORD_CASES:
            for name in id_fields:
                with self.subTest(record=factory.__name__, field=name):
                    record = factory(**{name: " \t referencia local:ñ/α \n "})
                    self.assertEqual(getattr(record, name), "referencia local:ñ/α")

    def test_all_id_fields_reject_invalid_values(self):
        for factory, _, id_fields in RECORD_CASES:
            for name in id_fields:
                for value in (None, "", " \t\n", "x" * 129, 1, True, [], {}, b"id"):
                    with self.subTest(record=factory.__name__, field=name, value=value), self.assertRaises(ValueError):
                        factory(**{name: value})

    def test_all_id_fields_accept_128_characters_after_stripping(self):
        for factory, _, id_fields in RECORD_CASES:
            for name in id_fields:
                with self.subTest(record=factory.__name__, field=name):
                    self.assertEqual(getattr(factory(**{name: " " + "x" * 128 + " "}), name), "x" * 128)

    def test_all_records_have_exact_fields_frozen_slots_and_no_extra_attributes(self):
        for factory, expected_fields, _ in RECORD_CASES:
            with self.subTest(record=factory.__name__):
                record = factory()
                self.assertEqual(tuple(field.name for field in fields(record)), expected_fields)
                self.assertEqual(type(record).__slots__, expected_fields)
                self.assertFalse(hasattr(record, "__dict__"))
                with self.assertRaises(FrozenInstanceError):
                    setattr(record, expected_fields[0], "changed")
                with self.assertRaises(FrozenInstanceError):
                    delattr(record, expected_fields[0])
                with self.assertRaises((AttributeError, TypeError)):
                    record.extra = "new"


class BrowserDiscoveryAuthorizationTests(unittest.TestCase):
    def test_minimal_authorization_declares_permissions_and_positive_maxima(self):
        authorization = make_authorization()
        self.assertEqual(authorization.authorization_id, "authorization-1")
        self.assertEqual(authorization.expected_session_id, "session-1")
        self.assertEqual(authorization.source_url, "https://example.com/")
        self.assertEqual(authorization.allowed_origins, frozenset({BrowserOrigin("https", "example.com", 443)}))
        self.assertEqual(authorization.allowed_interaction_kinds, frozenset({"click"}))
        self.assertTrue(all(getattr(authorization, name) == 1 for name in LIMIT_FIELDS))

    def test_source_url_canonicalization_and_port_rules_preserve_static_path(self):
        cases = (
            ("HTTPS://Example.COM", "https://example.com/", "https", 443),
            ("https://example.com:443/page?x=VALUE#fragment", "https://example.com/page", "https", 443),
            ("https://Example.COM:8443/Page/", "https://example.com:8443/Page/", "https", 8443),
            ("HTTP://Example.COM:80", "http://example.com/", "http", 80),
            ("http://example.com:8080/page", "http://example.com:8080/page", "http", 8080),
            ("https://example.com:80/", "https://example.com:80/", "https", 80),
            ("http://example.com:443/", "http://example.com:443/", "http", 443),
            ("https://example.com:00443/a_b-c.d~e", "https://example.com/a_b-c.d~e", "https", 443),
            ("https://example.com?secret=VALUE#fragment", "https://example.com/", "https", 443),
        )
        for source, expected, scheme, port in cases:
            with self.subTest(source=source):
                authorization = make_authorization(
                    source_url=source, allowed_origins=frozenset({BrowserOrigin(scheme, "example.com", port)}),
                )
                self.assertEqual(authorization.source_url, expected)

    def test_query_and_fragment_values_are_not_retained_or_passed_to_url_parsers(self):
        secret = "VALUE_MUST_NOT_BE_STORED"
        source = "https://example.com/page?token=" + secret + "#" + secret
        with (
            patch.object(discovery_module, "browser_origin_from_url", wraps=browser_origin_from_url) as origin_parser,
            patch.object(discovery_module, "urlsplit", wraps=discovery_module.urlsplit) as path_parser,
        ):
            authorization = make_authorization(source_url=source)
        origin_parser.assert_called_once_with("https://example.com/page")
        path_parser.assert_called_once_with("https://example.com/page")
        self.assertEqual(authorization.source_url, "https://example.com/page")
        self.assertNotIn(secret, repr(authorization))
        for source in ("https://example.com/page#fragment?ignored=secret", "https://example.com/page?", "https://example.com/page#"):
            with self.subTest(source=source):
                self.assertEqual(make_authorization(source_url=source).source_url, "https://example.com/page")

    def test_source_rejects_non_absolute_http_dns_urls_and_credentials(self):
        for source in (
            None, 1, True, [], "", "example.com", "/page", "//example.com/page",
            "ftp://example.com/", "file:///page", "ws://example.com/", "javascript:alert(1)",
            "https://user:password@example.com/", "https://user@example.com/", "https://@example.com/",
            "https://127.0.0.1/", "https://127.1/", "https://2130706433/", "https://[::1]/",
            "https://example.123/", "https://*.example.com/", "https://example_com/", "https://éxample.com/",
            "https:///page", "https://", "https://example.com:/", "https://example.com:0/",
            "https://example.com:65536/", "https://example.com./",
        ):
            with self.subTest(source=source), self.assertRaises(ValueError):
                make_authorization(source_url=source)

    def test_source_rejects_whitespace_controls_and_backslashes_even_in_discarded_values(self):
        for character in (" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f", "\x85", "\x9f", "\\"):
            for source in (f"https://example.com/{character}page", f"https://example.com/?x={character}"):
                with self.subTest(character=repr(character), source=source), self.assertRaises(ValueError):
                    make_authorization(source_url=source)

    def test_source_path_uses_the_existing_v1_static_subset(self):
        for path in ("//page", "/a//b", "/.", "/..", "/a/../b", "/a/./b", "/a%2fb", "/a;b", "/é"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                make_authorization(source_url="https://example.com" + path)

    def test_origins_require_exact_nonempty_frozenset(self):
        origin = BrowserOrigin("https", "example.com", 443)
        for origins in (
            None, frozenset(), [origin], {origin}, (origin,), {"origin": origin}, FrozensetSubclass({origin}),
        ):
            with self.subTest(origins=origins), self.assertRaises(ValueError):
                make_authorization(allowed_origins=origins)

    def test_origin_members_require_exact_browser_origin(self):
        for origin in (None, "https://example.com", 1, OriginSubclass("https", "example.com", 443)):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_authorization(allowed_origins=frozenset({origin}))

    def test_source_origin_membership_uses_exact_equality(self):
        for origin in (
            BrowserOrigin("http", "example.com", 80), BrowserOrigin("https", "example.com", 8443),
            BrowserOrigin("https", "api.example.com", 443), BrowserOrigin("https", "other.example", 443),
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_authorization(allowed_origins=frozenset({origin}))

    def test_multiple_origins_are_representable_with_16_origin_bound(self):
        source = BrowserOrigin("https", "example.com", 443)
        origins = frozenset({source} | {BrowserOrigin("http", f"host-{index}.example", 8080) for index in range(15)})
        authorization = make_authorization(allowed_origins=origins)
        self.assertEqual(authorization.allowed_origins, origins)
        self.assertEqual(len(authorization.allowed_origins), 16)
        with self.assertRaises(ValueError):
            make_authorization(allowed_origins=origins | {BrowserOrigin("https", "extra.example", 443)})

    def test_allowed_kinds_require_exact_nonempty_frozenset(self):
        for kinds in (None, frozenset(), ["click"], {"click"}, ("click",), {}, FrozensetSubclass({"click"})):
            with self.subTest(kinds=kinds), self.assertRaises(ValueError):
                make_authorization(allowed_interaction_kinds=kinds)

    def test_all_four_kinds_are_authorizable(self):
        for kinds in (frozenset(KINDS),) + tuple(frozenset({kind}) for kind in KINDS):
            with self.subTest(kinds=kinds):
                self.assertEqual(make_authorization(allowed_interaction_kinds=kinds).allowed_interaction_kinds, kinds)

    def test_allowed_kind_enum_is_closed_and_not_normalized(self):
        for kind in ("other", "CLICK", " click ", "", "execute", None, 1, True):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_authorization(allowed_interaction_kinds=frozenset({kind}))
        with self.assertRaises(ValueError):
            make_authorization(allowed_interaction_kinds=frozenset(KINDS + ("other",)))

    def test_all_authorized_maxima_allow_the_signed_64_bit_boundary(self):
        maximum = (1 << 63) - 1
        authorization = make_authorization(**dict.fromkeys(LIMIT_FIELDS, maximum))
        self.assertTrue(all(getattr(authorization, name) == maximum for name in LIMIT_FIELDS))

    def test_every_limit_requires_exact_positive_bounded_int(self):
        for name in LIMIT_FIELDS:
            for value in (0, -1, 1 << 63, True, False, 1.0, "1", None, [], IntSubclass(1)):
                with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                    make_authorization(**{name: value})


class BrowserInteractionValueBindingTests(unittest.TestCase):
    def test_binding_stores_only_opaque_local_references(self):
        binding = make_binding(target_id="unregistered-target", value_ref="unresolved-value")
        self.assertEqual(binding.target_id, "unregistered-target")
        self.assertEqual(binding.value_ref, "unresolved-value")
        self.assertFalse(hasattr(binding, "value"))
        self.assertFalse(hasattr(binding, "selector"))

    def test_reference_equality_is_not_forbidden(self):
        binding = make_binding(target_id="local-1", value_ref="local-1")
        self.assertEqual(binding.target_id, binding.value_ref)


class BrowserInteractionStepTests(unittest.TestCase):
    def test_valid_binding_intentions_for_each_kind(self):
        cases = (
            ("click", (), "none"),
            ("navigation", (), "navigation"),
            ("submit", (), "native_submission"),
            ("submit", (make_binding(),), "network_activity"),
            ("input_submit", (make_binding(),), "native_submission"),
        )
        for kind, bindings, effect in cases:
            with self.subTest(kind=kind, count=len(bindings), effect=effect):
                step = make_step(interaction_kind=kind, value_bindings=bindings, expected_effect=effect)
                self.assertEqual(step.interaction_kind, kind)
                self.assertIs(step.value_bindings, bindings)
                self.assertEqual(step.expected_effect, effect)

    def test_input_submit_requires_bindings(self):
        with self.assertRaises(ValueError):
            make_step(interaction_kind="input_submit", expected_effect="native_submission")

    def test_click_and_navigation_forbid_bindings(self):
        for kind in ("click", "navigation"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_step(interaction_kind=kind, value_bindings=(make_binding(),), expected_effect="navigation")

    def test_interaction_kind_enum_is_closed_and_not_normalized(self):
        for kind in ("other", "CLICK", " click ", "", "execute", None, 1, [], True):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                make_step(interaction_kind=kind)

    def test_binding_collection_requires_exact_tuple(self):
        binding = make_binding()
        for bindings in (None, [binding], {binding}, frozenset({binding}), {}, TupleSubclass((binding,))):
            with self.subTest(bindings=bindings), self.assertRaises(ValueError):
                make_step(interaction_kind="submit", expected_effect="native_submission", value_bindings=bindings)

    def test_binding_members_require_exact_record_type(self):
        for binding in (None, "target-1", {}, 1, BindingSubclass("target-1", "value-1")):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                make_step(interaction_kind="submit", expected_effect="navigation", value_bindings=(binding,))

    def test_binding_count_boundary_for_both_submission_kinds(self):
        bindings = tuple(make_binding(target_id=f"target-{index}") for index in range(32))
        for kind in ("submit", "input_submit"):
            with self.subTest(kind=kind):
                step = make_step(interaction_kind=kind, value_bindings=bindings, expected_effect="native_submission")
                self.assertIs(step.value_bindings, bindings)
                with self.assertRaises(ValueError):
                    make_step(
                        interaction_kind=kind, expected_effect="native_submission",
                        value_bindings=bindings + (make_binding(target_id="target-32"),),
                    )

    def test_binding_target_ids_must_be_unique_after_stripping(self):
        bindings = (make_binding(), make_binding(target_id=" target-1 ", value_ref="different-value"))
        with self.assertRaises(ValueError):
            make_step(interaction_kind="submit", expected_effect="native_submission", value_bindings=bindings)

    def test_binding_order_shared_value_refs_and_activation_target_are_permitted(self):
        bindings = (make_binding(target_id="target-z"), make_binding(target_id="target-a"))
        step = make_step(
            interaction_kind="input_submit", activation_target_id="target-z",
            expected_effect="network_activity", value_bindings=bindings,
        )
        self.assertIs(step.value_bindings, bindings)
        self.assertEqual(tuple(binding.target_id for binding in step.value_bindings), ("target-z", "target-a"))
        self.assertEqual(step.value_bindings[0].value_ref, step.value_bindings[1].value_ref)
        self.assertEqual(step.activation_target_id, step.value_bindings[0].target_id)

    def test_complete_kind_effect_compatibility_matrix(self):
        compatibility = (
            ("navigation", ("navigation",)),
            ("submit", ("native_submission", "navigation", "network_activity")),
            ("input_submit", ("native_submission", "navigation", "network_activity")),
            ("click", ("navigation", "network_activity", "none")),
        )
        for kind, permitted in compatibility:
            bindings = (make_binding(),) if kind == "input_submit" else ()
            for effect in EFFECTS:
                with self.subTest(kind=kind, effect=effect):
                    if effect in permitted:
                        step = make_step(interaction_kind=kind, expected_effect=effect, value_bindings=bindings)
                        self.assertEqual(step.expected_effect, effect)
                    else:
                        with self.assertRaises(ValueError):
                            make_step(interaction_kind=kind, expected_effect=effect, value_bindings=bindings)

    def test_expected_effect_enum_is_closed_and_not_normalized(self):
        for effect in ("NAVIGATION", " none ", "completed", "success", "", None, 1, [], True):
            with self.subTest(effect=effect), self.assertRaises(ValueError):
                make_step(expected_effect=effect)

    def test_expectations_remain_intentions_without_execution_or_attribution(self):
        step = make_step(interaction_kind="submit", expected_effect="network_activity")
        for name in ("executed", "completed", "success", "attribution_basis", "exchange_id", "response"):
            with self.subTest(field=name):
                self.assertFalse(hasattr(step, name))


class BrowserInteractionPlanTests(unittest.TestCase):
    def test_empty_plan_is_valid(self):
        plan = make_plan()
        self.assertEqual(plan.plan_id, "plan-1")
        self.assertEqual(plan.authorization_id, "authorization-1")
        self.assertEqual(plan.session_id, "session-1")
        self.assertEqual(plan.steps, ())

    def test_plan_preserves_step_order_and_allows_reused_activation_targets(self):
        steps = (make_step(interaction_id="interaction-z"), make_step(interaction_id="interaction-a"))
        plan = make_plan(steps=steps)
        self.assertIs(plan.steps, steps)
        self.assertEqual(tuple(step.interaction_id for step in plan.steps), ("interaction-z", "interaction-a"))
        self.assertEqual(plan.steps[0].activation_target_id, plan.steps[1].activation_target_id)

    def test_steps_require_exact_tuple(self):
        step = make_step()
        for steps in (None, [step], {step}, frozenset({step}), {}, TupleSubclass((step,))):
            with self.subTest(steps=steps), self.assertRaises(ValueError):
                make_plan(steps=steps)

    def test_step_members_require_exact_record_type(self):
        subclass = StepSubclass("interaction-1", "click", "activation-1", (), "none")
        for step in (None, "interaction-1", {}, 1, subclass, make_binding()):
            with self.subTest(step=step), self.assertRaises(ValueError):
                make_plan(steps=(step,))

    def test_plan_step_count_boundary(self):
        steps = tuple(make_step(interaction_id=f"interaction-{index}") for index in range(64))
        self.assertIs(make_plan(steps=steps).steps, steps)
        with self.assertRaises(ValueError):
            make_plan(steps=steps + (make_step(interaction_id="interaction-64"),))

    def test_interaction_ids_must_be_unique_after_stripping(self):
        steps = (make_step(), make_step(interaction_id=" interaction-1 ", activation_target_id="other-target"))
        with self.assertRaises(ValueError):
            make_plan(steps=steps)

    def test_plan_is_independent_of_authorization_existence_and_permissions(self):
        authorization = make_authorization(max_plan_steps=1, allowed_interaction_kinds=frozenset({"click"}))
        plan = make_plan(
            authorization_id="unregistered-authorization", session_id="unregistered-session",
            steps=(
                make_step(interaction_id="submit-1", interaction_kind="submit", expected_effect="native_submission"),
                make_step(interaction_id="navigate-1", interaction_kind="navigation", expected_effect="navigation"),
            ),
        )
        self.assertNotEqual(plan.authorization_id, authorization.authorization_id)
        self.assertNotEqual(plan.session_id, authorization.expected_session_id)
        self.assertGreater(len(plan.steps), authorization.max_plan_steps)
        self.assertTrue(all(step.interaction_kind not in authorization.allowed_interaction_kinds for step in plan.steps))
        self.assertFalse(hasattr(plan, "authorization"))
        self.assertFalse(hasattr(plan, "session"))


class BrowserDiscoveryPlanSafetyTests(unittest.TestCase):
    def test_no_trust_execution_or_sensitive_fields(self):
        forbidden = (
            "trusted", "verified", "executed", "completed", "success", "confidence", "sufficient",
            "research_status", "capability_id", "contract_id", "candidate_id", "attribution_basis",
            "css", "xpath", "selector", "selectors", "role", "name", "dom_text", "html", "javascript",
            "callback", "callbacks", "function", "code", "target_url", "raw_url", "raw_path",
            "query_values", "body_values", "value", "tracking_code", "password", "cookies",
            "Authorization", "headers", "request_body", "response_body", "body", "raw_network_errors",
        )
        for factory, _, _ in RECORD_CASES:
            record = factory()
            for name in forbidden:
                with self.subTest(record=type(record).__name__, field=name):
                    self.assertFalse(hasattr(record, name))
                    with self.assertRaises(TypeError):
                        replace(record, **{name: "FORBIDDEN_SECRET"})

    def test_only_the_four_requested_types_are_exported(self):
        self.assertEqual(discovery_module.__all__, (
            "BrowserDiscoveryAuthorization", "BrowserInteractionValueBinding",
            "BrowserInteractionStep", "BrowserInteractionPlan",
        ))

    def test_no_serializers_execution_or_reference_resolution_methods(self):
        for factory, _, _ in RECORD_CASES:
            record = factory()
            for name in (
                "to_prompt_context", "to_mapping", "to_json", "from_json", "serialize", "save", "load",
                "register", "resolve", "resolve_target", "resolve_value", "execute", "collect", "evaluate",
            ):
                with self.subTest(record=type(record).__name__, method=name):
                    self.assertFalse(hasattr(record, name))

    def test_construction_has_no_network_dns_or_filesystem_access(self):
        targets = (
            (socket, "getaddrinfo"), (socket, "gethostbyname"), (socket, "gethostbyname_ex"),
            (socket, "socket"), (socket, "create_connection"), (urllib.request, "urlopen"),
            (http.client.HTTPConnection, "connect"), (http.client.HTTPSConnection, "connect"),
            (io, "open"), (os, "open"), (os, "stat"), (Path, "read_text"), (Path, "write_text"),
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch.object(owner, name, side_effect=AssertionError("I/O executed"))) for owner, name in targets]
            guards.append(stack.enter_context(patch("builtins.open", side_effect=AssertionError("I/O executed"))))
            authorization = make_authorization(source_url="https://example.com/?q=VALUE_TO_DROP#fragment")
            binding = make_binding(target_id="unregistered-target", value_ref="unresolved-value")
            step = make_step(
                activation_target_id="unregistered-activation", interaction_kind="input_submit",
                value_bindings=(binding,), expected_effect="network_activity",
            )
            plan = make_plan(steps=(step,))
            self.assertEqual(authorization.source_url, "https://example.com/")
            self.assertEqual(plan.steps[0].value_bindings[0].value_ref, "unresolved-value")
            with self.assertRaises(ValueError):
                replace(authorization, max_bytes=0)
            for guard in guards:
                guard.assert_not_called()

    def test_callbacks_and_overridden_type_properties_are_never_executed(self):
        for callback in (Mock(side_effect=AssertionError("callback executed")), CallbackObject()):
            for factory, record_fields, _ in RECORD_CASES:
                for name in record_fields:
                    with self.subTest(record=factory.__name__, field=name, callback_type=type(callback).__name__), self.assertRaises(ValueError):
                        factory(**{name: callback})
            if type(callback) is not CallbackObject:
                callback.assert_not_called()
        callback = Mock(side_effect=AssertionError("nested callback executed"))
        for factory, overrides in (
            (make_authorization, {"allowed_origins": frozenset({callback})}),
            (make_authorization, {"allowed_interaction_kinds": frozenset({callback})}),
            (make_step, {"value_bindings": (callback,)}),
            (make_plan, {"steps": (callback,)}),
        ):
            with self.subTest(record=factory.__name__, fields=tuple(overrides)), self.assertRaises(ValueError):
                factory(**overrides)
        callback.assert_not_called()

    def test_scalar_string_subclasses_are_detached_without_overridden_callbacks(self):
        for factory, _, id_fields in RECORD_CASES:
            for name in id_fields:
                original = CallbackString(" local-reference ")
                with self.subTest(record=factory.__name__, field=name):
                    record = factory(**{name: original})
                    self.assertIs(type(getattr(record, name)), str)
                    self.assertEqual(getattr(record, name), "local-reference")
                    original.state.append("later mutation")
                    self.assertFalse(hasattr(getattr(record, name), "state"))
        authorization = make_authorization(source_url=CallbackString("HTTPS://EXAMPLE.COM/?x=VALUE#fragment"))
        step = make_step(interaction_kind=CallbackString("click"), expected_effect=CallbackString("none"))
        self.assertIs(type(authorization.source_url), str)
        self.assertEqual(authorization.source_url, "https://example.com/")
        self.assertIs(type(step.interaction_kind), str)
        self.assertIs(type(step.expected_effect), str)

    def test_nested_origin_and_enum_strings_cannot_retain_mutable_subclass_state(self):
        scheme, hostname, kind = MutableString("https"), MutableString("example.com"), MutableString("click")
        for value in (scheme, hostname, kind):
            value.state = []
        origin = BrowserOrigin(scheme, hostname, 443)
        origins = frozenset({origin})
        kinds = frozenset({kind})
        authorization = make_authorization(allowed_origins=origins, allowed_interaction_kinds=kinds)
        exported_origin = next(iter(authorization.allowed_origins))
        self.assertIs(type(exported_origin), BrowserOrigin)
        self.assertIs(type(exported_origin.scheme), str)
        self.assertIs(type(exported_origin.hostname), str)
        self.assertIs(type(next(iter(authorization.allowed_interaction_kinds))), str)
        for value in (scheme, hostname, kind):
            value.state.append("later mutation")
        self.assertFalse(hasattr(exported_origin.scheme, "state"))
        self.assertFalse(hasattr(exported_origin.hostname, "state"))
        self.assertFalse(hasattr(next(iter(authorization.allowed_interaction_kinds)), "state"))
        self.assertIs(origin.scheme, scheme)
        self.assertIs(origin.hostname, hostname)
        self.assertEqual(origins, frozenset({origin}))
        self.assertEqual(kinds, frozenset({kind}))

    def test_nested_records_and_collections_are_immutable(self):
        plan = make_plan(steps=(make_step(
            interaction_kind="input_submit", value_bindings=(make_binding(),), expected_effect="native_submission",
        ),))
        with self.assertRaises(FrozenInstanceError):
            plan.steps[0].activation_target_id = "changed"
        with self.assertRaises(FrozenInstanceError):
            plan.steps[0].value_bindings[0].value_ref = "changed"
        with self.assertRaises(TypeError):
            plan.steps[0] = make_step()
        with self.assertRaises(TypeError):
            plan.steps[0].value_bindings[0] = make_binding()
        authorization = make_authorization()
        with self.assertRaises(AttributeError):
            authorization.allowed_origins.add(BrowserOrigin("https", "other.example", 443))
        with self.assertRaises(FrozenInstanceError):
            next(iter(authorization.allowed_origins)).hostname = "changed.example"

    def test_existing_collections_are_preserved_without_mutation(self):
        origins = frozenset({BrowserOrigin("https", "example.com", 443)})
        kinds = frozenset(KINDS)
        bindings = (make_binding(target_id="target-z"), make_binding(target_id="target-a"))
        steps = (make_step(interaction_kind="submit", value_bindings=bindings, expected_effect="network_activity"),)
        snapshot = (hash(origins), hash(kinds), hash(bindings), hash(steps))
        authorization = make_authorization(allowed_origins=origins, allowed_interaction_kinds=kinds)
        plan = make_plan(steps=steps)
        self.assertEqual(authorization.allowed_origins, origins)
        self.assertEqual(authorization.allowed_interaction_kinds, kinds)
        self.assertIs(plan.steps, steps)
        self.assertIs(plan.steps[0].value_bindings, bindings)
        self.assertEqual((hash(origins), hash(kinds), hash(bindings), hash(steps)), snapshot)
        invalid_bindings = [make_binding()]
        with self.assertRaises(ValueError):
            make_step(value_bindings=invalid_bindings)
        self.assertEqual(invalid_bindings, [make_binding()])

    def test_dataclasses_replace_revalidates_all_four_records(self):
        cases = (
            (make_authorization(), ({"source_url": "/relative"}, {"max_bytes": True}, {"allowed_origins": frozenset()})),
            (make_binding(), ({"target_id": ""}, {"value_ref": "x" * 129})),
            (make_step(), ({"interaction_kind": "other"}, {"expected_effect": "native_submission"}, {"value_bindings": (make_binding(),)})),
            (make_plan(), ({"steps": [make_step()]}, {"steps": (make_step(), make_step())})),
        )
        for record, invalid_overrides in cases:
            for overrides in invalid_overrides:
                with self.subTest(record=type(record).__name__, fields=tuple(overrides)), self.assertRaises(ValueError):
                    replace(record, **overrides)
            name = fields(record)[0].name
            changed = replace(record, **{name: " replacement-id "})
            self.assertEqual(getattr(changed, name), "replacement-id")

    def test_equivalent_inputs_produce_equal_objects_and_hashes(self):
        for factory, _, _ in RECORD_CASES:
            with self.subTest(record=factory.__name__):
                first, second = factory(), factory()
                self.assertIsNot(first, second)
                self.assertEqual(first, second)
                self.assertEqual(hash(first), hash(second))
                self.assertEqual(len({first, second}), 1)
        first = make_authorization(source_url="HTTPS://EXAMPLE.COM:443/?token=VALUE#fragment")
        second = make_authorization()
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))

    def test_rejected_values_are_not_included_in_validation_messages(self):
        secret = "VALUE_MUST_NOT_APPEAR_IN_ERRORS"
        for factory, overrides in (
            (make_authorization, {"source_url": "https://user:" + secret + "@example.com/"}),
            (make_authorization, {"allowed_interaction_kinds": frozenset({secret})}),
            (make_binding, {"value_ref": secret * 5}),
            (make_step, {"expected_effect": secret}),
            (make_plan, {"plan_id": secret * 5}),
        ):
            with self.subTest(record=factory.__name__, fields=tuple(overrides)):
                with self.assertRaises(ValueError) as caught:
                    factory(**overrides)
                self.assertNotIn(secret, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
