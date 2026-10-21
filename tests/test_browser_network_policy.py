import builtins
import http.client
import os
import socket
import subprocess
import unittest
import urllib.request
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

from jarvis.core.browser_network_policy import (
    BrowserNetworkAdmissionDecision,
    evaluate_browser_network_resolution,
)
from jarvis.core.browser_operation_contract import BrowserOrigin


ORIGIN = BrowserOrigin("https", "example.com", 443)
ALLOWED_ORIGINS = frozenset({ORIGIN})
PUBLIC_IPV4 = "8.8.8.8"
PUBLIC_IPV6 = "2606:4700:4700::1111"
DENIAL_REASONS = (
    "origin_not_allowed", "https_required", "port_443_required",
    "empty_resolution", "invalid_address", "duplicate_address",
    "ipv4_mapped_address", "non_global_address",
)
BLOCKED_IPV4 = (
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
    "169.254.1.1", "169.254.169.254", "0.0.0.0", "224.0.0.1",
    "100.64.0.1", "192.0.2.1", "240.0.0.1",
    "100.64.0.0", "100.127.255.255", "198.51.100.1", "203.0.113.1",
    "198.18.0.1", "255.255.255.255",
)
BLOCKED_IPV6 = (
    "::1", "::", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
    "fd00::1", "fec0::1", "ff0e::1", "100::1", "::8.8.8.8",
)


def evaluate(addresses=(PUBLIC_IPV4,), *, origin=ORIGIN, allowed=ALLOWED_ORIGINS):
    return evaluate_browser_network_resolution(origin, allowed, addresses)


def make_decision(**overrides):
    values = {
        "origin": ORIGIN,
        "admitted": True,
        "reason": "allowed",
        "admitted_ip_addresses": (PUBLIC_IPV4,),
    }
    values.update(overrides)
    return BrowserNetworkAdmissionDecision(**values)


class TupleSubclass(tuple):
    pass


class FrozensetSubclass(frozenset):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class HostileString(str):
    """Arm only after constructing the existing BrowserOrigin and allowlist."""

    def __new__(cls, value):
        instance = str.__new__(cls, value)
        instance.state = {"armed": False, "calls": []}
        return instance

    def _check(self, name):
        if self.state["armed"]:
            self.state["calls"].append(name)
            raise AssertionError("string callback must not run")

    def __str__(self):
        self._check("__str__")
        return str.__str__(self)

    def __len__(self):
        self._check("__len__")
        return str.__len__(self)

    def __iter__(self):
        self._check("__iter__")
        return str.__iter__(self)

    def __eq__(self, other):
        self._check("__eq__")
        return str.__eq__(self, other)

    def __hash__(self):
        self._check("__hash__")
        return str.__hash__(self)

    def strip(self, *args):
        self._check("strip")
        return str.strip(self, *args)

    def lower(self):
        self._check("lower")
        return str.lower(self)

    def isascii(self):
        self._check("isascii")
        return str.isascii(self)

    def split(self, *args):
        self._check("split")
        return str.split(self, *args)


class HostileNonString:
    def __init__(self):
        self.calls = []

    def _fail(self, *args, **kwargs):
        self.calls.append("callback")
        raise AssertionError("object callback must not run")

    __str__ = __iter__ = __len__ = __eq__ = __hash__ = __call__ = _fail

    @property
    def __class__(self):
        return self._fail()


class NetworkResolutionPolicyTests(unittest.TestCase):
    def assert_denied(self, result, reason):
        self.assertIs(result.admitted, False)
        self.assertEqual(result.reason, reason)
        self.assertEqual(result.admitted_ip_addresses, ())

    def test_single_public_ipv4_and_ipv6(self):
        for address in (PUBLIC_IPV4, PUBLIC_IPV6):
            with self.subTest(address=address):
                result = evaluate((address,))
                self.assertIs(type(result), BrowserNetworkAdmissionDecision)
                self.assertIs(result.admitted, True)
                self.assertEqual(result.reason, "allowed")
                self.assertEqual(result.origin, ORIGIN)
                self.assertEqual(result.admitted_ip_addresses, (address,))

    def test_multiple_public_and_mixed_addresses_preserve_order(self):
        for addresses in (
            ("1.1.1.1", PUBLIC_IPV4),
            (PUBLIC_IPV6, PUBLIC_IPV4, "1.1.1.1"),
            (PUBLIC_IPV4, PUBLIC_IPV6),
        ):
            with self.subTest(addresses=addresses):
                self.assertEqual(evaluate(addresses).admitted_ip_addresses, addresses)

    def test_ipv6_is_canonicalized_without_sorting(self):
        result = evaluate(("2606:4700:4700:0000:0000:0000:0000:1111", PUBLIC_IPV4))
        self.assertEqual(result.admitted_ip_addresses, (PUBLIC_IPV6, PUBLIC_IPV4))
        result = evaluate(("2606:4700:4700:0000:0000:0000:0000:ABCD",))
        self.assertEqual(result.admitted_ip_addresses, ("2606:4700:4700::abcd",))

    def test_origin_requires_exact_membership(self):
        for origin in (
            BrowserOrigin("https", "other.example", 443),
            BrowserOrigin("https", "sub.example.com", 443),
            BrowserOrigin("http", "example.com", 443),
            BrowserOrigin("https", "example.com", 8443),
        ):
            with self.subTest(origin=origin):
                self.assert_denied(evaluate(origin=origin), "origin_not_allowed")

    def test_http_is_denied_even_when_origin_is_allowed(self):
        origin = BrowserOrigin("http", "example.com", 80)
        self.assert_denied(evaluate(origin=origin, allowed=frozenset({origin})), "https_required")

    def test_non_443_https_is_denied_even_when_origin_is_allowed(self):
        for port in (80, 8443, 65535):
            with self.subTest(port=port):
                origin = BrowserOrigin("https", "example.com", port)
                self.assert_denied(
                    evaluate(origin=origin, allowed=frozenset({origin})), "port_443_required",
                )

    def test_empty_resolution_is_denied(self):
        self.assert_denied(evaluate(()), "empty_resolution")

    def test_syntax_whitespace_and_scoped_addresses_are_denied(self):
        for address in (
            "", "not-an-ip", " 8.8.8.8", "8.8.8.8 ", "8.8.8.8\n",
            "8.8.8.8\x00", "008.8.8.8", "134744072", "https://8.8.8.8",
            "[2606:4700:4700::1111]", "fe80::1%eth0", "2606:4700:4700::1111%0",
        ):
            with self.subTest(address=address):
                self.assert_denied(evaluate((address,)), "invalid_address")

    def test_ipv4_special_categories_are_denied(self):
        for address in BLOCKED_IPV4:
            with self.subTest(address=address):
                self.assert_denied(evaluate((address,)), "non_global_address")

    def test_ipv6_special_categories_including_site_local_are_denied(self):
        for address in BLOCKED_IPV6:
            with self.subTest(address=address):
                self.assert_denied(evaluate((address,)), "non_global_address")

    def test_public_and_private_ipv4_mapped_addresses_are_denied(self):
        for address in ("::ffff:8.8.8.8", "::ffff:10.0.0.1", "::ffff:127.0.0.1"):
            with self.subTest(address=address):
                self.assert_denied(evaluate((address,)), "ipv4_mapped_address")

    def test_mixed_resolutions_never_admit_a_public_subset(self):
        for blocked in BLOCKED_IPV4 + BLOCKED_IPV6 + ("::ffff:8.8.8.8",):
            reason = "ipv4_mapped_address" if blocked == "::ffff:8.8.8.8" else "non_global_address"
            for addresses in ((PUBLIC_IPV4, blocked), (blocked, PUBLIC_IPV6)):
                with self.subTest(addresses=addresses):
                    self.assert_denied(evaluate(addresses), reason)

    def test_duplicates_are_denied_without_deduplication(self):
        for addresses in (
            (PUBLIC_IPV4, PUBLIC_IPV4),
            (PUBLIC_IPV6, "2606:4700:4700:0:0:0:0:1111"),
            ("2001:db8::1", "2001:0db8:0:0:0:0:0:1"),
        ):
            with self.subTest(addresses=addresses):
                self.assert_denied(evaluate(addresses), "duplicate_address")

    def test_origin_protocol_port_gates_precede_address_parsing(self):
        http = BrowserOrigin("http", "example.com", 8443)
        https = BrowserOrigin("https", "example.com", 8443)
        for addresses in ((), ("invalid",)):
            with self.subTest(addresses=addresses):
                self.assert_denied(evaluate(addresses, origin=http), "origin_not_allowed")
                self.assert_denied(
                    evaluate(addresses, origin=http, allowed=frozenset({http})), "https_required",
                )
                self.assert_denied(
                    evaluate(addresses, origin=https, allowed=frozenset({https})), "port_443_required",
                )

    def test_syntax_precedes_duplicate_mapped_and_global_gates_in_either_order(self):
        for earlier in (
            (PUBLIC_IPV4, PUBLIC_IPV4), ("::ffff:8.8.8.8",), ("10.0.0.1",),
        ):
            for addresses in (earlier + ("invalid",), ("invalid",) + earlier):
                with self.subTest(addresses=addresses):
                    self.assert_denied(evaluate(addresses), "invalid_address")

    def test_duplicate_precedes_mapped_and_mapped_precedes_non_global(self):
        self.assert_denied(
            evaluate(("::ffff:8.8.8.8", "::ffff:0808:0808")), "duplicate_address",
        )
        for addresses in (("10.0.0.1", "::ffff:8.8.8.8"), ("::ffff:8.8.8.8", "10.0.0.1")):
            with self.subTest(addresses=addresses):
                self.assert_denied(evaluate(addresses), "ipv4_mapped_address")


class NetworkResolutionStructureTests(unittest.TestCase):
    def test_origin_must_be_exactly_browser_origin(self):
        for value in (None, "https://example.com", object(), OriginSubclass("https", "example.com", 443)):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                evaluate(origin=value)
            self.assertEqual(str(error.exception), "origin must be exactly BrowserOrigin")

    def test_allowlist_must_be_exact_frozenset(self):
        for value in (None, [ORIGIN], (ORIGIN,), {ORIGIN}, FrozensetSubclass({ORIGIN})):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                evaluate(allowed=value)
            self.assertEqual(str(error.exception), "allowed_origins must be exactly frozenset")

    def test_allowlist_size_boundaries(self):
        sixteen = frozenset({ORIGIN} | {BrowserOrigin("https", f"host-{i}.example", 443) for i in range(15)})
        self.assertIs(evaluate(allowed=sixteen).admitted, True)
        seventeen = sixteen | {BrowserOrigin("https", "extra.example", 443)}
        for value in (frozenset(), seventeen):
            with self.subTest(size=len(value)), self.assertRaises(ValueError) as error:
                evaluate(allowed=value)
            self.assertEqual(str(error.exception), "allowed_origins must contain 1..16 origins")

    def test_allowlist_members_must_be_exact_browser_origins(self):
        for value in ("DO_NOT_LEAK_ORIGIN", 1, None, OriginSubclass("https", "example.com", 443)):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                evaluate(allowed=frozenset({value}))
            self.assertEqual(str(error.exception), "allowed_origins member must be exactly BrowserOrigin")

    def test_resolved_addresses_must_be_exact_tuple(self):
        for value in (None, PUBLIC_IPV4, [PUBLIC_IPV4], {PUBLIC_IPV4}, frozenset({PUBLIC_IPV4}), TupleSubclass((PUBLIC_IPV4,))):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                evaluate(value)
            self.assertEqual(str(error.exception), "resolved_ip_addresses must be exactly tuple")

    def test_resolved_size_boundaries(self):
        addresses = tuple(f"8.8.8.{i}" for i in range(1, 65))
        self.assertEqual(evaluate(addresses).admitted_ip_addresses, addresses)
        with self.assertRaises(ValueError) as error:
            evaluate(addresses + ("8.8.8.65",))
        self.assertEqual(str(error.exception), "resolved_ip_addresses must contain at most 64 addresses")

    def test_resolved_members_must_be_exact_strings(self):
        hostile = HostileString(PUBLIC_IPV4)
        hostile.state["armed"] = True
        non_string = HostileNonString()
        for value in (None, 134744072, True, b"8.8.8.8", object(), hostile, non_string):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                evaluate((value,))
            self.assertEqual(str(error.exception), "resolved_ip_addresses members must be exactly str")
        self.assertEqual(hostile.state["calls"], [])
        self.assertEqual(non_string.calls, [])

    def test_structure_is_validated_before_a_policy_denial(self):
        not_allowed = BrowserOrigin("http", "other.example", 80)
        with self.assertRaises(ValueError):
            evaluate([PUBLIC_IPV4], origin=not_allowed)
        with self.assertRaises(ValueError):
            evaluate(origin=not_allowed, allowed=frozenset())

    def test_hostile_non_strings_are_rejected_without_callbacks(self):
        hostile = HostileNonString()
        for arguments in (
            (hostile, ALLOWED_ORIGINS, (PUBLIC_IPV4,)),
            (ORIGIN, hostile, (PUBLIC_IPV4,)),
            (ORIGIN, ALLOWED_ORIGINS, hostile),
        ):
            with self.subTest(argument_types=tuple(type(arg) for arg in arguments)), self.assertRaises(ValueError):
                evaluate_browser_network_resolution(*arguments)
        self.assertEqual(hostile.calls, [])

    def test_nested_origin_strings_are_detached_before_hash_or_comparison(self):
        scheme = HostileString("https")
        hostname = HostileString("example.com")
        allowed_scheme = HostileString("https")
        allowed_hostname = HostileString("example.com")
        origin = BrowserOrigin(scheme, hostname, 443)
        allowed = frozenset({BrowserOrigin(allowed_scheme, allowed_hostname, 443)})
        strings = (scheme, hostname, allowed_scheme, allowed_hostname)
        for value in strings:
            value.state["armed"] = True
        result = evaluate(origin=origin, allowed=allowed)
        self.assertIs(result.admitted, True)
        self.assertIs(type(result.origin), BrowserOrigin)
        self.assertIs(type(result.origin.scheme), str)
        self.assertIs(type(result.origin.hostname), str)
        self.assertEqual(result.origin, ORIGIN)
        self.assertIsNot(result.origin, origin)
        for value in strings:
            value.state["mutated"] = True
            self.assertEqual(value.state["calls"], [])
        self.assertEqual(result.origin, ORIGIN)
        self.assertIs(origin.scheme, scheme)
        self.assertIs(origin.hostname, hostname)

    def test_inputs_remain_unchanged_and_equivalent_results_have_equal_hashes(self):
        addresses = (PUBLIC_IPV6, PUBLIC_IPV4)
        first = evaluate(addresses)
        second = evaluate(addresses)
        self.assertEqual(first, second)
        self.assertEqual(hash(first), hash(second))
        self.assertEqual(addresses, (PUBLIC_IPV6, PUBLIC_IPV4))
        self.assertEqual(ALLOWED_ORIGINS, frozenset({ORIGIN}))
        self.assertEqual(ORIGIN, BrowserOrigin("https", "example.com", 443))


class NetworkAdmissionDecisionTests(unittest.TestCase):
    def test_admitted_decision_accepts_canonical_public_addresses(self):
        addresses = (PUBLIC_IPV6, PUBLIC_IPV4)
        result = make_decision(admitted_ip_addresses=addresses)
        self.assertIs(result.admitted, True)
        self.assertIs(result.admitted_ip_addresses, addresses)
        self.assertEqual(result.reason, "allowed")

    def test_all_denial_reasons_retain_no_addresses(self):
        for reason in DENIAL_REASONS:
            with self.subTest(reason=reason):
                result = make_decision(admitted=False, reason=reason, admitted_ip_addresses=())
                self.assertIs(result.admitted, False)
                self.assertEqual(result.admitted_ip_addresses, ())

    def test_admitted_requires_exact_bool(self):
        for value in (0, 1, None, "True", [], HostileNonString()):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                make_decision(admitted=value)
            self.assertEqual(str(error.exception), "admitted must be exactly bool")

    def test_reason_is_a_closed_case_sensitive_enum(self):
        hostile = HostileNonString()
        for value in (None, 1, [], "ALLOWED", " allowed", "allowed ", "DO_NOT_LEAK_REASON", hostile):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                make_decision(reason=value)
            self.assertNotIn("DO_NOT_LEAK_REASON", str(error.exception))
        self.assertEqual(hostile.calls, [])

    def test_decision_origin_must_be_exact_browser_origin(self):
        for value in (None, "DO_NOT_LEAK_ORIGIN", OriginSubclass("https", "example.com", 443)):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                make_decision(origin=value)
            self.assertEqual(str(error.exception), "origin must be exactly BrowserOrigin")

    def test_direct_construction_detaches_hostile_origin_strings_and_reason(self):
        scheme = HostileString("https")
        hostname = HostileString("example.com")
        reason = HostileString("allowed")
        origin = BrowserOrigin(scheme, hostname, 443)
        for value in (scheme, hostname, reason):
            value.state["armed"] = True
        result = make_decision(origin=origin, reason=reason)
        self.assertEqual(result.origin, ORIGIN)
        self.assertIs(type(result.origin.scheme), str)
        self.assertIs(type(result.origin.hostname), str)
        self.assertIs(type(result.reason), str)
        for value in (scheme, hostname, reason):
            value.state["mutated"] = True
            self.assertEqual(value.state["calls"], [])
        self.assertEqual(result, make_decision())
        self.assertEqual(hash(result), hash(make_decision()))

    def test_decision_addresses_require_exact_tuple_and_members(self):
        hostile = HostileString(PUBLIC_IPV4)
        hostile.state["armed"] = True
        non_string = HostileNonString()
        for value in ([PUBLIC_IPV4], {PUBLIC_IPV4}, frozenset({PUBLIC_IPV4}), TupleSubclass((PUBLIC_IPV4,)), None):
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError) as error:
                make_decision(admitted_ip_addresses=value)
            self.assertEqual(str(error.exception), "admitted_ip_addresses must be exactly tuple")
        for value in (None, 1, True, b"8.8.8.8", hostile, non_string):
            with self.subTest(member_type=type(value)), self.assertRaises(ValueError) as error:
                make_decision(admitted_ip_addresses=(value,))
            self.assertEqual(str(error.exception), "admitted_ip_addresses members must be exactly str")
        self.assertEqual(hostile.state["calls"], [])
        self.assertEqual(non_string.calls, [])

    def test_decision_address_limit_is_inclusive(self):
        addresses = tuple(f"8.8.8.{i}" for i in range(1, 65))
        self.assertEqual(make_decision(admitted_ip_addresses=addresses).admitted_ip_addresses, addresses)
        with self.assertRaises(ValueError) as error:
            make_decision(admitted_ip_addresses=addresses + ("8.8.8.65",))
        self.assertEqual(str(error.exception), "admitted_ip_addresses must contain at most 64 addresses")

    def test_decision_requires_admission_reason_and_address_coherence(self):
        for admitted, reason, addresses in (
            (True, "allowed", ()),
            (True, "non_global_address", (PUBLIC_IPV4,)),
            (True, "empty_resolution", ()),
            (False, "allowed", ()),
            (False, "allowed", (PUBLIC_IPV4,)),
            (False, "non_global_address", (PUBLIC_IPV4,)),
        ):
            with self.subTest(admitted=admitted, reason=reason, addresses=addresses), self.assertRaises(ValueError):
                make_decision(admitted=admitted, reason=reason, admitted_ip_addresses=addresses)

    def test_direct_admission_requires_canonical_unique_admissible_addresses(self):
        for addresses in (
            ("2606:4700:4700:0:0:0:0:1111",), ("2606:4700:4700::ABCD",),
            ("invalid",), ("2606:4700:4700::1111%0",), (PUBLIC_IPV4, PUBLIC_IPV4),
            ("::ffff:8.8.8.8",), ("10.0.0.1",), (PUBLIC_IPV4, "169.254.169.254"),
        ):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError) as error:
                make_decision(admitted_ip_addresses=addresses)
            self.assertEqual(str(error.exception), "admitted_ip_addresses must be unique canonical admissible IPs")

    def test_direct_admission_requires_https_443(self):
        for origin in (BrowserOrigin("http", "example.com", 443), BrowserOrigin("https", "example.com", 8443)):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                make_decision(origin=origin)

    def test_reason_and_origin_strings_are_detached_without_callbacks(self):
        scheme = HostileString("https")
        hostname = HostileString("example.com")
        reason = HostileString("allowed")
        origin = BrowserOrigin(scheme, hostname, 443)
        for value in (scheme, hostname, reason):
            value.state["armed"] = True
        result = make_decision(origin=origin, reason=reason)
        self.assertIs(type(result.reason), str)
        self.assertIs(type(result.origin.scheme), str)
        self.assertIs(type(result.origin.hostname), str)
        self.assertEqual(result, make_decision())
        self.assertEqual(hash(result), hash(make_decision()))
        for value in (scheme, hostname, reason):
            value.state["mutated"] = True
            self.assertEqual(value.state["calls"], [])
        self.assertEqual(result, make_decision())

    def test_frozen_slots_and_exact_fields(self):
        result = make_decision()
        expected = ("origin", "admitted", "reason", "admitted_ip_addresses")
        self.assertEqual(tuple(field.name for field in fields(result)), expected)
        self.assertEqual(BrowserNetworkAdmissionDecision.__slots__, expected)
        self.assertFalse(hasattr(result, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            result.admitted = False
        with self.assertRaises(FrozenInstanceError):
            del result.reason
        with self.assertRaises((AttributeError, TypeError)):
            result.extra = "unexpected"

    def test_no_trust_execution_raw_addresses_or_serializers(self):
        result = make_decision()
        for name in (
            "trusted", "verified", "sufficient", "confidence", "research_status",
            "capability_id", "functional_result", "attribution", "executed", "connected",
            "denied_ip_addresses", "raw_addresses", "diagnostics", "raw_url", "raw_path",
            "to_dict", "to_mapping", "to_json", "serialize", "save", "load",
        ):
            with self.subTest(name=name):
                self.assertFalse(hasattr(result, name))

    def test_replace_revalidates(self):
        result = make_decision()
        with self.assertRaises(ValueError):
            replace(result, admitted=False)
        with self.assertRaises(ValueError):
            replace(result, admitted_ip_addresses=("10.0.0.1",))
        denied = replace(result, admitted=False, reason="empty_resolution", admitted_ip_addresses=())
        self.assertEqual(denied.admitted_ip_addresses, ())


class NetworkPolicyPurityTests(unittest.TestCase):
    def test_non_string_hostile_inputs_do_not_execute_callbacks(self):
        hostile = HostileNonString()
        calls = (
            lambda: evaluate(origin=hostile),
            lambda: evaluate(allowed=hostile),
            lambda: evaluate(hostile),
            lambda: evaluate((hostile,)),
            lambda: make_decision(origin=hostile),
            lambda: make_decision(admitted=hostile),
            lambda: make_decision(reason=hostile),
            lambda: make_decision(admitted_ip_addresses=hostile),
            lambda: make_decision(admitted_ip_addresses=(hostile,)),
        )
        for index, call in enumerate(calls):
            with self.subTest(index=index), self.assertRaises(ValueError):
                call()
        self.assertEqual(hostile.calls, [])

    def test_structural_errors_do_not_leak_received_values(self):
        marker = "DO_NOT_LEAK_RECEIVED_VALUE"
        calls = (
            lambda: evaluate(origin=marker),
            lambda: evaluate(allowed=marker),
            lambda: evaluate(allowed=frozenset({marker})),
            lambda: evaluate(marker),
            lambda: evaluate((marker.encode(),)),
            lambda: make_decision(origin=marker),
            lambda: make_decision(admitted=marker),
            lambda: make_decision(reason=marker),
            lambda: make_decision(admitted_ip_addresses=marker),
            lambda: make_decision(admitted_ip_addresses=(marker,)),
        )
        for index, call in enumerate(calls):
            with self.subTest(index=index), self.assertRaises(ValueError) as error:
                call()
            self.assertNotIn(marker, str(error.exception))
            self.assertNotIn(marker, repr(error.exception))

    def test_denial_does_not_retain_rejected_addresses(self):
        for addresses in ((PUBLIC_IPV4, "169.254.169.254"), ("DO_NOT_LEAK_INVALID_ADDRESS",)):
            with self.subTest(addresses=addresses):
                result = evaluate(addresses)
                self.assertEqual(result.admitted_ip_addresses, ())
                for address in addresses:
                    self.assertNotIn(address, repr(result))

    def test_construction_and_evaluation_have_no_io(self):
        targets = (
            (socket, "getaddrinfo"), (socket, "gethostbyname"),
            (socket, "gethostbyname_ex"), (socket, "socket"),
            (socket, "create_connection"), (urllib.request, "urlopen"),
            (http.client.HTTPConnection, "connect"), (http.client.HTTPSConnection, "connect"),
            (builtins, "open"), (os, "open"), (os, "stat"),
            (subprocess, "run"), (subprocess, "Popen"),
        )
        with ExitStack() as stack:
            mocks = [
                stack.enter_context(patch.object(module, name, side_effect=AssertionError("I/O forbidden")))
                for module, name in targets
            ]
            self.assertIs(make_decision().admitted, True)
            self.assertIs(evaluate((PUBLIC_IPV4, PUBLIC_IPV6)).admitted, True)
            self.assertIs(evaluate((PUBLIC_IPV4, "169.254.169.254")).admitted, False)
            self.assertEqual(evaluate(()).reason, "empty_resolution")
            self.assertEqual(
                make_decision(admitted=False, reason="invalid_address", admitted_ip_addresses=()).admitted_ip_addresses,
                (),
            )
            for mocked in mocks:
                mocked.assert_not_called()


if __name__ == "__main__":
    unittest.main()
