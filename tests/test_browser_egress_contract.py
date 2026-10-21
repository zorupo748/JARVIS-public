import ast
import inspect
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock, patch

import jarvis.core.browser_egress_contract as contract
from jarvis.core.browser_egress_contract import (
    BrowserAdmittedResolution, BrowserConnectionAuthorization,
    BrowserEgressDestinationDecision, authorize_browser_connection,
    evaluate_browser_egress_destination,
)
from jarvis.core.browser_network_policy import (
    BrowserNetworkAdmissionDecision, evaluate_browser_network_resolution,
)
from jarvis.core.browser_operation_contract import BrowserOrigin

ORIGIN = BrowserOrigin("https", "example.com", 443)
IPS = ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")


def admission(ips=IPS, origin=ORIGIN):
    return evaluate_browser_network_resolution(origin, frozenset({origin}), ips)


def resolution():
    return BrowserAdmittedResolution("resolution-1", admission())


def authorization():
    return authorize_browser_connection(resolution(), "authorization-1", "session-1", "operation-1")


_DEFAULT_AUTH = object()


def selection(auth=_DEFAULT_AUTH, **overrides):
    values = dict(resolution_id="resolution-1", authorization_id="authorization-1",
                  session_id="session-1", operation_id="operation-1", origin=ORIGIN,
                  port=443, selected_ip_address=IPS[0])
    values.update(overrides)
    return evaluate_browser_egress_destination(authorization() if auth is _DEFAULT_AUTH else auth, **values)


class StringSubclass(str):
    pass


class IntSubclass(int):
    pass


class TupleSubclass(tuple):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class AdmissionSubclass(BrowserNetworkAdmissionDecision):
    __slots__ = ()


class ResolutionSubclass(BrowserAdmittedResolution):
    __slots__ = ()


class Hostile:
    def fail(self, *args, **kwargs):
        raise AssertionError("input callback executed")
    __str__ = __eq__ = __hash__ = __iter__ = __len__ = __call__ = fail

    @property
    def __class__(self):
        return self.fail()


class BrowserEgressContractTests(unittest.TestCase):
    def test_valid_structural_authorization_retains_full_snapshot(self):
        snapshot = resolution()
        auth = authorize_browser_connection(snapshot, "authorization-1", "session-1", "operation-1")
        self.assertIs(auth.resolution, snapshot)
        self.assertIs(auth.resolution.admission.origin, ORIGIN)
        self.assertEqual(auth.resolution.admission.admitted_ip_addresses, IPS)
        for ip in IPS:
            self.assertTrue(selection(auth, selected_ip_address=ip).policy_allowed)

    def test_all_policy_denials_cannot_become_authorizations(self):
        cases = ((), ("10.0.0.1",), ("169.254.169.254",), ("::ffff:8.8.8.8",),
                 ("8.8.8.8", "10.0.0.1"), ("8.8.8.8", "8.8.8.8"), ("invalid",))
        for ips in cases:
            with self.subTest(ips=ips):
                denied = admission(ips)
                self.assertFalse(denied.admitted)
                self.assertEqual(denied.admitted_ip_addresses, ())
                with self.assertRaises(ValueError):
                    BrowserAdmittedResolution("resolution-1", denied)
        for origin in (BrowserOrigin("http", "example.com", 80),
                       BrowserOrigin("https", "example.com", 8443)):
            self.assertFalse(admission(origin=origin).admitted)
            with self.assertRaises(ValueError):
                BrowserAdmittedResolution("resolution-1", admission(origin=origin))
        denied = evaluate_browser_network_resolution(ORIGIN, frozenset({BrowserOrigin("https", "other.example", 443)}), IPS)
        with self.assertRaises(ValueError):
            BrowserAdmittedResolution("resolution-1", denied)

    def test_origin_hostname_scheme_and_port_are_exact(self):
        for origin in (BrowserOrigin("https", "other.example", 443),
                       BrowserOrigin("https", "sub.example.com", 443),
                       BrowserOrigin("https", "ample.com", 443),
                       BrowserOrigin("http", "example.com", 443),
                       BrowserOrigin("https", "example.com", 8443)):
            with self.subTest(origin=origin):
                self.assertFalse(selection(origin=origin).policy_allowed)
        for port in (80, 8443, 65535):
            self.assertFalse(selection(port=port).policy_allowed)

    def test_ip_membership_and_existing_policy_both_required(self):
        for ip in ("9.9.9.9", "10.0.0.1", "169.254.169.254", "127.0.0.1",
                   "100.64.0.1", "224.0.0.1", "192.0.2.1", "::", "::1",
                   "fe80::1", "fc00::1", "2001:db8::1", "::ffff:8.8.8.8", ""):
            with self.subTest(ip=ip):
                self.assertFalse(selection(selected_ip_address=ip).policy_allowed)
                existing = admission((ip,))
                if existing.admitted:
                    self.assertNotIn(ip, IPS)
                else:
                    self.assertEqual(existing.admitted_ip_addresses, ())

    def test_noncanonical_selection_is_not_normalized_into_permission(self):
        noncanonical = "2606:4700:4700:0000:0000:0000:0000:1111"
        self.assertTrue(admission((noncanonical,)).admitted)
        self.assertEqual(admission((noncanonical,)).admitted_ip_addresses, (IPS[2],))
        self.assertFalse(selection(selected_ip_address=noncanonical).policy_allowed)
        with self.assertRaises(ValueError):
            BrowserNetworkAdmissionDecision(ORIGIN, True, "allowed", (noncanonical,))

    def test_identifiers_bind_all_four_roles(self):
        for name in ("resolution_id", "authorization_id", "session_id", "operation_id"):
            self.assertFalse(selection(**{name: "other-id"}).policy_allowed)
        swapped = dict(session_id="operation-1", operation_id="session-1")
        self.assertFalse(selection(**swapped).policy_allowed)

    def test_id_types_syntax_and_boundaries(self):
        bad = ("", " ", " id", "id ", "a.b", "a/b", "a\n", "é", "x" * 129,
               1, True, None, StringSubclass("id"), Hostile())
        for value in bad:
            with self.subTest(value_type=type(value)):
                with self.assertRaises(ValueError):
                    BrowserAdmittedResolution(value, admission())
                for name in ("authorization_id", "session_id", "operation_id"):
                    with self.assertRaises(ValueError):
                        replace(authorization(), **{name: value})
                for name in ("resolution_id", "authorization_id", "session_id", "operation_id"):
                    with self.assertRaises(ValueError):
                        selection(**{name: value})
        for value in ("a", "X" * 128, "a_0-Z"):
            self.assertEqual(BrowserAdmittedResolution(value, admission()).resolution_id, value)

    def test_duplicate_local_ids_are_rejected_without_global_uniqueness_claim(self):
        auth = authorization()
        labels = ("resolution-1", "authorization-1", "session-1", "operation-1")
        for name in ("authorization_id", "session_id", "operation_id"):
            for label in labels:
                if label != getattr(auth, name):
                    with self.assertRaises(ValueError):
                        replace(auth, **{name: label})
        self.assertEqual(authorization(), authorization())  # No registry or single-use claim.

    def test_exact_record_and_scalar_types_no_callbacks(self):
        hostile = Hostile()
        for value in (None, {}, hostile, Mock()):
            with self.assertRaises(ValueError):
                BrowserAdmittedResolution("resolution-1", value)
            with self.assertRaises(ValueError):
                authorize_browser_connection(value, "authorization-1", "session-1", "operation-1")
            with self.assertRaises(ValueError):
                selection(value)
        subclass = AdmissionSubclass(ORIGIN, True, "allowed", IPS)
        with self.assertRaises(ValueError):
            BrowserAdmittedResolution("resolution-1", subclass)
        with self.assertRaises(ValueError):
            authorize_browser_connection(ResolutionSubclass("resolution-1", admission()), "authorization-1", "session-1", "operation-1")
        for value in (True, False, IntSubclass(443), 443.0, "443", 0, 65536, hostile):
            with self.assertRaises(ValueError):
                selection(port=value)
        for value in (None, 1, True, StringSubclass(IPS[0]), hostile, lambda: None):
            with self.assertRaises(ValueError):
                selection(selected_ip_address=value)
        for value in (OriginSubclass("https", "example.com", 443), hostile, "https://example.com",
                      BrowserOrigin(StringSubclass("https"), "example.com", 443),
                      BrowserOrigin("https", StringSubclass("example.com"), 443)):
            with self.assertRaises(ValueError):
                selection(origin=value)

    def test_fabricated_admission_rechecked_by_known_api(self):
        good = admission()
        for changes in (dict(admitted=False), dict(admitted=1), dict(reason="rejected"),
                        dict(admitted_ip_addresses=()), dict(admitted_ip_addresses=("10.0.0.1",)),
                        dict(admitted_ip_addresses=("::ffff:8.8.8.8",)),
                        dict(admitted_ip_addresses=(IPS[0], IPS[0])),
                        dict(admitted_ip_addresses=IPS + ("10.0.0.1",)),
                        dict(admitted_ip_addresses=TupleSubclass(IPS)),
                        dict(origin=BrowserOrigin("http", "example.com", 80))):
            forged = object.__new__(BrowserNetworkAdmissionDecision)
            for item in fields(good):
                object.__setattr__(forged, item.name, changes.get(item.name, getattr(good, item.name)))
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                BrowserAdmittedResolution("resolution-1", forged)
        # A coherent manually constructed record remains only structural data.
        manual = BrowserNetworkAdmissionDecision(ORIGIN, True, "allowed", IPS)
        self.assertEqual(BrowserAdmittedResolution("resolution-1", manual), resolution())

    def test_fabricated_nested_records_and_replace_are_revalidated(self):
        fake = object.__new__(BrowserAdmittedResolution)
        object.__setattr__(fake, "resolution_id", "resolution-1")
        object.__setattr__(fake, "admission", admission(("10.0.0.1",)))
        with self.assertRaises(ValueError):
            authorize_browser_connection(fake, "authorization-1", "session-1", "operation-1")
        fake_auth = object.__new__(BrowserConnectionAuthorization)
        for name, value in (("resolution", fake), ("authorization_id", "authorization-1"),
                            ("session_id", "session-1"), ("operation_id", "operation-1")):
            object.__setattr__(fake_auth, name, value)
        with self.assertRaises(ValueError):
            selection(fake_auth)
        with self.assertRaises(ValueError):
            replace(resolution(), admission=admission(()))
        self.assertFalse(replace(selection(), selected_ip_address="9.9.9.9").policy_allowed)

    def test_immutability_no_serializers_or_transport_claim_fields(self):
        for record in (resolution(), authorization(), selection()):
            self.assertFalse(hasattr(record, "__dict__"))
            first = fields(record)[0].name
            with self.assertRaises(FrozenInstanceError):
                setattr(record, first, None)
            for forbidden in ("verified_connection", "trusted_connection", "actual_peer",
                              "connected", "transport_secure", "authorized", "to_dict",
                              "to_json", "serialize", "cookies", "headers", "tokens"):
                self.assertFalse(hasattr(record, forbidden))
        with self.assertRaises(ValueError):
            replace(selection(), policy_allowed=True)
        self.assertIs(type(selection().policy_allowed), bool)
        self.assertIs(type(resolution().admission.admitted_ip_addresses), tuple)

    def test_errors_are_constant_and_do_not_echo_inputs(self):
        for value in ("DO_NOT_LEAK/SECRET", Hostile(), StringSubclass("DO_NOT_LEAK")):
            with self.assertRaises(ValueError) as error:
                BrowserAdmittedResolution(value, admission())
            self.assertEqual(str(error.exception), "invalid browser egress contract")
            self.assertIsNone(error.exception.__cause__)

    def test_no_external_operations(self):
        targets = ("socket.getaddrinfo", "socket.gethostbyname", "socket.socket",
                   "socket.create_connection", "urllib.request.urlopen",
                   "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
                   "builtins.open", "pathlib.Path.open", "subprocess.Popen", "os.system")
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(name, side_effect=AssertionError(name))) for name in targets]
            self.assertTrue(selection().policy_allowed)
            self.assertFalse(selection(selected_ip_address="169.254.169.254").policy_allowed)
            for mock in mocks:
                mock.assert_not_called()
        tree = ast.parse(inspect.getsource(contract))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"__future__", "re", "dataclasses",
                                  "jarvis.core.browser_operation_contract",
                                  "jarvis.core.browser_network_policy"})
        self.assertIs(contract.BrowserOrigin, BrowserOrigin)
        self.assertIs(contract.BrowserNetworkAdmissionDecision, BrowserNetworkAdmissionDecision)
        self.assertIs(contract.evaluate_browser_network_resolution, evaluate_browser_network_resolution)


if __name__ == "__main__":
    unittest.main()
