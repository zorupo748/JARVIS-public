import ast
import inspect
import socket
import threading
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock, patch

import jarvis.core.browser_dns_resolver as resolver
from jarvis.core.browser_dns_resolver import (
    BrowserDNSResolutionLimits, BrowserDNSResolutionResult, resolve_browser_dns,
)
from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_network_policy import (
    BrowserNetworkAdmissionDecision, evaluate_browser_network_resolution,
)
from jarvis.core.browser_egress_contract import BrowserAdmittedResolution

ORIGIN = BrowserOrigin("https", "example.com", 443)
ALLOWLIST = frozenset({ORIGIN})
PUBLIC4 = "8.8.8.8"
PUBLIC6 = "2606:4700:4700::1111"


def record(address=PUBLIC4, family=socket.AF_INET):
    sockaddr = (address, 443) if family == socket.AF_INET else (address, 443, 0, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def run(records=None, **kwargs):
    with patch.object(resolver.socket, "getaddrinfo", return_value=[record()] if records is None else records) as dns:
        result = resolve_browser_dns(ORIGIN, ALLOWLIST, **kwargs)
    dns.assert_called_once_with("example.com", 443, family=socket.AF_UNSPEC,
                                type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=0)
    return result


class StringSubclass(str):
    pass


class IntSubclass(int):
    pass


class ListSubclass(list):
    pass


class TupleSubclass(tuple):
    pass


class FrozensetSubclass(frozenset):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class Hostile:
    def fail(self, *args, **kwargs):
        raise AssertionError("untrusted callback executed")
    __str__ = __eq__ = __hash__ = __iter__ = __len__ = __call__ = fail

    @property
    def __class__(self):
        return self.fail()


class BrowserDNSResolverTests(unittest.TestCase):
    def assert_infrastructure_error(self, result, error):
        self.assertEqual(result.status, "infrastructure_error")
        self.assertEqual(result.infrastructure_error, error)
        self.assertIsNone(result.admission)

    def test_ipv4_ipv6_and_all_public_addresses(self):
        for records, expected in (([record()], (PUBLIC4,)),
                                  ([record(PUBLIC6, socket.AF_INET6)], (PUBLIC6,)),
                                  ([record(), record(PUBLIC6, socket.AF_INET6), record("1.1.1.1")],
                                   (PUBLIC4, PUBLIC6, "1.1.1.1"))):
            with self.subTest(records=records):
                result = run(records)
                self.assertEqual(result.status, "admitted")
                self.assertIsNone(result.infrastructure_error)
                self.assertEqual(result.admission, evaluate_browser_network_resolution(ORIGIN, ALLOWLIST, expected))
                admitted = BrowserAdmittedResolution("resolution-1", result.admission)
                self.assertEqual(admitted.admission.admitted_ip_addresses, expected)

    def test_native_integer_and_python_socket_enum_records(self):
        native = (int(socket.AF_INET), int(socket.SOCK_STREAM), int(socket.IPPROTO_TCP), "", (PUBLIC4, 443))
        self.assertEqual(run([native]).status, "admitted")
        self.assertEqual(run([record()]).status, "admitted")

    def test_noncanonical_ipv6_uses_existing_policy_canonicalization(self):
        expanded = "2606:4700:4700:0:0:0:0:1111"
        result = run([record(expanded, socket.AF_INET6)])
        self.assertEqual(result.admission.admitted_ip_addresses, (PUBLIC6,))

    def test_private_special_metadata_mapped_and_mixed_are_denied_whole(self):
        blocked4 = ("10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
                    "169.254.169.254", "100.64.0.1", "192.0.2.1", "0.0.0.0", "224.0.0.1")
        blocked6 = ("::", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:8.8.8.8")
        for ip, family in [(ip, socket.AF_INET) for ip in blocked4] + [(ip, socket.AF_INET6) for ip in blocked6]:
            for records, ips in (([record(ip, family)], (ip,)),
                                 ([record(), record(ip, family)], (PUBLIC4, ip)),
                                 ([record(ip, family), record()], (ip, PUBLIC4))):
                with self.subTest(ip=ip, ips=ips):
                    result = run(records)
                    self.assertEqual(result.status, "rejected")
                    self.assertEqual(result.admission, evaluate_browser_network_resolution(ORIGIN, ALLOWLIST, ips))
                    self.assertEqual(result.admission.admitted_ip_addresses, ())
                    self.assertNotIn(ip, repr(result))
                    with self.assertRaises(ValueError):
                        BrowserAdmittedResolution("resolution-1", result.admission)

    def test_invalid_text_not_silently_removed(self):
        for ip in ("", "not-an-ip", " 8.8.8.8", "008.8.8.8", "8.8.8.8\x00", "fe80::1%eth0"):
            records = [record(), record(ip, socket.AF_INET6 if ":" in ip else socket.AF_INET)]
            result = run(records)
            self.assertEqual(result.status, "rejected")
            self.assertEqual(result.admission.reason, "invalid_address")
            self.assertEqual(result.admission.admitted_ip_addresses, ())

    def test_duplicates_preserved_including_equivalent_ipv6_spellings(self):
        for records in ([record(), record()],
                        [record(PUBLIC6, socket.AF_INET6), record("2606:4700:4700:0:0:0:0:1111", socket.AF_INET6)]):
            result = run(records)
            self.assertEqual(result.status, "rejected")
            self.assertEqual(result.admission.reason, "duplicate_address")
            self.assertEqual(result.admission.admitted_ip_addresses, ())

    def test_empty_response_is_policy_denial(self):
        result = run([])
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.admission.reason, "empty_resolution")
        self.assertIsNone(result.infrastructure_error)

    def test_evaluator_receives_entire_snapshot_once_after_lookup(self):
        ips = (PUBLIC4, "10.0.0.1", "invalid")
        with patch.object(resolver, "evaluate_browser_network_resolution", wraps=evaluate_browser_network_resolution) as policy:
            result = run([record(ip) for ip in ips])
        self.assertEqual(result.admission.reason, "invalid_address")
        self.assertEqual(policy.call_count, 2)  # Empty preflight plus complete snapshot.
        self.assertEqual(policy.call_args_list[0].args, (ORIGIN, ALLOWLIST, ()))
        self.assertEqual(policy.call_args_list[1].args, (ORIGIN, ALLOWLIST, ips))

    def test_unauthorized_http_and_non443_never_query(self):
        origins = (BrowserOrigin("https", "other.example", 443),
                   BrowserOrigin("https", "sub.example.com", 443),
                   BrowserOrigin("http", "example.com", 80),
                   BrowserOrigin("https", "example.com", 8443))
        with patch.object(resolver.socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")) as dns:
            for origin in origins:
                for allowed in (ALLOWLIST, frozenset({origin})):
                    if origin.scheme == "https" and origin.effective_port == 443 and origin in allowed:
                        continue
                    result = resolve_browser_dns(origin, allowed)
                    expected = evaluate_browser_network_resolution(origin, allowed, ())
                    self.assertEqual(result.status, "rejected")
                    self.assertEqual(result.admission, expected)
            dns.assert_not_called()

    def test_invalid_origins_and_allowlists_never_query_or_run_callbacks(self):
        hostile = Hostile()
        origins = (None, "https://example.com", hostile, OriginSubclass("https", "example.com", 443),
                   BrowserOrigin(StringSubclass("https"), "example.com", 443),
                   BrowserOrigin("https", StringSubclass("example.com"), 443))
        invalid_allowlists = (None, [], {ORIGIN}, (), frozenset(), FrozensetSubclass({ORIGIN}),
                             frozenset({"https://example.com"}), frozenset(origins[-3:-2]))
        forged = object.__new__(BrowserOrigin)
        for name, value in (("scheme", "https"), ("hostname", "*.example.com"), ("effective_port", 443)):
            object.__setattr__(forged, name, value)
        with patch.object(resolver.socket, "getaddrinfo") as dns:
            for origin in origins + (forged,):
                with self.assertRaisesRegex(ValueError, "^invalid browser DNS resolver input$"):
                    resolve_browser_dns(origin, ALLOWLIST)
            for allowed in invalid_allowlists:
                with self.assertRaises(ValueError):
                    resolve_browser_dns(ORIGIN, allowed)
            for port in (True, IntSubclass(443)):
                object.__setattr__(forged, "hostname", "example.com")
                object.__setattr__(forged, "effective_port", port)
                with self.assertRaises(ValueError):
                    resolve_browser_dns(forged, frozenset({forged}))
            dns.assert_not_called()

    def test_allowlist_limit_reused_and_no_suffix_matching(self):
        allowed16 = ALLOWLIST | frozenset(BrowserOrigin("https", f"host-{i}.example", 443) for i in range(15))
        with patch.object(resolver.socket, "getaddrinfo", return_value=[record()]) as dns:
            self.assertEqual(resolve_browser_dns(ORIGIN, allowed16).status, "admitted")
            with self.assertRaises(ValueError):
                resolve_browser_dns(ORIGIN, allowed16 | {BrowserOrigin("https", "extra.example", 443)})
            dns.assert_called_once()

    def test_dns_and_infrastructure_exceptions_are_sanitized_and_not_retried(self):
        for exception, expected in ((socket.gaierror(socket.EAI_NONAME, "INTERNAL_SECRET"), "dns_error"),
                                    (socket.gaierror(socket.EAI_AGAIN, "INTERNAL_SECRET"), "dns_error"),
                                    (OSError("INTERNAL_SECRET"), "dns_error"),
                                    (TimeoutError("INTERNAL_SECRET"), "resolver_timeout"),
                                    (MemoryError("INTERNAL_SECRET"), "resource_limit"),
                                    (RuntimeError("INTERNAL_SECRET"), "resolver_error")):
            with self.subTest(exception=type(exception)), patch.object(resolver.socket, "getaddrinfo", side_effect=exception) as dns:
                result = resolve_browser_dns(ORIGIN, ALLOWLIST)
                self.assert_infrastructure_error(result, expected)
                self.assertNotIn("INTERNAL_SECRET", repr(result))
                dns.assert_called_once()
            self.assertEqual(run().status, "admitted")  # Slot released on every failure.

    def test_process_control_exceptions_release_slot(self):
        for exception in (KeyboardInterrupt(), SystemExit()):
            with patch.object(resolver.socket, "getaddrinfo", side_effect=exception):
                with self.assertRaises(type(exception)):
                    resolve_browser_dns(ORIGIN, ALLOWLIST)
            self.assertEqual(run().status, "admitted")

    def test_response_record_limits_reject_without_truncation(self):
        records = [record(f"8.8.8.{i}") for i in range(1, 65)]
        self.assertEqual(run(records).status, "admitted")
        self.assert_infrastructure_error(run(records + [record("10.0.0.1")]), "resource_limit")
        self.assert_infrastructure_error(run(records, limits=BrowserDNSResolutionLimits(max_records=63)), "resource_limit")
        self.assertEqual(run([record()], limits=BrowserDNSResolutionLimits(max_records=1)).status, "admitted")

    def test_string_resource_limits_reject_whole_response(self):
        self.assert_infrastructure_error(run([record(), record("x" * 65)]), "resource_limit")
        long_name = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "x" * 254, (PUBLIC4, 443))
        self.assert_infrastructure_error(run([record(), long_name]), "resource_limit")

    def test_malformed_responses_never_authorize_public_subset(self):
        bad_records = (None, (), (socket.AF_INET,), TupleSubclass(record()),
                       (999, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC4, 443)),
                       (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_TCP, "", (PUBLIC4, 443)),
                       (socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC4, 443)),
                       (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, Hostile(), (PUBLIC4, 443)),
                       record(PUBLIC6), record(PUBLIC4, socket.AF_INET6),
                       (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC4, 80)),
                       (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC4, True)),
                       (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", [PUBLIC4, 443]),
                       (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (StringSubclass(PUBLIC4), 443)),
                       (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC6, 443, 0, 1)),
                       (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC6, 443, 1, 0)),
                       (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC6, 443, 0, False)))
        for bad in bad_records:
            with self.subTest(record_type=type(bad)):
                self.assert_infrastructure_error(run([record(), bad]), "malformed_response")
        for response in ((), ListSubclass([record()]), Hostile(), iter([record()])):
            self.assert_infrastructure_error(run(response), "malformed_response")

    def test_elapsed_budget_checked_after_lookup_and_admission(self):
        limit = BrowserDNSResolutionLimits(max_elapsed_ms=1)
        for ticks in ((0, 1_000_001), (0, 0, 1_000_001)):
            with patch.object(resolver.time, "monotonic_ns", side_effect=ticks):
                self.assert_infrastructure_error(run(limits=limit), "elapsed_budget_exceeded")
        with patch.object(resolver.time, "monotonic_ns", side_effect=(0, 1_000_000, 1_000_000)):
            self.assertEqual(run(limits=limit).status, "admitted")
        # No worker cancellation/return-time claim: only post-return acceptance.
        self.assertIn("NOT a bound", resolver.__doc__)

    def test_limits_validate_exact_types_and_forged_records_before_dns(self):
        for name, values in (("max_records", (0, 65, True, IntSubclass(1), 1.0, "1", Hostile())),
                             ("max_elapsed_ms", (0, 60_001, True, IntSubclass(1), None, Hostile()))):
            for value in values:
                with self.assertRaises(ValueError):
                    BrowserDNSResolutionLimits(**{name: value})
        with patch.object(resolver.socket, "getaddrinfo") as dns:
            for limits in (None, {}, Hostile()):
                with self.assertRaises(ValueError):
                    resolve_browser_dns(ORIGIN, ALLOWLIST, limits=limits)
            fake = object.__new__(BrowserDNSResolutionLimits)
            object.__setattr__(fake, "max_records", 65)
            object.__setattr__(fake, "max_elapsed_ms", 1)
            with self.assertRaises(ValueError):
                resolve_browser_dns(ORIGIN, ALLOWLIST, limits=fake)
            dns.assert_not_called()

    def test_concurrent_request_is_rejected_without_dns_or_queue(self):
        entered = threading.Event()
        release = threading.Event()
        results = []

        def blocked_lookup(*args, **kwargs):
            entered.set()
            if not release.wait(2):
                raise AssertionError("test worker was not released")
            return [record()]

        with patch.object(resolver.socket, "getaddrinfo", side_effect=blocked_lookup) as dns:
            worker = threading.Thread(target=lambda: results.append(resolve_browser_dns(ORIGIN, ALLOWLIST)))
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assert_infrastructure_error(resolve_browser_dns(ORIGIN, ALLOWLIST), "resolver_busy")
                dns.assert_called_once()
            finally:
                release.set()
                worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(results[0].status, "admitted")
        self.assertEqual(run().status, "admitted")

    def test_result_coherence_frozen_slots_and_no_transport_claims(self):
        good = run()
        denied = run([])
        error = BrowserDNSResolutionResult(ORIGIN, None, "dns_error")
        for result in (good, denied, error, BrowserDNSResolutionLimits()):
            self.assertFalse(hasattr(result, "__dict__"))
            with self.assertRaises(FrozenInstanceError):
                setattr(result, fields(result)[0].name, None)
            for name in ("connected", "verified_connection", "trusted_connection", "actual_peer",
                         "transport_secure", "authenticated", "pinned", "to_dict", "to_json", "serialize"):
                self.assertFalse(hasattr(result, name))
        for decision, code in ((None, None), (good.admission, "dns_error"), (None, "INTERNAL_SECRET"),
                               (None, StringSubclass("dns_error")), (Hostile(), None)):
            with self.assertRaises(ValueError):
                BrowserDNSResolutionResult(ORIGIN, decision, code)
        with self.assertRaises(ValueError):
            replace(good, origin=BrowserOrigin("https", "other.example", 443))
        fake = object.__new__(BrowserNetworkAdmissionDecision)
        for name, value in (("origin", ORIGIN), ("admitted", True), ("reason", "allowed"),
                            ("admitted_ip_addresses", ("10.0.0.1",))):
            object.__setattr__(fake, name, value)
        with self.assertRaises(ValueError):
            BrowserDNSResolutionResult(ORIGIN, fake, None)

    def test_no_connections_logs_global_timeouts_or_other_external_operations(self):
        targets = ("socket.socket", "socket.create_connection", "socket.gethostbyname",
                   "socket.setdefaulttimeout", "urllib.request.urlopen",
                   "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
                   "subprocess.Popen", "os.system", "builtins.open", "pathlib.Path.open",
                   "logging.Logger._log")
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(name, side_effect=AssertionError(name))) for name in targets]
            self.assertEqual(run().status, "admitted")
            self.assertEqual(run([record("169.254.169.254")]).status, "rejected")
            for mock in mocks:
                mock.assert_not_called()
        imports = set()
        for node in ast.walk(ast.parse(inspect.getsource(resolver))):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"__future__", "ipaddress", "socket", "threading", "time", "dataclasses",
                                  "jarvis.core.browser_operation_contract", "jarvis.core.browser_network_policy"})
        self.assertIs(resolver.BrowserOrigin, BrowserOrigin)
        self.assertIs(resolver.evaluate_browser_network_resolution, evaluate_browser_network_resolution)
        callback = Mock(side_effect=AssertionError("resolver injection"))
        with self.assertRaises(TypeError):
            resolve_browser_dns(ORIGIN, ALLOWLIST, resolver=callback)
        callback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
