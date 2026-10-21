import ast
import inspect
import os
import socket
import ssl
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import Mock, patch

import jarvis.core.browser_https_broker as broker
from jarvis.core.browser_https_broker import (
    BrowserHTTPSBrokerError, BrowserHTTPSBrokerLimits, open_browser_https_connection,
)
from jarvis.core.browser_dns_resolver import BrowserDNSResolutionResult, resolve_browser_dns
from jarvis.core.browser_egress_contract import (
    BrowserAdmittedResolution, BrowserConnectionAuthorization, evaluate_browser_egress_destination,
)
from jarvis.core.browser_network_policy import BrowserNetworkAdmissionDecision
from jarvis.core.browser_operation_contract import BrowserOrigin

ORIGIN = BrowserOrigin("https", "example.com", 443)
ALLOWLIST = frozenset({ORIGIN})
PUBLIC4 = "8.8.8.8"
PUBLIC6 = "2606:4700:4700::1111"
SOCKET_TYPE = socket.socket
TLS_SOCKET_TYPE = ssl.SSLSocket
SSL_CONTEXT_TYPE = ssl.SSLContext


def record(ip=PUBLIC4, family=socket.AF_INET):
    peer = (ip, 443) if family == socket.AF_INET else (ip, 443, 0, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", peer)


def open_connection(**overrides):
    values = dict(origin=ORIGIN, allowed_origins=ALLOWLIST, resolution_id="resolution-1",
                  authorization_id="authorization-1", session_id="session-1", operation_id="operation-1")
    values.update(overrides)
    return open_browser_https_connection(**values)


class StringSubclass(str):
    pass


class IntSubclass(int):
    pass


class TupleSubclass(tuple):
    pass


class FrozenSetSubclass(frozenset):
    pass


class OriginSubclass(BrowserOrigin):
    __slots__ = ()


class Hostile:
    def fail(self, *args, **kwargs):
        raise AssertionError("input callback executed")
    __str__ = __eq__ = __hash__ = __len__ = __iter__ = __call__ = fail

    @property
    def __class__(self):
        return self.fail()


class BrowserHTTPSBrokerTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.tcp = Mock(spec=SOCKET_TYPE)
        self.tls = Mock(spec=TLS_SOCKET_TYPE)
        self.tcp.getpeername.return_value = (PUBLIC4, 443)
        self.tls.getpeername.return_value = (PUBLIC4, 443)
        self.dns = self.stack.enter_context(patch("socket.getaddrinfo", return_value=[record()]))
        self.factory = self.stack.enter_context(patch.object(broker.socket, "socket", return_value=self.tcp))
        self.load_certs = self.stack.enter_context(patch.object(SSL_CONTEXT_TYPE, "load_default_certs", autospec=True))
        self.wrap = self.stack.enter_context(patch.object(SSL_CONTEXT_TYPE, "wrap_socket", autospec=True, side_effect=self.wrap_tls))
        self.clock = self.stack.enter_context(patch.object(broker.time, "monotonic_ns", return_value=0))
        self.events = []
        self.tcp.connect.side_effect = lambda target: self.events.append(("connect", target))
        self.tcp.getpeername.side_effect = lambda: self.peer("tcp_peer", self.tcp.getpeername.return_value)
        self.tls.getpeername.side_effect = lambda: self.peer("tls_peer", self.tls.getpeername.return_value)
        self.tls.do_handshake.side_effect = lambda: self.events.append(("handshake",))
        self.env = self.stack.enter_context(patch.dict(os.environ, {
            "HTTPS_PROXY": "http://127.0.0.1:3128", "ALL_PROXY": "http://127.0.0.1:3128",
            "SSLKEYLOGFILE": "/must-not-be-used/secret-keys.log",
        }))

    def peer(self, kind, value):
        self.events.append((kind, value))
        return value

    def wrap_tls(self, context, tcp, **kwargs):
        self.events.append(("wrap", kwargs["server_hostname"]))
        self.tls.context = context
        self.tls.server_hostname = kwargs["server_hostname"]
        return self.tls

    def assert_failure(self, code, **overrides):
        with self.assertRaises(BrowserHTTPSBrokerError) as caught:
            with open_connection(**overrides):
                self.fail("failed establishment exposed a connection")
        self.assertEqual(str(caught.exception), code)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("INTERNAL_SECRET", repr(caught.exception))
        return caught.exception

    def assert_no_socket(self):
        self.factory.assert_not_called()
        self.wrap.assert_not_called()
        self.tcp.connect.assert_not_called()

    def test_numeric_ipv4_pinning_sni_tls_and_actual_peers(self):
        with open_connection() as transport:
            self.assertIs(transport, self.tls)
            self.tls.close.assert_not_called()
            self.factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.tcp.connect.assert_called_once_with((PUBLIC4, 443))
            context, wrapped_tcp = self.wrap.call_args.args
            self.assertIs(wrapped_tcp, self.tcp)
            self.assertEqual(self.wrap.call_args.kwargs, dict(
                server_hostname="example.com", do_handshake_on_connect=False,
                suppress_ragged_eofs=False,
            ))
            self.assertIs(context.check_hostname, True)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(context.protocol, ssl.PROTOCOL_TLS_CLIENT)
            self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertIsNone(context.keylog_filename)
            self.load_certs.assert_called_once_with(context, ssl.Purpose.SERVER_AUTH)
            self.tls.do_handshake.assert_called_once_with()
            self.assertEqual([event[0] for event in self.events], ["connect", "tcp_peer", "wrap", "handshake", "tls_peer"])
        self.tls.close.assert_called_once_with()
        self.tcp.close.assert_called_once_with()
        self.dns.assert_called_once_with("example.com", 443, family=socket.AF_UNSPEC,
                                         type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=0)

    def test_ipv6_family_numeric_destination_and_peer(self):
        self.dns.return_value = [record(PUBLIC6, socket.AF_INET6)]
        self.tcp.getpeername.return_value = (PUBLIC6, 443, 0, 0)
        self.tls.getpeername.return_value = (PUBLIC6, 443, 0, 0)
        with open_connection():
            self.factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.tcp.connect.assert_called_once_with((PUBLIC6, 443, 0, 0))
            self.assertEqual(self.tls.server_hostname, "example.com")
        self.dns.assert_called_once()

    def test_select_second_admitted_ip_without_fallback_or_second_dns(self):
        self.dns.return_value = [record(), record("1.1.1.1")]
        self.tcp.getpeername.return_value = ("1.1.1.1", 443)
        self.tls.getpeername.return_value = ("1.1.1.1", 443)
        with patch.object(broker, "resolve_browser_dns", wraps=resolve_browser_dns) as lookup:
            with patch.object(broker, "BrowserConnectionAuthorization", wraps=BrowserConnectionAuthorization) as auth:
                with open_connection(selected_ip_address="1.1.1.1"):
                    self.tcp.connect.assert_called_once_with(("1.1.1.1", 443))
                self.assertEqual(auth.call_args.args[0].admission.admitted_ip_addresses, (PUBLIC4, "1.1.1.1"))
            lookup.assert_called_once()
        self.dns.assert_called_once()

    def test_egress_contract_checks_selection_and_both_measured_peers(self):
        with patch.object(broker, "evaluate_browser_egress_destination", wraps=evaluate_browser_egress_destination) as policy:
            with open_connection():
                pass
        self.assertEqual(policy.call_count, 3)
        for call in policy.call_args_list:
            self.assertEqual(call.kwargs["selected_ip_address"], PUBLIC4)
            self.assertEqual(call.kwargs["port"], 443)
            self.assertEqual(call.kwargs["origin"], ORIGIN)
            self.assertEqual(type(call.args[0]), BrowserConnectionAuthorization)
            self.assertEqual(type(call.args[0].resolution), BrowserAdmittedResolution)

    def test_out_of_snapshot_private_mapped_noncanonical_and_empty_selection(self):
        for ip in ("9.9.9.9", "10.0.0.1", "169.254.169.254", "::ffff:8.8.8.8", "", "008.8.8.8"):
            with self.subTest(ip=ip):
                self.assert_failure("destination_denied", selected_ip_address=ip)
                self.assert_no_socket()
        self.dns.return_value = [record(PUBLIC6, socket.AF_INET6)]
        self.assert_failure("destination_denied", selected_ip_address="2606:4700:4700:0:0:0:0:1111")
        self.assert_no_socket()

    def test_private_metadata_mixed_duplicates_and_empty_resolution_open_no_socket(self):
        cases = ([record("10.0.0.1")], [record("169.254.169.254")],
                 [record(), record("10.0.0.1")], [record(), record()], [],
                 [record("::ffff:8.8.8.8", socket.AF_INET6)], [record(), record("invalid")])
        for records in cases:
            self.dns.return_value = records
            self.assert_failure("resolution_denied")
            self.assert_no_socket()

    def test_http_other_port_and_unauthorized_origin_no_dns_or_socket(self):
        for origin, allowed in ((BrowserOrigin("http", "example.com", 80), None),
                                (BrowserOrigin("https", "example.com", 8443), None),
                                (BrowserOrigin("https", "other.example", 443), ALLOWLIST),
                                (BrowserOrigin("https", "sub.example.com", 443), ALLOWLIST)):
            self.assert_failure("resolution_denied", origin=origin,
                                allowed_origins=frozenset({origin}) if allowed is None else allowed)
            self.dns.assert_not_called()
            self.assert_no_socket()

    def test_invalid_inputs_and_subclasses_no_callbacks_dns_or_socket(self):
        for origin in (None, "https://example.com", Hostile(), OriginSubclass("https", "example.com", 443),
                       BrowserOrigin(StringSubclass("https"), "example.com", 443)):
            self.assert_failure("invalid_input", origin=origin)
        for value in (None, [], {ORIGIN}, FrozenSetSubclass(ALLOWLIST), frozenset(), frozenset({"example.com"})):
            self.assert_failure("invalid_input", allowed_origins=value)
        for value in (True, 1, StringSubclass(PUBLIC4), Hostile()):
            self.assert_failure("invalid_input", selected_ip_address=value)
        for name in ("resolution_id", "authorization_id", "session_id", "operation_id"):
            self.assert_failure("invalid_input", **{name: Hostile()})
        for value in (None, {}, Hostile()):
            self.assert_failure("invalid_input", limits=value)
        self.dns.assert_not_called()
        self.assert_no_socket()

    def test_malformed_and_duplicate_ids_revalidated_by_egress_before_socket(self):
        for name in ("resolution_id", "authorization_id", "session_id", "operation_id"):
            for value in ("", " id", "a/b", "x" * 129):
                self.assert_failure("invalid_input", **{name: value})
                self.assert_no_socket()
        self.assert_failure("invalid_input", authorization_id="resolution-1")
        self.assert_no_socket()

    def test_forged_dns_records_are_not_accepted_as_credential(self):
        fake_decision = object.__new__(BrowserNetworkAdmissionDecision)
        for name, value in (("origin", ORIGIN), ("admitted", True), ("reason", "allowed"),
                            ("admitted_ip_addresses", ("10.0.0.1",))):
            object.__setattr__(fake_decision, name, value)
        fake_result = object.__new__(BrowserDNSResolutionResult)
        for name, value in (("origin", ORIGIN), ("admission", fake_decision), ("infrastructure_error", None)):
            object.__setattr__(fake_result, name, value)
        for value in (None, {}, Hostile(), fake_result):
            with patch.object(broker, "resolve_browser_dns", return_value=value):
                self.assert_failure("dns_failed")
            self.assert_no_socket()

    def test_dns_origin_substitution_is_rejected(self):
        other = BrowserOrigin("https", "other.example", 443)
        result = BrowserDNSResolutionResult(other, BrowserNetworkAdmissionDecision(other, True, "allowed", (PUBLIC4,)), None)
        with patch.object(broker, "resolve_browser_dns", return_value=result):
            self.assert_failure("dns_failed")
        self.assert_no_socket()

    def test_actual_tcp_peer_mismatch_prevents_tls(self):
        self.dns.return_value = [record(), record("1.1.1.1")]
        for peer in (("1.1.1.1", 443), ("10.0.0.1", 443), (PUBLIC4, 8443),
                     (PUBLIC4, True), ("::ffff:8.8.8.8", 443), (PUBLIC6, 443),
                     [PUBLIC4, 443], TupleSubclass((PUBLIC4, 443)), (Hostile(), 443), ()):
            self.tcp.getpeername.return_value = peer
            self.assert_failure("peer_mismatch")
            self.wrap.assert_not_called()
            self.tls.do_handshake.assert_not_called()
        self.assertEqual(self.tcp.close.call_count, 10)

    def test_post_handshake_peer_mismatch_closes_both_sockets(self):
        self.tls.getpeername.return_value = ("1.1.1.1", 443)
        self.assert_failure("peer_mismatch")
        self.tls.do_handshake.assert_called_once()
        self.tls.close.assert_called_once()
        self.tcp.close.assert_called_once()

    def test_ipv6_peer_mapped_family_scope_and_flow_mismatch(self):
        self.dns.return_value = [record(PUBLIC6, socket.AF_INET6)]
        for peer in ((PUBLIC6, 443, 0, 1), (PUBLIC6, 443, 1, 0), (PUBLIC6 + "%0", 443, 0, 0),
                     (PUBLIC4, 443, 0, 0), (PUBLIC6, 443, 0, False), (PUBLIC6, 443)):
            self.tcp.getpeername.return_value = peer
            self.assert_failure("peer_mismatch")
            self.wrap.assert_not_called()

    def test_unsafe_tls_context_rejected_before_socket(self):
        context = SSL_CONTEXT_TYPE(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        with patch.object(broker, "_create_tls_context", return_value=context):
            self.assert_failure("tls_failed")
        context.verify_mode = ssl.CERT_NONE
        with patch.object(broker, "_create_tls_context", return_value=context):
            self.assert_failure("tls_failed")
        self.assert_no_socket()

    def test_no_caller_injected_resolver_socket_or_tls_context(self):
        callback = Mock(side_effect=AssertionError("input executed"))
        for name in ("resolver", "socket_factory", "ssl_context", "connection", "admission", "authorization"):
            with self.assertRaises(TypeError):
                open_connection(**{name: callback})
        callback.assert_not_called()
        self.dns.assert_not_called()
        self.assert_no_socket()

    def test_dns_failure_no_sockets_and_slot_released(self):
        self.dns.side_effect = socket.gaierror(socket.EAI_NONAME, "INTERNAL_SECRET")
        self.assert_failure("dns_failed")
        self.assert_no_socket()
        self.dns.side_effect = None
        with open_connection():
            pass

    def test_tcp_error_no_retry_fallback_or_tls_and_close(self):
        self.dns.return_value = [record(), record("1.1.1.1")]
        self.tcp.connect.side_effect = OSError("INTERNAL_SECRET")
        self.assert_failure("tcp_failed")
        self.tcp.connect.assert_called_once_with((PUBLIC4, 443))
        self.wrap.assert_not_called()
        self.tcp.close.assert_called_once()
        self.dns.assert_called_once()

    def test_socket_creation_settimeout_and_peer_query_errors_are_closed(self):
        self.factory.side_effect = OSError("INTERNAL_SECRET")
        self.assert_failure("tcp_failed")
        self.tcp.close.assert_not_called()
        self.factory.side_effect = None
        self.tcp.settimeout.side_effect = OSError("INTERNAL_SECRET")
        self.assert_failure("tcp_failed")
        self.tcp.close.assert_called_once()
        self.tcp.settimeout.side_effect = None
        self.tcp.getpeername.side_effect = OSError("INTERNAL_SECRET")
        self.assert_failure("tcp_failed")
        self.wrap.assert_not_called()
        self.assertEqual(self.tcp.close.call_count, 2)

    def test_tls_wrap_and_handshake_failures_close_resources(self):
        self.wrap.side_effect = ssl.SSLError("INTERNAL_SECRET")
        self.assert_failure("tls_failed")
        self.tcp.close.assert_called_once()
        self.tls.close.assert_not_called()
        self.wrap.side_effect = self.wrap_tls
        self.tls.do_handshake.side_effect = ssl.SSLCertVerificationError(1, "INTERNAL_SECRET")
        self.assert_failure("tls_failed")
        self.tls.close.assert_called_once()
        self.assertEqual(self.tcp.close.call_count, 2)

    def test_ca_loading_failure_opens_no_socket(self):
        self.load_certs.side_effect = OSError("INTERNAL_SECRET")
        self.assert_failure("tls_failed")
        self.assert_no_socket()

    def test_tls_configuration_cannot_be_changed_during_handshake(self):
        def tamper():
            self.tls.context.check_hostname = False
        self.tls.do_handshake.side_effect = tamper
        self.assert_failure("tls_failed")
        self.tls.close.assert_called_once()
        self.tcp.close.assert_called_once()

    def test_tcp_and_handshake_timeouts_are_distinct_stages_and_close(self):
        limits = BrowserHTTPSBrokerLimits(tcp_timeout_ms=2_000, tls_timeout_ms=3_000)
        self.tcp.connect.side_effect = TimeoutError("INTERNAL_SECRET")
        self.assert_failure("timeout", limits=limits)
        self.tcp.settimeout.assert_called_once_with(2.0)
        self.wrap.assert_not_called()
        self.tcp.connect.side_effect = None
        self.tls.do_handshake.side_effect = TimeoutError("INTERNAL_SECRET")
        self.assert_failure("timeout", limits=limits)
        self.tls.settimeout.assert_called_once_with(3.0)
        self.tls.close.assert_called_once()
        self.assertEqual(self.tcp.close.call_count, 2)

    def test_establishment_budget_caps_tcp_and_tls_timeouts(self):
        limits = BrowserHTTPSBrokerLimits(tcp_timeout_ms=5_000, tls_timeout_ms=5_000,
                                         establishment_budget_ms=1_000)
        self.now = 0
        self.clock.side_effect = lambda: self.now
        def tcp_elapsed(target):
            self.now = 750_000_000
        self.tcp.connect.side_effect = tcp_elapsed
        with open_connection(limits=limits):
            self.assertEqual(self.tcp.settimeout.call_args_list[0].args, (1.0,))
            self.tls.settimeout.assert_called_once_with(0.25)

    def test_late_tcp_and_late_tls_fail_closed(self):
        limits = BrowserHTTPSBrokerLimits(establishment_budget_ms=1_000)
        self.now = 0
        self.clock.side_effect = lambda: self.now
        self.tcp.connect.side_effect = lambda target: setattr(self, "now", 1_000_000_000)
        self.assert_failure("budget_exceeded", limits=limits)
        self.wrap.assert_not_called()
        self.tcp.close.assert_called_once()
        self.now = 0
        self.tcp.connect.side_effect = None
        self.tls.do_handshake.side_effect = lambda: setattr(self, "now", 1_000_000_001)
        self.assert_failure("budget_exceeded", limits=limits)
        self.tls.close.assert_called_once()
        self.assertEqual(self.tcp.close.call_count, 2)

    def test_synchronous_dns_time_is_not_presented_as_total_timeout(self):
        self.now = 0
        self.clock.side_effect = lambda: self.now
        def slow_dns(*args, **kwargs):
            self.now = 4_000_000_000
            return [record()]
        self.dns.side_effect = slow_dns
        limits = BrowserHTTPSBrokerLimits(establishment_budget_ms=1_000)
        with open_connection(limits=limits):
            self.assertEqual(self.tcp.settimeout.call_args_list[0].args, (1.0,))
        self.assertIn("NOT a", broker.__doc__)
        self.assertIn("post-DNS", broker.__doc__)

    def test_excessive_selection_input_is_rejected_before_dns(self):
        self.assert_failure("invalid_input", selected_ip_address="x" * 65)
        self.dns.assert_not_called()
        self.assert_no_socket()

    def test_late_ca_loading_rejects_before_socket_allocation(self):
        self.now = 0
        self.clock.side_effect = lambda: self.now
        self.load_certs.side_effect = lambda *args: setattr(self, "now", 1_000_000_000)
        self.assert_failure("budget_exceeded", limits=BrowserHTTPSBrokerLimits(establishment_budget_ms=1_000))
        self.assert_no_socket()

    def test_wrong_tls_hostname_or_context_rejected_before_handshake(self):
        def wrong_hostname(context, tcp, **kwargs):
            tls = self.wrap_tls(context, tcp, **kwargs)
            tls.server_hostname = "other.example"
            return tls
        self.wrap.side_effect = wrong_hostname
        self.assert_failure("tls_failed")
        self.tls.do_handshake.assert_not_called()
        self.tls.close.assert_called_once()
        self.tcp.close.assert_called_once()

    def test_dns_budget_violation_opens_no_socket(self):
        self.now = 0
        self.clock.side_effect = lambda: self.now
        def very_slow_dns(*args, **kwargs):
            self.now = 6_000_000_000
            return [record()]
        self.dns.side_effect = very_slow_dns
        self.assert_failure("dns_failed")
        self.assert_no_socket()

    def test_limits_are_exact_frozen_bounded_and_revalidated(self):
        for name in ("tcp_timeout_ms", "tls_timeout_ms", "establishment_budget_ms"):
            for value in (True, 0, 60_001, IntSubclass(1), 1.0, None, Hostile()):
                with self.assertRaises(ValueError):
                    BrowserHTTPSBrokerLimits(**{name: value})
        limits = BrowserHTTPSBrokerLimits()
        self.assertFalse(hasattr(limits, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            limits.tcp_timeout_ms = 1
        with self.assertRaises(ValueError):
            replace(limits, dns_limits={})
        fake = object.__new__(BrowserHTTPSBrokerLimits)
        for field in fields(limits):
            object.__setattr__(fake, field.name, getattr(limits, field.name))
        object.__setattr__(fake, "tls_timeout_ms", True)
        self.assert_failure("invalid_input", limits=fake)
        self.dns.assert_not_called()
        self.assert_no_socket()

    def test_caller_exception_closes_resources_without_sanitizing_caller_code(self):
        error = RuntimeError("caller error")
        with self.assertRaises(RuntimeError) as caught:
            with open_connection():
                raise error
        self.assertIs(caught.exception, error)
        self.tls.close.assert_called_once()
        self.tcp.close.assert_called_once()
        with open_connection():
            pass  # Slot released after caller error.

    def test_process_control_exception_during_handshake_closes_resources(self):
        self.tls.do_handshake.side_effect = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            with open_connection():
                pass
        self.tls.close.assert_called_once()
        self.tcp.close.assert_called_once()
        self.tls.do_handshake.side_effect = None
        with open_connection():
            pass

    def test_cleanup_failure_is_reported_and_other_socket_and_slot_released(self):
        self.tls.close.side_effect = OSError("INTERNAL_SECRET")
        self.assert_failure("cleanup_failed")
        self.tcp.close.assert_called_once()
        self.tls.close.side_effect = None
        with open_connection():
            pass

    def test_no_secondary_connection_when_broker_context_active(self):
        with open_connection():
            self.assert_failure("broker_busy")
            self.factory.assert_called_once()
            self.dns.assert_called_once()
        with open_connection():
            pass
        self.assertEqual(self.factory.call_count, 2)

    def test_no_http_redirect_proxy_lookup_logs_or_additional_connections(self):
        targets = ("socket.create_connection", "socket.gethostbyname", "socket.setdefaulttimeout",
                   "urllib.request.getproxies", "urllib.request.urlopen",
                   "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
                   "http.client.HTTPConnection.request", "ssl.create_default_context", "logging.Logger._log")
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(name, side_effect=AssertionError(name))) for name in targets]
            with open_connection():
                pass
            for mock in mocks:
                mock.assert_not_called()
        self.factory.assert_called_once()
        self.tcp.connect.assert_called_once()
        self.tls.do_handshake.assert_called_once()
        for method in ("send", "sendall", "recv", "makefile", "connect", "unwrap"):
            getattr(self.tls, method).assert_not_called()
        self.assertEqual(broker.__all__, ("BrowserHTTPSBrokerLimits", "BrowserHTTPSBrokerError", "open_browser_https_connection"))
        self.assertIs(broker.BrowserOrigin, BrowserOrigin)
        self.assertIs(broker.BrowserAdmittedResolution, BrowserAdmittedResolution)
        imports = set()
        for node in ast.walk(ast.parse(inspect.getsource(broker))):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add(node.module)
        self.assertEqual(imports, {"__future__", "ipaddress", "socket", "ssl", "threading", "time",
                                  "collections.abc", "contextlib", "dataclasses",
                                  "jarvis.core.browser_operation_contract", "jarvis.core.browser_dns_resolver",
                                  "jarvis.core.browser_egress_contract", "jarvis.core.browser_network_policy"})


if __name__ == "__main__":
    unittest.main()
