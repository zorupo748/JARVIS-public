"""Real loopback TLS/HTTP; DNS and address mapping are test-only substitutes.

No mocked socket, SSLContext, handshake, send or recv is used. The mapping
refuses every client connect except the declared logical destination, checks
the real OS peer before translating it, and is scoped to each test. Production
policy never admits loopback and has no test flags or injectable transports.
"""

import socket
import ssl
import threading
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from jarvis.core import browser_http_transport as http
from jarvis.core import browser_https_broker as broker
from jarvis.core.browser_network_policy import evaluate_browser_network_resolution
from jarvis.core.browser_operation_contract import BrowserOrigin


FIXTURES = Path(__file__).parent / "fixtures" / "browser_tls"
ORIGIN = BrowserOrigin("https", "browser.test", 443)
ALLOWLIST = frozenset({ORIGIN})
LOGICAL_IP = "8.8.8.8"
REAL_CONNECT = socket.socket.connect
REAL_PEER = socket.socket.getpeername


class LocalTLSServer:
    """One connection, finite waits, bounded request, no external interface."""

    def __init__(self, response, *, certificate="server.pem", mode="clean"):
        self.response = response
        self.mode = mode
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(FIXTURES / certificate, FIXTURES / "server-key.pem")
        self.sni = []
        self.context.set_servername_callback(lambda transport, name, context: self.sni.append(name))
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.endpoint = self.listener.getsockname()
        self.stop = threading.Event()
        self.release = threading.Event()
        self.waiting = threading.Event()
        self.request = b""
        self.handshake_complete = False
        self.handshake_error = False
        self.accept_count = 0
        self.failure = None
        self.tls_version = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def _serve(self):
        try:
            while not self.stop.is_set():
                try:
                    raw, _ = self.listener.accept()
                    break
                except TimeoutError:
                    continue
                except OSError:
                    if self.stop.is_set():
                        return
                    raise
            else:
                return
            self.accept_count += 1
            with raw:
                raw.settimeout(3)
                try:
                    tls = self.context.wrap_socket(raw, server_side=True)
                except OSError:
                    # On Windows a rejected handshake can surface as a TCP
                    # reset rather than an SSL alert at the server side.
                    self.handshake_error = True
                    return
                with tls:
                    self.handshake_complete = True
                    self.tls_version = tls.version()
                    while b"\r\n\r\n" not in self.request:
                        data = tls.recv(4096)
                        if not data:
                            return
                        self.request += data
                        if len(self.request) > 16384:
                            raise AssertionError("test request exceeded limit")
                    if self.mode == "gated_response":
                        self.waiting.set()
                        if not self.release.wait(3):
                            raise AssertionError("gated response was not released")
                    tls.sendall(self.response)
                    if self.mode == "persistent":
                        self.waiting.set()
                        if not self.release.wait(3):
                            raise AssertionError("persistent server was not released")
                    elif self.mode in {"clean", "gated_response"}:
                        # Sends a genuine TLS close_notify; client may close its
                        # descriptor without returning a reciprocal alert.
                        try:
                            plain = tls.unwrap()
                        except (ssl.SSLError, OSError):
                            pass
                        else:
                            plain.close()
                    elif self.mode != "abrupt":
                        raise AssertionError("unknown test server mode")
                    # abrupt: SSLSocket.close without unwrap/close_notify.
        except BaseException as error:
            # Shutdown only excuses the listener's interrupted accept above;
            # never hide request/response failures racing with test cleanup.
            self.failure = error

    def __exit__(self, *args):
        self.release.set()
        self.stop.set()
        self.listener.close()
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError("local TLS server thread leaked")
        if self.failure is not None:
            raise self.failure


class BrowserHTTPRealTLSIntegrationTests(unittest.TestCase):
    @contextmanager
    def environment(self, server):
        self.connections = []
        self.peers = []
        self.contexts = []

        def connect(transport, destination):
            if destination != (LOGICAL_IP, 443):
                raise AssertionError("test blocked an undeclared network destination")
            self.connections.append(transport)
            return REAL_CONNECT(transport, server.endpoint)

        def peer(transport):
            actual = REAL_PEER(transport)
            # Server-side sockets retain their physical client peer. Only the
            # client peer equals the listener endpoint and needs translation.
            if transport.getsockname() == server.endpoint:
                return actual
            if actual != server.endpoint:
                raise AssertionError("actual client peer differs from selected local server")
            self.peers.append((transport, actual))
            return LOGICAL_IP, 443

        def context():
            value = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            value.minimum_version = ssl.TLSVersion.TLSv1_2
            value.load_verify_locations(cafile=FIXTURES / "ca.pem")
            self.contexts.append(value)
            return value

        record = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (LOGICAL_IP, 443))
        with ExitStack() as stack:
            dns = stack.enter_context(patch("socket.getaddrinfo", return_value=[record]))
            stack.enter_context(patch.object(socket.socket, "connect", new=connect))
            stack.enter_context(patch.object(socket.socket, "getpeername", new=peer))
            stack.enter_context(patch.object(socket.socket, "connect_ex", side_effect=AssertionError("alternate connection")))
            stack.enter_context(patch.object(broker, "_create_tls_context", new=context))
            guards = [stack.enter_context(patch(target, side_effect=AssertionError("alternate network client"))) for target in (
                "socket.create_connection", "socket.gethostbyname", "socket.gethostbyname_ex",
                "urllib.request.urlopen", "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
            )]
            try:
                yield dns
            finally:
                for guard in guards:
                    guard.assert_not_called()

    def execute(self, *, method="GET", allowed=ALLOWLIST, selected_ip_address=LOGICAL_IP, **kwargs):
        request = http.BrowserHTTPRequest(ORIGIN, method, "/test", (("q", "café & test"),))
        return http.execute_browser_http_request(
            request, allowed, resolution_id="resolution-real", authorization_id="authorization-real",
            session_id="session-real", operation_id="operation-real", selected_ip_address=selected_ip_address,
            limits=http.BrowserHTTPTransportLimits(io_timeout_ms=1500, exchange_budget_ms=3000),
            broker_limits=broker.BrowserHTTPSBrokerLimits(tcp_timeout_ms=1500, tls_timeout_ms=1500,
                                                        establishment_budget_ms=3000), **kwargs,
        )

    def assert_connected_and_closed(self, server, dns):
        dns.assert_called_once_with("browser.test", 443, family=socket.AF_UNSPEC,
                                    type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=0)
        self.assertEqual(len(self.connections), 1)
        self.assertIs(type(self.connections[0]), socket.socket)
        # CPython may also query the peer while wrapping the connected socket.
        # Require pre-TLS and TLS observations without assuming internal count.
        self.assertGreaterEqual(len(self.peers), 2)
        self.assertIs(type(self.peers[0][0]), socket.socket)
        self.assertIs(type(self.peers[-1][0]), ssl.SSLSocket)
        for _, actual in self.peers:
            self.assertEqual(actual, server.endpoint)
        for transport in self.connections + [entry[0] for entry in self.peers]:
            self.assertEqual(transport.fileno(), -1)
        self.assertEqual(server.sni, ["browser.test"])
        self.assertTrue(server.handshake_complete)
        self.assertIn(server.tls_version, {"TLSv1.2", "TLSv1.3"})
        self.assertEqual(server.accept_count, 1)
        self.assertIs(type(self.contexts[0]), ssl.SSLContext)
        self.assertTrue(self.contexts[0].check_hostname)
        self.assertEqual(self.contexts[0].verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(self.contexts[0].keylog_filename)

    def assert_failure(self, result, code):
        self.assertEqual(result.error_code, code)
        self.assertIsNone(result.response)
        self.assertFalse(result.response_validated)

    def test_get_real_tls_ca_sni_pinning_and_content_length(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        with LocalTLSServer(wire) as server, self.environment(server) as dns:
            result = self.execute()
        self.assertTrue(result.origin_authorized)
        self.assertTrue(result.tls_established)
        self.assertEqual(result.request_send_state, "sent")
        self.assertTrue(result.response_validated)
        self.assertEqual(result.response.body, b"hello")
        self.assertEqual(result.response.wire_bytes, len(wire))
        self.assertTrue(server.request.startswith(b"GET /test?q=caf%C3%A9%20%26%20test HTTP/1.1\r\n"))
        self.assertIn(b"Host: browser.test\r\n", server.request)
        self.assert_connected_and_closed(server, dns)

    def test_head_real_tls_on_persistent_connection(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: keep-alive\r\n\r\n"
        with LocalTLSServer(wire, mode="persistent") as server, self.environment(server) as dns:
            result = self.execute(method="HEAD")
            self.assertTrue(server.waiting.wait(1))
            self.assertTrue(server.thread.is_alive())
            self.assertFalse(server.release.is_set())
        self.assertTrue(result.response_validated)
        self.assertEqual(result.response.body, b"")
        self.assertTrue(server.request.startswith(b"HEAD /test?"))
        self.assert_connected_and_closed(server, dns)

    def test_complete_content_length_returns_before_persistent_server_closes(self):
        wire = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 5\r\n\r\nhello"
        with LocalTLSServer(wire, mode="persistent") as server, self.environment(server) as dns:
            result = self.execute()
            self.assertTrue(server.waiting.wait(1))
            self.assertTrue(server.thread.is_alive())
            self.assertFalse(server.release.is_set())
        self.assertEqual(result.response.body, b"hello")
        self.assert_connected_and_closed(server, dns)

    def test_chunked_real_tls_with_clean_close(self):
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
        with LocalTLSServer(wire) as server, self.environment(server) as dns:
            result = self.execute()
        self.assertEqual(result.response.body, b"hello")
        self.assertEqual(result.response.framing, "chunked")
        self.assert_connected_and_closed(server, dns)

    def test_chunked_and_bodyless_finish_on_real_persistent_tls(self):
        for method, wire, body in (
            ("GET", b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n", b"hi"),
            ("HEAD", b"HTTP/1.1 200 OK\r\n\r\n", b""),
            ("GET", b"HTTP/1.1 204 No Content\r\n\r\n", b""),
            ("GET", b"HTTP/1.1 304 Not Modified\r\n\r\n", b""),
            ("GET", b"HTTP/1.1 205 Reset Content\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", b""),
        ):
            with self.subTest(method=method, wire=wire):
                with LocalTLSServer(wire, mode="persistent") as server, self.environment(server) as dns:
                    result = self.execute(method=method)
                    self.assertTrue(server.waiting.wait(1))
                    self.assertTrue(server.thread.is_alive())
                    self.assertFalse(server.release.is_set())
                self.assertTrue(result.response_validated)
                self.assertEqual(result.response.body, body)
                self.assert_connected_and_closed(server, dns)

    def test_close_delimited_real_tls_close_notify(self):
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\n\r\nhello") as server, self.environment(server) as dns:
            result = self.execute()
        self.assertEqual(result.response.body, b"hello")
        self.assertEqual(result.response.framing, "close")
        self.assert_connected_and_closed(server, dns)

    def test_truncated_content_length_real_tls(self):
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi") as server, self.environment(server) as dns:
            result = self.execute()
        self.assert_failure(result, "truncated_response")
        self.assertTrue(result.tls_established)
        self.assertEqual(result.request_send_state, "sent")
        self.assert_connected_and_closed(server, dns)

    def test_truncated_chunked_real_tls(self):
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n"
        with LocalTLSServer(wire) as server, self.environment(server) as dns:
            result = self.execute()
        self.assert_failure(result, "truncated_response")
        self.assert_connected_and_closed(server, dns)

    def test_abrupt_real_tls_close_is_not_close_delimited_success(self):
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\n\r\npartial", mode="abrupt") as server, self.environment(server) as dns:
            result = self.execute()
        self.assert_failure(result, "tls_truncated")
        self.assert_connected_and_closed(server, dns)

    def test_ambiguous_framing_over_real_tls_is_rejected(self):
        wire = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
        with LocalTLSServer(wire) as server, self.environment(server) as dns:
            result = self.execute()
        self.assert_failure(result, "ambiguous_framing")
        self.assert_connected_and_closed(server, dns)

    def test_untrusted_expired_and_wrong_hostname_certificates_are_rejected(self):
        for certificate in ("untrusted.pem", "expired.pem", "wrong-host.pem"):
            with self.subTest(certificate=certificate):
                with LocalTLSServer(b"", certificate=certificate) as server, self.environment(server) as dns:
                    result = self.execute()
                self.assert_failure(result, "broker_tls_failed")
                self.assertTrue(result.origin_authorized)
                self.assertFalse(result.tls_established)
                self.assertEqual(result.request_send_state, "not_sent")
                self.assertEqual(server.request, b"")
                self.assertFalse(server.handshake_complete)
                self.assertTrue(server.handshake_error)
                self.assertEqual(server.sni, ["browser.test"])
                dns.assert_called_once()
                for transport in self.connections + [entry[0] for entry in self.peers]:
                    self.assertEqual(transport.fileno(), -1)

    def test_origin_permission_does_not_imply_any_connection(self):
        with LocalTLSServer(b"") as server, self.environment(server) as dns:
            other = BrowserOrigin("https", "other.test", 443)
            result = self.execute(allowed=frozenset({other}))
        self.assert_failure(result, "origin_not_allowed")
        self.assertFalse(result.origin_authorized)
        self.assertFalse(result.tls_established)
        self.assertEqual(result.request_send_state, "not_sent")
        self.assertEqual(self.connections, [])
        self.assertEqual(server.accept_count, 0)
        dns.assert_not_called()

    def test_loopback_remains_denied_by_production_policy(self):
        result = evaluate_browser_network_resolution(ORIGIN, ALLOWLIST, ("127.0.0.1",))
        self.assertFalse(result.admitted)
        self.assertEqual(result.reason, "non_global_address")
        self.assertEqual(result.admitted_ip_addresses, ())

    def test_test_adapters_are_restored_after_success_and_failure(self):
        original_context = broker._create_tls_context
        original_connect_ex = socket.socket.connect_ex
        original_dns = socket.getaddrinfo
        for certificate, valid in (("server.pem", True), ("wrong-host.pem", False)):
            with self.subTest(certificate=certificate):
                with LocalTLSServer(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                                    certificate=certificate) as server:
                    with self.environment(server):
                        self.assertEqual(self.execute().response_validated, valid)
                    self.assertIs(socket.socket.connect, REAL_CONNECT)
                    self.assertIs(socket.socket.getpeername, REAL_PEER)
                    self.assertIs(socket.socket.connect_ex, original_connect_ex)
                    self.assertIs(socket.getaddrinfo, original_dns)
                    self.assertIs(broker._create_tls_context, original_context)

    def test_selection_outside_admitted_snapshot_opens_no_real_connection(self):
        with LocalTLSServer(b"") as server, self.environment(server) as dns:
            result = self.execute(selected_ip_address="1.1.1.1")
        self.assert_failure(result, "broker_destination_denied")
        self.assertTrue(result.origin_authorized)
        self.assertFalse(result.tls_established)
        self.assertEqual(result.request_send_state, "not_sent")
        self.assertEqual(self.connections, [])
        self.assertEqual(server.accept_count, 0)
        dns.assert_called_once()


class BrowserGatewayRealTLSIntegrationTests(unittest.TestCase):
    """Entire trusted chain is real; reuse only the laboratory's OS adapters."""

    environment = BrowserHTTPRealTLSIntegrationTests.environment
    assert_connected_and_closed = BrowserHTTPRealTLSIntegrationTests.assert_connected_and_closed

    def setUp(self):
        from jarvis.core.browser_navigation_supervisor import create_browser_navigation_supervisor
        from jarvis.core.browser_request_authorization import (
            BrowserRequestPermission, BrowserRequestAuthorizationSnapshot, BrowserRequestAuthorizationContext,
        )
        from jarvis.core.browser_http_dispatch_gateway import BrowserHTTPDispatchGateway
        self.owner, self.authority = create_browser_navigation_supervisor(clock=lambda: 0)
        self.addCleanup(self.owner.close)
        self.request = http.BrowserHTTPRequest(ORIGIN, "GET", "/test", (("q", "caf\u00e9 & test"),))
        self.context = BrowserRequestAuthorizationContext("session-lab", "permission-lab", "operation", "operation-lab")
        self.permission_type = BrowserRequestPermission
        self.snapshot_type = BrowserRequestAuthorizationSnapshot
        self.gateway = BrowserHTTPDispatchGateway(self.owner, self.authority,
            limits=http.BrowserHTTPTransportLimits(io_timeout_ms=1500, exchange_budget_ms=3000),
            broker_limits=broker.BrowserHTTPSBrokerLimits(tcp_timeout_ms=1500, tls_timeout_ms=1500,
                                                        establishment_budget_ms=3000))

    def register(self, *, request=None, max_requests=1, used_requests=0):
        request = self.request if request is None else request
        permission = self.permission_type("permission-lab", "session-lab", "operation", "operation-lab",
                                          request, 0, 60000, False)
        return self.authority.register_session(self.snapshot_type("session-lab", (permission,), 0, 60000,
            False, used_requests, max_requests, 0, 4096, 4096))

    def dispatch(self, session, *, request=None, budget=4096, attempt="attempt-lab"):
        return self.gateway.dispatch(session, attempt, self.request if request is None else request,
                                     self.context, response_byte_budget=budget)

    def assert_settled(self, result, *, validated):
        from jarvis.core.browser_navigation_supervisor import ReservationState
        self.assertIs(result.lifecycle.state, ReservationState.COMPLETED)
        self.assertEqual(result.observation.response_validated, validated)
        self.assertEqual(self.authority.dispatch_outcome(result.lifecycle.reservation), result.observation)
        self.assertFalse(self.authority.record_dispatch_outcome(result.lifecycle.reservation, result.observation).accepted)

    def test_get_exact_query_content_length_and_single_use(self):
        session = self.register()
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", mode="persistent") as server, self.environment(server) as dns:
            result = self.dispatch(session)
            self.assertTrue(server.waiting.wait(1))
            self.assertFalse(server.release.is_set())
            self.assertFalse(self.dispatch(session).observation.transport_invoked)
        self.assertTrue(result.exchange.origin_authorized)
        self.assertTrue(result.observation.tls_established)
        self.assertEqual(result.observation.send_state, "sent")
        self.assertTrue(result.response_released)
        self.assertEqual(result.exchange.response.body, b"hello")
        self.assertEqual(server.request, b"GET /test?q=caf%C3%A9%20%26%20test HTTP/1.1\r\nHost: browser.test\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        self.assert_settled(result, validated=True)
        self.assert_connected_and_closed(server, dns)

    def test_head_real_tls(self):
        from dataclasses import replace
        request = replace(self.request, method="HEAD")
        session = self.register(request=request)
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", mode="persistent") as server, self.environment(server) as dns:
            result = self.dispatch(session, request=request)
        self.assertTrue(result.response_released)
        self.assertEqual(result.exchange.response.body, b"")
        self.assertTrue(server.request.startswith(b"HEAD /test?q=caf%C3%A9%20%26%20test HTTP/1.1\r\n"))
        self.assert_settled(result, validated=True)
        self.assert_connected_and_closed(server, dns)

    def test_chunked_real_tls(self):
        session = self.register()
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n") as server, self.environment(server) as dns:
            result = self.dispatch(session)
        self.assertTrue(result.response_released)
        self.assertEqual(result.exchange.response.body, b"hello")
        self.assertEqual(result.exchange.response.framing, "chunked")
        self.assert_settled(result, validated=True)
        self.assert_connected_and_closed(server, dns)

    def test_denied_requests_and_quota_never_reach_broker(self):
        from dataclasses import replace
        from jarvis.core import browser_http_dispatch_gateway as gateway
        session = self.register(used_requests=1)
        with LocalTLSServer(b"") as server, self.environment(server) as dns, patch.object(
                broker, "open_browser_https_connection", side_effect=AssertionError("broker invoked")) as guard:
            for request in (replace(self.request, query_parameters=()), self.request):
                result = self.dispatch(session, request=request)
                self.assertIs(result.status, gateway.HTTPDispatchStatus.REJECTED)
                self.assertFalse(result.observation.transport_invoked)
            guard.assert_not_called()
            dns.assert_not_called()
        self.assertEqual(server.accept_count, 0)

    def test_limit_truncation_and_abrupt_close_are_errors_and_settled(self):
        from jarvis.core.browser_http_dispatch_gateway import HTTPDispatchStatus
        cases = (
            (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b"x" * 100, "clean", 64, "response_limit"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi", "clean", 4096, "truncated_response"),
            (b"HTTP/1.1 200 OK\r\n\r\npartial", "abrupt", 4096, "tls_truncated"),
        )
        for wire, mode, budget, code in cases:
            with self.subTest(code=code):
                # Independent registries keep session IDs and budgets unchanged.
                self.setUp()
                session = self.register()
                with LocalTLSServer(wire, mode=mode) as server, self.environment(server) as dns:
                    result = self.dispatch(session, budget=budget)
                self.assertIs(result.status, HTTPDispatchStatus.ERROR)
                self.assertFalse(result.response_released)
                self.assertIsNone(result.exchange.response)
                self.assertEqual(result.exchange.error_code, code)
                self.assert_settled(result, validated=False)
                self.assert_connected_and_closed(server, dns)

    def test_wrong_hostname_real_tls_no_http_sent_and_quota_consumed(self):
        from jarvis.core.browser_http_dispatch_gateway import HTTPDispatchStatus
        session = self.register()
        with LocalTLSServer(b"", certificate="wrong-host.pem") as server, self.environment(server) as dns:
            result = self.dispatch(session)
            denied = self.dispatch(session, attempt="second-attempt")
        self.assertIs(result.status, HTTPDispatchStatus.NOT_SENT)
        self.assertFalse(result.observation.tls_established)
        self.assertEqual(result.exchange.error_code, "broker_tls_failed")
        self.assertFalse(result.response_released)
        self.assertEqual(server.request, b"")
        self.assertTrue(server.handshake_error)
        self.assertIs(denied.status, HTTPDispatchStatus.REJECTED)
        self.assert_settled(result, validated=False)
        dns.assert_called_once()
        for transport in self.connections + [entry[0] for entry in self.peers]:
            self.assertEqual(transport.fileno(), -1)

    def test_revocation_during_real_tls_preserves_receipt_but_denies_release(self):
        from concurrent.futures import ThreadPoolExecutor
        from jarvis.core.browser_navigation_supervisor import ReservationState
        session = self.register()
        with LocalTLSServer(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", mode="gated_response") as server, self.environment(server) as dns:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(self.dispatch, session)
                try:
                    self.assertTrue(server.waiting.wait(2))
                    self.authority.revoke_permission(session, "permission-lab")
                finally:
                    server.release.set()
                result = future.result(timeout=4)
        self.assertTrue(result.observation.tls_established)
        self.assertEqual(result.observation.send_state, "sent")
        self.assertTrue(result.observation.response_validated)
        self.assertIs(result.lifecycle.state, ReservationState.REVOKED)
        self.assertFalse(result.response_released)
        self.assertIsNone(result.exchange)
        self.assertEqual(self.authority.dispatch_outcome(result.lifecycle.reservation), result.observation)
        self.assert_connected_and_closed(server, dns)


if __name__ == "__main__":
    unittest.main()
