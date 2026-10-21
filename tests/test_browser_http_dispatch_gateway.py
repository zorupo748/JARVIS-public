import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from threading import Barrier, Event
from unittest.mock import patch

from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_http_transport import BrowserHTTPRequest, BrowserHTTPResponse, BrowserHTTPExchangeResult
from jarvis.core.browser_request_authorization import (
    BrowserRequestPermission, BrowserRequestAuthorizationSnapshot, BrowserRequestAuthorizationContext,
)
from jarvis.core.browser_navigation_supervisor import (
    create_browser_navigation_supervisor, NavigationDispatchOutcome,
    NavigationReason, ReservationState, NavigationSupervisorError,
)
from jarvis.core import browser_http_dispatch_gateway as gateway


ORIGIN = BrowserOrigin("https", "example.com", 443)
REQUEST = BrowserHTTPRequest(ORIGIN, "GET", "/page", (("q", "DO_NOT_LEAK"),))
CONTEXT = BrowserRequestAuthorizationContext("session-1", "permission-1", "operation", "operation-1")
GOOD = BrowserHTTPExchangeResult(True, True, "sent", BrowserHTTPResponse(
    200, (("content-length", "5"),), b"hello", "content_length", 43), None)


def snapshot(request=REQUEST, **kwargs):
    permission = BrowserRequestPermission("permission-1", "session-1", "operation", "operation-1", request, 0, 90, False)
    return replace(BrowserRequestAuthorizationSnapshot("session-1", (permission,), 0, 100, False,
                                                      0, 2, 0, 2000, 1000), **kwargs)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.now = 10
        self.owner, self.authority = create_browser_navigation_supervisor(clock=lambda: self.now)
        self.addCleanup(self.owner.close)
        self.session = self.authority.register_session(snapshot())
        self.gateway = gateway.BrowserHTTPDispatchGateway(self.owner, self.authority)
        self.transport = patch.object(gateway, "execute_browser_http_request", return_value=GOOD).start()
        self.addCleanup(patch.stopall)

    def dispatch(self, request_id="attempt-1", **kwargs):
        args = dict(session=self.session, request_id=request_id, request=REQUEST, context=CONTEXT,
                    response_byte_budget=1000)
        args.update(kwargs)
        return self.gateway.dispatch(**args)

    def test_get_uses_exact_binding_and_reserved_limits(self):
        result = self.dispatch()
        self.assertIs(result.status, gateway.HTTPDispatchStatus.RESPONSE_VALIDATED)
        self.assertTrue(result.response_released)
        self.assertEqual(result.exchange.response.body, b"hello")
        self.assertIs(result.lifecycle.state, ReservationState.COMPLETED)
        args, kwargs = self.transport.call_args
        self.assertEqual(args, (REQUEST, frozenset({ORIGIN})))
        self.assertEqual(kwargs["session_id"], CONTEXT.session_id)
        self.assertEqual(kwargs["operation_id"], CONTEXT.binding_id)
        self.assertEqual(kwargs["limits"].max_response_bytes, 1000)
        self.assertEqual(kwargs["limits"].max_body_bytes, 1000)
        self.assertLessEqual(kwargs["limits"].exchange_budget_ms, 80)
        self.assertNotIn("selected_ip_address", kwargs)
        self.assertNotIn("DO_NOT_LEAK", repr(result))
        observation = self.authority.dispatch_outcome(result.lifecycle.reservation)
        self.assertTrue(observation.response_validated)
        self.assertEqual(observation.http_status, 200)

    def test_head_authorized(self):
        request = replace(REQUEST, method="HEAD")
        session = self.authority.register_session(snapshot(request=request, session_id="head-session",
            permissions=(BrowserRequestPermission("head-permission", "head-session", "resource", "head-resource", request, 0, 90, False),)))
        context = BrowserRequestAuthorizationContext("head-session", "head-permission", "resource", "head-resource")
        self.transport.return_value = replace(GOOD, response=replace(GOOD.response, body=b"", framing="none"))
        result = self.dispatch(session=session, request=request, context=context)
        self.assertTrue(result.response_released)
        self.assertEqual(self.transport.call_args.args[0].method, "HEAD")

    def test_rejections_never_invoke_transport(self):
        for kwargs in ({"request": replace(REQUEST, static_path="/other")},
                       {"request": replace(REQUEST, query_parameters=())},
                       {"request": replace(REQUEST, origin=BrowserOrigin("https", "other.example", 443))},
                       {"context": replace(CONTEXT, session_id="other")},
                       {"context": replace(CONTEXT, permission_id="unknown")},
                       {"response_byte_budget": True}, {"response_byte_budget": 1001}):
            with self.subTest(fields=tuple(kwargs)):
                result = self.dispatch(**kwargs)
                self.assertIs(result.status, gateway.HTTPDispatchStatus.REJECTED)
                self.assertFalse(result.observation.transport_invoked)
                self.assertIsNone(result.exchange)
        self.transport.assert_not_called()

    def test_quota_is_reserved_before_transport(self):
        owner, authority = create_browser_navigation_supervisor(clock=lambda: 10)
        self.addCleanup(owner.close)
        session = authority.register_session(snapshot(max_requests=1))
        client = gateway.BrowserHTTPDispatchGateway(owner, authority)
        def execute(*args, **kwargs):
            other = owner.reserve(session, "other", REQUEST, CONTEXT, response_byte_budget=1)
            self.assertIs(other.reason, NavigationReason.REQUEST_LIMIT)
            return GOOD
        self.transport.side_effect = execute
        self.assertTrue(client.dispatch(session, "first", REQUEST, CONTEXT, response_byte_budget=1000).response_released)

    def test_revocation_between_binding_and_claim_prevents_invocation(self):
        original = self.authority.binding
        def revoke(token):
            binding = original(token)
            self.authority.revoke_session(self.session)
            return binding
        with patch.object(type(self.authority), "binding", side_effect=revoke):
            result = self.dispatch()
        self.assertIs(result.status, gateway.HTTPDispatchStatus.REJECTED)
        self.assertIs(result.lifecycle.state, ReservationState.REVOKED)
        self.transport.assert_not_called()
        stored = self.authority.dispatch_outcome(result.lifecycle.reservation)
        self.assertFalse(stored.transport_invoked)
        self.assertIs(self.owner.inspect(result.lifecycle.reservation).state, ReservationState.REVOKED)

    def test_revocation_in_flight_preserves_facts_but_withholds_payload(self):
        def execute(*args, **kwargs):
            self.authority.revoke_permission(self.session, "permission-1")
            return GOOD
        self.transport.side_effect = execute
        result = self.dispatch()
        self.assertTrue(result.observation.response_validated)
        self.assertIs(result.status, gateway.HTTPDispatchStatus.RESPONSE_VALIDATED)
        self.assertIs(result.lifecycle.state, ReservationState.REVOKED)
        self.assertFalse(result.response_released)
        self.assertIsNone(result.exchange)
        self.assertEqual(self.authority.dispatch_outcome(result.lifecycle.reservation), result.observation)

    def test_expiry_in_flight_withholds_payload(self):
        def execute(*args, **kwargs):
            self.now = 90
            return GOOD
        self.transport.side_effect = execute
        result = self.dispatch()
        self.assertIs(result.lifecycle.state, ReservationState.EXPIRED)
        self.assertFalse(result.response_released)
        self.assertTrue(result.observation.response_validated)

    def test_concurrent_cancellation_withholds_received_response(self):
        entered, release = Event(), Event()
        tokens = []
        original = self.owner.reserve
        def reserve(*args, **kwargs):
            result = original(*args, **kwargs)
            tokens.append(result.reservation)
            return result
        def execute(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("test synchronization failed")
            return GOOD
        self.transport.side_effect = execute
        with patch.object(type(self.owner), "reserve", side_effect=reserve), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.dispatch)
            try:
                self.assertTrue(entered.wait(timeout=5))
                self.assertTrue(self.owner.cancel(tokens[0]).accepted)
            finally:
                release.set()
            result = future.result(timeout=5)
        self.assertIs(result.lifecycle.state, ReservationState.CANCELLED)
        self.assertTrue(result.observation.response_validated)
        self.assertFalse(result.response_released)
        self.assertIsNone(result.exchange)

    def test_invalid_transport_result_is_not_a_response(self):
        self.transport.return_value = None
        with self.assertRaises(gateway.HTTPDispatchError) as caught:
            self.dispatch()
        self.assertIs(caught.exception.reason, gateway.HTTPDispatchReason.INVALID_TRANSPORT_RESULT)

    def test_duplicate_and_exhausted_attempts_do_not_send(self):
        self.dispatch()
        self.assertIs(self.dispatch().lifecycle.reason, NavigationReason.DUPLICATE_REQUEST)
        self.dispatch("second")
        self.assertIs(self.dispatch("third").lifecycle.reason, NavigationReason.REQUEST_LIMIT)
        self.assertEqual(self.transport.call_count, 2)

    def test_not_sent_unknown_and_incomplete_are_distinct_and_settled(self):
        for send, tls, code, status in (
            ("not_sent", False, "broker_dns_failed", gateway.HTTPDispatchStatus.NOT_SENT),
            ("unknown", True, "send_failed", gateway.HTTPDispatchStatus.SEND_UNKNOWN),
            ("sent", True, "truncated_response", gateway.HTTPDispatchStatus.ERROR),
        ):
            with self.subTest(send=send):
                owner, authority = create_browser_navigation_supervisor(clock=lambda: 10)
                session = authority.register_session(snapshot())
                client = gateway.BrowserHTTPDispatchGateway(owner, authority)
                self.transport.return_value = BrowserHTTPExchangeResult(True, tls, send, None, code)
                result = client.dispatch(session, "a", REQUEST, CONTEXT, response_byte_budget=1000)
                self.assertIs(result.status, status)
                self.assertEqual(result.observation.send_state, send)
                self.assertFalse(result.observation.response_validated)
                self.assertIs(result.lifecycle.state, ReservationState.COMPLETED)
                owner.close()

    def test_io_exception_is_unknown_and_reserved_quota_not_refunded(self):
        self.transport.side_effect = OSError("DO_NOT_LEAK")
        result = self.dispatch()
        self.assertIs(result.status, gateway.HTTPDispatchStatus.SEND_UNKNOWN)
        self.assertIs(result.reason, gateway.HTTPDispatchReason.TRANSPORT_EXCEPTION)
        self.assertEqual(result.observation.send_state, "unknown")
        self.assertIsNone(result.observation.tls_established)
        self.assertIs(result.lifecycle.state, ReservationState.COMPLETED)
        self.assertNotIn("DO_NOT_LEAK", repr(result))
        self.dispatch("second")
        self.assertIs(self.dispatch("third").lifecycle.reason, NavigationReason.REQUEST_LIMIT)

    def test_programming_exception_is_typed_sanitized_and_finalized(self):
        tokens = []
        original = self.owner.reserve
        def reserve(*args, **kwargs):
            result = original(*args, **kwargs)
            tokens.append(result.reservation)
            return result
        self.transport.side_effect = RuntimeError("DO_NOT_LEAK")
        with patch.object(type(self.owner), "reserve", side_effect=reserve):
            with self.assertRaises(gateway.HTTPDispatchError) as caught:
                self.dispatch()
        self.assertNotIn("DO_NOT_LEAK", str(caught.exception))
        self.assertIs(self.owner.inspect(tokens[0]).state, ReservationState.COMPLETED)
        self.assertEqual(self.authority.dispatch_outcome(tokens[0]).send_state, "unknown")

    def test_response_over_authorized_ceiling_is_never_released(self):
        self.transport.return_value = replace(GOOD, response=replace(GOOD.response, wire_bytes=1001))
        with self.assertRaises(gateway.HTTPDispatchError) as caught:
            self.dispatch()
        self.assertIs(caught.exception.reason, gateway.HTTPDispatchReason.INVALID_TRANSPORT_RESULT)

    def test_request_mutation_after_reserve_does_not_substitute_dispatch(self):
        request = replace(REQUEST)
        original = self.authority.binding
        def mutate(token):
            binding = original(token)
            object.__setattr__(request, "static_path", "/other")
            object.__setattr__(request, "query_parameters", (("q", "other"),))
            return binding
        with patch.object(type(self.authority), "binding", side_effect=mutate):
            self.assertTrue(self.dispatch(request=request).response_released)
        self.assertEqual(self.transport.call_args.args[0], REQUEST)

    def test_no_untrusted_infrastructure_arguments(self):
        for name in ("authority", "snapshot", "allowed_origins", "socket", "selected_ip_address",
                     "resolver", "ssl_context", "executor", "limits", "now_ms"):
            with self.subTest(name=name), self.assertRaises(TypeError):
                self.dispatch(**{name: object()})
        self.transport.assert_not_called()

    def test_concurrency_does_not_overrun_quota(self):
        barrier = Barrier(8)
        def dispatch(index):
            barrier.wait(timeout=5)
            return self.dispatch("thread-" + str(index))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(dispatch, range(8)))
        self.assertEqual(sum(r.observation.transport_invoked for r in results), 2)
        self.assertEqual(self.transport.call_count, 2)
        for result in results:
            if result.observation.transport_invoked:
                self.assertIs(result.lifecycle.state, ReservationState.COMPLETED)

    def test_dispatch_claim_and_recording_are_single_use(self):
        reservation = self.owner.reserve(self.session, "manual", REQUEST, CONTEXT, response_byte_budget=1000).reservation
        self.owner.start(reservation)
        self.authority.claim_dispatch(reservation)
        with self.assertRaises(NavigationSupervisorError):
            self.authority.claim_dispatch(reservation)
        fact = NavigationDispatchOutcome(True, "not_sent", False, False, None, True)
        self.assertTrue(self.authority.record_dispatch_outcome(reservation, fact).accepted)
        self.assertFalse(self.authority.record_dispatch_outcome(reservation, fact).accepted)

    def test_known_http_transport_and_broker_with_only_os_io_simulated(self):
        from test_browser_http_transport import HTTPTransportTests
        from jarvis.core.browser_http_transport import execute_browser_http_request
        harness = HTTPTransportTests("test_get_wire_request_and_valid_response")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        self.transport.side_effect = execute_browser_http_request
        result = self.dispatch()
        self.assertTrue(result.response_released)
        self.assertEqual(result.exchange.response.body, b"hello")
        harness.open_broker.assert_called_once()
        harness.dns.assert_called_once()
        harness.tls.close.assert_called_once()
        harness.tcp.close.assert_called_once()
        self.assertTrue(harness.tls.sendall.call_args.args[0].startswith(b"GET /page?q=DO_NOT_LEAK HTTP/1.1\r\n"))

    def test_real_transport_send_failure_closes_both_resources(self):
        from test_browser_http_transport import HTTPTransportTests
        from jarvis.core.browser_http_transport import execute_browser_http_request
        harness = HTTPTransportTests("test_get_wire_request_and_valid_response")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        harness.tls.sendall.side_effect = OSError("DO_NOT_LEAK")
        self.transport.side_effect = execute_browser_http_request
        result = self.dispatch()
        self.assertIs(result.status, gateway.HTTPDispatchStatus.SEND_UNKNOWN)
        harness.tls.close.assert_called_once()
        harness.tcp.close.assert_called_once()

    def test_reject_has_no_network_or_other_external_effects(self):
        names = ("socket.socket", "socket.getaddrinfo", "urllib.request.urlopen",
                 "http.client.HTTPConnection.connect", "builtins.open", "subprocess.Popen")
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(name, side_effect=AssertionError("external I/O"))) for name in names]
            self.authority.revoke_session(self.session)
            self.assertIs(self.dispatch().status, gateway.HTTPDispatchStatus.REJECTED)
            for guard in guards:
                guard.assert_not_called()
        self.transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
