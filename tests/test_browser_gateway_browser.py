"""Real Chromium + real laboratory TCP/TLS; no public navigation.

Only DNS, CA trust and physical destination translation use test adapters.
Unit adaptation tests below use constructible HTTP records, not network proof.
"""
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch, Mock

from jarvis.experimental import gateway_browser as bridge
from jarvis.experimental.synthetic_browser import SyntheticBrowserError
from jarvis.core.browser_http_transport import BrowserHTTPResponse
import test_browser_http_tls_integration as lab
import test_browser_synthetic_prototype as synthetic


class GatewayBrowserUnitTests(unittest.TestCase):
    def harness(self):
        harness = lab.BrowserGatewayRealTLSIntegrationTests("test_get_exact_query_content_length_and_single_use")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        session = harness.register()
        browser = bridge.GatewayLaboratoryBrowser("unused", enabled=True, gateway=harness.gateway,
            authority=harness.authority, session=session, request=harness.request, context=harness.context,
            fixture_id="fixture", response_byte_budget=4096)
        self.addCleanup(browser.close)
        browser._page = Mock()
        browser._page.url = browser._target
        route = Mock()
        route.request.url, route.request.method = browser._target, "GET"
        route.request.post_data = None
        route.request.is_navigation_request.return_value = True
        route.request.frame = browser._page.main_frame
        return harness, browser, route

    def test_changed_document_cannot_keep_broker_provenance(self):
        harness, browser, route = self.harness()
        browser._fixture_id = "fixture"
        browser.observations.append(bridge.BrowserDeliveryObservation("fixture", "delivered", 200, True, True))
        browser._page.url = "about:blank"
        browser._page.locator.return_value.count.return_value = 1
        browser._page.locator.return_value.text_content.return_value = "forged"
        with self.assertRaises(SyntheticBrowserError):
            browser.extract((("status", "h1"),))

    def test_fulfill_failure_is_uncertain_not_confirmed_absence_of_delivery(self):
        from test_browser_http_dispatch_gateway import GOOD
        harness, browser, route = self.harness()
        route.fulfill.side_effect = RuntimeError("DO_NOT_LEAK")
        with patch("jarvis.core.browser_http_dispatch_gateway.execute_browser_http_request", return_value=GOOD):
            browser._abort_request(route)
        self.assertEqual(browser.observations[-1].status, "delivery_uncertain")
        self.assertNotIn("DO_NOT_LEAK", repr(browser.observations))
        self.assertFalse(harness.authority.authorize_delivery(next(iter(harness.owner._reservations))))

    def test_fulfill_cancellation_and_abort_failure_preserve_uncertainty(self):
        from test_browser_http_dispatch_gateway import GOOD
        harness, browser, route = self.harness()
        route.fulfill.side_effect = KeyboardInterrupt()
        route.abort.side_effect = RuntimeError("DO_NOT_LEAK")
        with patch("jarvis.core.browser_http_dispatch_gateway.execute_browser_http_request", return_value=GOOD):
            with self.assertRaises(KeyboardInterrupt):
                browser._abort_request(route)
        self.assertEqual(browser.observations[-1].status, "delivery_uncertain")
        self.assertFalse(harness.authority.authorize_delivery(next(iter(harness.owner._reservations))))

    def test_repeated_navigation_cannot_consume_another_permission_mocks(self):
        from test_browser_http_dispatch_gateway import GOOD
        harness, browser, route = self.harness()
        with patch("jarvis.core.browser_http_dispatch_gateway.execute_browser_http_request", return_value=GOOD) as execute:
            browser._abort_request(route)
            browser._abort_request(route)
        execute.assert_called_once()
        route.fulfill.assert_called_once()
        self.assertEqual(len(harness.owner._reservations), 1)

    def test_delivery_expiry_unknown_handle_and_close_fail_closed(self):
        from test_browser_http_dispatch_gateway import GOOD
        from jarvis.core.browser_navigation_supervisor import NavigationReservationHandle
        harness, browser, route = self.harness()
        with patch("jarvis.core.browser_http_dispatch_gateway.execute_browser_http_request", return_value=GOOD):
            result = browser._gateway.dispatch(browser._session, "manual", browser._request,
                browser._binding_context, response_byte_budget=4096)
        self.assertFalse(harness.authority.authorize_delivery(NavigationReservationHandle()))
        harness.owner._clock = lambda: 60000
        self.assertFalse(harness.authority.authorize_delivery(result.lifecycle.reservation))
        harness.owner.close()
        self.assertFalse(harness.authority.authorize_delivery(result.lifecycle.reservation))

    def test_concurrent_delivery_claim_has_one_winner(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from test_browser_http_dispatch_gateway import GOOD
        harness, browser, route = self.harness()
        with patch("jarvis.core.browser_http_dispatch_gateway.execute_browser_http_request", return_value=GOOD):
            result = browser._gateway.dispatch(browser._session, "manual", browser._request,
                browser._binding_context, response_byte_budget=4096)
        barrier = Barrier(8)
        def claim(_):
            barrier.wait(5)
            return harness.authority.authorize_delivery(result.lifecycle.reservation)
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(claim, range(8))), 1)

    def test_url_alternatives_and_secondary_requests_never_dispatch_mocks(self):
        harness = lab.BrowserGatewayRealTLSIntegrationTests("test_get_exact_query_content_length_and_single_use")
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        session = harness.register()
        browser = bridge.GatewayLaboratoryBrowser("unused", enabled=True, gateway=harness.gateway,
            authority=harness.authority, session=session, request=harness.request, context=harness.context,
            fixture_id="fixture")
        self.addCleanup(browser.close)
        browser._page = Mock()
        for url, method, navigation in (("https://browser.test:443/test?q=caf%C3%A9%20%26%20test", "GET", True),
                ("https://other.test/test", "GET", True), (browser._target, "POST", True),
                (browser._target, "GET", False)):
            with self.subTest(url=url, method=method):
                route = Mock()
                route.request.url, route.request.method = url, method
                route.request.post_data = None
                route.request.is_navigation_request.return_value = navigation
                route.request.frame = browser._page.main_frame
                with patch.object(type(harness.gateway), "dispatch", side_effect=AssertionError("unexpected dispatch")) as dispatch:
                    browser._abort_request(route)
                    dispatch.assert_not_called()
                route.abort.assert_called_once()
                route.fulfill.assert_not_called()
                route.fetch.assert_not_called()
                route.continue_.assert_not_called()

    def test_disabled_by_default(self):
        with self.assertRaisesRegex(SyntheticBrowserError, "experimental_disabled"):
            bridge.GatewayLaboratoryBrowser("unused", gateway=None, authority=None, session=None,
                request=None, context=None, fixture_id="fixture")

    def test_adaptation_preserves_security_and_removes_framing(self):
        response = BrowserHTTPResponse(200, (("transfer-encoding", "chunked"),
            ("content-security-policy", "default-src 'none'"), ("x-content-type-options", "nosniff")), b"hello", "chunked", 100)
        result = bridge.fulfillment(response, "GET")
        self.assertEqual(result["body"], b"hello")
        self.assertEqual(result["headers"], {"content-security-policy": "default-src 'none'", "x-content-type-options": "nosniff"})
        self.assertEqual(bridge.fulfillment(response, "HEAD")["body"], b"")

    def test_ambiguous_side_effect_headers_and_redirects_rejected(self):
        for headers, status in (((('x-test', 'one'), ('x-test', 'two')), 200),
                                ((("set-cookie", "x=y"),), 200), ((("refresh", "0;url=/other"),), 200),
                                ((("location", "/other"),), 302)):
            with self.subTest(headers=headers), self.assertRaises(SyntheticBrowserError):
                bridge.fulfillment(BrowserHTTPResponse(status, headers, b"", "content_length", 100), "GET")


class GatewayBrowserRealIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        synthetic.SyntheticPrototypeRealChromiumTests.setUpClass()
        cls.executable = synthetic.SyntheticPrototypeRealChromiumTests.executable
        cls.html = (Path(__file__).parent / "fixtures" / "synthetic_tracking.html").read_bytes()

    def setUp(self):
        self.lab = lab.BrowserGatewayRealTLSIntegrationTests("test_get_exact_query_content_length_and_single_use")
        self.lab.setUp()
        self.addCleanup(self.lab.doCleanups)
        self.session = self.lab.register()
        self.browser = bridge.GatewayLaboratoryBrowser(self.executable, enabled=True,
            gateway=self.lab.gateway, authority=self.lab.authority, session=self.session,
            request=self.lab.request, context=self.lab.context, fixture_id="synthetic-tracking-v1", response_byte_budget=4096)
        self.addCleanup(self.browser.close)

    def wire(self, status=200, *, chunked=False):
        headers = b"Content-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\n"
        if chunked:
            return b"HTTP/1.1 200 OK\r\n" + headers + b"Transfer-Encoding: chunked\r\n\r\n" + format(len(self.html), 'x').encode() + b"\r\n" + self.html + b"\r\n0\r\n\r\n"
        return ("HTTP/1.1 %d Test\r\n" % status).encode() + headers + ("Content-Length: %d\r\n\r\n" % len(self.html)).encode() + self.html

    def test_real_tls_html_dom_tracking_interaction_and_unapproved_fetch(self):
        self.browser.__enter__()
        with lab.LocalTLSServer(self.wire(chunked=True)) as server, self.lab.environment(server) as dns:
            with closing(self.browser):
                self.browser.navigate()
                self.assertIn("ning\u00fan servicio real", self.browser.read_text("h1"))
                self.browser.fill("#tracking-code", "DEMO-001")
                self.browser.click("#track")
                self.browser.wait_text("#status", "En tr\u00e1nsito (simulado)")
                observation = self.browser.extract((("code", "#observed-code"), ("status", "#status")))
                self.assertEqual(observation.fields, (("code", "DEMO-001"), ("status", "En tr\u00e1nsito (simulado)")))
                self.assertEqual(observation.provenance, "synthetic_dom_after_jarvis_broker_http")
                self.assertEqual(observation.http_status, 200)
                self.browser.click("#network")
                self.browser.wait_text("#network-result", "blocked")
                self.assertGreaterEqual(self.browser.blocked_requests, 1)
                self.assertEqual(self.browser._context.cookies(), [])
                self.assertEqual(self.browser._page.url, "https://browser.test/test?q=caf%C3%A9%20%26%20test")
                reservation = next(iter(self.lab.owner._reservations))
                self.assertFalse(self.lab.authority.authorize_delivery(reservation))
        self.assertTrue(self.browser.closed)
        self.assertTrue(self.browser.observations[0].http_received)
        self.assertTrue(self.browser.observations[0].delivered)
        self.assertTrue(server.request.startswith(b"GET /test?q=caf%C3%A9%20%26%20test HTTP/1.1\r\n"))
        self.lab.assert_connected_and_closed(server, dns)

    def test_real_http_error_status_is_retained(self):
        for status in (403, 404):
            with self.subTest(status=status):
                self.setUp()
                self.browser.__enter__()
                with lab.LocalTLSServer(self.wire(status)) as server, self.lab.environment(server) as dns:
                    with closing(self.browser):
                        self.browser.navigate()
                        self.assertEqual(self.browser.observations[0].http_status, status)
                        self.assertTrue(self.browser.observations[0].delivered)
                        self.assertEqual(self.browser.extract((("heading", "h1"),)).http_status, status)
                self.lab.assert_connected_and_closed(server, dns)

    def test_real_tls_and_truncation_never_deliver_content(self):
        for certificate, wire, code in (("wrong-host.pem", b"", "not_sent"),
                ("server.pem", b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial", "error")):
            with self.subTest(certificate=certificate):
                self.setUp()
                self.browser.__enter__()
                with lab.LocalTLSServer(wire, certificate=certificate) as server, self.lab.environment(server):
                    with self.assertRaises(SyntheticBrowserError):
                        self.browser.navigate()
                self.assertTrue(self.browser.closed)
                self.assertFalse(self.browser.observations[0].delivered)
                self.assertFalse(self.browser.observations[0].http_received)
                self.assertEqual(self.browser.observations[0].status, code)
                for transport in self.lab.connections + [entry[0] for entry in self.lab.peers]:
                    self.assertEqual(transport.fileno(), -1)

    def test_revocation_after_http_before_delivery_aborts(self):
        original = bridge.fulfillment
        def revoke(response, method):
            result = original(response, method)
            self.lab.authority.revoke_permission(self.session, "permission-lab")
            return result
        self.browser.__enter__()
        with lab.LocalTLSServer(self.wire()) as server, self.lab.environment(server) as dns:
            with patch.object(bridge, "fulfillment", side_effect=revoke):
                with self.assertRaises(SyntheticBrowserError):
                    self.browser.navigate()
        self.assertTrue(self.browser.closed)
        self.assertTrue(self.browser.observations[0].http_received)
        self.assertFalse(self.browser.observations[0].delivered)
        self.assertEqual(self.browser.observations[0].status, "delivery_revoked")
        self.lab.assert_connected_and_closed(server, dns)

    def test_revoked_session_no_broker_or_delivery(self):
        self.lab.authority.revoke_session(self.session)
        self.browser.__enter__()
        with lab.LocalTLSServer(b"") as server, self.lab.environment(server) as dns:
            with self.assertRaises(SyntheticBrowserError):
                self.browser.navigate()
            dns.assert_not_called()
        self.assertEqual(server.accept_count, 0)
        self.assertFalse(self.browser.observations[0].delivered)
        self.assertTrue(self.browser.closed)

    def test_real_iframe_popup_and_changed_document_do_not_extend_authority(self):
        # Same exact URL in an iframe still is not the authorized main document.
        self.html += (b'<iframe src="https://browser.test/test?q=caf%C3%A9%20%26%20test"></iframe>'
                      b'<button id="popup" onclick="window.open(\'https://browser.test/test?q=caf%C3%A9%20%26%20test\')">popup</button>'
                      b'<button id="change" onclick="location.href=\'about:blank\'">change</button>')
        self.browser.__enter__()
        with lab.LocalTLSServer(self.wire()) as server, self.lab.environment(server) as dns:
            with closing(self.browser):
                self.browser.navigate()
                self.assertGreaterEqual(self.browser.blocked_requests, 1)
                self.browser.click("#popup")
                self.browser._page.wait_for_timeout(100)
                self.assertEqual(len(self.browser._context.pages), 1)
                self.browser.click("#change")
                self.browser._page.wait_for_url("about:blank")
                with self.assertRaisesRegex(SyntheticBrowserError, "document_provenance_lost"):
                    self.browser.extract((("status", "h1"),))
                self.assertEqual(len(self.lab.owner._reservations), 1)
        self.lab.assert_connected_and_closed(server, dns)


if __name__ == "__main__":
    unittest.main()
