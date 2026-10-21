"""Opt-in synthetic browser.test laboratory bridge, never production routing.

Playwright interception/dead-end proxy do NOT isolate Chromium network access.
TLS is performed by JARVIS, not Chromium. Trusted bootstrap owns the gateway,
authority and one registered binding. No arbitrary URL or headers are accepted.
Delivery authorization is a commitment immediately before fulfill, not atomic
revocation of an external browser or removal of already delivered DOM data.
"""
from dataclasses import dataclass, field, replace

from jarvis.experimental.synthetic_browser import SyntheticBrowser, SyntheticBrowserError
from jarvis.core.browser_http_transport import BrowserHTTPRequest, BrowserHTTPResponse, _request_target
from jarvis.core.browser_http_dispatch_gateway import BrowserHTTPDispatchGateway
from jarvis.core.browser_navigation_supervisor import BrowserNavigationAuthority


@dataclass(frozen=True, slots=True)
class BrowserDeliveryObservation:
    """delivered means confirmed delivery; False is not proof of no delivery.

    delivery_uncertain means fulfill began but no successful acknowledgement
    was obtained. Previously accepted content cannot be withdrawn atomically.
    """
    fixture_id: str
    status: str
    http_status: int | None
    http_received: bool
    delivered: bool
    provenance: str = "jarvis_broker_http_to_synthetic_browser"


def fulfillment(response, method):
    """Fail closed on headers whose multiplicity/side effects cannot be kept."""
    if type(response) is not BrowserHTTPResponse or method not in {"GET", "HEAD"}:
        raise SyntheticBrowserError("invalid_response")
    headers = {}
    for name, value in response.headers:
        if name in {"set-cookie", "www-authenticate", "proxy-authenticate", "content-disposition", "refresh"}:
            raise SyntheticBrowserError("unsupported_response_headers")
        if name in headers:
            raise SyntheticBrowserError("duplicate_response_headers")
        headers[name] = value
    # Bodies have already been decoded from HTTP framing. Do not synthesize
    # header folding, silently drop CSP, or retain original wire lengths.
    for name in {"connection", "transfer-encoding", "content-length", "keep-alive"}:
        headers.pop(name, None)
    if "trailer" in headers or "upgrade" in headers or "proxy-connection" in headers:
        raise SyntheticBrowserError("unsupported_response_headers")
    if response.is_redirect:
        raise SyntheticBrowserError("redirect_denied")
    return dict(status=response.status_code, headers=headers, body=b"" if method == "HEAD" else response.body)


class GatewayLaboratoryBrowser(SyntheticBrowser):
    """One opt-in trusted fixture; inherits temporary context and DOM methods."""
    def __init__(self, executable_path, *, enabled=False, gateway, authority, session,
                 request, context, fixture_id, response_byte_budget=65536, timeout_ms=5000):
        if enabled is not True:
            raise SyntheticBrowserError("experimental_disabled")
        if (type(gateway) is not BrowserHTTPDispatchGateway or type(authority) is not BrowserNavigationAuthority
                or authority is not gateway._authority or type(request) is not BrowserHTTPRequest
                or request.origin.hostname != "browser.test" or type(fixture_id) is not str
                or not 1 <= len(fixture_id) <= 128):
            raise ValueError("invalid laboratory infrastructure")
        super().__init__(executable_path, timeout_ms=timeout_ms)
        self._gateway, self._authority, self._session = gateway, authority, session
        self._request, self._binding_context = replace(request), replace(context)
        self._budget, self._lab_fixture = response_byte_budget, fixture_id
        self._target = "https://browser.test" + _request_target(request.static_path, request.query_parameters)
        self._attempt = 0
        self._delivery_failed = False
        self.observations = []

    def load_html(self, *args, **kwargs):
        raise SyntheticBrowserError("gateway_content_only")

    def navigate(self):
        self._require_page()
        if self._fixture_id is not None:
            raise SyntheticBrowserError("fixture_already_loaded")
        try:
            self._invoke(lambda: self._page.goto(self._target, wait_until="load", timeout=self._timeout))
            if not self.observations or not self.observations[-1].delivered:
                raise SyntheticBrowserError("content_not_delivered")
            self._fixture_id = self._lab_fixture
        except BaseException:
            self.close()
            raise

    def _abort_request(self, route):
        browser_request = route.request
        if (self._attempt != 0 or browser_request.url != self._target or browser_request.method != self._request.method
                or browser_request.post_data is not None or not browser_request.is_navigation_request()
                or browser_request.frame != self._page.main_frame):
            return super()._abort_request(route)
        self._attempt += 1
        received, code = False, None
        fulfilling = False
        try:
            result = self._gateway.dispatch(self._session, "browser-attempt-" + str(self._attempt),
                self._request, self._binding_context, response_byte_budget=self._budget)
            received, code = result.observation.response_validated, result.observation.http_status
            if not result.response_released:
                raise SyntheticBrowserError(result.status.value)
            args = fulfillment(result.exchange.response, self._request.method)
            if not self._authority.authorize_delivery(result.lifecycle.reservation):
                raise SyntheticBrowserError("delivery_revoked")
            fulfilling = True
            route.fulfill(**args)
        except BaseException as error:
            self._delivery_failed = True
            status = "delivery_uncertain" if fulfilling else "delivery_error"
            safe_reasons = {"not_sent", "send_unknown", "error", "rejected", "delivery_revoked",
                            "unsupported_response_headers", "duplicate_response_headers", "redirect_denied", "invalid_response"}
            if not fulfilling and type(error) is SyntheticBrowserError and error.args and error.args[0] in safe_reasons:
                status = error.args[0]
            self.observations.append(BrowserDeliveryObservation(self._lab_fixture, status, code, received, False))
            try:
                route.abort("blockedbyclient")
            except Exception:
                # Abort can fail if fulfillment already settled the route.
                # Preserve uncertainty, never retry or refund the commitment.
                pass
            if not isinstance(error, Exception):
                raise
        else:
            self.observations.append(BrowserDeliveryObservation(self._lab_fixture, "delivered", code, received, True))

    def _locator(self, selector):
        self._require_page()
        if (self._delivery_failed or self._page.url != self._target or not self.observations
                or not self.observations[0].delivered):
            raise SyntheticBrowserError("document_provenance_lost")
        return super()._locator(selector)

    def extract(self, fields):
        result = super().extract(fields)
        return GatewayDOMObservation(result.fixture_id, result.fields, self.observations[-1].http_status)


@dataclass(frozen=True, slots=True)
class GatewayDOMObservation:
    fixture_id: str
    fields: tuple[tuple[str, str], ...] = field(repr=False)
    http_status: int
    provenance: str = "synthetic_dom_after_jarvis_broker_http"
