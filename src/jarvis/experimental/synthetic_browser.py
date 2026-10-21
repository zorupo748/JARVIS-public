"""Memory-only DOM prototype for TRUSTED synthetic fixtures, not Internet use.

Request/WebSocket interceptors and a dead-end proxy are defense in depth, NOT
network isolation. Chromium background traffic and OS behavior are not proven
contained. No production permissions, HTTP transport, broker or supervisor is
connected. No arbitrary URLs, JavaScript, browser launch arguments or profiles
are exposed by this interface. The executable is selected by test infrastructure.
Text is observed in a synthetic DOM, never evidence from a real tracking service.
"""

from dataclasses import dataclass, field


class SyntheticBrowserError(RuntimeError):
    """Fixed prototype error; underlying browser messages are never exported."""


def _string(value, maximum):
    if type(value) is not str or not value or len(value) > maximum:
        raise ValueError("invalid synthetic browser input")


@dataclass(frozen=True, slots=True)
class SyntheticDOMObservation:
    fixture_id: str
    fields: tuple[tuple[str, str], ...] = field(repr=False)
    provenance: str = "synthetic_dom"

    def __post_init__(self):
        _string(self.fixture_id, 128)
        if type(self.provenance) is not str or self.provenance != "synthetic_dom":
            raise ValueError("invalid synthetic observation")
        if type(self.fields) is not tuple or not 1 <= len(self.fields) <= 16:
            raise ValueError("invalid synthetic observation")
        names = set()
        for pair in self.fields:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("invalid synthetic observation")
            name, text = pair
            _string(name, 128)
            if type(text) is not str or len(text) > 4096 or name in names:
                raise ValueError("invalid synthetic observation")
            names.add(name)


class SyntheticBrowser:
    """One temporary context, fixed launch policy, bounded DOM operations.

    Only trusted test HTML is permitted. This is not a security boundary against
    arbitrary Python callers or hostile HTML. Observation construction records
    shape/provenance labels, not unforgeable collector authenticity.
    """

    def __init__(self, executable_path: str, *, timeout_ms: int = 1000):
        _string(executable_path, 4096)
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 10000:
            raise ValueError("invalid synthetic browser input")
        self._executable = executable_path
        self._timeout = timeout_ms
        self._driver = self._browser = self._context = self._page = None
        self._fixture_id = None
        self._closed = False
        self._blocked_requests = 0

    @property
    def closed(self):
        return self._closed

    @property
    def blocked_requests(self):
        return self._blocked_requests

    def __repr__(self):
        return "SyntheticBrowser(closed)" if self.closed else "SyntheticBrowser(open)"

    def __enter__(self):
        if self._closed or self._driver is not None:
            raise SyntheticBrowserError("invalid_lifecycle")
        try:
            from playwright.sync_api import sync_playwright, Error
        except ImportError:
            raise SyntheticBrowserError("playwright_unavailable") from None
        try:
            self._driver = sync_playwright().start()
            self._browser = self._driver.chromium.launch(
                executable_path=self._executable, headless=True, chromium_sandbox=True,
                proxy={"server": "http://127.0.0.1:9", "bypass": "<-loopback>"},
                args=["--disable-background-networking", "--disable-quic",
                      "--disable-component-update", "--disable-sync", "--no-first-run"],
                timeout=10000,
            )
            self._context = self._browser.new_context(
                service_workers="block", accept_downloads=False, permissions=[],
                ignore_https_errors=False,
            )
            self._context.set_default_timeout(self._timeout)
            self._context.route("**/*", self._abort_request)
            self._context.route_web_socket("**/*", self._abort_websocket)
            self._page = self._context.new_page()
            self._context.on("page", lambda page: page.close())
            self._page.on("download", lambda download: download.cancel())
            return self
        except Error:
            self.close()
            raise SyntheticBrowserError("browser_start_failed") from None
        except BaseException:
            self.close()
            raise

    def _abort_request(self, route):
        self._blocked_requests += 1
        route.abort("blockedbyclient")

    def _abort_websocket(self, route):
        self._blocked_requests += 1
        route.close(code=1008, reason="synthetic_only")

    def _require_page(self):
        if self._closed or self._page is None:
            raise SyntheticBrowserError("invalid_lifecycle")

    def _invoke(self, operation):
        from playwright.sync_api import Error, TimeoutError
        try:
            return operation()
        except TimeoutError:
            raise SyntheticBrowserError("dom_timeout") from None
        except Error:
            raise SyntheticBrowserError("dom_operation_failed") from None

    def load_html(self, fixture_id: str, html: str):
        self._require_page()
        _string(fixture_id, 128)
        _string(html, 65536)
        # A second fixture needs a fresh context so cookies/storage/JS state
        # cannot migrate between fixtures through about:blank's shared URL.
        if self._fixture_id is not None:
            raise SyntheticBrowserError("fixture_already_loaded")
        try:
            self._invoke(lambda: self._page.set_content(html, wait_until="load", timeout=self._timeout))
        except BaseException:
            # A partially loaded fixture is never eligible for extraction.
            self.close()
            raise
        self._fixture_id = fixture_id

    def _locator(self, selector):
        self._require_page()
        if self._fixture_id is None:
            raise SyntheticBrowserError("fixture_not_loaded")
        _string(selector, 256)
        locator = self._page.locator(selector)
        count = self._invoke(locator.count)
        if count != 1:
            raise SyntheticBrowserError("element_missing" if count == 0 else "element_ambiguous")
        return locator

    def read_text(self, selector: str):
        locator = self._locator(selector)
        text = self._invoke(locator.text_content)
        if text is None or len(text) > 4096:
            raise SyntheticBrowserError("invalid_dom_text")
        return text

    def fill(self, selector: str, value: str):
        if type(value) is not str or len(value) > 1024:
            raise ValueError("invalid synthetic browser input")
        locator = self._locator(selector)
        self._invoke(lambda: locator.fill(value))

    def click(self, selector: str):
        locator = self._locator(selector)
        self._invoke(locator.click)

    def wait_text(self, selector: str, expected: str):
        if type(expected) is not str or len(expected) > 4096:
            raise ValueError("invalid synthetic browser input")
        self._locator(selector)
        handle = self._invoke(lambda: self._page.wait_for_function(
            "({selector, expected}) => { const e = document.querySelectorAll(selector); "
            "return e.length === 1 && e[0].textContent === expected; }",
            arg={"selector": selector, "expected": expected}, timeout=self._timeout,
        ))
        self._invoke(handle.dispose)

    def extract(self, fields: tuple[tuple[str, str], ...]):
        if type(fields) is not tuple or not 1 <= len(fields) <= 16:
            raise ValueError("invalid synthetic browser input")
        names = set()
        for pair in fields:
            if type(pair) is not tuple or len(pair) != 2:
                raise ValueError("invalid synthetic browser input")
            name, selector = pair
            _string(name, 128)
            _string(selector, 256)
            if name in names:
                raise ValueError("invalid synthetic browser input")
            names.add(name)
        return SyntheticDOMObservation(self._fixture_id, tuple(
            (name, self.read_text(selector)) for name, selector in fields))

    def close(self):
        if self._closed:
            return
        failed = False
        for resource, method in ((self._context, "close"), (self._browser, "close"), (self._driver, "stop")):
            if resource is not None:
                try:
                    getattr(resource, method)()
                except Exception:
                    failed = True
        self._page = self._context = self._browser = self._driver = None
        self._closed = True
        if failed:
            raise SyntheticBrowserError("cleanup_failed") from None

    def __exit__(self, *args):
        self.close()
        return False
