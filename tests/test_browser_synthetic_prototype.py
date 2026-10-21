"""Real Chromium tests are explicitly skipped when no local executable exists.

Unit tests below use mocks; integration tests use real Playwright/Chromium,
memory HTML and abort-only routing, never public navigation or real services.
"""

import os
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock

from jarvis.experimental.synthetic_browser import (
    SyntheticBrowser, SyntheticBrowserError, SyntheticDOMObservation,
)


class SyntheticPrototypeUnitTests(unittest.TestCase):
    def test_input_validation_without_launch(self):
        for path, timeout in ((None, 100), ("", 100), ("browser", True), ("browser", 0)):
            with self.subTest(path=path, timeout=timeout), self.assertRaises(ValueError):
                SyntheticBrowser(path, timeout_ms=timeout)

    def test_request_and_websocket_handlers_are_abort_only_mocks(self):
        prototype = SyntheticBrowser("unused")
        request = Mock()
        websocket = Mock()
        prototype._abort_request(request)
        prototype._abort_websocket(websocket)
        request.abort.assert_called_once_with("blockedbyclient")
        request.continue_.assert_not_called()
        request.fetch.assert_not_called()
        websocket.close.assert_called_once_with(code=1008, reason="synthetic_only")
        websocket.connect_to_server.assert_not_called()
        self.assertEqual(prototype.blocked_requests, 2)

    def test_cleanup_attempts_all_resources_on_failure_mocks(self):
        prototype = SyntheticBrowser("unused")
        context, browser, driver = Mock(), Mock(), Mock()
        prototype._context, prototype._browser, prototype._driver = context, browser, driver
        context.close.side_effect = RuntimeError("DO_NOT_LEAK")
        with self.assertRaisesRegex(SyntheticBrowserError, "^cleanup_failed$"):
            prototype.close()
        browser.close.assert_called_once()
        driver.stop.assert_called_once()
        self.assertTrue(prototype.closed)
        prototype.close()

    def test_observation_provenance_immutability_and_safe_repr(self):
        observation = SyntheticDOMObservation("fixture-1", (("status", "DO_NOT_LEAK"),))
        self.assertEqual(observation.provenance, "synthetic_dom")
        self.assertNotIn("DO_NOT_LEAK", repr(observation))
        with self.assertRaises(FrozenInstanceError):
            observation.fixture_id = "other"
        for fields in ([], (), (("status", "x"), ("status", "y")), (("status", None),)):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                SyntheticDOMObservation("fixture", fields)

    def test_lifecycle_before_launch_and_after_close(self):
        prototype = SyntheticBrowser("unused")
        with self.assertRaisesRegex(SyntheticBrowserError, "^invalid_lifecycle$"):
            prototype.read_text("h1")
        prototype.close()
        with self.assertRaisesRegex(SyntheticBrowserError, "^invalid_lifecycle$"):
            prototype.__enter__()

    def test_partial_load_failure_poison_closes_context_mocks(self):
        from unittest.mock import patch
        prototype = SyntheticBrowser("unused")
        context, browser, driver, page = Mock(), Mock(), Mock(), Mock()
        prototype._context, prototype._browser, prototype._driver, prototype._page = context, browser, driver, page
        with patch.object(prototype, "_invoke", side_effect=SyntheticBrowserError("dom_timeout")):
            with self.assertRaisesRegex(SyntheticBrowserError, "^dom_timeout$"):
                prototype.load_html("partial", "<p>partial</p>")
        self.assertTrue(prototype.closed)
        context.close.assert_called_once()
        browser.close.assert_called_once()
        driver.stop.assert_called_once()

    def test_start_context_failure_cleans_browser_and_driver_mocks(self):
        from unittest.mock import patch
        try:
            from playwright.sync_api import Error
        except ImportError:
            self.skipTest("Playwright dependency unavailable for startup mock")
        driver, browser = Mock(), Mock()
        driver.chromium.launch.return_value = browser
        browser.new_context.side_effect = Error("DO_NOT_LEAK")
        with patch("playwright.sync_api.sync_playwright") as factory:
            factory.return_value.start.return_value = driver
            prototype = SyntheticBrowser("unused")
            with self.assertRaisesRegex(SyntheticBrowserError, "^browser_start_failed$"):
                prototype.__enter__()
        browser.close.assert_called_once()
        driver.stop.assert_called_once()
        self.assertTrue(prototype.closed)
        self.assertTrue(driver.chromium.launch.call_args.kwargs["chromium_sandbox"])
        self.assertEqual(browser.new_context.call_args.kwargs,
                         dict(service_workers="block", accept_downloads=False,
                              permissions=[], ignore_https_errors=False))


class SyntheticPrototypeRealChromiumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest("REAL CHROMIUM NOT EXECUTED: Playwright not installed")
        explicit = os.environ.get("JARVIS_SYNTHETIC_CHROMIUM")
        paths = [Path(explicit)] if explicit else []
        if not explicit:
            with sync_playwright() as p:
                paths.append(Path(p.chromium.executable_path))
            cache = Path(os.environ.get("LOCALAPPDATA", ".")) / "ms-playwright"
            paths.extend(sorted(cache.glob("chromium-*/chrome-win64/chrome.exe"), reverse=True))
        cls.executable = next((str(path) for path in paths if path.is_file()), None)
        if cls.executable is None:
            raise unittest.SkipTest("REAL CHROMIUM NOT EXECUTED: no existing executable; no auto-download")
        cls.html = (Path(__file__).parent / "fixtures" / "synthetic_tracking.html").read_text(encoding="utf-8")

    def setUp(self):
        self.prototype = SyntheticBrowser(self.executable, timeout_ms=500)
        # Launch failures are test failures, not silently converted into skips.
        self.prototype.__enter__()
        self.addCleanup(self.prototype.close)

    def load(self):
        self.prototype.load_html("synthetic-tracking-v1", self.html)

    def test_real_start_temporary_context_dom_and_close(self):
        self.load()
        self.assertEqual(self.prototype._context.cookies(), [])
        self.assertEqual(self.prototype._page.url, "about:blank")
        self.assertIn("ningún servicio real", self.prototype.read_text("h1"))
        browser = self.prototype._browser
        self.assertTrue(browser.is_connected())
        self.prototype.close()
        self.assertTrue(self.prototype.closed)
        self.assertFalse(browser.is_connected())

    def test_real_form_click_dynamic_javascript_and_structured_extraction(self):
        self.load()
        self.prototype.fill("#tracking-code", "DEMO-001")
        self.prototype.click("#track")
        self.prototype.wait_text("#status", "En tránsito (simulado)")
        result = self.prototype.extract((("code", "#observed-code"), ("status", "#status")))
        self.assertEqual(result.fields, (("code", "DEMO-001"), ("status", "En tránsito (simulado)")))
        self.assertEqual(result.fixture_id, "synthetic-tracking-v1")
        self.assertEqual(result.provenance, "synthetic_dom")

    def test_real_unknown_code_does_not_invent_status(self):
        self.load()
        self.prototype.fill("#tracking-code", "UNKNOWN")
        self.prototype.click("#track")
        self.prototype.wait_text("#status", "Sin datos en la fixture")
        self.assertEqual(self.prototype.read_text("#status"), "Sin datos en la fixture")
        with self.assertRaisesRegex(SyntheticBrowserError, "^element_missing$"):
            self.prototype.extract((("real_service_result", "#not-present"),))

    def test_real_missing_ambiguous_and_invalid_elements(self):
        self.load()
        for selector, code in (("#missing", "element_missing"), ("button", "element_ambiguous"),
                               ("[", "dom_operation_failed")):
            with self.subTest(selector=selector), self.assertRaisesRegex(SyntheticBrowserError, f"^{code}$"):
                self.prototype.read_text(selector)

    def test_real_timeout_is_explicit_and_does_not_return_content(self):
        self.load()
        with self.assertRaisesRegex(SyntheticBrowserError, "^dom_timeout$"):
            self.prototype.wait_text("#status", "never-produced")

    def test_real_fetch_is_intercepted_and_rejected(self):
        self.load()
        self.prototype.click("#network")
        self.prototype.wait_text("#network-result", "blocked")
        self.assertGreaterEqual(self.prototype.blocked_requests, 1)
        self.assertEqual(self.prototype.read_text("#network-result"), "blocked")

    def test_real_exception_closes_context_and_browser(self):
        self.prototype.close()
        with self.assertRaisesRegex(RuntimeError, "^test exception$"):
            with SyntheticBrowser(self.executable, timeout_ms=500) as prototype:
                browser = prototype._browser
                prototype.load_html("exception-fixture", self.html)
                raise RuntimeError("test exception")
        self.assertTrue(prototype.closed)
        self.assertFalse(browser.is_connected())

    def test_real_fixture_cannot_be_replaced_in_same_context(self):
        self.load()
        with self.assertRaisesRegex(SyntheticBrowserError, "^fixture_already_loaded$"):
            self.prototype.load_html("other", "<p>other</p>")


if __name__ == "__main__":
    unittest.main()
