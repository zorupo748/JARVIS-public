"""Tests for URLValidator and SecureWebSession in jarvis.core.security."""

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from jarvis.core.security.url_validator import URLValidator
from jarvis.core.security.secure_browser import SecureWebSession


class TestURLValidator(unittest.TestCase):
    def setUp(self):
        self.validator = URLValidator(allowed_domains=["wikipedia.org", "*.github.com"])

    def test_empty_or_whitespace_urls(self):
        for invalid in ["", "   ", "\t\n", None, 123]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.validator.validate_and_normalize(invalid)

    def test_scheme_enforcement(self):
        insecure_urls = [
            "http://wikipedia.org",
            "ftp://wikipedia.org",
            "file:///etc/passwd",
            "data:text/html,<html></html>",
            "javascript:alert(1)",
        ]
        for url in insecure_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    self.validator.validate_and_normalize(url)

    def test_missing_or_invalid_netloc(self):
        invalid_hosts = [
            "https://",
            "https:///path",
            "https://:443",
        ]
        for url in invalid_hosts:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    self.validator.validate_and_normalize(url)

    def test_embedded_credentials_rejected(self):
        phishing_attempts = [
            "https://admin:pass@wikipedia.org",
            "https://user@wikipedia.org",
            "https://legit.com@evil.com",
            "https://wikipedia.org@github.com",
        ]
        for url in phishing_attempts:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    self.validator.validate_and_normalize(url)

    def test_allowed_domains_exact_and_wildcard(self):
        # Allowed: wikipedia.org, *.github.com (matches github.com and sub.github.com)
        valid = [
            ("https://wikipedia.org/wiki/Python", "https://wikipedia.org/wiki/Python"),
            ("https://WIKIPEDIA.ORG/test", "https://wikipedia.org/test"),
            ("https://github.com/torvalds", "https://github.com/torvalds"),
            ("https://api.github.com/repos", "https://api.github.com/repos"),
            ("https://raw.github.com/file", "https://raw.github.com/file"),
        ]
        for input_url, expected in valid:
            with self.subTest(input_url=input_url):
                self.assertEqual(self.validator.validate_and_normalize(input_url), expected)

    def test_disallowed_domains_raise_permission_error(self):
        disallowed = [
            "https://sub.wikipedia.org",  # exact match only
            "https://google.com",
            "https://evil-github.com",
            "https://github.com.evil.com",
        ]
        for url in disallowed:
            with self.subTest(url=url):
                with self.assertRaises(PermissionError):
                    self.validator.validate_and_normalize(url)

    def test_fragment_stripping_and_normalization(self):
        url = "https://wikipedia.org/wiki/Test#Section1"
        normalized = self.validator.validate_and_normalize(url)
        self.assertEqual(normalized, "https://wikipedia.org/wiki/Test")

        # Query preserved, fragment removed
        url_with_query = "https://github.com/search?q=playwright#results"
        normalized_query = self.validator.validate_and_normalize(url_with_query)
        self.assertEqual(normalized_query, "https://github.com/search?q=playwright")

    def test_no_allowed_domains_configured_permits_any_valid_https(self):
        open_validator = URLValidator()
        self.assertEqual(
            open_validator.validate_and_normalize("https://example.com/"),
            "https://example.com/"
        )


class TestSecureWebSession(unittest.IsolatedAsyncioTestCase):
    def test_invalid_timeout(self):
        for bad_timeout in [0, -500, "15000", None]:
            with self.subTest(bad_timeout=bad_timeout):
                with self.assertRaises(ValueError):
                    SecureWebSession(timeout_ms=bad_timeout)

    @patch("jarvis.core.security.secure_browser.async_playwright")
    async def test_fetch_dom_success(self, mock_playwright):
        # Set up mocks
        mock_page = AsyncMock()
        mock_page.content.return_value = "<html><body><h1>Success</h1></body></html>"

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        mock_chromium = AsyncMock()
        mock_chromium.launch.return_value = mock_browser

        mock_p = AsyncMock()
        mock_p.chromium = mock_chromium

        # Context manager for async_playwright
        mock_playwright.return_value.__aenter__.return_value = mock_p

        session = SecureWebSession(allowed_domains=["wikipedia.org"])
        content = await session.fetch_dom("https://wikipedia.org/wiki/Python")

        self.assertIn("<h1>Success</h1>", content)
        mock_chromium.launch.assert_called_once_with(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )
        mock_page.goto.assert_called_once_with(
            "https://wikipedia.org/wiki/Python",
            timeout=15000,
            wait_until="domcontentloaded"
        )
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()

    @patch("jarvis.core.security.secure_browser.async_playwright")
    async def test_fetch_dom_timeout_handling(self, mock_playwright):
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError

        mock_page = AsyncMock()
        mock_page.goto.side_effect = PlaywrightTimeoutError("Timeout 15000ms exceeded")

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        mock_chromium = AsyncMock()
        mock_chromium.launch.return_value = mock_browser

        mock_p = AsyncMock()
        mock_p.chromium = mock_chromium
        mock_playwright.return_value.__aenter__.return_value = mock_p

        session = SecureWebSession(allowed_domains=["wikipedia.org"])
        with self.assertRaises(TimeoutError):
            await session.fetch_dom("https://wikipedia.org/timeout")

        # Ensure cleanup occurred even on failure
        mock_context.close.assert_called_once()
        mock_browser.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
