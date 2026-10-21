"""Unit tests for SecureSearchSkill in jarvis.skills.secure_search_skill."""

import unittest
from unittest.mock import AsyncMock, patch
from playwright.async_api import (
    Error as PlaywrightError,
    TimeoutError as PlaywrightTimeoutError,
)

from jarvis.skills.secure_search_skill import SecureSearchSkill


WIKIPEDIA_MOCK_HTML = """
<!DOCTYPE html>
<html>
<head><title>Quantum computing - Wikipedia</title></head>
<body>
<div id="mw-content-text">
    <div class="mw-parser-output">
        <table class="infobox">
            <tr><th>Infobox Header</th></tr>
            <tr><td>Infobox details that should be discarded</td></tr>
        </table>
        <div class="shortdescription">Subfield of computer science</div>
        <div class="toc" id="toc"><h2>Contents</h2></div>
        <p>Quantum computing is a rapidly-emerging technology that harnesses the laws of quantum mechanics to solve problems too complex for classical computers.</p>
        <p>Today, IBM Quantum hardware and open-source Qiskit software tools are available to thousands of developers.</p>
        <div class="navbox"><p>Navigation footer items that should be discarded</p></div>
    </div>
</div>
</body>
</html>
"""


class TestSecureSearchSkill(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.skill = SecureSearchSkill()

    def test_invalid_query_raises_value_error(self):
        for invalid in ["", "   ", "\t\n", None]:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    # We can pass through asyncio or test synchronous check
                    import asyncio
                    asyncio.run(self.skill.search_topic(invalid))

    def test_wikipedia_url_generation(self):
        url = self.skill._build_wikipedia_url("Artificial intelligence")
        self.assertEqual(url, "https://en.wikipedia.org/wiki/Artificial_intelligence")

        # Automatically capitalizes initial letter (standard MediaWiki title rule)
        lower_url = self.skill._build_wikipedia_url("artificial intelligence")
        self.assertEqual(lower_url, "https://en.wikipedia.org/wiki/Artificial_intelligence")

        # Special:Search route
        search_url = self.skill._build_wikipedia_url("Artificial Intelligence", use_search_route=True)
        self.assertEqual(search_url, "https://en.wikipedia.org/wiki/Special:Search?search=Artificial+Intelligence")

        # Explicit Special:Search query string
        explicit_search = self.skill._build_wikipedia_url("Special:Search?search=Artificial Intelligence")
        self.assertEqual(explicit_search, "https://en.wikipedia.org/wiki/Special:Search?search=Artificial+Intelligence")

        # Spanish language instance
        es_skill = SecureSearchSkill(lang="es")
        es_url = es_skill._build_wikipedia_url("Inteligencia artificial")
        self.assertEqual(es_url, "https://es.wikipedia.org/wiki/Inteligencia_artificial")

    def test_extract_summary_with_indicator_lock_and_content_text(self):
        html_with_indicator = """
        <html>
        <body>
            <div id="mw-indicator-pp-default" class="mw-indicator">
                <div class="mw-parser-output"></div>
            </div>
            <div id="mw-content-text" class="mw-body-content">
                <div class="mw-parser-output">
                    <p>Artificial intelligence (AI) is the capability of computational systems to perform tasks typically associated with human intelligence.</p>
                    <p>High-profile applications of AI include advanced web search engines, recommendation systems, and autonomous vehicles.</p>
                </div>
            </div>
        </body>
        </html>
        """
        summary = self.skill._extract_summary(html_with_indicator, "Artificial Intelligence")
        self.assertIn("Artificial intelligence (AI) is the capability", summary)
        self.assertIn("High-profile applications of AI include", summary)

    def test_extract_summary_search_results_page(self):
        search_html = """
        <html>
        <body>
            <div id="mw-content-text">
                <ul class="mw-search-results">
                    <li>
                        <div class="mw-search-result-heading"><a href="/wiki/Transformer_(deep_learning)">Transformer (deep learning)</a></div>
                        <div class="searchresult">In deep learning, the transformer is a neural network architecture based on self-attention.</div>
                    </li>
                </ul>
            </div>
        </body>
        </html>
        """
        summary = self.skill._extract_summary(search_html, "transformer")
        self.assertIn("[Transformer (deep learning)]:", summary)
        self.assertIn("In deep learning, the transformer is a neural network", summary)

    @patch("jarvis.core.security.secure_browser.async_playwright")
    async def test_search_topic_extracts_clean_summary(self, mock_playwright):
        # Set up Playwright page mock
        mock_page = AsyncMock()
        mock_page.content.return_value = WIKIPEDIA_MOCK_HTML

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        mock_chromium = AsyncMock()
        mock_chromium.launch.return_value = mock_browser

        mock_p = AsyncMock()
        mock_p.chromium = mock_chromium
        mock_playwright.return_value.__aenter__.return_value = mock_p

        summary = await self.skill.search_topic("Quantum computing")

        # Verify main paragraphs extracted
        self.assertIn("Quantum computing is a rapidly-emerging technology", summary)
        self.assertIn("Today, IBM Quantum hardware", summary)

        # Verify unwanted elements (infobox, navbox) were discarded
        self.assertNotIn("Infobox details that should be discarded", summary)
        self.assertNotIn("Navigation footer items", summary)

        # Verify correct URL was visited with security flags
        mock_page.goto.assert_called_once_with(
            "https://en.wikipedia.org/wiki/Quantum_computing",
            timeout=15000,
            wait_until="domcontentloaded",
        )
        mock_chromium.launch.assert_called_once_with(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )

    @patch("jarvis.core.security.secure_browser.async_playwright")
    async def test_unauthorized_domain_is_rejected(self, mock_playwright):
        # Playwright should never be called when domain validation fails
        unauthorized_urls = [
            "https://evil.com/wiki/Quantum_computing",
            "https://google.com/search?q=test",
            "https://fake-wikipedia.org/article",
        ]

        for url in unauthorized_urls:
            with self.subTest(url=url):
                with self.assertRaises(PermissionError):
                    await self.skill.search_topic(url)

        # Ensure browser was never launched
        mock_playwright.assert_not_called()

    @patch("jarvis.core.security.secure_browser.async_playwright")
    async def test_search_topic_timeout_handling(self, mock_playwright):
        mock_page = AsyncMock()
        mock_page.goto.side_effect = PlaywrightTimeoutError("Navigation timeout of 15000ms exceeded")

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        mock_chromium = AsyncMock()
        mock_chromium.launch.return_value = mock_browser

        mock_p = AsyncMock()
        mock_p.chromium = mock_chromium
        mock_playwright.return_value.__aenter__.return_value = mock_p

        with self.assertRaises(TimeoutError) as ctx:
            await self.skill.search_topic("Large language model")

        self.assertIn("Secure search timeout", str(ctx.exception))

    @patch("jarvis.core.security.secure_browser.async_playwright")
    async def test_search_topic_runtime_network_error(self, mock_playwright):
        mock_page = AsyncMock()
        mock_page.goto.side_effect = PlaywrightError("net::ERR_CONNECTION_REFUSED")

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page

        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context

        mock_chromium = AsyncMock()
        mock_chromium.launch.return_value = mock_browser

        mock_p = AsyncMock()
        mock_p.chromium = mock_chromium
        mock_playwright.return_value.__aenter__.return_value = mock_p

        with self.assertRaises(RuntimeError) as ctx:
            await self.skill.search_topic("Machine learning")

        self.assertIn("net::ERR_CONNECTION_REFUSED", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
