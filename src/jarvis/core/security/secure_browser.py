"""Secure Browser Session Module for JARVIS.

Provides an isolated, ephemeral web automation session utilizing Playwright with strict
sandboxing arguments, route-level resource filtration, and robust resource cleanup.
"""

import asyncio
import concurrent.futures
import logging
from typing import Any, Dict, List, Optional, Sequence
from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Route,
    TimeoutError as PlaywrightTimeoutError,
    async_playwright,
)

from .url_validator import URLValidator

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

CHROMIUM_SECURITY_ARGS: List[str] = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
]


def _run_coroutine_sync(coro: Any) -> Any:
    """Execute an asynchronous coroutine safely from synchronous contexts."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


class SecureWebSession:
    """Manages an isolated and secure Playwright headless browser session.

    Enforces input URL validation, blocks non-essential and unauthorized resources,
    and guarantees immediate cleanup of ephemeral contexts and browser processes.
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        timeout_ms: int = 15000,
        user_agent: str = DEFAULT_USER_AGENT,
        allow_http: bool = False,
    ) -> None:
        """Initialize the secure web session configuration.

        Args:
            allowed_domains: Optional list of authorized domain patterns (e.g.
                ["wikipedia.org", "*.github.com"]).
            timeout_ms: Maximum duration in milliseconds allowed for navigation (default: 15000).
            user_agent: Modern desktop user-agent header for request identification.
            allow_http: Whether to permit http URLs alongside https (default: False).

        Raises:
            ValueError: If timeout_ms is not a positive integer.
        """
        if not isinstance(timeout_ms, int) or timeout_ms <= 0:
            raise ValueError(f"timeout_ms must be a positive integer, received: {timeout_ms}")

        self.allow_http: bool = allow_http
        self.validator: URLValidator = URLValidator(allowed_domains=allowed_domains, allow_http=allow_http)
        self.timeout_ms: int = timeout_ms
        self.user_agent: str = user_agent

    async def fetch_dom(self, target_url: str) -> str:
        """Execute a secure, isolated page visit and extract the rendered DOM HTML content.

        Workflow:
            1. Validate and canonicalize the target URL using the configured URLValidator.
            2. Initialize async Playwright session context.
            3. Launch headless Chromium with mandated security flags.
            4. Establish an isolated ephemeral browser context with custom desktop User-Agent.
            5. Create a new browser page.
            6. Intercept and abort performance-heavy resources (images, css, fonts, media)
               and block any request/redirect with unsupported schemes.
            7. Navigate to the verified safe URL waiting until 'domcontentloaded'.
            8. Retrieve the full HTML string content.
            9. Catch timeouts and network failures, raising clear standard exceptions.
            10. Guarantee context and browser termination in a finally block to eliminate orphan processes.

        Args:
            target_url: Raw URL string destination.

        Returns:
            The complete DOM content string as rendered upon 'domcontentloaded'.

        Raises:
            ValueError: If the target_url fails structural or protocol validation.
            PermissionError: If the target_url host is not permitted by domain policy.
            TimeoutError: If the page load exceeds the configured timeout threshold.
            RuntimeError: If a browser lifecycle, transport, or navigation error occurs.
        """
        # Step 1: Validate and normalize target URL
        safe_url: str = self.validator.validate_and_normalize(target_url)

        # Step 2: Initialize Playwright instance
        async with async_playwright() as playwright:
            browser: Optional[Browser] = None
            context: Optional[BrowserContext] = None

            try:
                # Step 3: Launch Chromium with mandatory security switches
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=CHROMIUM_SECURITY_ARGS,
                )

                # Step 4: Ephemeral isolated context with modern desktop User-Agent
                context = await browser.new_context(
                    user_agent=self.user_agent,
                    ignore_https_errors=False,
                )

                # Step 5: Open new page
                page: Page = await context.new_page()

                # Step 6: Route-level network request filtration
                async def route_handler(route: Route) -> None:
                    try:
                        request = route.request
                        # Abort heavy assets not required for DOM structure
                        if request.resource_type in {"image", "stylesheet", "font", "media"}:
                            await route.abort("blockedbyclient")
                            return

                        # Block requests or redirects whose protocol is not strictly https or http
                        req_url: str = request.url.lower()
                        if not (req_url.startswith("https://") or req_url.startswith("http://")):
                            await route.abort("blockedbyclient")
                            return

                        await route.continue_()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "route filtering", exc)

                await page.route("**/*", route_handler)

                # Step 7: Navigate to the validated URL
                await page.goto(
                    safe_url,
                    timeout=self.timeout_ms,
                    wait_until="domcontentloaded",
                )

                # Step 8: Capture complete page content
                dom_content: str = await page.content()
                return dom_content

            except PlaywrightTimeoutError as exc:
                # Step 9: Re-raise timeout with clear descriptive message
                raise TimeoutError(
                    f"Navigation to '{safe_url}' timed out after {self.timeout_ms} ms: {exc}"
                ) from exc
            except PlaywrightError as exc:
                # Step 9: Re-raise network or browser error with clear runtime exception
                raise RuntimeError(
                    f"Playwright navigation or browser failure while visiting '{safe_url}': {exc}"
                ) from exc
            except Exception as exc:
                raise RuntimeError(
                    f"Unexpected error while fetching DOM from '{safe_url}': {exc}"
                ) from exc

            finally:
                # Step 10: Guaranteed cleanup of browser context and instance
                if context is not None:
                    try:
                        await context.close()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "context cleanup", exc)
                if browser is not None:
                    try:
                        await browser.close()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "browser cleanup", exc)

    def fetch_dom_sync(self, target_url: str) -> str:
        """Synchronously execute fetch_dom safely across running or new event loops."""
        return _run_coroutine_sync(self.fetch_dom(target_url))

    async def render_and_inspect_spa(
        self,
        target_url: str,
        *,
        wait_timeout_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute a secure browser session to render a dynamic SPA and capture network/DOM facts.

        Workflow:
            1. Validate URL while preserving hash routing fragments (e.g. /#/).
            2. Launch isolated Chromium in headless mode with mandated security flags.
            3. Intercept network requests:
               - Abort heavy assets (images, stylesheets, fonts, media).
               - Capture outgoing requests, identifying calls to APIs or tracking endpoints (e.g. 1688track).
            4. Navigate to URL.
            5. Wait for dynamic DOM mounting (networkidle + selector polling).
            6. Extract search / input fields (names, ids, placeholders, types) from mounted DOM.
            7. Return structured inspection result: DOM content, search fields, captured requests, final URL, title.
        """
        timeout_limit = wait_timeout_ms or self.timeout_ms
        safe_url: str = self.validator.validate_and_normalize(
            target_url, preserve_fragment=True, allow_http=self.allow_http
        )

        async with async_playwright() as playwright:
            browser: Optional[Browser] = None
            context: Optional[BrowserContext] = None

            try:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=CHROMIUM_SECURITY_ARGS,
                )

                context = await browser.new_context(
                    user_agent=self.user_agent,
                    ignore_https_errors=False,
                )

                page: Page = await context.new_page()

                captured_requests: List[Dict[str, Any]] = []

                async def route_handler(route: Route) -> None:
                    try:
                        req = route.request
                        # Abort heavy assets not needed for DOM structure or API requests
                        if req.resource_type in {"image", "stylesheet", "font", "media"}:
                            await route.abort("blockedbyclient")
                            return

                        req_url_lower = req.url.lower()
                        if not (req_url_lower.startswith("https://") or req_url_lower.startswith("http://")):
                            await route.abort("blockedbyclient")
                            return

                        captured_requests.append({
                            "url": req.url,
                            "method": req.method,
                            "resource_type": req.resource_type,
                            "post_data": req.post_data,
                            "headers": dict(req.headers),
                        })
                        await route.continue_()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "route filtering", exc)

                await page.route("**/*", route_handler)

                await page.goto(
                    safe_url,
                    timeout=timeout_limit,
                    wait_until="domcontentloaded",
                )

                # Wait for SPA dynamic DOM mounting
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(3000, timeout_limit))
                except Exception as exc:
                    logger.debug("Non-fatal error ignored (%s): %s", "SPA networkidle wait", exc)

                try:
                    await page.wait_for_selector(
                        "input, form, button, [id*='track'], [class*='track'], [id*='search'], [class*='search'], #app > *, #root > *",
                        timeout=min(3000, timeout_limit),
                    )
                except Exception as exc:
                    logger.debug("Non-fatal error ignored (%s): %s", "selector wait", exc)

                # Extract search and tracking input fields
                search_fields: List[Dict[str, str]] = []
                inputs = await page.query_selector_all("input, textarea")
                for inp in inputs:
                    try:
                        inp_type = (await inp.get_attribute("type") or "text").lower()
                        if inp_type in {"hidden", "submit", "button", "image", "checkbox", "radio"}:
                            continue
                        inp_name = await inp.get_attribute("name") or ""
                        inp_id = await inp.get_attribute("id") or ""
                        inp_placeholder = await inp.get_attribute("placeholder") or ""
                        inp_class = await inp.get_attribute("class") or ""
                        inp_aria = await inp.get_attribute("aria-label") or ""
                        search_fields.append({
                            "type": inp_type,
                            "name": inp_name,
                            "id": inp_id,
                            "placeholder": inp_placeholder,
                            "class": inp_class,
                            "aria_label": inp_aria,
                        })
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "input field extraction", exc)
                        continue

                final_url = page.url
                page_title = await page.title()
                dom_content = await page.content()

                return {
                    "dom_content": dom_content,
                    "final_url": final_url,
                    "title": page_title,
                    "search_fields": search_fields,
                    "captured_requests": captured_requests,
                }

            except PlaywrightTimeoutError as exc:
                raise TimeoutError(
                    f"SPA navigation to '{safe_url}' timed out after {timeout_limit} ms: {exc}"
                ) from exc
            except PlaywrightError as exc:
                raise RuntimeError(
                    f"Playwright navigation or browser failure while visiting '{safe_url}': {exc}"
                ) from exc
            except Exception as exc:
                raise RuntimeError(
                    f"Unexpected error while inspecting SPA from '{safe_url}': {exc}"
                ) from exc

            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "context cleanup", exc)
                if browser is not None:
                    try:
                        await browser.close()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "browser cleanup", exc)

    def inspect_spa_sync(
        self,
        target_url: str,
        *,
        wait_timeout_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Synchronously execute render_and_inspect_spa safely across running or new event loops."""
        return _run_coroutine_sync(
            self.render_and_inspect_spa(target_url, wait_timeout_ms=wait_timeout_ms)
        )

    async def interact_and_capture(
        self,
        target_url: str,
        query_text: str,
        *,
        input_selectors: Sequence[str] = (
            "input[type='text']",
            "input:not([type])",
            "textarea",
            "input[type='search']",
            ".el-input__inner",
        ),
        button_selectors: Sequence[str] = (
            "button[type='submit']",
            "button.el-button--primary",
            "button:has-text('查询')",
            "button:has-text('Search')",
            "button:has-text('Track')",
            "button:has-text('Buscar')",
            "button",
            "input[type='submit']",
        ),
        result_selectors: Sequence[str] = (
            "[class*='result']",
            "[id*='result']",
            "[class*='detail']",
            "[class*='track']",
            "[class*='content']",
            ".el-table",
            "table",
        ),
        wait_timeout_ms: Optional[int] = None,
        max_response_bytes: int = 262144,
    ) -> Dict[str, Any]:
        """Navigate to a SPA, fill one input, trigger the search and capture the outcome.

        Uses the same URL validation (hash routes preserved), request filtering and
        guaranteed cleanup as the other session methods. Returns a dict with
        ``dom_content``, ``final_url``, ``result_text``, ``result_selector``,
        ``result_dom_subtree``, ``responses`` (bounded XHR/fetch bodies observed
        after submission), ``input_selector`` and ``button_selector`` used.

        Raises:
            ValueError / PermissionError: URL or domain rejected by policy.
            LookupError: no input selector became available (page structure changed).
            TimeoutError / RuntimeError: navigation or browser failures.
        """
        if not isinstance(query_text, str) or not query_text.strip():
            raise ValueError("query_text must be a non-empty string.")
        timeout_limit = wait_timeout_ms or self.timeout_ms
        safe_url: str = self.validator.validate_and_normalize(
            target_url, preserve_fragment=True, allow_http=self.allow_http
        )

        async with async_playwright() as playwright:
            browser: Optional[Browser] = None
            context: Optional[BrowserContext] = None
            try:
                browser = await playwright.chromium.launch(
                    headless=True, args=CHROMIUM_SECURITY_ARGS
                )
                context = await browser.new_context(
                    user_agent=self.user_agent, ignore_https_errors=False
                )
                page: Page = await context.new_page()

                async def route_handler(route: Route) -> None:
                    try:
                        req = route.request
                        if req.resource_type in {"image", "stylesheet", "font", "media"}:
                            await route.abort("blockedbyclient")
                            return
                        lowered = req.url.lower()
                        if not (lowered.startswith("https://") or lowered.startswith("http://")):
                            await route.abort("blockedbyclient")
                            return
                        await route.continue_()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "route filtering", exc)

                await page.route("**/*", route_handler)

                responses: List[Dict[str, Any]] = []
                pending: List[Any] = []
                capturing = {"enabled": False}

                async def record_response(response: Any) -> None:
                    try:
                        body = await response.text()
                        responses.append({
                            "url": response.url,
                            "status": response.status,
                            "method": response.request.method,
                            "body": body[:max_response_bytes],
                        })
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "response body capture", exc)

                def on_response(response: Any) -> None:
                    try:
                        if not capturing["enabled"]:
                            return
                        if response.request.resource_type not in {"xhr", "fetch"}:
                            return
                        pending.append(asyncio.ensure_future(record_response(response)))
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "response listener", exc)

                page.on("response", on_response)

                await page.goto(safe_url, timeout=timeout_limit, wait_until="domcontentloaded")
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(4000, timeout_limit))
                except Exception as exc:
                    logger.debug("Non-fatal error ignored (%s): %s", "networkidle wait", exc)

                chosen_input: Optional[str] = None
                chosen_handle = None
                combined = ", ".join(input_selectors)
                try:
                    await page.wait_for_selector(
                        combined, state="visible", timeout=min(10000, timeout_limit)
                    )
                except PlaywrightTimeoutError:
                    pass
                for selector in input_selectors:
                    handle = await page.query_selector(selector)
                    if handle is not None and await handle.is_visible():
                        chosen_input, chosen_handle = selector, handle
                        break
                if chosen_handle is None:
                    raise LookupError("No tracking input became available on the page.")

                await chosen_handle.fill(query_text.strip())
                capturing["enabled"] = True

                clicked = False
                chosen_button: Optional[str] = None
                for selector in button_selectors:
                    try:
                        button = await page.query_selector(selector)
                        if button is not None and await button.is_visible():
                            await button.click(timeout=min(3000, timeout_limit))
                            clicked = True
                            chosen_button = selector
                            break
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "button probing", exc)
                        continue
                if not clicked:
                    await chosen_handle.press("Enter")
                    chosen_button = "Enter"

                try:
                    await page.wait_for_load_state("networkidle", timeout=min(8000, timeout_limit))
                except Exception as exc:
                    logger.debug("Non-fatal error ignored (%s): %s", "post-submit networkidle wait", exc)
                result_text = ""
                chosen_result_selector: Optional[str] = None
                result_dom_subtree: str = ""
                if result_selectors:
                    try:
                        await page.wait_for_selector(
                            ", ".join(result_selectors),
                            state="visible",
                            timeout=min(8000, timeout_limit),
                        )
                    except PlaywrightTimeoutError:
                        pass
                    for selector in result_selectors:
                        try:
                            handle = await page.query_selector(selector)
                            if handle is not None:
                                text = (await handle.inner_text()).strip()
                                if text:
                                    result_text = text
                                    chosen_result_selector = selector
                                    try:
                                        result_dom_subtree = (await handle.inner_html())[:65536]
                                    except Exception as exc:
                                        logger.debug("Non-fatal error ignored (%s): %s", "result subtree capture", exc)
                                    break
                        except Exception as exc:
                            logger.debug("Non-fatal error ignored (%s): %s", "result selector probing", exc)
                            continue
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

                return {
                    "dom_content": await page.content(),
                    "final_url": page.url,
                    "result_text": result_text,
                    "result_selector": chosen_result_selector,
                    "result_dom_subtree": result_dom_subtree,
                    "responses": responses,
                    "input_selector": chosen_input,
                    "button_selector": chosen_button,
                }
            except LookupError:
                raise
            except PlaywrightTimeoutError as exc:
                raise TimeoutError(
                    f"Interactive navigation to '{safe_url}' timed out after {timeout_limit} ms: {exc}"
                ) from exc
            except PlaywrightError as exc:
                raise RuntimeError(
                    f"Playwright failure during interaction with '{safe_url}': {exc}"
                ) from exc
            except Exception as exc:
                raise RuntimeError(
                    f"Unexpected error during interaction with '{safe_url}': {exc}"
                ) from exc
            finally:
                if context is not None:
                    try:
                        await context.close()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "context cleanup", exc)
                if browser is not None:
                    try:
                        await browser.close()
                    except Exception as exc:
                        logger.debug("Non-fatal error ignored (%s): %s", "browser cleanup", exc)

    def interact_and_capture_sync(self, target_url: str, query_text: str, **kwargs: Any) -> Dict[str, Any]:
        """Synchronous bridge for interact_and_capture."""
        return _run_coroutine_sync(self.interact_and_capture(target_url, query_text, **kwargs))
