from __future__ import annotations

import io
import json
import socket
import unittest
import urllib.request
from http.client import HTTPMessage
from unittest.mock import patch

from jarvis.core.external_source_research import (
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
)
from jarvis.core.safe_skill_authoring import (
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
)
from jarvis.core.trusted_external_source_research import (
    MAX_DOCUMENT_BYTES,
    MAX_JS_ASSETS,
    MAX_REDIRECTS,
    MAX_TOTAL_BYTES,
    MAX_TIMEOUT_SECONDS,
    TrustedWebExternalSourceResearchProvider,
)
from jarvis.tools.web.http_tool import (
    HTTPRequestTool,
    ResearchFetchResponse,
    _BoundedRedirectHandler,
    _validate_public_http_url,
)


PAGE_URL = "https://tracking.example.test/"


def html_response(
    body: str,
    *,
    url: str = PAGE_URL,
    content_type: str = "text/html; charset=utf-8",
    status: int = 200,
    content_length: int | None = None,
    truncated: bool = False,
) -> ResearchFetchResponse:
    return ResearchFetchResponse(
        requested_url=PAGE_URL,
        final_url=url,
        status_code=status,
        content_type=content_type,
        body=body.encode("utf-8"),
        content_length=content_length,
        truncated=truncated,
    )


class FakeHTTPTool:
    def __init__(self, responses: dict[str, ResearchFetchResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, object]]] = []

    def fetch_for_research(self, url: str, **limits) -> ResearchFetchResponse:
        self.calls.append((url, limits))
        if url not in self.responses:
            raise OSError(f"unexpected URL {url}")
        return self.responses[url]


class TrustedExternalSourceResearchTests(unittest.TestCase):
    def request(self, source: str = PAGE_URL) -> ExternalSourceResearchRequest:
        return ExternalSourceResearchRequest(
            user_request="Fetch current package tracking status.",
            source=source,
            capability="Read current tracking data.",
        )

    def test_simple_html_form_records_observed_route_and_required_parameter(self) -> None:
        tool = FakeHTTPTool({
            PAGE_URL: html_response(
                '<title>Tracking</title><form method="post" action="/lookup">'
                '<input name="tracking_number" required><button>Track</button></form>'
            )
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertTrue(result.sufficient)
        self.assertEqual(result.observed_endpoints, ("https://tracking.example.test/lookup",))
        self.assertEqual(result.required_parameters, ("tracking_number",))
        self.assertEqual(result.http_status, 200)
        self.assertTrue(any("HTML bytes" in item for item in result.evidence))

    def test_plain_html_without_query_path_is_insufficient(self) -> None:
        provider = TrustedWebExternalSourceResearchProvider(
            FakeHTTPTool({PAGE_URL: html_response("<title>Tracking</title><p>Welcome</p>")})
        )
        result = provider.research(self.request())
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertEqual(result.page_kind, "html_without_query_path")
        self.assertEqual(result.observed_endpoints, ())

    def test_spa_shell_without_query_data_is_insufficient(self) -> None:
        page = html_response(
            '<title>Track</title><div id="app"></div><script src="/assets/app.js"></script>'
        )
        js = html_response(
            "window.app={name:'tracking'};",
            url="https://tracking.example.test/assets/app.js",
            content_type="application/javascript",
        )
        tool = FakeHTTPTool({
            PAGE_URL: page,
            "https://tracking.example.test/assets/app.js": js,
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertEqual(result.page_kind, "spa_shell")
        self.assertEqual(result.observed_endpoints, ())
        self.assertEqual(result.observed_assets, ("https://tracking.example.test/assets/app.js",))

    def test_static_js_literal_request_endpoint_is_observed_without_execution(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        js = html_response(
            "fetch('/track/query').then(response => response.json());",
            url="https://tracking.example.test/app.js",
            content_type="application/javascript",
        )
        tool = FakeHTTPTool({PAGE_URL: page, "https://tracking.example.test/app.js": js})
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertTrue(result.sufficient)
        self.assertEqual(result.observed_endpoints, ("https://tracking.example.test/track/query",))
        self.assertIn("not executed", result.access_method)
        observation = result.endpoint_observations[0]
        self.assertEqual(observation.source_asset, "https://tracking.example.test/app.js")
        self.assertEqual(observation.observation_type, "static_request_call")
        self.assertEqual(observation.url_kind, "relative")
        self.assertFalse(observation.consulted)
        self.assertLessEqual(len(observation.context), 240)

    def test_large_vendor_is_skipped_and_small_app_asset_is_still_researched(self) -> None:
        page = html_response(
            '<script src="/vendor.js"></script><script src="/app.js"></script>'
        )
        vendor_url = "https://tracking.example.test/vendor.js"
        app_url = "https://tracking.example.test/app.js"
        tool = FakeHTTPTool({
            PAGE_URL: page,
            vendor_url: html_response(
                "", url=vendor_url, content_type="application/javascript",
                content_length=MAX_DOCUMENT_BYTES + 1, truncated=True,
            ),
            app_url: html_response(
                "fetch('/track/query').then(r => r.json());",
                url=app_url,
                content_type="application/javascript",
            ),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual([call[0] for call in tool.calls[1:]], [app_url, vendor_url])
        self.assertEqual(result.observed_endpoints, ("https://tracking.example.test/track/query",))
        self.assertTrue(result.sufficient)
        self.assertTrue(any("Omitted/truncated oversized asset" in item for item in result.evidence))

    def test_asset_prioritization_is_deterministic(self) -> None:
        page = html_response(
            '<script src="/vendor.js"></script><script src="/runtime.js"></script>'
            '<script src="/config.js"></script><script src="/app.js"></script>'
        )
        responses = {PAGE_URL: page}
        for name in ("vendor", "runtime", "config", "app"):
            url = f"https://tracking.example.test/{name}.js"
            responses[url] = html_response(
                "const loaded=true;",
                url=url,
                content_type="application/javascript",
            )
        tool = FakeHTTPTool(responses)
        TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(
            [call[0] for call in tool.calls[1:]],
            [
                "https://tracking.example.test/runtime.js",
                "https://tracking.example.test/config.js",
                "https://tracking.example.test/app.js",
                "https://tracking.example.test/vendor.js",
            ],
        )

    def test_script_count_limit_omits_low_priority_assets_and_continues(self) -> None:
        names = ["vendor.js", "misc.js", "chunk.js", "runtime.js", "main.js", "app.js"]
        page = html_response("".join(f'<script src="/{name}"></script>' for name in names))
        responses = {PAGE_URL: page}
        for name in names:
            url = f"https://tracking.example.test/{name}"
            responses[url] = html_response(
                "const loaded=true;",
                url=url,
                content_type="application/javascript",
            )
        tool = FakeHTTPTool(responses)
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(len(tool.calls), MAX_JS_ASSETS + 1)
        self.assertEqual(len(result.observed_assets), MAX_JS_ASSETS)
        self.assertTrue(any("lower-priority assets were omitted" in item for item in result.evidence))

    def test_truncated_chunk_is_not_used_as_complete_endpoint_evidence(self) -> None:
        page = html_response('<script src="/chunk.js"></script><script src="/app.js"></script>')
        chunk_url = "https://tracking.example.test/chunk.js"
        app_url = "https://tracking.example.test/app.js"
        tool = FakeHTTPTool({
            PAGE_URL: page,
            chunk_url: html_response(
                "fetch('/partial').then(r => r.json());",
                url=chunk_url,
                content_type="application/javascript",
                content_length=MAX_DOCUMENT_BYTES + 100,
                truncated=True,
            ),
            app_url: html_response("const app=true;", url=app_url, content_type="application/javascript"),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.observed_endpoints, ())
        self.assertFalse(any(item.source_asset == chunk_url for item in result.endpoint_observations))
        self.assertIn(app_url, result.observed_assets)

    def test_endpoint_candidates_keep_short_source_context_without_bundle_dump(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        app_url = "https://tracking.example.test/app.js"
        source = "x" * 5000 + ";fetch('/track/query').then(r => r.json());" + "y" * 5000
        tool = FakeHTTPTool({
            PAGE_URL: page,
            app_url: html_response(source, url=app_url, content_type="application/javascript"),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertLessEqual(len(result.endpoint_observations[0].context), 240)
        self.assertTrue(all(len(item) < 2_000 for item in result.evidence))
        self.assertTrue(any("Total response bytes read" in item for item in result.evidence))

    def test_axios_observed_base_url_and_relative_route_are_resolved(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        app_url = "https://tracking.example.test/app.js"
        js = (
            "const client=axios.create({baseURL:'https://tracking.example.test/api'});"
            "client.get('/lookup').then(r=>r.json());"
        )
        tool = FakeHTTPTool({
            PAGE_URL: page,
            app_url: html_response(js, url=app_url, content_type="application/javascript"),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(
            result.observed_endpoints,
            ("https://tracking.example.test/api/lookup",),
        )
        self.assertTrue(result.endpoint_observations)

    def test_unresolved_dynamic_endpoint_composition_is_not_invented(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        app_url = "https://tracking.example.test/app.js"
        js = "const base=getBase(); fetch(base + '/track').then(r=>r.json());"
        tool = FakeHTTPTool({
            PAGE_URL: page,
            app_url: html_response(js, url=app_url, content_type="application/javascript"),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.observed_endpoints, ())
        self.assertEqual(result.research_status, "insufficient_research")

    def test_absolute_private_endpoint_is_not_accepted_as_same_origin_evidence(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        app_url = "https://tracking.example.test/app.js"
        js = "fetch('http://127.0.0.1/api/x').then(r=>r.json());"
        tool = FakeHTTPTool({
            PAGE_URL: page,
            app_url: html_response(js, url=app_url, content_type="application/javascript"),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.observed_endpoints, ())
        self.assertEqual(result.research_status, "insufficient_research")

    def test_observed_endpoints_include_http_method_and_body_parameters(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        app_url = "https://tracking.example.test/app.js"
        js = (
            "fetch('/lookup',{method:'POST',body:JSON.stringify({tracking_number:code})})"
            ".then(r=>r.json());"
        )
        tool = FakeHTTPTool({
            PAGE_URL: page,
            app_url: html_response(js, url=app_url, content_type="application/javascript"),
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertTrue(result.sufficient)
        self.assertIn("tracking_number", result.required_parameters)
        self.assertTrue(any("POST request" in item for item in result.access_method.split(";")))

    def test_multiple_request_urls_in_js_are_ambiguous_and_not_verified(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        js = html_response(
            "fetch('/track/query'); axios.post('/events');",
            url="https://tracking.example.test/app.js",
            content_type="application/javascript",
        )
        tool = FakeHTTPTool({PAGE_URL: page, "https://tracking.example.test/app.js": js})
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertIn("ambiguous", result.notes[0])
        self.assertEqual(
            result.observed_endpoints,
            (
                "https://tracking.example.test/events",
                "https://tracking.example.test/track/query",
            ),
        )

    def test_third_party_script_is_not_used_as_endpoint_evidence(self) -> None:
        page = html_response('<script src="https://cdn.other.test/app.js"></script>')
        tool = FakeHTTPTool({PAGE_URL: page})
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertEqual(result.observed_endpoints, ())
        self.assertFalse(any("other.test" in asset for asset in result.observed_assets))

    def test_endpoint_literals_without_request_call_are_not_endpoints(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        js = html_response(
            "const documentation='/api/track';",
            url="https://tracking.example.test/app.js",
            content_type="application/javascript",
        )
        tool = FakeHTTPTool({PAGE_URL: page, "https://tracking.example.test/app.js": js})
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.observed_endpoints, ())
        self.assertEqual(result.research_status, "insufficient_research")

    def test_documented_official_endpoint_literal_in_request_call_is_observed(self) -> None:
        page = html_response('<title>Official API docs</title><script src="/docs.js"></script>')
        js = html_response(
            "axios.get('https://tracking.example.test/v2/lookup')"
            ".then(response => response.json());",
            url="https://tracking.example.test/docs.js",
            content_type="application/javascript",
        )
        tool = FakeHTTPTool({PAGE_URL: page, "https://tracking.example.test/docs.js": js})
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.observed_endpoints, ("https://tracking.example.test/v2/lookup",))
        self.assertEqual(result.confidence, 0.8)

    def test_request_url_without_trustworthy_source_is_rejected(self) -> None:
        result = TrustedWebExternalSourceResearchProvider(FakeHTTPTool({})).research(
            self.request("file:///etc/passwd")
        )
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertEqual(result.page_kind, "unsupported_source")

    def test_valid_same_origin_redirect_is_recorded_as_final_url(self) -> None:
        final_url = "https://tracking.example.test/home"
        tool = FakeHTTPTool({
            PAGE_URL: html_response(
                '<form action="/lookup"><input name="code" required></form>',
                url=final_url,
            )
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.final_url, final_url)
        self.assertTrue(result.sufficient)

    def test_redirect_to_other_public_origin_fails_closed(self) -> None:
        tool = FakeHTTPTool({
            PAGE_URL: html_response("<title>redirect</title>", url="https://other.example.test/")
        })
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.page_kind, "redirected_external")
        self.assertFalse(result.sufficient)

    def test_http_fetch_uses_bounded_timeout_bytes_and_redirects(self) -> None:
        tool = FakeHTTPTool({PAGE_URL: html_response("<p>static</p>")})
        TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        _url, limits = tool.calls[0]
        self.assertEqual(limits["timeout_seconds"], MAX_TIMEOUT_SECONDS)
        self.assertEqual(limits["max_bytes"], MAX_DOCUMENT_BYTES)
        self.assertEqual(limits["max_redirects"], MAX_REDIRECTS)

    def test_ssrf_blocks_private_loopback_link_local_and_metadata_hosts(self) -> None:
        private_addresses = [
            ("10.0.0.1", 0),
            ("127.0.0.1", 0),
            ("169.254.169.254", 0),
            ("192.168.1.1", 0),
        ]
        for address, _ in private_addresses:
            with self.subTest(address=address), patch(
                "jarvis.tools.web.http_tool.socket.getaddrinfo",
                return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))],
            ):
                with self.assertRaises(ValueError):
                    _validate_public_http_url("https://public.example.test/")
        for url in (
            "http://localhost/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
            "ftp://example.test/file",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    _validate_public_http_url(url)

    def test_redirect_handler_rejects_private_redirect(self) -> None:
        handler = _BoundedRedirectHandler(MAX_REDIRECTS, {})
        with patch(
            "jarvis.tools.web.http_tool.socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))],
        ):
            with self.assertRaises(ValueError):
                handler.redirect_request(
                    urllib.request.Request(PAGE_URL),
                    io.BytesIO(),
                    302,
                    "Found",
                    HTTPMessage(),
                    "http://private.example.test/",
                )

    def test_http_fetch_rejects_body_limit_before_returning_content(self) -> None:
        with patch("jarvis.tools.web.http_tool.socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]), patch("jarvis.tools.web.http_tool.urllib.request.build_opener") as opener:
            context = opener.return_value.open.return_value.__enter__.return_value
            context.read.return_value = b""
            context.status = 200
            context.geturl.return_value = PAGE_URL
            context.headers = {"Content-Type": "text/html", "Content-Length": "21"}
            result = HTTPRequestTool().fetch_for_research(
                PAGE_URL, max_bytes=20, timeout_seconds=1
            )
            context.read.assert_not_called()
            self.assertEqual(result.body, b"")
            self.assertTrue(result.truncated)
            self.assertEqual(result.content_length, 21)

    def test_too_many_assets_uses_priority_and_skips_only_assets_over_limit(self) -> None:
        sources = "".join(f'<script src="/{index}.js"></script>' for index in range(MAX_JS_ASSETS + 1))
        page = html_response(sources)
        responses = {PAGE_URL: page}
        for index in range(MAX_JS_ASSETS + 1):
            url = f"https://tracking.example.test/{index}.js"
            responses[url] = html_response(
                "const x=1;", url=url, content_type="application/javascript"
            )
        tool = FakeHTTPTool(responses)
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(len(tool.calls), MAX_JS_ASSETS + 1)
        self.assertEqual(len(result.observed_assets), MAX_JS_ASSETS)
        self.assertTrue(any("lower-priority assets were omitted" in item for item in result.evidence))

    def test_too_many_observed_routes_fail_closed(self) -> None:
        forms = "".join(
            f'<form action="/lookup/{index}"><input name="code" required></form>'
            for index in range(6)
        )
        tool = FakeHTTPTool({PAGE_URL: html_response(forms)})
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertEqual(result.page_kind, "analysis_limited")

    def test_global_byte_budget_stops_after_budget_is_exhausted(self) -> None:
        names = [f"/{index}.js" for index in range(MAX_JS_ASSETS)]
        page = html_response("".join(f'<script src="{name}"></script>' for name in names))
        page_bytes = len(page.body)
        asset_bytes = 400_000
        responses = {PAGE_URL: page}
        for index, name in enumerate(names):
            url = f"https://tracking.example.test{name}"
            available = MAX_TOTAL_BYTES - page_bytes - index * asset_bytes
            size = min(asset_bytes, available)
            truncated = index == len(names) - 1
            responses[url] = ResearchFetchResponse(
                PAGE_URL,
                url,
                200,
                "application/javascript",
                b"x" * size,
                content_length=asset_bytes if truncated else size,
                truncated=truncated,
            )
        tool = FakeHTTPTool(responses)
        result = TrustedWebExternalSourceResearchProvider(tool).research(self.request())
        self.assertEqual(result.page_kind, "analysis_limited")
        self.assertEqual(len(tool.calls), MAX_JS_ASSETS + 1)

    def test_timeout_is_reported_as_insufficient_research(self) -> None:
        class TimeoutTool:
            def fetch_for_research(self, url: str, **limits) -> ResearchFetchResponse:
                raise TimeoutError("bounded timeout")

        result = TrustedWebExternalSourceResearchProvider(TimeoutTool()).research(
            self.request()
        )
        self.assertEqual(result.research_status, "insufficient_research")
        self.assertEqual(result.page_kind, "unavailable")

    def test_total_timeout_stops_before_the_next_asset_fetch(self) -> None:
        page = html_response('<script src="/app.js"></script>')
        class TickClock:
            values = iter((0.0, 0.0, MAX_TIMEOUT_SECONDS + 30.0))

            def __call__(self) -> float:
                return next(self.values)

        tool = FakeHTTPTool({PAGE_URL: page})
        result = TrustedWebExternalSourceResearchProvider(
            tool, clock=TickClock()
        ).research(self.request())
        self.assertEqual(result.page_kind, "analysis_limited")
        self.assertEqual(len(tool.calls), 1)
        self.assertIn("time budget", result.notes[0])

    def test_missing_content_length_stream_is_capped_and_marked_truncated(self) -> None:
        with patch(
            "jarvis.tools.web.http_tool.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
            ],
        ), patch("jarvis.tools.web.http_tool.urllib.request.build_opener") as opener:
            context = opener.return_value.open.return_value.__enter__.return_value
            context.read.return_value = b"x" * 20
            context.status = 200
            context.geturl.return_value = PAGE_URL
            context.headers = {"Content-Type": "application/javascript"}
            response = HTTPRequestTool().fetch_for_research(
                PAGE_URL, max_bytes=20, timeout_seconds=1
            )
            context.read.assert_called_once_with(20)
            self.assertTrue(response.truncated)
            self.assertIsNone(response.content_length)
            self.assertEqual(len(response.body), 20)

    def test_authoring_aborts_on_insufficient_live_research_without_coder_or_reviewer(self) -> None:
        class Coder:
            def run_local_coding(self, prompt: str) -> str:
                raise AssertionError("coder must not run")

        class Researcher:
            def research(self, request: ExternalSourceResearchRequest):
                return ExternalSourceResearchResult(
                    source=PAGE_URL,
                    access_method="",
                    research_status="insufficient_research",
                    notes=("insufficient_research: SPA shell has no query path.",),
                )

        service = SafeSkillAuthoringService(
            Coder(), external_source_research=Researcher()
        )
        result = service.author(
            SkillAuthoringRequest("Check current tracking at https://tracking.example.test/")
        )
        self.assertFalse(result.success)
        self.assertIn("insufficient_research", result.failure_reason or "")

    def test_sufficient_research_facts_arrive_exactly_in_coder_prompt(self) -> None:
        form_html = (
            '<title>Tracking</title><form method="get" action="/lookup">'
            '<input name="tracking_code" required></form>'
        )
        facts = TrustedWebExternalSourceResearchProvider(
            FakeHTTPTool({PAGE_URL: html_response(form_html)})
        ).research(self.request())
        self.assertTrue(facts.sufficient)
        encoded = json.loads(facts.to_prompt_context())
        self.assertEqual(encoded["required_parameters"], ["tracking_code"])
        self.assertEqual(encoded["observed_endpoints"], ["https://tracking.example.test/lookup"])

    def test_fake_data_gate_remains_active_with_observed_endpoint(self) -> None:
        from jarvis.core.code_validation import LocalCodeValidator

        source = (
            "import requests\n"
            "def ejecutar_skill():\n"
            "    response = requests.get('https://tracking.example.test/lookup')\n"
            "    location = 'Shanghai'\n"
            "    # simulated result\n"
            "    return {'location': location}\n"
        )
        report = LocalCodeValidator().validate_dynamic_skill_source(
            source,
            user_request="Check current tracking status.",
        )
        self.assertFalse(report.success)
        self.assertTrue(any(
            not check.success and check.name == "dynamic_external_data"
            for check in report.checks
        ))

    def test_dynamic_spa_autonomous_probe_with_intercepted_json_api(self) -> None:
        from unittest.mock import MagicMock

        mock_http_tool = FakeHTTPTool({
            PAGE_URL: html_response(
                "<html><head><script src='/app.js'></script></head><body><div id='app'></div></body></html>"
            )
        })
        mock_browser = MagicMock()
        mock_browser.inspect_spa_sync.return_value = {
            "dom_content": (
                "<html><body><div id='app'>"
                "<input id='query_in' name='track_code' placeholder='Enter code'>"
                "<button class='btn-search'>Buscar</button>"
                "</div></body></html>"
            ),
            "final_url": "https://tracking.example.test/#/home",
            "title": "Interactive Logistics Portal",
            "search_fields": [
                {
                    "type": "text",
                    "name": "track_code",
                    "id": "query_in",
                    "placeholder": "Enter code",
                    "class": "query-input",
                }
            ],
            "captured_requests": [],
        }
        mock_browser.interact_and_capture_sync.return_value = {
            "dom_content": "<html><body><div class='result'>Shipment In Transit</div></body></html>",
            "final_url": "https://tracking.example.test/#/result",
            "result_text": "Shipment In Transit",
            "result_selector": ".result",
            "result_dom_subtree": "<div class='result'>Shipment In Transit</div>",
            "input_selector": "#query_in",
            "button_selector": ".btn-search",
            "responses": [
                {
                    "url": "https://tracking.example.test/api/v1/shipment/status?id=OXCGH6082081H",
                    "method": "POST",
                    "status": 200,
                    "body": json.dumps({
                        "code": 200,
                        "data": {
                            "status": "in_transit",
                            "location": "Valencia Hub",
                            "checkpoints": [{"date": "2026-10-19", "desc": "Arrived at destination hub"}],
                        },
                    }),
                }
            ],
        }

        provider = TrustedWebExternalSourceResearchProvider(
            http_tool=mock_http_tool,
            browser_session=mock_browser,
        )
        request = ExternalSourceResearchRequest(
            user_request="Consulta el estado del tracking: OXCGH6082081H en https://tracking.example.test/#/",
            source="https://tracking.example.test/#/",
            capability="Consultar tracking de paquete",
        )
        result = provider.research(request)

        self.assertTrue(result.sufficient)
        self.assertEqual(result.research_status, "sufficient")
        self.assertIn("https://tracking.example.test/api/v1/shipment/status", result.observed_endpoints)
        self.assertIsNotNone(result.dynamic_interaction_evidence)
        ev = result.dynamic_interaction_evidence
        self.assertTrue(ev["interaction_performed"])
        self.assertEqual(ev["probe_value"], "OXCGH6082081H")
        self.assertEqual(ev["input_selector"], "#query_in")
        self.assertEqual(ev["button_selector"], ".btn-search")
        self.assertIsNotNone(ev["captured_api"])
        api = ev["captured_api"]
        self.assertEqual(api["clean_endpoint"], "https://tracking.example.test/api/v1/shipment/status")
        self.assertEqual(api["http_method"], "POST")
        self.assertIn("data", api["sample_keys"])
        self.assertIn("code", api["sample_keys"])

        # Verify interact_and_capture_sync was called with candidate selectors and probe value
        mock_browser.interact_and_capture_sync.assert_called_once()
        call_args = mock_browser.interact_and_capture_sync.call_args
        self.assertEqual(call_args[0][0], "https://tracking.example.test/#/")
        self.assertEqual(call_args[0][1], "OXCGH6082081H")

    def test_dynamic_spa_autonomous_probe_dom_subtree_fallback(self) -> None:
        from unittest.mock import MagicMock

        mock_http_tool = FakeHTTPTool({
            PAGE_URL: html_response(
                "<html><head><script src='/app.js'></script></head><body><div id='root'></div></body></html>"
            )
        })
        mock_browser = MagicMock()
        mock_browser.inspect_spa_sync.return_value = {
            "dom_content": (
                "<html><body><div id='root'>"
                "<input type='text' name='search_term' placeholder='Search item'>"
                "</div></body></html>"
            ),
            "final_url": "https://tracking.example.test/#/",
            "title": "Client-rendered Catalog",
            "search_fields": [{"type": "text", "name": "search_term", "placeholder": "Search item"}],
            "captured_requests": [],
        }
        mock_browser.interact_and_capture_sync.return_value = {
            "dom_content": "<html><body><div class='items'><span>Found: Item #99</span></div></body></html>",
            "final_url": "https://tracking.example.test/#/catalog",
            "result_text": "Found: Item #99",
            "result_selector": ".items",
            "result_dom_subtree": "<div class='items'><span>Found: Item #99</span></div>",
            "input_selector": "input[name='search_term']",
            "button_selector": "Enter",
            "responses": [],  # Pure client-side filtering / no XHR
        }

        provider = TrustedWebExternalSourceResearchProvider(
            http_tool=mock_http_tool,
            browser_session=mock_browser,
        )
        request = ExternalSourceResearchRequest(
            user_request="Busca el item 'item-99' en https://tracking.example.test/#/",
            source="https://tracking.example.test/#/",
            capability="Buscar item en catalogo SPA",
        )
        result = provider.research(request)

        self.assertTrue(result.sufficient)
        self.assertEqual(result.research_status, "sufficient")
        self.assertIsNotNone(result.dynamic_interaction_evidence)
        ev = result.dynamic_interaction_evidence
        self.assertTrue(ev["interaction_performed"])
        self.assertEqual(ev["probe_value"], "item-99")
        self.assertEqual(ev["input_selector"], "input[name='search_term']")
        self.assertEqual(ev["button_selector"], "Enter")
        self.assertEqual(ev["result_selector"], ".items")
        self.assertEqual(ev["result_text_sample"], "Found: Item #99")
        self.assertIn("Found: Item #99", ev["result_dom_subtree"])


if __name__ == "__main__":
    unittest.main()
