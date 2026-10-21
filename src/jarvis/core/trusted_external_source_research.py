"""Bounded, non-executing research through JARVIS's native HTTP tool."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Protocol
import json
from urllib.parse import urljoin, urlsplit

from jarvis.core.external_source_research import (
    ExternalEndpointObservation,
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
)
from jarvis.core.security.secure_browser import SecureWebSession
from jarvis.tools.web.http_tool import HTTPRequestTool, ResearchFetchResponse


MAX_TIMEOUT_SECONDS = 8.0
MAX_REDIRECTS = 3
MAX_DOCUMENT_BYTES = 512_000
MAX_TOTAL_BYTES = 2_000_000
MAX_JS_ASSETS = 5
MAX_OBSERVED_ENDPOINTS = 5
MAX_RESEARCH_SECONDS = 30.0
MAX_VISIBLE_TEXT_CHARS = 1_000


class ResearchHTTPTool(Protocol):
    def fetch_for_research(
        self,
        url: str,
        *,
        timeout_seconds: float,
        max_bytes: int,
        max_redirects: int,
    ) -> ResearchFetchResponse: ...


@dataclass
class _HTMLFacts(HTMLParser):
    title_parts: list[str] = field(default_factory=list)
    visible_parts: list[str] = field(default_factory=list)
    script_sources: list[str] = field(default_factory=list)
    forms: list[dict[str, object]] = field(default_factory=list)
    _inside_title: bool = False
    _inside_script: bool = False
    _inside_style: bool = False
    _current_form: dict[str, object] | None = None

    def __post_init__(self) -> None:
        HTMLParser.__init__(self, convert_charrefs=True)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value for name, value in attrs}
        if tag == "title":
            self._inside_title = True
        elif tag in {"script", "style"}:
            self._inside_script = tag == "script"
            self._inside_style = tag == "style"
            if tag == "script" and attributes.get("src"):
                self.script_sources.append(str(attributes["src"]))
        elif tag == "form":
            self._current_form = {
                "action": attributes.get("action"),
                "method": (attributes.get("method") or "get").upper(),
                "required_parameters": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = attributes.get("name")
            if name and "required" in attributes:
                required = self._current_form["required_parameters"]
                if isinstance(required, list):
                    required.append(str(name))
        elif tag == "button" and self._current_form is not None:
            self._current_form["has_submit_control"] = (
                (attributes.get("type") or "submit").lower() == "submit"
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._inside_title = False
        elif tag == "script":
            self._inside_script = False
        elif tag == "style":
            self._inside_style = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return
        if self._inside_title:
            self.title_parts.append(text)
        elif not self._inside_script and not self._inside_style:
            self.visible_parts.append(text)


_REQUEST_LITERAL = re.compile(
    r"""(?ix)
    (?P<call>
        \bfetch\s*\( |
        \bopen\s*\(\s*['"](?P<open_method>GET|POST|PUT|PATCH|DELETE|HEAD)['"]\s*,\s*|
        \b(?:axios|client|api)\s*\.\s*(?P<client_method>get|post|put|patch|delete|request)\s*\(
    )
    ['"](?P<url>https?://[^'"`]+|/(?!/)[^'"`]+)['"]
    """
)
_PLACEHOLDER_URL = re.compile(r"(?:\$\{|%s|\{\w+\}|\s*\+|\{\})")
_JS_PARAMETER = re.compile(r"""(?:^|[,{\s])([A-Za-z_$][\w$]*)\s*:""")
_AXIOS_BASE_URL = re.compile(
    r"""\baxios\s*\.\s*create\s*\(\s*\{[^}]{0,800}?\bbaseURL\s*:\s*(['"])(https?://[^'"]+|/(?!/)[^'"]*)\1""",
    re.IGNORECASE | re.DOTALL,
)


def _without_fragment(url: str) -> str:
    parsed = urlsplit(url)
    return parsed._replace(fragment="").geturl()


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def _asset_priority(source: str) -> int:
    name = urlsplit(source).path.rsplit("/", 1)[-1].casefold()
    if any(token in name for token in ("app", "main", "config", "runtime", "chunk")):
        return 0
    if "vendor" in name or any(token in name for token in ("jquery", "react", "vue")):
        return 2
    return 1


def _request_facts(
    js_text: str, base_url: str
) -> dict[str, tuple[str, tuple[str, ...], str, str, str]]:
    requests: dict[str, tuple[str, tuple[str, ...], str, str, str]] = {}
    base_origin = _origin(base_url)
    base_urls = _AXIOS_BASE_URL.findall(js_text)
    has_axios_base = len(base_urls) == 1
    axios_base = urljoin(base_url, base_urls[0][1]) if has_axios_base else base_url
    for match in _REQUEST_LITERAL.finditer(js_text):
        literal = match.group("url").strip()
        if _PLACEHOLDER_URL.search(literal):
            continue
        is_axios_call = bool(match.group("client_method"))
        resolution_base = axios_base if is_axios_call else base_url
        if is_axios_call and has_axios_base and not urlsplit(literal).scheme:
            resolved = resolution_base.rstrip("/") + "/" + literal.lstrip("/")
        else:
            resolved = urljoin(resolution_base, literal)
        if _origin(resolved) != base_origin:
            continue
        method = (
            match.group("open_method")
            or match.group("client_method")
            or "GET"
        ).upper()
        context = js_text[match.end():match.end() + 800]
        if method == "GET" and re.search(
            r"\bmethod\s*:\s*['\"](POST|PUT|PATCH|DELETE)['\"]",
            context,
            re.IGNORECASE,
        ):
            method_match = re.search(
                r"\bmethod\s*:\s*['\"](POST|PUT|PATCH|DELETE)['\"]",
                context,
                re.IGNORECASE,
            )
            if method_match is not None:
                method = method_match.group(1).upper()
        parameters = set()
        query = urlsplit(resolved).query
        parameters.update(
            part.split("=", 1)[0]
            for part in query.split("&")
            if part
        )
        body_match = re.search(
            r"(?:body|data)\s*:\s*(?:JSON\.stringify\s*\()?\s*\{([^}]*)\}",
            context,
            re.IGNORECASE,
        )
        if body_match is not None:
            parameters.update(_JS_PARAMETER.findall(body_match.group(1)))
        response_format = ""
        if re.search(r"\.json\s*\(", context, re.IGNORECASE):
            response_format = "JSON (response.json() observed in static JavaScript)"
        elif re.search(r"\.text\s*\(", context, re.IGNORECASE):
            response_format = "text (response.text() observed in static JavaScript)"
        context_start = max(0, match.start() - 120)
        context_end = min(len(js_text), match.end() + 320)
        requests[resolved] = (
            method,
            tuple(sorted(parameters)),
            response_format,
            js_text[context_start:context_end],
            "absolute" if urlsplit(literal).scheme else "relative",
        )
    return requests


def _confidence_from_observations(
    *,
    observed_assets: list[str],
    endpoint_count: int,
    response_format_observed: bool,
    access_method_observed: bool,
) -> float:
    score = 0.30
    if access_method_observed:
        score += 0.10
    if observed_assets:
        score += 0.10
    if endpoint_count:
        score += 0.15
    if response_format_observed:
        score += 0.15
    return min(score, 1.0)


def _extract_probe_parameter(user_request: str) -> str | None:
    """Extract a query, tracking number or search parameter from user request for dynamic probing."""
    if not user_request:
        return None
    labeled_match = re.search(
        r"(?:tracking|paquete|env[ií]o|c[oó]digo|gu[ií]a|pedido|order|query|b[uú]squeda|search|id|n[uú]mero|num)\s*(?:de|del|es|is|:|=|#)?\s*([A-Za-z0-9_-]{4,40})",
        user_request,
        re.IGNORECASE,
    )
    if labeled_match:
        val = labeled_match.group(1).strip()
        if val.lower() not in {"http", "https", "true", "false", "null", "none", "con", "para", "una", "del"}:
            return val
    quoted = re.search(r"['\"]([^'\"]{3,60})['\"]", user_request)
    if quoted:
        candidate = quoted.group(1).strip()
        if not candidate.lower().startswith(("http://", "https://")):
            return candidate
    tokens = re.findall(r"\b([A-Z0-9]{8,32})\b", user_request)
    for tok in tokens:
        if tok not in {"JAVASCRIPT", "PLAYWRIGHT", "REQUESTS", "TRACKING", "PROVISTO", "CONSULTA"}:
            return tok
    return None


def _extract_json_schema(val: Any, depth: int = 0) -> Any:
    """Extract a structural schema representation from a dynamic JSON payload."""
    if depth > 4:
        return "..."
    if isinstance(val, dict):
        return {str(k): _extract_json_schema(v, depth + 1) for k, v in list(val.items())[:20]}
    elif isinstance(val, list):
        if not val:
            return []
        return [_extract_json_schema(val[0], depth + 1)]
    elif isinstance(val, bool):
        return "boolean"
    elif isinstance(val, int):
        return "integer"
    elif isinstance(val, float):
        return "number"
    elif isinstance(val, str):
        return "string"
    elif val is None:
        return "null"
    return type(val).__name__


class TrustedWebExternalSourceResearchProvider:
    """Research source HTML, static first-party JavaScript, and dynamic SPAs via SecureWebSession."""

    def __init__(
        self,
        http_tool: ResearchHTTPTool | None = None,
        browser_session: SecureWebSession | None = None,
        *,
        clock=time.monotonic,
    ) -> None:
        self._http_tool = http_tool or HTTPRequestTool()
        self._browser_session = browser_session
        self._clock = clock

    def research(
        self, request: ExternalSourceResearchRequest
    ) -> ExternalSourceResearchResult:
        started = self._clock()
        requested_url = _without_fragment(request.source.strip())
        requested = urlsplit(requested_url)
        if requested.scheme.lower() not in {"http", "https"} or not requested.hostname:
            return self._insufficient(
                request.source,
                "Research requires an explicit HTTP(S) source URL.",
                page_kind="unsupported_source",
            )

        try:
            page = self._fetch(requested_url)
        except Exception as exc:
            return self._insufficient(
                request.source,
                f"Initial page fetch failed safely: {type(exc).__name__}: {exc}",
                page_kind="unavailable",
            )
        if _origin(page.final_url) != _origin(requested_url):
            return self._insufficient(
                request.source,
                "The page redirected to a different origin; source identity was not retained.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="redirected_external",
            )
        if page.truncated or len(page.body) > MAX_DOCUMENT_BYTES:
            return self._insufficient(
                request.source,
                "Initial HTML exceeded the per-document limit and was not parsed.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="analysis_limited",
                evidence=(
                    f"HTML Content-Length observed: {page.content_length}.",
                    "Truncated HTML is never used as complete structural evidence.",
                ),
            )
        if not 200 <= page.status_code < 300:
            return self._insufficient(
                request.source,
                f"Initial page returned unsuccessful HTTP status {page.status_code}.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="http_error",
            )

        content_type = page.content_type.lower()
        if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
            return self._insufficient(
                request.source,
                "The source response was not HTML; no document facts were extracted.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="non_html",
            )
        try:
            html_text = page.body.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return self._insufficient(
                request.source,
                "HTML response was not valid UTF-8; analysis stopped.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="ambiguous_html",
            )

        facts = _HTMLFacts()
        try:
            facts.feed(html_text)
            facts.close()
        except Exception as exc:
            return self._insufficient(
                request.source,
                f"HTML parsing failed: {type(exc).__name__}.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="ambiguous_html",
            )

        endpoints: set[str] = set()
        endpoint_access: dict[str, tuple[str, tuple[str, ...], str, str, str]] = {}
        endpoint_observations: list[ExternalEndpointObservation] = []
        required_parameters: set[str] = set()
        access_methods: list[str] = []
        evidence = [
            f"GET returned HTTP {page.status_code} from {page.final_url}.",
            f"Content-Type observed: {page.content_type}.",
            f"Received {len(page.body)} HTML bytes; JavaScript was not executed.",
        ]
        title = " ".join(facts.title_parts).strip()
        if title:
            evidence.append(f"Observed page title: {title[:200]}.")
        visible_text = " ".join(facts.visible_parts)
        if visible_text:
            evidence.append(
                "Visible HTML text excerpt: "
                + visible_text[:MAX_VISIBLE_TEXT_CHARS]
            )
        referenced_assets = tuple(
            urljoin(page.final_url, src)
            for src in dict.fromkeys(facts.script_sources)
        )
        if referenced_assets:
            evidence.append(
                f"HTML references {len(referenced_assets)} script asset(s): "
                + ", ".join(referenced_assets)
            )
        prioritized_assets = sorted(
            dict.fromkeys(facts.script_sources),
            key=lambda src: (_asset_priority(src), facts.script_sources.index(src)),
        )
        if len(prioritized_assets) > MAX_JS_ASSETS:
            evidence.append(
                f"Asset count limit {MAX_JS_ASSETS} reached; lower-priority assets "
                f"were omitted: {', '.join(urljoin(page.final_url, src) for src in prioritized_assets[MAX_JS_ASSETS:])}."
            )
            prioritized_assets = prioritized_assets[:MAX_JS_ASSETS]

        for form in facts.forms:
            action = form.get("action")
            method = form.get("method")
            if not isinstance(action, str) or not action.strip():
                continue
            resolved_action = urljoin(page.final_url, action.strip())
            if _origin(resolved_action) != _origin(page.final_url):
                continue
            endpoint = urlsplit(resolved_action)._replace(query="", fragment="").geturl()
            endpoints.add(endpoint)
            raw_parameters = form.get("required_parameters")
            form_parameters = (
                tuple(value for value in raw_parameters if isinstance(value, str))
                if isinstance(raw_parameters, list)
                else ()
            )
            endpoint_access[endpoint] = (
                str(method),
                (),
                "HTML form submission response (not fetched).",
                f"HTML form action={action!r} method={method!r}.",
                "absolute" if urlsplit(action.strip()).scheme else "relative",
            )
            endpoint_observations.append(
                ExternalEndpointObservation(
                    endpoint=endpoint,
                    source_asset=page.final_url,
                    context=f"HTML form action={action!r} method={method!r}.",
                    observation_type="html_form_action",
                    url_kind=(
                        "absolute"
                        if urlsplit(action.strip()).scheme
                        else "relative"
                    ),
                    http_method=str(method).upper(),
                    parameters=form_parameters,
                )
            )
            access_methods.append(f"Observed HTML form {method} {endpoint}.")
            required_parameters.update(form_parameters)

        observed_assets: list[str] = []
        total_bytes = len(page.body)
        endpoints_from_assets: dict[
            str, tuple[str, tuple[str, ...], str, str, str]
        ] = {}
        asset_problem: str | None = None
        for src in prioritized_assets:
            if self._clock() - started > MAX_RESEARCH_SECONDS:
                asset_problem = "Research exceeded its total time budget."
                break
            remaining_bytes = MAX_TOTAL_BYTES - total_bytes
            if remaining_bytes <= 0:
                asset_problem = f"Total research byte budget ({MAX_TOTAL_BYTES}) exhausted."
                break
            asset_url = urljoin(page.final_url, src)
            if _origin(asset_url) != _origin(page.final_url):
                evidence.append(f"Skipped cross-origin script asset: {asset_url}.")
                continue
            per_asset_limit = min(MAX_DOCUMENT_BYTES, remaining_bytes)
            remaining_seconds = MAX_RESEARCH_SECONDS - (self._clock() - started)
            if remaining_seconds <= 0:
                asset_problem = "Research exceeded its total time budget."
                break
            try:
                asset = self._fetch(
                    asset_url,
                    max_bytes=per_asset_limit,
                    timeout_seconds=min(MAX_TIMEOUT_SECONDS, remaining_seconds),
                )
            except Exception as exc:
                evidence.append(
                    f"Static JavaScript asset could not be fetched: "
                    f"{type(exc).__name__}."
                )
                continue
            if len(asset.body) > per_asset_limit:
                asset_problem = (
                    "HTTP research tool returned a body above the requested byte cap."
                )
                evidence.append(
                    f"Rejected oversized response body from {asset_url}; "
                    "contents were not inspected or logged."
                )
                break
            total_bytes += len(asset.body)
            if self._clock() - started > MAX_RESEARCH_SECONDS:
                asset_problem = "Research exceeded its total time budget."
                break
            if _origin(asset.final_url) != _origin(page.final_url):
                evidence.append("Skipped asset redirected to another origin.")
                continue
            if not (
                "javascript" in asset.content_type.lower()
                or urlsplit(asset.final_url).path.lower().endswith((".js", ".mjs"))
            ):
                evidence.append(f"Skipped non-JavaScript asset: {asset.final_url}.")
                continue
            if asset.truncated:
                length_fact = (
                    f" Content-Length was {asset.content_length} bytes."
                    if asset.content_length is not None
                    else ""
                )
                evidence.append(
                    f"Omitted/truncated oversized asset {asset.final_url}; "
                    f"at most {len(asset.body)} bytes were read.{length_fact} "
                    "Truncated content was not used as endpoint evidence."
                )
                if total_bytes >= MAX_TOTAL_BYTES:
                    asset_problem = (
                        f"Total research byte budget ({MAX_TOTAL_BYTES}) exhausted."
                    )
                    break
                continue
            try:
                js_text = asset.body.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                evidence.append("Skipped JavaScript asset with non-UTF-8 contents.")
                continue
            observed_assets.append(asset.final_url)
            evidence.append(
                f"Inspected static JavaScript asset {asset.final_url}: "
                f"{len(asset.body)} bytes; inspection order {len(observed_assets)}."
            )
            endpoint_facts = _request_facts(js_text, asset.final_url)
            endpoints_from_assets.update(endpoint_facts)
            for endpoint, request_facts in endpoint_facts.items():
                context = request_facts[3]
                url_kind = request_facts[4]
                endpoint_observations.append(
                    ExternalEndpointObservation(
                        endpoint=endpoint,
                        source_asset=asset.final_url,
                        context=context[:240],
                        observation_type="static_request_call",
                        url_kind=url_kind,
                        http_method=request_facts[0],
                        parameters=request_facts[1],
                    )
                )
                evidence.append(
                    f"Request candidate {endpoint} observed in {asset.final_url}; "
                    f"type=static_request_call; method={request_facts[0]}; "
                    f"parameters={request_facts[1]}; URL kind={url_kind}; consulted=false; "
                    f"static context: {context[:240]!r}."
                )

        evidence.append(
            f"Total response bytes read during research: {total_bytes} "
            f"({max(0, total_bytes - len(page.body))} JavaScript bytes)."
        )
        if asset_problem:
            is_spa = (
                "/#/" in request.source
                or "/#/" in page.final_url
                or bool(facts.script_sources)
            )
            is_timeout = "time budget" in asset_problem.lower()
            if is_spa and not is_timeout:
                dynamic_res = self._investigate_dynamic_spa(
                    request,
                    request.source,
                    evidence=list(evidence),
                    observed_assets=list(observed_assets),
                )
                if dynamic_res is not None and dynamic_res.sufficient:
                    return dynamic_res

            return self._insufficient(
                request.source,
                asset_problem,
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="analysis_limited",
                evidence=tuple(evidence),
                observed_assets=tuple(observed_assets),
                observed_endpoints=tuple(
                    urlsplit(endpoint)._replace(query="", fragment="").geturl()
                    for endpoint in endpoints_from_assets
                ),
                endpoint_observations=tuple(endpoint_observations),
            )

        if len(endpoints_from_assets) > 1:
            return self._insufficient(
                request.source,
                "Multiple distinct request URLs were observed in first-party JavaScript; "
                "their tracking role is ambiguous.",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind="ambiguous_spa",
                evidence=tuple(evidence),
                observed_assets=tuple(observed_assets),
                observed_endpoints=tuple(sorted(
                    urlsplit(endpoint)._replace(query="", fragment="").geturl()
                    for endpoint in endpoints_from_assets
                )),
                endpoint_observations=tuple(endpoint_observations),
            )
        for endpoint, facts_for_endpoint in endpoints_from_assets.items():
            safe_endpoint = urlsplit(endpoint)._replace(query="", fragment="").geturl()
            endpoints.add(safe_endpoint)
            endpoint_access[safe_endpoint] = facts_for_endpoint
        if endpoints_from_assets:
            endpoint = next(iter(endpoints_from_assets))
            method, parameters, _, _, _ = endpoints_from_assets[endpoint]
            required_parameters.update(parameters)
            access_methods.append(
                f"Static first-party JavaScript contains an observed {method} request "
                f"call to {urlsplit(endpoint)._replace(query='', fragment='').geturl()}; "
                "the script was inspected as text and not executed."
            )

        enough_request_facts = bool(endpoints) and all(
            bool(facts_for_endpoint[2])
            for facts_for_endpoint in endpoint_access.values()
        )
        if endpoints and access_methods and enough_request_facts:
            if len(endpoints) > MAX_OBSERVED_ENDPOINTS:
                return self._insufficient(
                    request.source,
                    "Observed endpoint count exceeded the configured limit.",
                    final_url=page.final_url,
                    http_status=page.status_code,
                    content_type=page.content_type,
                    page_kind="analysis_limited",
                    evidence=tuple(evidence),
                    observed_assets=tuple(observed_assets),
                    endpoint_observations=tuple(endpoint_observations),
                )
            page_kind = "spa_with_observed_endpoint" if facts.script_sources else "html_form"
            evidence.append(
                f"Observed {len(endpoints)} same-origin request endpoint(s) in HTML "
                "forms or request-call literals."
            )
            return ExternalSourceResearchResult(
                source=request.source,
                access_method=" ".join(access_methods),
                observed_endpoints=tuple(sorted(endpoints)),
                response_format="; ".join(sorted({
                    facts_for_endpoint[2]
                    for facts_for_endpoint in endpoint_access.values()
                })),
                required_parameters=tuple(sorted(required_parameters)),
                notes=("Only same-origin, literal request routes are recorded.",),
                confidence=_confidence_from_observations(
                    observed_assets=observed_assets,
                    endpoint_count=len(endpoints),
                    response_format_observed=all(
                        bool(facts_for_endpoint[2])
                        for facts_for_endpoint in endpoint_access.values()
                    ),
                    access_method_observed=bool(access_methods),
                ),
                research_status="sufficient",
                final_url=page.final_url,
                http_status=page.status_code,
                content_type=page.content_type,
                page_kind=page_kind,
                evidence=tuple(evidence),
                observed_assets=tuple(observed_assets),
                endpoint_observations=tuple(endpoint_observations),
            )

        spa_shell = bool(facts.script_sources) and (
            not visible_text or len(visible_text) < 160
        )
        is_spa_detected = (
            spa_shell
            or "/#/" in request.source
            or "/#/" in page.final_url
            or bool(facts.script_sources)
        )
        if is_spa_detected:
            dynamic_res = self._investigate_dynamic_spa(
                request,
                request.source,
                evidence=list(evidence),
                observed_assets=list(observed_assets),
            )
            if dynamic_res is not None and dynamic_res.sufficient:
                return dynamic_res

        page_kind = "spa_shell" if spa_shell else "html_without_query_path"
        evidence.append(
            "No executable query form or attributable request endpoint was observed."
        )
        return self._insufficient(
            request.source,
            "insufficient_research: page content does not establish a reliable "
            "programmatic query path.",
            final_url=page.final_url,
            http_status=page.status_code,
            content_type=page.content_type,
            page_kind=page_kind,
            evidence=tuple(evidence),
            observed_assets=tuple(observed_assets),
            observed_endpoints=tuple(sorted(endpoints)),
            endpoint_observations=tuple(endpoint_observations),
        )

    def _investigate_dynamic_spa(
        self,
        request: ExternalSourceResearchRequest,
        target_url: str,
        *,
        evidence: list[str],
        observed_assets: list[str],
    ) -> ExternalSourceResearchResult | None:
        """Render a SPA using SecureWebSession (Playwright), wait for DOM, probe interactively, and capture network/DOM."""
        session = self._browser_session
        if session is None:
            try:
                session = SecureWebSession(allow_http=True)
            except Exception as exc:
                evidence.append(f"Failed to initialize SecureWebSession: {type(exc).__name__}: {exc}")
                return None

        try:
            spa_data = session.inspect_spa_sync(target_url)
        except Exception as exc:
            evidence.append(
                f"Dynamic SPA inspection with SecureWebSession failed safely: {type(exc).__name__}: {exc}"
            )
            return None

        dom_content = spa_data.get("dom_content", "")
        final_url = spa_data.get("final_url", target_url)
        page_title = spa_data.get("title", "")
        search_fields = spa_data.get("search_fields", [])
        captured_requests = spa_data.get("captured_requests", [])

        rendered_facts = _HTMLFacts()
        try:
            rendered_facts.feed(dom_content)
            rendered_facts.close()
        except Exception:
            pass

        visible_rendered = " ".join(rendered_facts.visible_parts)
        evidence.append("Rendered dynamic SPA DOM with SecureWebSession (Playwright); DOM mounted.")
        if page_title:
            evidence.append(f"Rendered page title: {page_title[:200]}.")
        if visible_rendered:
            evidence.append(
                f"Mounted DOM visible text excerpt: {visible_rendered[:MAX_VISIBLE_TEXT_CHARS]}"
            )

        endpoints: set[str] = set()
        required_params: set[str] = set()
        access_methods: list[str] = []
        endpoint_observations: list[ExternalEndpointObservation] = []
        response_formats: set[str] = set()

        # 1. Capture dynamic network requests from initial load
        tracking_keywords = {"1688track", "track", "tracking", "order", "query", "search", "api"}
        for req in captured_requests:
            req_url = req.get("url", "")
            if not req_url:
                continue
            req_method = req.get("method", "GET").upper()
            url_lower = req_url.lower()

            is_tracking_api = any(kw in url_lower for kw in tracking_keywords) or (
                _origin(req_url) == _origin(final_url)
                and any(seg in url_lower for seg in ("/api/", "/v1/", "/v2/"))
            )
            if is_tracking_api:
                clean_endpoint = urlsplit(req_url)._replace(query="", fragment="").geturl()
                endpoints.add(clean_endpoint)
                q = urlsplit(req_url).query
                params = [p.split("=", 1)[0] for p in q.split("&") if p]
                post_data = req.get("post_data")
                if post_data and isinstance(post_data, str):
                    try:
                        parsed_body = json.loads(post_data)
                        if isinstance(parsed_body, dict):
                            params.extend(str(k) for k in parsed_body.keys())
                    except Exception:
                        pass
                for p in params:
                    required_params.add(p)

                fmt = "JSON (captured dynamic tracking API network request)"
                response_formats.add(fmt)
                access_methods.append(
                    f"Captured dynamic network request: {req_method} {clean_endpoint}."
                )
                endpoint_observations.append(
                    ExternalEndpointObservation(
                        endpoint=clean_endpoint,
                        source_asset=final_url,
                        context=f"SPA dynamic network request {req_method} {clean_endpoint}",
                        observation_type="dynamic_captured_request",
                        url_kind="absolute",
                        http_method=req_method,
                        parameters=tuple(sorted(params)),
                        consulted=True,
                    )
                )

        # 2. Extract search fields from mounted DOM
        for field in search_fields:
            param_name = field.get("name") or field.get("id") or ""
            placeholder = field.get("placeholder") or ""
            if not param_name and placeholder:
                param_name = re.sub(r"[^a-zA-Z0-9_]", "_", placeholder.lower()).strip("_")
            if not param_name:
                param_name = "tracking_number"
            required_params.add(param_name)
            evidence.append(
                f"Extracted search field from mounted DOM: name={field.get('name')!r}, "
                f"id={field.get('id')!r}, placeholder={placeholder!r}."
            )

        # 3. Check mounted forms in rendered DOM
        for form in rendered_facts.forms:
            action = form.get("action")
            method = form.get("method") or "POST"
            if isinstance(action, str) and action.strip():
                resolved = urljoin(final_url, action.strip())
                clean_ep = urlsplit(resolved)._replace(query="", fragment="").geturl()
                endpoints.add(clean_ep)
                access_methods.append(f"Rendered DOM form {method} {clean_ep}.")
                endpoint_observations.append(
                    ExternalEndpointObservation(
                        endpoint=clean_ep,
                        source_asset=final_url,
                        context=f"Mounted DOM form action={action!r} method={method!r}",
                        observation_type="dynamic_dom_form",
                        url_kind="absolute" if urlsplit(action.strip()).scheme else "relative",
                        http_method=str(method).upper(),
                        parameters=tuple(sorted(required_params)),
                    )
                )

        # 4. AUTONOMOUS DYNAMIC INTERACTION PROBE
        dynamic_interaction_evidence: dict[str, object] = {
            "interaction_performed": False,
        }
        captured_backend_api: dict[str, object] | None = None
        probe_value = _extract_probe_parameter(request.user_request)

        if hasattr(session, "interact_and_capture_sync") and (probe_value or search_fields):
            test_query = probe_value or "TEST_QUERY"
            candidate_inputs: list[str] = []
            for sf in search_fields:
                if sf.get("id"):
                    candidate_inputs.append(f"#{sf['id']}")
                if sf.get("name"):
                    candidate_inputs.append(f"input[name='{sf['name']}']")
                if sf.get("class"):
                    for c in sf["class"].split():
                        if c and not c.startswith("is-"):
                            candidate_inputs.append(f".{c}")
            for fallback in (
                "input[type='text']",
                "input:not([type])",
                "textarea",
                ".el-input__inner",
                "input[type='search']",
            ):
                if fallback not in candidate_inputs:
                    candidate_inputs.append(fallback)

            candidate_buttons = (
                "button[type='submit']",
                "button.el-button--primary",
                "[class*='submit']",
                "[class*='search']",
                "[class*='query']",
                "button:has-text('查询')",
                "button:has-text('Search')",
                "button:has-text('Track')",
                "button:has-text('Buscar')",
                "button",
                "input[type='submit']",
            )
            candidate_results = (
                "[class*='result']",
                "[id*='result']",
                "[class*='detail']",
                "[class*='track']",
                "[class*='content']",
                ".el-table",
                "table",
                ".track-list",
            )

            try:
                interact_result = session.interact_and_capture_sync(
                    target_url,
                    test_query,
                    input_selectors=tuple(candidate_inputs),
                    button_selectors=candidate_buttons,
                    result_selectors=candidate_results,
                )
            except Exception as exc:
                evidence.append(
                    f"Dynamic interaction probe with SecureWebSession completed safely: {type(exc).__name__}: {exc}"
                )
                interact_result = None

            if isinstance(interact_result, dict):
                chosen_input = interact_result.get("input_selector")
                chosen_button = interact_result.get("button_selector")
                result_text = interact_result.get("result_text", "")
                result_selector = interact_result.get("result_selector")
                result_dom_subtree = interact_result.get("result_dom_subtree", "")
                post_responses = interact_result.get("responses", [])

                dynamic_interaction_evidence["interaction_performed"] = True
                dynamic_interaction_evidence["probe_value"] = test_query
                dynamic_interaction_evidence["input_selector"] = chosen_input
                dynamic_interaction_evidence["button_selector"] = chosen_button
                dynamic_interaction_evidence["result_selector"] = result_selector
                dynamic_interaction_evidence["result_text_sample"] = result_text[:500] if result_text else ""
                dynamic_interaction_evidence["result_dom_subtree"] = result_dom_subtree[:2000] if result_dom_subtree else ""
                dynamic_interaction_evidence["responses_count"] = len(post_responses)

                evidence.append(
                    f"Dynamic interaction probe executed: input_selector={chosen_input!r}, "
                    f"button_selector={chosen_button!r}. Intercepted {len(post_responses)} response(s)."
                )

                for resp in post_responses:
                    resp_url = resp.get("url", "")
                    resp_method = resp.get("method", "GET").upper()
                    resp_status = resp.get("status", 200)
                    resp_body = resp.get("body", "")

                    if resp_body and (resp_body.strip().startswith("{") or resp_body.strip().startswith("[")):
                        try:
                            parsed_json = json.loads(resp_body)
                            schema = _extract_json_schema(parsed_json)
                            clean_endpoint = urlsplit(resp_url)._replace(query="", fragment="").geturl()
                            endpoints.add(clean_endpoint)
                            q = urlsplit(resp_url).query
                            params = [p.split("=", 1)[0] for p in q.split("&") if p]
                            if isinstance(parsed_json, dict):
                                keys = list(parsed_json.keys())
                            else:
                                keys = []

                            captured_backend_api = {
                                "endpoint": resp_url,
                                "clean_endpoint": clean_endpoint,
                                "http_method": resp_method,
                                "status": resp_status,
                                "json_schema": schema,
                                "sample_keys": keys[:20],
                            }
                            dynamic_interaction_evidence["captured_api"] = captured_backend_api

                            fmt = "JSON (captured dynamic backend API)"
                            response_formats.add(fmt)
                            access_methods.append(
                                f"Dynamic interaction intercepted backend API: {resp_method} {clean_endpoint}."
                            )
                            endpoint_observations.append(
                                ExternalEndpointObservation(
                                    endpoint=clean_endpoint,
                                    source_asset=final_url,
                                    context=f"Intercepted backend API response: {resp_method} {resp_url}",
                                    observation_type="dynamic_intercepted_api",
                                    url_kind="absolute",
                                    http_method=resp_method,
                                    parameters=tuple(sorted(params or ([probe_value] if probe_value else ["query"]))),
                                    consulted=True,
                                )
                            )
                            evidence.append(
                                f"Intercepted backend API response: {resp_method} {clean_endpoint} with JSON schema. "
                                f"Keys: {keys[:10]}."
                            )
                            break
                        except Exception:
                            pass

                if not captured_backend_api and (result_text or result_dom_subtree):
                    evidence.append(
                        f"Dynamic interaction DOM updated without visible network JSON. Captured result in selector {result_selector!r}: {result_text[:200]}."
                    )
                    response_formats.add("HTML (dynamic rendered DOM subtree)")
                    clean_page_endpoint = urlsplit(final_url)._replace(query="", fragment="").geturl()
                    endpoints.add(clean_page_endpoint)

        if not dynamic_interaction_evidence.get("interaction_performed"):
            dynamic_interaction_evidence["search_fields"] = search_fields
            dynamic_interaction_evidence["captured_requests"] = captured_requests

        # Fallback query endpoint if search field is found on SPA
        if not endpoints and search_fields:
            clean_page_endpoint = urlsplit(final_url)._replace(query="", fragment="").geturl()
            endpoints.add(clean_page_endpoint)
            access_methods.append(
                f"Rendered SPA DOM query interface with search field(s) on {final_url}."
            )
            response_formats.add("HTML (rendered DOM search interface)")

        if (endpoints or search_fields) and (required_params or probe_value or captured_backend_api):
            return ExternalSourceResearchResult(
                source=request.source,
                access_method=" ".join(access_methods) if access_methods else "Dynamic SPA search interface",
                observed_endpoints=tuple(sorted(endpoints)),
                response_format="; ".join(sorted(response_formats)) if response_formats else "JSON (dynamic API)",
                required_parameters=tuple(sorted(required_params or ([probe_value] if probe_value else ["query"]))),
                notes=("Dynamic facts extracted via SecureWebSession with mounted DOM and dynamic probing.",),
                confidence=0.85,
                research_status="sufficient",
                final_url=final_url,
                http_status=200,
                content_type="text/html",
                page_kind="rendered_spa",
                evidence=tuple(evidence),
                observed_assets=tuple(observed_assets),
                endpoint_observations=tuple(endpoint_observations),
                dynamic_interaction_evidence=dynamic_interaction_evidence,
            )

        return None

    def _fetch(
        self,
        url: str,
        *,
        max_bytes: int = MAX_DOCUMENT_BYTES,
        timeout_seconds: float = MAX_TIMEOUT_SECONDS,
    ) -> ResearchFetchResponse:
        return self._http_tool.fetch_for_research(
            url,
            timeout_seconds=timeout_seconds,
            max_bytes=max_bytes,
            max_redirects=MAX_REDIRECTS,
        )

    @staticmethod
    def _insufficient(
        source: str,
        message: str,
        *,
        final_url: str = "",
        http_status: int | None = None,
        content_type: str = "",
        page_kind: str = "unknown",
        evidence: tuple[str, ...] = (),
        observed_assets: tuple[str, ...] = (),
        observed_endpoints: tuple[str, ...] = (),
        endpoint_observations: tuple[ExternalEndpointObservation, ...] = (),
    ) -> ExternalSourceResearchResult:
        return ExternalSourceResearchResult(
            source=source,
            access_method="",
            observed_endpoints=observed_endpoints,
            response_format="",
            notes=(message,),
            confidence=0.0,
            research_status="insufficient_research",
            final_url=final_url,
            http_status=http_status,
            content_type=content_type,
            page_kind=page_kind,
            evidence=evidence,
            observed_assets=observed_assets,
            endpoint_observations=endpoint_observations,
        )


__all__ = ["TrustedWebExternalSourceResearchProvider"]
