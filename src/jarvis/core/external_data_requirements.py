"""Deterministic live external-data intent and source inspection."""

from __future__ import annotations

import ast
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


_STATIC_KNOWLEDGE = re.compile(
    r"^\s*(?:que es|quien fue|define|explica(?:me)?|what is|who was|define|explain)\b"
)
_LIVE_ACTION = re.compile(
    r"\b(?:consult(?:a|as|an|ar|e|es|en)?|check|comprueba|verifica|mira|"
    r"busc(?:a|as|an|ar|e|es|en)?|look up|fetch|obten(?:go|ga|gan|er)?|"
    r"retrieve|track|rastrea(?:r)?|scrape|visit(?:a|as|an|ar|e|es|en)?)\b"
)
_EXTERNAL_SOURCE = re.compile(
    r"\b(?:web|sitio|pagina|internet|url|api|endpoint|fuente|website|site|"
    r"service|servicio|track(?:ing)?|seguimiento|envio|paquete)\b|"
    r"\b[a-z0-9.-]*(?:track|ollama|coinbase|binance|github|weather|openweather)"
    r"[a-z0-9.-]*\b",
    re.IGNORECASE,
)
_LIVE_TIME = re.compile(
    r"\b(?:actual(?:es)?|actualmente|ahora|hoy|ultima|ultimo|ultimas|ultimos|"
    r"reciente|recientes|tiempo real|en vivo|current|currently|latest|newest|"
    r"recent|today|now|real time|live|published)\b"
)
_DYNAMIC_DATA = re.compile(
    r"\b(?:precio|precios|price|prices|btc|bitcoin|eth|crypto|criptomoneda|"
    r"version|release|clima|weather|temperatura|temperature|pronostico|forecast|"
    r"tracking|seguimiento|paquete|envio|estado|status|noticias|news|"
    r"tipo de cambio|exchange rate|acciones|stock|cotizacion|quote)\b"
)
_PRICE_DATA = re.compile(r"\b(?:precio|price|btc|bitcoin|eth|crypto|criptomoneda)\b")

_NETWORK_MODULES = frozenset({"requests", "httpx", "urllib", "urllib.request", "urllib3", "aiohttp"})
_NETWORK_FUNCTIONS = frozenset({"urlopen", "urlretrieve"})
_NETWORK_METHODS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "request", "urlopen",
    "interact_and_capture", "interact_and_capture_sync",
    "fetch_dom", "fetch_dom_sync", "inspect_spa_sync", "render_and_inspect_spa",
})
_NATIVE_WEB_MODULES = frozenset({
    "jarvis.tools.web.web_search",
    "jarvis.tools.web.http_tool",
    "jarvis.core.security.secure_browser",
    "jarvis.core.security",
})
_SIMULATION_MARKERS = re.compile(
    r"\b(?:simulat(?:ed|ion|ing)?|mock(?:ed|ing)?|demo(?:nstration)?|"
    r"placeholder|fake|dummy|hardcoded|datos?\s+simulados?|valores?\s+ficticios?|"
    r"datos?\s+de\s+ejemplo|valores?\s+inventados?)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ExternalDataCheck:
    requires_live_data: bool
    has_acquisition: bool
    acquisition_reaches_result: bool
    simulation_marker: str | None = None
    unverified_endpoint: str | None = None

    @property
    def valid(self) -> bool:
        return not self.requires_live_data or (
            self.has_acquisition
            and self.acquisition_reaches_result
            and self.simulation_marker is None
            and self.unverified_endpoint is None
        )

    @property
    def details(self) -> str:
        if not self.requires_live_data:
            return "The request does not require changing external data."
        if self.simulation_marker is not None:
            return "dynamic_external_data: simulated/mock data cannot satisfy a live-data requirement"
        if not self.has_acquisition:
            return (
                "dynamic_external_data: request requires live external data but source "
                "contains no external acquisition path"
            )
        if not self.acquisition_reaches_result:
            return (
                "dynamic_external_data: external acquisition does not flow into the "
                "returned result"
            )
        if self.unverified_endpoint is not None:
            return (
                "dynamic_external_data: source uses an endpoint not verified by "
                f"external source research: {self.unverified_endpoint}"
            )
        return "A plausible external acquisition path reaches the returned result."


def _normalize(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.casefold())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def requires_live_external_data(user_request: str | None) -> bool:
    """Classify explicit requests for remote, current, or changing information."""

    if not isinstance(user_request, str) or not user_request.strip():
        return False
    request = _normalize(user_request).replace("_", " ")
    static_concept_question = bool(_STATIC_KNOWLEDGE.search(request))
    has_action = bool(_LIVE_ACTION.search(request))
    has_source = bool(_EXTERNAL_SOURCE.search(request))
    has_time = bool(_LIVE_TIME.search(request))
    has_dynamic_data = bool(_DYNAMIC_DATA.search(request))
    has_url = "http://" in request or "https://" in request
    if static_concept_question and not (
        (has_time and has_dynamic_data)
        or (has_action and has_source)
        or (_PRICE_DATA.search(request) and re.search(r"\b(?:dime|tell|show|get|consulta|consult|precio|price)\b", request))
    ):
        return False
    if has_url and (has_action or has_dynamic_data):
        return True
    if has_action and has_source:
        return True
    if has_time and has_dynamic_data:
        return True
    return bool(_PRICE_DATA.search(request) and re.search(r"\b(?:dime|tell|show|get|consulta|consult|precio|price)\b", request))


def inspect_external_data_source(
    source: str,
    user_request: str | None,
    *,
    verified_endpoints: tuple[str, ...] | None = None,
    verified_source: str | None = None,
) -> ExternalDataCheck:
    """Conservatively detect a network/tool acquisition flowing into a result.

    Candidate source is parsed but never imported or executed.
    """

    requires_live = requires_live_external_data(user_request)
    if not requires_live:
        return ExternalDataCheck(False, False, False)

    normalized_source = _normalize(source).replace("_", " ")
    marker = _SIMULATION_MARKERS.search(normalized_source)
    if marker:
        return ExternalDataCheck(True, False, False, marker.group(0))

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return ExternalDataCheck(True, False, False)

    module_aliases: dict[str, str] = {}
    function_aliases: set[str] = set()
    web_tool_classes: set[str] = set()
    network_calls: set[ast.Call] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if alias.name in _NETWORK_MODULES or root in _NETWORK_MODULES:
                    module_aliases[alias.asname or root] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module in _NETWORK_MODULES or node.module.startswith("urllib."):
                function_aliases.update(alias.asname or alias.name for alias in node.names)
            elif node.module in _NATIVE_WEB_MODULES:
                web_tool_classes.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in {"WebSearchTool", "HTTPRequestTool", "SecureWebSession"}
                )

    def dotted_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = dotted_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def is_network_call(node: ast.Call, web_instances: set[str]) -> bool:
        name = dotted_name(node.func)
        if isinstance(node.func, ast.Name):
            is_network = node.func.id in function_aliases or (
                node.func.id in module_aliases
                and module_aliases[node.func.id] in _NETWORK_FUNCTIONS
            )
            if is_network:
                network_calls.add(node)
            return is_network
        if isinstance(node.func, ast.Attribute):
            for alias, module in module_aliases.items():
                if name.startswith(alias + "."):
                    method = name.rsplit(".", 1)[-1]
                    if (
                        (module in _NETWORK_MODULES or module.startswith("urllib."))
                        and method in _NETWORK_METHODS | _NETWORK_FUNCTIONS
                    ):
                        network_calls.add(node)
                        return True
            root = node.func.value
            if isinstance(root, ast.Name) and root.id in web_instances and (
                node.func.attr == "execute" or node.func.attr in _NETWORK_METHODS
            ):
                network_calls.add(node)
                return True
            if isinstance(root, ast.Name) and root.id in module_aliases:
                module = module_aliases[root.id]
                is_network = (
                    (module in _NETWORK_MODULES or module.startswith("urllib."))
                    and node.func.attr in _NETWORK_METHODS | _NETWORK_FUNCTIONS
                )
                if is_network:
                    network_calls.add(node)
                return is_network
            if isinstance(root, ast.Call):
                constructor = dotted_name(root.func)
                constructor_root = constructor.split(".")[0]
                if (
                    constructor in web_tool_classes
                    or constructor_root in web_tool_classes
                ) and (node.func.attr == "execute" or node.func.attr in _NETWORK_METHODS):
                    network_calls.add(node)
                    return True
                if constructor_root in module_aliases and node.func.attr in _NETWORK_METHODS:
                    is_network = module_aliases[constructor_root] in {"httpx", "aiohttp", "urllib3"}
                    if is_network:
                        network_calls.add(node)
                    return is_network
        is_network = name in function_aliases
        if is_network:
            network_calls.add(node)
        return is_network

    def normalized_endpoint(value: str) -> tuple[str, str, str, str] | None:
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            return (
                parsed.scheme.lower(),
                parsed.hostname.lower(),
                (parsed.path.rstrip("/") or "/"),
                "",
            )
        except ValueError:
            return None

    literal_assignments = {
        target.id: node.value.value
        for node in ast.walk(tree)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        for target in (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        )
        if isinstance(target, ast.Name)
    }

    def call_endpoint(call: ast.Call) -> str | None:
        value_node = next(
            (
                keyword.value
                for keyword in call.keywords
                if keyword.arg in {"url", "url_", "endpoint"}
            ),
            call.args[0] if call.args else None,
        )
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            return value_node.value
        if isinstance(value_node, ast.Name):
            return literal_assignments.get(value_node.id)
        return None

    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    helper_tainted: set[str] = set()

    def analyze_function(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        known_helpers: set[str],
    ) -> tuple[bool, bool]:
        tainted: set[str] = set()
        web_instances: set[str] = set()
        has_network_call = False
        returns_tainted = False

        def depends_on_acquisition(node: ast.AST | None) -> bool:
            nonlocal has_network_call
            if node is None:
                return False
            if isinstance(node, ast.Call):
                if is_network_call(node, web_instances):
                    has_network_call = True
                    return True
                if isinstance(node.func, ast.Name) and node.func.id in known_helpers:
                    return True
            if isinstance(node, ast.Name) and node.id in tainted:
                return True
            return any(depends_on_acquisition(child) for child in ast.iter_child_nodes(node))

        def assigned_names(target: ast.AST) -> set[str]:
            if isinstance(target, ast.Name):
                return {target.id}
            if isinstance(target, (ast.Tuple, ast.List)):
                return set().union(*(assigned_names(item) for item in target.elts))
            return set()

        def visit_statements(statements: list[ast.stmt]) -> None:
            nonlocal returns_tainted, has_network_call
            for statement in statements:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                if isinstance(statement, ast.Assign):
                    value_depends = depends_on_acquisition(statement.value)
                    for target in statement.targets:
                        names = assigned_names(target)
                        if value_depends:
                            tainted.update(names)
                        else:
                            tainted.difference_update(names)
                            if (
                                isinstance(statement.value, ast.Call)
                                and isinstance(statement.value.func, ast.Name)
                                and statement.value.func.id in web_tool_classes
                            ):
                                web_instances.update(names)
                elif isinstance(statement, ast.AnnAssign):
                    value_depends = depends_on_acquisition(statement.value)
                    names = assigned_names(statement.target)
                    if value_depends:
                        tainted.update(names)
                    else:
                        tainted.difference_update(names)
                        if (
                            isinstance(statement.value, ast.Call)
                            and isinstance(statement.value.func, ast.Name)
                            and statement.value.func.id in web_tool_classes
                        ):
                            web_instances.update(names)
                elif isinstance(statement, ast.Return):
                    returns_tainted = returns_tainted or depends_on_acquisition(statement.value)
                elif isinstance(statement, ast.If):
                    visit_statements(statement.body)
                    visit_statements(statement.orelse)
                elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                    visit_statements(statement.body)
                    visit_statements(statement.orelse)
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    visit_statements(statement.body)
                elif isinstance(statement, (ast.Try,)):
                    visit_statements(statement.body)
                    for handler in statement.handlers:
                        visit_statements(handler.body)
                    visit_statements(statement.orelse)
                    visit_statements(statement.finalbody)

        visit_statements(function.body)
        has_network_call = has_network_call or any(
            isinstance(node, ast.Call) and is_network_call(node, web_instances)
            for node in ast.walk(function)
        )
        return has_network_call, returns_tainted

    for _ in range(max(1, len(functions))):
        previous = set(helper_tainted)
        for function in functions:
            has_call, returns_data = analyze_function(function, helper_tainted)
            if has_call and returns_data:
                helper_tainted.add(function.name)
        if helper_tainted == previous:
            break

    entrypoints = [
        function for function in functions
        if function.name == "ejecutar_skill" and function in tree.body
    ]
    if entrypoints:
        has_acquisition, data_reaches_result = analyze_function(entrypoints[0], helper_tainted)
    else:
        has_acquisition, data_reaches_result = False, False
    unverified_endpoint = None
    if verified_endpoints is not None and has_acquisition:
        allowed_values = (
            *verified_endpoints,
            *((verified_source,) if verified_source else ()),
        )
        allowed = {
            endpoint
            for value in allowed_values
            if (endpoint := normalized_endpoint(value)) is not None
        }
        used = [call_endpoint(call) for call in network_calls]
        if not used or any(
            endpoint is None
            or normalized_endpoint(endpoint) not in allowed
            for endpoint in used
        ):
            unverified_endpoint = next(
                (endpoint for endpoint in used if endpoint is None or normalized_endpoint(endpoint) not in allowed),
                "<dynamic endpoint>",
            )
    return ExternalDataCheck(
        True, has_acquisition, data_reaches_result,
        unverified_endpoint=unverified_endpoint,
    )
