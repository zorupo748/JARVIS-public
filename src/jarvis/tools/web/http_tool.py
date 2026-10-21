"""Generic HTTP Request Tool — Allows JARVIS to consume any REST API or Web Service."""

from __future__ import annotations

import json
import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any
import urllib.request
import urllib.error
from urllib.parse import urlsplit, urlunsplit

from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry


@dataclass(frozen=True)
class ResearchFetchResponse:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    content_length: int | None = None
    truncated: bool = False


def _validate_public_http_url(url: str) -> tuple[str, ...]:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid research URL.") from exc
    host_value = parsed.hostname
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not host_value
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 80, 443}
    ):
        raise ValueError("Research supports only public HTTP(S) URLs on standard ports.")

    host = host_value.rstrip(".").casefold()
    if (
        host in {"localhost", "metadata", "metadata.google.internal"}
        or host.endswith((".localhost", ".local", ".internal"))
    ):
        raise ValueError("Private and metadata hostnames are blocked for research.")

    try:
        addresses: set[str] = {
            str(item[4][0])
            for item in socket.getaddrinfo(
                host, port or (443 if parsed.scheme == "https" else 80)
            )
        }
    except OSError as exc:
        raise ValueError("Research host could not be resolved safely.") from exc
    if not addresses:
        raise ValueError("Research host resolved to no addresses.")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global:
            raise ValueError("Private, loopback, link-local, and reserved IPs are blocked.")
    return tuple(sorted(addresses))


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, pinned_ip: str, **kwargs: Any) -> None:
        super().__init__(host, **kwargs)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, *, pinned_ip: str, **kwargs: Any) -> None:
        context = kwargs.pop("context", None) or ssl.create_default_context()
        super().__init__(host, context=context, **kwargs)
        self._pinned_ip = pinned_ip
        self._research_context = context

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._pinned_ip, self.port),
            self.timeout,
        )
        self.sock = self._research_context.wrap_socket(
            raw_socket,
            server_hostname=self.host,
        )


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, host_addresses: dict[str, tuple[str, ...]]) -> None:
        super().__init__()
        self._host_addresses = host_addresses

    def http_open(self, req):
        return self.do_open(self._connection_factory, req)

    def _connection_factory(self, host: str, **kwargs: Any) -> _PinnedHTTPConnection:
        hostname = urlsplit("//" + host).hostname
        addresses = self._host_addresses.get((hostname or "").casefold(), ())
        if not addresses:
            raise ValueError("HTTP destination has no validated public address.")
        return _PinnedHTTPConnection(host, pinned_ip=addresses[0], **kwargs)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, host_addresses: dict[str, tuple[str, ...]]) -> None:
        super().__init__()
        self._host_addresses = host_addresses

    def https_open(self, req):
        return self.do_open(self._connection_factory, req)

    def _connection_factory(self, host: str, **kwargs: Any) -> _PinnedHTTPSConnection:
        hostname = urlsplit("//" + host).hostname
        addresses = self._host_addresses.get((hostname or "").casefold(), ())
        if not addresses:
            raise ValueError("HTTPS destination has no validated public address.")
        return _PinnedHTTPSConnection(host, pinned_ip=addresses[0], **kwargs)


class _BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(
        self,
        max_redirects: int,
        host_addresses: dict[str, tuple[str, ...]],
    ) -> None:
        super().__init__()
        self.max_redirects = max_redirects
        self.redirect_count = 0
        self._host_addresses = host_addresses

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise urllib.error.HTTPError(
                req.full_url, code, "Research redirect limit exceeded.", headers, fp
            )
        addresses = _validate_public_http_url(newurl)
        hostname = urlsplit(newurl).hostname
        if hostname is None:
            raise ValueError("Redirect URL has no hostname.")
        self._host_addresses[hostname.casefold()] = addresses
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@ToolRegistry.register("http_request")
class HTTPRequestTool(BaseTool):
    """Ejecuta peticiones HTTP (GET, POST, PUT, DELETE) contra cualquier API o endpoint web."""

    tool_id = "http_request"

    def fetch_for_research(
        self,
        url: str,
        *,
        timeout_seconds: float = 8.0,
        max_bytes: int = 512_000,
        max_redirects: int = 3,
    ) -> ResearchFetchResponse:
        """Fetch a bounded public document for trusted static source research."""

        if not isinstance(url, str):
            raise TypeError("Research URL must be a string.")
        parsed = urlsplit(url.strip())
        request_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, "")
        )
        initial_addresses = _validate_public_http_url(request_url)
        if not 0 < timeout_seconds <= 15 or not 0 < max_bytes <= 1_000_000:
            raise ValueError("Research fetch limits are outside the allowed range.")
        if not 0 <= max_redirects <= 3:
            raise ValueError("Research redirect limit is outside the allowed range.")

        initial_host = urlsplit(request_url).hostname
        if initial_host is None:
            raise ValueError("Research URL has no hostname.")
        host_addresses = {initial_host.casefold(): initial_addresses}
        redirects = _BoundedRedirectHandler(max_redirects, host_addresses)
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _PinnedHTTPHandler(host_addresses),
            _PinnedHTTPSHandler(host_addresses),
            redirects,
        )
        request = urllib.request.Request(
            request_url,
            headers={
                "Accept": "text/html,application/javascript,text/javascript,*/*;q=0.1",
                "User-Agent": "JARVIS-Trusted-Research/1.0",
            },
            method="GET",
        )
        started = time.monotonic()
        with opener.open(request, timeout=timeout_seconds) as response:
            if time.monotonic() - started > timeout_seconds:
                raise TimeoutError("Research fetch exceeded its deadline.")
            raw_content_length = response.headers.get("Content-Length")
            try:
                content_length = (
                    int(raw_content_length) if raw_content_length is not None else None
                )
            except (TypeError, ValueError):
                content_length = None
            if content_length is not None and content_length < 0:
                content_length = None
            truncated = content_length is not None and content_length > max_bytes
            body = b"" if truncated else response.read(max_bytes)
            if not truncated and (
                len(body) == max_bytes
                and (content_length is None or content_length > len(body))
            ):
                truncated = True
            final_url = response.geturl()
            _validate_public_http_url(final_url)
            return ResearchFetchResponse(
                requested_url=request_url,
                final_url=final_url,
                status_code=int(response.status),
                content_type=response.headers.get("Content-Type", ""),
                body=body,
                content_length=content_length,
                truncated=truncated,
            )

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="http_request",
            description=(
                "Realiza peticiones HTTP REST (GET, POST, PUT, DELETE) a cualquier API web. "
                "Soporta parámetros URL, cabeceras personalizadas y cuerpo JSON."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "La URL completa del endpoint de la API.",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE"],
                        "description": "Método HTTP a utilizar (por defecto 'GET').",
                    },
                    "headers": {
                        "type": "object",
                        "description": "Diccionario de cabeceras HTTP (ej. Authorization, Content-Type).",
                    },
                    "body": {
                        "type": "object",
                        "description": "Cuerpo de la petición en formato JSON (para POST/PUT).",
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Tiempo máximo de espera en segundos (por defecto 30).",
                    },
                },
                "required": ["url"],
            },
            category="web",
        )

    def execute(self, **params: Any) -> ToolResult:
        url = params.get("url")
        if not url:
            return ToolResult(
                tool_name=self.tool_id,
                content="Error: No se proporcionó la URL de la petición.",
                success=False,
            )

        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        body = params.get("body")
        
        # SANITIZACIÓN: Forzar que el timeout sea un entero
        raw_timeout = params.get("timeout_seconds", 30)
        try:
            timeout = int(raw_timeout)
        except (ValueError, TypeError):
            timeout = 30

        data = None
        if body is not None:
            if isinstance(body, dict):
                data = json.dumps(body).encode("utf-8")
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"
            elif isinstance(body, str):
                data = body.encode("utf-8")

        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                response_text = response.read().decode("utf-8", errors="replace")

                # Intentar formatear como JSON si es posible
                try:
                    json_data = json.loads(response_text)
                    formatted_content = json.dumps(json_data, indent=2, ensure_ascii=False)
                except Exception:
                    formatted_content = response_text

                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Respuesta HTTP {status}:\n\n{formatted_content[:2000]}",
                    success=True,
                    metadata={"status_code": status, "url": url},
                )

        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error HTTP {e.code} ({e.reason}):\n{error_body[:1000]}",
                success=False,
                metadata={"status_code": e.code},
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error al realizar la petición HTTP: {e}",
                success=False,
            )


__all__ = ["HTTPRequestTool"]