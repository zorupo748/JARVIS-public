"""Web search tool — Tavily API with DuckDuckGo fallback."""

from __future__ import annotations

import logging
import os
import re
from importlib import import_module
from typing import Any

from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

try:
    TavilyClient = getattr(import_module("tavily"), "TavilyClient")
except ImportError:
    TavilyClient = None  # type: ignore

try:
    DDGS = getattr(import_module("ddgs"), "DDGS")
except ImportError:
    try:
        DDGS = getattr(import_module("duckduckgo_search"), "DDGS")
    except ImportError:
        DDGS = None  # type: ignore


@ToolRegistry.register("web_search")
class WebSearchTool(BaseTool):
    """Herramienta de búsqueda web mediante la API de Tavily con fallback a DuckDuckGo."""

    tool_id = "web_search"

    def __init__(self, api_key: str | None = None, max_results: int = 8):
        self._api_key = api_key or os.environ.get("TAVILY_API_KEY")
        self._max_results = max_results

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="web_search",
            description=(
                "Busca en la web información actualizada o extrae texto de una URL directa."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Término de búsqueda o URL completa a consultar.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Número máximo de resultados a devolver.",
                    },
                },
                "required": ["query"],
            },
            category="search",
        )

    @staticmethod
    def _is_url(text: str) -> bool:
        stripped = text.strip()
        return stripped.startswith("http://") or stripped.startswith("https://")

    @staticmethod
    def _extract_url(text: str) -> str | None:
        match = re.search(r"https?://[^\s,;\"'<>]+", text)
        return match.group(0).rstrip(".,;)") if match else None

    @classmethod
    def _normalize_url(cls, url: str) -> str:
        m = re.match(r"(https?://arxiv\.org)/pdf/(.+?)(?:\.pdf)?$", url)
        if m:
            return f"{m.group(1)}/abs/{m.group(2)}"
        return url

    @classmethod
    def _fetch_url(cls, url: str, max_chars: int = 6000) -> str:
        if httpx is None:
            raise ImportError("La librería 'httpx' no está instalada. Ejecuta: pip install httpx")

        normalized_url = cls._normalize_url(url)
        resp = httpx.get(
            normalized_url.strip(),
            follow_redirects=True,
            timeout=30.0,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; JARVIS/1.0)"
            },
        )
        resp.raise_for_status()
        content_type = resp.headers.get("content-type", "")
        if "application/pdf" in content_type:
            return f"[El enlace apunta a un archivo PDF no legible directamente: {normalized_url}]"

        html = resp.text
        html = re.sub(
            r"<(script|style)[^>]*>.*?</\1>",
            "",
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > max_chars:
            text = text[:max_chars] + "\n\n[Contenido truncado]"
        return text

    def _duckduckgo_search(self, query: str, max_results: int) -> str:
        if DDGS is None:
            raise ImportError("No se encontró 'ddgs'. Ejecuta: pip install ddgs")

        ddgs = DDGS()
        results = list(ddgs.text(query, max_results=max_results))
        if not results:
            return ""

        formatted_results = []
        for r in results:
            title = r.get("title", "Sin título")
            link = r.get("href") or r.get("link", "")
            body = r.get("body") or r.get("snippet", "")
            formatted_results.append(f"**{title}**\n{link}\n{body}")

        return "\n\n".join(formatted_results)

    def execute(self, **params: Any) -> ToolResult:
        query = params.get("query", "")
        if not query:
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ningún término de búsqueda.",
                success=False,
            )

        # SANITIZACIÓN DE max_results: Forzar siempre a entero
        raw_max_results = params.get("max_results", self._max_results)
        try:
            max_results = int(raw_max_results)
        except (ValueError, TypeError):
            max_results = self._max_results

        url = query.strip() if self._is_url(query) else self._extract_url(query)
        if url:
            try:
                content = self._fetch_url(url)
                return ToolResult(
                    tool_name=self.tool_id,
                    content=content or "No se encontró contenido en la URL.",
                    success=True,
                    metadata={"url": url, "mode": "fetch"},
                )
            except Exception as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error al descargar la URL: {exc}",
                    success=False,
                )

        # Intento con Tavily protegido contra fallos de clave
        formatted = ""
        engine_used = "unknown"

        if self._api_key and TavilyClient is not None:
            try:
                client = TavilyClient(api_key=self._api_key)
                response = client.search(
                    query, 
                    max_results=max_results,
                    search_depth="advanced"
                )
                results = response.get("results", [])
                if results:
                    formatted = "\n\n".join(
                        f"**{r.get('title', 'Sin título')}**\n"
                        f"{r.get('url', '')}\n{r.get('content', '')}"
                        for r in results
                    )
                    engine_used = "tavily"
            except Exception as exc:
                logger.debug("Tavily no disponible o clave inválida (%s). Usando DuckDuckGo...", exc)

        # Fallback automático a DuckDuckGo si Tavily falla, no hay clave o no trajo resultados
        if not formatted:
            try:
                formatted = self._duckduckgo_search(query, max_results)
                engine_used = "duckduckgo"
            except Exception as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error en búsqueda web: {exc}",
                    success=False,
                )

        # Validación estricta centralizada para filtrar contenido basura o vacío
        if not formatted or len(formatted.strip()) < 100 or "no se encontraron resultados" in formatted.lower():
            formatted = "[Aviso del sistema: El buscador web no ha retornado información útil o contrastable para esta consulta.]"

        return ToolResult(
            tool_name=self.tool_id,
            content=formatted,
            success=True,
            metadata={"engine": engine_used},
        )


__all__ = ["WebSearchTool"]