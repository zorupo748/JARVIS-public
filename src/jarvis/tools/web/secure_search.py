"""Secure Search Tool for JARVIS.

Integrates SecureSearchSkill and SecureWebSession with JARVIS's ToolRegistry,
allowing AI agents to safely query authorized web knowledge repositories (Wikipedia)
within an isolated, ephemeral headless browser environment.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any, Dict, Optional

from jarvis.security.levels import SecurityLevel
from jarvis.skills.secure_search_skill import SecureSearchSkill
from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


def _run_coroutine_sync(coro: Any) -> Any:
    """Execute an asynchronous coroutine safely from synchronous contexts.

    Handles cases where an event loop is already running in the current thread
    by delegating execution to a dedicated thread pool worker.
    """
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


@ToolRegistry.register("secure_web_search")
@ToolRegistry.register("secure_search")
class SecureSearchTool(BaseTool):
    """Herramienta de búsqueda web segura y aislada en fuentes autorizadas (Wikipedia)."""

    tool_id = "secure_search"
    name = "secure_search"
    description = (
        "Consulta y extrae resúmenes seguros de fuentes de conocimiento autorizadas en la web "
        "(como Wikipedia) utilizando un navegador aislado que previene fugas de red y "
        "bloquea recursos innecesarios."
    )
    required_level = SecurityLevel.LEVEL_1

    def __init__(
        self,
        allowed_domains: Optional[list[str]] = None,
        timeout_ms: int = 15000,
        default_lang: str = "es",
    ) -> None:
        """Inicializa la herramienta de búsqueda segura.

        Args:
            allowed_domains: Dominios autorizados (por defecto Wikipedia).
            timeout_ms: Timeout en milisegundos para la navegación.
            default_lang: Idioma por defecto para las consultas ("es", "en").
        """
        self.allowed_domains = allowed_domains
        self.timeout_ms = timeout_ms
        self.default_lang = default_lang

    @property
    def spec(self) -> ToolSpec:
        """Especificación técnica estandarizada para el modelo LLM."""
        return ToolSpec(
            name="secure_search",
            description=(
                "Busca información factual y resúmenes enciclopédicos de forma segura en Wikipedia. "
                "Ideal para responder preguntas sobre historia, ciencia, tecnología, conceptos "
                "o biografías garantizando contenido verificado y libre de publicidad."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Término, concepto o tema a consultar (ej: 'Mecánica cuántica', 'Alan Turing').",
                    },
                    "lang": {
                        "type": "string",
                        "description": "Código de idioma opcional ('es' para español, 'en' para inglés). Por defecto 'es'.",
                        "default": self.default_lang,
                    },
                    "use_search_route": {
                        "type": "boolean",
                        "description": "Si es True, fuerza la ruta de búsqueda Special:Search de Wikipedia para consultas no exactas.",
                        "default": False,
                    },
                },
                "required": ["query"],
            },
            category="search",
        )

    async def execute_async(self, **params: Any) -> ToolResult:
        """Ejecución nativa asíncrona de la búsqueda segura."""
        raw_query = params.get("query") or params.get("topic") or ""
        if not isinstance(raw_query, str) or not raw_query.strip():
            return ToolResult(
                tool_name=self.tool_id,
                content="[Aviso del sistema]: No se proporcionó ningún término de búsqueda válido.",
                success=False,
            )

        query = raw_query.strip()
        lang = str(params.get("lang") or self.default_lang).strip().lower()
        use_search_route = bool(params.get("use_search_route", False))

        skill = SecureSearchSkill(
            allowed_domains=self.allowed_domains,
            timeout_ms=self.timeout_ms,
            lang=lang,
        )

        try:
            if use_search_route:
                summary = await skill.search_topic(query, use_search_route=True)
            else:
                summary = await skill.search_topic(query)
            formatted_content = (
                f"### Resumen de consulta segura: {query} ({lang.upper()})\n\n"
                f"{summary}\n\n"
                f"*(Fuente verificada e información extraída de Wikipedia en entorno aislado)*"
            )
            return ToolResult(
                tool_name=self.tool_id,
                content=formatted_content,
                success=True,
                metadata={"query": query, "lang": lang, "source": "wikipedia"},
            )

        except PermissionError as exc:
            logger.warning("Intento de acceso a dominio no autorizado: %s", exc)
            return ToolResult(
                tool_name=self.tool_id,
                content=f"[Error de Seguridad]: Acceso denegado. La búsqueda solicitada viola la política de dominios autorizados: {exc}",
                success=False,
                metadata={"blocked": True},
            )

        except TimeoutError as exc:
            logger.error("Tiempo de espera agotado en búsqueda segura de '%s': %s", query, exc)
            return ToolResult(
                tool_name=self.tool_id,
                content=f"[Tiempo Excedido]: La consulta sobre '{query}' no respondió en el tiempo límite ({self.timeout_ms} ms).",
                success=False,
                metadata={"timeout": True},
            )

        except RuntimeError as exc:
            logger.error("Error en motor de navegación para '%s': %s", query, exc)
            return ToolResult(
                tool_name=self.tool_id,
                content=f"[Error de Navegación]: No se pudo recuperar la información solicitada: {exc}",
                success=False,
            )

        except ValueError as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"[Consulta Inválida]: {exc}",
                success=False,
            )

        except Exception as exc:
            logger.exception("Error inesperado en SecureSearchTool para '%s'", query)
            return ToolResult(
                tool_name=self.tool_id,
                content=f"[Error Inesperado]: Ocurrió un fallo no controlado durante la búsqueda: {exc}",
                success=False,
            )

    def execute(self, **params: Any) -> ToolResult:
        """Punto de entrada síncrono estándar invocado por ToolExecutor y JarvisAgent."""
        return _run_coroutine_sync(self.execute_async(**params))


__all__ = ["SecureSearchTool"]
