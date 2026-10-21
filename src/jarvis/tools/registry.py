"""Central registry of all tools available to JARVIS."""

from __future__ import annotations

import logging
from typing import Any, Callable, Type, TypeVar

from jarvis.tools.base import BaseTool, ToolResult

logger = logging.getLogger(__name__)
TTool = TypeVar("TTool", bound=Type[BaseTool])


class ToolRegistry:
    """Registro central para la declaración y ejecución de herramientas."""

    _tools: dict[str, Type[BaseTool]] = {}

    @classmethod
    def register(cls, name: str) -> Callable[[TTool], TTool]:
        """Decorador para registrar clases de herramientas bajo un nombre único."""

        def decorator(tool_class: TTool) -> TTool:
            if name in cls._tools:
                logger.warning("Reemplazando registro de herramienta previa: '%s'", name)
            cls._tools[name] = tool_class
            return tool_class

        return decorator

    @classmethod
    def get(cls, name: str) -> Type[BaseTool] | None:
        """Retorna la clase de la herramienta registrada."""
        return cls._tools.get(name)

    @classmethod
    def create(cls, name: str, **kwargs: Any) -> BaseTool:
        """Instancia una herramienta registrada pasando parámetros opcionales al constructor."""
        tool_class = cls.get(name)
        if tool_class is None:
            raise KeyError(f"La herramienta '{name}' no está registrada.")
        return tool_class(**kwargs)

    @classmethod
    def all(cls) -> list[Type[BaseTool]]:
        """Retorna la lista de clases de herramientas actualmente registradas."""
        return list(cls._tools.values())

    @classmethod
    def specifications(cls) -> list[dict[str, Any]]:
        """Genera las especificaciones en formato interpretable por el modelo LLM."""
        specs = []
        seen_names = set()
        for tool_class in cls._tools.values():
            try:
                spec_dict = tool_class().specification()
                name = spec_dict.get("name")
                if not name or name not in seen_names:
                    if name:
                        seen_names.add(name)
                    specs.append(spec_dict)
            except Exception as exc:
                logger.error("Error al obtener la especificación de %s: %s", tool_class, exc)
        return specs

    @classmethod
    def execute(cls, name: str, **params: Any) -> ToolResult:
        """Instancia y ejecuta la herramienta especificada de forma directa."""
        try:
            tool_instance = cls.create(name)
            return tool_instance.execute(**params)
        except KeyError as err:
            return ToolResult(
                tool_name=name,
                content=str(err),
                success=False,
            )
        except Exception as exc:
            logger.exception("Error durante la ejecución de '%s'", name)
            return ToolResult(
                tool_name=name,
                content=f"Error inesperado al ejecutar '{name}': {exc}",
                success=False,
            )


__all__ = ["ToolRegistry"]