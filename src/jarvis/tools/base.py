"""Base classes and data models for JARVIS tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from jarvis.security.levels import SecurityLevel


@dataclass
class ToolSpec:
    """Especificación técnica y metadatos de una herramienta."""

    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    category: str = "general"
    requires_confirmation: bool = False
    timeout_seconds: float = 30.0
    required_capabilities: List[str] = field(default_factory=list)


@dataclass
class ToolResult:
    """Resultado estructurado devuelto tras la ejecución de una herramienta."""

    tool_name: str
    content: str
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolParameter:
    """Describe un parámetro individual aceptado por una herramienta."""

    name: str
    description: str
    required: bool = True
    parameter_type: str = "string"


class BaseTool(ABC):
    """Interfaz base para todas las herramientas de JARVIS."""

    tool_id: str = ""
    name: str = ""
    description: str = ""
    required_level: SecurityLevel = SecurityLevel.LEVEL_1

    @property
    def spec(self) -> ToolSpec:
        """Retorna la especificación estandarizada de la herramienta."""
        return ToolSpec(
            name=self.name or self.tool_id,
            description=self.description,
            parameters={
                p.name: {"description": p.description, "type": p.parameter_type}
                for p in self.parameters
            },
        )

    @property
    def parameters(self) -> list[ToolParameter]:
        """Lista de parámetros para compatibilidad con esquemas simples."""
        return []

    @abstractmethod
    def execute(self, **kwargs: Any) -> ToolResult:
        """Ejecuta la lógica de la herramienta y retorna un ToolResult."""
        raise NotImplementedError

    def specification(self) -> dict[str, Any]:
        """Genera el diccionario serializable para el modelo LLM."""
        spec_data = self.spec
        level_val = (
            self.required_level.value
            if hasattr(self.required_level, "value")
            else self.required_level
        )
        return {
            "name": spec_data.name,
            "description": spec_data.description,
            "required_level": level_val,
            "parameters": spec_data.parameters,
            "category": spec_data.category,
        }


__all__ = [
    "BaseTool",
    "ToolSpec",
    "ToolResult",
    "ToolParameter",
]