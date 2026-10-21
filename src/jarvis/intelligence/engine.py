from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AIResponse:
    """Respuesta generada por un motor de inteligencia."""

    content: str
    model: str
    finish_reason: Optional[str] = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)


class IntelligenceEngine(ABC):
    """Interfaz común para cualquier modelo de IA que use JARVIS."""

    @abstractmethod
    def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
    ) -> AIResponse:
        """Genera una respuesta a partir de una conversación y herramientas opcionales."""
        raise NotImplementedError

    @abstractmethod
    def health(self) -> bool:
        """Comprueba si el motor está disponible."""
        raise NotImplementedError