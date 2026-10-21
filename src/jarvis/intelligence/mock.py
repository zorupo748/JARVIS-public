from __future__ import annotations

from typing import Any, Optional

from .engine import AIResponse, IntelligenceEngine


class MockEngine(IntelligenceEngine):
    """Motor de prueba para desarrollar JARVIS sin un modelo real."""

    def __init__(
        self,
        model: str = "mock-model",
        responses: Optional[dict[str, AIResponse]] = None,
    ) -> None:
        self.model = model
        self.responses = responses or {}

    def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
    ) -> AIResponse:
        """Devuelve una respuesta simulada o configurada."""
        selected_model = model or self.model
        last_message = messages[-1].get("content", "") if messages else ""

        if last_message in self.responses:
            resp = self.responses[last_message]
            resp.model = selected_model
            return resp

        return AIResponse(
            content=f"[MOCK] He recibido: {last_message}",
            model=selected_model,
            finish_reason="stop",
        )

    def health(self) -> bool:
        """El motor de prueba siempre está disponible."""
        return True