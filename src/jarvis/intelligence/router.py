from __future__ import annotations

import logging
from typing import Any, Optional

from .engine import AIResponse, IntelligenceEngine
from .groq import GroqEngine
from .ollama import OllamaEngine

logger = logging.getLogger(__name__)

ARCHITECT_SYSTEM_PROMPT = (
    "ROL: Arquitecto y Planificador Central de JARVIS.\n"
    "OBJETIVO: Analizar peticiones complejas, establecer planes de acción estratégicos "
    "y dar respuestas de alto nivel sin asumir ejecución física de archivos."
)


class RouterEngine(IntelligenceEngine):
    """
    Enrutador de Inteligencia para JARVIS.
    Garantiza ejecución 100% local por defecto (Ollama) y deriva a Groq 
    como Arquitecto Estratégico o motor de contingencia.
    """

    def __init__(
        self,
        primary: Optional[IntelligenceEngine] = None,
        planner: Optional[IntelligenceEngine] = None,
        complexity_keywords: Optional[list[str]] = None,
    ) -> None:
        self.primary = primary or OllamaEngine()
        self.planner = planner or GroqEngine()
        self.complexity_keywords = complexity_keywords or [
            "planifica",
            "orquesta",
            "desglosa en pasos",
            "arquitectura",
            "plan de ejecución",
        ]

    def _is_complex_request(self, prompt: str) -> bool:
        """Comprueba si el prompt requiere el razonamiento del Arquitecto."""
        prompt_lower = prompt.lower()
        return any(kw in prompt_lower for kw in self.complexity_keywords)

    def _prepare_architect_messages(
        self, messages: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Inyecta la instrucción del Arquitecto Central en el historial."""
        prepended = [dict(m) for m in messages]
        if prepended and prepended[0].get("role") == "system":
            prepended[0]["content"] = (
                f"{prepended[0].get('content', '')}\n\n{ARCHITECT_SYSTEM_PROMPT}"
            )
        else:
            prepended.insert(0, {"role": "system", "content": ARCHITECT_SYSTEM_PROMPT})
        return prepended

    def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
    ) -> AIResponse:
        """Determina qué motor debe procesar la solicitud."""
        last_message = messages[-1].get("content", "") if messages else ""

        # 1. Si requiere planificación estratégica, se envía a Groq como Arquitecto
        if self._is_complex_request(last_message) and self.planner.health():
            logger.info("Enrutando a Groq (Arquitecto Central).")
            architect_messages = self._prepare_architect_messages(messages)
            response = self.planner.generate(architect_messages, tools=tools, model=model)
            if response.finish_reason != "error":
                return response
            logger.warning("Fallo en el Arquitecto Groq. Reintentando con el motor local.")

        # 2. Ejecución local por defecto (Ollama)
        if self.primary.health():
            response = self.primary.generate(messages, tools=tools, model=model)
            if response.finish_reason != "error":
                return response
            logger.warning("Motor local no pudo procesar la solicitud. Evaluando contingencia.")

        # 3. Fallback a Groq en caso de fallo del entorno local
        if self.planner.health():
            logger.warning("Activando Groq como motor de contingencia.")
            return self.planner.generate(messages, tools=tools, model=model)

        return AIResponse(
            content="Error: Ni el motor local ni el planificador remoto están disponibles.",
            model=model or "none",
            finish_reason="error",
        )

    def health(self) -> bool:
        """El enrutador está activo si al menos un motor responde."""
        return self.primary.health() or self.planner.health()