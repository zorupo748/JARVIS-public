"""Local Intelligence Engine using Ollama (OpenAI compatible endpoint)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from openai import OpenAI
from jarvis.intelligence.engine import AIResponse, IntelligenceEngine

logger = logging.getLogger("jarvis.intelligence")


class LocalEngine(IntelligenceEngine):
    """Motor que conecta con LLMs locales a través de Ollama o compatibles."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        api_key: str = "ollama",  # Ollama no requiere key real, pero la librería la pide
        default_model: str = "llama3.1", # Se recomienda llama3.1, qwen2.5 o mistral-nemo para tools
    ) -> None:
        self.client = OpenAI(base_url=base_url, api_key=api_key)
        self.default_model = default_model

    def _format_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Adapta el esquema interno de JARVIS al formato requerido por la API."""
        formatted = []
        for tool in tools:
            # JARVIS spec: {"name": "...", "description": "...", "parameters": {...}}
            formatted.append({
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {}),
                }
            })
        return formatted

    def generate(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> AIResponse:
        
        target_model = model or self.default_model
        formatted_tools = self._format_tools(tools) if tools else None

        try:
            # Llamada al modelo local
            response = self.client.chat.completions.create(
                model=target_model,
                messages=messages, # type: ignore
                tools=formatted_tools, # type: ignore
                temperature=0.2, # Baja temperatura para que sea más preciso al usar herramientas
            )

            message = response.choices[0].message
            content = message.content
            
            tool_calls = []
            if message.tool_calls:
                for call in message.tool_calls:
                    # Extraer argumentos JSON
                    function_call = getattr(call, "function", None)
                    custom_call = getattr(call, "custom", None)
                    call_name = getattr(function_call, "name", None) or getattr(custom_call, "name", "")
                    raw_arguments = (
                        getattr(function_call, "arguments", None)
                        or getattr(custom_call, "input", "{}")
                    )
                    try:
                        arguments = json.loads(raw_arguments)
                    except (json.JSONDecodeError, TypeError):
                        arguments = {}
                        
                    tool_calls.append({
                        "name": call_name,
                        "parameters": arguments,
                        "id": getattr(call, "id", None),
                    })

            return AIResponse(content=content or "", tool_calls=tool_calls, model=target_model)

        except Exception as e:
            logger.error(f"Error en LocalEngine: {e}")
            return AIResponse(
                content=f"Error al conectar con la IA local ({target_model}): {e}",
                model=target_model,
            )


__all__ = ["LocalEngine"]