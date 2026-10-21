"""Ollama Engine for local LLM execution."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from openai import OpenAI

from jarvis.intelligence.engine import AIResponse, IntelligenceEngine

logger = logging.getLogger(__name__)


class OllamaEngine(IntelligenceEngine):
    """Motor que conecta con modelos locales a través de Ollama."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        default_model: str = "llama3.1",
    ) -> None:
        self.client = OpenAI(base_url=base_url, api_key="ollama")
        self.default_model = default_model

    def health(self) -> bool:
        """Verifica que el servidor local de Ollama está accesible."""
        try:
            self.client.models.list()
            return True
        except Exception as e:
            logger.error("El servidor Ollama no está accesible: %s", e)
            return False

    def _format_tools(self, tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Adapta el esquema de JARVIS al formato nativo requerido por la API."""
        return [
            {
                "type": "function",
                "function": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {}),
                },
            }
            for tool in tools
        ]

    def generate(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> AIResponse:
        """Generate a response using Ollama.

        ``kwargs`` keeps this implementation compatible with the engine
        contract as it gains optional generation parameters.
        """
        target_model = model or self.default_model
        formatted_tools = self._format_tools(tools) if tools else None

        try:
            response = self.client.chat.completions.create(
                model=target_model,
                messages=messages, # type: ignore
                tools=formatted_tools, # type: ignore
                temperature=0.2,
            )

            message = response.choices[0].message
            content = message.content or ""
            
            tool_calls = []
            
            # 1. Comportamiento ideal: El modelo usa la API nativa de Tool Calling
            if getattr(message, "tool_calls", None):
                for call in message.tool_calls or []:
                    function = getattr(call, "function", None)
                    if function is None:
                        continue
                    try:
                        arguments = json.loads(getattr(function, "arguments", "{}"))
                    except json.JSONDecodeError:
                        arguments = {}
                        
                    tool_calls.append({
                        "name": getattr(function, "name", ""),
                        "parameters": arguments,
                        "id": call.id,
                    })
                    
            # 2. SISTEMA DE SEGURIDAD (FALLBACK): El modelo escupe el JSON en el texto
            elif "{" in content and "}" in content and '"name"' in content:
                try:
                    # Extraer lo que haya entre el primer { y el último }
                    start = content.find('{')
                    end = content.rfind('}')
                    if start != -1 and end != -1 and start < end:
                        json_str = content[start:end+1]
                        data = json.loads(json_str)
                        
                        # Si parece una herramienta, la interceptamos
                        if "name" in data and "parameters" in data:
                            tool_calls.append({
                                "name": data["name"],
                                "parameters": data["parameters"],
                                "id": f"call_fallback_{uuid.uuid4().hex[:8]}"
                            })
                            # Limpiamos el texto para que el usuario no vea el JSON
                            content = content[:start].strip()
                except Exception as e:
                    logger.debug(f"Fallback parse failed: {e}")

            return AIResponse(model=target_model, content=content, tool_calls=tool_calls)

        except Exception as e:
            logger.error("Error en OllamaEngine: %s", e)
            return AIResponse(
                model=target_model, 
                content=f"Error al conectar con la IA local ({target_model}): {e}"
            )


__all__ = ["OllamaEngine"]