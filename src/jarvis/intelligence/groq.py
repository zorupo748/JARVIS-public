from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Optional

from dotenv import load_dotenv

from .engine import AIResponse, IntelligenceEngine

load_dotenv()

logger = logging.getLogger(__name__)


class GroqEngine(IntelligenceEngine):
    """Motor de inteligencia basado en Groq API con control estricto de límites y formato."""

    def __init__(
        self,
        model: str = "qwen/qwen3.6-27b",
        api_key: Optional[str] = None,
        timeout: int = 20,
    ) -> None:
        self.model = model
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.timeout = timeout
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"

    def _clean_response_content(self, text: str) -> str:
        """Elimina etiquetas <think> sin perder el contenido del mensaje."""
        if not text:
            return ""

        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        if not cleaned and "<think>" in text:
            cleaned = re.sub(r"</?think>", "", text, flags=re.IGNORECASE).strip()

        return cleaned

    def _format_tools(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Garantiza que el campo parameters sea un JSON Schema válido para la API de Groq."""
        formatted = []
        for tool in tools:
            if not isinstance(tool, dict):
                continue

            if tool.get("type") == "function" and "function" in tool:
                func_spec = dict(tool["function"])
            else:
                func_spec = {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                }
                raw_params = tool.get("parameters") or tool.get("input_schema")

                # Conversión de listas internas de JARVIS a JSON Schema object
                if isinstance(raw_params, list):
                    properties = {}
                    required = []
                    for param in raw_params:
                        if isinstance(param, dict) and "name" in param:
                            p_name = param["name"]
                            properties[p_name] = {
                                "type": param.get("type", "string"),
                                "description": param.get("description", ""),
                            }
                            if param.get("required"):
                                required.append(p_name)
                    func_spec["parameters"] = {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    }
                elif isinstance(raw_params, dict):
                    func_spec["parameters"] = raw_params
                else:
                    func_spec["parameters"] = {"type": "object", "properties": {}}

            params = func_spec.get("parameters")
            if not isinstance(params, dict) or not params:
                params = {"type": "object", "properties": {}}
            else:
                params = dict(params)
                if "type" not in params:
                    params["type"] = "object"
                if "properties" not in params or not isinstance(params["properties"], dict):
                    params["properties"] = {}

            func_spec["parameters"] = params

            formatted.append({
                "type": "function",
                "function": func_spec,
            })
        return formatted

    def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
    ) -> AIResponse:
        """Envía peticiones de alta velocidad a la API de Groq inyectando restricciones de brevedad."""
        if not self.health():
            return AIResponse(
                content="Error: GROQ_API_KEY no configurada o no válida.",
                model=model or self.model,
                finish_reason="error",
            )

        prepended_messages = [dict(m) for m in messages]

        system_constraint = (
            "INSTRUCCIÓN CRÍTICA DE SALIDA:\n"
            "1. NO utilices etiquetas <think> ni bloques de razonamiento interno. Responde directamente.\n"
            "2. Mantén tus respuestas e invocaciones de herramientas concisas.\n"
            "3. Si se te solicita crear o modificar un archivo y tienes la herramienta disponible, INVOCA la herramienta directamente.\n"
            "4. Cierra siempre de forma correcta y completa los bloques de llamada a función."
        )

        if prepended_messages and prepended_messages[0].get("role") == "system":
            prepended_messages[0]["content"] = (
                f"{prepended_messages[0].get('content', '')}\n\n{system_constraint}"
            )
        else:
            prepended_messages.insert(0, {"role": "system", "content": system_constraint})

        selected_model = model or self.model
        payload: dict[str, Any] = {
            "model": selected_model,
            "messages": prepended_messages,
            "max_tokens": 4096,
            "temperature": 0.2,
        }

        if tools:
            formatted = self._format_tools(tools)
            if formatted:
                payload["tools"] = formatted

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.base_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "JARVIS-Agent/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
                choice = result.get("choices", [{}])[0]
                message = choice.get("message", {})

                raw_content = message.get("content") or ""
                clean_content = self._clean_response_content(raw_content)

                raw_tool_calls = message.get("tool_calls", [])
                formatted_calls = []

                for tc in raw_tool_calls:
                    func = tc.get("function", {})
                    args = func.get("arguments", "{}")
                    parsed_args = json.loads(args) if isinstance(args, str) else args
                    formatted_calls.append(
                        {
                            "name": func.get("name"),
                            "parameters": parsed_args,
                        }
                    )

                return AIResponse(
                    content=clean_content,
                    model=selected_model,
                    finish_reason=choice.get("finish_reason", "stop"),
                    tool_calls=formatted_calls,
                )

        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8") if exc.fp else str(exc)
            logger.error("Error HTTP de Groq (%d): %s", exc.code, error_body)
            return AIResponse(
                content=f"Error HTTP {exc.code} de Groq: {error_body}",
                model=selected_model,
                finish_reason="error",
            )
        except Exception as exc:
            logger.error("Error al conectar con Groq API: %s", exc)
            return AIResponse(
                content=f"Error en la llamada a Groq: {exc}",
                model=selected_model,
                finish_reason="error",
            )

    def health(self) -> bool:
        """Verifica que la clave API esté definida y tenga el formato correcto."""
        return bool(self.api_key and self.api_key.strip().startswith("gsk_"))