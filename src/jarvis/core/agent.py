from __future__ import annotations

import json
import logging
import sys
from typing import Any, Protocol, cast, runtime_checkable

from jarvis.intelligence.engine import AIResponse, IntelligenceEngine
from jarvis.security.levels import SecurityLevel

logger = logging.getLogger(__name__)


def _safe_print(text: str) -> None:
    """Imprime mensajes en consola protegiendo contra errores de codificación en Windows (cp1252)."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        try:
            print(text.encode(encoding, errors="replace").decode(encoding))
        except Exception:
            pass


@runtime_checkable
class ToolRegistry(Protocol):
    """Interfaz para el registro de herramientas."""

    def get(self, name: str) -> Any: ...
    def get_tool(self, name: str) -> Any: ...
    def specifications(self) -> list[dict[str, Any]]: ...
    def all(self) -> Any: ...


@runtime_checkable
class ToolExecutor(Protocol):
    """Interfaz para el ejecutor de herramientas."""

    def execute(
        self,
        user: Any,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any: ...


@runtime_checkable
class SecurityGateway(Protocol):
    """Interfaz para la validación de seguridad previa a la ejecución."""

    def authorize(
        self,
        tool_name: str,
        required_level: SecurityLevel,
        user_identity: Any = None,
    ) -> bool: ...


class JarvisAgent:
    """
    Orquestador principal de JARVIS. Conecta el motor de IA, el registro
    de herramientas, la pasarela de seguridad y el ejecutor.
    """

    DEFAULT_SYSTEM_PROMPT: str = (
        "Eres JARVIS, un asistente inteligente avanzado de ingeniería y automatización. "
        "Cuentas con un registro de herramientas para interactuar con el entorno y la web. "
        "Para consultar información factual, conceptos, ciencia, tecnología, historia o biografías en internet de forma segura, "
        "utiliza autónomamente la herramienta 'secure_search'. "
        "Para leer y escribir archivos en el workspace o ejecutar comandos, utiliza las herramientas correspondientes."
    )

    def __init__(
        self,
        intelligence_engine: IntelligenceEngine,
        tool_registry: ToolRegistry | None = None,
        tool_executor: ToolExecutor | None = None,
        security_gateway: SecurityGateway | None = None,
        max_iterations: int = 5,
        default_model: str | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.engine = intelligence_engine

        # Si no se proporciona tool_registry, carga el registro central garantizando la importación de jarvis.tools
        if tool_registry is None:
            import jarvis.tools  # noqa: F401
            from jarvis.tools.adapter import AgentRegistryAdapter

            self.registry: ToolRegistry = AgentRegistryAdapter()
        else:
            self.registry = tool_registry

        # Si no se proporciona tool_executor, usa el ejecutor estándar de herramientas de JARVIS
        if tool_executor is None:
            from jarvis.tools.executor import ToolExecutor as DefaultToolExecutor

            self.executor: ToolExecutor = DefaultToolExecutor()
        else:
            self.executor = tool_executor

        self.security = security_gateway
        self.max_iterations = max_iterations
        self.default_model = default_model
        self.system_prompt = system_prompt or self.DEFAULT_SYSTEM_PROMPT

    def _get_tool_specifications(self) -> list[dict[str, Any]]:
        """Extrae y normaliza las especificaciones de las herramientas registradas."""
        raw_specs: list[dict[str, Any]] = []
        if hasattr(self.registry, "specifications"):
            specs = self.registry.specifications()
            raw_specs = specs if isinstance(specs, list) else list(specs.values())
        elif hasattr(self.registry, "all"):
            tools = self.registry.all()
            tools_list = tools.values() if isinstance(tools, dict) else tools
            raw_specs = [
                t.specification() if hasattr(t, "specification") else t
                for t in tools_list
            ]

        # Deduplicar por nombre para evitar rechazos en las APIs de LLMs (OpenAI, Groq, Ollama)
        seen_names = set()
        unique_specs: list[dict[str, Any]] = []
        for s in raw_specs:
            name = s.get("name") if isinstance(s, dict) else getattr(s, "name", None)
            if name and name not in seen_names:
                seen_names.add(name)
                unique_specs.append(s)
            elif not name:
                unique_specs.append(s)

        return unique_specs

    def _get_tool(self, name: str) -> Any:
        """Obtiene la instancia/clase de una herramienta del registro."""
        if hasattr(self.registry, "get"):
            return self.registry.get(name)
        if hasattr(self.registry, "get_tool"):
            return self.registry.get_tool(name)
        return None

    def run(
        self,
        prompt: str,
        user_identity: Any = None,
        context: list[dict[str, Any]] | None = None,
        system_prompt: str | None = None,
    ) -> str:
        """Bucle de ejecución ReAct/Agent con visibilidad en consola."""
        history = list(context) if context else []
        active_system_prompt = system_prompt or self.system_prompt
        if active_system_prompt and not any(m.get("role") == "system" for m in history):
            history.insert(0, {"role": "system", "content": active_system_prompt})

        history.append({"role": "user", "content": prompt})

        tool_specs = self._get_tool_specifications()

        for step in range(self.max_iterations):
            response = self.engine.generate(
                messages=history,
                tools=tool_specs if tool_specs else None,
                model=self.default_model,
            )

            tool_calls = response.tool_calls or []
            content = response.content or ""

            assistant_msg: dict[str, Any] = {"role": "assistant"}
            if content:
                assistant_msg["content"] = content

            if tool_calls:
                formatted_calls = []
                for call in tool_calls:
                    formatted_calls.append({
                        "id": call.get("id", "call_default"),
                        "type": "function",
                        "function": {
                            "name": call.get("name"),
                            "arguments": json.dumps(call.get("parameters", {})),
                        },
                    })
                assistant_msg["tool_calls"] = formatted_calls

                if "content" not in assistant_msg:
                    assistant_msg["content"] = None

            history.append(assistant_msg)

            if not tool_calls:
                return content or "No se obtuvo respuesta del modelo."

            # JARVIS NOS AVISA DE LO QUE HACE
            _safe_print(f"\n  [Iteración {step + 1}] JARVIS ha decidido usar herramientas:")

            for call in tool_calls:
                tool_name = call.get("name")
                parameters = call.get("parameters", call.get("arguments", {}))
                call_id = call.get("id", "call_default")

                if not isinstance(tool_name, str):
                    continue

                tool = self._get_tool(tool_name)
                if not tool:
                    error_msg = f"Error: La herramienta '{tool_name}' no existe en el registro."
                    _safe_print(f"  ❌ {error_msg}")
                    history.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": error_msg,
                    })
                    continue

                if self.security:
                    required_level = cast(
                        SecurityLevel, getattr(tool, "required_level", SecurityLevel(1))
                    )
                    authorized = self.security.authorize(
                        tool_name=tool_name,
                        required_level=required_level,
                        user_identity=user_identity,
                    )
                    if not authorized:
                        denied_msg = f"Autorización denegada para ejecutar '{tool_name}'."
                        _safe_print(f"  ⛔ {denied_msg}")
                        history.append({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": tool_name,
                            "content": denied_msg,
                        })
                        continue

                try:
                    # MUESTRA LA HERRAMIENTA Y PARÁMETROS
                    _safe_print(f"  ⚡ Ejecutando: {tool_name} | Parámetros: {parameters}")

                    result = self.executor.execute(
                        user=user_identity,
                        tool_name=tool_name,
                        arguments=parameters,
                    )

                    result_text = str(result)
                    # MUESTRA EL RESULTADO INVISIBLE QUE LEE LA IA
                    _safe_print(f"  📥 Resultado interno: {result_text[:150]}...\n")

                    history.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": result_text,
                    })
                except Exception as exc:
                    _safe_print(f"  ❌ Error de ejecución en {tool_name}: {exc}")
                    history.append({
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": tool_name,
                        "content": f"Error de ejecución: {exc}",
                    })

        return history[-1].get("content", "Se alcanzó el límite de iteraciones.")