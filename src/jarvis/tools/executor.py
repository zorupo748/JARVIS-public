from __future__ import annotations

from typing import Any, Optional

from jarvis.identity.models import UserIdentity
from .registry import ToolRegistry


class ToolExecutionResult:
    """Resultado de la ejecución de una herramienta."""

    def __init__(
        self,
        success: bool,
        message: str,
        result: Any = None,
    ) -> None:
        self.success = success
        self.message = message
        self.result = result

    def __repr__(self) -> str:
        return (
            f"ToolExecutionResult("
            f"success={self.success!r}, "
            f"message={self.message!r}, "
            f"result={self.result!r})"
        )

    def __str__(self) -> str:
        """Permite que JarvisAgent obtenga el texto directamente con str(result)."""
        return self.message


class ToolExecutor:
    """
    Ejecuta herramientas registradas en ToolRegistry.

    Este componente es el punto de entrada utilizado por la IA cuando quiere
    utilizar una herramienta. La IA nunca debe importar ni ejecutar directamente
    los ejecutores reales del sistema.
    """

    def execute(
        self,
        user: Optional[UserIdentity],
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> ToolExecutionResult:

        # ---------------------------------------------------------
        # 1. Validar nombre de herramienta
        # ---------------------------------------------------------
        tool_class_or_obj = ToolRegistry.get(tool_name)

        if tool_class_or_obj is None:
            return ToolExecutionResult(
                success=False,
                message=f"La herramienta '{tool_name}' no está registrada.",
            )

        # ---------------------------------------------------------
        # 2. Crear instancia (Soporta ToolRegistry.create o instanciación directa)
        # ---------------------------------------------------------
        try:
            if hasattr(ToolRegistry, "create") and callable(getattr(ToolRegistry, "create")):
                tool = ToolRegistry.create(tool_name)
            elif isinstance(tool_class_or_obj, type):
                tool = tool_class_or_obj()
            else:
                tool = tool_class_or_obj
        except Exception as exc:
            return ToolExecutionResult(
                success=False,
                message=f"No se pudo crear la herramienta '{tool_name}': {exc}",
            )

        # ---------------------------------------------------------
        # 3. Preparar argumentos
        # ---------------------------------------------------------
        if arguments is None:
            arguments = {}

        arguments = dict(arguments)

        # La identidad nunca debe venir controlada por la IA.
        arguments["user"] = user

        # ---------------------------------------------------------
        # 4. Ejecutar herramienta
        # ---------------------------------------------------------
        try:
            result = tool.execute(**arguments)
        except TypeError as exc:
            # Fallback si la herramienta no acepta el parámetro 'user' explícito o extra
            if "user" in arguments and "unexpected keyword argument 'user'" in str(exc):
                arguments.pop("user", None)
                try:
                    result = tool.execute(**arguments)
                except Exception as inner_exc:
                    return ToolExecutionResult(
                        success=False,
                        message=f"Error ejecutando la herramienta '{tool_name}': {inner_exc}",
                    )
            else:
                return ToolExecutionResult(
                    success=False,
                    message=f"Argumentos inválidos para la herramienta '{tool_name}': {exc}",
                )
        except Exception as exc:
            return ToolExecutionResult(
                success=False,
                message=f"Error ejecutando la herramienta '{tool_name}': {exc}",
            )

        # ---------------------------------------------------------
        # 5. Normalizar resultado (Soporta .message y .content)
        # ---------------------------------------------------------
        success = bool(getattr(result, "success", True))

        message = getattr(
            result,
            "message",
            getattr(result, "content", str(result)),
        )

        return ToolExecutionResult(
            success=success,
            message=str(message),
            result=result,
        )


__all__ = ["ToolExecutor", "ToolExecutionResult"]