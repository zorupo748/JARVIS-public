"""System command execution tool — allows JARVIS to execute shell commands."""

from __future__ import annotations

import os
import subprocess
from typing import Any, Optional

from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry


@ToolRegistry.register("cmd_exec")
class CmdTool(BaseTool):
    """Ejecuta comandos en la consola / terminal del sistema operativo."""

    tool_id = "cmd_exec"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="cmd_exec",
            description=(
                "Ejecuta comandos del sistema operativo (PowerShell, CMD, Bash). "
                "Permite gestionar archivos, instalar paquetes de Python, consultar procesos y más."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "El comando de consola que se desea ejecutar.",
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Directorio de trabajo donde ejecutar el comando (opcional).",
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Tiempo límite de ejecución en segundos (por defecto 60).",
                    },
                },
                "required": ["command"],
            },
            category="system",
        )

    def execute(self, **params: Any) -> ToolResult:
        command = params.get("command", "")
        if not command:
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ningún comando para ejecutar.",
                success=False,
            )

        cwd = params.get("cwd")
        timeout = params.get("timeout_seconds", 60)

        if cwd and not os.path.exists(cwd):
            return ToolResult(
                tool_name=self.tool_id,
                content=f"El directorio especificado no existe: {cwd}",
                success=False,
            )

        try:
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=timeout,
            )

            stdout = process.stdout.strip() if process.stdout else ""
            stderr = process.stderr.strip() if process.stderr else ""

            output = []
            if stdout:
                output.append(f"--- STDOUT ---\n{stdout}")
            if stderr:
                output.append(f"--- STDERR ---\n{stderr}")

            content = "\n\n".join(output) if output else "Comando ejecutado sin salida."

            return ToolResult(
                tool_name=self.tool_id,
                content=content[:4000],
                success=(process.returncode == 0),
                metadata={"returncode": process.returncode},
            )

        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"La ejecución del comando superó el tiempo límite ({timeout}s).",
                success=False,
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error al ejecutar el comando: {e}",
                success=False,
            )


__all__ = ["CmdTool"]