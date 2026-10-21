"""Shell execution tool — run shell commands with security constraints."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from jarvis.tools.base import BaseTool, ToolResult, ToolSpec

# Maximum output size per stream (100 KB)
_MAX_OUTPUT_BYTES = 102_400

# Maximum allowed timeout (seconds)
_MAX_TIMEOUT = 300

# Default timeout (seconds)
_DEFAULT_TIMEOUT = 30

# Environment variables always passed through
_BASE_ENV_KEYS = ("PATH", "HOME", "USER", "LANG", "TERM", "SYSTEMROOT", "COMSPEC")


class ShellExecTool(BaseTool):
    """Ejecuta comandos del sistema con un entorno sanitizado."""

    tool_id = "shell_exec"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="shell_exec",
            description=(
                "Ejecuta un comando en la consola del sistema y devuelve stdout/stderr. "
                "Corre en un entorno aislado con limites de tiempo y memoria."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Comando de consola a ejecutar.",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Tiempo limite en segundos (default 30, max 300).",
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Directorio de trabajo para el comando.",
                    },
                    "env_passthrough": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Variables de entorno adicionales a heredar.",
                    },
                },
                "required": ["command"],
            },
            category="system",
            requires_confirmation=True,
            timeout_seconds=60.0,
            required_capabilities=["code:execute"],
        )

    def execute(self, **params: Any) -> ToolResult:
        command = params.get("command", "")
        if not command:
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporciono ningun comando.",
                success=False,
            )

        # Ajuste de timeout
        raw_timeout = params.get("timeout", _DEFAULT_TIMEOUT)
        try:
            timeout = int(raw_timeout)
        except (TypeError, ValueError):
            timeout = _DEFAULT_TIMEOUT

        timeout = max(1, min(timeout, _MAX_TIMEOUT))

        # Validacion del directorio de trabajo
        working_dir = params.get("working_dir")
        if working_dir is not None:
            wd_path = Path(working_dir)
            if not wd_path.exists():
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"El directorio de trabajo no existe: {working_dir}",
                    success=False,
                )
            if not wd_path.is_dir():
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"La ruta no es un directorio: {working_dir}",
                    success=False,
                )

        # Construccion del entorno sanitizado
        env: dict[str, str] = {}
        for key in _BASE_ENV_KEYS:
            val = os.environ.get(key)
            if val is not None:
                env[key] = val

        env_passthrough: list[str] = params.get("env_passthrough") or []
        for key in env_passthrough:
            val = os.environ.get(key)
            if val is not None:
                env[key] = val

        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"El comando supero el tiempo limite de {timeout} segundos.",
                success=False,
                metadata={"returncode": -1, "working_dir": working_dir},
            )
        except PermissionError as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Permiso denegado: {exc}",
                success=False,
            )
        except OSError as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error del sistema operativo: {exc}",
                success=False,
            )

        # Truncamiento de buffer
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        if len(stdout) > _MAX_OUTPUT_BYTES:
            stdout = stdout[:_MAX_OUTPUT_BYTES] + "\n... (stdout truncado)"
        if len(stderr) > _MAX_OUTPUT_BYTES:
            stderr = stderr[:_MAX_OUTPUT_BYTES] + "\n... (stderr truncado)"

        sections: list[str] = []
        if stdout:
            sections.append(f"=== STDOUT ===\n{stdout}")
        if stderr:
            sections.append(f"=== STDERR ===\n{stderr}")
        content = "\n".join(sections) if sections else "(sin salida)"

        return ToolResult(
            tool_name=self.tool_id,
            content=content,
            success=result.returncode == 0,
            metadata={
                "returncode": result.returncode,
                "timeout_used": timeout,
                "working_dir": working_dir,
            },
        )


__all__ = ["ShellExecTool"]