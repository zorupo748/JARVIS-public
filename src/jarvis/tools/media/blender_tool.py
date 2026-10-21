"""Blender automation tool — execute Python scripts (bpy) in headless mode."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry


@ToolRegistry.register("blender_exec")
class BlenderTool(BaseTool):
    """Ejecuta código Python dentro de Blender en modo desatendido (headless)."""

    tool_id = "blender_exec"

    def __init__(self, blender_path: Optional[str] = None) -> None:
        # Busca el ejecutable en el PATH o en la ruta por defecto de Windows
        default_path = os.environ.get("BLENDER_PATH", "blender")
        self._blender_path = blender_path or default_path

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="blender_exec",
            description=(
                "Ejecuta un script Python usando la API 'bpy' de Blender en segundo plano "
                "para generar, modificar o renderizar escenas y modelos 3D."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Código Python (usando la librería 'bpy') a ejecutar en Blender.",
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "description": "Tiempo límite de ejecución en segundos (por defecto 60).",
                    },
                },
                "required": ["code"],
            },
            category="3d_media",
        )

    def execute(self, **params: Any) -> ToolResult:
        code = params.get("code", "")
        if not code:
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ningún código Python para ejecutar.",
                success=False,
            )

        timeout = params.get("timeout_seconds", 60)

        # Crear un archivo temporal con el script Python
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp_file:
            tmp_file.write(code)
            tmp_script = tmp_file.name

        try:
            # Comando: blender --background --python script.py
            cmd = [self._blender_path, "--background", "--python", tmp_script]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            stdout = process.stdout
            stderr = process.stderr

            if process.returncode == 0:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Ejecución en Blender completada exitosamente:\n\n{stdout[-1000:]}",
                    success=True,
                    metadata={"returncode": 0},
                )
            else:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error en Blender (código {process.returncode}):\n{stderr or stdout}",
                    success=False,
                )

        except FileNotFoundError:
            return ToolResult(
                tool_name=self.tool_id,
                content=(
                    "No se encontró el ejecutable de Blender. Asegúrate de que está instalado "
                    "y añadido al PATH del sistema o configura la variable 'BLENDER_PATH'."
                ),
                success=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"La ejecución en Blender superó el tiempo límite ({timeout}s).",
                success=False,
            )
        finally:
            if os.path.exists(tmp_script):
                os.remove(tmp_script)


__all__ = ["BlenderTool"]