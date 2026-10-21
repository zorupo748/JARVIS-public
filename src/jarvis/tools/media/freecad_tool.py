"""FreeCAD automation tool — execute Python CAD scripts in headless mode."""

from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any, Optional

from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry


@ToolRegistry.register("freecad_exec")
class FreeCADTool(BaseTool):
    """Ejecuta código Python dentro de FreeCAD en modo desatendido (headless)."""

    tool_id = "freecad_exec"

    def __init__(self, freecad_path: Optional[str] = None) -> None:
        default_path = os.environ.get("FREECAD_PATH", "freecadcmd")
        self._freecad_path = freecad_path or default_path

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="freecad_exec",
            description=(
                "Ejecuta un script Python usando la API de FreeCAD en segundo plano "
                "para diseñar piezas paramétricas, exportar a STEP/STL o hacer análisis de ingeniería."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Código Python con la API de FreeCAD a ejecutar.",
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

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as tmp_file:
            tmp_file.write(code)
            tmp_script = tmp_file.name

        try:
            cmd = [self._freecad_path, tmp_script]

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
                    content=f"Ejecución en FreeCAD completada exitosamente:\n\n{stdout[-1000:]}",
                    success=True,
                    metadata={"returncode": 0},
                )
            else:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error en FreeCAD (código {process.returncode}):\n{stderr or stdout}",
                    success=False,
                )

        except FileNotFoundError:
            return ToolResult(
                tool_name=self.tool_id,
                content=(
                    "No se encontró el ejecutable 'freecadcmd'. Asegúrate de que FreeCAD está instalado "
                    "y su ejecutable o alias está en el PATH del sistema o define 'FREECAD_PATH'."
                ),
                success=False,
            )
        except subprocess.TimeoutExpired:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"La ejecución en FreeCAD superó el tiempo límite ({timeout}s).",
                success=False,
            )
        finally:
            if os.path.exists(tmp_script):
                os.remove(tmp_script)


__all__ = ["FreeCADTool"]