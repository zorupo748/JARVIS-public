"""3D Printer tool adapter for Klipper/Moonraker integration."""

from __future__ import annotations

import logging
from typing import Any, Optional

from jarvis.security.levels import SecurityLevel
from jarvis.skills.printer_3d import KlipperPrinterSkill
from jarvis.tools.base import BaseTool, ToolParameter, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


@ToolRegistry.register("printer_status")
class PrinterStatusTool(BaseTool):
    """Herramienta de solo lectura para consultar estado y temperaturas de la impresora 3D."""

    tool_id = "printer_status"
    name = "printer_status"
    description = (
        "Consulta de solo lectura del estado de la impresora 3D (Klipper/Moonraker). "
        "Permite obtener estado de conexión, avance y temperaturas de extrusor y cama caliente."
    )
    required_level = SecurityLevel.LEVEL_1

    def __init__(self, printer_skill: Optional[KlipperPrinterSkill] = None) -> None:
        self.printer_skill = printer_skill or KlipperPrinterSkill()

    @property
    def parameters(self) -> list[ToolParameter]:
        return [
            ToolParameter(
                name="query_type",
                description="Tipo de consulta: 'status' (estado completo) o 'temperatures' (solo temperaturas).",
                required=False,
                parameter_type="string",
            )
        ]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "query_type": {
                        "type": "string",
                        "description": "Tipo de consulta de solo lectura: 'status' o 'temperatures'.",
                    },
                },
            },
            category="system",
            required_capabilities=["hardware:printer:read"],
        )

    def execute(self, **params: Any) -> ToolResult:
        query_type = str(params.get("query_type", "status")).strip().lower()

        # Blindaje estricto: denegar cualquier intento de control o parada desde la herramienta de consulta
        if query_type in ("stop", "emergency_stop", "parada", "cancel", "start", "print"):
            return ToolResult(
                tool_name=self.tool_id,
                content="Acceso denegado: 'printer_status' es exclusivamente de solo lectura. No permite comandos de control.",
                success=False,
                metadata={"blocked": True},
            )

        try:
            status_data = self.printer_skill.get_status()
        except Exception as exc:
            logger.warning("Error al comunicar con la impresora 3D: %s", exc)
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error de comunicación con la impresora 3D: {exc}",
                success=False,
                metadata={"online": False, "error": str(exc)},
            )

        if not isinstance(status_data, dict):
            return ToolResult(
                tool_name=self.tool_id,
                content="Respuesta de estado incompleta o inválida recibida de la impresora.",
                success=False,
                metadata={"online": False},
            )

        online = bool(status_data.get("online", False))
        if not online:
            err = status_data.get("error", "Impresora fuera de línea o inalcanzable")
            return ToolResult(
                tool_name=self.tool_id,
                content=f"La impresora 3D no está disponible ({err}).",
                success=False,
                metadata=status_data,
            )

        bed_temp = status_data.get("bed_temp", "N/A")
        ext_temp = status_data.get("extruder_temp", "N/A")
        state = status_data.get("state", "desconocido")
        progress = status_data.get("progress", "0%")
        filename = status_data.get("filename", "")

        if query_type == "temperatures":
            content = f"Temperaturas actuales: Extrusor {ext_temp}°C, Cama caliente {bed_temp}°C."
        else:
            file_info = f", Archivo: '{filename}' ({progress})" if filename else ""
            content = (
                f"Estado de la impresora: {state}. "
                f"Temperatura Extrusor: {ext_temp}°C, Cama: {bed_temp}°C{file_info}."
            )

        return ToolResult(
            tool_name=self.tool_id,
            content=content,
            success=True,
            metadata=status_data,
        )


@ToolRegistry.register("printer_tool")
class PrinterTool(BaseTool):
    """Adaptador de herramientas de sistema para interacción con la impresora 3D."""

    tool_id = "printer_tool"
    name = "printer_tool"
    description = (
        "Herramienta integral para consultar estado, temperaturas o emitir parada de emergencia en Klipper/Moonraker."
    )
    required_level = SecurityLevel.LEVEL_1

    def __init__(self, printer_skill: Optional[KlipperPrinterSkill] = None) -> None:
        self.printer_skill = printer_skill or KlipperPrinterSkill()

    @property
    def parameters(self) -> list[ToolParameter]:
        return [
            ToolParameter(
                name="action",
                description="Acción a realizar: 'status', 'temperatures', 'list_files', o 'emergency_stop'.",
                required=False,
                parameter_type="string",
            )
        ]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Acción a ejecutar: 'status', 'temperatures', 'list_files' o 'emergency_stop'.",
                    },
                },
            },
            category="system",
            required_capabilities=["hardware:printer"],
        )

    def execute(self, **params: Any) -> ToolResult:
        action = str(params.get("action", "status")).strip().lower()

        # 1. Operación de lectura: Estado general
        if action in ("status", "get_status"):
            try:
                status = self.printer_skill.get_status()
            except Exception as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error al consultar el estado de la impresora: {exc}",
                    success=False,
                )

            if not status.get("online"):
                err = status.get("error", "Sin conexión")
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"La impresora 3D está desconectada o no responde ({err}).",
                    success=False,
                    metadata=status,
                )

            filename_txt = f", Archivo: '{status.get('filename')}'" if status.get("filename") else ""
            res_text = (
                f"Estado: {status.get('state', 'desconocido')}. "
                f"Extrusor: {status.get('extruder_temp')}°C, Cama: {status.get('bed_temp')}°C. "
                f"Progreso: {status.get('progress', '0%')}{filename_txt}."
            )
            return ToolResult(
                tool_name=self.tool_id,
                content=res_text,
                success=True,
                metadata=status,
            )

        # 2. Operación de lectura: Solo temperaturas
        if action in ("temperatures", "get_temperatures", "temps"):
            try:
                status = self.printer_skill.get_status()
            except Exception as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error al consultar temperaturas: {exc}",
                    success=False,
                )

            if not status.get("online"):
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Impresora desconectada ({status.get('error', 'desconocido')}).",
                    success=False,
                    metadata=status,
                )

            return ToolResult(
                tool_name=self.tool_id,
                content=f"Extrusor: {status.get('extruder_temp')}°C | Cama caliente: {status.get('bed_temp')}°C",
                success=True,
                metadata=status,
            )

        # 3. Operación de lectura: Listar archivos
        if action in ("list_files", "listar_archivos"):
            try:
                files = self.printer_skill.list_files()
                if not files:
                    return ToolResult(
                        tool_name=self.tool_id,
                        content="No hay archivos G-Code listos en la impresora.",
                        success=True,
                        metadata={"files": []},
                    )
                return ToolResult(
                    tool_name=self.tool_id,
                    content="Archivos G-Code listos:\n" + "\n".join(f"- {f}" for f in files),
                    success=True,
                    metadata={"files": files},
                )
            except Exception as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Error al listar archivos G-Code: {exc}",
                    success=False,
                )

        # 4. Operación crítica de seguridad: Parada de emergencia M112
        if action in ("emergency_stop", "parada_emergencia", "m112"):
            try:
                msg = self.printer_skill.emergency_stop()
                return ToolResult(
                    tool_name=self.tool_id,
                    content=msg,
                    success=True,
                    metadata={"action": "emergency_stop", "result": msg},
                )
            except Exception as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Fallo al emitir la parada de emergencia: {exc}",
                    success=False,
                )

        return ToolResult(
            tool_name=self.tool_id,
            content=f"Acción '{action}' no admitida. Usa 'status', 'temperatures', 'list_files' o 'emergency_stop'.",
            success=False,
        )


__all__ = ["PrinterTool", "PrinterStatusTool"]
