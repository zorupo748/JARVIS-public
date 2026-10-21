"""Tracking Tool for JARVIS: exposes `seguimiento_paquete_1688track` via ToolRegistry."""

from __future__ import annotations

import logging
from typing import Any

from jarvis.security.levels import SecurityLevel
from jarvis.skills.seguimiento_paquete_1688track import (
    SeguimientoPaquete1688Track,
    TrackingError,
)
from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


@ToolRegistry.register("consultar_seguimiento_1688track")
@ToolRegistry.register("tracking_1688track")
@ToolRegistry.register("seguimiento_paquete_1688track")
class TrackingTool(BaseTool):
    """Consulta el estado de un paquete en 1688track con navegador aislado."""

    tool_id = "seguimiento_paquete_1688track"
    name = "seguimiento_paquete_1688track"
    description = (
        "Consulta el estado de seguimiento de un paquete en 1688track y detalla "
        "los cambios desde la consulta anterior."
    )
    required_level = SecurityLevel.LEVEL_1

    def __init__(self, skill: SeguimientoPaquete1688Track | None = None) -> None:
        self._skill = skill

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="seguimiento_paquete_1688track",
            description=(
                "Rastrea un paquete en 1688track.com (solo lectura web). Úsala cuando el usuario "
                "pregunte dónde está su paquete o el estado de un envío. Si no hay código, "
                "se usa el predeterminado."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "tracking_code": {
                        "type": "string",
                        "description": "Código de seguimiento (8-40 letras, números o guiones). Opcional.",
                    }
                },
                "required": [],
            },
            category="search",
        )

    def execute(self, **params: Any) -> ToolResult:
        code = params.get("tracking_code") or params.get("codigo")
        skill = self._skill or SeguimientoPaquete1688Track()
        try:
            result = skill.consultar(code)
        except TrackingError as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"No pude consultar el seguimiento: {exc}",
                success=False,
            )
        except Exception:
            logger.exception("Unexpected tracking tool failure")
            return ToolResult(
                tool_name=self.tool_id,
                content="No pude consultar el seguimiento por un error inesperado.",
                success=False,
            )
        return ToolResult(
            tool_name=self.tool_id,
            content=skill.formatear(result),
            success=True,
            metadata={"tracking_code": result["codigo"], "source": "1688track"},
        )


__all__ = ["TrackingTool"]
