"""Schedule automation tool — allows JARVIS to dynamically schedule recurring or timed tasks."""

from __future__ import annotations

from typing import Any, Optional
from jarvis.tools.base import BaseTool, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

_global_scheduler: Optional[Any] = None


def get_global_scheduler():
    global _global_scheduler
    if _global_scheduler is None:
        from jarvis.scheduler.task_scheduler import TaskScheduler
        _global_scheduler = TaskScheduler()
        _global_scheduler.start()
    return _global_scheduler


@ToolRegistry.register("schedule_task")
class ScheduleTaskTool(BaseTool):
    """Herramienta para programar la ejecución recurrente o diaria de cualquier otra herramienta."""

    tool_id = "schedule_task"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="schedule_task",
            description=(
                "Programa una tarea o herramienta para que se ejecute automáticamente "
                "a intervalos regulares (minutos/horas) o diariamente a una hora específica."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "Identificador único de la tarea programada.",
                    },
                    "target_tool": {
                        "type": "string",
                        "description": "Nombre de la herramienta a ejecutar (ej. 'web_search', 'blender_exec').",
                    },
                    "tool_params": {
                        "type": "object",
                        "description": "Parámetros que se pasarán a la herramienta objetivo.",
                    },
                    "schedule_type": {
                        "type": "string",
                        "enum": ["interval", "daily"],
                        "description": "Tipo de programación: 'interval' (cada X tiempo) o 'daily' (diario a hora fija).",
                    },
                    "interval_minutes": {
                        "type": "integer",
                        "description": "Si schedule_type es 'interval', cada cuántos minutos se ejecuta.",
                    },
                    "daily_hour": {
                        "type": "integer",
                        "description": "Si schedule_type es 'daily', hora del día (0-23).",
                    },
                    "daily_minute": {
                        "type": "integer",
                        "description": "Si schedule_type es 'daily', minuto del día (0-59).",
                    },
                },
                "required": ["job_id", "target_tool", "schedule_type"],
            },
            category="automation",
        )

    def execute(self, **params: Any) -> ToolResult:
        job_id = params.get("job_id", "")
        target_tool = params.get("target_tool", "")
        tool_params = params.get("tool_params", {})
        schedule_type = params.get("schedule_type", "interval")

        scheduler = get_global_scheduler()

        try:
            if schedule_type == "interval":
                minutes = params.get("interval_minutes", 60)
                scheduler.add_tool_job_interval(
                    job_id=job_id,
                    tool_name=target_tool,
                    tool_params=tool_params,
                    minutes=minutes,
                )
                msg = f"Tarea '{job_id}' programada con éxito cada {minutes} minutos."
            elif schedule_type == "daily":
                hour = params.get("daily_hour", 8)
                minute = params.get("daily_minute", 0)
                scheduler.add_tool_job_daily(
                    job_id=job_id,
                    tool_name=target_tool,
                    tool_params=tool_params,
                    hour=hour,
                    minute=minute,
                )
                msg = f"Tarea '{job_id}' programada diariamente a las {hour:02d}:{minute:02d}."
            else:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Tipo de programación desconocido: {schedule_type}",
                    success=False,
                )

            return ToolResult(
                tool_name=self.tool_id,
                content=msg,
                success=True,
                metadata={"job_id": job_id, "jobs": scheduler.list_jobs()},
            )
        except Exception as e:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error al programar la tarea: {e}",
                success=False,
            )


__all__ = ["ScheduleTaskTool", "get_global_scheduler"]