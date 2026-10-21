"""JARVIS Task Scheduler — background execution of periodic and scheduled tools."""

from __future__ import annotations

import logging
from typing import Any, Dict, Protocol
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger("jarvis.scheduler")

class ProtectedSkillDispatcher(Protocol):
    """Minimal callback contract used by scheduled skill jobs."""

    def dispatch(
        self,
        skill_name: str,
        parameters: Dict[str, Any] | None = None,
        *,
        scheduled: bool = False,
    ) -> Any: ...


class TaskScheduler:
    """Maneja la programación y ejecución de tareas periódicas o a horas fijas."""

    def __init__(self) -> None:
        self._scheduler = BackgroundScheduler()
        self._is_running = False

    def start(self) -> None:
        """Inicia el motor del programador en segundo plano."""
        if not self._is_running:
            self._scheduler.start()
            self._is_running = True
            logger.info("Programador de tareas iniciado correctamente.")

    def stop(self) -> None:
        """Detiene el programador de tareas."""
        if self._is_running:
            self._scheduler.shutdown()
            self._is_running = False
            logger.info("Programador de tareas detenido.")

    def add_tool_job_interval(
        self,
        job_id: str,
        tool_name: str,
        tool_params: Dict[str, Any],
        minutes: int = 0,
        hours: int = 0,
        seconds: int = 0,
    ) -> None:
        """Programa la ejecución periódica de una herramienta cada X horas/minutos/segundos."""
        raise PermissionError(
            "Las tareas programadas de tools estan desactivadas hasta que usen un dispatcher protegido."
        )

        from jarvis.tools.registry import ToolRegistry

        tool_cls_or_obj = ToolRegistry.get(tool_name)
        if not tool_cls_or_obj:
            raise ValueError(f"La herramienta '{tool_name}' no está registrada.")

        def _execute_job():
            print(f"\n[SCHEDULER '{job_id}'] Ejecutando {tool_name}...")
            tool_instance = (
                tool_cls_or_obj()
                if isinstance(tool_cls_or_obj, type)
                else tool_cls_or_obj
            )
            result = tool_instance.execute(**tool_params)
            print(f"[RESULTADO '{job_id}']: {result.content[:150]}...\n")

        self._scheduler.add_job(
            _execute_job,
            trigger=IntervalTrigger(hours=hours, minutes=minutes, seconds=seconds),
            id=job_id,
            replace_existing=True,
        )
        print(f"[SCHEDULER] Tarea '{job_id}' programada cada {hours}h {minutes}m {seconds}s.")

    def add_tool_job_daily(
        self,
        job_id: str,
        tool_name: str,
        tool_params: Dict[str, Any],
        hour: int,
        minute: int = 0,
    ) -> None:
        """Programa la ejecución diaria de una herramienta a una hora exacta (ej. 08:30)."""
        raise PermissionError(
            "Las tareas programadas de tools estan desactivadas hasta que usen un dispatcher protegido."
        )

        from jarvis.tools.registry import ToolRegistry

        tool_cls_or_obj = ToolRegistry.get(tool_name)
        if not tool_cls_or_obj:
            raise ValueError(f"La herramienta '{tool_name}' no está registrada.")

        def _execute_job():
            print(f"\n[SCHEDULER DIARIO '{job_id}'] Ejecutando {tool_name}...")
            tool_instance = (
                tool_cls_or_obj()
                if isinstance(tool_cls_or_obj, type)
                else tool_cls_or_obj
            )
            result = tool_instance.execute(**tool_params)
            print(f"[RESULTADO '{job_id}']: {result.content[:150]}...\n")

        self._scheduler.add_job(
            _execute_job,
            trigger=CronTrigger(hour=hour, minute=minute),
            id=job_id,
            replace_existing=True,
        )
        print(f"[SCHEDULER] Tarea '{job_id}' programada todos los días a las {hour:02d}:{minute:02d}.")

    def add_skill_job_daily(
        self,
        job_id: str,
        skill_name: str,
        skill_dispatcher: ProtectedSkillDispatcher,
        hour: int,
        minute: int = 0,
    ) -> None:
        """Programa una skill dinámica para ejecutarse diariamente a una hora fija."""
        if not 0 <= hour <= 23 or not 0 <= minute <= 59:
            raise ValueError("La hora debe estar entre 00:00 y 23:59.")

        def _execute_job():
            print(f"\n[SKILL PROGRAMADA '{job_id}'] Ejecutando {skill_name}...")
            try:
                result = skill_dispatcher.dispatch(skill_name, scheduled=True)
                print(f"[RESULTADO '{job_id}']: {result}\n")
            except Exception as exc:
                logger.exception("Falló la skill programada '%s'", skill_name)
                print(f"[ERROR '{job_id}']: {exc}\n")

        self._scheduler.add_job(
            _execute_job,
            trigger=CronTrigger(hour=hour, minute=minute),
            id=job_id,
            replace_existing=True,
        )
        print(f"[SCHEDULER] Skill '{skill_name}' programada todos los días a las {hour:02d}:{minute:02d}.")

    def list_jobs(self) -> list:
        """Devuelve la lista de tareas actualmente programadas."""
        return [
            {"id": job.id, "next_run": str(job.next_run_time)}
            for job in self._scheduler.get_jobs()
        ]