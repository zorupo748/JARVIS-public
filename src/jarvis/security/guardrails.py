from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class GuardrailResult:
    status: str  # "SAFE", "REQUIRES_EXPLANATION", "CRITICAL_BLOCKED"
    message: str


class GuardrailSystem:
    # Rutas del Sistema Operativo intocables
    CRITICAL_SYSTEM_PATHS = {
        Path("C:/Windows"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
        Path("C:/Users/Default"),
    }

    @classmethod
    def evaluate_target(cls, target_path_str: str | None) -> GuardrailResult:
        if not target_path_str:
            return GuardrailResult("SAFE", "No hay ruta de destino especificada.")

        target = Path(target_path_str).resolve()

        # 1. Bloqueo absoluto de archivos de sistema
        for sys_path in cls.CRITICAL_SYSTEM_PATHS:
            if sys_path in target.parents or target == sys_path:
                return GuardrailResult(
                    status="CRITICAL_BLOCKED",
                    message="La ruta pertenece al núcleo del Sistema Operativo. Operación bloqueada.",
                )

        # 2. Carpetas de usuario sensibles que requieren diálogo
        user_home = Path.home()
        sensitive_user_folders = [
            user_home / "Downloads",
            user_home / "Desktop",
            user_home / "Documents",
        ]

        for folder in sensitive_user_folders:
            if target == folder or folder in target.parents:
                return GuardrailResult(
                    status="REQUIRES_EXPLANATION",
                    message=(
                        f"La ubicación '{target.name}' contiene archivos personales del usuario. "
                        "JARVIS debe confirmar el alcance exacto antes de proceder."
                    ),
                )

        return GuardrailResult("SAFE", "Ruta segura dentro del espacio del usuario.")