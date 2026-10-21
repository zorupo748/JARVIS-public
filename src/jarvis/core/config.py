import os
from dataclasses import dataclass


DYNAMIC_SKILLS_DISABLED_MESSAGE = (
    "Las skills dinámicas están desactivadas por configuración. "
    "Quita JARVIS_ENABLE_DYNAMIC_SKILLS=false o configúrala como true para habilitarlas."
)

DYNAMIC_SKILL_EXTERNAL_LOAD_DISABLED_MESSAGE = (
    "La carga directa de skills desde archivos externos está bloqueada. "
    "La ejecución explícita de skills históricas debe pasar por dynamic_runtime."
)

DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE = (
    "La generación, prueba con exec, instalación de dependencias, reparación y "
    "sobrescritura de skills dinámicas están bloqueadas de forma incondicional."
)


def get_gemini_api_key() -> str | None:
    """Return the optional Gemini credential without loading .env files."""
    value = os.getenv("GEMINI_API_KEY", "").strip()
    return value or None


def dynamic_skills_enabled() -> bool:
    """Enable verified dynamic skills by default; explicit false disables them."""
    value = os.getenv("JARVIS_ENABLE_DYNAMIC_SKILLS", "").strip().lower()
    return value not in {"0", "false", "no", "off"}


def dynamic_skill_authoring_enabled() -> bool:
    """Keep legacy generated-skill authoring disabled independently of runtime."""
    return False

from pathlib import Path

from dotenv import dotenv_values


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def get_local_device_credentials() -> tuple[str | None, str | None]:
    """
    Return this installation's local device ID and secret.

    Environment variables take precedence over the project-local .env.
    Reading .env here does not inject all of its contents into os.environ.
    """
    env_file = dotenv_values(PROJECT_ROOT / ".env")

    device_id = (
        os.getenv("JARVIS_LOCAL_DEVICE_ID", "").strip()
        or str(env_file.get("JARVIS_LOCAL_DEVICE_ID") or "").strip()
    )

    token = (
        os.getenv("JARVIS_LOCAL_DEVICE_TOKEN", "").strip()
        or str(env_file.get("JARVIS_LOCAL_DEVICE_TOKEN") or "").strip()
    )

    return device_id or None, token or None

@dataclass
class JarvisConfig:
    name: str = "JARVIS"
    debug: bool = True
