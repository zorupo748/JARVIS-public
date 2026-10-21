"""File read tool — read content from files with path validation and limits."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from jarvis.security.levels import SecurityLevel
from jarvis.tools.base import BaseTool, ToolParameter, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

# Maximum file size to read directly (10 MB)
_MAX_SIZE_BYTES = 10_485_760
_DEFAULT_MAX_CHARS = 10_000

# Archivos y patrones sensibles a bloquear por seguridad tanto en lectura como en escritura
_SENSITIVE_NAMES = {
    ".env",
    "credentials.json",
    "token.json",
    "secrets.json",
    "trusted_devices.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
}

_SENSITIVE_EXTENSIONS = {
    ".pem",
    ".key",
    ".pfx",
    ".p12",
    ".pkcs12",
    ".kdbx",
}

_SENSITIVE_DIRS = {
    ".git",
    ".venv",
    ".ssh",
    ".aws",
    ".azure",
}


def _is_sensitive_path(path: Path) -> bool:
    """Verificación rigurosa para evitar acceso a secretos, credenciales o claves."""
    # Comprobar componentes del path
    for part in path.parts:
        part_lower = part.lower().strip()
        if part_lower in _SENSITIVE_DIRS:
            return True
        if part_lower in _SENSITIVE_NAMES:
            return True
        if part_lower.startswith(".env"):
            return True
        if part_lower.startswith("id_") and ("rsa" in part_lower or "ed25519" in part_lower or "dsa" in part_lower or "key" in part_lower):
            return True
        if any(part_lower.endswith(ext) for ext in _SENSITIVE_EXTENSIONS):
            return True

    name_lower = path.name.lower().strip()
    if name_lower in _SENSITIVE_NAMES:
        return True
    if name_lower.startswith(".env"):
        return True
    if any(name_lower.endswith(ext) for ext in _SENSITIVE_EXTENSIONS):
        return True

    return False


@ToolRegistry.register("file_read")
class FileReadTool(BaseTool):
    """Lee el contenido de archivos de texto con límites estrictos de sandbox."""

    tool_id = "file_read"
    name = "file_read"
    description = "Lee el contenido de un archivo de texto dentro del sandbox permitido del workspace."
    required_level = SecurityLevel.LEVEL_1

    def __init__(self, allowed_dirs: Optional[List[str | Path]] = None) -> None:
        if allowed_dirs is not None:
            self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs]
        else:
            # Workspace predeterminado a partir de la raíz del proyecto JARVIS
            project_root = Path(__file__).resolve().parents[3]
            self._allowed_dirs = [
                (project_root / "workspace").resolve(),
                (project_root / "data").resolve(),
            ]

    @property
    def parameters(self) -> list[ToolParameter]:
        return [
            ToolParameter(
                name="path",
                description="Ruta relativa al workspace o absoluta autorizada del archivo a leer.",
                required=True,
                parameter_type="string",
            ),
            ToolParameter(
                name="max_chars",
                description="Número máximo de caracteres a devolver (por defecto 10000).",
                required=False,
                parameter_type="integer",
            ),
        ]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Ruta del archivo dentro del workspace a leer.",
                    },
                    "max_chars": {
                        "type": "integer",
                        "description": "Número máximo de caracteres a devolver (por defecto 10000).",
                    },
                },
                "required": ["path"],
            },
            category="filesystem",
            required_capabilities=["file:read"],
        )

    def _resolve_safe_path(self, file_path: str) -> tuple[Optional[Path], Optional[str]]:
        """Valida que la ruta no contenga secuencias maliciosas y resida dentro del sandbox."""
        if "\0" in file_path:
            return None, "Ruta no válida: contiene caracteres nulos."

        path_obj = Path(file_path.strip().strip('"\''))

        # Verificación directa contra patrones sensibles en la ruta solicitada
        if _is_sensitive_path(path_obj):
            return None, "Acceso denegado: el archivo o directorio solicitado es sensible o confidencial."

        # Resolución dentro del sandbox
        if path_obj.is_absolute():
            resolved = path_obj.resolve()
        else:
            if not self._allowed_dirs:
                return None, "No hay directorios autorizados configurados para el sandbox."
            primary_dir = self._allowed_dirs[0]
            resolved = (primary_dir / path_obj).resolve()

        # Comprobar si la ruta resuelta está contenida en alguno de los directorios permitidos
        inside_allowed = any(
            resolved == d or resolved.is_relative_to(d)
            for d in self._allowed_dirs
        )
        if not inside_allowed:
            return None, "Acceso denegado: la ruta solicitada se encuentra fuera del sandbox permitido."

        # Verificación contra enlaces simbólicos que apunten fuera del sandbox
        try:
            real_target = resolved.resolve(strict=False)
            if not any(real_target == d or real_target.is_relative_to(d) for d in self._allowed_dirs):
                return None, "Acceso denegado: el enlace simbólico apunta fuera del sandbox autorizado."
        except OSError:
            pass

        # Re-verificar la ruta canónica final contra secretos
        if _is_sensitive_path(resolved):
            return None, "Acceso denegado: la ruta efectiva apunta a un archivo sensible o protegido."

        return resolved, None

    def execute(self, **params: Any) -> ToolResult:
        file_path = params.get("path", "")
        if not file_path or not str(file_path).strip():
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ninguna ruta de archivo.",
                success=False,
            )

        resolved_path, error_msg = self._resolve_safe_path(str(file_path))
        if error_msg or resolved_path is None:
            return ToolResult(
                tool_name=self.tool_id,
                content=error_msg or "Error de validación de ruta.",
                success=False,
                metadata={"blocked": True},
            )

        if not resolved_path.exists():
            return ToolResult(
                tool_name=self.tool_id,
                content=f"El archivo no existe: {file_path}",
                success=False,
            )

        if not resolved_path.is_file():
            return ToolResult(
                tool_name=self.tool_id,
                content=f"La ruta especificada no es un archivo regular: {file_path}",
                success=False,
            )

        try:
            file_size = resolved_path.stat().st_size
            if file_size > _MAX_SIZE_BYTES:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"Archivo demasiado grande para leer (>10MB, {file_size} bytes).",
                    success=False,
                )
        except OSError as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error al verificar el tamaño del archivo: {exc}",
                success=False,
            )

        max_chars = params.get("max_chars", _DEFAULT_MAX_CHARS)
        if not isinstance(max_chars, int) or max_chars <= 0:
            max_chars = _DEFAULT_MAX_CHARS

        try:
            with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(max_chars + 1)

            truncated = False
            if len(content) > max_chars:
                content = content[:max_chars] + "\n\n[Contenido truncado]"
                truncated = True

            return ToolResult(
                tool_name=self.tool_id,
                content=content,
                success=True,
                metadata={"path": str(resolved_path), "truncated": truncated, "size_bytes": file_size},
            )
        except PermissionError:
            return ToolResult(
                tool_name=self.tool_id,
                content="Permiso denegado por el sistema operativo al leer el archivo.",
                success=False,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error inesperado al leer el archivo: {type(exc).__name__}",
                success=False,
            )


__all__ = ["FileReadTool"]