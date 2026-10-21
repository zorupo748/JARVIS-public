"""File write tool — write content to files with path validation."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from jarvis.security.levels import SecurityLevel
from jarvis.tools.base import BaseTool, ToolParameter, ToolResult, ToolSpec
from jarvis.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

# Maximum file size to write (10 MB)
_MAX_SIZE_BYTES = 10_485_760

# Archivos y extensiones sensibles a bloquear por seguridad
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
    "src/jarvis",
}


def _is_sensitive_path(path: Path) -> bool:
    """Verificación rigurosa para evitar escritura en archivos sensibles o de sistema."""
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


@ToolRegistry.register("file_write")
class FileWriteTool(BaseTool):
    """Escribe contenido en archivos con opciones de sobrescritura y anexo dentro del sandbox."""

    tool_id = "file_write"
    name = "file_write"
    description = "Escribe contenido en un archivo dentro del sandbox permitido (workspace, data, output). Soporta modos 'write' y 'append'."
    required_level = SecurityLevel.LEVEL_2

    def __init__(self, allowed_dirs: Optional[List[str | Path]] = None) -> None:
        project_root = Path(__file__).resolve().parents[3]
        self._project_root = project_root.resolve()
        self._protected_dirs = [
            (project_root / "src" / "jarvis").resolve(),
            (project_root / ".venv").resolve(),
            (project_root / ".git").resolve(),
        ]

        if allowed_dirs is not None:
            self._allowed_dirs = [Path(d).resolve() for d in allowed_dirs]
        else:
            self._allowed_dirs = [
                (project_root / "workspace").resolve(),
                (project_root / "data").resolve(),
                (project_root / "output").resolve(),
            ]

    @property
    def parameters(self) -> list[ToolParameter]:
        return [
            ToolParameter(
                name="path",
                description="Ruta del archivo dentro del sandbox a escribir.",
                required=True,
                parameter_type="string",
            ),
            ToolParameter(
                name="content",
                description="Contenido textual a escribir.",
                required=True,
                parameter_type="string",
            ),
            ToolParameter(
                name="mode",
                description="Modo de escritura: 'write' (sobrescribir) o 'append' (anexar).",
                required=False,
                parameter_type="string",
            ),
            ToolParameter(
                name="create_dirs",
                description="Crea directorios padres si no existen (por defecto False).",
                required=False,
                parameter_type="boolean",
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
                        "description": "Ruta del archivo a escribir.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Contenido que se escribirá en el archivo.",
                    },
                    "mode": {
                        "type": "string",
                        "description": "Modo de escritura: 'write' (sobrescribir) o 'append' (anexar). Default: 'write'.",
                    },
                    "create_dirs": {
                        "type": "boolean",
                        "description": "Crea directorios padres si no existen. Default: false.",
                    },
                },
                "required": ["path", "content"],
            },
            category="filesystem",
            requires_confirmation=True,
            required_capabilities=["file:write"],
        )

    def _resolve_safe_path(self, file_path: str) -> tuple[Optional[Path], Optional[str]]:
        """Valida que la ruta de destino resida dentro de los directorios permitidos para escritura."""
        if "\0" in file_path:
            return None, "Ruta no válida: contiene caracteres nulos."

        path_obj = Path(file_path.strip().strip('"\''))

        if _is_sensitive_path(path_obj):
            return None, "Acceso denegado: el archivo o directorio solicitado es sensible o protegido."

        if path_obj.is_absolute():
            resolved = path_obj.resolve()
        else:
            if not self._allowed_dirs:
                return None, "No hay directorios autorizados configurados para escritura."
            primary_dir = self._allowed_dirs[0]
            resolved = (primary_dir / path_obj).resolve()

        # Comprobar pertenencia al sandbox
        inside_allowed = any(
            resolved == d or resolved.is_relative_to(d)
            for d in self._allowed_dirs
        )
        if not inside_allowed:
            return None, "Acceso denegado: la ruta solicitada está fuera de los directorios autorizados para escritura."

        # Proteger contra sobrescritura de directorios de sistema del proyecto
        for protected in self._protected_dirs:
            if resolved == protected or resolved.is_relative_to(protected):
                return None, "Acceso denegado: la ruta apunta a un directorio de sistema protegido."

        # Verificación de enlaces simbólicos existentes
        try:
            if resolved.is_symlink():
                target = resolved.resolve(strict=False)
                if not any(target == d or target.is_relative_to(d) for d in self._allowed_dirs):
                    return None, "Acceso denegado: el enlace simbólico destino apunta fuera del sandbox autorizado."
        except OSError:
            pass

        if _is_sensitive_path(resolved):
            return None, "Acceso denegado: la ruta efectiva apunta a un archivo sensible o protegido."

        return resolved, None

    def execute(self, **params: Any) -> ToolResult:
        file_path = params.get("path", "")
        if not file_path or not str(file_path).strip():
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ninguna ruta.",
                success=False,
            )

        content = params.get("content")
        if content is None:
            return ToolResult(
                tool_name=self.tool_id,
                content="No se proporcionó ningún contenido.",
                success=False,
            )

        mode = str(params.get("mode", "write")).strip().lower()
        if mode not in ("write", "append"):
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Modo no válido: {mode!r}. Usa 'write' o 'append'.",
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

        content_str = str(content)
        content_bytes = content_str.encode("utf-8")
        if len(content_bytes) > _MAX_SIZE_BYTES:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Contenido demasiado grande: {len(content_bytes)} bytes (máximo {_MAX_SIZE_BYTES} bytes).",
                success=False,
            )

        create_dirs = bool(params.get("create_dirs", False))
        if create_dirs:
            try:
                # Asegurar que el padre resida dentro del sandbox antes de crearlo
                inside_parent = any(
                    resolved_path.parent == d or resolved_path.parent.is_relative_to(d)
                    for d in self._allowed_dirs
                )
                if not inside_parent:
                    return ToolResult(
                        tool_name=self.tool_id,
                        content="Acceso denegado: el directorio padre está fuera del sandbox.",
                        success=False,
                    )
                resolved_path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"No se pudieron crear los directorios padres: {exc}",
                    success=False,
                )
        else:
            if not resolved_path.parent.exists():
                return ToolResult(
                    tool_name=self.tool_id,
                    content=f"El directorio padre no existe: {resolved_path.parent}. Activa create_dirs=True.",
                    success=False,
                )

        try:
            write_mode = "w" if mode == "write" else "a"
            with open(resolved_path, write_mode, encoding="utf-8") as f:
                f.write(content_str)
        except PermissionError:
            return ToolResult(
                tool_name=self.tool_id,
                content="Permiso denegado por el sistema operativo al escribir en el archivo.",
                success=False,
            )
        except OSError as exc:
            return ToolResult(
                tool_name=self.tool_id,
                content=f"Error del sistema de archivos durante la escritura: {exc}",
                success=False,
            )

        try:
            size = resolved_path.stat().st_size
        except OSError:
            size = len(content_bytes)

        return ToolResult(
            tool_name=self.tool_id,
            content=f"Escritura exitosa en {file_path}",
            success=True,
            metadata={"path": str(resolved_path), "size_bytes": size, "mode": mode},
        )


__all__ = ["FileWriteTool"]