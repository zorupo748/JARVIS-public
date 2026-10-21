from __future__ import annotations

from pathlib import Path

from jarvis.identity.models import UserIdentity
from jarvis.security.filesystem import FileSystemPolicy


class FileExecutionResult:
    """
    Result of a filesystem operation.
    """

    def __init__(
        self,
        success: bool,
        message: str,
        path: Path | None = None,
    ) -> None:
        self.success = success
        self.message = message
        self.path = path

    def __repr__(self) -> str:
        return (
            f"FileExecutionResult("
            f"success={self.success!r}, "
            f"message={self.message!r}, "
            f"path={str(self.path)!r})"
        )


class FileExecutor:
    """
    Performs real filesystem operations.

    This class does NOT decide the user's security level.
    It relies on FileSystemPolicy and performs a second
    path validation immediately before touching the filesystem.
    """

    def __init__(
        self,
        policy: FileSystemPolicy | None = None,
    ) -> None:
        self.policy = policy or FileSystemPolicy()

    def create_file(
        self,
        user: UserIdentity,
        target: str | Path,
        content: str = "",
    ) -> FileExecutionResult:

        path = self.policy._resolve(target)

        if not self.policy.can_create(user, target):
            return FileExecutionResult(
                False,
                "El usuario no tiene permiso para crear este archivo.",
                path,
            )

        if path.exists():
            return FileExecutionResult(
                False,
                "El archivo ya existe.",
                path,
            )

        try:
            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            path.write_text(
                content,
                encoding="utf-8",
            )

        except OSError as exc:
            return FileExecutionResult(
                False,
                f"No se pudo crear el archivo: {exc}",
                path,
            )

        return FileExecutionResult(
            True,
            "Archivo creado correctamente.",
            path,
        )

    def create_directory(
        self,
        user: UserIdentity,
        target: str | Path,
    ) -> FileExecutionResult:

        path = self.policy._resolve(target)

        if not self.policy.can_create(user, target):
            return FileExecutionResult(
                False,
                "El usuario no tiene permiso para crear esta carpeta.",
                path,
            )

        if path.exists():
            return FileExecutionResult(
                False,
                "La carpeta ya existe.",
                path,
            )

        try:
            path.mkdir(
                parents=True,
                exist_ok=False,
            )

        except OSError as exc:
            return FileExecutionResult(
                False,
                f"No se pudo crear la carpeta: {exc}",
                path,
            )

        return FileExecutionResult(
            True,
            "Carpeta creada correctamente.",
            path,
        )

    def modify_file(
        self,
        user: UserIdentity,
        target: str | Path,
        content: str,
    ) -> FileExecutionResult:

        path = self.policy._resolve(target)

        if not self.policy.can_modify(user, target):
            return FileExecutionResult(
                False,
                "El usuario no tiene permiso para modificar este archivo.",
                path,
            )

        if not path.exists():
            return FileExecutionResult(
                False,
                "El archivo no existe.",
                path,
            )

        if not path.is_file():
            return FileExecutionResult(
                False,
                "La ruta indicada no es un archivo.",
                path,
            )

        try:
            path.write_text(
                content,
                encoding="utf-8",
            )

        except OSError as exc:
            return FileExecutionResult(
                False,
                f"No se pudo modificar el archivo: {exc}",
                path,
            )

        return FileExecutionResult(
            True,
            "Archivo modificado correctamente.",
            path,
        )

    def delete(
        self,
        user: UserIdentity,
        target: str | Path,
    ) -> FileExecutionResult:

        path = self.policy._resolve(target)

        if not self.policy.can_delete(user, target):
            return FileExecutionResult(
                False,
                "El usuario no tiene permiso para eliminar esta ruta.",
                path,
            )

        if not path.exists():
            return FileExecutionResult(
                False,
                "La ruta no existe.",
                path,
            )

        try:
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
            else:
                return FileExecutionResult(
                    False,
                    "La ruta no es un archivo ni una carpeta válida.",
                    path,
                )

        except OSError as exc:
            return FileExecutionResult(
                False,
                f"No se pudo eliminar la ruta: {exc}",
                path,
            )

        return FileExecutionResult(
            True,
            "Ruta eliminada correctamente.",
            path,
        )