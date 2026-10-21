from __future__ import annotations

from pathlib import Path

from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel


class FileSystemPolicy:
    """
    Defines which filesystem locations a user can access.

    This is a second security layer. The authorization system
    decides whether the user has enough security level, while
    this policy decides whether the requested path itself is
    allowed.

    IMPORTANT:
    No normal security level can escape the JARVIS project root.
    Absolute paths, drive changes and path traversal outside the
    project are always blocked.
    """

    def __init__(self, project_root: str | Path = ".") -> None:
        self.project_root = Path(project_root).resolve()

    # ------------------------------------------------------------------
    # Public path resolution
    # ------------------------------------------------------------------

    def resolve(self, target: str | Path) -> Path:
        """
        Resolve a target path safely.

        The resulting path MUST remain inside project_root.

        Raises:
            ValueError: if the target escapes the project root.
        """

        target_path = Path(target)

        # --------------------------------------------------------------
        # Absolute paths are not allowed.
        # --------------------------------------------------------------

        if target_path.is_absolute():
            raise ValueError(
                "Las rutas absolutas no están permitidas."
            )

        # --------------------------------------------------------------
        # Resolve relative to the JARVIS project root.
        # --------------------------------------------------------------

        path = (self.project_root / target_path).resolve()

        # --------------------------------------------------------------
        # The resolved path must remain inside project_root.
        # This blocks ../ traversal.
        # --------------------------------------------------------------

        if not self._inside(
            path,
            self.project_root,
        ):
            raise ValueError(
                "La ruta solicitada está fuera del proyecto JARVIS."
            )

        return path

    # ------------------------------------------------------------------
    # Compatibility alias
    # ------------------------------------------------------------------

    def _resolve(self, target: str | Path) -> Path:
        """
        Internal compatibility wrapper.

        Existing executors may still call _resolve().
        """

        return self.resolve(target)

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def can_create(
        self,
        user: UserIdentity,
        target: str | Path,
    ) -> bool:
        """
        Check whether the user may create a file or directory.
        """

        if user.security_level < SecurityLevel.LEVEL_1:
            return False

        try:
            path = self.resolve(target)
        except ValueError:
            return False

        return self._is_allowed_path(user, path)

    # ------------------------------------------------------------------
    # Modify
    # ------------------------------------------------------------------

    def can_modify(
        self,
        user: UserIdentity,
        target: str | Path,
    ) -> bool:
        """
        Check whether the user may modify an existing file.
        """

        if user.security_level < SecurityLevel.LEVEL_2:
            return False

        try:
            path = self.resolve(target)
        except ValueError:
            return False

        return self._is_allowed_path(user, path)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def can_delete(
        self,
        user: UserIdentity,
        target: str | Path,
    ) -> bool:
        """
        Check whether the user may delete a file or directory.
        """

        if user.security_level < SecurityLevel.LEVEL_4:
            return False

        try:
            path = self.resolve(target)
        except ValueError:
            return False

        return self._is_allowed_path(user, path)

    # ------------------------------------------------------------------
    # Allowed paths
    # ------------------------------------------------------------------

    def _is_allowed_path(
        self,
        user: UserIdentity,
        path: Path,
    ) -> bool:
        """
        Determine whether the path is allowed for this user.

        Protected JARVIS locations are blocked regardless of
        normal security level.
        """

        # --------------------------------------------------------------
        # Absolute safety boundary
        # --------------------------------------------------------------

        if not self._inside(path, self.project_root):
            return False

        # --------------------------------------------------------------
        # Protected locations
        # --------------------------------------------------------------

        if self._is_protected(path):
            return False

        # --------------------------------------------------------------
        # Level 5
        #
        # Level 5 has broad access inside the project, but NEVER
        # outside the project and NEVER to protected locations.
        # --------------------------------------------------------------

        if user.security_level >= SecurityLevel.LEVEL_5:
            return True

        # --------------------------------------------------------------
        # Level 1
        # --------------------------------------------------------------

        if user.security_level >= SecurityLevel.LEVEL_1:

            allowed = [
                self.project_root / "workspace",
                self.project_root / "data",
            ]

            if self._inside_any(path, allowed):
                return True

        # --------------------------------------------------------------
        # Level 2
        # --------------------------------------------------------------

        if user.security_level >= SecurityLevel.LEVEL_2:

            allowed = [
                self.project_root / "workspace",
                self.project_root / "data",
                self.project_root / "output",
            ]

            if self._inside_any(path, allowed):
                return True

        # --------------------------------------------------------------
        # Level 3
        # --------------------------------------------------------------

        if user.security_level >= SecurityLevel.LEVEL_3:

            allowed = [
                self.project_root / "workspace",
                self.project_root / "data",
                self.project_root / "output",
                self.project_root / "tools",
            ]

            if self._inside_any(path, allowed):
                return True

        # --------------------------------------------------------------
        # Level 4
        # --------------------------------------------------------------

        if user.security_level >= SecurityLevel.LEVEL_4:

            allowed = [
                self.project_root / "workspace",
                self.project_root / "data",
                self.project_root / "output",
                self.project_root / "tools",
                self.project_root / "projects",
            ]

            if self._inside_any(path, allowed):
                return True

        return False

    # ------------------------------------------------------------------
    # Protected locations
    # ------------------------------------------------------------------

    def _is_protected(self, path: Path) -> bool:
        """
        Locations that normal security levels can NEVER modify.
        """

        protected = [
            self.project_root / "src" / "jarvis",
            self.project_root / ".venv",
            self.project_root / ".git",
        ]

        return self._inside_any(path, protected)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _inside(
        path: Path,
        directory: Path,
    ) -> bool:
        """
        Return True if path is inside directory.

        The directory itself is also considered inside.
        """

        try:
            path.relative_to(directory.resolve())
            return True
        except ValueError:
            return False

    @classmethod
    def _inside_any(
        cls,
        path: Path,
        directories: list[Path],
    ) -> bool:
        """
        Check whether path is inside one of the directories.
        """

        return any(
            cls._inside(path, directory)
            for directory in directories
        )