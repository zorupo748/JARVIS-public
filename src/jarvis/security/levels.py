from __future__ import annotations

from enum import IntEnum
from typing import Any, Optional


class SecurityLevel(IntEnum):
    """
    Normal security levels available to JARVIS.

    Level 5 is the absolute maximum normal level.
    SUPER is NOT a security level and cannot be reached by increasing
    the user's level.
    """

    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_2 = 2
    LEVEL_3 = 3
    LEVEL_4 = 4
    LEVEL_5 = 5

    @property
    def name_es(self) -> str:
        names = {
            SecurityLevel.LEVEL_0: "Nivel 0",
            SecurityLevel.LEVEL_1: "Nivel 1",
            SecurityLevel.LEVEL_2: "Nivel 2",
            SecurityLevel.LEVEL_3: "Nivel 3",
            SecurityLevel.LEVEL_4: "Nivel 4",
            SecurityLevel.LEVEL_5: "Nivel 5",
        }

        return names[self]


class AuthorityLevel:
    """
    Special authorities that are NOT part of SecurityLevel.

    SUPER can only be granted by the authenticated owner for a
    specific operation. JARVIS can never obtain it by itself.
    """

    SUPER = "SUPER"


class SecurityGateway:
    """Pasarela de autorización previa a la ejecución de herramientas."""

    def authorize(
        self,
        tool_name: str,
        required_level: SecurityLevel,
        user_identity: Optional[Any] = None,
    ) -> bool:
        if user_identity is None:
            return required_level == SecurityLevel.LEVEL_0

        is_owner = getattr(user_identity, "is_owner", False)
        if is_owner:
            return True

        user_level = getattr(user_identity, "security_level", SecurityLevel.LEVEL_0)
        return user_level >= required_level


__all__ = ["SecurityLevel", "AuthorityLevel", "SecurityGateway"]