from dataclasses import dataclass, field
from enum import Enum

from jarvis.security.levels import SecurityLevel

class AuthorizationStatus(Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    REQUIRES_IDENTITY = "requires_identity"


class ExecutionChannel(Enum):
    INTERNAL = "internal"
    TOOL = "tool"
    PYTHON = "python"
    CMD = "cmd"
    POWERSHELL = "powershell"
    APPLICATION = "application"


@dataclass
class SecurityAction:
    """
    Represents an operation JARVIS wants to perform.

    IMPORTANT:
    required_level is informational only.
    The SecurityManager must calculate the real required
    security level independently.
    """

    action: str
    description: str

    required_level: SecurityLevel = SecurityLevel.LEVEL_5

    target: str | None = None

    execution_channel: ExecutionChannel = ExecutionChannel.INTERNAL

    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class AuthorizationRequest:
    """
    Result of a security authorization attempt.
    """

    action: SecurityAction

    status: AuthorizationStatus

    reason: str

    required_level: SecurityLevel | None = None

    requires_confirmation: bool = False
    requires_identity: bool = False

    confirmation_phrase: str | None = None