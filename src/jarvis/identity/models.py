from dataclasses import dataclass
from datetime import datetime

from jarvis.security.levels import SecurityLevel


@dataclass
class UserIdentity:
    """
    Represents a person known by JARVIS.

    Security level belongs to the person, not to JARVIS.
    """

    user_id: str
    display_name: str

    security_level: SecurityLevel = SecurityLevel.LEVEL_0

    is_owner: bool = False

    # Future voice-recognition data.
    voice_profile_id: str | None = None

    created_at: str | None = None

    def __post_init__(self) -> None:
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()

        # SUPER is never represented as a security level.
        if not isinstance(self.security_level, SecurityLevel):
            self.security_level = SecurityLevel.LEVEL_0