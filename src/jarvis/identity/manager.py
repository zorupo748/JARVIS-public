from __future__ import annotations

from .models import UserIdentity
from .registry import UserRegistry
from jarvis.security.levels import SecurityLevel


class IdentityManager:
    """
    Resolves who is interacting with JARVIS.

    Security level belongs to the person, not to JARVIS.

    Voice recognition will be connected here later.
    """

    def __init__(self, registry: UserRegistry | None = None):
        self.registry = registry or UserRegistry()
        self.current_user: UserIdentity | None = None

    def identify(self, user_id: str) -> UserIdentity | None:
        """
        Identify a known user by ID.

        Returns None if the user is unknown.
        """

        user = self.registry.get(user_id)

        self.current_user = user

        return user

    def register_user(
        self,
        user_id: str,
        display_name: str,
    ) -> UserIdentity:
        """
        Register a new user.

        New users ALWAYS start at Level 0.
        """

        user = UserIdentity(
            user_id=user_id,
            display_name=display_name,
            security_level=SecurityLevel.LEVEL_0,
            is_owner=False,
        )

        self.registry.add(user)

        return user

    def get_user(self, user_id: str) -> UserIdentity | None:
        """Return a registered user without making them the current user."""
        return self.registry.get(user_id)

    def get_current_user(self) -> UserIdentity | None:
        """Return the currently authenticated user."""
        return self.current_user

    def get_current_security_level(self) -> SecurityLevel:
        """
        Return the security level of the authenticated user.

        No authenticated user means Level 0.
        """

        if self.current_user is None:
            return SecurityLevel.LEVEL_0

        return self.current_user.security_level

    def is_authenticated(self) -> bool:
        """Return True if a user is currently identified."""
        return self.current_user is not None

    def logout(self) -> None:
        """Clear the current identity."""
        self.current_user = None