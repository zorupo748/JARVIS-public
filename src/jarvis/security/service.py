from __future__ import annotations

from jarvis.identity.models import UserIdentity

from .manager import SecurityManager
from .models import AuthorizationRequest, SecurityAction


class AuthorizationService:
    """
    High-level security gateway for JARVIS.

    Every action that JARVIS wants to perform should pass through
    this service before execution.

    Security permissions belong to the authenticated user, never
    to JARVIS itself.
    """

    def __init__(
        self,
        security_manager: SecurityManager | None = None,
    ) -> None:
        self.security_manager = security_manager or SecurityManager()

    def authorize(
        self,
        user: UserIdentity | None,
        action: SecurityAction,
    ) -> AuthorizationRequest:
        """
        Authorize an action on behalf of a specific user.

        The user's identity and security level are passed directly
        to SecurityManager.
        """

        return self.security_manager.authorize(
            user=user,
            action=action,
        )