from __future__ import annotations

from dataclasses import dataclass

from jarvis.identity.models import UserIdentity

from .confirmation import ConfirmationManager, ConfirmationRequest
from .models import (
    AuthorizationStatus,
    SecurityAction,
)
from .service import AuthorizationService


@dataclass
class SecurityDecision:
    """
    Final security decision before an action reaches an executor.

    This object does not execute anything.
    """

    authorized: bool

    action: SecurityAction

    user: UserIdentity | None

    confirmation: ConfirmationRequest | None = None

    reason: str = ""


class SecurityGateway:
    """
    Main security entry point for JARVIS actions.

    Flow:

        User
          ↓
        AuthorizationService
          ↓
        SecurityGateway
          ↓
        ConfirmationManager (if necessary)
          ↓
        Executor (later)

    The gateway never executes the action itself.
    """

    def __init__(
        self,
        authorization_service: AuthorizationService | None = None,
        confirmation_manager: ConfirmationManager | None = None,
    ) -> None:

        self.authorization_service = (
            authorization_service
            or AuthorizationService()
        )

        self.confirmation_manager = (
            confirmation_manager
            or ConfirmationManager()
        )

    def request_action(
        self,
        user: UserIdentity | None,
        action: SecurityAction,
    ) -> SecurityDecision:
        """
        Ask the security system whether an action may proceed.

        If confirmation is required, a confirmation request is created.
        """

        authorization = self.authorization_service.authorize(
            user=user,
            action=action,
        )

        # ---------------------------------------------------------
        # Completely denied
        # ---------------------------------------------------------

        if authorization.status == AuthorizationStatus.DENIED:
            return SecurityDecision(
                authorized=False,
                action=action,
                user=user,
                reason=authorization.reason,
            )

        # ---------------------------------------------------------
        # Confirmation required
        # ---------------------------------------------------------

        if authorization.status in {
            AuthorizationStatus.REQUIRES_CONFIRMATION,
            AuthorizationStatus.REQUIRES_IDENTITY,
        }:

            if user is None:
                return SecurityDecision(
                    authorized=False,
                    action=action,
                    user=None,
                    reason="No hay un usuario autenticado.",
                )

            confirmation = self.confirmation_manager.create(
                user_id=user.user_id,
                action=action,
            )

            return SecurityDecision(
                authorized=False,
                action=action,
                user=user,
                confirmation=confirmation,
                reason=authorization.reason,
            )

        # ---------------------------------------------------------
        # Already authorized
        # ---------------------------------------------------------

        return SecurityDecision(
            authorized=True,
            action=action,
            user=user,
            reason=authorization.reason,
        )

    def confirm(
        self,
        confirmation_id: str,
        user_id: str,
    ) -> bool:
        """
        Confirm a previously authorized action.
        """

        return self.confirmation_manager.confirm(
            confirmation_id=confirmation_id,
            user_id=user_id,
        )

    def reject(
        self,
        confirmation_id: str,
        user_id: str,
    ) -> bool:
        """
        Reject a previously authorized action.
        """

        return self.confirmation_manager.reject(
            confirmation_id=confirmation_id,
            user_id=user_id,
        )

    def is_confirmed(
        self,
        confirmation_id: str,
        user_id: str,
    ) -> bool:
        """
        Check whether a specific action has been confirmed.
        """

        return self.confirmation_manager.is_confirmed(
            confirmation_id=confirmation_id,
            user_id=user_id,
        )