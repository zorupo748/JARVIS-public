from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from .models import SecurityAction


class ConfirmationStatus:
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ConfirmationRequest:
    """
    Represents a single pending confirmation.

    A confirmation belongs to one specific user and one specific
    security action.
    """

    confirmation_id: str
    user_id: str
    action: SecurityAction

    status: str = ConfirmationStatus.PENDING

    created_at: str | None = None
    confirmed_at: str | None = None

    def __post_init__(self) -> None:
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


class ConfirmationManager:
    """
    Manages explicit confirmations for security-sensitive actions.

    This class does NOT execute actions.
    It only manages whether a previously authorized action has been
    explicitly confirmed by the user.
    """

    def __init__(self) -> None:
        self._pending: dict[str, ConfirmationRequest] = {}

    def create(
        self,
        user_id: str,
        action: SecurityAction,
    ) -> ConfirmationRequest:
        """
        Create a new confirmation request for a specific user and action.
        """

        confirmation = ConfirmationRequest(
            confirmation_id=str(uuid4()),
            user_id=user_id,
            action=action,
        )

        self._pending[confirmation.confirmation_id] = confirmation

        return confirmation

    def get(
        self,
        confirmation_id: str,
    ) -> ConfirmationRequest | None:
        """
        Retrieve a pending or previously resolved confirmation.
        """

        return self._pending.get(confirmation_id)

    def confirm(
        self,
        confirmation_id: str,
        user_id: str,
    ) -> bool:
        """
        Confirm a specific action.

        The user confirming the action must be the same user for whom
        the confirmation was originally created.
        """

        request = self._pending.get(confirmation_id)

        if request is None:
            return False

        if request.status != ConfirmationStatus.PENDING:
            return False

        if request.user_id != user_id:
            return False

        request.status = ConfirmationStatus.CONFIRMED
        request.confirmed_at = datetime.now().isoformat()

        return True

    def reject(
        self,
        confirmation_id: str,
        user_id: str,
    ) -> bool:
        """
        Reject a specific action.

        The user rejecting the action must be the same user for whom
        the confirmation was originally created.
        """

        request = self._pending.get(confirmation_id)

        if request is None:
            return False

        if request.status != ConfirmationStatus.PENDING:
            return False

        if request.user_id != user_id:
            return False

        request.status = ConfirmationStatus.REJECTED

        return True

    def is_confirmed(
        self,
        confirmation_id: str,
        user_id: str,
    ) -> bool:
        """
        Check whether a specific confirmation was approved by its user.
        """

        request = self._pending.get(confirmation_id)

        if request is None:
            return False

        return (
            request.user_id == user_id
            and request.status == ConfirmationStatus.CONFIRMED
        )

    def clear(
        self,
        confirmation_id: str,
    ) -> None:
        """
        Remove a confirmation from memory.
        """

        self._pending.pop(confirmation_id, None)

    def pending(self) -> list[ConfirmationRequest]:
        """
        Return all currently pending confirmations.
        """

        return [
            request
            for request in self._pending.values()
            if request.status == ConfirmationStatus.PENDING
        ]