from __future__ import annotations

from dataclasses import dataclass

from jarvis.identity.models import UserIdentity

from .confirmation import ConfirmationManager
from .models import SecurityAction


@dataclass
class ExecutionResult:
    """
    Result of the security execution gate.
    """

    success: bool
    action: SecurityAction
    message: str
    authorized: bool = False


class ExecutionGateway:
    """
    Final security barrier before an action is executed.

    This class does NOT create authorizations or confirmations.

    It only verifies that an already authorized and confirmed
    operation is allowed to reach an executor.
    """

    def __init__(
        self,
        confirmation_manager: ConfirmationManager,
    ) -> None:

        self.confirmation_manager = confirmation_manager

    def execute(
        self,
        user: UserIdentity | None,
        action: SecurityAction,
        confirmation_id: str | None = None,
    ) -> ExecutionResult:

        # ---------------------------------------------------------
        # 1. User must be authenticated
        # ---------------------------------------------------------

        if user is None:
            return ExecutionResult(
                success=False,
                action=action,
                message=(
                    "No hay ningún usuario autenticado. "
                    "La operación ha sido bloqueada."
                ),
                authorized=False,
            )

        # ---------------------------------------------------------
        # 2. Level 3+ requires explicit confirmation
        # ---------------------------------------------------------

        if action.required_level.value >= 3:

            if confirmation_id is None:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message=(
                        "Esta operación requiere una "
                        "confirmación explícita del usuario."
                    ),
                    authorized=False,
                )

            # -----------------------------------------------------
            # 3. Retrieve confirmation
            # -----------------------------------------------------

            confirmation = self.confirmation_manager.get(
                confirmation_id
            )

            if confirmation is None:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message="La confirmación indicada no existe.",
                    authorized=False,
                )

            # -----------------------------------------------------
            # 4. Confirmation must belong to this user
            # -----------------------------------------------------

            if confirmation.user_id != user.user_id:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message=(
                        "La confirmación pertenece a otro usuario. "
                        "La operación ha sido bloqueada."
                    ),
                    authorized=False,
                )

            # -----------------------------------------------------
            # 5. Confirmation must correspond to this action
            # -----------------------------------------------------

            if not self._actions_match(
                confirmation.action,
                action,
            ):
                return ExecutionResult(
                    success=False,
                    action=action,
                    message=(
                        "La confirmación no corresponde "
                        "a la operación solicitada."
                    ),
                    authorized=False,
                )

            # -----------------------------------------------------
            # 6. Confirmation must actually be confirmed
            # -----------------------------------------------------

            if not self.confirmation_manager.is_confirmed(
                confirmation_id,
                user.user_id,
            ):
                return ExecutionResult(
                    success=False,
                    action=action,
                    message=(
                        "La operación todavía no ha sido "
                        "confirmada por el usuario."
                    ),
                    authorized=False,
                )

        # ---------------------------------------------------------
        # 7. All security checks passed
        # ---------------------------------------------------------

        return ExecutionResult(
            success=True,
            action=action,
            message="Operación autorizada para ejecución.",
            authorized=True,
        )

    @staticmethod
    def _actions_match(
        confirmed: SecurityAction,
        requested: SecurityAction,
    ) -> bool:
        """
        Ensure that the confirmed operation is exactly the
        operation being requested for execution.
        """

        return (
            confirmed.action == requested.action
            and confirmed.description == requested.description
            and confirmed.required_level == requested.required_level
            and confirmed.target == requested.target
            and confirmed.execution_channel
            == requested.execution_channel
            and confirmed.metadata == requested.metadata
        )