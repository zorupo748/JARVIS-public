from __future__ import annotations

from jarvis.identity.models import UserIdentity

from .command_executor import CommandExecutor
from .command_policy import CommandPolicy
from .confirmation import ConfirmationManager
from .execution import ExecutionGateway, ExecutionResult
from .file_executor import FileExecutor
from .guardrails import GuardrailSystem
from .models import ExecutionChannel, SecurityAction


class ActionExecutor:
    """
    Connects the security layer with the real executors.

    Every action must pass through the ExecutionGateway first.

    Filesystem actions are checked against GuardrailSystem and dispatched
    to FileExecutor.

    CMD and PowerShell actions are additionally checked by
    CommandPolicy before reaching CommandExecutor.
    """

    def __init__(
        self,
        confirmation_manager: ConfirmationManager | None = None,
        file_executor: FileExecutor | None = None,
        command_executor: CommandExecutor | None = None,
        command_policy: CommandPolicy | None = None,
    ) -> None:

        self.confirmation_manager = (
            confirmation_manager or ConfirmationManager()
        )

        self.execution_gateway = ExecutionGateway(
            self.confirmation_manager
        )

        self.file_executor = (
            file_executor or FileExecutor()
        )

        self.command_executor = (
            command_executor or CommandExecutor()
        )

        self.command_policy = (
            command_policy or CommandPolicy()
        )

    def execute(
        self,
        user: UserIdentity | None,
        action: SecurityAction,
        confirmation_id: str | None = None,
    ):
        """
        Execute an action only after it has passed
        the guardrail system and security gateway.
        """

        # =========================================================
        # 1. FINAL SECURITY BARRIER
        # =========================================================

        security_result = self.execution_gateway.execute(
            user,
            action,
            confirmation_id,
        )

        if not security_result.authorized:
            return security_result

        # =========================================================
        # 2. USER MUST EXIST
        # =========================================================

        if user is None:
            return security_result

        # =========================================================
        # 3. FILESYSTEM ACTIONS
        # =========================================================

        if action.action == "create_file":

            if action.target is None:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message="La acción requiere una ruta de destino.",
                    authorized=False,
                )

            content = str(
                action.metadata.get("content", "")
            )

            return self.file_executor.create_file(
                user,
                action.target,
                content,
            )

        if action.action == "create_directory":

            if action.target is None:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message="La acción requiere una ruta de destino.",
                    authorized=False,
                )

            return self.file_executor.create_directory(
                user,
                action.target,
            )

        if action.action == "modify_file":

            if action.target is None:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message="La acción requiere una ruta de destino.",
                    authorized=False,
                )

            content = str(
                action.metadata.get("content", "")
            )

            return self.file_executor.modify_file(
                user,
                action.target,
                content,
            )

        if action.action in {
            "delete_file",
            "delete_directory",
        }:

            if action.target is None:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message="La acción requiere una ruta de destino.",
                    authorized=False,
                )

            # -----------------------------------------------------
            # GUARDRAIL INSPECTION (Context Negotiation)
            # -----------------------------------------------------

            guardrail_res = GuardrailSystem.evaluate_target(action.target)

            if guardrail_res.status == "CRITICAL_BLOCKED":
                return ExecutionResult(
                    success=False,
                    action=action,
                    message=guardrail_res.message,
                    authorized=False,
                )

            if guardrail_res.status == "REQUIRES_EXPLANATION":
                context_approved = action.metadata.get("user_justified", False)
                if not context_approved:
                    return ExecutionResult(
                        success=False,
                        action=action,
                        message=(
                            f"{guardrail_res.message} "
                            "Explícale a JARVIS qué archivos exactos quieres eliminar "
                            "para acotar la acción y permitir la ejecución."
                        ),
                        authorized=False,
                    )

            return self.file_executor.delete(
                user,
                action.target,
            )

        # =========================================================
        # 4. CMD / POWERSHELL
        # =========================================================

        if action.execution_channel in {
            ExecutionChannel.CMD,
            ExecutionChannel.POWERSHELL,
        }:

            policy_result = self.command_policy.check(
                user,
                action,
            )

            if not policy_result.allowed:
                return ExecutionResult(
                    success=False,
                    action=action,
                    message=policy_result.message,
                    authorized=False,
                )

            return self.command_executor.execute(
                user,
                action,
            )

        # =========================================================
        # 5. UNKNOWN ACTION
        # =========================================================

        return ExecutionResult(
            success=False,
            action=action,
            message="Acción no soportada por ActionExecutor.",
            authorized=False,
        )