
from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from jarvis.identity.models import UserIdentity

from .command_policy import CommandPolicy
from .models import SecurityAction, ExecutionChannel


@dataclass
class CommandExecutionResult:
    """
    Result of a command execution.
    """

    success: bool
    message: str
    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None


class CommandExecutor:
    """
    Executes CMD and PowerShell commands.

    This class contains a second defensive security check.

    Normal execution flow:

        ActionExecutor
            ↓
        ExecutionGateway
            ↓
        CommandPolicy
            ↓
        CommandExecutor
            ↓
        subprocess

    CommandExecutor performs the CommandPolicy check again so that
    an accidental or unintended direct call cannot bypass the
    command security policy.
    """

    def __init__(
        self,
        command_policy: CommandPolicy | None = None,
    ) -> None:

        self.command_policy = (
            command_policy
            or CommandPolicy()
        )

    def execute(
        self,
        user: UserIdentity,
        action: SecurityAction,
    ) -> CommandExecutionResult:

        # =========================================================
        # 1. Validate execution channel
        # =========================================================

        if action.execution_channel not in {
            ExecutionChannel.CMD,
            ExecutionChannel.POWERSHELL,
        }:
            return CommandExecutionResult(
                success=False,
                message=(
                    "El canal de ejecución no es compatible "
                    "con CommandExecutor."
                ),
            )

        # =========================================================
        # 2. Validate command
        # =========================================================

        command = action.metadata.get("command")

        if not isinstance(command, str) or not command.strip():
            return CommandExecutionResult(
                success=False,
                message="No se ha proporcionado ningún comando.",
            )

        # =========================================================
        # 3. SECOND SECURITY BARRIER
        # =========================================================

        policy_result = self.command_policy.check(
            user,
            action,
        )

        if not policy_result.allowed:
            return CommandExecutionResult(
                success=False,
                message=policy_result.message,
            )

        # =========================================================
        # 4. Execute command
        # =========================================================

        try:

            if action.execution_channel == ExecutionChannel.CMD:

                result = subprocess.run(
                    [
                        "cmd.exe",
                        "/d",
                        "/c",
                        command,
                    ],
                    capture_output=True,
                    text=True,
                    cwd=None,
                    shell=False,
                )

            else:

                result = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        command,
                    ],
                    capture_output=True,
                    text=True,
                    cwd=None,
                    shell=False,
                )

        except OSError as exc:

            return CommandExecutionResult(
                success=False,
                message=f"No se pudo ejecutar el comando: {exc}",
            )

        # =========================================================
        # 5. Return execution result
        # =========================================================

        return CommandExecutionResult(
            success=result.returncode == 0,
            message=(
                "Comando ejecutado correctamente."
                if result.returncode == 0
                else "El comando terminó con errores."
            ),
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
        )
