from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from jarvis.identity.models import UserIdentity

from .levels import SecurityLevel
from .models import SecurityAction, ExecutionChannel


@dataclass
class CommandPolicyResult:
    allowed: bool
    message: str


class CommandPolicy:
    """
    Controls which CMD and PowerShell commands may reach
    the real CommandExecutor.

    This policy is deliberately conservative.

    Security layers:

    1. Execution channel validation.
    2. Command validation.
    3. Shell operator / redirection blocking.
    4. Dangerous command blocking.
    5. Security-level command allowlist.

    Authorization and confirmation are handled separately
    by ExecutionGateway.
    """

    # =========================================================
    # Commands allowed through CMD
    # =========================================================

    SAFE_COMMANDS = {
        "echo",
        "whoami",
        "hostname",
        "ver",
        "dir",
        "type",
        "where",
        "cd",
        "set",
    }

    # =========================================================
    # Commands allowed through PowerShell
    # =========================================================

    SAFE_POWERSHELL_COMMANDS = {
        "get-location",
        "get-childitem",
        "get-content",
        "get-date",
        "get-process",
        "get-service",
        "get-command",
        "get-variable",
        "write-output",
        "whoami",
        "hostname",
    }

    # =========================================================
    # Commands that are NEVER allowed through this executor
    # =========================================================

    BLOCKED_COMMANDS = {
        # Disk / filesystem destruction
        "format",
        "diskpart",
        "del",
        "erase",
        "rd",
        "rmdir",
        "remove-item",
        "remove",
        "rm",

        # System shutdown / restart
        "shutdown",
        "restart-computer",
        "stop-computer",
        "restart",

        # Registry
        "reg",
        "regedit",

        # Boot configuration
        "bcdedit",

        # Permissions / ownership
        "takeown",
        "icacls",

        # Encryption / disk manipulation
        "cipher",

        # PowerShell execution bypass
        "invoke-expression",
        "iex",
        "invoke-command",
        "start-process",

        # Script execution
        "powershell",
        "pwsh",

        # CMD interpreter nesting
        "cmd",

        # Network / remote execution
        "wmic",
        "winrs",
        "psexec",

        # Services / scheduled tasks
        "sc",
        "schtasks",

        # Process termination
        "taskkill",

        # Firewall / networking configuration
        "netsh",

        # User / account administration
        "net",
        "net1",

        # Dangerous scripting / code execution
        "mshta",
        "rundll32",
        "regsvr32",
        "cscript",
        "wscript",
    }

    # =========================================================
    # Shell operators
    # =========================================================

    SHELL_OPERATORS = {
        "&",
        "&&",
        "||",
        "|",
        ";",
    }

    REDIRECTION_OPERATORS = {
        ">",
        ">>",
        "<",
        "<<",
    }

    # =========================================================
    # Public policy check
    # =========================================================

    def check(
        self,
        user: UserIdentity,
        action: SecurityAction,
    ) -> CommandPolicyResult:

        # -----------------------------------------------------
        # 1. Validate execution channel
        # -----------------------------------------------------

        if action.execution_channel not in {
            ExecutionChannel.CMD,
            ExecutionChannel.POWERSHELL,
        }:
            return CommandPolicyResult(
                False,
                "El canal de ejecución no es un canal de comandos.",
            )

        # -----------------------------------------------------
        # 2. Validate command
        # -----------------------------------------------------

        command = action.metadata.get("command")

        if not isinstance(command, str) or not command.strip():
            return CommandPolicyResult(
                False,
                "No se ha proporcionado ningún comando.",
            )

        command = command.strip()

        # -----------------------------------------------------
        # 3. Reject shell operators and redirection
        # -----------------------------------------------------

        operator_result = self._check_shell_operators(command)

        if not operator_result.allowed:
            return operator_result

        # -----------------------------------------------------
        # 4. Extract the base command
        # -----------------------------------------------------

        first_token = self._extract_command(command)

        if not first_token:
            return CommandPolicyResult(
                False,
                "No se pudo determinar el comando solicitado.",
            )

        # -----------------------------------------------------
        # 5. Explicit dangerous command block
        # -----------------------------------------------------

        if first_token in self.BLOCKED_COMMANDS:
            return CommandPolicyResult(
                False,
                (
                    f"El comando '{first_token}' está bloqueado "
                    "por la política de seguridad."
                ),
            )

        # -----------------------------------------------------
        # 6. Level 5
        #
        # Level 5 has the widest command access, but NEVER
        # bypasses the explicit dangerous-command block or
        # shell-operator protection above.
        # -----------------------------------------------------

        if user.security_level >= SecurityLevel.LEVEL_5:
            return CommandPolicyResult(
                True,
                "Comando permitido para Nivel 5.",
            )

        # -----------------------------------------------------
        # 7. CMD
        # -----------------------------------------------------

        if action.execution_channel == ExecutionChannel.CMD:

            if first_token in self.SAFE_COMMANDS:
                return CommandPolicyResult(
                    True,
                    "Comando CMD permitido.",
                )

            return CommandPolicyResult(
                False,
                (
                    "El comando CMD no está permitido "
                    "para este nivel de seguridad."
                ),
            )

        # -----------------------------------------------------
        # 8. PowerShell
        # -----------------------------------------------------

        if action.execution_channel == ExecutionChannel.POWERSHELL:

            if first_token in self.SAFE_POWERSHELL_COMMANDS:
                return CommandPolicyResult(
                    True,
                    "Comando PowerShell permitido.",
                )

            return CommandPolicyResult(
                False,
                (
                    "El comando PowerShell no está permitido "
                    "para este nivel de seguridad."
                ),
            )

        # -----------------------------------------------------
        # 9. Unknown channel
        # -----------------------------------------------------

        return CommandPolicyResult(
            False,
            "Canal de ejecución no permitido.",
        )

    # =========================================================
    # Command extraction
    # =========================================================

    @staticmethod
    def _extract_command(command: str) -> str:
        """
        Extract the executable / command name from the command line.

        Handles simple forms such as:

            echo hola
            echo.exe hola
            ECHO hola
            "echo" hola

        The result is normalized to lowercase.
        """

        command = command.strip()

        if not command:
            return ""

        # Remove a surrounding quote from the first token.
        if command.startswith('"'):
            closing_quote = command.find('"', 1)

            if closing_quote == -1:
                return ""

            token = command[1:closing_quote]

        elif command.startswith("'"):
            closing_quote = command.find("'", 1)

            if closing_quote == -1:
                return ""

            token = command[1:closing_quote]

        else:
            token = command.split(maxsplit=1)[0]

        token = token.strip().lower()

        # Extract only the executable filename if a Windows path
        # is supplied.
        token = token.replace("\\", "/")

        if "/" in token:
            token = token.rsplit("/", 1)[-1]

        # Remove common executable suffix.
        if token.endswith(".exe"):
            token = token[:-4]

        return token

    # =========================================================
    # Shell operator validation
    # =========================================================

    @classmethod
    def _check_shell_operators(
        cls,
        command: str,
    ) -> CommandPolicyResult:
        """
        Reject shell operators and redirections.

        Examples blocked:

            echo hola & format X:
            echo hola && shutdown
            echo hola || del archivo
            echo hola | powershell
            echo hola > archivo.txt
            echo hola >> archivo.txt
        """

        # -----------------------------------------------------
        # Multi-character operators first.
        # -----------------------------------------------------

        dangerous_sequences = {
            "&&",
            "||",
            ">>",
            "<<",
        }

        for operator in dangerous_sequences:
            if operator in command:
                return CommandPolicyResult(
                    False,
                    (
                        f"El operador '{operator}' no está permitido "
                        "por la política de seguridad."
                    ),
                )

        # -----------------------------------------------------
        # Single-character operators.
        # -----------------------------------------------------

        for operator in (
            "&",
            "|",
            ";",
            ">",
            "<",
        ):
            if operator in command:
                return CommandPolicyResult(
                    False,
                    (
                        f"El operador '{operator}' no está permitido "
                        "por la política de seguridad."
                    ),
                )

        return CommandPolicyResult(
            True,
            "No se han detectado operadores de shell peligrosos.",
        )