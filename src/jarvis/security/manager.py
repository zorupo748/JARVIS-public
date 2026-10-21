from __future__ import annotations

from .levels import SecurityLevel, AuthorityLevel
from .models import (
    AuthorizationRequest,
    AuthorizationStatus,
    SecurityAction,
    ExecutionChannel,
)
from .policies import is_super_action


class SecurityManager:
    """
    Central authorization system for JARVIS.

    Security permissions belong to the authenticated user.
    JARVIS itself does not have a security level.

    Normal security levels:
        Level 0 -> Level 5

    SUPER:
        Special owner-only authority.
        It is NOT a security level and cannot be reached
        by increasing a user's normal security level.
    """

    def authorize(
        self,
        user,
        action: SecurityAction,
    ) -> AuthorizationRequest:
        """
        Determine whether a user is authorized to perform an action.

        This method only decides authorization.
        It does not execute the action.
        """

        required_level = action.required_level

        # ---------------------------------------------------------
        # No authenticated user
        # ---------------------------------------------------------

        if user is None:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.DENIED,
                reason=(
                    "No hay ningún usuario autenticado. "
                    "JARVIS no puede ejecutar esta operación."
                ),
                required_level=required_level,
            )

        # ---------------------------------------------------------
        # SUPER operations
        # ---------------------------------------------------------

        if is_super_action(action.action):
            return self._authorize_super(
                user=user,
                action=action,
            )

        # ---------------------------------------------------------
        # Validate user's security level
        # ---------------------------------------------------------

        user_level = user.security_level

        if not isinstance(user_level, SecurityLevel):
            user_level = SecurityLevel.LEVEL_0

        # ---------------------------------------------------------
        # Normal security level check
        # ---------------------------------------------------------

        if user_level < required_level:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.DENIED,
                reason=(
                    f"La operación requiere Nivel "
                    f"{required_level.value}, pero "
                    f"{user.display_name} tiene Nivel "
                    f"{user_level.value}."
                ),
                required_level=required_level,
            )

        # ---------------------------------------------------------
        # Shell execution
        # ---------------------------------------------------------
        #
        # CMD and PowerShell NEVER grant additional permissions.
        #
        # The user must already have the required security level.
        # Even then, shell execution requires explicit confirmation.
        #

        if action.execution_channel in {
            ExecutionChannel.CMD,
            ExecutionChannel.POWERSHELL,
        }:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.REQUIRES_CONFIRMATION,
                reason=(
                    "La operación utiliza una consola del sistema. "
                    "El usuario tiene el nivel necesario, pero la "
                    "ejecución mediante consola requiere confirmación "
                    "explícita."
                ),
                required_level=required_level,
                requires_confirmation=True,
            )

        # ---------------------------------------------------------
        # Level 5
        # ---------------------------------------------------------
        #
        # Level 5 is the highest normal security level.
        # Operations at this level require additional identity
        # verification.
        #

        if required_level >= SecurityLevel.LEVEL_5:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.REQUIRES_IDENTITY,
                reason=(
                    "Esta operación requiere Nivel 5. "
                    "Se necesita una verificación adicional "
                    "de identidad y confirmación explícita."
                ),
                required_level=required_level,
                requires_confirmation=True,
                requires_identity=True,
            )

        # ---------------------------------------------------------
        # Level 4
        # ---------------------------------------------------------

        if required_level >= SecurityLevel.LEVEL_4:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.REQUIRES_IDENTITY,
                reason=(
                    "Esta operación tiene un nivel de riesgo elevado. "
                    "Se necesita una verificación adicional de identidad "
                    "y confirmación explícita."
                ),
                required_level=required_level,
                requires_confirmation=True,
                requires_identity=True,
            )

        # ---------------------------------------------------------
        # Level 3
        # ---------------------------------------------------------
        #
        # Level 3 introduces explicit confirmation.
        # Later this confirmation will be performed through voice.
        #

        if required_level >= SecurityLevel.LEVEL_3:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.REQUIRES_CONFIRMATION,
                reason=(
                    "Esta operación puede modificar archivos, "
                    "ejecutar herramientas o interactuar con el sistema. "
                    "Se requiere confirmación explícita del usuario."
                ),
                required_level=required_level,
                requires_confirmation=True,
            )

        # ---------------------------------------------------------
        # Level 0-2
        # ---------------------------------------------------------

        return AuthorizationRequest(
            action=action,
            status=AuthorizationStatus.ALLOWED,
            reason="Operación permitida.",
            required_level=required_level,
        )

    def _authorize_super(
        self,
        user,
        action: SecurityAction,
    ) -> AuthorizationRequest:
        """
        Authorize an owner-only SUPER operation.

        SUPER is deliberately not represented by SecurityLevel.
        """

        if not user.is_owner:
            return AuthorizationRequest(
                action=action,
                status=AuthorizationStatus.DENIED,
                reason=(
                    "Esta operación requiere autoridad SUPER. "
                    "El usuario actual no es el propietario."
                ),
                required_level=None,
            )

        return AuthorizationRequest(
            action=action,
            status=AuthorizationStatus.REQUIRES_IDENTITY,
            reason=(
                f"La operación requiere autoridad "
                f"{AuthorityLevel.SUPER}. "
                "El propietario debe autenticarse y confirmar "
                "explícitamente la operación crítica."
            ),
            required_level=None,
            requires_confirmation=True,
            requires_identity=True,
            confirmation_phrase="Autorizo esta operación crítica",
        )