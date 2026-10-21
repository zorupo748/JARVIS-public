"""Verification for text entered through a trusted local JARVIS console."""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path

from jarvis.identity.registry import UserRegistry

from .policy_core import VerifiedFactor
from .verification import VerificationIssuer, VerificationResult


class LocalConsoleVerifier:
    """
    Verify a particular registered local device.

    An interactive terminal alone is not sufficient. The installation
    must also possess the secret token associated with its device record.
    """

    def __init__(
        self,
        registry: UserRegistry,
        *,
        device_id: str | None,
        device_token: str | None,
        trusted_devices_path: Path,
        issuer: VerificationIssuer | None = None,
    ) -> None:
        self._registry = registry
        self._device_id = (device_id or "").strip()
        self._device_token = (device_token or "").strip()
        self._trusted_devices_path = Path(trusted_devices_path)

        issuer_id = (
            f"local-console:{self._device_id}"
            if self._device_id
            else "local-console:unconfigured"
        )

        self._issuer = issuer or VerificationIssuer(
            issuer_id,
            {VerifiedFactor.OWNER_DEVICE},
        )

    @property
    def issuer(self) -> VerificationIssuer:
        return self._issuer

    def verify(self) -> VerificationResult:
        if not self._device_id or not self._device_token:
            raise RuntimeError(
                "El dispositivo local no tiene credenciales configuradas."
            )

        record = self._load_device_record()

        if not record.get("enabled", False):
            raise RuntimeError("El dispositivo local está deshabilitado.")

        if record.get("kind") != "local_console":
            raise RuntimeError(
                "La credencial registrada no pertenece a una consola local."
            )

        expected_hash = str(record.get("token_sha256") or "").strip().lower()
        if len(expected_hash) != 64:
            raise RuntimeError(
                "El registro del dispositivo no contiene una huella válida."
            )

        actual_hash = hashlib.sha256(
            self._device_token.encode("utf-8")
        ).hexdigest()

        if not secrets.compare_digest(actual_hash, expected_hash):
            raise RuntimeError(
                "La credencial del dispositivo local no es válida."
            )

        user_id = str(record.get("user_id") or "").strip()
        if not user_id:
            raise RuntimeError(
                "El dispositivo no tiene un usuario asociado."
            )

        user = self._registry.get(user_id)

        if user is None:
            raise RuntimeError(
                "El usuario asociado al dispositivo no existe."
            )

        if not user.is_owner:
            raise RuntimeError(
                "El dispositivo local no está asociado a un propietario."
            )

        return self._issuer.issue(
            user.user_id,
            VerifiedFactor.OWNER_DEVICE,
        )

    def _load_device_record(self) -> dict:
        try:
            payload = json.loads(
                self._trusted_devices_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "No se pudo leer el registro de dispositivos de confianza."
            ) from exc

        devices = payload.get("devices")
        if not isinstance(devices, dict):
            raise RuntimeError(
                "El registro de dispositivos tiene un formato inválido."
            )

        record = devices.get(self._device_id)
        if not isinstance(record, dict):
            raise RuntimeError(
                "Este dispositivo no está registrado como dispositivo de confianza."
            )

        return record


__all__ = ["LocalConsoleVerifier"]
