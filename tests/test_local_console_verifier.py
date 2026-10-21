from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.identity.models import UserIdentity
from jarvis.identity.registry import UserRegistry
from jarvis.security.levels import SecurityLevel
from jarvis.security.local_console_verifier import LocalConsoleVerifier
from jarvis.security.policy_core import VerifiedFactor


class LocalConsoleVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)

        self.registry = UserRegistry(root / "users.json")
        self.devices_path = root / "trusted_devices.json"

        self.owner = UserIdentity(
            user_id="owner-user",
            display_name="Owner",
            security_level=SecurityLevel.LEVEL_5,
            is_owner=True,
        )
        self.registry.add(self.owner)

        self.token = "correct-device-secret"
        self.device_id = "desktop-main"

        self.write_device(
            device_id=self.device_id,
            user_id=self.owner.user_id,
            token=self.token,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_device(
        self,
        *,
        device_id: str,
        user_id: str,
        token: str,
        enabled: bool = True,
        kind: str = "local_console",
    ) -> None:
        token_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        payload = {
            "devices": {
                device_id: {
                    "user_id": user_id,
                    "kind": kind,
                    "enabled": enabled,
                    "token_sha256": token_hash,
                }
            }
        }

        self.devices_path.write_text(
            json.dumps(payload),
            encoding="utf-8",
        )

    def make_verifier(
        self,
        *,
        device_id: str | None = None,
        token: str | None = None,
    ) -> LocalConsoleVerifier:
        return LocalConsoleVerifier(
            self.registry,
            device_id=self.device_id if device_id is None else device_id,
            device_token=self.token if token is None else token,
            trusted_devices_path=self.devices_path,
        )

    def test_valid_registered_device_verifies_owner(self) -> None:
        result = self.make_verifier().verify()

        self.assertEqual(result.user_id, self.owner.user_id)
        self.assertEqual(result.factor, VerifiedFactor.OWNER_DEVICE)
        self.assertEqual(
            result.issuer_id,
            f"local-console:{self.device_id}",
        )

    def test_wrong_device_token_is_rejected(self) -> None:
        verifier = self.make_verifier(token="wrong-secret")

        with self.assertRaises(RuntimeError):
            verifier.verify()

    def test_disabled_device_is_rejected(self) -> None:
        self.write_device(
            device_id=self.device_id,
            user_id=self.owner.user_id,
            token=self.token,
            enabled=False,
        )

        with self.assertRaises(RuntimeError):
            self.make_verifier().verify()

    def test_unknown_device_is_rejected(self) -> None:
        verifier = self.make_verifier(
            device_id="unknown-device",
        )

        with self.assertRaises(RuntimeError):
            verifier.verify()

    def test_missing_credentials_are_rejected(self) -> None:
        verifier = LocalConsoleVerifier(
            self.registry,
            device_id=None,
            device_token=None,
            trusted_devices_path=self.devices_path,
        )

        with self.assertRaises(RuntimeError):
            verifier.verify()

    def test_non_owner_device_cannot_emit_owner_factor(self) -> None:
        other = UserIdentity(
            user_id="ordinary-user",
            display_name="Other",
            security_level=SecurityLevel.LEVEL_2,
            is_owner=False,
        )
        self.registry.add(other)

        self.write_device(
            device_id=self.device_id,
            user_id=other.user_id,
            token=self.token,
        )

        with self.assertRaises(RuntimeError):
            self.make_verifier().verify()

    def test_wrong_device_kind_is_rejected(self) -> None:
        self.write_device(
            device_id=self.device_id,
            user_id=self.owner.user_id,
            token=self.token,
            kind="remote_client",
        )

        with self.assertRaises(RuntimeError):
            self.make_verifier().verify()

    def test_missing_device_registry_fails_closed(self) -> None:
        self.devices_path.unlink()

        with self.assertRaises(RuntimeError):
            self.make_verifier().verify()


if __name__ == "__main__":
    unittest.main()
