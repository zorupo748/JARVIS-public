from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
from jarvis.security.policy_core import PresenceState, VerifiedFactor
from jarvis.security.session import SecuritySession
from jarvis.security.verification import (
    VerificationIssuer,
    VerificationResult,
)


NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)


class VerificationTests(unittest.TestCase):
    def test_trusted_issuer_emits_fresh_valid_result(self) -> None:
        issuer = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )

        result = issuer.issue("owner-user", VerifiedFactor.OWNER_DEVICE)

        self.assertTrue(issuer.validates(result, now=NOW))
        self.assertEqual(result.user_id, "owner-user")
        self.assertEqual(result.factor, VerifiedFactor.OWNER_DEVICE)

    def test_issuer_cannot_emit_disallowed_factor(self) -> None:
        issuer = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )

        with self.assertRaises(ValueError):
            issuer.issue("owner-user", VerifiedFactor.OWNER_FACE)

    def test_forged_result_with_same_issuer_id_is_rejected(self) -> None:
        issuer = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )

        forged = VerificationResult(
            verification_id="forged",
            issuer_id="local-console",
            user_id="owner-user",
            factor=VerifiedFactor.OWNER_DEVICE,
            issued_at=NOW,
            _capability=object(),
        )

        self.assertFalse(issuer.validates(forged, now=NOW))

    def test_expired_verification_is_rejected(self) -> None:
        issuer = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )
        result = issuer.issue("owner-user", VerifiedFactor.OWNER_DEVICE)

        self.assertFalse(
            issuer.validates(
                result,
                now=NOW + timedelta(seconds=61),
            )
        )

    def test_future_verification_is_rejected(self) -> None:
        issuer = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )
        result = issuer.issue("owner-user", VerifiedFactor.OWNER_DEVICE)

        self.assertFalse(
            issuer.validates(
                result,
                now=NOW - timedelta(seconds=1),
            )
        )


class SecuritySessionVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        registry_path = Path(self.tempdir.name) / "users.json"
        self.registry = UserRegistry(registry_path)

        self.owner = UserIdentity(
            user_id="owner-user",
            display_name="Owner",
            security_level=SecurityLevel.LEVEL_3,
            is_owner=True,
        )
        self.other = UserIdentity(
            user_id="other-user",
            display_name="Other",
            security_level=SecurityLevel.LEVEL_2,
            is_owner=False,
        )

        self.registry.add(self.owner)
        self.registry.add(self.other)

        self.issuer = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )

        self.session = SecuritySession(
            registry=self.registry,
            trusted_issuers=(self.issuer,),
            now=lambda: NOW,
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_trusted_owner_device_verification_establishes_identity(self) -> None:
        self.session.begin_interaction("owner-user")
        result = self.issuer.issue(
            "owner-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        accepted = self.session.apply_verification(result)
        context = self.session.context()

        self.assertTrue(accepted)
        self.assertEqual(context.identity, self.owner)
        self.assertEqual(context.presence, PresenceState.PRESENT)
        self.assertIn(
            VerifiedFactor.OWNER_DEVICE,
            context.verified_factors,
        )
        self.assertTrue(context.is_verified_owner)

    def test_verification_cannot_be_reused(self) -> None:
        self.session.begin_interaction("owner-user")
        result = self.issuer.issue(
            "owner-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        self.assertTrue(self.session.apply_verification(result))
        self.assertFalse(self.session.apply_verification(result))

    def test_untrusted_issuer_is_rejected(self) -> None:
        rogue = VerificationIssuer(
            "rogue-device",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )

        self.session.begin_interaction("owner-user")
        result = rogue.issue(
            "owner-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        self.assertFalse(self.session.apply_verification(result))
        self.assertIsNone(self.session.context().identity)

    def test_same_issuer_name_with_wrong_capability_is_rejected(self) -> None:
        rogue = VerificationIssuer(
            "local-console",
            {VerifiedFactor.OWNER_DEVICE},
            now=lambda: NOW,
        )

        self.session.begin_interaction("owner-user")
        result = rogue.issue(
            "owner-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        self.assertFalse(self.session.apply_verification(result))
        self.assertIsNone(self.session.context().identity)

    def test_claimed_identity_must_match_verified_identity(self) -> None:
        self.session.begin_interaction("other-user")
        result = self.issuer.issue(
            "owner-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        self.assertFalse(self.session.apply_verification(result))
        self.assertIsNone(self.session.context().identity)

    def test_owner_factor_cannot_promote_non_owner(self) -> None:
        self.session.begin_interaction("other-user")
        result = self.issuer.issue(
            "other-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        self.assertFalse(self.session.apply_verification(result))
        self.assertIsNone(self.session.context().identity)

    def test_unknown_user_is_rejected(self) -> None:
        self.session.begin_interaction("missing-user")
        result = self.issuer.issue(
            "missing-user",
            VerifiedFactor.OWNER_DEVICE,
        )

        self.assertFalse(self.session.apply_verification(result))
        self.assertIsNone(self.session.context().identity)


if __name__ == "__main__":
    unittest.main()
