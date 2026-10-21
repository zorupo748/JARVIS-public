from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import PresenceState
from jarvis.security.session import SecuritySession


class SecuritySessionTests(unittest.TestCase):
    def test_new_session_starts_unknown_and_unprivileged(self) -> None:
        session = SecuritySession()

        context = session.context()

        self.assertIsNone(context.identity)
        self.assertIsNone(context.claimed_user_id)
        self.assertEqual(context.presence, PresenceState.UNKNOWN)
        self.assertEqual(context.effective_level, SecurityLevel.LEVEL_0)
        self.assertFalse(context.is_verified_owner)
        self.assertEqual(context.verified_factors, frozenset())

    def test_begin_interaction_marks_presence_without_authenticating(self) -> None:
        session = SecuritySession()

        session.begin_interaction()

        context = session.context()

        self.assertEqual(context.presence, PresenceState.PRESENT)
        self.assertIsNone(context.identity)
        self.assertEqual(context.effective_level, SecurityLevel.LEVEL_0)

    def test_claimed_user_id_does_not_authenticate_or_raise_privileges(self) -> None:
        session = SecuritySession()

        session.begin_interaction("owner-user")

        context = session.context()

        self.assertEqual(context.claimed_user_id, "owner-user")
        self.assertIsNone(context.identity)
        self.assertEqual(context.effective_level, SecurityLevel.LEVEL_0)
        self.assertFalse(context.is_owner_identity)
        self.assertFalse(context.is_verified_owner)
        self.assertEqual(context.verified_factors, frozenset())

    def test_empty_claim_is_not_preserved(self) -> None:
        session = SecuritySession()

        session.begin_interaction("   ")

        self.assertIsNone(session.context().claimed_user_id)

    def test_clear_removes_interaction_state(self) -> None:
        session = SecuritySession()
        session.begin_interaction("some-user")

        session.clear()

        context = session.context()

        self.assertIsNone(context.identity)
        self.assertIsNone(context.claimed_user_id)
        self.assertEqual(context.presence, PresenceState.UNKNOWN)
        self.assertEqual(context.effective_level, SecurityLevel.LEVEL_0)


if __name__ == "__main__":
    unittest.main()
