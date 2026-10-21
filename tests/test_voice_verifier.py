from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.core.audio_input import CapturedUtterance
from jarvis.identity.models import UserIdentity
from jarvis.identity.registry import UserRegistry
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import VerifiedFactor
from jarvis.security.voice_verifier import (
    VoiceProfile,
    VoiceProfileStore,
    VoiceVerifier,
)


class FakeSpeakerBackend:
    model_id = "fake-speaker-v1"

    def __init__(self, embedding) -> None:
        self.embedding = embedding
        self.received = []

    def embed(self, utterance):
        self.received.append(utterance)
        return self.embedding


class VoiceVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)

        self.registry = UserRegistry(root / "users.json")
        self.store = VoiceProfileStore(root / "voice_profiles")

        self.owner = UserIdentity(
            user_id="owner-user",
            display_name="Owner",
            security_level=SecurityLevel.LEVEL_5,
            is_owner=True,
            voice_profile_id="owner-voice",
        )
        self.registry.add(self.owner)

        self.store.save(
            VoiceProfile(
                profile_id="owner-voice",
                model_id="fake-speaker-v1",
                embedding=(1.0, 0.0, 0.0),
            )
        )

        self.utterance = CapturedUtterance(b"voice")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def make_verifier(
        self,
        embedding,
        threshold=0.8,
    ) -> VoiceVerifier:
        return VoiceVerifier(
            self.registry,
            self.store,
            FakeSpeakerBackend(embedding),
            threshold=threshold,
        )

    def test_matching_voice_emits_owner_voice_factor(self) -> None:
        verifier = self.make_verifier(
            (0.99, 0.05, 0.0)
        )

        match = verifier.verify(self.utterance)

        self.assertTrue(match.accepted)
        self.assertIsNotNone(match.verification)
        self.assertEqual(
            match.verification.user_id,
            self.owner.user_id,
        )
        self.assertEqual(
            match.verification.factor,
            VerifiedFactor.OWNER_VOICE,
        )

    def test_nonmatching_voice_does_not_emit_verification(self) -> None:
        verifier = self.make_verifier(
            (0.0, 1.0, 0.0)
        )

        match = verifier.verify(self.utterance)

        self.assertFalse(match.accepted)
        self.assertIsNone(match.verification)

    def test_backend_receives_the_original_utterance(self) -> None:
        backend = FakeSpeakerBackend(
            (1.0, 0.0, 0.0)
        )
        verifier = VoiceVerifier(
            self.registry,
            self.store,
            backend,
            threshold=0.8,
        )

        verifier.verify(self.utterance)

        self.assertEqual(
            backend.received,
            [self.utterance],
        )
        self.assertIs(
            backend.received[0],
            self.utterance,
        )

    def test_missing_voice_profile_fails_closed(self) -> None:
        root = Path(self.tempdir.name)
        registry = UserRegistry(root / "other-users.json")

        registry.add(
            UserIdentity(
                user_id="owner-no-voice",
                display_name="Owner",
                security_level=SecurityLevel.LEVEL_5,
                is_owner=True,
                voice_profile_id=None,
            )
        )

        verifier = VoiceVerifier(
            registry,
            self.store,
            FakeSpeakerBackend((1.0, 0.0, 0.0)),
            threshold=0.8,
        )

        with self.assertRaises(RuntimeError):
            verifier.verify(self.utterance)

    def test_profile_from_other_model_fails_closed(self) -> None:
        self.store.save(
            VoiceProfile(
                profile_id="owner-voice",
                model_id="another-model",
                embedding=(1.0, 0.0, 0.0),
            ),
            overwrite=True,
        )

        verifier = self.make_verifier(
            (1.0, 0.0, 0.0)
        )

        with self.assertRaises(RuntimeError):
            verifier.verify(self.utterance)

    def test_embedding_dimension_mismatch_fails_closed(self) -> None:
        verifier = self.make_verifier(
            (1.0, 0.0)
        )

        with self.assertRaises(RuntimeError):
            verifier.verify(self.utterance)

    def test_multiple_owners_fail_closed(self) -> None:
        self.registry.add(
            UserIdentity(
                user_id="second-owner",
                display_name="Second",
                security_level=SecurityLevel.LEVEL_5,
                is_owner=True,
                voice_profile_id="second-profile",
            )
        )

        verifier = self.make_verifier(
            (1.0, 0.0, 0.0)
        )

        with self.assertRaises(RuntimeError):
            verifier.verify(self.utterance)

    def test_profile_id_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.load("../owner")

    def test_threshold_outside_cosine_range_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            VoiceVerifier(
                self.registry,
                self.store,
                FakeSpeakerBackend((1.0, 0.0, 0.0)),
                threshold=1.1,
            )


if __name__ == "__main__":
    unittest.main()
