from __future__ import annotations

import math
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
from jarvis.security.voice_enrollment import (
    OwnerVoiceEnrollmentService,
)
from jarvis.security.voice_verifier import VoiceProfileStore


class SequentialBackend:
    model_id = "fake-enrollment-model"

    def __init__(self, embeddings) -> None:
        self.embeddings = list(embeddings)
        self.index = 0

    def embed(self, utterance):
        value = self.embeddings[self.index]
        self.index += 1
        return value


class VoiceEnrollmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)

        self.registry_path = root / "users.json"
        self.registry = UserRegistry(self.registry_path)
        self.store = VoiceProfileStore(root / "voice_profiles")

        self.owner = UserIdentity(
            user_id="owner-user",
            display_name="Owner",
            security_level=SecurityLevel.LEVEL_5,
            is_owner=True,
            voice_profile_id=None,
        )
        self.registry.add(self.owner)

        self.samples = [
            CapturedUtterance(f"sample-{i}".encode())
            for i in range(5)
        ]

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_enrollment_builds_profile_and_links_owner(self) -> None:
        backend = SequentialBackend(
            [
                (1.00, 0.00, 0.00),
                (0.99, 0.05, 0.00),
                (0.98, -0.04, 0.01),
                (0.97, 0.03, -0.02),
                (0.99, -0.02, 0.02),
            ]
        )

        service = OwnerVoiceEnrollmentService(
            self.registry,
            self.store,
            backend,
        )

        result = service.enroll(
            "owner-voice",
            self.samples,
        )

        self.assertEqual(result.sample_count, 5)
        self.assertEqual(
            result.profile.profile_id,
            "owner-voice",
        )
        self.assertEqual(
            result.profile.model_id,
            backend.model_id,
        )

        norm = math.sqrt(
            sum(
                value * value
                for value in result.profile.embedding
            )
        )
        self.assertAlmostEqual(norm, 1.0, places=6)

        stored = self.store.load("owner-voice")
        self.assertEqual(stored, result.profile)

        reloaded = UserRegistry(self.registry_path)
        owner = reloaded.get("owner-user")

        self.assertIsNotNone(owner)
        self.assertEqual(
            owner.voice_profile_id,
            "owner-voice",
        )

    def test_enrollment_reports_similarity_to_centroid(self) -> None:
        backend = SequentialBackend(
            [(1.0, 0.0)] * 5
        )

        service = OwnerVoiceEnrollmentService(
            self.registry,
            self.store,
            backend,
        )

        result = service.enroll(
            "owner-voice",
            self.samples,
        )

        self.assertAlmostEqual(
            result.mean_similarity,
            1.0,
        )
        self.assertAlmostEqual(
            result.minimum_similarity,
            1.0,
        )

    def test_too_few_samples_fail_closed(self) -> None:
        service = OwnerVoiceEnrollmentService(
            self.registry,
            self.store,
            SequentialBackend(
                [(1.0, 0.0)] * 4
            ),
        )

        with self.assertRaises(RuntimeError):
            service.enroll(
                "owner-voice",
                self.samples[:4],
            )

    def test_dimension_mismatch_fails_closed(self) -> None:
        service = OwnerVoiceEnrollmentService(
            self.registry,
            self.store,
            SequentialBackend(
                [
                    (1.0, 0.0),
                    (1.0, 0.0),
                    (1.0, 0.0),
                    (1.0, 0.0),
                    (1.0, 0.0, 0.0),
                ]
            ),
        )

        with self.assertRaises(RuntimeError):
            service.enroll(
                "owner-voice",
                self.samples,
            )

    def test_nonfinite_embedding_fails_closed(self) -> None:
        service = OwnerVoiceEnrollmentService(
            self.registry,
            self.store,
            SequentialBackend(
                [
                    (1.0, 0.0),
                    (1.0, 0.0),
                    (float("nan"), 0.0),
                    (1.0, 0.0),
                    (1.0, 0.0),
                ]
            ),
        )

        with self.assertRaises(RuntimeError):
            service.enroll(
                "owner-voice",
                self.samples,
            )

    def test_existing_profile_requires_explicit_overwrite(self) -> None:
        self.owner.voice_profile_id = "existing-profile"
        self.registry.save()

        service = OwnerVoiceEnrollmentService(
            self.registry,
            self.store,
            SequentialBackend(
                [(1.0, 0.0)] * 5
            ),
        )

        with self.assertRaises(RuntimeError):
            service.enroll(
                "owner-voice",
                self.samples,
            )


if __name__ == "__main__":
    unittest.main()
