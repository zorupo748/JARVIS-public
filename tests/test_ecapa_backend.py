from __future__ import annotations

import io
import sys
import unittest
import wave
from pathlib import Path

import torch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.core.audio_input import CapturedUtterance
from jarvis.security.ecapa_backend import (
    ECAPA_MODEL_ID,
    EcapaSpeakerBackend,
)


def make_wav_bytes(
    *,
    sample_rate: int = 16000,
    channels: int = 1,
    frames: int = 1600,
) -> bytes:
    buffer = io.BytesIO()

    with wave.open(buffer, "wb") as wav:
        wav.setnchannels(channels)
        wav.setsampwidth(2)
        wav.setframerate(sample_rate)

        samples = bytearray()

        for index in range(frames):
            value = 1000 if index % 2 == 0 else -1000
            encoded = int(value).to_bytes(
                2,
                byteorder="little",
                signed=True,
            )

            for _ in range(channels):
                samples.extend(encoded)

        wav.writeframes(bytes(samples))

    return buffer.getvalue()


class FakeClassifier:
    def __init__(
        self,
        embedding: torch.Tensor | None = None,
    ) -> None:
        self.embedding = (
            embedding
            if embedding is not None
            else torch.tensor(
                [[[1.0, 2.0, 3.0]]],
                dtype=torch.float32,
            )
        )

        self.received = []
        self.normalize_values = []

    def encode_batch(self, waveform, normalize=False):
        self.received.append(waveform.detach().cpu())
        self.normalize_values.append(normalize)
        return self.embedding


class EcapaSpeakerBackendTests(unittest.TestCase):
    def test_model_id_matches_enrollment_model(self) -> None:
        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=FakeClassifier(),
        )

        self.assertEqual(
            backend.model_id,
            ECAPA_MODEL_ID,
        )

    def test_valid_wav_returns_flat_embedding(self) -> None:
        classifier = FakeClassifier()

        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=classifier,
        )

        utterance = CapturedUtterance(
            make_wav_bytes()
        )

        embedding = backend.embed(utterance)

        self.assertEqual(
            embedding,
            (1.0, 2.0, 3.0),
        )
        self.assertEqual(
            classifier.normalize_values,
            [True],
        )

    def test_classifier_receives_mono_batch(self) -> None:
        classifier = FakeClassifier()

        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=classifier,
        )

        utterance = CapturedUtterance(
            make_wav_bytes(
                channels=2,
            )
        )

        backend.embed(utterance)

        received = classifier.received[0]

        self.assertEqual(received.ndim, 2)
        self.assertEqual(received.shape[0], 1)

    def test_non_16khz_audio_is_resampled(self) -> None:
        classifier = FakeClassifier()

        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=classifier,
        )

        utterance = CapturedUtterance(
            make_wav_bytes(
                sample_rate=8000,
                frames=800,
            ),
            sample_rate=8000,
        )

        backend.embed(utterance)

        received = classifier.received[0]

        self.assertGreater(
            received.shape[1],
            800,
        )

    def test_empty_audio_fails_closed(self) -> None:
        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=FakeClassifier(),
        )

        with self.assertRaises(RuntimeError):
            backend.embed(
                CapturedUtterance(b"")
            )

    def test_invalid_wav_fails_closed(self) -> None:
        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=FakeClassifier(),
        )

        with self.assertRaises(RuntimeError):
            backend.embed(
                CapturedUtterance(
                    b"this-is-not-a-wav"
                )
            )

    def test_nonfinite_embedding_fails_closed(self) -> None:
        classifier = FakeClassifier(
            torch.tensor(
                [[[1.0, float("nan")]]]
            )
        )

        backend = EcapaSpeakerBackend(
            device="cpu",
            classifier=classifier,
        )

        with self.assertRaises(RuntimeError):
            backend.embed(
                CapturedUtterance(
                    make_wav_bytes()
                )
            )


if __name__ == "__main__":
    unittest.main()
