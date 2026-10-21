from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


try:
    import speech_recognition  # noqa: F401
except ModuleNotFoundError:
    speech_recognition_stub = types.ModuleType("speech_recognition")
    speech_recognition_stub.Recognizer = type("Recognizer", (), {})
    speech_recognition_stub.Microphone = type("Microphone", (), {})
    speech_recognition_stub.WaitTimeoutError = type("WaitTimeoutError", (Exception,), {})
    sys.modules["speech_recognition"] = speech_recognition_stub

try:
    import faster_whisper  # noqa: F401
except ModuleNotFoundError:
    faster_whisper_stub = types.ModuleType("faster_whisper")
    faster_whisper_stub.WhisperModel = type("WhisperModel", (), {})
    sys.modules["faster_whisper"] = faster_whisper_stub


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.core.audio_input import CapturedUtterance
import jarvis.core.stt_engine as stt_engine
from jarvis.core.stt_engine import STTEngine


class FakeSegment:
    def __init__(self, text: str) -> None:
        self.text = text


class FakeWhisperModel:
    def __init__(self, texts: list[str]) -> None:
        self.texts = texts
        self.received_bytes: bytes | None = None
        self.kwargs: dict | None = None

    def transcribe(self, stream, **kwargs):
        self.received_bytes = stream.read()
        self.kwargs = kwargs
        return [FakeSegment(text) for text in self.texts], object()


class STTConfigurationTests(unittest.TestCase):
    def test_defaults_use_cpu_int8_and_pass_all_runtime_arguments(self) -> None:
        with patch.dict(stt_engine.os.environ, {}, clear=True), patch.object(
            stt_engine,
            "WhisperModel",
        ) as whisper_model, patch.object(stt_engine.sr, "Recognizer"):
            engine = STTEngine()

        whisper_model.assert_called_once_with(
            "small",
            device="cpu",
            compute_type="int8",
            cpu_threads=4,
            num_workers=1,
        )
        self.assertEqual(engine.whisper_config.device, "cpu")
        self.assertEqual(engine.whisper_config.compute_type, "int8")
        self.assertEqual(engine.whisper_config.cpu_threads, 4)
        self.assertEqual(engine.whisper_config.num_workers, 1)

    def test_cuda_environment_is_forwarded_to_whisper_model(self) -> None:
        environment = {
            "JARVIS_WHISPER_DEVICE": "cuda",
            "JARVIS_WHISPER_COMPUTE_TYPE": "float16",
            "JARVIS_WHISPER_CPU_THREADS": "6",
            "JARVIS_WHISPER_NUM_WORKERS": "2",
        }
        with patch.dict(stt_engine.os.environ, environment, clear=True), patch.object(
            stt_engine,
            "WhisperModel",
        ) as whisper_model, patch.object(stt_engine.sr, "Recognizer"):
            engine = STTEngine()

        whisper_model.assert_called_once_with(
            "small",
            device="cuda",
            compute_type="float16",
            cpu_threads=6,
            num_workers=2,
        )
        self.assertEqual(engine.whisper_config.device, "cuda")
        self.assertEqual(engine.whisper_config.compute_type, "float16")


    def test_cuda_uses_float16_when_compute_type_is_not_configured(self) -> None:
        with patch.dict(
            stt_engine.os.environ,
            {"JARVIS_WHISPER_DEVICE": "cuda"},
            clear=True,
        ):
            config = stt_engine.get_whisper_runtime_config()

        self.assertEqual(config.compute_type, "float16")
        self.assertEqual(config.cpu_threads, 4)
        self.assertEqual(config.num_workers, 1)


class STTAudioFlowTests(unittest.TestCase):
    def make_engine(self, texts: list[str]) -> STTEngine:
        engine = STTEngine.__new__(STTEngine)
        engine.model = FakeWhisperModel(texts)
        return engine

    def test_transcribe_reuses_captured_wav_bytes(self) -> None:
        engine = self.make_engine([" hola", " mundo"])
        utterance = CapturedUtterance(b"fake-wav-data")

        text = engine.transcribe(utterance)

        self.assertEqual(text, "hola  mundo")
        self.assertEqual(
            engine.model.received_bytes,
            b"fake-wav-data",
        )
        self.assertEqual(
            engine.model.kwargs["language"],
            "es",
        )

    def test_transcribe_rejects_repetitive_whisper_loop(self) -> None:
        engine = self.make_engine(
            ["hola " * 12]
        )

        result = engine.transcribe(
            CapturedUtterance(b"audio")
        )

        self.assertEqual(result, "")

    def test_transcribe_rejects_known_garbage(self) -> None:
        engine = self.make_engine(["gracias"])

        result = engine.transcribe(
            CapturedUtterance(b"audio")
        )

        self.assertEqual(result, "")

    def test_listen_returns_empty_when_capture_fails(self) -> None:
        engine = STTEngine.__new__(STTEngine)
        engine.capture = lambda: None

        result = engine.listen()

        self.assertEqual(result, "")

    def test_listen_passes_same_capture_to_transcription(self) -> None:
        engine = STTEngine.__new__(STTEngine)

        utterance = CapturedUtterance(b"same-audio")
        received = []

        engine.capture = lambda: utterance

        def fake_transcribe(value):
            received.append(value)
            return "texto"

        engine.transcribe = fake_transcribe

        result = engine.listen()

        self.assertEqual(result, "texto")
        self.assertEqual(received, [utterance])
        self.assertIs(received[0], utterance)


if __name__ == "__main__":
    unittest.main()
