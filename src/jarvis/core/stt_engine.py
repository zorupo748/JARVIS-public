from __future__ import annotations

import io
import os
from dataclasses import dataclass

import speech_recognition as sr
from faster_whisper import WhisperModel

from .audio_input import CapturedUtterance


# Silenciar el warning de HuggingFace en Windows.
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"


@dataclass(frozen=True)
class WhisperRuntimeConfig:
    device: str
    compute_type: str
    cpu_threads: int
    num_workers: int


def _positive_integer_from_environment(name: str, default: int) -> int:
    value = os.getenv(name, "").strip()
    if not value:
        return default

    try:
        parsed = int(value)
    except ValueError:
        return default

    return parsed if parsed > 0 else default


def get_whisper_runtime_config() -> WhisperRuntimeConfig:
    """Read Faster-Whisper settings from the process environment only."""

    device = os.getenv("JARVIS_WHISPER_DEVICE", "cpu").strip().lower() or "cpu"
    default_compute_type = "float16" if device == "cuda" else "int8"
    compute_type = (
        os.getenv("JARVIS_WHISPER_COMPUTE_TYPE", default_compute_type).strip()
        or default_compute_type
    )

    return WhisperRuntimeConfig(
        device=device,
        compute_type=compute_type,
        cpu_threads=_positive_integer_from_environment(
            "JARVIS_WHISPER_CPU_THREADS", 4
        ),
        num_workers=_positive_integer_from_environment(
            "JARVIS_WHISPER_NUM_WORKERS", 1
        ),
    )


def _whisper_startup_message(config: WhisperRuntimeConfig) -> str:
    if config.device == "cuda":
        return (
            " > [OK] Whisper cargado en GPU "
            f"(CUDA, {config.compute_type})."
        )

    return (
        f" > [OK] Whisper cargado en {config.device.upper()} "
        f"({config.compute_type.upper()}, {config.cpu_threads} threads)."
    )


class STTEngine:
    def __init__(self, model_size: str = "small") -> None:
        print(" > [STT] Cargando modelo neuronal de escucha (Whisper)...")

        config = get_whisper_runtime_config()
        try:
            self.model = WhisperModel(
                model_size,
                device=config.device,
                compute_type=config.compute_type,
                cpu_threads=config.cpu_threads,
                num_workers=config.num_workers,
            )
        except Exception:
            if config.device != "cuda":
                raise

            config = WhisperRuntimeConfig(
                device="cpu",
                compute_type="int8",
                cpu_threads=config.cpu_threads,
                num_workers=config.num_workers,
            )
            self.model = WhisperModel(
                model_size,
                device=config.device,
                compute_type=config.compute_type,
                cpu_threads=config.cpu_threads,
                num_workers=config.num_workers,
            )
            print(" > [WARN] CUDA no disponible; usando la configuración CPU.")

        self.whisper_config = config
        print(_whisper_startup_message(config))

        self.recognizer = sr.Recognizer()
        self.recognizer.dynamic_energy_threshold = True
        self.recognizer.pause_threshold = 1.0

    def capture(self) -> CapturedUtterance | None:
        """
        Capture one microphone utterance and normalize it to 16 kHz PCM WAV.

        The returned audio can be consumed by both STT and future speaker
        verification without recording the user twice.
        """

        try:
            with sr.Microphone() as source:
                print("\n[STT] Ajustando ruido de fondo...")
                self.recognizer.adjust_for_ambient_noise(
                    source,
                    duration=1.0,
                )

                print("[STT] Te escucho. Habla ahora...")

                audio = self.recognizer.listen(
                    source,
                    timeout=5,
                    phrase_time_limit=10,
                )

            wav_bytes = audio.get_wav_data(
                convert_rate=16000,
                convert_width=2,
            )

            return CapturedUtterance(
                wav_bytes=wav_bytes,
                sample_rate=16000,
                sample_width=2,
            )

        except sr.WaitTimeoutError:
            print(" > [STT] No se detectó voz (Timeout).")
            return None
        except Exception as exc:
            print(f" > [ERROR STT CAPTURE]: {exc}")
            return None

    def transcribe(self, utterance: CapturedUtterance) -> str:
        """Transcribe one previously captured utterance."""

        try:
            print(" > [STT] Procesando voz...")

            segments, _info = self.model.transcribe(
                io.BytesIO(utterance.wav_bytes),
                language="es",
                beam_size=1,
                vad_filter=True,
                vad_parameters=dict(
                    min_silence_duration_ms=500,
                ),
                condition_on_previous_text=False,
                temperature=0.0,
                compression_ratio_threshold=1.5,
            )

            texto = " ".join(
                segment.text for segment in segments
            ).strip()

            # Si hay muchas palabras y casi todas son iguales,
            # probablemente Whisper ha entrado en un bucle.
            palabras = texto.split()

            if (
                len(palabras) > 10
                and len(set(palabras)) < len(palabras) / 3
            ):
                print(" > [STT] Bucle de red neuronal ignorado.")
                return ""

            frases_basura = [
                "oh no",
                "no no",
                "suscríbete",
                "amara.org",
                "gracias",
            ]

            if (
                any(
                    basura in texto.lower()
                    for basura in frases_basura
                )
                or len(texto) < 3
            ):
                print(" > [STT] Ruido estático ignorado.")
                return ""

            return texto

        except Exception as exc:
            print(f" > [ERROR STT]: {exc}")
            return ""

    def listen(self) -> str:
        """
        Compatibility wrapper.

        Existing callers keep the old API while capture and transcription
        remain independently reusable.
        """

        utterance = self.capture()

        if utterance is None:
            return ""

        return self.transcribe(utterance)
