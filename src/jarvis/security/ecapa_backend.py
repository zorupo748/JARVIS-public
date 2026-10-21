"""SpeechBrain ECAPA speaker-embedding backend."""

from __future__ import annotations

import io
import math
from pathlib import Path
from typing import Any

import torch
import torchaudio
from speechbrain.inference.speaker import EncoderClassifier
from speechbrain.utils.fetching import LocalStrategy

from jarvis.core.audio_input import CapturedUtterance


ECAPA_MODEL_ID = "speechbrain/spkrec-ecapa-voxceleb"
ECAPA_SAMPLE_RATE = 16000


class EcapaSpeakerBackend:
    """Convert captured speech into a SpeechBrain ECAPA speaker embedding."""

    def __init__(
        self,
        *,
        savedir: Path | str = "models/spkrec-ecapa-voxceleb",
        device: str | None = None,
        classifier: Any | None = None,
    ) -> None:
        if device is None:
            device = "cuda:0" if torch.cuda.is_available() else "cpu"

        self._device = torch.device(device)

        if classifier is None:
            classifier = EncoderClassifier.from_hparams(
                source=ECAPA_MODEL_ID,
                savedir=str(savedir),
                run_opts={"device": str(self._device)},
                local_strategy=LocalStrategy.COPY,
            )

        self._classifier = classifier

    @property
    def model_id(self) -> str:
        return ECAPA_MODEL_ID

    @property
    def device(self) -> str:
        return str(self._device)

    def embed(
        self,
        utterance: CapturedUtterance,
    ) -> tuple[float, ...]:
        waveform, sample_rate = self._decode_wav(utterance)

        if waveform.shape[0] > 1:
            waveform = waveform.mean(dim=0, keepdim=True)

        if sample_rate != ECAPA_SAMPLE_RATE:
            waveform = torchaudio.functional.resample(
                waveform,
                orig_freq=sample_rate,
                new_freq=ECAPA_SAMPLE_RATE,
            )

        if waveform.numel() == 0:
            raise RuntimeError(
                "La muestra de voz está vacía."
            )

        if not torch.isfinite(waveform).all():
            raise RuntimeError(
                "La muestra de voz contiene valores no finitos."
            )

        waveform = waveform.to(
            device=self._device,
            dtype=torch.float32,
        )

        try:
            with torch.inference_mode():
                embedding = self._classifier.encode_batch(
                    waveform,
                    normalize=True,
                )
        except Exception as exc:
            raise RuntimeError(
                "ECAPA no pudo generar el embedding de voz."
            ) from exc

        flattened = (
            embedding
            .detach()
            .to(device="cpu", dtype=torch.float32)
            .reshape(-1)
        )

        if flattened.numel() == 0:
            raise RuntimeError(
                "ECAPA devolvió un embedding vacío."
            )

        values = tuple(
            float(value)
            for value in flattened.tolist()
        )

        if not all(math.isfinite(value) for value in values):
            raise RuntimeError(
                "ECAPA devolvió valores no finitos."
            )

        return values

    @staticmethod
    def _decode_wav(
        utterance: CapturedUtterance,
    ) -> tuple[torch.Tensor, int]:
        if not utterance.wav_bytes:
            raise RuntimeError(
                "La muestra de voz no contiene audio."
            )

        try:
            waveform, sample_rate = torchaudio.load(
                io.BytesIO(utterance.wav_bytes),
                format="wav",
            )
        except Exception as exc:
            raise RuntimeError(
                "No se pudo decodificar la muestra WAV."
            ) from exc

        if waveform.ndim != 2:
            raise RuntimeError(
                "La muestra WAV tiene una forma inesperada."
            )

        return waveform, int(sample_rate)


__all__ = [
    "ECAPA_MODEL_ID",
    "ECAPA_SAMPLE_RATE",
    "EcapaSpeakerBackend",
]
