"""Controlled enrollment of the registered owner's voice profile."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

from jarvis.core.audio_input import CapturedUtterance
from jarvis.identity.registry import UserRegistry

from .voice_verifier import (
    SpeakerEmbeddingBackend,
    VoiceProfile,
    VoiceProfileStore,
)


@dataclass(frozen=True)
class VoiceEnrollmentResult:
    profile: VoiceProfile
    sample_count: int
    mean_similarity: float
    minimum_similarity: float


class OwnerVoiceEnrollmentService:
    """
    Build one owner voice profile from several independent utterances.

    Enrollment never grants a runtime verification factor. It only creates
    the reference profile that VoiceVerifier may compare against later.
    """

    def __init__(
        self,
        registry: UserRegistry,
        profile_store: VoiceProfileStore,
        backend: SpeakerEmbeddingBackend,
        *,
        minimum_samples: int = 5,
    ) -> None:
        if minimum_samples < 3:
            raise ValueError(
                "minimum_samples debe ser al menos 3."
            )

        self._registry = registry
        self._profile_store = profile_store
        self._backend = backend
        self._minimum_samples = minimum_samples

    def enroll(
        self,
        profile_id: str,
        utterances: Iterable[CapturedUtterance],
        *,
        overwrite: bool = False,
    ) -> VoiceEnrollmentResult:
        owner = self._registered_owner()
        samples = list(utterances)

        if len(samples) < self._minimum_samples:
            raise RuntimeError(
                f"Se necesitan al menos {self._minimum_samples} "
                "muestras de voz."
            )

        if owner.voice_profile_id and not overwrite:
            raise RuntimeError(
                "El propietario ya tiene un perfil de voz configurado."
            )

        embeddings = [
            _normalize_embedding(
                self._backend.embed(utterance)
            )
            for utterance in samples
        ]

        dimensions = {len(embedding) for embedding in embeddings}

        if len(dimensions) != 1:
            raise RuntimeError(
                "Las muestras produjeron embeddings de "
                "dimensiones distintas."
            )

        centroid = _normalized_centroid(embeddings)

        similarities = [
            _cosine(embedding, centroid)
            for embedding in embeddings
        ]

        profile = VoiceProfile(
            profile_id=profile_id,
            model_id=self._backend.model_id,
            embedding=centroid,
        )

        self._profile_store.save(
            profile,
            overwrite=overwrite,
        )

        owner.voice_profile_id = profile_id
        self._registry.save()

        return VoiceEnrollmentResult(
            profile=profile,
            sample_count=len(samples),
            mean_similarity=sum(similarities) / len(similarities),
            minimum_similarity=min(similarities),
        )

    def _registered_owner(self):
        owners = [
            user
            for user in self._registry.all()
            if user.is_owner
        ]

        if len(owners) != 1:
            raise RuntimeError(
                "El enrolamiento requiere exactamente un "
                "propietario registrado."
            )

        return owners[0]


def _normalize_embedding(
    values: Sequence[float],
) -> tuple[float, ...]:
    embedding = tuple(float(value) for value in values)

    if not embedding:
        raise RuntimeError(
            "El backend devolvió un embedding vacío."
        )

    if not all(math.isfinite(value) for value in embedding):
        raise RuntimeError(
            "El backend devolvió valores no finitos."
        )

    norm = math.sqrt(
        sum(value * value for value in embedding)
    )

    if norm == 0.0:
        raise RuntimeError(
            "El backend devolvió un embedding de norma cero."
        )

    return tuple(
        value / norm
        for value in embedding
    )


def _normalized_centroid(
    embeddings: Sequence[Sequence[float]],
) -> tuple[float, ...]:
    dimension = len(embeddings[0])

    mean = tuple(
        sum(embedding[index] for embedding in embeddings)
        / len(embeddings)
        for index in range(dimension)
    )

    return _normalize_embedding(mean)


def _cosine(
    left: Sequence[float],
    right: Sequence[float],
) -> float:
    if len(left) != len(right):
        raise RuntimeError(
            "No se pueden comparar embeddings de dimensiones distintas."
        )

    score = sum(
        a * b
        for a, b in zip(left, right)
    )

    return max(-1.0, min(1.0, score))


__all__ = [
    "OwnerVoiceEnrollmentService",
    "VoiceEnrollmentResult",
]
