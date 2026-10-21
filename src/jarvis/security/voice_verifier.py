"""Owner voice verification independent from the ML backend."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from jarvis.core.audio_input import CapturedUtterance
from jarvis.identity.registry import UserRegistry

from .policy_core import VerifiedFactor
from .verification import VerificationIssuer, VerificationResult


_PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class SpeakerEmbeddingBackend(Protocol):
    """Backend capable of converting speech into a speaker embedding."""

    @property
    def model_id(self) -> str:
        ...

    def embed(
        self,
        utterance: CapturedUtterance,
    ) -> Sequence[float]:
        ...


@dataclass(frozen=True)
class VoiceProfile:
    profile_id: str
    model_id: str
    embedding: tuple[float, ...]


@dataclass(frozen=True)
class VoiceMatch:
    score: float
    threshold: float
    verification: VerificationResult | None

    @property
    def accepted(self) -> bool:
        return self.verification is not None


class VoiceProfileStore:
    """Private on-disk storage for enrolled speaker embeddings."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def load(self, profile_id: str) -> VoiceProfile:
        path = self._profile_path(profile_id)

        try:
            payload = json.loads(
                path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "No se pudo leer el perfil de voz."
            ) from exc

        if payload.get("profile_id") != profile_id:
            raise RuntimeError(
                "El identificador del perfil de voz no coincide."
            )

        model_id = str(payload.get("model_id") or "").strip()
        embedding = payload.get("embedding")

        if not model_id:
            raise RuntimeError(
                "El perfil de voz no indica el modelo usado."
            )

        if not isinstance(embedding, list) or not embedding:
            raise RuntimeError(
                "El perfil de voz no contiene un embedding válido."
            )

        try:
            values = tuple(float(value) for value in embedding)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "El embedding del perfil de voz es inválido."
            ) from exc

        if not all(math.isfinite(value) for value in values):
            raise RuntimeError(
                "El embedding del perfil contiene valores no finitos."
            )

        return VoiceProfile(
            profile_id=profile_id,
            model_id=model_id,
            embedding=values,
        )

    def save(
        self,
        profile: VoiceProfile,
        *,
        overwrite: bool = False,
    ) -> None:
        path = self._profile_path(profile.profile_id)

        if path.exists() and not overwrite:
            raise FileExistsError(
                f"El perfil '{profile.profile_id}' ya existe."
            )

        if not profile.model_id.strip():
            raise ValueError("model_id no puede estar vacío.")

        if not profile.embedding:
            raise ValueError("El embedding no puede estar vacío.")

        if not all(
            math.isfinite(float(value))
            for value in profile.embedding
        ):
            raise ValueError(
                "El embedding contiene valores no finitos."
            )

        self._root.mkdir(parents=True, exist_ok=True)

        payload = {
            "profile_id": profile.profile_id,
            "model_id": profile.model_id,
            "embedding": list(profile.embedding),
        }

        temp = path.with_suffix(".tmp")
        temp.write_text(
            json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )
        temp.replace(path)

    def _profile_path(self, profile_id: str) -> Path:
        normalized = profile_id.strip()

        if not _PROFILE_ID_RE.fullmatch(normalized):
            raise ValueError(
                "Identificador de perfil de voz inválido."
            )

        return self._root / f"{normalized}.json"


class VoiceVerifier:
    """
    Verify the registered owner's speaker embedding.

    A speaker mismatch is a normal authentication failure and returns
    VoiceMatch(accepted=False). Configuration/storage failures fail closed
    by raising RuntimeError.
    """

    def __init__(
        self,
        registry: UserRegistry,
        profile_store: VoiceProfileStore,
        backend: SpeakerEmbeddingBackend,
        *,
        threshold: float,
        issuer: VerificationIssuer | None = None,
    ) -> None:
        if not math.isfinite(threshold):
            raise ValueError("threshold debe ser finito.")

        if threshold < -1.0 or threshold > 1.0:
            raise ValueError(
                "threshold debe estar entre -1 y 1."
            )

        self._registry = registry
        self._profile_store = profile_store
        self._backend = backend
        self._threshold = float(threshold)

        self._issuer = issuer or VerificationIssuer(
            f"voice:{backend.model_id}",
            {VerifiedFactor.OWNER_VOICE},
        )

    @property
    def issuer(self) -> VerificationIssuer:
        return self._issuer

    def verify(
        self,
        utterance: CapturedUtterance,
    ) -> VoiceMatch:
        owner = self._registered_owner()
        profile_id = (owner.voice_profile_id or "").strip()

        if not profile_id:
            raise RuntimeError(
                "El propietario no tiene un perfil de voz configurado."
            )

        profile = self._profile_store.load(profile_id)

        if profile.model_id != self._backend.model_id:
            raise RuntimeError(
                "El perfil de voz pertenece a otro modelo."
            )

        current = tuple(
            float(value)
            for value in self._backend.embed(utterance)
        )

        score = _cosine_similarity(
            profile.embedding,
            current,
        )

        if score < self._threshold:
            return VoiceMatch(
                score=score,
                threshold=self._threshold,
                verification=None,
            )

        verification = self._issuer.issue(
            owner.user_id,
            VerifiedFactor.OWNER_VOICE,
        )

        return VoiceMatch(
            score=score,
            threshold=self._threshold,
            verification=verification,
        )

    def _registered_owner(self):
        owners = [
            user
            for user in self._registry.all()
            if user.is_owner
        ]

        if len(owners) != 1:
            raise RuntimeError(
                "La verificación de voz requiere exactamente "
                "un propietario registrado."
            )

        return owners[0]


def _cosine_similarity(
    left: Sequence[float],
    right: Sequence[float],
) -> float:
    if not left or not right:
        raise RuntimeError(
            "No se puede comparar un embedding vacío."
        )

    if len(left) != len(right):
        raise RuntimeError(
            "Los embeddings de voz tienen dimensiones distintas."
        )

    left_values = tuple(float(value) for value in left)
    right_values = tuple(float(value) for value in right)

    if not all(
        math.isfinite(value)
        for value in left_values + right_values
    ):
        raise RuntimeError(
            "El embedding contiene valores no finitos."
        )

    dot = sum(
        a * b
        for a, b in zip(left_values, right_values)
    )

    left_norm = math.sqrt(
        sum(value * value for value in left_values)
    )
    right_norm = math.sqrt(
        sum(value * value for value in right_values)
    )

    if left_norm == 0.0 or right_norm == 0.0:
        raise RuntimeError(
            "No se puede comparar un embedding de norma cero."
        )

    score = dot / (left_norm * right_norm)

    return max(-1.0, min(1.0, score))


__all__ = [
    "SpeakerEmbeddingBackend",
    "VoiceMatch",
    "VoiceProfile",
    "VoiceProfileStore",
    "VoiceVerifier",
]
