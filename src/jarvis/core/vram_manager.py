"""Deterministic single-slot coordination for local heavy LLM VRAM usage."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from threading import Condition
from time import monotonic
from types import MappingProxyType
from typing import Iterator, Mapping


MAX_LOCAL_HEAVY_MODELS = 1
"""Conservative policy: an 8 GiB RTX 4060 runs one heavy local LLM at a time."""

GPU_BASELINE_VRAM_MIB = 1350
VRAM_SAFETY_MARGIN_MIB = 768


@dataclass(frozen=True)
class LocalModelMetadata:
    """Observed VRAM measurements for a known Ollama model at ``num_ctx=4096``."""

    model_id: str
    ollama_size_vram_gib: float
    observed_total_vram_mib: int


KNOWN_LOCAL_HEAVY_MODELS: Mapping[str, LocalModelMetadata] = MappingProxyType(
    {
        "qwen3.5:4b": LocalModelMetadata(
            model_id="qwen3.5:4b",
            ollama_size_vram_gib=2.91,
            observed_total_vram_mib=5205,
        ),
        "qwen2.5-coder:7b-instruct-q4_K_M": LocalModelMetadata(
            model_id="qwen2.5-coder:7b-instruct-q4_K_M",
            ollama_size_vram_gib=4.42,
            observed_total_vram_mib=5999,
        ),
        "qwen3-vl:4b": LocalModelMetadata(
            model_id="qwen3-vl:4b",
            ollama_size_vram_gib=3.29,
            observed_total_vram_mib=5954,
        ),
        "qwen3.5:9b": LocalModelMetadata(
            model_id="qwen3.5:9b",
            ollama_size_vram_gib=5.11,
            observed_total_vram_mib=7660,
        ),
    }
)


@dataclass(frozen=True)
class VramSlotStatus:
    """Snapshot for future routing and queue planning; it has no cloud behavior."""

    owner_model_id: str | None
    resident_model_id: str | None
    waiting_requests: int
    max_local_heavy_models: int = MAX_LOCAL_HEAVY_MODELS

    @property
    def local_available(self) -> bool:
        return self.owner_model_id is None


class VramReservationTimeout(TimeoutError):
    """Raised when a context-managed reservation cannot obtain the local slot."""


class VramManager:
    """Thread-safe, deterministic ownership of one local-heavy-LLM slot.

    The single slot, rather than arithmetic over reported VRAM sizes, is the
    source of truth in this phase. Callers can inspect ``status()`` to plan a
    future local queue or cloud fallback without this module selecting either.
    """

    def __init__(self) -> None:
        self._condition = Condition()
        self._owner_model_id: str | None = None
        self._resident_model_id: str | None = None
        self._waiting_requests = 0

    @staticmethod
    def _normalise_model_id(model_id: str) -> str:
        if not isinstance(model_id, str) or not model_id.strip():
            raise ValueError("model_id must be a non-empty string")
        return model_id.strip()

    @property
    def current_model_id(self) -> str | None:
        """Return the model that currently owns the local-heavy slot."""

        with self._condition:
            return self._owner_model_id

    @property
    def owner_model_id(self) -> str | None:
        """Alias for ``current_model_id`` for callers that use ownership wording."""

        return self.current_model_id

    @property
    def resident_model_id(self) -> str | None:
        """Return the known model intentionally kept resident by Ollama."""

        with self._condition:
            return self._resident_model_id

    def mark_model_resident(self, model_id: str) -> None:
        """Record a successful local model use while its slot is exclusively held."""

        normalised_model_id = self._normalise_model_id(model_id)
        with self._condition:
            self._resident_model_id = normalised_model_id

    def clear_resident_model(self, model_id: str | None = None) -> bool:
        """Clear matching residency after an unload without disturbing other state."""

        normalised_model_id = (
            None if model_id is None else self._normalise_model_id(model_id)
        )
        with self._condition:
            if self._resident_model_id is None:
                return False
            if (
                normalised_model_id is not None
                and self._resident_model_id != normalised_model_id
            ):
                return False

            self._resident_model_id = None
            return True

    def status(self) -> VramSlotStatus:
        """Return a consistent snapshot of local availability and queue depth."""

        with self._condition:
            return VramSlotStatus(
                owner_model_id=self._owner_model_id,
                resident_model_id=self._resident_model_id,
                waiting_requests=self._waiting_requests,
            )

    def can_run_local_now(self) -> bool:
        """Return whether the one local-heavy slot is immediately available."""

        with self._condition:
            return self._owner_model_id is None

    def try_acquire(self, model_id: str) -> bool:
        """Attempt an immediate, non-blocking reservation."""

        return self.acquire(model_id, timeout=0)

    def acquire(self, model_id: str, timeout: float | None = None) -> bool:
        """Reserve the slot for ``model_id`` until the matching ``release``.

        A false result means the timeout elapsed before ownership was granted.
        The implementation does not make reservations re-entrant, even when a
        second caller uses the same model identifier: each worker needs a
        separate, unambiguous ownership interval.
        """

        normalised_model_id = self._normalise_model_id(model_id)
        if timeout is not None and timeout < 0:
            raise ValueError("timeout must be non-negative or None")

        deadline = None if timeout is None else monotonic() + timeout
        with self._condition:
            if self._owner_model_id is None:
                self._owner_model_id = normalised_model_id
                return True

            self._waiting_requests += 1
            try:
                while self._owner_model_id is not None:
                    if deadline is None:
                        self._condition.wait()
                        continue

                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        return False
                    self._condition.wait(remaining)

                self._owner_model_id = normalised_model_id
                return True
            finally:
                self._waiting_requests -= 1

    def release(self, model_id: str) -> bool:
        """Release only a matching owner; mismatches leave the state unchanged."""

        normalised_model_id = self._normalise_model_id(model_id)
        with self._condition:
            if self._owner_model_id != normalised_model_id:
                return False

            self._owner_model_id = None
            self._condition.notify_all()
            return True

    @contextmanager
    def reserve(
        self, model_id: str, timeout: float | None = None
    ) -> Iterator[None]:
        """Acquire the slot and always release it, including on caller errors."""

        normalised_model_id = self._normalise_model_id(model_id)
        if not self.acquire(normalised_model_id, timeout=timeout):
            raise VramReservationTimeout(
                f"Timed out waiting for the local VRAM slot for {normalised_model_id!r}."
            )

        try:
            yield
        finally:
            self.release(normalised_model_id)


__all__ = [
    "GPU_BASELINE_VRAM_MIB",
    "KNOWN_LOCAL_HEAVY_MODELS",
    "LocalModelMetadata",
    "MAX_LOCAL_HEAVY_MODELS",
    "VRAM_SAFETY_MARGIN_MIB",
    "VramManager",
    "VramReservationTimeout",
    "VramSlotStatus",
]