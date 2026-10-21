"""Reusable captured audio for STT and speaker verification."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CapturedUtterance:
    """One microphone utterance normalized for JARVIS voice processing."""

    wav_bytes: bytes
    sample_rate: int = 16000
    sample_width: int = 2


__all__ = ["CapturedUtterance"]
