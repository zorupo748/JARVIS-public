"""Typed input events for JARVIS runtime input channels."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class InputSource(str, Enum):
    LOCAL_CONSOLE = "local_console"
    UNTRUSTED_STDIN = "untrusted_stdin"
    RECOVERY = "recovery"


@dataclass(frozen=True)
class PendingInput:
    text: str
    source: InputSource


def classify_stdin_source(stdin: Any) -> InputSource:
    """
    Only a real interactive terminal counts as the trusted local console.

    Redirected stdin, pipes or objects whose terminal status cannot be
    established fail closed as untrusted input.
    """

    try:
        is_terminal = bool(stdin.isatty())
    except (AttributeError, OSError):
        return InputSource.UNTRUSTED_STDIN

    if is_terminal:
        return InputSource.LOCAL_CONSOLE

    return InputSource.UNTRUSTED_STDIN


__all__ = [
    "InputSource",
    "PendingInput",
    "classify_stdin_source",
]
