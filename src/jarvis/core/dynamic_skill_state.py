"""Central, bounded JSON persistence for dynamic-skill state."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path

MAX_DYNAMIC_SKILL_STATE_BYTES = 256 * 1024
JARVIS_DATA_KEY = "__jarvis_data__"
JARVIS_STATE_KEY = "__jarvis_state__"
_SKILL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class DynamicSkillStateError(ValueError):
    """A skill state value is invalid or exceeds its configured bound."""


class DynamicSkillStateStore:
    """Read and atomically replace one JSON state file per installed skill."""

    def __init__(self, directory: Path | str | None = None) -> None:
        project_root = Path(__file__).resolve().parents[3]
        self.directory = Path(directory) if directory is not None else project_root / "data" / "dynamic_skill_state"

    def load(self, skill_name: str) -> dict[str, object]:
        path = self._path(skill_name)
        try:
            if path.is_symlink():
                return {}
            if path.stat().st_size > MAX_DYNAMIC_SKILL_STATE_BYTES:
                return {}
            raw = path.read_text(encoding="utf-8")
            decoded = json.loads(raw)
            return self.validate_state(decoded)
        except FileNotFoundError:
            return {}
        except (OSError, UnicodeError, json.JSONDecodeError, DynamicSkillStateError):
            return {}

    def save(self, skill_name: str, state: Mapping[str, object]) -> None:
        path = self._path(skill_name)
        normalized = self.validate_state(state)
        serialized = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        encoded = serialized.encode("utf-8")
        if len(encoded) > MAX_DYNAMIC_SKILL_STATE_BYTES:
            raise DynamicSkillStateError(
                f"Dynamic skill state exceeds {MAX_DYNAMIC_SKILL_STATE_BYTES} bytes."
            )

        self.directory.mkdir(parents=True, exist_ok=True)
        if self.directory.is_symlink() or path.is_symlink():
            raise DynamicSkillStateError("Dynamic skill state paths may not be symlinks.")
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                prefix=f".{skill_name}.",
                suffix=".tmp",
                dir=self.directory,
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                temporary_file.write(serialized)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def delete(self, skill_name: str) -> None:
        self._path(skill_name).unlink(missing_ok=True)

    @staticmethod
    def validate_state(state: object) -> dict[str, object]:
        if not isinstance(state, Mapping):
            raise DynamicSkillStateError("Dynamic skill state must be a mapping.")
        normalized = _normalize_json_value(state, set())
        if not isinstance(normalized, dict):
            raise DynamicSkillStateError("Dynamic skill state must be a JSON object.")
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_DYNAMIC_SKILL_STATE_BYTES:
            raise DynamicSkillStateError(
                f"Dynamic skill state exceeds {MAX_DYNAMIC_SKILL_STATE_BYTES} bytes."
            )
        return normalized

    def _path(self, skill_name: str) -> Path:
        if not isinstance(skill_name, str) or not _SKILL_NAME_PATTERN.fullmatch(skill_name):
            raise ValueError("Invalid dynamic skill name for state storage.")
        path = self.directory / f"{skill_name}.json"
        if path.parent != self.directory:
            raise ValueError("Dynamic skill state path escapes its directory.")
        return path


def extract_dynamic_skill_envelope(
    result: object,
) -> tuple[object, Mapping[str, object] | None]:
    """Separate visible data from an optional central-state update envelope."""
    if not isinstance(result, Mapping):
        return result, None
    if JARVIS_DATA_KEY not in result:
        if JARVIS_STATE_KEY in result:
            return None, None
        return result, None
    state = result.get(JARVIS_STATE_KEY)
    return result[JARVIS_DATA_KEY], state if isinstance(state, Mapping) else None


def _normalize_json_value(value: object, ancestors: set[int]) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise DynamicSkillStateError("Dynamic skill state contains a non-finite number.")
        return value

    if isinstance(value, Mapping):
        object_id = id(value)
        if object_id in ancestors:
            raise DynamicSkillStateError("Dynamic skill state contains a circular reference.")
        ancestors.add(object_id)
        try:
            normalized: dict[str, object] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise DynamicSkillStateError("Dynamic skill state keys must be strings.")
                normalized[key] = _normalize_json_value(item, ancestors)
            return normalized
        finally:
            ancestors.remove(object_id)

    if isinstance(value, (list, tuple)):
        object_id = id(value)
        if object_id in ancestors:
            raise DynamicSkillStateError("Dynamic skill state contains a circular reference.")
        ancestors.add(object_id)
        try:
            return [_normalize_json_value(item, ancestors) for item in value]
        finally:
            ancestors.remove(object_id)

    raise DynamicSkillStateError(
        f"Dynamic skill state contains a non-JSON value: {type(value).__name__}."
    )


__all__ = [
    "DynamicSkillStateError",
    "DynamicSkillStateStore",
    "extract_dynamic_skill_envelope",
    "JARVIS_DATA_KEY",
    "JARVIS_STATE_KEY",
    "MAX_DYNAMIC_SKILL_STATE_BYTES",
]