"""Child-process adapter for a parent-authorized dynamic skill invocation.

It is failure containment only, not an operating-system sandbox.  The parent
must verify deployment metadata, hash and PolicyCore before starting this worker.
"""

from __future__ import annotations

import hashlib
import json
import sys
import traceback
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Mapping

from jarvis.core.dynamic_skill_input import DynamicSkillInputError, extract_dynamic_skill_result

from jarvis.skills.dynamic_runtime import (
    DynamicSkillEntrypointError,
    _execute_authorized_dynamic_skill,
)


def _text(value: object) -> str:
    return value if isinstance(value, str) else str(value)


def _json_value(value: object) -> object:
    if isinstance(value, dict) and any(isinstance(key, str) and key.startswith("__jarvis_input") for key in value):
        _data, state, request = extract_dynamic_skill_result(value)
        envelope = {"__jarvis_data__": None, "__jarvis_input_request__": request.as_mapping()}
        if state is not None:
            envelope["__jarvis_state__"] = state
        return envelope
    if isinstance(value, dict) and "__jarvis_data__" in value:
        envelope = {"__jarvis_data__": _json_value(value["__jarvis_data__"])}
        if "__jarvis_state__" in value:
            state = value["__jarvis_state__"]
            try:
                json.dumps(state, ensure_ascii=False, allow_nan=False)
            except (TypeError, ValueError):
                envelope["__jarvis_state__"] = None
            else:
                envelope["__jarvis_state__"] = state
        return envelope
    try:
        json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError):
        return str(value)
    return value


def _read_request() -> tuple[str, Path, Mapping[str, object], str]:
    try:
        payload = json.loads(sys.stdin.read())
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid dynamic runtime request JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Dynamic runtime request must be an object.")
    name = payload.get("skill_name")
    directory = payload.get("dynamic_dir")
    parameters = payload.get("parameters", {})
    expected_hash = payload.get("expected_hash")
    if not isinstance(name, str) or not name:
        raise ValueError("Invalid dynamic skill name.")
    if not isinstance(directory, str) or not directory:
        raise ValueError("Invalid dynamic skill directory.")
    if not isinstance(parameters, dict) or any(not isinstance(key, str) for key in parameters):
        raise ValueError("Invalid dynamic skill parameters.")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise ValueError("Invalid expected source hash.")
    root = Path(directory).resolve()
    source = (root / f"{name}.py").resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise ValueError("Dynamic skill path escapes the requested directory.") from exc
    actual_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError("Dynamic skill hash changed before child runtime start.")
    return name, root, parameters, expected_hash


def main() -> int:
    captured_stdout = StringIO()
    captured_stderr = StringIO()
    try:
        name, directory, parameters, _expected_hash = _read_request()
        with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
            result = _execute_authorized_dynamic_skill(name, directory, parameters)
        payload = {
            "ok": True,
            "result": _json_value(result),
            "stdout": captured_stdout.getvalue(),
            "stderr": captured_stderr.getvalue(),
        }
    except DynamicSkillInputError as exc:
        payload = {"ok": False, "error": f"DynamicSkillInputError: {exc}", "failure_kind": "result_contract",
                   "stdout": captured_stdout.getvalue(), "stderr": captured_stderr.getvalue()}
    except DynamicSkillEntrypointError as exc:
        payload = {
            "ok": False,
            "error": f"{exc.error_type}: {exc.original_message}",
            "failure_kind": "skill_exception",
            "stderr": captured_stderr.getvalue() + exc.traceback_text,
            "stdout": captured_stdout.getvalue(),
        }
    except Exception as exc:
        payload = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "failure_kind": "worker_infrastructure",
            "stdout": captured_stdout.getvalue(),
            "stderr": captured_stderr.getvalue() + traceback.format_exc(),
        }
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
