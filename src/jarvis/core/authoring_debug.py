"""Best-effort persistent diagnostics for safe skill authoring.

This module records coder responses, sanitized reviewer responses, and authoring
diagnostics. It never persists prompts, environment variables, credentials, or
unredacted transport secrets.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping


AUTHORING_DEBUG_ENV = "JARVIS_SKILL_AUTHORING_DEBUG"
_DEFAULT_DEBUG_ROOT = Path(".debug") / "skill_authoring"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_JSON_SECRET_PATTERN = re.compile(
    r'(?i)("(?:api[_-]?key|authorization|token|cookie|password|secret)"\s*:\s*")([^"]*)(")'
)
_HEADER_SECRET_PATTERN = re.compile(
    r'(?im)^(\s*(?:authorization|x-api-key|cookie)\s*:\s*)(.+)$'
)
_BEARER_PATTERN = re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+')


def skill_authoring_debug_enabled(
    environ: Mapping[str, str] | None = None,
) -> bool:
    """Return whether persistent authoring diagnostics were explicitly enabled."""

    environment = os.environ if environ is None else environ
    value = environment.get(AUTHORING_DEBUG_ENV, "")
    return isinstance(value, str) and value.strip().lower() in _TRUE_VALUES


@dataclass
class AuthoringDebugSession:
    """A best-effort artifact writer for one authoring invocation.

    I/O failures are contained in this class. They turn off further persistence
    for the session and emit one concise warning, while the actual authoring
    pipeline continues unchanged.
    """

    directory: Path | None
    display_path: str | None
    _warning_sink: Callable[[str], None]
    _persistence_failed: bool = field(default=False, init=False)
    _warning_emitted: bool = field(default=False, init=False)

    @classmethod
    def start(
        cls,
        *,
        enabled: bool,
        warning_sink: Callable[[str], None],
        debug_root: Path | None = None,
        original_user_request: str | None = None,
    ) -> "AuthoringDebugSession":
        if not enabled:
            return cls(directory=None, display_path=None, _warning_sink=warning_sink)

        root = debug_root or _DEFAULT_DEBUG_ROOT
        session_id = _make_session_id(original_user_request)
        directory = root / session_id
        display_path = _display_path(root, session_id)
        session = cls(
            directory=directory,
            display_path=display_path,
            _warning_sink=warning_sink,
        )
        try:
            directory.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            session._disable_after_error(exc)
            return session

        warning_sink(f"[AUTHORING DEBUG] Session: {display_path}")
        return session

    @property
    def active(self) -> bool:
        return self.directory is not None and not self._persistence_failed

    def write_raw_response(self, iteration: int, raw_response: object) -> None:
        content = raw_response if isinstance(raw_response, str) else repr(raw_response)
        self._append_json_line(
            "raw_responses.jsonl",
            {
                "iteration": iteration,
                "raw_response": content,
            },
        )

    def write_reviewer_response(
        self,
        *,
        authoring_iteration: int,
        review_attempt: int,
        provider: str,
        raw_response: object,
        normalization_success: bool,
        normalization_error: str | None,
        approved: bool | None,
        truncated: bool,
        local_review_num_predict: int | None = None,
        blockers_downgraded_by_policy: tuple[str, ...] = (),
        normalization_error_kind: str | None = None,
        unknown_severity_normalized: tuple[str, ...] = (),
    ) -> None:
        """Persist one sanitized reviewer transport response, best effort only."""

        raw_text = raw_response if isinstance(raw_response, str) else None
        self._append_json_line(
            "reviewer_responses.jsonl",
            {
                "authoring_iteration": authoring_iteration,
                "review_attempt": review_attempt,
                "provider": provider,
                "raw_response": _sanitize_review_debug_response(raw_text),
                "raw_length": len(raw_text) if raw_text is not None else None,
                "normalization_success": normalization_success,
                "normalization_error": normalization_error,
                "normalization_error_kind": normalization_error_kind,
                "unknown_severity_normalized": unknown_severity_normalized,
                "truncated": truncated,
                "approved": approved,
                "local_review_num_predict": local_review_num_predict,
                "blockers_downgraded_by_policy": blockers_downgraded_by_policy,
            },
        )
    def write_extracted_code(self, iteration: int, extraction: object) -> None:
        if not bool(getattr(extraction, "success", False)):
            return

        source = getattr(extraction, "source_code", None)
        if isinstance(source, str) and source.strip():
            self._write_text(self._iteration_path(iteration, "source.py"), source)

        tests = getattr(extraction, "tests_source", None)
        if isinstance(tests, str) and tests.strip():
            self._write_text(self._iteration_path(iteration, "tests.py"), tests)

    def write_diagnostic(self, diagnostic: object) -> None:
        if not self.active:
            return
        payload = {
            "phase": getattr(diagnostic, "phase", None),
            "iteration": getattr(diagnostic, "iteration", None),
            "normalized_kind": getattr(diagnostic, "normalized_kind", None),
            "normalization_error": getattr(diagnostic, "normalization_error", None),
            "truncated": getattr(diagnostic, "truncated", None),
            "review_attempts": getattr(diagnostic, "review_attempts", None),
            "review_skipped_reason": getattr(diagnostic, "review_skipped_reason", None),
            "review_transport_failed": getattr(diagnostic, "review_transport_failed", None),
            "reviewer_normalized": getattr(diagnostic, "reviewer_normalized", None),
            "reviewer_normalization_error": getattr(diagnostic, "reviewer_normalization_error", None),
            "reviewer_truncated": getattr(diagnostic, "reviewer_truncated", None),
            "local_review_num_predict": getattr(diagnostic, "local_review_num_predict", None),
            "blockers_downgraded_by_policy": getattr(diagnostic, "blockers_downgraded_by_policy", None),
            "review_plan_created": getattr(diagnostic, "review_plan_created", None),
            "blocking_total": getattr(diagnostic, "blocking_total", None),
            "blocking_unresolved": getattr(diagnostic, "blocking_unresolved", None),
            "blocking_resolved": getattr(diagnostic, "blocking_resolved", None),
            "advisory_count": getattr(diagnostic, "advisory_count", None),
            "regression_blockers": getattr(diagnostic, "regression_blockers", None),
            "source_repair_count": getattr(diagnostic, "source_repair_count", None),
            "repair_blocker_ids": getattr(diagnostic, "repair_blocker_ids", None),
            "repair_blocker_count": getattr(diagnostic, "repair_blocker_count", None),
            "repair_source_unchanged": getattr(diagnostic, "repair_source_unchanged", None),
            "metadata_reused": getattr(diagnostic, "metadata_reused", None),
            "metadata_change_ignored": getattr(diagnostic, "metadata_change_ignored", None),
            "elapsed_seconds": getattr(diagnostic, "elapsed_seconds", None),
            "generation_success": getattr(diagnostic, "generation_success", None),
            "structural_retry_count": getattr(diagnostic, "structural_retry_count", None),
            "consecutive_structural_failures": getattr(diagnostic, "structural_retries", None),
            "first_response_structurally_valid": getattr(diagnostic, "first_response_structurally_valid", None),
            "structurally_recovered": getattr(diagnostic, "structurally_recovered", None),
            "structural_error_code": getattr(diagnostic, "structural_error_code", None),
            "reviewer_repair_count": getattr(diagnostic, "reviewer_repair_count", None),
            "extraction_method": getattr(diagnostic, "extraction_method", None),
            "structural_error": getattr(diagnostic, "structural_error", None),
            "has_meta": getattr(diagnostic, "has_meta", None),
            "has_source": getattr(diagnostic, "has_source", None),
            "has_tests": getattr(diagnostic, "has_tests", None),
            "source_hash": getattr(diagnostic, "source_hash", None),
            "validation_passed": getattr(diagnostic, "validation_success", None),
            "validation_fingerprint": getattr(diagnostic, "validation_fingerprint", None),
            "reviewer_used": getattr(diagnostic, "reviewer_used", None),
            "cloud_failed": getattr(diagnostic, "cloud_failed", None),
            "cloud_failure_reason": getattr(diagnostic, "cloud_failure_reason", None),
            "review_approved": getattr(diagnostic, "review_approved", None),
            "review_fingerprint": getattr(diagnostic, "review_fingerprint", None),
            "progress": getattr(diagnostic, "progress_detected", None),
            "stagnation_count": getattr(diagnostic, "stagnation_count", None),
            "rescue_used": getattr(diagnostic, "rescue_triggered", None),
        }
        self._append_json_line("diagnostics.jsonl", payload)

    def _iteration_path(self, iteration: int, suffix: str) -> str:
        return f"iteration_{iteration:03d}_{suffix}"

    def _write_text(self, filename: str, content: str) -> None:
        if not self.active:
            return
        assert self.directory is not None
        try:
            (self.directory / filename).write_text(content, encoding="utf-8")
        except OSError as exc:
            self._disable_after_error(exc)

    def _append_json_line(self, filename: str, payload: Mapping[str, object]) -> None:
        if not self.active:
            return
        assert self.directory is not None
        try:
            with (self.directory / filename).open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
                handle.write("\n")
        except OSError as exc:
            self._disable_after_error(exc)

    def _disable_after_error(self, _error: OSError) -> None:
        self._persistence_failed = True
        if not self._warning_emitted:
            self._warning_emitted = True
            self._warning_sink(
                "[AUTHORING DEBUG] Persistent artifacts unavailable; continuing without debug files."
            )


def _sanitize_review_debug_response(raw_response: str | None) -> str | None:
    """Redact credential-shaped data without changing the live review payload."""

    if raw_response is None:
        return None
    sanitized = _JSON_SECRET_PATTERN.sub(r'\1[REDACTED]\3', raw_response)
    sanitized = _HEADER_SECRET_PATTERN.sub(r'\1[REDACTED]', sanitized)
    return _BEARER_PATTERN.sub("Bearer [REDACTED]", sanitized)


def _request_slug(original_user_request: str | None) -> str:
    if not original_user_request:
        return "skill-authoring"
    normalized = unicodedata.normalize("NFKD", original_user_request)
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_text).strip("-")
    for prefix in ("crea-una-skill-para-", "crear-una-skill-para-", "haz-una-skill-para-"):
        if slug.startswith(prefix):
            slug = slug[len(prefix):]
            break
    return slug[:48].strip("-") or "skill-authoring"


def _make_session_id(original_user_request: str | None = None) -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}_{_request_slug(original_user_request)}_{uuid.uuid4().hex[:8]}"


def _display_path(root: Path, session_id: str) -> str:
    if root == _DEFAULT_DEBUG_ROOT:
        return f".debug/skill_authoring/{session_id}"
    return (root / session_id).as_posix()


__all__ = [
    "AUTHORING_DEBUG_ENV",
    "AuthoringDebugSession",
    "skill_authoring_debug_enabled",
]
