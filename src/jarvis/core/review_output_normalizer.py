"""Deterministic, non-executing normalization for code-review responses."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from jarvis.core.structured_response import extract_structured_response


_OPEN_TAG = "<JARVIS_DATA>"
_CLOSE_TAG = "</JARVIS_DATA>"
_JSON_FENCE_OPEN = re.compile(r"[\x60]{3}json\b", flags=re.IGNORECASE)
_REVIEW_ROOT_START = re.compile(r'\{\s*"approved"\s*:', flags=re.DOTALL)


@dataclass(frozen=True)
class NormalizedReviewOutput:
    """A review payload structurally safe to pass to CodeReviewer."""

    success: bool
    payload: dict[str, object] | None
    extraction_method: str | None = None
    error: str | None = None
    truncated: bool = False


def normalize_review_output(raw_response: object) -> NormalizedReviewOutput:
    """Extract one complete review decision without inventing data.

    The ordered transport formats are a closed JARVIS_DATA block, complete JSON,
    a complete Markdown JSON fence, or prose containing one complete root object.
    An opened tagged payload or root review object is never recovered from
    internal issue dictionaries: it is classified as incomplete instead.
    """

    if not isinstance(raw_response, str) or not raw_response.strip():
        return _failure("review response is empty or not text")

    truncated_error = _truncated_payload_error(raw_response)
    if truncated_error is not None:
        return _failure(truncated_error, truncated=True)

    extraction = extract_structured_response(raw_response)
    if not extraction.success or not isinstance(extraction.data, dict):
        return _failure(
            extraction.error or "review response does not contain a JSON object",
            extraction_method=extraction.extraction_method.value,
        )

    if (
        extraction.extraction_method.value == "balanced_json"
        and _count_recoverable_top_level_json_objects(raw_response) != 1
    ):
        return _failure(
            "review response contains ambiguous top-level JSON objects",
            extraction_method=extraction.extraction_method.value,
        )

    payload = extraction.data
    if "approved" not in payload:
        return _failure(
            "review response is missing required field 'approved'",
            extraction_method=extraction.extraction_method.value,
        )
    if not isinstance(payload["approved"], bool):
        return _failure(
            "review response requires boolean 'approved'",
            extraction_method=extraction.extraction_method.value,
        )
    structured_review = "blocking_issues" in payload or "blocker_statuses" in payload
    if "issues" not in payload and not structured_review:
        return _failure(
            "review response is missing required field 'issues'",
            extraction_method=extraction.extraction_method.value,
        )
    if not structured_review and not isinstance(payload["issues"], list):
        return _failure(
            "review response field 'issues' must be a list",
            extraction_method=extraction.extraction_method.value,
        )
    return NormalizedReviewOutput(
        success=True,
        payload=payload,
        extraction_method=extraction.extraction_method.value,
    )


def _truncated_payload_error(text: str) -> str | None:
    """Return a safe truncation reason before generic JSON recovery."""

    tag_start = text.find(_OPEN_TAG)
    if tag_start >= 0 and text.find(_CLOSE_TAG, tag_start + len(_OPEN_TAG)) < 0:
        return "review response truncated before completing structured payload"

    fence_match = _JSON_FENCE_OPEN.search(text)
    if fence_match is not None and text.find(chr(96) * 3, fence_match.end()) < 0:
        return "review response truncated before completing structured payload"

    root_match = _REVIEW_ROOT_START.search(text)
    if root_match is not None and _json_container_is_incomplete(text, root_match.start()):
        return "review response truncated before completing structured payload"
    return None


def _json_container_is_incomplete(text: str, start: int) -> bool:
    """Check only container closure; it does not repair malformed JSON."""

    stack: list[str] = []
    in_string = False
    escaped = False
    for character in text[start:]:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "{[":
            stack.append(character)
        elif character in "}]":
            if not stack:
                return False
            opening = stack.pop()
            if (opening, character) not in {("{", "}"), ("[", "]")}:
                return False
            if not stack:
                return False
    return bool(stack) or in_string


def _count_recoverable_top_level_json_objects(text: str) -> int:
    """Count complete root objects; nested issue dictionaries are consumed once."""

    decoder = json.JSONDecoder()
    count = 0
    index = 0
    while index < len(text):
        start = text.find("{", index)
        if start < 0:
            break
        try:
            payload, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            index = start + 1
            continue
        if isinstance(payload, dict):
            count += 1
        index = end
    return count


def _failure(
    error: str,
    *,
    extraction_method: str | None = None,
    truncated: bool = False,
) -> NormalizedReviewOutput:
    return NormalizedReviewOutput(
        success=False,
        payload=None,
        extraction_method=extraction_method,
        error=error,
        truncated=truncated,
    )


__all__ = ["NormalizedReviewOutput", "normalize_review_output"]
