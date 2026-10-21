"""Deterministic extraction of structured payloads from model responses.

Extractors remove optional human-readable prose without inventing missing fields
or changing payloads. Contract validation remains each caller's responsibility.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum


class ExtractionMethod(str, Enum):
    JARVIS_DATA = "jarvis_data"
    MARKDOWN_JSON = "markdown_json"
    BALANCED_JSON = "balanced_json"
    NONE = "none"


class CodeProposalExtractionMethod(str, Enum):
    META_SOURCE_TESTS = "meta_source_tests"
    MARKDOWN_CODE_PROPOSAL = "markdown_code_proposal"
    LEGACY_JARVIS_DATA = "legacy_jarvis_data"
    LEGACY_JSON = "legacy_json"
    NONE = "none"


@dataclass(frozen=True)
class StructuredResponseResult:
    success: bool
    data: object | None
    extraction_method: ExtractionMethod
    raw_payload: str | None
    error: str | None = None
    structural_error: str | None = None
    has_meta: bool | None = None
    has_source: bool | None = None
    has_tests: bool | None = None


@dataclass(frozen=True)
class StructuredCodeProposal:
    """Transport-only representation of a coder response.

    ``metadata`` remains strict JSON. Source and tests are literal block content
    so Python does not need to be escaped into a JSON string.
    """

    success: bool
    metadata: dict[str, object] | None
    source_code: str | None
    tests_source: str | None
    extraction_method: CodeProposalExtractionMethod
    diagnostics: tuple[str, ...] = ()
    error: str | None = None
    structural_error: str | None = None
    has_meta: bool | None = None
    has_source: bool | None = None
    has_tests: bool | None = None


_OPEN_TAG = "<JARVIS_DATA>"
_CLOSE_TAG = "</JARVIS_DATA>"
_META_OPEN_TAG = "<JARVIS_META>"
_META_CLOSE_TAG = "</JARVIS_META>"
_SOURCE_OPEN_TAG = "<JARVIS_SOURCE>"
_SOURCE_CLOSE_TAG = "</JARVIS_SOURCE>"
_TESTS_OPEN_TAG = "<JARVIS_TESTS>"
_TESTS_CLOSE_TAG = "</JARVIS_TESTS>"
_MARKDOWN_JSON_PATTERN = re.compile(
    r"```json[ \t]*(?:\r?\n)?(.*?)```",
    flags=re.DOTALL | re.IGNORECASE,
)


_FENCED_CODE_BLOCK_PATTERN = re.compile(
    r"```(?P<language>json|python)[ \t]*(?:\r?\n)?(?P<payload>.*?)```",
    flags=re.DOTALL | re.IGNORECASE,
)
_MARKDOWN_METADATA_FIELDS = frozenset(
    {"skill_name", "implementation_summary", "dependencies"}
)

def extract_structured_response(raw_response: str) -> StructuredResponseResult:
    """Extract one JSON object using a deterministic priority order.

    A tagged payload has priority over a Markdown block, which has priority over
    a balanced object embedded in ordinary prose. Once a higher-priority wrapper
    is present but invalid, it fails closed rather than silently selecting a
    different object from the same response.
    """

    if not isinstance(raw_response, str) or not raw_response.strip():
        return _failure(ExtractionMethod.NONE, None, "Response is empty or not text.")

    tagged_payload = _find_tagged_payload(raw_response)
    if tagged_payload is not None:
        return _parse_payload(tagged_payload, ExtractionMethod.JARVIS_DATA)

    markdown_payload = _find_markdown_payload(raw_response)
    if markdown_payload is not None:
        return _parse_payload(markdown_payload, ExtractionMethod.MARKDOWN_JSON)

    balanced_payload = _find_first_balanced_json_object(raw_response)
    if balanced_payload is None:
        return _failure(
            ExtractionMethod.NONE,
            None,
            "Response does not contain a complete JSON object.",
        )
    return _parse_payload(balanced_payload, ExtractionMethod.BALANCED_JSON)


def extract_structured_code_proposal(raw_response: str) -> StructuredCodeProposal:
    """Extract code proposals in deterministic, fail-closed priority order.

    Priority is explicit: JARVIS META/SOURCE/TESTS, Markdown metadata plus
    Python, legacy JARVIS_DATA, then failure. No parser infers source from prose
    or executes candidate content.
    """

    if not isinstance(raw_response, str) or not raw_response.strip():
        return _proposal_failure(
            "empty model response",
            diagnostics=("response=empty",),
            has_meta=False,
            has_source=False,
            has_tests=False,
        )

    tagged = _extract_tagged_code_proposal(raw_response)
    if tagged is not None:
        return tagged

    markdown = _extract_markdown_code_proposal(raw_response)
    if markdown is not None:
        return markdown

    legacy = _extract_legacy_code_proposal(raw_response)
    if legacy is not None:
        return legacy

    return _proposal_failure(
        "unknown structured response format",
        diagnostics=("structured=absent",),
        has_meta=False,
        has_source=False,
        has_tests=False,
    )


def _extract_tagged_code_proposal(
    raw_response: str,
) -> StructuredCodeProposal | None:
    meta_state, meta_payload = _tag_state(
        raw_response,
        _META_OPEN_TAG,
        _META_CLOSE_TAG,
    )
    source_state, source_payload = _tag_state(
        raw_response,
        _SOURCE_OPEN_TAG,
        _SOURCE_CLOSE_TAG,
    )
    tests_state, tests_payload = _tag_state(
        raw_response,
        _TESTS_OPEN_TAG,
        _TESTS_CLOSE_TAG,
    )
    has_meta = meta_state != "absent"
    has_source = source_state != "absent"
    has_tests = tests_state != "absent"

    if not has_meta and not has_source and not has_tests:
        return None
    if meta_state == "unclosed":
        return _proposal_failure(
            "unclosed JARVIS_META",
            diagnostics=("meta=unclosed",),
            has_meta=has_meta,
            has_source=has_source,
            has_tests=has_tests,
        )
    if not has_meta:
        return _proposal_failure(
            "missing JARVIS_META",
            diagnostics=("meta=missing",),
            has_meta=has_meta,
            has_source=has_source,
            has_tests=has_tests,
        )

    assert meta_payload is not None
    metadata_result = _parse_payload(
        meta_payload.strip(),
        ExtractionMethod.JARVIS_DATA,
    )
    if not metadata_result.success or not isinstance(metadata_result.data, dict):
        return _proposal_failure(
            "invalid JARVIS_META JSON",
            diagnostics=("meta=invalid",),
            has_meta=has_meta,
            has_source=has_source,
            has_tests=has_tests,
        )
    if source_state == "absent":
        return _proposal_failure(
            "missing JARVIS_SOURCE",
            diagnostics=("meta=ok", "source=missing"),
            has_meta=has_meta,
            has_source=has_source,
            has_tests=has_tests,
        )
    if source_state == "unclosed":
        return _proposal_failure(
            "unclosed JARVIS_SOURCE",
            diagnostics=("meta=ok", "source=unclosed"),
            has_meta=has_meta,
            has_source=has_source,
            has_tests=has_tests,
        )
    if tests_state == "unclosed":
        return _proposal_failure(
            "unclosed JARVIS_TESTS",
            diagnostics=("meta=ok", "source=ok", "tests=unclosed"),
            has_meta=has_meta,
            has_source=has_source,
            has_tests=has_tests,
        )

    assert source_payload is not None
    source_code = _literal_payload(source_payload)
    tests_source = (
        _literal_payload(tests_payload)
        if tests_state == "complete" and tests_payload is not None
        else None
    )
    if tests_source is not None and not tests_source.strip():
        tests_source = None
    return StructuredCodeProposal(
        success=True,
        metadata=metadata_result.data,
        source_code=source_code,
        tests_source=tests_source,
        extraction_method=CodeProposalExtractionMethod.META_SOURCE_TESTS,
        diagnostics=(
            "meta=ok",
            "source=ok",
            "tests=present" if tests_state == "complete" else "tests=absent",
        ),
        has_meta=has_meta,
        has_source=has_source,
        has_tests=has_tests,
    )


def _extract_markdown_code_proposal(
    raw_response: str,
) -> StructuredCodeProposal | None:
    blocks = tuple(
        (match.group("language").lower(), match.group("payload"))
        for match in _FENCED_CODE_BLOCK_PATTERN.finditer(raw_response)
    )
    json_indexes = [
        index for index, (language, _payload) in enumerate(blocks) if language == "json"
    ]
    python_indexes = [
        index for index, (language, _payload) in enumerate(blocks) if language == "python"
    ]
    if not json_indexes and not python_indexes:
        return None
    if not json_indexes:
        return _proposal_failure(
            "missing Markdown JSON metadata",
            diagnostics=("markdown=missing_json",),
            has_meta=False,
            has_source=bool(python_indexes),
            has_tests=False,
        )

    metadata: dict[str, object] | None = None
    metadata_index: int | None = None
    for index in json_indexes:
        parsed = _parse_payload(blocks[index][1].strip(), ExtractionMethod.MARKDOWN_JSON)
        if not parsed.success or not isinstance(parsed.data, dict):
            continue
        if _MARKDOWN_METADATA_FIELDS.issubset(parsed.data):
            metadata = parsed.data
            metadata_index = index
            break
    if metadata is None or metadata_index is None:
        return _proposal_failure(
            "invalid Markdown metadata JSON",
            diagnostics=("markdown=invalid_metadata",),
            has_meta=True,
            has_source=bool(python_indexes),
            has_tests=False,
        )

    python_index = next(
        (index for index in python_indexes if index > metadata_index),
        None,
    )
    if python_index is None:
        return _proposal_failure(
            "missing Markdown Python fence",
            diagnostics=("markdown=missing_python",),
            has_meta=True,
            has_source=False,
            has_tests=False,
        )

    source_code, tests_source = _split_markdown_source_and_tests(
        blocks[python_index][1]
    )
    return StructuredCodeProposal(
        success=True,
        metadata=metadata,
        source_code=source_code,
        tests_source=tests_source,
        extraction_method=CodeProposalExtractionMethod.MARKDOWN_CODE_PROPOSAL,
        diagnostics=(
            "markdown_meta=ok",
            "markdown_source=ok",
            "markdown_tests=present" if tests_source is not None else "markdown_tests=absent",
        ),
        has_meta=True,
        has_source=True,
        has_tests=tests_source is not None,
    )


def _split_markdown_source_and_tests(source: str) -> tuple[str, str | None]:
    lines = source.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.strip() == "# JARVIS_TESTS":
            tests = "".join(lines[index + 1 :])
            return "".join(lines[:index]), tests if tests.strip() else None
    return source, None


def _extract_legacy_code_proposal(
    raw_response: str,
) -> StructuredCodeProposal | None:
    legacy_state, legacy_payload = _tag_state(raw_response, _OPEN_TAG, _CLOSE_TAG)
    if legacy_state == "absent":
        return None
    if legacy_state == "unclosed":
        return _proposal_failure(
            "legacy JARVIS_DATA invalid",
            diagnostics=("legacy=unclosed",),
            has_meta=False,
            has_source=False,
            has_tests=False,
        )

    assert legacy_payload is not None
    legacy = _parse_payload(legacy_payload.strip(), ExtractionMethod.JARVIS_DATA)
    if not legacy.success or not isinstance(legacy.data, dict):
        return _proposal_failure(
            "legacy JARVIS_DATA invalid",
            diagnostics=("legacy=invalid",),
            has_meta=False,
            has_source=False,
            has_tests=False,
        )
    return _legacy_proposal(
        legacy.data,
        CodeProposalExtractionMethod.LEGACY_JARVIS_DATA,
    )

def _legacy_proposal(
    payload: dict[str, object],
    method: CodeProposalExtractionMethod,
) -> StructuredCodeProposal:
    source_code = payload.get("source_code")
    tests_source = payload.get("tests_source")
    return StructuredCodeProposal(
        success=True,
        metadata=payload,
        source_code=source_code if isinstance(source_code, str) else None,
        tests_source=tests_source if isinstance(tests_source, str) else tests_source,
        extraction_method=method,
        diagnostics=(f"legacy_method={method.value}",),
        has_meta=False,
        has_source=False,
        has_tests=False,
    )

def _find_tagged_payload(text: str) -> str | None:
    payload = _find_block(text, _OPEN_TAG, _CLOSE_TAG)
    return payload.strip() if payload is not None else None


def _find_block(text: str, opening_tag: str, closing_tag: str) -> str | None:
    state, payload = _tag_state(text, opening_tag, closing_tag)
    return payload if state == "complete" else None


def _tag_state(
    text: str,
    opening_tag: str,
    closing_tag: str,
) -> tuple[str, str | None]:
    start = text.find(opening_tag)
    if start < 0:
        return "absent", None
    payload_start = start + len(opening_tag)
    end = text.find(closing_tag, payload_start)
    if end < 0:
        return "unclosed", None
    return "complete", text[payload_start:end]


def _literal_payload(payload: str) -> str:
    # Tags conventionally occupy their own line. Drop only that separator; all
    # remaining bytes, including the source's final newline, are literal data.
    if payload.startswith("\r\n"):
        return payload[2:]
    if payload.startswith("\n"):
        return payload[1:]
    return payload

def _find_markdown_payload(text: str) -> str | None:
    match = _MARKDOWN_JSON_PATTERN.search(text)
    return match.group(1).strip() if match else None


def _find_first_balanced_json_object(text: str) -> str | None:
    """Return the first parseable brace-balanced object in ``text``.

    The scanner tracks JSON strings and escapes, so braces inside string values
    (including Python source held in JSON) never change object depth.
    """

    for start, character in enumerate(text):
        if character != "{":
            continue
        end = _balanced_object_end(text, start)
        if end is None:
            continue
        candidate = text[start:end]
        try:
            value = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(value, dict):
            return candidate
    return None


def _balanced_object_end(text: str, start: int) -> int | None:
    depth = 0
    in_string = False
    escaped = False

    for index in range(start, len(text)):
        character = text[index]
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
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index + 1
            if depth < 0:
                return None
    return None


def _parse_payload(
    raw_payload: str,
    extraction_method: ExtractionMethod,
) -> StructuredResponseResult:
    if not raw_payload:
        return _failure(extraction_method, raw_payload, "Structured payload is empty.")
    try:
        data = json.loads(raw_payload)
    except (json.JSONDecodeError, TypeError) as exc:
        return _failure(
            extraction_method,
            raw_payload,
            "Structured payload contains invalid JSON: "
            f"{exc.msg if isinstance(exc, json.JSONDecodeError) else exc}",
        )
    if not isinstance(data, dict):
        return _failure(
            extraction_method,
            raw_payload,
            "Structured payload must be a JSON object.",
        )
    return StructuredResponseResult(
        success=True,
        data=data,
        extraction_method=extraction_method,
        raw_payload=raw_payload,
    )


def _proposal_failure(
    error: str,
    *,
    diagnostics: tuple[str, ...] = (),
    has_meta: bool | None = None,
    has_source: bool | None = None,
    has_tests: bool | None = None,
) -> StructuredCodeProposal:
    return StructuredCodeProposal(
        success=False,
        metadata=None,
        source_code=None,
        tests_source=None,
        extraction_method=CodeProposalExtractionMethod.NONE,
        diagnostics=diagnostics,
        error=error,
        structural_error=error,
        has_meta=has_meta,
        has_source=has_source,
        has_tests=has_tests,
    )


def _failure(
    extraction_method: ExtractionMethod,
    raw_payload: str | None,
    error: str,
) -> StructuredResponseResult:
    return StructuredResponseResult(
        success=False,
        data=None,
        extraction_method=extraction_method,
        raw_payload=raw_payload,
        error=error,
    )


__all__ = [
    "CodeProposalExtractionMethod",
    "ExtractionMethod",
    "StructuredCodeProposal",
    "StructuredResponseResult",
    "extract_structured_code_proposal",
    "extract_structured_response",
]