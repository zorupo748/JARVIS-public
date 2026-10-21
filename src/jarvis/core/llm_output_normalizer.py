"""Deterministic, non-executing normalization for authoring model output."""

from __future__ import annotations

import ast
import io
import json
import re
import tokenize
from dataclasses import dataclass
from enum import Enum

from jarvis.core.authoring_metadata import build_initial_metadata

from jarvis.core.structured_response import (
    extract_structured_code_proposal,
    extract_structured_response,
)


class AuthoringPhase(str, Enum):
    """The expected contract for a single local-coder response."""

    SOURCE_INITIAL = "source_initial"
    # Compatibility alias for callers from the first two-phase implementation.
    SOURCE = "source_initial"
    SOURCE_REPAIR = "source_repair"
    TESTS = "tests"


class NormalizedOutputKind(str, Enum):
    SOURCE_PROPOSAL = "source_proposal"
    TESTS = "tests"
    REVIEW_RESULT = "review_result"
    VALIDATION_REPORT = "validation_report"
    TRUNCATED = "truncated"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NormalizedAuthoringOutput:
    """A recovered literal payload, or a deterministic failure classification.

    This module only classifies and extracts literal text.  It never writes,
    imports, fixes, or executes candidate text; metadata reuse belongs to the
    authoring service, which has the frozen, previously validated metadata.
    """

    kind: NormalizedOutputKind
    phase: AuthoringPhase
    metadata: dict[str, object] | None = None
    source_code: str | None = None
    tests_source: str | None = None
    extraction_method: str | None = None
    error: str | None = None
    truncated: bool = False
    has_meta: bool | None = None
    has_source: bool | None = None
    has_tests: bool | None = None
    structural_error_code: str | None = None
    structurally_recovered: bool = False

    @property
    def success(self) -> bool:
        return self.kind in {
            NormalizedOutputKind.SOURCE_PROPOSAL,
            NormalizedOutputKind.TESTS,
        }


_TESTS_TAG = "JARVIS_TESTS"
_SOURCE_TAG = "JARVIS_SOURCE"
_META_TAG = "JARVIS_META"
_FENCE = "`" * 3
_PYTHON_FENCE_PATTERN = re.compile(
    r"```(?:python|py)[ \t]*(?:\r?\n)?(?P<payload>.*?)```", re.IGNORECASE | re.DOTALL
)


def normalize_authoring_output(
    raw_response: object,
    *,
    phase: AuthoringPhase,
    user_request: str = "",
    existing_skill_name: str | None = None,
) -> NormalizedAuthoringOutput:
    """Classify raw LLM text according to the explicit authoring phase.

    Transport is tolerant; candidate validation remains a separate step.
    Initial metadata is built statically. Repairs reuse the caller's frozen
    metadata and never derive replacement declarations from repaired code.
    """

    if not isinstance(raw_response, str) or not raw_response.strip():
        return _failure(phase, "empty model response")

    literal_python = _is_plain_source(raw_response) or _is_tests_only(raw_response)
    truncation = None if literal_python else _truncation_reason(raw_response)
    if truncation is not None:
        return _failure(
            phase,
            truncation,
            kind=NormalizedOutputKind.TRUNCATED,
            truncated=True,
        )

    candidate = _candidate_python_for_token_check(raw_response)
    # Structured data inside a Python implementation is code, not a review.
    python_contract = literal_python or bool(candidate and _python_tree(candidate) is not None and (
        _is_plain_source(candidate) or _is_tests_only(candidate)
    ))
    wrong_kind = None if python_contract else _classify_non_authoring_json(raw_response)
    if wrong_kind is not None:
        return _failure(
            phase,
            "model returned a different structured contract",
            kind=wrong_kind,
        )

    if phase is AuthoringPhase.SOURCE_INITIAL:
        return _normalize_source(raw_response, phase, user_request, existing_skill_name)
    if phase is AuthoringPhase.SOURCE_REPAIR:
        return _normalize_source(raw_response, phase, user_request, existing_skill_name)
    return _normalize_tests(raw_response)


def _normalize_source(
    raw: str, phase: AuthoringPhase, user_request: str,
    existing_skill_name: str | None,
) -> NormalizedAuthoringOutput:
    """Extract literal code first; secondary metadata cannot hide that code."""
    plain = _is_plain_source(raw)
    tagged = [] if plain else _tag_payloads(raw, _SOURCE_TAG)
    fenced = [] if plain else _python_payloads(raw)
    if len(tagged) > 1 or len(fenced) > 1:
        return _failure(phase, "ambiguous Python blocks in source", code="ambiguous_python_blocks")
    metadata, metadata_error, has_meta = (None, None, False) if plain else _optional_repair_metadata(raw)
    if metadata_error:
        return _failure(phase, metadata_error, code="ambiguous_metadata", has_meta=True)

    legacy = extract_structured_code_proposal(raw)
    if plain:
        source = raw
        method = "plain_python"
    elif tagged:
        source = tagged[0]
        inner_fences = _python_payloads(source)
        if len(inner_fences) == 1 and _PYTHON_FENCE_PATTERN.fullmatch(source.strip()):
            source = inner_fences[0]
        if fenced and fenced[0].strip() != source.strip() and _extract_closed_tag(fenced[0], _SOURCE_TAG) != source:
            return _failure(phase, "contradictory source representations", code="ambiguous_python_blocks")
        method = "jarvis_source_repair" if phase is AuthoringPhase.SOURCE_REPAIR else "meta_source_tests"
    elif fenced:
        source = fenced[0]
        method = "markdown_python_source_repair" if phase is AuthoringPhase.SOURCE_REPAIR else "python_fence"
    elif legacy.success and isinstance(legacy.source_code, str):
        source = legacy.source_code
        metadata = legacy.metadata
        has_meta = isinstance(metadata, dict)
        method = legacy.extraction_method.value
    else:
        return _failure(phase, "missing identifiable Python source", code="no_source_found", has_meta=has_meta, has_source=False)

    outside = re.sub(_tag_pattern(_SOURCE_TAG), "", raw, flags=re.DOTALL)
    outside = _PYTHON_FENCE_PATTERN.sub("", outside)
    if method != "plain_python" and re.search(r"^def\s+ejecutar_skill\s*\(", outside, re.MULTILINE):
        return _failure(phase, "additional unwrapped source implementation", code="ambiguous_python_blocks")

    if _mixed_source_tests(source) or _is_tests_only(source):
        return _failure(phase, "source and tests contracts are mixed or tests were returned as source", code="mixed_source_tests")
    if not source.strip():
        return _failure(phase, "source output is empty", code="no_source_found")
    initial = phase is AuthoringPhase.SOURCE_INITIAL
    built = build_initial_metadata(source, metadata, user_request, existing_skill_name=existing_skill_name) if initial else metadata
    recovered = (
        method not in {"meta_source_tests", "jarvis_source_repair"}
        or (initial and (built != metadata or not legacy.success))
        or bool(tagged and source != tagged[0])
    )
    return NormalizedAuthoringOutput(
        kind=NormalizedOutputKind.SOURCE_PROPOSAL, phase=phase,
        metadata=built, source_code=source, extraction_method=method,
        has_meta=has_meta, has_source=True, has_tests=bool(_tag_payloads(raw, _TESTS_TAG)),
        structurally_recovered=recovered,
    )


def _python_tree(source: str) -> ast.Module | None:
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


def _is_plain_source(source: str) -> bool:
    tree = _python_tree(source)
    return tree is not None and any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "ejecutar_skill"
        for node in tree.body
    )


def _has_tests(tree: ast.Module) -> bool:
    return any(
        (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"))
        or isinstance(node, ast.Assert)
        or (isinstance(node, ast.ClassDef) and _is_test_case(node))
        for node in ast.walk(tree)
    )


def _is_test_case(node: ast.ClassDef) -> bool:
    return any(
        (isinstance(base, ast.Attribute) and base.attr == "TestCase")
        or (isinstance(base, ast.Name) and base.id == "TestCase") for base in node.bases
    )


def _is_tests_only(source: str) -> bool:
    tree = _python_tree(source)
    return tree is not None and _has_tests(tree) and not any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "ejecutar_skill"
        for node in tree.body
    )


def _mixed_source_tests(source: str) -> bool:
    tree = _python_tree(source)
    if tree is None:
        return False  # Syntax-invalid explicit payloads belong to the validator.
    entry = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "ejecutar_skill" for n in tree.body)
    tests = any(
        (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_"))
        or (isinstance(n, ast.ClassDef) and _is_test_case(n))
        for n in tree.body
    )
    return entry and tests


def _optional_repair_metadata(
    raw_response: str,
) -> tuple[dict[str, object] | None, str | None, bool]:
    tagged = _tag_payloads(raw_response, _META_TAG)
    # Only inspect transport outside Python. A dict literal in source is not
    # proposal metadata, even if it happens to contain a skill_name key.
    outside = _PYTHON_FENCE_PATTERN.sub("", raw_response)
    outside = re.sub(_tag_pattern(_SOURCE_TAG), "", outside, flags=re.DOTALL)
    if _is_plain_source(raw_response):
        outside = ""
    outside = re.sub(_tag_pattern(_META_TAG), "", outside, flags=re.DOTALL)
    payloads = [*tagged, outside]
    objects: list[dict[str, object]] = []
    try:
        for payload in payloads:
            objects.extend(_metadata_objects(payload))
    except ValueError:
        return None, "ambiguous metadata JSON keys", True
    if len(objects) > 1 and any(obj != objects[0] for obj in objects[1:]):
        return None, "contradictory metadata objects", True
    return (objects[0] if objects else None), None, bool(tagged or objects)


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _metadata_objects(payload: str) -> list[dict[str, object]]:
    decoder = json.JSONDecoder(object_pairs_hook=_unique_json_pairs)
    objects = []
    index = 0
    while (start := payload.find("{", index)) >= 0:
        try:
            value, end = decoder.raw_decode(payload[start:])
        except json.JSONDecodeError:
            index = start + 1
            continue
        index = start + end
        if isinstance(value, dict) and isinstance(value.get("metadata"), dict):
            value = value["metadata"]
        if isinstance(value, dict) and {"skill_name", "implementation_summary", "dependencies"}.intersection(value):
            objects.append(value)
    return objects


def _normalize_tests(raw_response: str) -> NormalizedAuthoringOutput:
    if _is_tests_only(raw_response):
        return _tests_result(raw_response, extraction_method="plain_python", has_tests=True)
    if len(_tag_payloads(raw_response, _TESTS_TAG)) > 1:
        return _failure(AuthoringPhase.TESTS, "ambiguous JARVIS_TESTS blocks", code="ambiguous_python_blocks")
    tagged = _extract_closed_tag(raw_response, _TESTS_TAG)
    if tagged is not None:
        outside_source = re.sub(_tag_pattern(_SOURCE_TAG), "", raw_response, flags=re.DOTALL)
        for payload in _python_payloads(outside_source):
            if _extract_closed_tag(payload, _TESTS_TAG) == tagged:
                continue  # A Markdown wrapper around the same explicit tests.
            if payload.strip() != tagged.strip():
                return _failure(AuthoringPhase.TESTS, "contradictory tests representations", code="ambiguous_python_blocks")
        return _tests_result(tagged, extraction_method="jarvis_tests", has_tests=True)
    if f"<{_TESTS_TAG}>" in raw_response:
        return _failure(
            AuthoringPhase.TESTS,
            "unclosed JARVIS_TESTS",
            kind=NormalizedOutputKind.TRUNCATED,
            truncated=True,
            has_tests=True,
        )
    if any(
        re.search(rf"<\s*/?\s*{tag}\s*>", raw_response)
        for tag in (_SOURCE_TAG, _META_TAG, "JARVIS_DATA")
    ):
        return _failure(AuthoringPhase.TESTS, "model returned a different structured contract", code="wrong_contract")
    python_payloads = _python_payloads(raw_response)
    if len(python_payloads) == 1:
        return _tests_result(
            python_payloads[0], extraction_method="markdown_python", has_tests=True
        )
    if len(python_payloads) > 1:
        return _failure(AuthoringPhase.TESTS, "ambiguous Python fences in tests", code="ambiguous_python_blocks")
    if _FENCE not in raw_response and _is_tests_only(raw_response):
        return _tests_result(raw_response, extraction_method="plain_python", has_tests=True)
    return _failure(AuthoringPhase.TESTS, "missing JARVIS_TESTS or Python fence", code="no_tests_found")


def _tests_result(
    tests_source: str,
    *,
    extraction_method: str,
    has_tests: bool,
) -> NormalizedAuthoringOutput:
    if not tests_source.strip():
        return _failure(AuthoringPhase.TESTS, "tests output is empty", has_tests=has_tests)
    if _python_tree(tests_source) is not None and not _is_tests_only(tests_source):
        return _failure(AuthoringPhase.TESTS, "Python payload has no unambiguous tests", code="wrong_contract")
    return NormalizedAuthoringOutput(
        kind=NormalizedOutputKind.TESTS,
        phase=AuthoringPhase.TESTS,
        tests_source=tests_source,
        extraction_method=extraction_method,
        has_tests=has_tests,
        structurally_recovered=extraction_method != "jarvis_tests",
    )


def _classify_non_authoring_json(raw_response: str) -> NormalizedOutputKind | None:
    extraction = extract_structured_response(raw_response)
    payload = extraction.data if extraction.success else None
    if not isinstance(payload, dict):
        return None
    if "approved" in payload and {"issues", "blocking_issues", "blocker_statuses"}.intersection(payload):
        return NormalizedOutputKind.REVIEW_RESULT
    validation_keys = {"checks", "timed_out", "return_code", "traceback"}
    if "success" in payload and validation_keys.intersection(payload):
        return NormalizedOutputKind.VALIDATION_REPORT
    if "issues" in payload and "source_code" not in payload and "skill_name" not in payload:
        return NormalizedOutputKind.REVIEW_RESULT
    return None


def _truncation_reason(text: str) -> str | None:
    for tag in ("JARVIS_META", "JARVIS_SOURCE", "JARVIS_TESTS", "JARVIS_DATA"):
        openings = re.findall(rf"<\s*{tag}\s*>", text)
        closings = re.findall(rf"<\s*/\s*{tag}\s*>", text)
        if len(openings) > len(closings) or _tag_state(text, tag)[0] == "unclosed":
            return f"unclosed {tag}"
    if text.count(_FENCE) % 2:
        return "unclosed Markdown fence"
    stripped = text.rstrip()
    if stripped.startswith("{") and _unclosed_json_object(stripped):
        return "incomplete JSON object"
    candidate = _candidate_python_for_token_check(text)
    if candidate and _has_unclosed_python_string(candidate):
        return "Python appears truncated inside a string literal or statement"
    return None


def _candidate_python_for_token_check(text: str) -> str | None:
    source = _extract_closed_tag(text, _SOURCE_TAG)
    if source is not None:
        return source
    tests = _extract_closed_tag(text, _TESTS_TAG)
    if tests is not None:
        return tests
    payloads = _python_payloads(text)
    if len(payloads) == 1:
        return payloads[0]
    if not payloads and re.search(r"^\s*(?:def |import |from |class )", text, re.MULTILINE):
        return text
    return None


def _has_unclosed_python_string(source: str) -> bool:
    try:
        ast.parse(source)
    except SyntaxError as exc:
        if "unterminated" in exc.msg:
            return True
    try:
        list(tokenize.generate_tokens(io.StringIO(source).readline))
    except tokenize.TokenError as exc:
        if "multi-line string" in str(exc).lower():
            return True
        try:
            ast.parse(source)
        except SyntaxError as syntax_error:
            # A complete wrapper with e.g. `def broken(:` is an identifiable
            # invalid candidate, rather than evidence of transport truncation.
            return "never closed" in syntax_error.msg or "unterminated" in syntax_error.msg
        return True
    except (IndentationError, SyntaxError):
        pass  # Complete but invalid syntax must reach CodeValidation.
    return False


def _unclosed_json_object(text: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
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
    return depth > 0 or in_string


def _tag_state(text: str, tag: str) -> tuple[str, str | None]:
    opening = re.search(rf"<\s*{tag}\s*>", text)
    if opening is None:
        return "absent", None
    closing = re.search(rf"<\s*/\s*{tag}\s*>", text[opening.end():])
    if closing is None:
        return "unclosed", None
    return "complete", _drop_initial_newline(text[opening.end():opening.end() + closing.start()])


def _tag_pattern(tag: str) -> str:
    return rf"<\s*{tag}\s*>(.*?)<\s*/\s*{tag}\s*>"


def _tag_payloads(text: str, tag: str) -> list[str]:
    return [_drop_initial_newline(m.group(1)) for m in re.finditer(_tag_pattern(tag), text, re.DOTALL)]


def _extract_closed_tag(text: str, tag: str) -> str | None:
    state, payload = _tag_state(text, tag)
    return payload if state == "complete" else None


def _python_payloads(text: str) -> list[str]:
    return [
        _drop_initial_newline(match.group("payload"))
        for match in _PYTHON_FENCE_PATTERN.finditer(text)
    ]


def _drop_initial_newline(payload: str) -> str:
    if payload.startswith("\r\n"):
        return payload[2:]
    if payload.startswith("\n"):
        return payload[1:]
    return payload


def _failure(
    phase: AuthoringPhase,
    error: str,
    *,
    kind: NormalizedOutputKind = NormalizedOutputKind.UNKNOWN,
    truncated: bool = False,
    extraction_method: str | None = "none",
    has_meta: bool | None = None,
    has_source: bool | None = None,
    has_tests: bool | None = None,
    code: str | None = None,
) -> NormalizedAuthoringOutput:
    if code is None:
        code = "truncated_response" if truncated else "wrong_contract" if kind in {
            NormalizedOutputKind.REVIEW_RESULT, NormalizedOutputKind.VALIDATION_REPORT,
        } else "no_source_found"
    return NormalizedAuthoringOutput(
        kind=kind,
        phase=phase,
        error=error,
        truncated=truncated,
        extraction_method=extraction_method,
        has_meta=has_meta,
        has_source=has_source,
        has_tests=has_tests,
        structural_error_code=code,
    )


__all__ = [
    "AuthoringPhase",
    "NormalizedAuthoringOutput",
    "NormalizedOutputKind",
    "normalize_authoring_output",
]
