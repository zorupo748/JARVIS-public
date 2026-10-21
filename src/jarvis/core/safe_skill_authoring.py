"""Isolated, non-deploying authoring pipeline for proposed skills.

This service coordinates a local code proposal, static validation, and review. It
never enables dynamic authoring, writes a skill, imports candidate code, or
executes any generated content.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Iterable, Mapping, Protocol

from jarvis.core.authoring_debug import (
    AuthoringDebugSession,
    skill_authoring_debug_enabled,
)
from jarvis.core.dependency_resolver import (
    DependencyResolution,
    DependencyResolver,
    DependencyStatus,
)
from jarvis.core.code_reviewer import (
    CodeReviewRequest,
    CodeReviewResult,
    CodeReviewer,
    ReviewIssue,
    ReviewSeverity,
    ReviewRuntimeContext,
)
from jarvis.core.review_acceptance import ReviewAcceptancePlan, ReviewAcceptanceState
from jarvis.core.code_validation import (
    LocalCodeValidator,
    ValidationCheck,
    ValidationReport,
    with_dynamic_skill_entrypoint_validation,
)
from jarvis.core.external_data_requirements import requires_live_external_data
from jarvis.core.external_source_research import (
    ExternalSourceResearch,
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
    requested_external_source,
    research_source_matches,
    validate_research_result,
)
from jarvis.core.structured_response import (
    StructuredCodeProposal,
    extract_structured_code_proposal,
)


AUTHORING_MAX_SECONDS_ENV = "JARVIS_SKILL_AUTHORING_MAX_SECONDS"
DEFAULT_MAX_AUTHORING_SECONDS = 1_200.0
# This cap only prevents an accidental infinite loop. The authoring deadline is
# the normal stopping condition, not a small fixed number of iterations.
DEFAULT_MAX_AUTHORING_ITERATIONS_HARD_CAP = 10_000
DEFAULT_NO_PROGRESS_ITERATIONS = 3
DEFAULT_MAX_REVIEW_CYCLES = 2
DEFAULT_MAX_SOURCE_REPAIRS = 6
SOURCE_REPAIRS_ENV = "JARVIS_SKILL_AUTHORING_MAX_SOURCE_REPAIRS"
DEFAULT_STRUCTURAL_RESCUE_AFTER_FAILURES = 3
DEFAULT_MAX_CONSECUTIVE_STRUCTURAL_FAILURES = 5
_SKILL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class LocalCodingRouter(Protocol):
    def run_local_coding(self, prompt: str) -> str: ...


@dataclass(frozen=True)
class SkillAuthoringRequest:
    """Original user intent and optional non-executable authoring context."""

    user_request: str
    existing_skill_name: str | None = None
    relevant_context: str | None = None
    external_source_research: ExternalSourceResearchResult | None = None


@dataclass(frozen=True)
class GeneratedSkillProposal:
    skill_name: str
    source_code: str
    implementation_summary: str
    tests_source: str | None = None
    dependencies: tuple[str, ...] = ()
    iteration: int = 1


@dataclass(frozen=True)
class AuthoringIterationDiagnostic:
    """Non-sensitive, concise state captured for one authoring attempt."""

    iteration: int
    elapsed_seconds: float
    source_hash: str | None
    validation_success: bool | None
    review_approved: bool | None
    issue_fingerprint: str | None
    progress_detected: bool
    generation_success: bool = False
    structural_retries: int = 0
    source_changed: bool | None = None
    validation_fingerprint: str | None = None
    reviewer_used: str | None = None
    cloud_failed: bool | None = None
    cloud_failure_reason: str | None = None
    review_fingerprint: str | None = None
    stagnation_count: int = 0
    rescue_triggered: bool = False
    extraction_method: str | None = None
    structural_error: str | None = None
    has_meta: bool | None = None
    has_source: bool | None = None
    has_tests: bool | None = None
    phase: str = 'source'
    normalized_kind: str | None = None
    normalization_error: str | None = None
    truncated: bool | None = None
    metadata_reused: bool | None = None
    metadata_change_ignored: bool | None = None
    review_attempts: int | None = None
    review_transport_failed: bool | None = None
    reviewer_normalized: bool | None = None
    reviewer_normalization_error: str | None = None
    reviewer_truncated: bool | None = None
    review_plan_created: bool = False
    blocking_total: int | None = None
    blocking_unresolved: int | None = None
    blocking_resolved: int | None = None
    advisory_count: int | None = None
    regression_blockers: int | None = None
    source_repair_count: int = 0
    repair_blocker_ids: tuple[str, ...] = ()
    repair_blocker_count: int = 0
    repair_source_unchanged: bool | None = None
    local_review_num_predict: int | None = None
    blockers_downgraded_by_policy: tuple[str, ...] = ()
    review_skipped_reason: str | None = None
    structural_error_code: str | None = None
    structurally_recovered: bool = False
    first_response_structurally_valid: bool | None = None
    structural_retry_count: int = 0
    reviewer_repair_count: int = 0


@dataclass(frozen=True)
class SkillAuthoringResult:
    success: bool
    proposal: GeneratedSkillProposal | None
    iterations: int
    validation_reports: tuple[ValidationReport, ...]
    review_results: tuple[CodeReviewResult, ...]
    failure_reason: str | None = None
    declared_dependencies: tuple[str, ...] = ()
    unavailable_dependencies: tuple[str, ...] = ()
    dependency_results: tuple[DependencyResolution, ...] = ()
    diagnostics: tuple[AuthoringIterationDiagnostic, ...] = ()
    review_acceptance_plan: ReviewAcceptancePlan | None = None


class SkillProposalParseError(ValueError):
    """The local coder did not return a safe structured proposal."""


def get_skill_authoring_max_seconds(
    environ: Mapping[str, str] | None = None,
) -> float:
    """Read the authoring-only deadline without loading a dotenv file.

    Invalid or empty environment values fail safely to the documented default,
    so a malformed optional setting cannot prevent JARVIS from starting.
    """

    environment = os.environ if environ is None else environ
    raw_value = environment.get(AUTHORING_MAX_SECONDS_ENV, "").strip()
    if not raw_value:
        return DEFAULT_MAX_AUTHORING_SECONDS
    try:
        value = float(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_AUTHORING_SECONDS
    return value if math.isfinite(value) and value > 0 else DEFAULT_MAX_AUTHORING_SECONDS


def get_skill_authoring_max_source_repairs(
    environ: Mapping[str, str] | None = None,
) -> int:
    environment = os.environ if environ is None else environ
    raw_value = environment.get(SOURCE_REPAIRS_ENV, "").strip()
    try:
        value = int(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_SOURCE_REPAIRS
    return value if 1 <= value <= 100 else DEFAULT_MAX_SOURCE_REPAIRS


def format_dynamic_evidence_prompt(research: ExternalSourceResearchResult) -> str:
    """Format observed dynamic interaction evidence into unambiguous instructions for the coder LLM."""
    if not research.dynamic_interaction_evidence:
        return ""
    ev = research.dynamic_interaction_evidence
    lines = [
        "--- VERIFIED DYNAMIC INTERACTION EVIDENCE (SPA / INTERACTIVE WEB) ---",
        "An autonomous dynamic interaction probe was executed using SecureWebSession Playwright automation.",
    ]
    if ev.get("interaction_performed"):
        lines.append(f"- Probe Parameter Tested: {ev.get('probe_value')!r}")
        if ev.get("input_selector"):
            lines.append(f"- Verified Input Selector: {ev.get('input_selector')}")
        if ev.get("button_selector"):
            lines.append(f"- Verified Button Selector: {ev.get('button_selector')}")
        if ev.get("result_selector"):
            lines.append(f"- Verified Result Container Selector: {ev.get('result_selector')}")
        if ev.get("result_text_sample"):
            lines.append(f"- Sample Result Text Captured from DOM: {ev.get('result_text_sample')}")
        if ev.get("result_dom_subtree"):
            lines.append(f"- Result DOM Subtree Excerpt: {ev.get('result_dom_subtree')}")

        captured_api = ev.get("captured_api")
        if isinstance(captured_api, dict):
            lines.extend([
                "- Intercepted Backend API Call:",
                f"    Endpoint URL: {captured_api.get('endpoint')}",
                f"    HTTP Method: {captured_api.get('http_method')}",
                f"    HTTP Status: {captured_api.get('status')}",
                f"    Observed JSON Keys: {captured_api.get('sample_keys')}",
                f"    Observed JSON Schema: {json.dumps(captured_api.get('json_schema'), ensure_ascii=False, indent=2)}",
            ])

    lines.extend([
        "\nMANDATORY INSTRUCTIONS FOR DYNAMIC SPA AUTOMATION:",
        "1. DO NOT GUESS OR INVENT SELECTORS: Use the exact verified input_selector, button_selector, and result_selector shown above.",
        "2. IF AN INTERCEPTED BACKEND API IS PRESENT: You may query the backend endpoint directly via secure HTTP (e.g. urllib.request, requests, or httpx) using the exact endpoint URL, parameters, and observed JSON keys, OR use SecureWebSession to automate the browser interaction.",
        "3. IF DOM INTERACTION IS REQUIRED: Reuse SecureWebSession (`from jarvis.core.security.secure_browser import SecureWebSession`) and call `session.interact_and_capture_sync(url, query_text, input_selectors=[...], button_selectors=[...])` using the verified selectors.",
        "--- END VERIFIED DYNAMIC INTERACTION EVIDENCE ---",
    ])
    return "\n".join(lines)


class SafeSkillAuthoringService:
    """Generate, validate, review, and repair proposals without deploying them.

    The only generation route is ``run_local_coding``. Review remains delegated
    to ``CodeReviewer``, which owns its explicit Groq-to-local review fallback.
    """

    def __init__(
        self,
        model_router: LocalCodingRouter,
        *,
        validator: LocalCodeValidator | None = None,
        reviewer: CodeReviewer | None = None,
        max_seconds: float | None = None,
        max_iterations_hard_cap: int = DEFAULT_MAX_AUTHORING_ITERATIONS_HARD_CAP,
        max_iterations: int | None = None,
        no_progress_iterations: int = DEFAULT_NO_PROGRESS_ITERATIONS,
        max_review_cycles: int = DEFAULT_MAX_REVIEW_CYCLES,
        max_source_repairs: int | None = None,
        structural_rescue_after_failures: int = DEFAULT_STRUCTURAL_RESCUE_AFTER_FAILURES,
        max_consecutive_structural_failures: int = DEFAULT_MAX_CONSECUTIVE_STRUCTURAL_FAILURES,
        clock: Callable[[], float] | None = None,
        diagnostic_sink: Callable[[str], None] | None = None,
        debug_root: Path | None = None,
        known_available_dependencies: Iterable[str] = (),
        dependency_resolver: DependencyResolver | None = None,
        external_source_research: ExternalSourceResearch | None = None,
    ) -> None:
        if max_seconds is None:
            max_seconds = get_skill_authoring_max_seconds()
        if (
            not isinstance(max_seconds, (int, float))
            or isinstance(max_seconds, bool)
            or not math.isfinite(float(max_seconds))
            or max_seconds <= 0
        ):
            raise ValueError("max_seconds must be a positive finite number")
        # ``max_iterations`` remains as a compatibility-only explicit hard cap
        # for callers/tests. It is no longer a normal authoring budget.
        if max_iterations is not None:
            if (
                not isinstance(max_iterations, int)
                or isinstance(max_iterations, bool)
                or max_iterations < 1
            ):
                raise ValueError("max_iterations must be a positive integer")
            max_iterations_hard_cap = max_iterations
        if (
            not isinstance(max_iterations_hard_cap, int)
            or isinstance(max_iterations_hard_cap, bool)
            or max_iterations_hard_cap < 1
        ):
            raise ValueError("max_iterations_hard_cap must be a positive integer")
        if (
            not isinstance(no_progress_iterations, int)
            or isinstance(no_progress_iterations, bool)
            or no_progress_iterations < 1
        ):
            raise ValueError("no_progress_iterations must be a positive integer")
        if (
            not isinstance(max_review_cycles, int)
            or isinstance(max_review_cycles, bool)
            or max_review_cycles < 1
        ):
            raise ValueError("max_review_cycles must be a positive integer")
        if max_source_repairs is None:
            max_source_repairs = get_skill_authoring_max_source_repairs()
        if not isinstance(max_source_repairs, int) or isinstance(max_source_repairs, bool) or max_source_repairs < 1:
            raise ValueError("max_source_repairs must be a positive integer")
        if (
            not isinstance(structural_rescue_after_failures, int)
            or isinstance(structural_rescue_after_failures, bool)
            or structural_rescue_after_failures < 1
        ):
            raise ValueError("structural_rescue_after_failures must be a positive integer")
        if (
            not isinstance(max_consecutive_structural_failures, int)
            or isinstance(max_consecutive_structural_failures, bool)
            or max_consecutive_structural_failures < structural_rescue_after_failures
        ):
            raise ValueError(
                "max_consecutive_structural_failures must be an integer at or above "
                "structural_rescue_after_failures"
            )
        self._model_router = model_router
        self._validator = validator or LocalCodeValidator()
        self._reviewer = reviewer or CodeReviewer(model_router)  # type: ignore[arg-type]
        self._max_authoring_seconds = float(max_seconds)
        self._max_iterations_hard_cap = max_iterations_hard_cap
        self._no_progress_iterations = no_progress_iterations
        self._max_review_cycles = max_review_cycles
        self._max_source_repairs = max_source_repairs
        self._structural_rescue_after_failures = structural_rescue_after_failures
        self._max_consecutive_structural_failures = (
            max_consecutive_structural_failures
        )
        self._clock = clock or time.monotonic
        self._diagnostic_sink = diagnostic_sink or print
        self._debug_root = debug_root
        # The former allowlist is retained only for constructor compatibility.
        # It cannot assert availability without inspecting the active interpreter.
        self._dependency_resolver = dependency_resolver or DependencyResolver()
        self._external_source_research = external_source_research

    def _start_debug_session(self, original_user_request: str | None = None) -> AuthoringDebugSession:
        return AuthoringDebugSession.start(
            enabled=skill_authoring_debug_enabled(),
            warning_sink=self._diagnostic_sink,
            debug_root=self._debug_root,
            original_user_request=original_user_request,
        )
    def author(self, request: SkillAuthoringRequest) -> SkillAuthoringResult:
        """Return an approved in-memory proposal only after validation and review."""

        from jarvis.core.authoring_two_phase import author_two_phase

        self._validate_request(request)
        live_data_required = requires_live_external_data(request.user_request)
        research_provider = self._external_source_research
        if live_data_required:
            if research_provider is None:
                return self._failure(
                    iterations=0,
                    reports=[],
                    reviews=[],
                    diagnostics=[],
                    declared_dependencies=[],
                    reason=(
                        "No pude determinar de forma fiable cómo consultar esta fuente. "
                        "No hay un proveedor de investigación externa configurado."
                    ),
                )
            research_request = ExternalSourceResearchRequest(
                user_request=request.user_request,
                source=requested_external_source(request.user_request),
                capability="Acquire current external data and return source-grounded results.",
            )
            try:
                research = validate_research_result(
                    research_provider.research(research_request)
                )
                if not research_source_matches(research_request.source, research.source):
                    raise ValueError(
                        "external source research does not match the source named in the request"
                    )
                if research.final_url and not research_source_matches(
                    research_request.source, research.final_url
                ):
                    raise ValueError(
                        "final page URL does not match the source named in the request"
                    )
                if not research.sufficient:
                    detail = "; ".join(research.evidence or research.notes)
                    raise ValueError(
                        "insufficient_research"
                        + (f": {detail}" if detail else "")
                    )
            except Exception as exc:
                return self._failure(
                    iterations=0,
                    reports=[],
                    reviews=[],
                    diagnostics=[],
                    declared_dependencies=[],
                    reason=(
                        "No pude determinar de forma fiable cómo consultar esta fuente. "
                        f"External source research failed: {type(exc).__name__}: {exc}"
                    ),
                )
            context = request.relevant_context or ""
            facts_block = (
                "--- VERIFIED EXTERNAL SOURCE FACTS (DATA ONLY) ---\n"
                f"{research.to_prompt_context()}\n"
                "Only use endpoints listed as observed. An empty observed_endpoints list "
                "means no API endpoint was verified; do not infer or invent endpoints, "
                "selectors or parameters. If these facts do not support a real acquisition "
                "path, do not simulate results.\n"
                "--- END VERIFIED EXTERNAL SOURCE FACTS ---"
            )
            dynamic_block = format_dynamic_evidence_prompt(research)
            research_context = f"{facts_block}\n\n{dynamic_block}" if dynamic_block else facts_block
            request = replace(
                request,
                external_source_research=research,
                relevant_context="\n\n".join(
                    value for value in (context, research_context) if value
                ),
            )
        return author_two_phase(self, request)

    def build_coder_prompt(
        self,
        request: SkillAuthoringRequest,
        *,
        iteration: int,
        previous_proposal: GeneratedSkillProposal | None = None,
        previous_validation: ValidationReport | None = None,
        previous_review: CodeReviewResult | None = None,
        rescue_diagnostic: str | None = None,
    ) -> str:
        """Compatibility entry point for the active SOURCE-only prompt."""

        from jarvis.core.authoring_two_phase import build_source_prompt

        return build_source_prompt(
            self,
            request,
            iteration=iteration,
            previous_proposal=previous_proposal,
            previous_validation=previous_validation,
            previous_review=previous_review,
            rescue_diagnostic=rescue_diagnostic,
        )
    def _validate_proposal(self, proposal: GeneratedSkillProposal) -> ValidationReport:
        source_report = self._validator.validate_python_source(
            proposal.source_code,
            filename=f"{proposal.skill_name}.py",
        )
        source_report = with_dynamic_skill_entrypoint_validation(
            source_report, proposal.source_code, filename=f"{proposal.skill_name}.py"
        )
        reports = [("source", source_report)]
        if proposal.tests_source is not None:
            reports.append(
                (
                    "tests",
                    self._validator.validate_python_source(
                        proposal.tests_source,
                        filename=f"test_{proposal.skill_name}.py",
                    ),
                )
            )

        checks = tuple(
            ValidationCheck(
                name=f"{label}.{check.name}",
                success=check.success,
                details=check.details,
            )
            for label, report in reports
            for check in report.checks
        )
        tracebacks = [report.traceback for _label, report in reports if report.traceback]
        return ValidationReport(
            success=all(report.success for _label, report in reports),
            checks=checks,
            stdout="\n".join(report.stdout for _label, report in reports if report.stdout),
            stderr="\n".join(report.stderr for _label, report in reports if report.stderr),
            timed_out=any(report.timed_out for _label, report in reports),
            traceback="\n".join(tracebacks) or None,
        )

    def _review_proposal(
        self,
        request: SkillAuthoringRequest,
        proposal: GeneratedSkillProposal,
        validation: ValidationReport,
    ) -> CodeReviewResult:
        try:
            result = self._reviewer.review(
                self._build_review_request(request, proposal, validation)
            )
        except Exception as exc:
            return self._review_failure(
                f"Code reviewer failed: {type(exc).__name__}: {exc}"
            )
        if not isinstance(result, CodeReviewResult):
            return self._review_failure("Code reviewer returned no structured result.")
        return result

    def _request_structural_rescue(
        self,
        request: SkillAuthoringRequest,
        structural_error: str,
    ) -> str:
        """Request one format-only diagnosis through the existing reviewer path."""

        rescue_request = CodeReviewRequest(
            user_request=request.user_request,
            implementation_summary=(
                "Format-only rescue. Diagnose why the local coder failed to return "
                "the required structured proposal. Detected structural error: "
                f"{structural_error}"
            ),
            code_diff="No candidate source was extracted from the local coder response.",
            validation_report=None,
        )
        try:
            diagnose = getattr(self._reviewer, "diagnose_stagnation", None)
            result = (
                diagnose(rescue_request)
                if callable(diagnose)
                else self._reviewer.review(rescue_request)
            )
        except Exception as exc:
            reviewer_guidance = f"Reviewer format diagnosis unavailable: {type(exc).__name__}."
        else:
            reviewer_guidance = (
                self._review_context(result)
                if isinstance(result, CodeReviewResult)
                else "Reviewer format diagnosis returned no structured result."
            )
        return (
            "SOURCE-ONLY FORMAT RESCUE. Return the exact JARVIS_META and "
            "JARVIS_SOURCE blocks. Do not return tests, Markdown fences, or "
            "prose in place of required blocks. "
            f"Detected format error: {structural_error}. "
            f"Reviewer guidance: {reviewer_guidance}"
        )
    def _request_stagnation_rescue(
        self,
        request: SkillAuthoringRequest,
        proposal: GeneratedSkillProposal,
        validation: ValidationReport,
    ) -> str:
        """Obtain one safe unblock diagnosis without altering approval state."""

        rescue_request = self._build_review_request(
            request,
            proposal,
            validation,
            summary_prefix="Stagnation rescue: diagnose the concrete missing change.",
        )
        try:
            diagnose = getattr(self._reviewer, "diagnose_stagnation", None)
            result = (
                diagnose(rescue_request)
                if callable(diagnose)
                else self._reviewer.review(rescue_request)
            )
        except Exception as exc:
            return f"Rescue diagnosis unavailable: {type(exc).__name__}."
        if not isinstance(result, CodeReviewResult):
            return "Rescue diagnosis returned no structured result."
        return self._review_context(result)

    @staticmethod
    def _build_review_request(
        request: SkillAuthoringRequest,
        proposal: GeneratedSkillProposal,
        validation: ValidationReport,
        *,
        summary_prefix: str = "",
        acceptance_state: ReviewAcceptanceState | None = None,
        previous_source: str | None = None,
    ) -> CodeReviewRequest:
        candidate = proposal.source_code
        if proposal.tests_source is not None:
            candidate += f"\n\n--- PROPOSED TESTS ---\n{proposal.tests_source}"
        summary = proposal.implementation_summary
        if summary_prefix:
            summary = f"{summary_prefix}\n{summary}"
        return CodeReviewRequest(
            user_request=request.user_request,
            implementation_summary=summary,
            code_diff=candidate,
            validation_report=validation,
            acceptance_state=acceptance_state,
            previous_source=previous_source,
            runtime_context=ReviewRuntimeContext(),
            external_research_context=(
                request.relevant_context
                if request.relevant_context
                and "VERIFIED EXTERNAL SOURCE RESEARCH" in request.relevant_context
                else None
            ),
        )

    @staticmethod
    def _review_failure(description: str) -> CodeReviewResult:
        return CodeReviewResult(
            approved=False,
            issues=(
                ReviewIssue(
                    severity=ReviewSeverity.CRITICAL,
                    description=description,
                ),
            ),
            reviewer_used="none",
            cloud_attempted=False,
            cloud_failed=False,
        )

    @staticmethod
    def _review_context(review: CodeReviewResult | None) -> str:
        if review is None:
            return "No prior review result was produced."
        return json.dumps(
            {
                "approved": review.approved,
                "reviewer_used": review.reviewer_used,
                "cloud_failed": review.cloud_failed,
                "cloud_failure_reason": review.cloud_failure_reason,
                "issues": [
                    {
                        "severity": issue.severity.value,
                        "file": issue.file,
                        "description": issue.description,
                        "suggested_fix": issue.suggested_fix,
                    }
                    for issue in review.issues
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
        )

    @staticmethod
    def _validate_request(request: SkillAuthoringRequest) -> None:
        if not isinstance(request, SkillAuthoringRequest):
            raise TypeError("request must be a SkillAuthoringRequest")
        if not isinstance(request.user_request, str) or not request.user_request:
            raise ValueError("user_request must be a non-empty string")
        if request.existing_skill_name is not None and not isinstance(
            request.existing_skill_name, str
        ):
            raise TypeError("existing_skill_name must be a string or None")
        if request.relevant_context is not None and not isinstance(
            request.relevant_context, str
        ):
            raise TypeError("relevant_context must be a string or None")

    @staticmethod
    def _append_dependencies(target: list[str], dependencies: tuple[str, ...]) -> None:
        for dependency in dependencies:
            if dependency not in target:
                target.append(dependency)

    def _unavailable_dependencies(
        self,
        declared_dependencies: Iterable[str],
    ) -> tuple[str, ...]:
        return tuple(
            result.dependency
            for result in self._resolve_dependencies(declared_dependencies)
            if result.status is not DependencyStatus.AVAILABLE
        )

    def _resolve_dependencies(
        self,
        declared_dependencies: Iterable[str],
    ) -> tuple[DependencyResolution, ...]:
        return self._dependency_resolver.resolve_many(tuple(declared_dependencies))

    def _failure(
        self,
        *,
        iterations: int,
        reports: list[ValidationReport],
        reviews: list[CodeReviewResult],
        diagnostics: list[AuthoringIterationDiagnostic],
        declared_dependencies: list[str],
        reason: str,
    ) -> SkillAuthoringResult:
        dependency_results = self._resolve_dependencies(declared_dependencies)
        return SkillAuthoringResult(
            success=False,
            proposal=None,
            iterations=iterations,
            validation_reports=tuple(reports),
            review_results=tuple(reviews),
            failure_reason=reason,
            declared_dependencies=tuple(declared_dependencies),
            unavailable_dependencies=tuple(
                result.dependency for result in dependency_results
                if result.status is not DependencyStatus.AVAILABLE
            ),
            dependency_results=dependency_results,
            diagnostics=tuple(diagnostics),
        )

    def _elapsed_seconds(self, started_at: float) -> float:
        return max(0.0, self._clock() - started_at)

    def _deadline_reached(self, started_at: float) -> bool:
        return self._elapsed_seconds(started_at) >= self._max_authoring_seconds

    def _hard_cap_reason(self) -> str:
        return "Authoring reached its defensive iteration hard cap before the time budget expired."

    def _structural_failure_reason_for_phase(self, phase: object) -> str:
        phase_name = getattr(phase, "value", str(phase)).capitalize()
        return (
            f"{phase_name} authoring aborted after "
            f"{self._max_consecutive_structural_failures} consecutive structural "
            "response failures without a valid phase payload."
        )

    def _stagnation_reason_for_phase(self, phase: object) -> str:
        phase_name = getattr(phase, "value", str(phase)).capitalize()
        return (
            f"{phase_name} authoring stalled after "
            f"{self._no_progress_iterations} consecutive iterations without progress."
        )
    def _deadline_reason(self) -> str:
        return (
            "Authoring time budget exhausted after "
            f"{self._max_authoring_seconds:g} seconds."
        )

    def _failed_iteration_diagnostic(
        self,
        iteration: int,
        started_at: float,
        *,
        structural_retries: int,
    ) -> AuthoringIterationDiagnostic:
        return AuthoringIterationDiagnostic(
            iteration=iteration,
            elapsed_seconds=self._elapsed_seconds(started_at),
            source_hash=None,
            validation_success=None,
            review_approved=None,
            issue_fingerprint=None,
            progress_detected=False,
            generation_success=False,
            structural_retries=structural_retries,
            reviewer_used="none",
        )

    def _proposal_diagnostic(
        self,
        *,
        iteration: int,
        started_at: float,
        source_hash: str,
        source_changed: bool,
        validation: ValidationReport,
        validation_fingerprint: str,
        review: CodeReviewResult,
        review_fingerprint: str,
        progress_detected: bool,
        structural_retries: int,
        stagnation_count: int,
        rescue_triggered: bool = False,
        extraction: StructuredCodeProposal | None = None,
    ) -> AuthoringIterationDiagnostic:
        return AuthoringIterationDiagnostic(
            iteration=iteration,
            elapsed_seconds=self._elapsed_seconds(started_at),
            source_hash=source_hash,
            validation_success=validation.success,
            review_approved=review.approved,
            issue_fingerprint=review_fingerprint,
            progress_detected=progress_detected,
            generation_success=True,
            structural_retries=structural_retries,
            source_changed=source_changed,
            validation_fingerprint=validation_fingerprint,
            reviewer_used=review.reviewer_used,
            cloud_failed=review.cloud_failed,
            cloud_failure_reason=review.cloud_failure_reason,
            review_fingerprint=review_fingerprint,
            stagnation_count=stagnation_count,
            rescue_triggered=rescue_triggered,
            extraction_method=(
                extraction.extraction_method.value if extraction is not None else None
            ),
            structural_error=(
                extraction.structural_error if extraction is not None else None
            ),
            has_meta=extraction.has_meta if extraction is not None else None,
            has_source=extraction.has_source if extraction is not None else None,
            has_tests=extraction.has_tests if extraction is not None else None,
        )

    def _record_diagnostic(
        self,
        diagnostics: list[AuthoringIterationDiagnostic],
        diagnostic: AuthoringIterationDiagnostic,
        *,
        debug_session: AuthoringDebugSession | None = None,
    ) -> None:
        diagnostics.append(diagnostic)
        if debug_session is not None:
            debug_session.write_diagnostic(diagnostic)
        self._diagnostic_sink(self._format_diagnostic(diagnostic))

    @staticmethod
    def _format_diagnostic(diagnostic: AuthoringIterationDiagnostic) -> str:
        def show_bool(value: bool | None) -> str:
            return "-" if value is None else str(value).lower()

        def short_hash(value: str | None) -> str:
            return "-" if value is None else value[:12]

        return (
            f"[AUTHORING #{diagnostic.iteration}] "
            f"elapsed={diagnostic.elapsed_seconds:.2f}s "
            f"generation={'OK' if diagnostic.generation_success else 'FAIL'} "
            f"structural_retries={diagnostic.structural_retries} "
            f"structural_error={diagnostic.structural_error_code or '-'} "
            f"structurally_recovered={show_bool(diagnostic.structurally_recovered)} "
            f"method={diagnostic.extraction_method or '-'} "
            f"first_response_structurally_valid={show_bool(diagnostic.first_response_structurally_valid)} "
            f"structural_retry_count={diagnostic.structural_retry_count} "
            f"reviewer_repair_count={diagnostic.reviewer_repair_count} "
            f"source_hash={short_hash(diagnostic.source_hash)} "
            f"source_changed={show_bool(diagnostic.source_changed)} "
            f"validation={'-' if diagnostic.validation_success is None else ('PASS' if diagnostic.validation_success else 'FAIL')} "
            f"validation_fingerprint={short_hash(diagnostic.validation_fingerprint)} "
            f"reviewer={diagnostic.reviewer_used or '-'} "
            f"cloud_failed={show_bool(diagnostic.cloud_failed)} "
            f"cloud_failure_reason={diagnostic.cloud_failure_reason or '-'} "
            f"review_approved={show_bool(diagnostic.review_approved)} "
            f"review_fingerprint={short_hash(diagnostic.review_fingerprint or diagnostic.issue_fingerprint)} "
            f"progress={str(diagnostic.progress_detected).lower()} "
            f"stagnation_count={diagnostic.stagnation_count} "
            f"rescue={str(diagnostic.rescue_triggered).lower()} "
            f"metadata_reused={show_bool(diagnostic.metadata_reused)} "
            f"metadata_change_ignored={show_bool(diagnostic.metadata_change_ignored)} "
            f"review_attempts={diagnostic.review_attempts if diagnostic.review_attempts is not None else '-'} "
            f"review_skipped_reason={diagnostic.review_skipped_reason or '-'} "
            f"review_transport_failed={show_bool(diagnostic.review_transport_failed)} "
            f"reviewer_normalized={show_bool(diagnostic.reviewer_normalized)} "
            f"reviewer_normalization_error={diagnostic.reviewer_normalization_error or '-'} "
            f"reviewer_truncated={show_bool(diagnostic.reviewer_truncated)}"
            f" plan_created={show_bool(diagnostic.review_plan_created)}"
            f" blocking_unresolved={diagnostic.blocking_unresolved}"
            f" source_repairs={diagnostic.source_repair_count}"
        )

    def _structural_failure_reason(self) -> str:
        return (
            "Authoring aborted after "
            f"{self._max_consecutive_structural_failures} consecutive structural "
            "response failures without a valid proposal."
        )
    def _stagnation_reason(self) -> str:
        return (
            "Authoring stalled after "
            f"{self._no_progress_iterations} consecutive iterations without progress."
        )

    @staticmethod
    def _source_hash(source_code: str) -> str:
        return hashlib.sha256(source_code.encode("utf-8")).hexdigest()

    @staticmethod
    def _validation_fingerprint(validation: ValidationReport) -> str:
        payload = {
            "success": validation.success,
            "checks": [
                {
                    "name": check.name,
                    "success": check.success,
                    "details": check.details,
                }
                for check in validation.checks
            ],
            "stderr": validation.stderr,
            "timed_out": validation.timed_out,
            "traceback": validation.traceback,
        }
        return SafeSkillAuthoringService._fingerprint(payload)

    @staticmethod
    def _issue_fingerprint(review: CodeReviewResult) -> str:
        payload = {
            "approved": review.approved,
            "issues": [
                {
                    "severity": issue.severity.value,
                    "file": issue.file,
                    "description": issue.description,
                    "suggested_fix": issue.suggested_fix,
                }
                for issue in review.issues
            ],
        }
        return SafeSkillAuthoringService._fingerprint(payload)

    @staticmethod
    def _fingerprint(payload: object) -> str:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def _proposal_from_parts(
    metadata: Mapping[str, object],
    source_code: str,
    *,
    tests_source: str | None,
    iteration: int,
) -> GeneratedSkillProposal:
    required_fields = ("skill_name", "implementation_summary", "dependencies")
    missing_fields = [field for field in required_fields if field not in metadata]
    if missing_fields:
        raise SkillProposalParseError(
            "Local coder response is missing required field(s): "
            + ", ".join(missing_fields)
            + "."
        )
    skill_name = metadata["skill_name"]
    implementation_summary = metadata["implementation_summary"]
    dependencies = metadata["dependencies"]
    if not isinstance(skill_name, str) or not _SKILL_NAME_PATTERN.fullmatch(skill_name):
        raise SkillProposalParseError("skill_name must be a lowercase identifier.")
    if not isinstance(source_code, str) or not source_code.strip():
        raise SkillProposalParseError("JARVIS_SOURCE must contain non-empty Python source.")
    if not isinstance(implementation_summary, str) or not implementation_summary.strip():
        raise SkillProposalParseError("implementation_summary must be a non-empty string.")
    if tests_source is not None and (
        not isinstance(tests_source, str) or not tests_source.strip()
    ):
        raise SkillProposalParseError("tests_source must be non-empty text or null.")
    if not isinstance(dependencies, list) or any(
        not isinstance(dependency, str) or not dependency.strip()
        for dependency in dependencies
    ):
        raise SkillProposalParseError("dependencies must be a list of non-empty strings.")
    return GeneratedSkillProposal(
        skill_name=skill_name,
        source_code=source_code,
        implementation_summary=implementation_summary,
        tests_source=tests_source,
        dependencies=tuple(dict.fromkeys(dependency.strip() for dependency in dependencies)),
        iteration=iteration,
    )

def parse_generated_skill_proposal(
    raw_response: str,
    *,
    iteration: int,
    extraction: StructuredCodeProposal | None = None,
) -> GeneratedSkillProposal:
    """Parse a literal code proposal without executing candidate source."""

    extraction = extraction or extract_structured_code_proposal(raw_response)
    if not extraction.success or not isinstance(extraction.metadata, dict):
        raise SkillProposalParseError(
            extraction.error or "Local coder response does not contain a proposal."
        )
    payload = extraction.metadata
    required_fields = ("skill_name", "implementation_summary", "dependencies")
    if extraction.extraction_method.value.startswith("legacy"):
        required_fields += ("source_code", "tests_source")
    missing_fields = [field for field in required_fields if field not in payload]
    if missing_fields:
        raise SkillProposalParseError(
            "Local coder response is missing required field(s): "
            + ", ".join(missing_fields)
            + "."
        )

    skill_name = payload["skill_name"]
    source_code = extraction.source_code
    implementation_summary = payload["implementation_summary"]
    tests_source = extraction.tests_source
    dependencies = payload["dependencies"]

    if not isinstance(skill_name, str) or not _SKILL_NAME_PATTERN.fullmatch(skill_name):
        raise SkillProposalParseError("skill_name must be a lowercase identifier.")
    if not isinstance(source_code, str) or not source_code.strip():
        raise SkillProposalParseError("JARVIS_SOURCE must contain non-empty Python source.")
    if not isinstance(implementation_summary, str) or not implementation_summary.strip():
        raise SkillProposalParseError("implementation_summary must be a non-empty string.")
    if tests_source is not None and (
        not isinstance(tests_source, str) or not tests_source.strip()
    ):
        raise SkillProposalParseError("tests_source must be non-empty text or null.")
    if not isinstance(dependencies, list) or any(
        not isinstance(dependency, str) or not dependency.strip()
        for dependency in dependencies
    ):
        raise SkillProposalParseError("dependencies must be a list of non-empty strings.")

    return GeneratedSkillProposal(
        skill_name=skill_name,
        source_code=source_code,
        implementation_summary=implementation_summary,
        tests_source=tests_source,
        dependencies=tuple(dict.fromkeys(dependency.strip() for dependency in dependencies)),
        iteration=iteration,
    )


__all__ = [
    "AUTHORING_MAX_SECONDS_ENV",
    "AuthoringIterationDiagnostic",
    "DEFAULT_MAX_AUTHORING_ITERATIONS_HARD_CAP",
    "DEFAULT_MAX_AUTHORING_SECONDS",
    "DEFAULT_NO_PROGRESS_ITERATIONS",
    "DEFAULT_MAX_REVIEW_CYCLES",
    "DEFAULT_MAX_SOURCE_REPAIRS",
    "SOURCE_REPAIRS_ENV",
    "GeneratedSkillProposal",
    "SafeSkillAuthoringService",
    "SkillAuthoringRequest",
    "SkillAuthoringResult",
    "SkillProposalParseError",
    "format_dynamic_evidence_prompt",
    "get_skill_authoring_max_seconds",
    "get_skill_authoring_max_source_repairs",
    "parse_generated_skill_proposal",
]
