"""Independent deterministic orchestration for structured code reviews."""

from __future__ import annotations

import json
from dataclasses import dataclass
from difflib import SequenceMatcher
import re
from enum import Enum
from typing import Protocol

from jarvis.core.code_validation import ValidationReport
from jarvis.core.dynamic_skill_contract import FUNCTIONAL_REVIEW_CONTRACT
from jarvis.core.external_data_requirements import (
    inspect_external_data_source,
    requires_live_external_data,
)
from jarvis.core.review_acceptance import (
    BlockerAssessment,
    BlockingCategory,
    BlockingFinding,
    ReviewAcceptanceState,
)
from jarvis.core.review_output_normalizer import normalize_review_output
from jarvis.core.review_blocker_policy import ReviewPolicyFacts, assess_blocker

MAX_REVIEW_ISSUES = 5
MAX_REVIEW_ADVISORIES = 5


class CodeReviewModelRouter(Protocol):
    groq_api_key: str | None

    def run_groq_code_review(self, prompt: str) -> str: ...

    def run_local_reasoning(self, prompt: str) -> str: ...


class ReviewSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ReviewIssue:
    severity: ReviewSeverity
    description: str
    file: str | None = None
    suggested_fix: str | None = None


@dataclass(frozen=True)
class CodeReviewRequest:
    """All context needed to judge implementation against the original request."""

    user_request: str
    implementation_summary: str
    code_diff: str
    validation_report: ValidationReport | None = None
    acceptance_state: ReviewAcceptanceState | None = None
    previous_source: str | None = None
    runtime_context: ReviewRuntimeContext | None = None
    external_research_context: str | None = None


@dataclass(frozen=True)
class CodeReviewResult:
    approved: bool
    issues: tuple[ReviewIssue, ...]
    reviewer_used: str
    cloud_attempted: bool
    cloud_failed: bool
    raw_response: str | None = None
    cloud_failure_reason: str | None = None
    review_mode: str | None = None
    blocking_findings: tuple[BlockingFinding, ...] = ()
    advisory_issues: tuple[ReviewIssue, ...] = ()
    blocker_assessments: tuple[BlockerAssessment, ...] = ()
    regression_findings: tuple[BlockingFinding, ...] = ()
    blockers_downgraded_by_policy: tuple[str, ...] = ()
    unknown_severity_normalized: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewProviderAttempt:
    """One real provider call and its deterministic normalization result."""

    provider: str
    raw_response: str | None
    normalization_success: bool
    normalization_error: str | None = None
    approved: bool | None = None
    cloud_failure_reason: str | None = None
    truncated: bool = False
    local_review_num_predict: int | None = None
    blockers_downgraded_by_policy: tuple[str, ...] = ()
    normalization_error_kind: str | None = None
    unknown_severity_normalized: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReviewAttemptOutcome:
    """A complete Groq-to-local review cycle without a synthetic verdict."""

    result: CodeReviewResult | None
    provider_attempts: tuple[ReviewProviderAttempt, ...]
    cloud_attempted: bool
    cloud_failure_reason: str | None = None


class CodeReviewParseError(ValueError):
    """The provider response cannot safely be used as a structured review."""

    def __init__(
        self, message: str, *, truncated: bool = False,
        normalization_error_kind: str | None = None,
    ) -> None:
        super().__init__(message)
        self.truncated = truncated
        self.normalization_error_kind = (
            "truncated" if truncated else normalization_error_kind
        )


@dataclass(frozen=True)
class ReviewRuntimeContext:
    """Verified platform facts relevant to a local dynamic skill review."""

    facts: tuple[str, ...] = (
        "Dynamic skills are dispatched through SafeSkillExecution and PolicyCore.",
        "Deployment checks authorization and publishes source with hash metadata.",
        "Execution verifies deployment metadata and source hash before a child worker runs.",
        "The child worker has a timeout; it is not an operating-system sandbox.",
        "Do not require a skill to duplicate checks already enforced by the platform.",
    )
    # Trusted, explicit requirements; absent by default. The LLM cannot set these.
    required_capabilities: frozenset[str] = frozenset()
    policy_facts: ReviewPolicyFacts = ReviewPolicyFacts()

    def to_prompt(self) -> str:
        lines = [f"- {fact}" for fact in self.facts]
        if self.policy_facts.local_component and not self.policy_facts.distributed_service:
            lines.append("- A skill is a local JARVIS component, not a distributed production service.")
        if self.required_capabilities:
            lines.append(
                "- Explicit trusted requirements: "
                + ", ".join(sorted(self.required_capabilities))
            )
        return "\n".join(lines)


class CodeReviewer:
    """Review code with Groq first and a direct local reasoning fallback.

    ``review_with_attempts`` is the lossless transport API: if neither provider
    returns a structurally valid review, it returns ``result=None``.  The older
    ``review`` method remains compatible by mapping that condition to the
    historic fail-closed synthetic rejection for callers that have not yet
    adopted the trace API.
    """

    def __init__(self, model_router: CodeReviewModelRouter) -> None:
        self._model_router = model_router

    def review(self, request: CodeReviewRequest) -> CodeReviewResult:
        self._validate_request(request)
        external_rejection = self._live_data_rejection(request)
        if external_rejection is not None:
            return external_rejection
        outcome = self._review_with_prompt(self.build_prompt(request), review_request=request)
        if outcome.result is not None:
            return outcome.result
        return self._unavailable_result(outcome)

    def review_with_attempts(self, request: CodeReviewRequest) -> ReviewAttemptOutcome:
        self._validate_request(request)
        external_rejection = self._live_data_rejection(request)
        if external_rejection is not None:
            return ReviewAttemptOutcome(
                result=external_rejection,
                provider_attempts=(),
                cloud_attempted=False,
            )
        prompt = (
            self.build_followup_prompt(request)
            if request.acceptance_state is not None
            else self.build_prompt(request)
        )
        return self._review_with_prompt(
            prompt,
            review_request=request,
            expected_mode="followup" if request.acceptance_state is not None else "initial",
            expected_ids=(
                {blocker.id for blocker in request.acceptance_state.plan.blockers + request.acceptance_state.regression_blockers}
                if request.acceptance_state is not None
                else None
            ),
        )

    def diagnose_stagnation(self, request: CodeReviewRequest) -> CodeReviewResult:
        """Request one concrete unblock diagnosis through the usual fallback."""

        outcome = self.diagnose_stagnation_with_attempts(request)
        if outcome.result is not None:
            return outcome.result
        return self._unavailable_result(outcome)

    def diagnose_stagnation_with_attempts(
        self,
        request: CodeReviewRequest,
    ) -> ReviewAttemptOutcome:
        self._validate_request(request)
        return self._review_with_prompt(self.build_stagnation_prompt(request), review_request=request)

    def _review_with_prompt(
        self,
        prompt: str,
        *,
        review_request: CodeReviewRequest | None = None,
        expected_mode: str | None = None,
        expected_ids: set[str] | None = None,
    ) -> ReviewAttemptOutcome:
        cloud_attempted = bool(getattr(self._model_router, "groq_api_key", None))
        cloud_failure_reason: str | None = None
        attempts: list[ReviewProviderAttempt] = []

        if cloud_attempted:
            raw_response: str | None = None
            try:
                raw_response = self._model_router.run_groq_code_review(prompt)
                result = parse_review_response(
                    raw_response,
                    reviewer_used="groq",
                    cloud_attempted=True,
                    cloud_failed=False,
                    user_request=review_request.user_request if review_request else "",
                    runtime_context=review_request.runtime_context if review_request else None,
                )
                self._assert_expected_review(result, expected_mode, expected_ids)
            except Exception as exc:
                cloud_failure_reason = self._safe_cloud_failure_reason(exc)
                attempts.append(
                    ReviewProviderAttempt(
                        provider="groq",
                        raw_response=raw_response,
                        normalization_success=False,
                        normalization_error=self._safe_normalization_error(exc),
                        cloud_failure_reason=cloud_failure_reason,
                        truncated=bool(getattr(exc, "truncated", False)),
                        normalization_error_kind=getattr(exc, "normalization_error_kind", None),
                    )
                )
            else:
                attempts.append(
                    ReviewProviderAttempt(
                        provider="groq",
                        raw_response=raw_response,
                        normalization_success=True,
                        approved=result.approved,
                        blockers_downgraded_by_policy=result.blockers_downgraded_by_policy,
                        unknown_severity_normalized=result.unknown_severity_normalized,
                    )
                )
                return ReviewAttemptOutcome(
                    result=result,
                    provider_attempts=tuple(attempts),
                    cloud_attempted=True,
                )
        else:
            cloud_failure_reason = "not configured"

        raw_response = None
        local_budget = getattr(self._model_router, "local_code_review_num_predict", None)
        try:
            local_review = getattr(self._model_router, "run_local_code_review", None)
            raw_response = (
                local_review(prompt) if callable(local_review)
                else self._model_router.run_local_reasoning(prompt)
            )
            result = parse_review_response(
                raw_response,
                reviewer_used="local",
                cloud_attempted=cloud_attempted,
                cloud_failed=True,
                cloud_failure_reason=cloud_failure_reason,
                user_request=review_request.user_request if review_request else "",
                runtime_context=review_request.runtime_context if review_request else None,
            )
            self._assert_expected_review(result, expected_mode, expected_ids)
        except Exception as exc:
            attempts.append(
                ReviewProviderAttempt(
                    provider="local",
                    raw_response=raw_response,
                    normalization_success=False,
                    normalization_error=self._safe_normalization_error(exc),
                    cloud_failure_reason=cloud_failure_reason,
                    truncated=bool(getattr(exc, "truncated", False)),
                    local_review_num_predict=local_budget if isinstance(local_budget, int) else None,
                    normalization_error_kind=getattr(exc, "normalization_error_kind", None),
                )
            )
            return ReviewAttemptOutcome(
                result=None,
                provider_attempts=tuple(attempts),
                cloud_attempted=cloud_attempted,
                cloud_failure_reason=cloud_failure_reason,
            )

        attempts.append(
            ReviewProviderAttempt(
                provider="local",
                raw_response=raw_response,
                normalization_success=True,
                approved=result.approved,
                cloud_failure_reason=cloud_failure_reason,
                local_review_num_predict=local_budget if isinstance(local_budget, int) else None,
                blockers_downgraded_by_policy=result.blockers_downgraded_by_policy,
                unknown_severity_normalized=result.unknown_severity_normalized,
            )
        )
        return ReviewAttemptOutcome(
            result=result,
            provider_attempts=tuple(attempts),
            cloud_attempted=cloud_attempted,
            cloud_failure_reason=cloud_failure_reason,
        )

    @staticmethod
    def _assert_expected_review(
        result: CodeReviewResult,
        expected_mode: str | None,
        expected_ids: set[str] | None,
    ) -> None:
        if expected_mode is not None and result.review_mode != expected_mode:
            raise CodeReviewParseError(
                "Reviewer returned the wrong acceptance review schema.",
                normalization_error_kind="new_contract_parse_error",
            )
        if expected_ids is not None:
            identifiers = [assessment.id for assessment in result.blocker_assessments]
            if len(identifiers) != len(set(identifiers)) or set(identifiers) != expected_ids:
                raise CodeReviewParseError(
                    "Reviewer must assess every frozen blocker exactly once.",
                    normalization_error_kind="new_contract_parse_error",
                )

    @staticmethod
    def _unavailable_result(outcome: ReviewAttemptOutcome) -> CodeReviewResult:
        return CodeReviewResult(
            approved=False,
            issues=(
                ReviewIssue(
                    severity=ReviewSeverity.CRITICAL,
                    description=(
                        "No structured code review was available. "
                        f"Groq failure category: {outcome.cloud_failure_reason or 'unknown'}."
                    ),
                ),
            ),
            reviewer_used="none",
            cloud_attempted=outcome.cloud_attempted,
            cloud_failed=True,
            cloud_failure_reason=outcome.cloud_failure_reason,
        )

    @staticmethod
    def build_prompt(request: CodeReviewRequest) -> str:
        validation_context = (
            request.validation_report.to_prompt_context()
            if request.validation_report is not None
            else "No local validation report was supplied."
        )
        return f"""You review a local JARVIS skill against the ORIGINAL USER REQUEST.
Return ONLY JARVIS_DATA JSON. No introduction, analysis, Markdown or closing prose.
Do not rewrite code. Report at most {MAX_REVIEW_ISSUES} blocking issues, each concise.
The only blocker categories are: {', '.join(category.value for category in BlockingCategory)}.
Each blocker needs concrete source evidence and a relation to an explicit user
requirement or an actual JARVIS runtime boundary. Do not invent requirements.
Optional improvements belong in advisory_issues and never block approval.
For every finding, severity must be one of: info | low | medium | high | critical.
Do not use warning, error, blocker, major, minor or fatal as severity values.
Use at most {MAX_REVIEW_ADVISORIES} concise advisories. Keep descriptions, evidence,
and suggested_fix short; do not repeat the same explanation in several fields.
If no blocking_issues remain, set approved=true and use an empty blocker list.
Unless specifically required, Redis, SQLite for simple JSON state, scalability,
distributed deployment, Kubernetes/containers, theoretical thread safety,
micro I/O optimizations, newline/BOM, style, elaborate logging, exponential
backoff, every HTTP status, hypothetical future API schema changes, call
optimization, enterprise hardening, unused-platform portability and pure
architecture refactors are not blockers. Advanced rate limiting is advisory
when ordinary failures are handled. Do not demand HTML/XSS protection for
content that is not rendered as arbitrary HTML.

{FUNCTIONAL_REVIEW_CONTRACT}

For requests that require current external data, explicitly answer:
1. Where does the code obtain current data?
2. What concrete source does it use?
3. Is there an executable acquisition-to-result path?
4. Are simulated, mocked, placeholder or hardcoded current values substituting
   for acquired data?
If you cannot point to a concrete acquisition in the source and its path into
the returned result, report a user_requirement_unmet blocker. Plausible-looking
values, comments, or an unused network call are not evidence of acquisition.

ACTUAL JARVIS RUNTIME FACTS:
{(request.runtime_context or ReviewRuntimeContext()).to_prompt()}

<JARVIS_DATA>
{{
  "approved": false,
  "blocking_issues": [
    {{
      "severity": "high",
      "category": "runtime_failure",
      "file": null,
      "description": "specific current failure",
      "suggested_fix": "concrete correction",
      "evidence": "specific current source behavior",
      "requirement_relation": "explicit request or real runtime boundary"
    }}
  ],
  "advisory_issues": []
}}
</JARVIS_DATA>

--- ORIGINAL USER REQUEST (verbatim) ---
{request.user_request}
--- END ORIGINAL USER REQUEST ---

--- IMPLEMENTATION SUMMARY ---
{request.implementation_summary}
--- END IMPLEMENTATION SUMMARY ---

--- CODE DIFF OR CANDIDATE CODE ---
{request.code_diff}
--- END CODE DIFF OR CANDIDATE CODE ---

--- LOCAL VALIDATION REPORT ---
{validation_context}
--- END LOCAL VALIDATION REPORT ---
--- EXTERNAL SOURCE RESEARCH FACTS ---
{request.external_research_context or 'No verified external-source research facts were supplied.'}
--- END EXTERNAL SOURCE RESEARCH FACTS ---
"""

    @staticmethod
    def build_followup_prompt(request: CodeReviewRequest) -> str:
        state = request.acceptance_state
        if state is None:
            raise ValueError("Follow-up review requires an acceptance state.")
        frozen = [
            {
                "id": blocker.id,
                "category": blocker.category.value,
                "description": blocker.description,
                "suggested_fix": blocker.suggested_fix,
                "previous_status": "unresolved" if blocker.id in state.unresolved_ids else "resolved",
            }
            for blocker in state.plan.blockers + state.regression_blockers
        ]
        status_template = [
            {
                "id": blocker["id"],
                "status": "resolved or unresolved",
                "evidence": "specific current source evidence",
            }
            for blocker in frozen
        ]
        previous = request.previous_source or "No previous source was supplied."
        return f"""Review ONLY whether each frozen blocker is resolved and whether
the repair introduced a NEW blocking regression. Do not perform a new general
audit or turn optional improvements into blockers. A regression needs a permitted
category, concrete current source evidence, the newly introduced behavior,
why it did not apply before, and evidence in the source change. New concerns
without that proof are advisory only. Report EVERY frozen blocker once.
If a real regression exists, each regression_blockers object must contain
severity, category, description, suggested_fix, evidence,
requirement_relation, introduced_behavior, prior_absence and
source_change_evidence. Otherwise use regression_blockers=[].
Set approved=true only when every frozen blocker is resolved and there are no
valid regression blockers; Python independently verifies this state.
Return ONLY JARVIS_DATA JSON, no prose. Maximum {MAX_REVIEW_ISSUES} regression blockers.
Use at most {MAX_REVIEW_ADVISORIES} short advisories and no repeated explanations.
For regressions and advisories, severity must be one of: info | low | medium | high | critical.
Do not use warning, error, blocker, major, minor or fatal as severity values.

{FUNCTIONAL_REVIEW_CONTRACT}
Apply these checks only to frozen blockers or proven newly introduced regressions;
the frozen-plan and regression-proof rules above still apply.
For frozen live-data blockers, explicitly verify the concrete source, the
executable acquisition-to-result path, and that current values are not
simulated or hardcoded. Do not mark such a blocker resolved without that evidence.

ACTUAL JARVIS RUNTIME FACTS:
{(request.runtime_context or ReviewRuntimeContext()).to_prompt()}
--- ORIGINAL USER REQUEST (verbatim) ---
{request.user_request}
--- FROZEN BLOCKERS AND PRIOR STATUS ---
{json.dumps(frozen, ensure_ascii=False)}
--- PREVIOUS SOURCE ---
{previous}
--- CURRENT SOURCE ---
{request.code_diff}
--- VALIDATION ---
{request.validation_report.to_prompt_context() if request.validation_report else 'No report.'}
--- EXTERNAL SOURCE RESEARCH FACTS ---
{request.external_research_context or 'No verified external-source research facts were supplied.'}
--- END EXTERNAL SOURCE RESEARCH FACTS ---
<JARVIS_DATA>
{{"approved": false, "blocker_statuses": {json.dumps(status_template, ensure_ascii=False)}, "regression_blockers": [], "advisory_issues": []}}
</JARVIS_DATA>"""
    @staticmethod
    def build_stagnation_prompt(request: CodeReviewRequest) -> str:
        validation_context = (
            request.validation_report.to_prompt_context()
            if request.validation_report is not None
            else "No local validation report was supplied."
        )
        return f"""You are JARVIS's code-review unblock diagnostician. The coder has repeated
an essentially unchanged proposal despite unresolved validation or review errors.
Do not rewrite the code. Identify why it remains stuck, state one concrete change
the coder must make, and explicitly state what it must not repeat unchanged.

Return a structured diagnosis in exactly this form:
<JARVIS_DATA>
{{
  "approved": false,
  "issues": [
    {{
      "severity": "high|critical",
      "file": "optional path or null",
      "description": "why the proposal is still failing",
      "suggested_fix": "one concrete required change; include what not to repeat"
    }}
  ]
}}
</JARVIS_DATA>

--- ORIGINAL USER REQUEST (verbatim) ---
{request.user_request}
--- END ORIGINAL USER REQUEST ---

--- CURRENT IMPLEMENTATION SUMMARY ---
{request.implementation_summary}
--- END IMPLEMENTATION SUMMARY ---

--- CURRENT SOURCE OR TEST CANDIDATE ---
{request.code_diff}
--- END CURRENT SOURCE OR TEST CANDIDATE ---

--- EXACT LOCAL VALIDATION REPORT ---
{validation_context}
--- END LOCAL VALIDATION REPORT ---
"""

    @staticmethod
    def _live_data_rejection(
        request: CodeReviewRequest,
    ) -> CodeReviewResult | None:
        if not requires_live_external_data(request.user_request):
            return None
        candidate = request.code_diff.split("\n\n--- PROPOSED TESTS ---", 1)[0]
        check = inspect_external_data_source(candidate, request.user_request)
        if check.valid:
            return None
        finding = BlockingFinding(
            category=BlockingCategory.USER_REQUIREMENT_UNMET,
            description=(
                "Live external data is required, but the candidate does not provide "
                "a verified acquisition path to its returned result."
            ),
            suggested_fix=(
                "Implement real external acquisition, parse its response, and derive "
                "the returned current data from that response."
            ),
            evidence=check.details,
            requirement_relation=(
                "The original user request explicitly requires current or changing "
                "information from an external source."
            ),
            severity=ReviewSeverity.HIGH.value,
        )
        issue = ReviewIssue(
            severity=ReviewSeverity.HIGH,
            description=f"{finding.description} Evidence: {finding.evidence}",
            suggested_fix=finding.suggested_fix,
        )
        return CodeReviewResult(
            approved=False,
            issues=(issue,),
            reviewer_used="deterministic",
            cloud_attempted=False,
            cloud_failed=False,
            review_mode="initial" if request.acceptance_state is None else None,
            blocking_findings=(finding,) if request.acceptance_state is None else (),
        )

    @staticmethod
    def _safe_cloud_failure_reason(exc: Exception) -> str:
        if isinstance(exc, CodeReviewParseError):
            message = str(exc).lower()
            if exc.truncated:
                return "truncated structured response"
            if "empty" in message:
                return "empty response"
            if "ambiguous top-level json" in message:
                return "ambiguous top-level JSON"
            if "missing required field" in message or "requires boolean" in message or "must be a list" in message:
                return "invalid review schema"
            return "invalid structured response"
        response = getattr(exc, "response", None)
        status_code = getattr(response, "status_code", None)
        if not isinstance(status_code, int):
            status_code = getattr(exc, "status_code", None)
        if isinstance(status_code, int):
            return f"HTTP {status_code}"
        message = str(exc).lower()
        type_name = type(exc).__name__.lower()
        if "429" in message or "rate limit" in message:
            return "HTTP 429"
        if "404" in message:
            return "HTTP 404"
        if "timeout" in type_name or "timeout" in message:
            return "timeout"
        if "connection" in type_name or "connection" in message:
            return "connection error"
        if "not configured" in message or "api key" in message:
            return "not configured"
        return "provider error"

    @staticmethod
    def _safe_normalization_error(exc: Exception) -> str:
        if isinstance(exc, CodeReviewParseError):
            return str(exc)
        return type(exc).__name__

    @staticmethod
    def _validate_request(request: CodeReviewRequest) -> None:
        if not isinstance(request, CodeReviewRequest):
            raise TypeError("request must be a CodeReviewRequest")
        for field_name in ("user_request", "implementation_summary", "code_diff"):
            value = getattr(request, field_name)
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")


def parse_review_response(
    raw_response: str,
    *,
    reviewer_used: str,
    cloud_attempted: bool,
    cloud_failed: bool,
    cloud_failure_reason: str | None = None,
    user_request: str = "",
    runtime_context: ReviewRuntimeContext | None = None,
) -> CodeReviewResult:
    """Convert a normalized response into a fail-closed review result."""

    normalized = normalize_review_output(raw_response)
    if not normalized.success or normalized.payload is None:
        raise CodeReviewParseError(
            normalized.error or "Reviewer response does not contain a valid review.",
            truncated=normalized.truncated,
            normalization_error_kind="review_output_parse_error",
        )
    payload = normalized.payload
    approved = payload["approved"]
    # Select the contract before interpreting findings. Extra legacy metadata
    # cannot invalidate or affect approval of an acceptance review.
    issues: tuple[ReviewIssue, ...] = ()
    review_mode: str | None = None
    blocking_findings: tuple[BlockingFinding, ...] = ()
    advisory_issues: tuple[ReviewIssue, ...] = ()
    blocker_assessments: tuple[BlockerAssessment, ...] = ()
    regression_findings: tuple[BlockingFinding, ...] = ()
    downgraded: tuple[str, ...] = ()
    normalized_severities: list[str] = []
    try:
        if "blocking_issues" in payload:
            review_mode = "initial"
            payload = _normalize_new_contract_severities(
                payload, "blocking_issues", normalized_severities,
            )
            blocking_findings, advisory_issues, downgraded = _parse_initial_findings(
                payload, user_request=user_request, runtime_context=runtime_context,
            )
        elif "blocker_statuses" in payload:
            review_mode = "followup"
            payload = _normalize_new_contract_severities(
                payload, "regression_blockers", normalized_severities,
            )
            blocker_assessments, regression_findings, advisory_issues, downgraded = _parse_followup_findings(
                payload, user_request=user_request, runtime_context=runtime_context,
            )
        else:
            issues = _deduplicate_and_limit_issues(tuple(
                _parse_issue(issue) for issue in payload["issues"]
            ))
            if not approved and not issues:
                raise CodeReviewParseError("Rejected review requires at least one issue.")
    except CodeReviewParseError as exc:
        exc.normalization_error_kind = (
            "new_contract_parse_error" if review_mode else "legacy_issue_parse_error"
        )
        raise
    disqualifying_issue = any(
        issue.severity in (ReviewSeverity.HIGH, ReviewSeverity.CRITICAL)
        for issue in issues
    )
    return CodeReviewResult(
        approved=approved and not disqualifying_issue,
        issues=issues,
        reviewer_used=reviewer_used,
        cloud_attempted=cloud_attempted,
        cloud_failed=cloud_failed,
        raw_response=raw_response,
        cloud_failure_reason=cloud_failure_reason,
        review_mode=review_mode,
        blocking_findings=blocking_findings,
        advisory_issues=advisory_issues,
        blocker_assessments=blocker_assessments,
        regression_findings=regression_findings,
        blockers_downgraded_by_policy=downgraded,
        unknown_severity_normalized=tuple(normalized_severities),
    )


def _normalize_new_contract_severities(
    payload: dict[str, object],
    blocker_field: str,
    normalized_fields: list[str],
) -> dict[str, object]:
    """Default priority metadata only; preserve all functional contract fields."""

    normalized = dict(payload)
    for field, default in (
        (blocker_field, ReviewSeverity.HIGH),
        ("advisory_issues", ReviewSeverity.MEDIUM),
    ):
        findings = payload.get(field, [])
        if not isinstance(findings, list):
            raise CodeReviewParseError(f"Review field '{field}' must be a list.")
        items: list[object] = []
        for index, finding in enumerate(findings):
            if isinstance(finding, dict):
                try:
                    ReviewSeverity(str(finding.get("severity", "")).lower())
                except ValueError:
                    finding = {**finding, "severity": default.value}
                    normalized_fields.append(f"{field}[{index}].severity")
            items.append(finding)
        normalized[field] = items
    return normalized


def _parse_initial_findings(
    payload: dict[str, object],
    *,
    user_request: str,
    runtime_context: ReviewRuntimeContext | None,
) -> tuple[tuple[BlockingFinding, ...], tuple[ReviewIssue, ...], tuple[str, ...]]:
    raw_blockers = payload["blocking_issues"]
    raw_advisories = payload.get("advisory_issues", [])
    if not isinstance(raw_blockers, list) or not isinstance(raw_advisories, list):
        raise CodeReviewParseError("Initial review findings must be lists.")
    blockers: list[BlockingFinding] = []
    advisories = [_parse_issue(issue) for issue in raw_advisories]
    downgraded: list[str] = []
    for raw in raw_blockers:
        issue = _parse_issue(raw)
        finding = _parse_blocking_finding(raw)
        decision = assess_blocker(
            finding, user_request=user_request,
            required_capabilities=(runtime_context or ReviewRuntimeContext()).required_capabilities,
            runtime_facts=(runtime_context or ReviewRuntimeContext()).policy_facts,
        )
        if decision.accepted:
            blockers.append(finding)
        else:
            advisories.append(issue)
            downgraded.append(f"{finding.category.value}:{decision.reason}")
    blockers = sorted(
        enumerate(blockers),
        key=lambda item: (_SEVERITY_PRIORITY[ReviewSeverity(item[1].severity)], item[0]),
    )
    return (
        tuple(blocker for _index, blocker in blockers[:MAX_REVIEW_ISSUES]),
        tuple(advisories[:MAX_REVIEW_ADVISORIES]),
        tuple(downgraded),
    )


def _parse_followup_findings(
    payload: dict[str, object],
    *,
    user_request: str,
    runtime_context: ReviewRuntimeContext | None,
) -> tuple[tuple[BlockerAssessment, ...], tuple[BlockingFinding, ...], tuple[ReviewIssue, ...], tuple[str, ...]]:
    raw_statuses = payload["blocker_statuses"]
    raw_regressions = payload.get("regression_blockers", [])
    raw_advisories = payload.get("advisory_issues", [])
    if not all(isinstance(items, list) for items in (raw_statuses, raw_regressions, raw_advisories)):
        raise CodeReviewParseError("Follow-up review fields must be lists.")
    assessments: list[BlockerAssessment] = []
    for raw in raw_statuses:
        if not isinstance(raw, dict):
            raise CodeReviewParseError("Blocker status must be an object.")
        identifier, status, evidence = (raw.get(field) for field in ("id", "status", "evidence"))
        if not all(isinstance(value, str) and value.strip() for value in (identifier, status, evidence)):
            raise CodeReviewParseError("Blocker status requires id, status and evidence.")
        if status not in {"resolved", "unresolved"}:
            raise CodeReviewParseError("Blocker status must be resolved or unresolved.")
        assessments.append(BlockerAssessment(identifier, status, evidence))
    if len({assessment.id for assessment in assessments}) != len(assessments):
        raise CodeReviewParseError("Reviewer must assess every frozen blocker exactly once.")
    regressions: list[BlockingFinding] = []
    advisories = [_parse_issue(issue) for issue in raw_advisories]
    downgraded: list[str] = []
    for raw in raw_regressions:
        issue = _parse_issue(raw)
        finding = _parse_blocking_finding(raw)
        if not all(
            (finding.introduced_behavior, finding.prior_absence, finding.source_change_evidence)
        ):
            raise CodeReviewParseError(
                "Regression blocker requires introduced_behavior, prior_absence and source_change_evidence."
            )
        decision = assess_blocker(
            finding, user_request=user_request,
            required_capabilities=(runtime_context or ReviewRuntimeContext()).required_capabilities,
            runtime_facts=(runtime_context or ReviewRuntimeContext()).policy_facts,
        )
        if decision.accepted:
            regressions.append(finding)
        else:
            advisories.append(issue)
            downgraded.append(f"{finding.category.value}:{decision.reason}")
    regressions = sorted(
        enumerate(regressions),
        key=lambda item: (_SEVERITY_PRIORITY[ReviewSeverity(item[1].severity)], item[0]),
    )
    return (
        tuple(assessments),
        tuple(regression for _index, regression in regressions[:MAX_REVIEW_ISSUES]),
        tuple(advisories[:MAX_REVIEW_ADVISORIES]),
        tuple(downgraded),
    )


def _parse_blocking_finding(value: object) -> BlockingFinding:
    if not isinstance(value, dict):
        raise CodeReviewParseError("Every blocker must be a JSON object.")
    try:
        category = BlockingCategory(value.get("category"))
    except (ValueError, TypeError) as exc:
        raise CodeReviewParseError("Every blocker requires a valid category.") from exc
    fields = ("description", "suggested_fix", "evidence", "requirement_relation")
    if not all(isinstance(value.get(field), str) and value[field].strip() for field in fields):
        raise CodeReviewParseError(
            "Every blocker requires description, suggested_fix, evidence and requirement_relation."
        )
    return BlockingFinding(
        category=category,
        description=value["description"],
        suggested_fix=value["suggested_fix"],
        evidence=value["evidence"],
        requirement_relation=value["requirement_relation"],
        severity=_parse_issue(value).severity.value,
        introduced_behavior=_optional_text(value.get("introduced_behavior")),
        prior_absence=_optional_text(value.get("prior_absence")),
        source_change_evidence=_optional_text(value.get("source_change_evidence")),
    )


def _optional_text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


_SEVERITY_PRIORITY = {
    ReviewSeverity.CRITICAL: 0,
    ReviewSeverity.HIGH: 1,
    ReviewSeverity.MEDIUM: 2,
    ReviewSeverity.LOW: 3,
    ReviewSeverity.INFO: 4,
}


def _deduplicate_and_limit_issues(
    issues: tuple[ReviewIssue, ...],
) -> tuple[ReviewIssue, ...]:
    """Keep at most five materially distinct issues in deterministic priority order."""

    unique: list[ReviewIssue] = []
    for issue in issues:
        if not any(_issues_are_near_duplicates(issue, prior) for prior in unique):
            unique.append(issue)

    if len(unique) <= MAX_REVIEW_ISSUES:
        return tuple(unique)
    ranked = sorted(
        enumerate(unique),
        key=lambda entry: (_SEVERITY_PRIORITY[entry[1].severity], entry[0]),
    )
    return tuple(issue for _index, issue in ranked[:MAX_REVIEW_ISSUES])


def _issues_are_near_duplicates(left: ReviewIssue, right: ReviewIssue) -> bool:
    """Conservatively merge only same-scope, near-identical reviewer findings."""

    if left.severity is not right.severity or left.file != right.file:
        return False
    left_text = _normalized_issue_text(left)
    right_text = _normalized_issue_text(right)
    if left_text == right_text:
        return True
    if not left_text or not right_text:
        return False
    if SequenceMatcher(a=left_text, b=right_text).ratio() >= 0.93:
        return True

    left_tokens = set(left_text.split())
    right_tokens = set(right_text.split())
    if not left_tokens or not right_tokens:
        return False
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens) >= 0.92


def _normalized_issue_text(issue: ReviewIssue) -> str:
    combined = f"{issue.description} {issue.suggested_fix or ''}".lower()
    return " ".join(re.findall(r"[a-z0-9_]+", combined))


def _parse_issue(value: object) -> ReviewIssue:
    if not isinstance(value, dict):
        raise CodeReviewParseError("Every issue must be a JSON object.")
    description = value.get("description")
    if not isinstance(description, str) or not description.strip():
        raise CodeReviewParseError("Every issue requires a non-empty description.")
    try:
        severity = ReviewSeverity(str(value.get("severity", "")).lower())
    except ValueError as exc:
        raise CodeReviewParseError("Every issue requires a known severity.") from exc
    file_name = value.get("file")
    suggested_fix = value.get("suggested_fix")
    if file_name is not None and not isinstance(file_name, str):
        raise CodeReviewParseError("Issue file must be a string or null.")
    if suggested_fix is not None and not isinstance(suggested_fix, str):
        raise CodeReviewParseError("Issue suggested_fix must be a string or null.")
    return ReviewIssue(
        severity=severity,
        description=description,
        file=file_name,
        suggested_fix=suggested_fix,
    )


__all__ = [
    "MAX_REVIEW_ISSUES",
    "CodeReviewParseError",
    "CodeReviewRequest",
    "CodeReviewResult",
    "CodeReviewer",
    "ReviewAttemptOutcome",
    "ReviewIssue",
    "ReviewProviderAttempt",
    "ReviewSeverity",
    "ReviewRuntimeContext",
    "parse_review_response",
]
