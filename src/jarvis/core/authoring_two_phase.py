"""Two-phase, non-executing implementation used by SafeSkillAuthoringService."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Callable, cast

from jarvis.core.code_reviewer import (
    CodeReviewRequest,
    CodeReviewResult,
    ReviewIssue,
    ReviewSeverity,
    ReviewAttemptOutcome,
    ReviewProviderAttempt,
)
from jarvis.core.code_validation import ValidationReport, with_dynamic_skill_entrypoint_validation
from jarvis.core.dynamic_skill_contract import SOURCE_ENTRYPOINT_CONTRACT
from jarvis.core.external_data_requirements import requires_live_external_data
from jarvis.core.dependency_resolver import DependencyStatus
from jarvis.core.review_acceptance import (
    BlockerAssessment,
    BlockingFinding,
    ReviewAcceptanceState,
    apply_assessment,
    create_acceptance_state,
)
from jarvis.core.llm_output_normalizer import (
    AuthoringPhase,
    NormalizedAuthoringOutput,
    NormalizedOutputKind,
    normalize_authoring_output,
)

if TYPE_CHECKING:
    from jarvis.core.safe_skill_authoring import (
        AuthoringIterationDiagnostic,
        GeneratedSkillProposal,
        SafeSkillAuthoringService,
        SkillAuthoringRequest,
        SkillAuthoringResult,
    )


@dataclass(frozen=True)
class SourceRepairTask:
    """Frozen obligations plus the latest assessment, without altering the plan."""

    original_user_request: str
    current_source: str
    pending_blockers: tuple[BlockingFinding, ...]
    repair_iteration: int
    previous_repair_changed_source: bool | None = None
    latest_assessments: tuple[BlockerAssessment, ...] = ()
    latest_reviewed_source_hash: str | None = None
    previous_repair_reduced_blockers: bool | None = None


def author_two_phase(
    service: SafeSkillAuthoringService,
    request: SkillAuthoringRequest,
) -> SkillAuthoringResult:
    """Author source, review it, then author tests for that immutable source."""

    from jarvis.core.safe_skill_authoring import (
        AuthoringIterationDiagnostic,
        GeneratedSkillProposal,
        SkillAuthoringResult,
        SkillProposalParseError,
        _proposal_from_parts,
    )

    service._validate_request(request)
    reports: list[ValidationReport] = []
    reviews: list[CodeReviewResult] = []
    diagnostics: list[AuthoringIterationDiagnostic] = []
    dependencies: list[str] = []
    debug_session = service._start_debug_session(request.user_request)
    started_at = service._clock()
    iteration = 0
    first_response_structurally_valid: bool | None = None
    structural_retry_count = 0
    reviewer_repair_count = 0
    latest_normalization: tuple[int, NormalizedAuthoringOutput] | None = None

    def fail(reason: str) -> SkillAuthoringResult:
        failure = service._failure(
            iterations=iteration,
            reports=reports,
            reviews=reviews,
            diagnostics=diagnostics,
            declared_dependencies=dependencies,
            reason=reason,
        )
        return replace(
            failure,
            review_acceptance_plan=acceptance_state.plan if acceptance_state else None,
        )

    def record(diagnostic: AuthoringIterationDiagnostic) -> None:
        nonlocal first_response_structurally_valid, structural_retry_count, reviewer_repair_count
        if diagnostic.iteration == 1:
            first_response_structurally_valid = diagnostic.generation_success
        if not diagnostic.generation_success and diagnostic.normalization_error:
            structural_retry_count += 1
        if diagnostic.phase == AuthoringPhase.SOURCE_REPAIR.value and diagnostic.review_attempts:
            reviewer_repair_count += 1
        normalized = (
            latest_normalization[1]
            if latest_normalization and latest_normalization[0] == diagnostic.iteration else None
        )
        diagnostic = replace(
            diagnostic,
            first_response_structurally_valid=first_response_structurally_valid,
            structurally_recovered=bool(diagnostic.generation_success and normalized and normalized.structurally_recovered),
            structural_error_code=normalized.structural_error_code if normalized else None,
            structural_retry_count=structural_retry_count,
            reviewer_repair_count=reviewer_repair_count,
            source_repair_count=source_repair_count,
        )
        service._record_diagnostic(
            diagnostics,
            diagnostic,
            debug_session=debug_session,
        )

    def can_continue() -> str | None:
        if service._deadline_reached(started_at):
            return service._deadline_reason()
        if iteration >= service._max_iterations_hard_cap:
            return service._hard_cap_reason()
        return None

    source_previous: GeneratedSkillProposal | None = None
    source_validation: ValidationReport | None = None
    source_review: CodeReviewResult | None = None
    source_reviewed_source: str | None = None
    source_previous_hash: str | None = None
    source_previous_implementation: str | None = None
    source_previous_unresolved: int | None = None
    source_structural_retries = 0
    source_structural_rescue_used = False
    source_stagnation_count = 0
    source_rescue_used_for_episode = False
    source_rescue: str | None = None
    approved_source: GeneratedSkillProposal | None = None
    frozen_source_metadata: dict[str, object] | None = None
    acceptance_state: ReviewAcceptanceState | None = None
    source_repair_count = 0
    previous_repair_changed_source: bool | None = None
    previous_repair_reduced_blockers: bool | None = None

    while approved_source is None:
        stop_reason = can_continue()
        if stop_reason is not None:
            return fail(stop_reason)
        iteration += 1
        source_phase = (
            AuthoringPhase.SOURCE_INITIAL
            if frozen_source_metadata is None
            else AuthoringPhase.SOURCE_REPAIR
        )
        if source_phase is AuthoringPhase.SOURCE_REPAIR:
            if source_repair_count >= service._max_source_repairs:
                return fail(_source_repair_limit_reason(acceptance_state, source_review))
        repair_task = None
        if (
            source_phase is AuthoringPhase.SOURCE_REPAIR
            and source_previous is not None
            and (
                acceptance_state is not None
                or (source_validation is not None and not source_validation.success)
            )
        ):
            repair_task = SourceRepairTask(
                original_user_request=request.user_request,
                current_source=source_previous.source_code,
                pending_blockers=(
                    acceptance_state.pending_blockers
                    if acceptance_state is not None
                    else ()
                ),
                repair_iteration=source_repair_count + 1,
                previous_repair_changed_source=previous_repair_changed_source,
                latest_assessments=source_review.blocker_assessments if source_review is not None else (),
                latest_reviewed_source_hash=(
                    service._source_hash(source_reviewed_source) if source_reviewed_source is not None else None
                ),
                previous_repair_reduced_blockers=previous_repair_reduced_blockers,
            )
        prompt = build_source_prompt(
            service,
            request,
            iteration=iteration,
            previous_proposal=source_previous,
            previous_validation=source_validation,
            previous_review=source_review,
            rescue_diagnostic=source_rescue,
            repair_task=repair_task,
        )
        source_rescue = None
        try:
            raw_response = service._model_router.run_local_coding(prompt)
        except Exception as exc:
            record(
                _failed_diagnostic(
                    service,
                    iteration,
                    started_at,
                    phase=source_phase,
                    structural_retries=source_structural_retries,
                )
            )
            return fail(f"Local coder failed: {type(exc).__name__}: {exc}")

        debug_session.write_raw_response(iteration, raw_response)
        normalized = normalize_authoring_output(
            raw_response,
            phase=source_phase,
            user_request=request.user_request,
            existing_skill_name=request.existing_skill_name,
        )
        latest_normalization = (iteration, normalized)
        debug_session.write_extracted_code(iteration, normalized)
        if normalized.kind is not NormalizedOutputKind.SOURCE_PROPOSAL:
            source_structural_retries += 1
            rescue_triggered = False
            if (
                source_structural_retries == service._structural_rescue_after_failures
                and not source_structural_rescue_used
            ):
                source_rescue = _source_structural_rescue(
                    service,
                    request,
                    normalized.error or "unknown source response format",
                    repair=frozen_source_metadata is not None,
                )
                source_structural_rescue_used = True
                rescue_triggered = True
            record(
                _normalization_diagnostic(
                    service,
                    iteration=iteration,
                    started_at=started_at,
                    phase=source_phase,
                    normalized=normalized,
                    structural_retries=source_structural_retries,
                    stagnation_count=source_stagnation_count,
                    rescue_triggered=rescue_triggered,
                )
            )
            if service._deadline_reached(started_at):
                return fail(service._deadline_reason())
            if source_structural_retries >= service._max_consecutive_structural_failures:
                return fail(service._structural_failure_reason_for_phase(source_phase))
            continue

        try:
            proposal, metadata_reused, metadata_change_ignored = _source_proposal(
                normalized,
                iteration,
                frozen_metadata=frozen_source_metadata,
            )
        except SkillProposalParseError as exc:
            source_structural_retries += 1
            invalid = NormalizedAuthoringOutput(
                kind=NormalizedOutputKind.UNKNOWN,
                phase=source_phase,
                extraction_method=normalized.extraction_method,
                error=str(exc),
                structural_error_code="invalid_metadata",
                has_meta=normalized.has_meta,
                has_source=normalized.has_source,
                has_tests=normalized.has_tests,
            )
            latest_normalization = (iteration, invalid)
            record(
                _normalization_diagnostic(
                    service,
                    iteration=iteration,
                    started_at=started_at,
                    phase=AuthoringPhase.SOURCE,
                    normalized=invalid,
                    structural_retries=source_structural_retries,
                    stagnation_count=source_stagnation_count,
                )
            )
            if source_structural_retries >= service._max_consecutive_structural_failures:
                return fail(service._structural_failure_reason_for_phase(source_phase))
            continue

        if frozen_source_metadata is None:
            frozen_source_metadata = _metadata_from_proposal(proposal)
        elif source_phase is AuthoringPhase.SOURCE_REPAIR:
            source_repair_count += 1
        source_structural_retries = 0
        source_structural_rescue_used = False
        service._append_dependencies(dependencies, proposal.dependencies)
        source_hash = service._source_hash(proposal.source_code)
        source_changed = source_hash != source_previous_hash
        source_implementation = _source_implementation_key(proposal.source_code)
        implementation_changed = source_implementation != source_previous_implementation
        if source_phase is AuthoringPhase.SOURCE_REPAIR:
            previous_repair_changed_source = implementation_changed
        external_research = request.external_source_research
        validation = _validate_source(
            service,
            proposal,
            request.user_request,
            verified_external_endpoints=(
                external_research.observed_endpoints
                if external_research is not None
                else None
            ),
            verified_external_source=(
                external_research.source
                if (
                    external_research is not None
                    and external_research.direct_page_fetch_verified
                )
                else None
            ),
        )
        reports.append(validation)
        if any(check.name in ("dynamic_entrypoint", "dynamic_command_gate", "dynamic_text_index", "dynamic_result", "dynamic_persistence_state", "dynamic_external_data")
               and not check.success for check in validation.checks):
            # Contract failures belong to the deterministic validator. Give the
            # coder its exact error, without spending a review or changing the
            # frozen acceptance plan. Valid repairs still count toward limits.
            progress_detected = source_previous_hash is None or implementation_changed
            source_stagnation_count = 0 if progress_detected else source_stagnation_count + 1
            record(AuthoringIterationDiagnostic(
                iteration=iteration,
                elapsed_seconds=service._elapsed_seconds(started_at),
                phase=source_phase.value,
                source_hash=source_hash,
                source_changed=source_changed,
                validation_success=False,
                validation_fingerprint=service._validation_fingerprint(validation),
                review_approved=None,
                issue_fingerprint=None,
                progress_detected=progress_detected,
                generation_success=True,
                extraction_method=normalized.extraction_method,
                normalized_kind=normalized.kind.value,
                truncated=normalized.truncated,
                has_meta=normalized.has_meta,
                has_source=normalized.has_source,
                has_tests=normalized.has_tests,
                metadata_reused=metadata_reused,
                metadata_change_ignored=metadata_change_ignored,
                source_repair_count=source_repair_count,
                stagnation_count=source_stagnation_count,
                blocking_total=acceptance_state.blocking_total if acceptance_state else None,
                blocking_unresolved=acceptance_state.blocking_unresolved if acceptance_state else None,
                reviewer_used="none",
                review_attempts=0,
                rescue_triggered=bool(repair_task and repair_task.previous_repair_changed_source is False),
                review_skipped_reason=("invalid_entrypoint" if any(
                    check.name == "dynamic_entrypoint" and not check.success for check in validation.checks
                ) else "invalid_source_functionality"),
            ))
            if source_stagnation_count >= service._no_progress_iterations:
                return fail(service._stagnation_reason_for_phase(source_phase))
            if source_repair_count >= service._max_source_repairs:
                return fail("SOURCE_REPAIR limit reached with deterministic source validation failures.")
            source_previous = proposal
            source_validation = validation
            source_previous_hash = source_hash
            source_previous_implementation = source_implementation
            previous_repair_reduced_blockers = None
            continue
        review_skipped = (
            source_phase is AuthoringPhase.SOURCE_REPAIR
            and acceptance_state is not None
            and bool(acceptance_state.unresolved_ids)
            and not implementation_changed
        )
        if review_skipped:
            # The frozen assessment still applies to exactly the same source.
            # Keep it for prompt context; do not create a new provider verdict.
            review_resolution = _ReviewResolution(result=source_review, provider_attempts=())
        else:
            review_resolution = _obtain_valid_review(
                service,
                request,
                proposal,
                validation,
                authoring_iteration=iteration,
                debug_session=debug_session,
                acceptance_state=acceptance_state,
                previous_source=source_reviewed_source,
            )
        if review_resolution.result is None:
            record(
                _review_unavailable_diagnostic(
                    service,
                    iteration=iteration,
                    started_at=started_at,
                    phase=source_phase,
                    normalized=normalized,
                    source_hash=source_hash,
                    source_changed=source_changed,
                    validation=validation,
                    structural_retries=source_structural_retries,
                    stagnation_count=source_stagnation_count,
                    metadata_reused=metadata_reused,
                    metadata_change_ignored=metadata_change_ignored,
                    resolution=review_resolution,
                )
            )
            if service._deadline_reached(started_at):
                return fail(service._deadline_reason())
            return fail("Unable to obtain a valid code review for the current source.")
        review = review_resolution.result
        plan_created = False
        if not review_skipped and review.review_mode == "initial":
            if acceptance_state is not None:
                return fail("Reviewer returned an initial review after the acceptance plan was frozen.")
            acceptance_state = create_acceptance_state(review.blocking_findings, source_hash)
            plan_created = True
        elif not review_skipped and review.review_mode == "followup":
            if acceptance_state is None:
                return fail("Reviewer returned blocker statuses without an acceptance plan.")
            try:
                acceptance_state = apply_assessment(
                    acceptance_state,
                    review.blocker_assessments,
                    review.regression_findings,
                    source_changed=source_changed,
                )
            except ValueError:
                return fail("Reviewer returned invalid frozen blocker assessments.")
        effective_approved = (
            not acceptance_state.unresolved_ids
            if acceptance_state is not None
            else review.approved
        )
        if acceptance_state is not None and not review_skipped:
            pending_issues = tuple(
                ReviewIssue(
                    severity=ReviewSeverity.HIGH,
                    description=f"{blocker.id} {blocker.category.value}: {blocker.description}",
                    suggested_fix=blocker.suggested_fix,
                )
                for blocker in acceptance_state.pending_blockers
            )
            review = replace(review, approved=effective_approved, issues=pending_issues)
        if not review_skipped:
            reviews.append(review)
            source_reviewed_source = proposal.source_code
        validation_fingerprint = service._validation_fingerprint(validation)
        review_fingerprint = service._issue_fingerprint(review)
        unresolved_count = (
            acceptance_state.blocking_unresolved
            if acceptance_state is not None
            else 0 if review.approved else len(review.issues)
        )
        validation_improved = (
            source_validation is not None
            and not source_validation.success
            and validation.success
        )
        if source_phase is AuthoringPhase.SOURCE_REPAIR and not review_skipped:
            previous_repair_reduced_blockers = (
                source_previous_unresolved is not None and unresolved_count < source_previous_unresolved
            )
        progress_detected = not review_skipped and (
            source_previous_hash is None
            or implementation_changed
            or validation_improved
            or (source_previous_unresolved is not None and unresolved_count < source_previous_unresolved)
        )
        same_outcome = not progress_detected
        source_stagnation_count = source_stagnation_count + 1 if same_outcome else 0
        rescue_triggered = bool(repair_task and repair_task.previous_repair_changed_source is False)
        if (
            (not validation.success or not review.approved)
            and same_outcome
            and source_stagnation_count == 2
            and not source_rescue_used_for_episode
            and acceptance_state is None
        ):
            source_rescue = service._request_stagnation_rescue(
                request,
                proposal,
                validation,
            )
            source_rescue_used_for_episode = True
            rescue_triggered = True

        record(
            _source_diagnostic(
                service,
                iteration=iteration,
                started_at=started_at,
                normalized=normalized,
                phase=source_phase,
                metadata_reused=metadata_reused,
                metadata_change_ignored=metadata_change_ignored,
                review_attempts=review_resolution.review_attempts,
                review_transport_failed=review_resolution.transport_failed,
                reviewer_normalized=True,
                reviewer_normalization_error=None,
                reviewer_truncated=False,
                review_plan_created=plan_created,
                acceptance_state=acceptance_state,
                advisory_count=len(review.advisory_issues),
                source_repair_count=source_repair_count,
                source_hash=source_hash,
                source_changed=source_changed,
                validation=validation,
                validation_fingerprint=validation_fingerprint,
                review=review,
                review_fingerprint=review_fingerprint,
                progress_detected=progress_detected,
                structural_retries=source_structural_retries,
                stagnation_count=source_stagnation_count,
                rescue_triggered=rescue_triggered,
                repair_task=repair_task,
                repair_source_unchanged=(not implementation_changed) if repair_task else None,
                local_review_num_predict=review_resolution.local_review_num_predict,
                review_skipped_reason="unchanged_source" if review_skipped else None,
            )
        )
        if service._deadline_reached(started_at):
            return fail(service._deadline_reason())
        if not review_skipped and validation.success and review.approved:
            approved_source = proposal
            break
        if source_stagnation_count >= service._no_progress_iterations:
            return fail(service._stagnation_reason_for_phase(source_phase))
        if source_repair_count >= service._max_source_repairs:
            return fail(_source_repair_limit_reason(acceptance_state, review))
        source_previous = proposal
        source_validation = validation
        source_review = review
        source_previous_hash = source_hash
        source_previous_implementation = source_implementation
        source_previous_unresolved = unresolved_count
        if progress_detected:
            source_rescue_used_for_episode = False

    tests_previous: str | None = None
    tests_previous_hash: str | None = None
    tests_previous_validation: ValidationReport | None = None
    tests_previous_validation_fingerprint: str | None = None
    tests_structural_retries = 0
    tests_structural_rescue_used = False
    tests_stagnation_count = 0
    tests_rescue: str | None = None
    approved_source_hash = service._source_hash(approved_source.source_code)

    while True:
        stop_reason = can_continue()
        if stop_reason is not None:
            return fail(stop_reason)
        iteration += 1
        prompt = build_tests_prompt(
            service,
            request,
            approved_source=approved_source,
            iteration=iteration,
            previous_tests=tests_previous,
            previous_validation=tests_previous_validation,
            rescue_diagnostic=tests_rescue,
        )
        tests_rescue = None
        try:
            raw_response = service._model_router.run_local_coding(prompt)
        except Exception as exc:
            record(
                _failed_diagnostic(
                    service,
                    iteration,
                    started_at,
                    phase=AuthoringPhase.TESTS,
                    structural_retries=tests_structural_retries,
                )
            )
            return fail(f"Local coder failed: {type(exc).__name__}: {exc}")

        debug_session.write_raw_response(iteration, raw_response)
        normalized = normalize_authoring_output(raw_response, phase=AuthoringPhase.TESTS)
        latest_normalization = (iteration, normalized)
        debug_session.write_extracted_code(iteration, normalized)
        if normalized.kind is not NormalizedOutputKind.TESTS:
            tests_structural_retries += 1
            rescue_triggered = False
            if (
                tests_structural_retries == service._structural_rescue_after_failures
                and not tests_structural_rescue_used
            ):
                tests_rescue = _tests_structural_rescue(
                    approved_source,
                    normalized.error or "unknown tests response format",
                )
                tests_structural_rescue_used = True
                rescue_triggered = True
            record(
                _normalization_diagnostic(
                    service,
                    iteration=iteration,
                    started_at=started_at,
                    phase=AuthoringPhase.TESTS,
                    normalized=normalized,
                    structural_retries=tests_structural_retries,
                    stagnation_count=tests_stagnation_count,
                    rescue_triggered=rescue_triggered,
                    source_hash=approved_source_hash,
                )
            )
            if service._deadline_reached(started_at):
                return fail(service._deadline_reason())
            if tests_structural_retries >= service._max_consecutive_structural_failures:
                return fail(service._structural_failure_reason_for_phase(AuthoringPhase.TESTS))
            continue

        tests_structural_retries = 0
        tests_structural_rescue_used = False
        tests_source = normalized.tests_source
        if not isinstance(tests_source, str) or not tests_source.strip():
            return fail("Tests normalizer returned empty tests unexpectedly.")
        validation = _validate_tests(service, approved_source, tests_source)
        reports.append(validation)
        tests_hash = service._source_hash(tests_source)
        validation_fingerprint = service._validation_fingerprint(validation)
        same_outcome = (
            tests_previous_hash is not None
            and tests_hash == tests_previous_hash
            and validation_fingerprint == tests_previous_validation_fingerprint
        )
        progress_detected = not same_outcome
        tests_stagnation_count = tests_stagnation_count + 1 if same_outcome else 0
        rescue_triggered = False
        if same_outcome and tests_stagnation_count == 2:
            tests_rescue = (
                "TESTS-ONLY STAGNATION RESCUE. Return only corrected JARVIS_TESTS "
                "content. Do not repeat the current tests unchanged."
            )
            rescue_triggered = True
        record(
            _tests_diagnostic(
                service,
                iteration=iteration,
                started_at=started_at,
                normalized=normalized,
                source_hash=approved_source_hash,
                source_changed=tests_hash != tests_previous_hash,
                validation=validation,
                validation_fingerprint=validation_fingerprint,
                progress_detected=progress_detected,
                structural_retries=tests_structural_retries,
                stagnation_count=tests_stagnation_count,
                rescue_triggered=rescue_triggered,
            )
        )
        if service._deadline_reached(started_at):
            return fail(service._deadline_reason())
        if validation.success:
            dependency_results = service._resolve_dependencies(dependencies)
            final_proposal = GeneratedSkillProposal(
                skill_name=approved_source.skill_name,
                source_code=approved_source.source_code,
                implementation_summary=approved_source.implementation_summary,
                tests_source=tests_source,
                dependencies=approved_source.dependencies,
                iteration=iteration,
            )
            return SkillAuthoringResult(
                success=True,
                proposal=final_proposal,
                iterations=iteration,
                validation_reports=tuple(reports),
                review_results=tuple(reviews),
                declared_dependencies=tuple(dependencies),
                unavailable_dependencies=tuple(
                    result.dependency for result in dependency_results
                    if result.status is not DependencyStatus.AVAILABLE
                ),
                dependency_results=dependency_results,
                diagnostics=tuple(diagnostics),
                review_acceptance_plan=acceptance_state.plan if acceptance_state else None,
            )
        if tests_stagnation_count >= service._no_progress_iterations:
            return fail(service._stagnation_reason_for_phase(AuthoringPhase.TESTS))
        tests_previous = tests_source
        tests_previous_hash = tests_hash
        tests_previous_validation = validation
        tests_previous_validation_fingerprint = validation_fingerprint


def build_source_prompt(
    service: SafeSkillAuthoringService,
    request: SkillAuthoringRequest,
    *,
    iteration: int,
    previous_proposal: GeneratedSkillProposal | None,
    previous_validation: ValidationReport | None,
    previous_review: CodeReviewResult | None,
    rescue_diagnostic: str | None,
    repair_task: SourceRepairTask | None = None,
) -> str:
    """Build the contract-specific local-coder prompt for the SOURCE phase."""

    context = request.relevant_context or "No additional context was supplied."
    existing_name = request.existing_skill_name or "No existing skill is being referenced."
    rescue_context = ""
    if rescue_diagnostic:
        rescue_context = f"""
--- SOURCE NORMALIZATION OR RESCUE DIAGNOSIS ---
{rescue_diagnostic}
--- END SOURCE NORMALIZATION OR RESCUE DIAGNOSIS ---
"""

    if previous_proposal is None:
        live_data_instruction = ""
        if requires_live_external_data(request.user_request):
            live_data_instruction = """
LIVE EXTERNAL DATA REQUIREMENT:
The request requires current data from an external source. Implement a real
acquisition call whose returned data reaches the user-visible result. Never
substitute simulated, mocked, demo, placeholder, example, fake, dummy or
hardcoded current values. Do not invent an endpoint or source interface. Use
only verified source facts in RELEVANT CONTEXT; if they are insufficient, fail
the authoring task instead of fabricating a successful result.
"""
            if request.external_source_research and request.external_source_research.dynamic_interaction_evidence:
                live_data_instruction += """
DYNAMIC INTERACTION EVIDENCE AVAILABLE:
A dynamic interaction probe captured real selectors, endpoints, and/or DOM results in RELEVANT CONTEXT.
Reuse the verified selectors and/or endpoints in your code (using SecureWebSession or secure HTTP).
Do NOT guess or fabricate selectors.
"""
        return f"""You are the local Qwen coding specialist for JARVIS. Produce SOURCE only.
No files will be written and nothing will be executed from your response.

{SOURCE_ENTRYPOINT_CONTRACT}

The source must avoid eval and
exec and automatic dependency installation. Do not assume permission to access
hardware, filesystem, applications, or Klipper. Network access is appropriate
only when explicitly required by the original request and must use a real,
request-relevant acquisition path. Use explicit imports; do not install them.

Return one complete Python implementation, preferably a single ```python block.
Plain Python or a single <JARVIS_SOURCE>...</JARVIS_SOURCE> block is also accepted.
Do not return tests, JSON, metadata, placeholders or an explanation. JARVIS builds
the proposal name, summary and dependency declarations statically from the code
and request. Focus on implementing the requested behavior completely and concisely.
JARVIS handles runtime authorization; do not substitute simulation for the
requested capability. Implement real data acquisition and processing when
requested. Do not invent successful observations, service interfaces or current
results, and do not leave the requested operation as a TODO or placeholder.
{live_data_instruction}

--- ORIGINAL USER REQUEST (verbatim) ---
{request.user_request}
--- END ORIGINAL USER REQUEST ---
--- EXISTING SKILL REFERENCE ---
{existing_name}
--- RELEVANT CONTEXT ---
{context}
--- ITERATION ---
{iteration}
{rescue_context}"""

    validation_context = (
        previous_validation.to_prompt_context()
        if previous_validation is not None
        else "No validation report was produced."
    )
    external_data_failure = bool(
        previous_validation
        and any(
            check.name == "dynamic_external_data" and not check.success
            for check in previous_validation.checks
        )
    )
    frozen_metadata = {
        "skill_name": previous_proposal.skill_name,
        "implementation_summary": previous_proposal.implementation_summary,
        "dependencies": list(previous_proposal.dependencies),
    }
    blocker_context = "No pending review blockers; fix the local validation errors below."
    if repair_task is not None:
        current_hash = hashlib.sha256(repair_task.current_source.encode("utf-8")).hexdigest()
        blocker_context = _repair_blocker_context(repair_task, current_hash)
        escalation = ""
        if repair_task.previous_repair_changed_source is False:
            escalation = "previous_repair_changed_source=false\nrepair_source_unchanged=true\n" + _source_repair_unchanged_rescue()
        elif repair_task.previous_repair_reduced_blockers is False:
            escalation = (
                "previous_repair_changed_source=true\nprevious_repair_reduced_blockers=false\n"
                "The last repair changed code but did not reduce the pending blockers. "
                "It was rejected. Use the latest reviewer evidence below to make a "
                "different, concrete correction; do not repeat the failed approach."
            )
        review_context = (
            f"current_source_hash={current_hash}\n{escalation}\n"
            "--- PENDING BLOCKERS FROM FROZEN ACCEPTANCE PLAN ---\n"
            f"{blocker_context}\n"
            "--- END PENDING BLOCKERS ---\n"
            "Repair only the pending obligations above and the local validation errors. "
            "For each pending blocker, identify its failing data/control path in the "
            "CURRENT SOURCE and implement an observable code correction. "
            "Acknowledge no blocker as resolved yourself; the reviewer decides. "
            "Do not work on already resolved blockers or add unrequested features. "
            "Preserve behavior and subparts that are already correct.\n"
            "Latest reviewer evidence describes the remaining failure. Initial evidence "
            "is historical and may refer to an older source. Suggested fixes are guidance; "
            "equivalent implementations satisfying the requirement are allowed. "
            "Do not invent an API endpoint or a new requirement from a suggestion.\n"
        )
        if external_data_failure:
            review_context += (
                "MANDATORY LIVE-DATA REPAIR: the deterministic validator rejected this "
                "source because it did not demonstrate real external acquisition flowing "
                "to the returned result, or it contained simulated data. Implement a real "
                "acquisition and derive the result from that response. Do not repair this "
                "by changing, moving, or relabeling literal/fake values, adding a mock, "
                "or adding an unused network call. If verified source facts are insufficient, "
                "do not fabricate an endpoint or a successful result.\n"
            )
    else:
        # Compatibility for callers using the historical, unplanned review API.
        review_context = (
            "--- PRIOR REVIEW ISSUES ---\n"
            f"{service._review_context(previous_review)}\n"
            "--- END PRIOR REVIEW ISSUES ---\n"
        )
    return f"""You are the local Qwen coding specialist for JARVIS. Produce a SOURCE REPAIR only.
No files will be written and nothing will be executed from your response.

{review_context}

The metadata below is frozen. Do NOT regenerate metadata and do NOT change the
skill name, implementation summary, or dependencies. Do NOT return tests, a
review, or a validation report. Correct the source specifically for every listed
validator error and pending blocker. If any validator error or blocker remains,
returning the source unchanged is invalid.
Whitespace-only, comment-only or unrelated changes do not count as progress.
Implement the requested operation; comments describing it, placeholders and
simulated current results are not an implementation.

Return only corrected Python source, preferably in this literal block:
<JARVIS_SOURCE>
complete corrected Python source with ejecutar_skill
</JARVIS_SOURCE>
A single unambiguous ```python fenced block or plain Python is also accepted. Do not emit both
formats and do not emit any JARVIS_META or JARVIS_TESTS block.
Return the full corrected source, not a diff or a partial snippet.

--- ORIGINAL USER REQUEST (verbatim) ---
{request.user_request}
--- END ORIGINAL USER REQUEST ---
--- RELEVANT CONTEXT ---
{context}
--- FROZEN METADATA ---
{json.dumps(frozen_metadata, ensure_ascii=False, sort_keys=True)}
--- END FROZEN METADATA ---
--- PRIOR SOURCE TO REPAIR ---
{previous_proposal.source_code}
--- EXACT PRIOR LOCAL SOURCE VALIDATION ---
{validation_context}
--- END PRIOR SOURCE MATERIAL ---
--- RUNTIME CONTRACT TO PRESERVE ---
{SOURCE_ENTRYPOINT_CONTRACT}
--- ITERATION ---
{iteration}
--- REPAIR ITERATION ---
{repair_task.repair_iteration if repair_task else iteration}
{rescue_context}"""


def _repair_blocker_context(task: SourceRepairTask, current_hash: str) -> str:
    """Prefer assessed evidence; retain immutable findings as labelled history."""
    assessments = {assessment.id: assessment for assessment in task.latest_assessments}
    sections = []
    for blocker in task.pending_blockers:
        assessment = assessments.get(blocker.id)
        evidence = blocker.evidence
        origin = "initial finding; check its old snippet against the current source"
        history = ""
        if assessment is not None and assessment.status == "unresolved":
            evidence = assessment.evidence
            scope = "current source" if task.latest_reviewed_source_hash == current_hash else "earlier reviewed source; recheck against current source"
            origin = f"latest follow-up, {scope}, hash={task.latest_reviewed_source_hash}"
            history = f"\nOriginal finding evidence (historical): {blocker.evidence}"
        sections.append(
            f"{blocker.id} — {blocker.category.value}\nStatus: unresolved\n"
            f"Problem: {blocker.description}\n"
            f"Requirement relation: {blocker.requirement_relation}\n"
            f"Evidence: {evidence}\nEvidence origin: {origin}\n"
            f"Suggested fix: {blocker.suggested_fix}{history}"
        )
    return "\n\n".join(sections) or "No pending review blockers; fix the local validation errors below."


def _source_implementation_key(source: str) -> str:
    """Ignore comments/layout for progress; syntax failures still reach validation."""
    try:
        return ast.dump(ast.parse(source), include_attributes=False)
    except (SyntaxError, ValueError):
        return "invalid_python:" + source


def build_tests_prompt(
    service: SafeSkillAuthoringService,
    request: SkillAuthoringRequest,
    *,
    approved_source: GeneratedSkillProposal,
    iteration: int,
    previous_tests: str | None,
    previous_validation: ValidationReport | None,
    rescue_diagnostic: str | None,
) -> str:
    repair_context = ""
    if previous_tests is not None:
        validation_context = (
            previous_validation.to_prompt_context()
            if previous_validation is not None
            else "No validation report was produced."
        )
        repair_context = f"""
--- PRIOR TESTS TO REPAIR ---
{previous_tests}
--- EXACT PRIOR TEST VALIDATION ---
{validation_context}
--- END PRIOR TEST MATERIAL ---
Do not return the tests unchanged while any listed test error remains unresolved.
"""
    rescue_context = ""
    if rescue_diagnostic:
        rescue_context = f"""
--- TESTS NORMALIZATION OR RESCUE DIAGNOSIS ---
{rescue_diagnostic}
--- END TESTS NORMALIZATION OR RESCUE DIAGNOSIS ---
"""
    metadata = {
        "skill_name": approved_source.skill_name,
        "implementation_summary": approved_source.implementation_summary,
        "dependencies": list(approved_source.dependencies),
    }
    return f"""You are the local Qwen coding specialist for JARVIS. Produce TESTS only.
The approved source below is immutable: do not rewrite, replace or repair it.
Do not return metadata, source, JSON, a review or a validation report.
Do not explain your answer. Do not use Markdown or code fences.
Tests are proposal text only and will not be executed here.

Return exactly one <JARVIS_TESTS>...</JARVIS_TESTS> block and nothing else.
The content inside must be complete Python, with every statement finished.
Write at most 3 focused tests in at most 45 lines of Python. Keep mock data
small, share setup, and cover the requested behavior and an important failure
or state transition. Do not write a separate test for every helper or edge case.
Prefer compact test_* functions with asserts. Omit a main block or test runner.
Base assertions and mocks on the exact approved functions and behavior;
do not invent import paths, APIs, logging or return values. Finish with the
closing tag before adding any optional coverage. The following is a valid format example;
write tests for the actual approved behavior rather than copying this example:
<JARVIS_TESTS>
def test_entrypoint_is_callable():
    assert callable(ejecutar_skill)
</JARVIS_TESTS>

--- ORIGINAL USER REQUEST (verbatim) ---
{request.user_request}
--- END ORIGINAL USER REQUEST ---
--- APPROVED METADATA ---
{json.dumps(metadata, ensure_ascii=False, sort_keys=True)}
--- END APPROVED METADATA ---
--- IMMUTABLE APPROVED SOURCE ---
{approved_source.source_code}
--- END IMMUTABLE APPROVED SOURCE ---
--- ITERATION ---
{iteration}
{repair_context}{rescue_context}"""


def _source_proposal(
    normalized: NormalizedAuthoringOutput,
    iteration: int,
    *,
    frozen_metadata: dict[str, object] | None,
) -> tuple[GeneratedSkillProposal, bool, bool]:
    """Build a source proposal without permitting repair-time metadata drift.

    The initial normalized proposal contains statically built metadata. Once frozen, absent
    repair metadata is deliberately supplied only from the prior canonical
    proposal.  Supplied changed metadata is recorded and ignored; it cannot
    alter the deployment-facing contract silently.
    """

    from jarvis.core.safe_skill_authoring import SkillProposalParseError, _proposal_from_parts

    if (
        normalized.kind is not NormalizedOutputKind.SOURCE_PROPOSAL
        or not isinstance(normalized.source_code, str)
    ):
        raise SkillProposalParseError("normalized output is not a source proposal")

    if frozen_metadata is None:
        if not isinstance(normalized.metadata, dict):
            raise SkillProposalParseError(
                "initial source proposal is missing required metadata."
            )
        return (
            _proposal_from_parts(
                normalized.metadata,
                normalized.source_code,
                tests_source=None,
                iteration=iteration,
            ),
            False,
            False,
        )

    metadata_reused = normalized.metadata is None
    metadata_change_ignored = (
        isinstance(normalized.metadata, dict)
        and normalized.metadata != frozen_metadata
    )
    return (
        _proposal_from_parts(
            frozen_metadata,
            normalized.source_code,
            tests_source=None,
            iteration=iteration,
        ),
        metadata_reused,
        metadata_change_ignored,
    )


def _metadata_from_proposal(proposal: GeneratedSkillProposal) -> dict[str, object]:
    """Return the canonical metadata that becomes immutable for SOURCE repairs."""

    return {
        "skill_name": proposal.skill_name,
        "implementation_summary": proposal.implementation_summary,
        "dependencies": list(proposal.dependencies),
    }


@dataclass(frozen=True)
class _ReviewResolution:
    result: CodeReviewResult | None
    provider_attempts: tuple[ReviewProviderAttempt, ...]
    cloud_failure_reason: str | None = None

    @property
    def review_attempts(self) -> int:
        return len(self.provider_attempts)

    @property
    def transport_failed(self) -> bool:
        return self.result is None

    @property
    def normalization_error(self) -> str | None:
        for attempt in reversed(self.provider_attempts):
            if attempt.normalization_error:
                return attempt.normalization_error
        return None

    @property
    def truncated(self) -> bool:
        return any(attempt.truncated for attempt in self.provider_attempts)

    @property
    def local_review_num_predict(self) -> int | None:
        for attempt in reversed(self.provider_attempts):
            if attempt.local_review_num_predict is not None:
                return attempt.local_review_num_predict
        return None


def _obtain_valid_review(
    service: SafeSkillAuthoringService,
    request: SkillAuthoringRequest,
    proposal: GeneratedSkillProposal,
    validation: ValidationReport,
    *,
    authoring_iteration: int,
    debug_session: object,
    acceptance_state: ReviewAcceptanceState | None,
    previous_source: str | None,
) -> _ReviewResolution:
    """Run bounded review-only retries without regenerating the candidate source."""

    review_request = service._build_review_request(
        request,
        proposal,
        validation,
        acceptance_state=acceptance_state,
        previous_source=previous_source,
    )
    reviewer = service._reviewer
    traced_review = getattr(reviewer, "review_with_attempts", None)

    if not callable(traced_review):
        review = service._review_proposal(request, proposal, validation)
        attempt = ReviewProviderAttempt(
            provider=review.reviewer_used,
            raw_response=review.raw_response,
            normalization_success=review.reviewer_used != "none",
            normalization_error=(
                None
                if review.reviewer_used != "none"
                else "reviewer returned no structured result"
            ),
            approved=review.approved if review.reviewer_used != "none" else None,
            cloud_failure_reason=review.cloud_failure_reason,
        )
        _write_reviewer_attempts(
            debug_session,
            authoring_iteration=authoring_iteration,
            attempts=(attempt,),
        )
        return _ReviewResolution(
            result=review if review.reviewer_used != "none" else None,
            provider_attempts=(attempt,),
            cloud_failure_reason=review.cloud_failure_reason,
        )

    review_with_attempts = cast(
        Callable[[CodeReviewRequest], ReviewAttemptOutcome], traced_review
    )
    all_attempts: list[ReviewProviderAttempt] = []
    cloud_failure_reason: str | None = None
    for _review_cycle in range(service._max_review_cycles):
        try:
            outcome = review_with_attempts(review_request)
        except Exception as exc:
            attempts = (
                ReviewProviderAttempt(
                    provider="none",
                    raw_response=None,
                    normalization_success=False,
                    normalization_error=type(exc).__name__,
                ),
            )
            outcome = ReviewAttemptOutcome(
                result=None,
                provider_attempts=attempts,
                cloud_attempted=False,
            )
        all_attempts.extend(outcome.provider_attempts)
        _write_reviewer_attempts(
            debug_session,
            authoring_iteration=authoring_iteration,
            attempts=outcome.provider_attempts,
            attempt_offset=len(all_attempts) - len(outcome.provider_attempts),
        )
        cloud_failure_reason = outcome.cloud_failure_reason or cloud_failure_reason
        if outcome.result is not None:
            return _ReviewResolution(
                result=outcome.result,
                provider_attempts=tuple(all_attempts),
                cloud_failure_reason=cloud_failure_reason,
            )

    return _ReviewResolution(
        result=None,
        provider_attempts=tuple(all_attempts),
        cloud_failure_reason=cloud_failure_reason,
    )


def _write_reviewer_attempts(
    debug_session: object,
    *,
    authoring_iteration: int,
    attempts: tuple[ReviewProviderAttempt, ...],
    attempt_offset: int = 0,
) -> None:
    writer = getattr(debug_session, "write_reviewer_response", None)
    if not callable(writer):
        return
    for index, attempt in enumerate(attempts, start=1):
        writer(
            authoring_iteration=authoring_iteration,
            review_attempt=attempt_offset + index,
            provider=attempt.provider,
            raw_response=attempt.raw_response,
            normalization_success=attempt.normalization_success,
            normalization_error=attempt.normalization_error,
            approved=attempt.approved,
            truncated=attempt.truncated,
            local_review_num_predict=attempt.local_review_num_predict,
            blockers_downgraded_by_policy=attempt.blockers_downgraded_by_policy,
            normalization_error_kind=attempt.normalization_error_kind,
            unknown_severity_normalized=attempt.unknown_severity_normalized,
        )


def _review_unavailable_diagnostic(
    service: SafeSkillAuthoringService,
    *,
    iteration: int,
    started_at: float,
    phase: AuthoringPhase,
    normalized: NormalizedAuthoringOutput,
    source_hash: str,
    source_changed: bool,
    validation: ValidationReport,
    structural_retries: int,
    stagnation_count: int,
    metadata_reused: bool,
    metadata_change_ignored: bool,
    resolution: _ReviewResolution,
) -> "AuthoringIterationDiagnostic":
    from jarvis.core.safe_skill_authoring import AuthoringIterationDiagnostic

    return AuthoringIterationDiagnostic(
        iteration=iteration,
        elapsed_seconds=service._elapsed_seconds(started_at),
        source_hash=source_hash,
        validation_success=validation.success,
        review_approved=None,
        issue_fingerprint=None,
        progress_detected=False,
        generation_success=True,
        structural_retries=structural_retries,
        source_changed=source_changed,
        validation_fingerprint=service._validation_fingerprint(validation),
        reviewer_used="none",
        cloud_failed=True,
        cloud_failure_reason=resolution.cloud_failure_reason,
        stagnation_count=stagnation_count,
        extraction_method=normalized.extraction_method,
        structural_error=normalized.error,
        has_meta=normalized.has_meta,
        has_source=normalized.has_source,
        has_tests=normalized.has_tests,
        phase=phase.value,
        normalized_kind=normalized.kind.value,
        metadata_reused=metadata_reused,
        metadata_change_ignored=metadata_change_ignored,
        review_attempts=resolution.review_attempts,
        review_transport_failed=True,
        reviewer_normalized=False,
        reviewer_normalization_error=resolution.normalization_error,
        reviewer_truncated=resolution.truncated,
        local_review_num_predict=resolution.local_review_num_predict,
        normalization_error=normalized.error,
        truncated=normalized.truncated,
    )
def _validate_source(
    service: SafeSkillAuthoringService,
    proposal: GeneratedSkillProposal,
    user_request: str | None = None,
    *,
    verified_external_endpoints: tuple[str, ...] | None = None,
    verified_external_source: str | None = None,
) -> ValidationReport:
    report = service._validator.validate_python_source(
        proposal.source_code,
        filename=f"{proposal.skill_name}.py",
    )
    return with_dynamic_skill_entrypoint_validation(
        report,
        proposal.source_code,
        filename=f"{proposal.skill_name}.py",
        user_request=user_request,
        verified_external_endpoints=verified_external_endpoints,
        verified_external_source=verified_external_source,
    )


def _validate_tests(
    service: SafeSkillAuthoringService,
    proposal: GeneratedSkillProposal,
    tests_source: str,
) -> ValidationReport:
    return service._validator.validate_python_source(
        tests_source,
        filename=f"test_{proposal.skill_name}.py",
    )


def _source_repair_unchanged_rescue() -> str:
    """Escalate an unchanged repair using only known validation/review obligations."""

    return (
        "The previous SOURCE_REPAIR returned the same source, or only changed "
        "comments/whitespace with the same executable Python AST. "
        "That response made zero progress and was rejected. "
        "You MUST change the Python source in this response to resolve the failing "
        "local validation checks and/or pending review blockers. Returning the same "
        "source again is invalid. Make only concrete changes required by the "
        "validator diagnostics or pending blockers. "
        "Do not make whitespace-only, comment-only or unrelated changes. "
        "Do not add unrelated features or make cosmetic changes merely to change "
        "the source hash."
    )


def _source_structural_rescue(
    service: SafeSkillAuthoringService,
    request: SkillAuthoringRequest,
    structural_error: str,
    *,
    repair: bool,
) -> str:
    # Format classification is deterministic. There is no candidate to review,
    # and an additional model cannot resolve an ambiguous literal response.
    guidance = "Return one implementation, with no alternate versions or tests."
    if any(word in structural_error.lower() for word in ("truncated", "unclosed", "incomplete")):
        guidance = (
            "Regenerate a compact COMPLETE implementation from scratch. Do not "
            "continue, concatenate or reconstruct the incomplete previous response."
        )
    elif "metadata" in structural_error.lower():
        guidance = "Omit all metadata; JARVIS constructs it. Return only Python source."
    return (
        "SOURCE-ONLY FORMAT RESCUE. "
        f"Detected format error: {structural_error}. {guidance} "
        "Use one complete Python fence or plain Python with ejecutar_skill. "
        "Do not return JSON, metadata, a review, tests or prose. "
        + ("Previously frozen metadata remains unchanged." if repair else "")
    )


def _tests_structural_rescue(
    approved_source: GeneratedSkillProposal,
    structural_error: str,
) -> str:
    return (
        "TESTS-ONLY FORMAT RESCUE. "
        f"Detected format error: {structural_error}. "
        f"Regenerate tests for {approved_source.skill_name} from scratch; "
        "do not continue or reconstruct the previous incomplete response. "
        "Use at most 2 compact tests in at most 30 lines of complete Python. "
        "Return exactly one <JARVIS_TESTS>...</JARVIS_TESTS> block, closing "
        "every Python statement and the tag before adding optional coverage. "
        "No Markdown, fences, prose, JSON, metadata, source, review or audit. "
        "Omit a main block or test runner. The approved source is immutable."
    )


def _failed_diagnostic(
    service: SafeSkillAuthoringService,
    iteration: int,
    started_at: float,
    *,
    phase: AuthoringPhase,
    structural_retries: int,
) -> AuthoringIterationDiagnostic:
    from jarvis.core.safe_skill_authoring import AuthoringIterationDiagnostic

    return AuthoringIterationDiagnostic(
        iteration=iteration,
        elapsed_seconds=service._elapsed_seconds(started_at),
        source_hash=None,
        validation_success=None,
        review_approved=None,
        issue_fingerprint=None,
        progress_detected=False,
        generation_success=False,
        structural_retries=structural_retries,
        reviewer_used="none",
        phase=phase.value,
    )


def _normalization_diagnostic(
    service: SafeSkillAuthoringService,
    *,
    iteration: int,
    started_at: float,
    phase: AuthoringPhase,
    normalized: NormalizedAuthoringOutput,
    structural_retries: int,
    stagnation_count: int,
    rescue_triggered: bool = False,
    source_hash: str | None = None,
) -> AuthoringIterationDiagnostic:
    from jarvis.core.safe_skill_authoring import AuthoringIterationDiagnostic

    return AuthoringIterationDiagnostic(
        iteration=iteration,
        elapsed_seconds=service._elapsed_seconds(started_at),
        source_hash=source_hash,
        validation_success=None,
        review_approved=None,
        issue_fingerprint=None,
        progress_detected=False,
        generation_success=False,
        structural_retries=structural_retries,
        reviewer_used="none",
        stagnation_count=stagnation_count,
        rescue_triggered=rescue_triggered,
        extraction_method=normalized.extraction_method,
        structural_error=normalized.error,
        has_meta=normalized.has_meta,
        has_source=normalized.has_source,
        has_tests=normalized.has_tests,
        phase=phase.value,
        normalized_kind=normalized.kind.value,
        normalization_error=normalized.error,
        truncated=normalized.truncated,
    )


def _source_diagnostic(
    service: SafeSkillAuthoringService,
    *,
    iteration: int,
    started_at: float,
    normalized: NormalizedAuthoringOutput,
    phase: AuthoringPhase,
    metadata_reused: bool,
    metadata_change_ignored: bool,
    review_attempts: int,
    review_transport_failed: bool,
    reviewer_normalized: bool,
    reviewer_normalization_error: str | None,
    reviewer_truncated: bool,
    review_plan_created: bool,
    acceptance_state: ReviewAcceptanceState | None,
    advisory_count: int,
    source_repair_count: int,
    source_hash: str,
    source_changed: bool,
    validation: ValidationReport,
    validation_fingerprint: str,
    review: CodeReviewResult,
    review_fingerprint: str,
    progress_detected: bool,
    structural_retries: int,
    stagnation_count: int,
    rescue_triggered: bool,
    repair_task: SourceRepairTask | None,
    repair_source_unchanged: bool | None,
    local_review_num_predict: int | None,
    review_skipped_reason: str | None = None,
) -> AuthoringIterationDiagnostic:
    from jarvis.core.safe_skill_authoring import AuthoringIterationDiagnostic

    return AuthoringIterationDiagnostic(
        iteration=iteration,
        elapsed_seconds=service._elapsed_seconds(started_at),
        source_hash=source_hash,
        validation_success=validation.success,
        review_approved=None if review_skipped_reason else review.approved,
        local_review_num_predict=local_review_num_predict,
        blockers_downgraded_by_policy=review.blockers_downgraded_by_policy,
        issue_fingerprint=review_fingerprint,
        progress_detected=progress_detected,
        generation_success=True,
        structural_retries=structural_retries,
        source_changed=source_changed,
        validation_fingerprint=validation_fingerprint,
        reviewer_used="none" if review_skipped_reason else review.reviewer_used,
        cloud_failed=None if review_skipped_reason else review.cloud_failed,
        cloud_failure_reason=None if review_skipped_reason else review.cloud_failure_reason,
        review_fingerprint=review_fingerprint,
        stagnation_count=stagnation_count,
        rescue_triggered=rescue_triggered,
        extraction_method=normalized.extraction_method,
        structural_error=normalized.error,
        has_meta=normalized.has_meta,
        has_source=normalized.has_source,
        has_tests=normalized.has_tests,
        phase=phase.value,
        normalized_kind=normalized.kind.value,
        metadata_reused=metadata_reused,
        metadata_change_ignored=metadata_change_ignored,
        review_attempts=review_attempts,
        review_transport_failed=review_transport_failed,
        reviewer_normalized=None if review_skipped_reason else reviewer_normalized,
        reviewer_normalization_error=reviewer_normalization_error,
        reviewer_truncated=None if review_skipped_reason else reviewer_truncated,
        review_skipped_reason=review_skipped_reason,
        review_plan_created=review_plan_created,
        blocking_total=acceptance_state.blocking_total if acceptance_state else None,
        blocking_unresolved=acceptance_state.blocking_unresolved if acceptance_state else None,
        blocking_resolved=acceptance_state.blocking_resolved if acceptance_state else None,
        advisory_count=advisory_count,
        regression_blockers=len(acceptance_state.regression_blockers) if acceptance_state else None,
        source_repair_count=source_repair_count,
        repair_blocker_ids=tuple(blocker.id for blocker in repair_task.pending_blockers) if repair_task else (),
        repair_blocker_count=len(repair_task.pending_blockers) if repair_task else 0,
        repair_source_unchanged=repair_source_unchanged,
        normalization_error=normalized.error,
        truncated=normalized.truncated,
    )


def _source_repair_limit_reason(
    state: ReviewAcceptanceState | None,
    review: CodeReviewResult | None,
) -> str:
    if state is not None:
        pending = [
            f"{blocker.id} {blocker.category.value}: {blocker.description}"
            for blocker in state.pending_blockers
        ]
    else:
        pending = [issue.description for issue in review.issues] if review else []
    return "Source repair limit reached. Pending blockers: " + (
        "; ".join(pending) if pending else "none"
    )


def _tests_diagnostic(
    service: SafeSkillAuthoringService,
    *,
    iteration: int,
    started_at: float,
    normalized: NormalizedAuthoringOutput,
    source_hash: str,
    source_changed: bool,
    validation: ValidationReport,
    validation_fingerprint: str,
    progress_detected: bool,
    structural_retries: int,
    stagnation_count: int,
    rescue_triggered: bool,
) -> AuthoringIterationDiagnostic:
    from jarvis.core.safe_skill_authoring import AuthoringIterationDiagnostic

    return AuthoringIterationDiagnostic(
        iteration=iteration,
        elapsed_seconds=service._elapsed_seconds(started_at),
        source_hash=source_hash,
        validation_success=validation.success,
        review_approved=None,
        issue_fingerprint=None,
        progress_detected=progress_detected,
        generation_success=True,
        structural_retries=structural_retries,
        source_changed=source_changed,
        validation_fingerprint=validation_fingerprint,
        reviewer_used="none",
        stagnation_count=stagnation_count,
        rescue_triggered=rescue_triggered,
        extraction_method=normalized.extraction_method,
        structural_error=normalized.error,
        has_meta=normalized.has_meta,
        has_source=normalized.has_source,
        has_tests=normalized.has_tests,
        phase=AuthoringPhase.TESTS.value,
        normalized_kind=normalized.kind.value,
        normalization_error=normalized.error,
        truncated=normalized.truncated,
    )
