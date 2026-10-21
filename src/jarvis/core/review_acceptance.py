"""Deterministic acceptance state for a reviewed skill source."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum


class BlockingCategory(str, Enum):
    RUNTIME_FAILURE = "runtime_failure"
    USER_REQUIREMENT_UNMET = "user_requirement_unmet"
    STATE_PERSISTENCE_BROKEN = "state_persistence_broken"
    INCORRECT_RESULT = "incorrect_result"
    SECURITY_BOUNDARY_VIOLATION = "security_boundary_violation"
    DATA_CORRUPTION = "data_corruption"


@dataclass(frozen=True)
class BlockingFinding:
    category: BlockingCategory
    description: str
    suggested_fix: str
    evidence: str
    requirement_relation: str
    severity: str = "high"
    id: str = ""
    fingerprint: str = ""
    introduced_behavior: str = ""
    prior_absence: str = ""
    source_change_evidence: str = ""


@dataclass(frozen=True)
class BlockerAssessment:
    id: str
    status: str
    evidence: str


@dataclass(frozen=True)
class ReviewAcceptancePlan:
    blockers: tuple[BlockingFinding, ...]
    initial_source_hash: str


@dataclass(frozen=True)
class ReviewAcceptanceState:
    plan: ReviewAcceptancePlan
    unresolved_ids: frozenset[str]
    regression_blockers: tuple[BlockingFinding, ...] = ()

    @property
    def blocking_total(self) -> int:
        return len(self.plan.blockers) + len(self.regression_blockers)

    @property
    def blocking_unresolved(self) -> int:
        return len(self.unresolved_ids)

    @property
    def blocking_resolved(self) -> int:
        return self.blocking_total - self.blocking_unresolved

    @property
    def pending_blockers(self) -> tuple[BlockingFinding, ...]:
        return tuple(
            blocker
            for blocker in self.plan.blockers + self.regression_blockers
            if blocker.id in self.unresolved_ids
        )


def finding_fingerprint(finding: BlockingFinding) -> str:
    payload = json.dumps(
        [finding.category.value, finding.description.strip().casefold(), finding.evidence.strip().casefold()],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_acceptance_state(
    findings: tuple[BlockingFinding, ...], source_hash: str
) -> ReviewAcceptanceState:
    distinct: list[BlockingFinding] = []
    seen: set[str] = set()
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        if fingerprint not in seen:
            distinct.append(finding)
            seen.add(fingerprint)
    blockers = tuple(
        replace(finding, id=f"B{index}", fingerprint=finding_fingerprint(finding))
        for index, finding in enumerate(distinct[:5], start=1)
    )
    plan = ReviewAcceptancePlan(blockers=blockers, initial_source_hash=source_hash)
    return ReviewAcceptanceState(plan, frozenset(blocker.id for blocker in blockers))


def apply_assessment(
    state: ReviewAcceptanceState,
    assessments: tuple[BlockerAssessment, ...],
    regressions: tuple[BlockingFinding, ...],
    *,
    source_changed: bool,
) -> ReviewAcceptanceState:
    known = {blocker.id for blocker in state.plan.blockers + state.regression_blockers}
    reported = [assessment.id for assessment in assessments]
    if len(reported) != len(set(reported)) or set(reported) != known:
        raise ValueError("Review must assess every frozen blocker exactly once.")
    if any(assessment.status not in {"resolved", "unresolved"} or not assessment.evidence.strip() for assessment in assessments):
        raise ValueError("Every blocker assessment requires a status and evidence.")
    unresolved = {assessment.id for assessment in assessments if assessment.status == "unresolved"}
    existing_fingerprints = {
        blocker.fingerprint for blocker in state.plan.blockers + state.regression_blockers
    }
    accepted = list(state.regression_blockers)
    if source_changed:
        for finding in regressions:
            if not all((finding.introduced_behavior, finding.prior_absence, finding.source_change_evidence)):
                continue
            fingerprint = finding_fingerprint(finding)
            if fingerprint in existing_fingerprints:
                continue
            blocker = replace(finding, id=f"R{len(accepted) + 1}", fingerprint=fingerprint)
            accepted.append(blocker)
            unresolved.add(blocker.id)
            existing_fingerprints.add(fingerprint)
    return ReviewAcceptanceState(state.plan, frozenset(unresolved), tuple(accepted))
