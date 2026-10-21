"""Conservative, deterministic guardrail for optional code-review demands.

This does not decide whether generated code is correct. It only prevents a
reviewer from elevating known optional infrastructure choices into blockers
without an explicit requirement or a real JARVIS security boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from jarvis.core.review_acceptance import BlockingCategory, BlockingFinding


@dataclass(frozen=True)
class BlockerPolicyDecision:
    accepted: bool
    reason: str | None = None


@dataclass(frozen=True)
class ReviewPolicyFacts:
    """Trusted runtime facts, independent of the reviewer's prose."""

    local_component: bool = True
    distributed_service: bool = False
    platform_execution_controls: bool = True


_OPTIONAL_TOPICS = (
    ("redis", re.compile(r"\bredis\b", re.I)),
    ("sqlite", re.compile(r"\bsqlite\b", re.I)),
    ("concurrency", re.compile(r"\b(?:thread[ -]?safe(?:ty)?|file[ -]?lock(?:ing)?|concurren\w*|race condition)\b", re.I)),
    ("backoff", re.compile(r"\b(?:exponential backoff|backoff exponencial)\b", re.I)),
    ("rate_limit", re.compile(r"\b(?:advanced rate[ -]?limit\w*|sophisticated rate[ -]?limit\w*|rate[ -]?limit backoff|limitaci[oó]n avanzada de tasa)\b", re.I)),
    ("user_agent", re.compile(r"\buser[ -]?agent\b", re.I)),
    ("containers", re.compile(r"\b(?:kubernetes|k8s|containers?|contenedores?)\b", re.I)),
    ("distributed", re.compile(r"\b(?:distributed scal\w*|distributed deploy\w*|escalabilidad distribuida|despliegue distribuido)\b", re.I)),
    ("formatting", re.compile(r"\b(?:BOM|final newline|trailing newline|newline final|salto de l[ií]nea final)\b", re.I)),
    ("logging", re.compile(r"\b(?:sophisticated logging|elaborate logging|logging sofisticado)\b", re.I)),
    ("refactor", re.compile(r"\b(?:architectural refactor|pure refactor|refactor arquitect[oó]nico)\b", re.I)),
    ("platform_controls", re.compile(r"\b(?:reimplement PolicyCore|duplicate PolicyCore|own authorization layer|reimplement SafeSkillExecution|duplicate permission checks)\b", re.I)),
)
_BOUNDARY = re.compile(
    r"\b(?:PolicyCore|SafeSkillExecution|authorization|unauthorized access|"
    r"permission|confirmation|worker escape|sandbox escape|outside permitted paths|"
    r"autorizaci[oó]n|acceso no autorizado|confirmaci[oó]n|rutas permitidas)\b",
    re.I,
)
_PERSISTENCE_FAILURE = re.compile(
    r"\b(?:does not (?:save|persist|retain)|not (?:saved|persisted|retained)|"
    r"no (?:se )?(?:guarda|persiste|conserva)|lost between runs|se pierde entre ejecuciones)\b",
    re.I,
)
_STATE_REQUEST = re.compile(r"\b(?:persist\w*|remember|state|recordar|estado|guardar)\b", re.I)
_NEGATION = re.compile(r"\b(?:no|not|without|sin)\s+(?:debe\s+|must\s+|use\s+|usar\s+)?$", re.I)


def _explicitly_requested(topic: str, user_request: str, required_capabilities: frozenset[str]) -> bool:
    if topic in required_capabilities:
        return True
    # Only narrow affirmative directives in the original request count; model
    # claims in requirement_relation are deliberately not trusted as authority.
    target = dict(_OPTIONAL_TOPICS)[topic]
    for match in target.finditer(user_request):
        prefix = user_request[max(0, match.start() - 48):match.start()].rstrip()
        if _NEGATION.search(prefix):
            continue
        if re.search(r"\b(?:usa|usar|utiliza|utilizar|use|using|requiere|require|debe|must|con|with)\b", prefix, re.I):
            return True
    return False


def assess_blocker(
    finding: BlockingFinding,
    *,
    user_request: str = "",
    required_capabilities: frozenset[str] = frozenset(),
    runtime_facts: ReviewPolicyFacts = ReviewPolicyFacts(),
) -> BlockerPolicyDecision:
    """Accept or downgrade only recognizable optional demands."""

    text = f"{finding.description}\n{finding.suggested_fix}"
    topics = [name for name, pattern in _OPTIONAL_TOPICS if pattern.search(text)]
    if finding.category is BlockingCategory.SECURITY_BOUNDARY_VIOLATION:
        boundary_evidence = f"{finding.evidence}\n{finding.requirement_relation}"
        if not _BOUNDARY.search(boundary_evidence):
            return BlockerPolicyDecision(False, "security boundary not identified")
    for topic in topics:
        if topic == "platform_controls" and not runtime_facts.platform_execution_controls:
            continue
        if topic in {"distributed", "containers"} and runtime_facts.distributed_service:
            continue
        if _explicitly_requested(topic, user_request, required_capabilities):
            continue
        if not runtime_facts.local_component and topic in {"redis", "sqlite", "concurrency", "distributed", "containers"}:
            continue
        if (
            topic in {"redis", "sqlite"}
            and finding.category is BlockingCategory.STATE_PERSISTENCE_BROKEN
            and _PERSISTENCE_FAILURE.search(finding.description)
            and _STATE_REQUEST.search(user_request)
        ):
            continue
        return BlockerPolicyDecision(False, f"optional {topic} requirement")
    return BlockerPolicyDecision(True)


__all__ = ["BlockerPolicyDecision", "ReviewPolicyFacts", "assess_blocker"]
