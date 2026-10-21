from __future__ import annotations

import json
import unittest

from jarvis.core.code_reviewer import ReviewRuntimeContext, parse_review_response
from jarvis.core.review_acceptance import BlockingCategory, BlockingFinding
from jarvis.core.review_blocker_policy import ReviewPolicyFacts, assess_blocker


def finding(
    description: str,
    *,
    category: BlockingCategory = BlockingCategory.USER_REQUIREMENT_UNMET,
    suggested_fix: str = "Make the requested change.",
    evidence: str = "The candidate source lacks this behavior.",
    relation: str = "Normal requested use.",
) -> BlockingFinding:
    return BlockingFinding(category, description, suggested_fix, evidence, relation)


class ReviewBlockerPolicyTests(unittest.TestCase):
    def test_optional_infrastructure_is_advisory_by_default(self) -> None:
        examples = (
            "Use Redis for this simple JSON state.",
            "Use SQLite for this simple JSON state.",
            "Add theoretical thread safety.",
            "Add file locking for hypothetical concurrency.",
            "Add exponential backoff.",
            "Add advanced rate-limit handling.",
            "Set a User-Agent for every request.",
            "Deploy on Kubernetes containers.",
            "Add distributed scalability.",
            "Handle BOM and final newline.",
            "Add sophisticated logging.",
            "Perform an architectural refactor.",
            "Reimplement PolicyCore in the skill.",
        )
        for description in examples:
            with self.subTest(description=description):
                self.assertFalse(assess_blocker(finding(description)).accepted)

    def test_explicit_concurrency_and_storage_requirements_can_block(self) -> None:
        self.assertTrue(assess_blocker(
            finding("Add thread safety."),
            required_capabilities=frozenset({"concurrency"}),
        ).accepted)
        self.assertTrue(assess_blocker(
            finding("Use SQLite storage."),
            required_capabilities=frozenset({"sqlite"}),
        ).accepted)
        self.assertTrue(assess_blocker(
            finding("Use Redis storage."), user_request="Usa Redis para este estado.",
        ).accepted)
        self.assertTrue(assess_blocker(
            finding("Add distributed scalability."),
            runtime_facts=ReviewPolicyFacts(local_component=False, distributed_service=True),
        ).accepted)

    def test_real_runtime_and_explicit_functional_failures_remain_blockers(self) -> None:
        self.assertTrue(assess_blocker(finding(
            "NameError when executing the requested function.",
            category=BlockingCategory.RUNTIME_FAILURE,
        )).accepted)
        self.assertTrue(assess_blocker(finding(
            "The implementation omits the requested summary.",
        ), user_request="Resume los cambios.").accepted)
        self.assertTrue(assess_blocker(finding(
            "The state is not saved; SQLite is one possible correction.",
            category=BlockingCategory.STATE_PERSISTENCE_BROKEN,
        ), user_request="Recuerda el estado entre ejecuciones.").accepted)

    def test_network_reliability_is_not_a_security_boundary(self) -> None:
        self.assertFalse(assess_blocker(finding(
            "Missing User-Agent and rate-limit backoff.",
            category=BlockingCategory.SECURITY_BOUNDARY_VIOLATION,
            evidence="HTTP request has no User-Agent.",
            relation="Network reliability.",
        )).accepted)
        self.assertTrue(assess_blocker(finding(
            "The skill bypasses the required policy decision.",
            category=BlockingCategory.SECURITY_BOUNDARY_VIOLATION,
            evidence="Candidate invokes action before PolicyCore authorization.",
            relation="PolicyCore authorization is mandatory.",
        )).accepted)

    def test_parser_downgrades_optional_blocker_to_advisory(self) -> None:
        raw = json.dumps({
            "approved": False, "issues": [],
            "blocking_issues": [{
                "severity": "high", "category": "user_requirement_unmet",
                "description": "Use Redis for simple local state.",
                "suggested_fix": "Replace JSON with Redis.",
                "evidence": "The source writes JSON.",
                "requirement_relation": "General hardening.",
            }],
            "advisory_issues": [],
        })
        result = parse_review_response(
            raw, reviewer_used="local", cloud_attempted=False, cloud_failed=True,
            runtime_context=ReviewRuntimeContext(),
        )
        self.assertEqual(result.blocking_findings, ())
        self.assertEqual(len(result.advisory_issues), 1)
        self.assertEqual(len(result.blockers_downgraded_by_policy), 1)


if __name__ == "__main__":
    unittest.main()
