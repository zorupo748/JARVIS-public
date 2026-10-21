from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.core.code_reviewer import (
    CodeReviewParseError,
    CodeReviewRequest,
    CodeReviewer,
    ReviewRuntimeContext,
    parse_review_response,
)
from jarvis.core.review_acceptance import (
    BlockerAssessment,
    BlockingCategory,
    BlockingFinding,
    apply_assessment,
    create_acceptance_state,
)
from jarvis.core.safe_skill_authoring import (
    GeneratedSkillProposal,
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
    get_skill_authoring_max_source_repairs,
)


SOURCE = "def ejecutar_skill():\n    return 'state'\n"
TESTS = "<JARVIS_TESTS>\ndef test_skill():\n    assert True\n</JARVIS_TESTS>"


def source_with_result(value: str) -> str:
    """Change executable code; comments alone are no longer repair progress."""
    return SOURCE.replace("return 'state'", f"return {value!r}")


def source_response(source: str = SOURCE, *, repair: bool = False) -> str:
    if repair:
        return f"<JARVIS_SOURCE>\n{source}</JARVIS_SOURCE>"
    return (
        '<JARVIS_META>{"skill_name":"review_plan_skill",'
        '"implementation_summary":"track a state", "dependencies":[]}</JARVIS_META>'
        f"<JARVIS_SOURCE>\n{source}</JARVIS_SOURCE>"
    )


def blocker(category: str = "user_requirement_unmet") -> dict[str, str]:
    return {
        "severity": "high",
        "category": category,
        "description": "The requested state is not saved.",
        "suggested_fix": "Save the state after reading it.",
        "evidence": "ejecutar_skill returns before any state write.",
        "requirement_relation": "The original request asks to remember state.",
    }


def initial_review(
    blockers: list[dict] | None = None,
    advisories: list[dict] | None = None,
    *,
    approved: bool = False,
) -> str:
    return json.dumps({
        "approved": approved,
        "issues": [],
        "blocking_issues": blockers or [],
        "advisory_issues": advisories or [],
    })


def followup_review(
    status: str = "resolved",
    *,
    approved: bool = False,
    evidence: str = "The current source saves the state.",
    regressions: list[dict] | None = None,
    advisories: list[dict] | None = None,
) -> str:
    return json.dumps({
        "approved": approved,
        "issues": [],
        "blocker_statuses": [{"id": "B1", "status": status, "evidence": evidence}],
        "regression_blockers": regressions or [],
        "advisory_issues": advisories or [],
    })


class FakeRouter:
    groq_api_key: str | None = "configured-in-test"

    def __init__(self, reviews: list[str]) -> None:
        self.reviews = list(reviews)
        self.prompts: list[str] = []

    def run_groq_code_review(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.reviews.pop(0)

    def run_local_reasoning(self, prompt: str) -> str:
        raise AssertionError("Groq responses in this test are valid")


class FakeCoder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.responses.pop(0)


def service_with(reviews: list[str], responses: list[str], *, max_repairs: int = 6):
    router = FakeRouter(reviews)
    coder = FakeCoder(responses)
    service = SafeSkillAuthoringService(
        coder,
        reviewer=CodeReviewer(router),
        max_seconds=60,
        max_source_repairs=max_repairs,
        diagnostic_sink=lambda _message: None,
    )
    return service, coder, router


class ReviewAcceptancePlanTests(unittest.TestCase):
    def test_repair_uses_only_frozen_pending_blockers_when_followup_issues_empty(self) -> None:
        imports = blocker("runtime_failure")
        imports.update({
            "description": "Required imports are missing.",
            "suggested_fix": "Import the required modules.",
            "evidence": "The source references modules that it does not import.",
            "requirement_relation": "The requested normal execution must run.",
        })
        summary = blocker("user_requirement_unmet")
        summary.update({
            "description": "The requested summary is absent.",
            "suggested_fix": "Produce the requested summary.",
            "evidence": "The source returns without constructing a summary.",
            "requirement_relation": "The original request explicitly asks for a summary.",
        })
        b2_pending = json.dumps({
            "approved": False, "issues": [],
            "blocker_statuses": [
                {"id": "B1", "status": "resolved", "evidence": "Imports are present."},
                {"id": "B2", "status": "unresolved", "evidence": "Summary is absent."},
            ],
            "regression_blockers": [], "advisory_issues": [],
        })
        all_resolved = json.dumps({
            "approved": False, "issues": [],
            "blocker_statuses": [
                {"id": "B1", "status": "resolved", "evidence": "Imports remain present."},
                {"id": "B2", "status": "resolved", "evidence": "Summary is now returned."},
            ],
            "regression_blockers": [], "advisory_issues": [],
        })
        service, coder, _router = service_with(
            [initial_review([imports, summary]), b2_pending, all_resolved],
            [source_response(), source_response("import math\n" + SOURCE, repair=True),
             source_response("import math\n" + source_with_result("requested summary"), repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Return the requested summary."))
        self.assertTrue(result.success)
        self.assertEqual(len(coder.prompts), 4)
        first_repair, second_repair = coder.prompts[1:3]
        self.assertIn("B1 — runtime_failure", first_repair)
        self.assertIn("B2 — user_requirement_unmet", first_repair)
        self.assertIn("B2 — user_requirement_unmet", second_repair)
        self.assertNotIn("B1 — runtime_failure", second_repair)
        self.assertIn(summary["description"], second_repair)
        self.assertIn(summary["suggested_fix"], second_repair)
        self.assertIn(summary["evidence"], second_repair)
        self.assertIn(summary["requirement_relation"], second_repair)
        self.assertEqual(result.diagnostics[2].repair_blocker_ids, ("B2",))
        self.assertEqual(result.diagnostics[2].repair_blocker_count, 1)

    def test_identical_repair_warns_next_attempt_and_preserves_stagnation(self) -> None:
        service, coder, _router = service_with(
            [initial_review([blocker()]), followup_review("resolved")],
            [source_response(), source_response(repair=True),
             source_response(source_with_result("saved state"), repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember the previous state."))
        self.assertTrue(result.success)
        self.assertTrue(result.diagnostics[1].repair_source_unchanged)
        self.assertEqual(result.diagnostics[1].stagnation_count, 1)
        self.assertIn("previous_repair_changed_source=false", coder.prompts[2])
        self.assertIn("You MUST change the Python source", coder.prompts[2])
        self.assertIn("Returning the same source again is invalid", coder.prompts[2])
        self.assertFalse(result.diagnostics[2].repair_source_unchanged)
        self.assertEqual(result.diagnostics[2].stagnation_count, 0)

    def test_first_blocker_creates_stable_plan_and_followup_resolves_it(self) -> None:
        service, coder, router = service_with(
            [initial_review([blocker()], approved=True), followup_review(approved=False)],
            [source_response(), source_response(source_with_result("saved state"), repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember the previous state."))
        self.assertTrue(result.success)
        self.assertEqual(result.diagnostics[0].blocking_total, 1)
        self.assertEqual(result.diagnostics[0].blocking_unresolved, 1)
        self.assertTrue(result.diagnostics[0].review_plan_created)
        self.assertEqual(result.diagnostics[1].blocking_resolved, 1)
        self.assertIn('"id": "B1"', router.prompts[1])
        self.assertIn("Review ONLY whether each frozen blocker is resolved", router.prompts[1])
        self.assertIn("Produce TESTS only.", coder.prompts[-1])
        assert result.review_acceptance_plan is not None
        self.assertEqual(result.review_acceptance_plan.blockers[0].id, "B1")

    def test_model_approval_cannot_override_unresolved_frozen_blocker(self) -> None:
        service, coder, _router = service_with(
            [initial_review([blocker()], approved=True),
             followup_review("unresolved", approved=True),
             followup_review("resolved", approved=False)],
            [source_response(), source_response(source_with_result("partial state"), repair=True),
             source_response(source_with_result("saved state"), repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember state."))
        self.assertTrue(result.success)
        self.assertFalse(result.review_results[0].approved)
        self.assertFalse(result.review_results[1].approved)
        self.assertTrue(result.review_results[2].approved)
        self.assertEqual(len(coder.prompts), 4)

    def test_advisories_only_approve_source_without_repair(self) -> None:
        advisory = {"severity": "medium", "description": "SQLite would be more scalable."}
        service, coder, _router = service_with(
            [initial_review(advisories=[advisory], approved=False)],
            [source_response(), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember one local value."))
        self.assertTrue(result.success)
        self.assertEqual(len(coder.prompts), 2)
        self.assertEqual(result.diagnostics[0].advisory_count, 1)
        self.assertEqual(result.diagnostics[0].blocking_unresolved, 0)

    def test_invalid_category_or_missing_evidence_fails_closed(self) -> None:
        invalid_category = blocker("enterprise_hardening")
        missing_evidence = blocker()
        missing_evidence.pop("evidence")
        for candidate in (invalid_category, missing_evidence):
            with self.subTest(candidate=candidate), self.assertRaises(CodeReviewParseError):
                parse_review_response(
                    initial_review([candidate]),
                    reviewer_used="groq", cloud_attempted=True, cloud_failed=False,
                )

    def test_recommendations_do_not_become_blockers_without_contract_evidence(self) -> None:
        for recommendation in (
            "Add newline and BOM handling.",
            "Use Redis or SQLite for simple local JSON state.",
            "Add advanced rate limiting despite existing error handling.",
        ):
            with self.subTest(recommendation=recommendation):
                candidate = blocker()
                candidate["description"] = recommendation
                candidate.pop("requirement_relation")
                with self.assertRaises(CodeReviewParseError):
                    parse_review_response(
                        initial_review([candidate]),
                        reviewer_used="groq", cloud_attempted=True, cloud_failed=False,
                    )

    def test_fingerprint_and_id_are_stable(self) -> None:
        finding = BlockingFinding(
            BlockingCategory.RUNTIME_FAILURE, "Call crashes", "Check response",
            "response is None", "Normal requested call",
        )
        first = create_acceptance_state((finding,), "source-hash")
        second = create_acceptance_state((finding,), "source-hash")
        self.assertEqual(first.plan, second.plan)
        self.assertEqual(first.plan.blockers[0].id, "B1")
        self.assertEqual(len(first.plan.blockers[0].fingerprint), 64)

    def test_review_limits_blockers_to_five_with_critical_priority(self) -> None:
        findings = []
        for index in range(6):
            item = blocker()
            item["description"] = f"Problem {index}"
            item["severity"] = "critical" if index == 5 else "medium"
            findings.append(item)
        result = parse_review_response(
            initial_review(findings),
            reviewer_used="groq", cloud_attempted=True, cloud_failed=False,
        )
        self.assertEqual(len(result.blocking_findings), 5)
        self.assertEqual(result.blocking_findings[0].description, "Problem 5")

    def test_non_regression_cannot_move_frozen_plan(self) -> None:
        finding = BlockingFinding(
            BlockingCategory.RUNTIME_FAILURE, "Call crashes", "Check response",
            "response is None", "Normal requested call",
        )
        state = create_acceptance_state((finding,), "hash")
        new_finding = BlockingFinding(
            BlockingCategory.DATA_CORRUPTION, "Potential corruption", "Use SQLite",
            "state.json is written", "Hypothetical concurrent writes",
        )
        updated = apply_assessment(
            state,
            (BlockerAssessment("B1", "resolved", "The response is now checked."),),
            (new_finding,), source_changed=True,
        )
        self.assertEqual(updated.plan, state.plan)
        self.assertEqual(updated.blocking_unresolved, 0)

    def test_real_regression_can_be_added_only_after_changed_source(self) -> None:
        state = create_acceptance_state((BlockingFinding(
            BlockingCategory.RUNTIME_FAILURE, "Call crashes", "Check response",
            "response is None", "Normal requested call",
        ),), "hash")
        regression = BlockingFinding(
            BlockingCategory.INCORRECT_RESULT, "New code returns wrong value",
            "Return the parsed value", "New return literal on line 3", "Original lookup request",
            introduced_behavior="Return literal", prior_absence="Prior code returned parsed value",
            source_change_evidence="Repair changed return statement",
        )
        assessment = (BlockerAssessment("B1", "resolved", "Now guarded."),)
        unchanged = apply_assessment(state, assessment, (regression,), source_changed=False)
        changed = apply_assessment(state, assessment, (regression,), source_changed=True)
        self.assertEqual(unchanged.blocking_unresolved, 0)
        self.assertEqual(changed.blocking_unresolved, 1)
        self.assertEqual(changed.regression_blockers[0].id, "R1")
        self.assertEqual(changed.plan, state.plan)

    def test_regression_in_followup_requires_another_repair(self) -> None:
        regression = blocker("incorrect_result")
        regression.update({
            "description": "Repair now returns an incorrect value.",
            "introduced_behavior": "Return literal value",
            "prior_absence": "Prior source returned parsed value",
            "source_change_evidence": "Changed return statement in repair",
        })
        second_followup = json.dumps({
            "approved": True, "issues": [],
            "blocker_statuses": [{"id": "B1", "status": "resolved", "evidence": "State is saved."}],
            "regression_blockers": [regression], "advisory_issues": [],
        })
        final_followup = json.dumps({
            "approved": False, "issues": [],
            "blocker_statuses": [
                {"id": "B1", "status": "resolved", "evidence": "State remains saved."},
                {"id": "R1", "status": "resolved", "evidence": "Parsed value is now returned."},
            ],
            "regression_blockers": [], "advisory_issues": [],
        })
        service, coder, router = service_with(
            [initial_review([blocker()]), second_followup, final_followup],
            [source_response(), source_response(source_with_result("incorrect value"), repair=True),
             source_response(source_with_result("parsed value"), repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember state."))
        self.assertTrue(result.success)
        self.assertEqual(result.diagnostics[1].regression_blockers, 1)
        self.assertEqual(result.diagnostics[1].blocking_unresolved, 1)
        self.assertIn('"id": "R1"', router.prompts[2])
        self.assertIn("source_change_evidence", router.prompts[2])
        self.assertEqual(len(coder.prompts), 4)

    def test_same_source_skips_queued_reviews_without_resetting_stagnation(self) -> None:
        second = followup_review("unresolved", evidence="Still not saved, wording A.")
        third = followup_review("unresolved", evidence="Still not saved, wording B.")
        service, coder, router = service_with(
            [initial_review([blocker()]), second, third, third],
            [source_response(), source_response(repair=True), source_response(repair=True), source_response(repair=True)],
        )
        result = service.author(SkillAuthoringRequest("Remember previous state."))
        self.assertFalse(result.success)
        self.assertEqual([item.progress_detected for item in result.diagnostics], [True, False, False, False])
        self.assertEqual([item.stagnation_count for item in result.diagnostics], [0, 1, 2, 3])
        self.assertEqual(len(coder.prompts), 4)
        self.assertEqual(len(router.prompts), 1)
        self.assertEqual(router.reviews, [second, third, third])

    def test_changed_source_counts_as_progress(self) -> None:
        service, _coder, _router = service_with(
            [initial_review([blocker()]), followup_review("unresolved"), followup_review()],
            [source_response(), source_response(source_with_result("partially changed state"), repair=True),
             source_response(source_with_result("saved state"), repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember previous state."))
        self.assertTrue(result.success)
        self.assertTrue(result.diagnostics[1].progress_detected)

    def test_reduced_blocker_count_counts_as_progress_without_source_change(self) -> None:
        state = create_acceptance_state((
            BlockingFinding(BlockingCategory.RUNTIME_FAILURE, "Crash", "Guard result", "None return", "Normal use"),
            BlockingFinding(BlockingCategory.INCORRECT_RESULT, "Wrong value", "Parse response", "Raw value", "Lookup request"),
        ), "hash")
        updated = apply_assessment(state, (
            BlockerAssessment("B1", "resolved", "Guard exists"),
            BlockerAssessment("B2", "unresolved", "Parse still absent"),
        ), (), source_changed=False)
        self.assertLess(updated.blocking_unresolved, state.blocking_unresolved)

    def test_authoring_progresses_when_pending_blockers_decrease(self) -> None:
        second = blocker("incorrect_result")
        second["description"] = "The normal result is wrong."
        first_followup = json.dumps({
            "approved": False, "issues": [],
            "blocker_statuses": [
                {"id": "B1", "status": "resolved", "evidence": "State is now saved."},
                {"id": "B2", "status": "unresolved", "evidence": "Result remains wrong."},
            ],
            "regression_blockers": [], "advisory_issues": [],
        })
        second_followup = json.dumps({
            "approved": False, "issues": [],
            "blocker_statuses": [
                {"id": "B1", "status": "resolved", "evidence": "State remains saved."},
                {"id": "B2", "status": "resolved", "evidence": "Result is now parsed."},
            ],
            "regression_blockers": [], "advisory_issues": [],
        })
        service, _coder, _router = service_with(
            [initial_review([blocker(), second]), first_followup, second_followup],
            [source_response(), source_response("def ejecutar_skill():\n    return 'saved-state'\n", repair=True),
             source_response("def ejecutar_skill():\n    return 'saved-state and parsed-result'\n", repair=True), TESTS],
        )
        result = service.author(SkillAuthoringRequest("Remember state and return a result."))
        self.assertTrue(result.success)
        self.assertTrue(result.diagnostics[1].progress_detected)
        self.assertEqual(result.diagnostics[1].blocking_unresolved, 1)

    def test_advisory_on_followup_does_not_change_frozen_plan(self) -> None:
        review = parse_review_response(
            followup_review(advisories=[{"severity": "low", "description": "Add Redis later."}]),
            reviewer_used="groq", cloud_attempted=True, cloud_failed=False,
        )
        state = create_acceptance_state((BlockingFinding(
            BlockingCategory.RUNTIME_FAILURE, "Crash", "Guard result", "None return", "Normal use",
        ),), "hash")
        updated = apply_assessment(
            state, review.blocker_assessments, review.regression_findings, source_changed=True,
        )
        self.assertEqual(updated.plan, state.plan)
        self.assertEqual(updated.blocking_unresolved, 0)
        self.assertEqual(len(review.advisory_issues), 1)

    def test_max_source_repair_setting_has_safe_default(self) -> None:
        self.assertEqual(get_skill_authoring_max_source_repairs({}), 6)
        self.assertEqual(get_skill_authoring_max_source_repairs({
            "JARVIS_SKILL_AUTHORING_MAX_SOURCE_REPAIRS": "4",
        }), 4)
        self.assertEqual(get_skill_authoring_max_source_repairs({
            "JARVIS_SKILL_AUTHORING_MAX_SOURCE_REPAIRS": "invalid",
        }), 6)

    def test_debug_persists_acceptance_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "authoring-debug"
            router = FakeRouter([initial_review([blocker()]), followup_review()])
            coder = FakeCoder([
                source_response(), source_response(source_with_result("saved state"), repair=True), TESTS,
            ])
            service = SafeSkillAuthoringService(
                coder, reviewer=CodeReviewer(router), max_seconds=60,
                debug_root=root, diagnostic_sink=lambda _message: None,
            )
            with patch.dict(os.environ, {"JARVIS_SKILL_AUTHORING_DEBUG": "true"}):
                self.assertTrue(service.author(SkillAuthoringRequest("Remember state.")).success)
            session = next(root.iterdir())
            diagnostics = [json.loads(line) for line in
                (session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(diagnostics[0]["review_plan_created"])
            self.assertEqual(diagnostics[0]["blocking_unresolved"], 1)
            self.assertEqual(diagnostics[1]["blocking_resolved"], 1)
            self.assertEqual(diagnostics[1]["source_repair_count"], 1)
            self.assertEqual(diagnostics[1]["repair_blocker_ids"], ["B1"])
            self.assertEqual(diagnostics[1]["repair_blocker_count"], 1)
            self.assertFalse(diagnostics[1]["repair_source_unchanged"])

    def test_repair_limit_lists_only_pending_blockers(self) -> None:
        advisory = {"severity": "low", "description": "Use Redis."}
        service, coder, _router = service_with(
            [initial_review([blocker()], [advisory]), followup_review("unresolved")],
            [source_response(), source_response(source_with_result("partially changed state"), repair=True)],
            max_repairs=1,
        )
        result = service.author(SkillAuthoringRequest("Remember previous state."))
        self.assertFalse(result.success)
        self.assertIn("B1", result.failure_reason or "")
        self.assertNotIn("Redis", result.failure_reason or "")
        self.assertEqual(len(coder.prompts), 2)
        self.assertEqual(result.diagnostics[-1].source_repair_count, 1)

    def test_runtime_context_is_in_initial_and_followup_prompts(self) -> None:
        service, _coder, router = service_with(
            [initial_review([blocker()]), followup_review()],
            [source_response(), source_response(source_with_result("saved state"), repair=True), TESTS],
        )
        self.assertTrue(service.author(SkillAuthoringRequest("Remember state.")).success)
        self.assertIsInstance(
            service._build_review_request(
                SkillAuthoringRequest("Remember state."),
                GeneratedSkillProposal(
                    skill_name="review_plan_skill",
                    source_code=SOURCE,
                    implementation_summary="track a state",
                ),
                service._validator.validate_python_source(SOURCE),
            ).runtime_context,
            ReviewRuntimeContext,
        )
        for prompt in router.prompts:
            self.assertIn("SafeSkillExecution", prompt)
            self.assertIn("PolicyCore", prompt)
            self.assertIn("child worker", prompt)
            self.assertIn("not a distributed production service", prompt)


if __name__ == "__main__":
    unittest.main()
