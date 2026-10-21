"""Replay sanitized real coder/reviewer transports; never execute candidates."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from jarvis.core.authoring_two_phase import SourceRepairTask, build_source_prompt
from jarvis.core.code_reviewer import CodeReviewer, parse_review_response
from jarvis.core.code_validation import LocalCodeValidator
from jarvis.core.review_acceptance import create_acceptance_state
from jarvis.core.safe_skill_authoring import (
    GeneratedSkillProposal, SafeSkillAuthoringService, SkillAuthoringRequest,
    DEFAULT_MAX_SOURCE_REPAIRS, DEFAULT_NO_PROGRESS_ITERATIONS,
)


FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "source_repair_real_session.json").read_text(encoding="utf-8"))
# Keep review-repair lifecycle tests independent of the live-data policy. The
# recorded tracking request and its simulation are rejected in live-data tests.
REQUEST = SkillAuthoringRequest(
    "Return the requested information and summarize it; remember previous queries."
)
RAW = [record["raw_response"] for record in FIXTURE["raw_responses"]]
REVIEW_RAW = [record["raw_response"] for record in FIXTURE["reviewer_responses"]]
ARTIFACT_SOURCES = [source.strip() for source in FIXTURE["sources"]]
# The real #2 artifact still has direct state indexing rejected by the current
# local validator. Keep the recorded text intact and use a validator-compatible
# candidate for tests that exercise the later review/repair lifecycle.
SOURCES = [
    ARTIFACT_SOURCES[0],
    *[
        source.replace('estado["location"]', 'estado.get("location", "Desconocido")')
        .replace('estado["status"]', 'estado.get("status", "Desconocido")')
        .replace('estado["next_steps"]', 'estado.get("next_steps", "Desconocido")')
        for source in ARTIFACT_SOURCES[1:]
    ],
]
RAW = [
    response.replace(ARTIFACT_SOURCES[index], SOURCES[index])
    for index, response in enumerate(RAW)
]
TESTS = "def test_entrypoint():\n    assert callable(ejecutar_skill)\n"


def review(raw):
    return parse_review_response(raw, reviewer_used="groq", cloud_attempted=True, cloud_failed=False)


INITIAL = review(REVIEW_RAW[0])
FOLLOWUP = review(REVIEW_RAW[1])
PLAN = create_acceptance_state(INITIAL.blocking_findings, hashlib.sha256(SOURCES[0].encode()).hexdigest())


def followup(statuses):
    return json.dumps({"approved": all(status == "resolved" for status in statuses.values()),
                       "blocker_statuses": [{"id": key, "status": status, "evidence": f"Current assessment of {key}: {status}."} for key, status in statuses.items()],
                       "regression_blockers": [], "advisory_issues": []})


class Coder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []

    def run_local_coding(self, prompt):
        self.prompts.append(prompt)
        return self.responses.pop(0)


class ReviewerRouter:
    groq_api_key = "test-only"

    def __init__(self, responses, local=()):
        self.responses = list(responses)
        self.local = list(local)
        self.prompts = []
        self.local_prompts = []

    def run_groq_code_review(self, prompt):
        self.prompts.append(prompt)
        return self.responses.pop(0)

    def run_local_reasoning(self, prompt):
        self.local_prompts.append(prompt)
        return self.local.pop(0)


class SourceRepairContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def run_authoring(self, responses, reviews=REVIEW_RAW, local=()):
        coder = Coder(responses)
        router = ReviewerRouter(reviews, local)
        service = SafeSkillAuthoringService(coder, reviewer=CodeReviewer(router), max_seconds=60,
                                           debug_root=Path(self.temporary.name), diagnostic_sink=lambda _: None)
        result = service.author(REQUEST)
        return result, coder, router, service

    def prompt(self, *, changed=None, latest=False, reviewed_hash=None):
        coder = Coder([])
        service = SafeSkillAuthoringService(coder, max_seconds=60, diagnostic_sink=lambda _: None)
        source = SOURCES[1 if latest else 0]
        proposal = GeneratedSkillProposal(skill_name="repair_context", source_code=source,
                                          implementation_summary="Frozen summary", dependencies=())
        task = SourceRepairTask(REQUEST.user_request, source, PLAN.pending_blockers, 2 if latest else 1,
                                changed, FOLLOWUP.blocker_assessments if latest else (),
                                reviewed_hash or hashlib.sha256(source.encode()).hexdigest(),
                                False if latest else None)
        return build_source_prompt(service, REQUEST, iteration=3 if latest else 2, previous_proposal=proposal,
                                   previous_validation=LocalCodeValidator().validate_dynamic_skill_source(source),
                                   previous_review=FOLLOWUP if latest else INITIAL, rescue_diagnostic=None, repair_task=task)

    def test_pending_blockers_have_stable_ids_categories_descriptions_and_statuses(self):
        prompt = self.prompt()
        for blocker in PLAN.pending_blockers:
            self.assertIn(f"{blocker.id} — {blocker.category.value}", prompt)
            self.assertIn(blocker.description, prompt)
        self.assertEqual(prompt.count("Status: unresolved"), 2)

    def test_evidence_is_explicit_for_each_blocker(self):
        for blocker in PLAN.pending_blockers:
            self.assertIn(f"Evidence: {blocker.evidence}", self.prompt())

    def test_suggested_fix_is_explicit_for_each_blocker(self):
        for blocker in PLAN.pending_blockers:
            self.assertIn(f"Suggested fix: {blocker.suggested_fix}", self.prompt())

    def test_requirement_relation_and_full_original_request_are_preserved(self):
        prompt = self.prompt()
        self.assertIn(REQUEST.user_request, prompt)
        self.assertIn(REQUEST.user_request, prompt)
        for blocker in PLAN.pending_blockers:
            self.assertIn(f"Requirement relation: {blocker.requirement_relation}", prompt)

    def test_two_tasks_remain_distinct_and_do_not_become_generic_issues(self):
        prompt = self.prompt()
        start = prompt.index("B1 —")
        second = prompt.index("B2 —")
        self.assertIn(PLAN.pending_blockers[0].evidence, prompt[start:second])
        self.assertIn(PLAN.pending_blockers[1].evidence, prompt[second:])

    def test_latest_followup_evidence_is_primary_and_initial_evidence_is_history(self):
        prompt = self.prompt(changed=True, latest=True)
        for assessment, blocker in zip(FOLLOWUP.blocker_assessments, PLAN.pending_blockers):
            self.assertIn(f"Evidence: {assessment.evidence}", prompt)
            self.assertIn(f"Original finding evidence (historical): {blocker.evidence}", prompt)
        self.assertIn("latest follow-up, current source", prompt)

    def test_evidence_for_older_source_is_not_labelled_as_current(self):
        prompt = self.prompt(changed=True, latest=True, reviewed_hash="a" * 64)
        self.assertIn("earlier reviewed source; recheck against current source", prompt)
        self.assertNotIn("latest follow-up, current source", prompt)

    def test_changed_repair_with_no_reduction_gets_a_specific_escalation(self):
        prompt = self.prompt(changed=True, latest=True)
        self.assertIn("previous_repair_reduced_blockers=false", prompt)
        self.assertIn("do not repeat the failed approach", prompt)
        self.assertIn("observable code correction", prompt)
        self.assertLess(prompt.index("B1 —"), prompt.index("RUNTIME CONTRACT TO PRESERVE"))

    def test_identical_repair_rescue_has_current_hash_latest_evidence_and_obligations(self):
        prompt = self.prompt(changed=False, latest=True)
        self.assertIn("previous_repair_changed_source=false", prompt)
        self.assertIn("repair_source_unchanged=true", prompt)
        self.assertIn(hashlib.sha256(SOURCES[1].encode()).hexdigest(), prompt)
        self.assertIn("You MUST change the Python source", prompt)
        self.assertIn("Returning the same source again is invalid", prompt)
        for blocker, assessment in zip(PLAN.pending_blockers, FOLLOWUP.blocker_assessments):
            self.assertIn(blocker.requirement_relation, prompt)
            self.assertIn(assessment.evidence, prompt)

    def test_output_requires_full_source_no_diff_tests_or_metadata(self):
        prompt = self.prompt()
        self.assertIn("Return the full corrected source, not a diff", prompt)
        self.assertIn("Do NOT regenerate metadata", prompt)
        self.assertIn("Do NOT return tests", prompt)
        self.assertIn(SOURCES[0], prompt)

    def test_fix_suggestions_allow_valid_alternatives_without_invented_api_requirements(self):
        prompt = self.prompt()
        self.assertIn("equivalent implementations satisfying the requirement are allowed", prompt)
        self.assertIn("Do not invent an API endpoint", prompt)

    def test_real_five_attempts_fail_closed_and_review_only_the_two_distinct_sources(self):
        result, coder, router, service = self.run_authoring(RAW)
        self.assertFalse(result.success)
        self.assertIn("stalled", result.failure_reason)
        self.assertEqual(result.diagnostics[-1].stagnation_count, 3)
        self.assertEqual(result.diagnostics[-1].source_repair_count, 4)
        self.assertEqual(len(coder.prompts), 5)
        self.assertEqual(len(router.prompts), 2)
        self.assertEqual(result.review_acceptance_plan.blockers, PLAN.plan.blockers)
        self.assertEqual([d.review_attempts for d in result.diagnostics], [1, 1, 0, 0, 0])
        self.assertEqual(service._max_source_repairs, DEFAULT_MAX_SOURCE_REPAIRS)
        self.assertEqual(service._no_progress_iterations, DEFAULT_NO_PROGRESS_ITERATIONS)

    def test_real_second_repair_reaches_reviewer_and_third_uses_updated_evidence(self):
        result, coder, router, _ = self.run_authoring(RAW)
        self.assertTrue(result.diagnostics[1].source_changed)
        self.assertFalse(result.diagnostics[1].review_approved)
        self.assertIn(SOURCES[1], router.prompts[1])
        self.assertIn("previous_repair_reduced_blockers=false", coder.prompts[2])
        for assessment in FOLLOWUP.blocker_assessments:
            self.assertIn(assessment.evidence, coder.prompts[2])

    def test_real_identical_repairs_keep_latest_evidence_and_use_deterministic_rescue(self):
        result, coder, router, _ = self.run_authoring(RAW)
        for prompt in coder.prompts[3:]:
            self.assertIn("previous_repair_changed_source=false", prompt)
            for assessment in FOLLOWUP.blocker_assessments:
                self.assertIn(assessment.evidence, prompt)
        self.assertEqual([d.rescue_triggered for d in result.diagnostics], [False, False, False, True, True])
        self.assertEqual(router.local_prompts, [])

    def test_whitespace_and_comment_only_repair_is_not_progress_or_reviewed(self):
        for candidate in (SOURCES[0] + "\n# cosmetic repair", SOURCES[0].replace("    ", "        "),
                          SOURCES[0].replace("# Update state with new information", "# Cosmetic rewording")):
            with self.subTest(candidate=candidate):
                result, coder, router, _ = self.run_authoring([RAW[0]] + [candidate] * 3,
                                                             [REVIEW_RAW[0], followup({"B1": "resolved", "B2": "resolved"})])
                self.assertFalse(result.success)
                self.assertEqual(len(router.prompts), 1)
                self.assertEqual(len(router.responses), 1)
                self.assertFalse(result.diagnostics[1].progress_detected)
                self.assertTrue(result.diagnostics[1].repair_source_unchanged)
                self.assertEqual(result.diagnostics[-1].source_repair_count, 3)
                self.assertIn("previous_repair_changed_source=false", coder.prompts[2])

    def test_resolved_blocker_is_excluded_from_next_repair(self):
        final_source = SOURCES[1].replace('"Desconocido"', '"Sin observación"')
        result, coder, _, _ = self.run_authoring([RAW[0], RAW[1], final_source, TESTS],
            [REVIEW_RAW[0], followup({"B1": "resolved", "B2": "unresolved"}), followup({"B1": "resolved", "B2": "resolved"})])
        self.assertTrue(result.success)
        self.assertNotIn("B1 —", coder.prompts[2])
        self.assertNotIn(PLAN.pending_blockers[0].evidence, coder.prompts[2])
        self.assertIn("B2 —", coder.prompts[2])
        self.assertIn("Current assessment of B2: unresolved.", coder.prompts[2])

    def test_metadata_is_frozen_even_when_repair_supplies_changes(self):
        repair = '<JARVIS_META>{"skill_name":"other","implementation_summary":"changed","dependencies":["unexpected"]}</JARVIS_META>' + RAW[1]
        result, coder, _, _ = self.run_authoring([RAW[0], repair, TESTS],
            [REVIEW_RAW[0], followup({"B1": "resolved", "B2": "resolved"})])
        self.assertTrue(result.success)
        self.assertNotEqual(result.proposal.skill_name, "other")
        self.assertEqual(result.proposal.implementation_summary, REQUEST.user_request)
        self.assertEqual(result.proposal.dependencies, ())
        self.assertTrue(result.diagnostics[1].metadata_change_ignored)
        self.assertIn("Frozen", coder.prompts[1].replace("FROZEN", "Frozen"))

    def test_changed_source_can_resolve_blockers_only_by_reviewer_and_enter_tests(self):
        result, coder, router, _ = self.run_authoring([RAW[0], RAW[1], TESTS],
            [REVIEW_RAW[0], followup({"B1": "resolved", "B2": "resolved"})])
        self.assertTrue(result.success)
        self.assertEqual(result.diagnostics[1].blocking_unresolved, 0)
        self.assertEqual(len(router.prompts), 2)
        self.assertIn("Produce TESTS only", coder.prompts[-1])
        self.assertEqual(result.proposal.source_code.strip(), SOURCES[1])

    def test_changed_candidate_still_uses_groq_to_local_review_fallback(self):
        result, _, router, _ = self.run_authoring([RAW[0], RAW[1], TESTS],
            [REVIEW_RAW[0], "invalid review transport"], [followup({"B1": "resolved", "B2": "resolved"})])
        self.assertTrue(result.success)
        self.assertEqual(len(router.local_prompts), 1)
        self.assertEqual(result.diagnostics[1].review_attempts, 2)

    def test_four_blockers_to_one_to_zero_keeps_global_acceptance_and_source_immutable_for_tests(self):
        raw_initial = json.loads(REVIEW_RAW[0])
        for index in range(2):
            finding = dict(raw_initial["blocking_issues"][0])
            finding["description"] = f"Additional requested result {index} is missing."
            finding["evidence"] = f"The returned source does not construct requested result {index}."
            raw_initial["blocking_issues"].append(finding)
        initial = json.dumps(raw_initial)
        final_source = SOURCES[1].replace('"Desconocido"', '"Sin observación"')
        result, coder, router, _ = self.run_authoring([RAW[0], RAW[1], final_source, TESTS],
            [initial, followup({"B1": "resolved", "B2": "resolved", "B3": "resolved", "B4": "unresolved"}),
             followup({"B1": "resolved", "B2": "resolved", "B3": "resolved", "B4": "resolved"})])
        self.assertTrue(result.success)
        self.assertEqual([d.blocking_unresolved for d in result.diagnostics[:3]], [4, 1, 0])
        self.assertEqual(len(router.prompts), 3)
        self.assertIn("B4 —", coder.prompts[2])
        self.assertNotIn("B1 —", coder.prompts[2])
        self.assertEqual(result.proposal.source_code.strip(), final_source)
        self.assertIn(final_source, coder.prompts[-1])

    def test_initial_prompt_requires_real_acquisition_without_simulating_authorization(self):
        service = SafeSkillAuthoringService(Coder([]), diagnostic_sink=lambda _: None)
        prompt = build_source_prompt(service, REQUEST, iteration=1, previous_proposal=None,
                                   previous_validation=None, previous_review=None, rescue_diagnostic=None)
        self.assertIn("JARVIS handles runtime authorization", prompt)
        self.assertIn("do not substitute simulation", prompt)
        self.assertIn("Do not ask again for a configured value", prompt)
        self.assertIn(REQUEST.user_request, prompt)


if __name__ == "__main__":
    unittest.main()
