from __future__ import annotations

import json
import unittest

from jarvis.core.code_reviewer import CodeReviewer
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService, SkillAuthoringRequest


def source_response(source: str = "def ejecutar_skill():\n    return 'ok'\n") -> str:
    return (
        '<JARVIS_META>{"skill_name":"review_skill",'
        '"implementation_summary":"review retry test", "dependencies":[]}</JARVIS_META>'
        "<JARVIS_SOURCE>\n"
        + source
        + "</JARVIS_SOURCE>"
    )


def tests_response() -> str:
    return "<JARVIS_TESTS>\ndef test_ok():\n    assert True\n</JARVIS_TESTS>"


def approved_review() -> str:
    return json.dumps({"approved": True, "issues": [], "blocking_issues": [], "advisory_issues": []})


def resolved_review() -> str:
    return json.dumps({"approved": True, "issues": [], "blocker_statuses": [
        {"id": "B1", "status": "resolved", "evidence": "The current source persists state."}
    ], "regression_blockers": [], "advisory_issues": []})


def rejected_review() -> str:
    return json.dumps(
        {
            "approved": False,
            "issues": [
                {
                    "severity": "high",
                    "description": "The required persistence is absent.",
                    "suggested_fix": "Persist the previous state before responding.",
                }
            ],
            "blocking_issues": [{
                "severity": "high",
                "category": "state_persistence_broken",
                "description": "The required persistence is absent.",
                "suggested_fix": "Persist the previous state before responding.",
                "evidence": "No state write occurs in ejecutar_skill.",
                "requirement_relation": "The user requested saved previous state.",
            }],
            "advisory_issues": [],
        }
    )


def truncated_review() -> str:
    return '<JARVIS_DATA>{"approved": false, "issues": [{"severity": "high"'

class FakeCoder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            raise AssertionError("coder must not be called again")
        return self.responses.pop(0)


class FakeReviewRouter:
    def __init__(self, groq: list[str], local: list[str]) -> None:
        self.groq_api_key = "configured-for-test"
        self.groq = list(groq)
        self.local = list(local)
        self.groq_calls = 0
        self.local_calls = 0

    def run_groq_code_review(self, _prompt: str) -> str:
        self.groq_calls += 1
        return self.groq.pop(0)

    def run_local_reasoning(self, _prompt: str) -> str:
        self.local_calls += 1
        return self.local.pop(0)


class AuthoringReviewRetryTests(unittest.TestCase):
    def test_new_contract_severity_normalization_keeps_frozen_acceptance_plan(self) -> None:
        initial = json.loads(rejected_review())
        initial["issues"] = [{"severity": "warning", "description": "Ignored legacy finding."}]
        initial["blocking_issues"][0]["severity"] = "warning"
        initial["advisory_issues"] = [{"description": "Add logging later."}]
        followup = json.loads(resolved_review())
        followup["approved"] = False
        followup["issues"] = [{"severity": "fatal", "description": "Ignored legacy finding."}]
        followup["advisory_issues"] = [{"severity": "error", "description": "Add documentation later."}]
        repaired = "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'fixed'\n</JARVIS_SOURCE>"
        service, coder, router = self._service(
            [source_response(), repaired, tests_response()],
            [json.dumps(initial), json.dumps(followup)], [],
        )
        result = service.author(SkillAuthoringRequest("Remember previous state."))
        self.assertTrue(result.success)
        self.assertEqual((router.groq_calls, router.local_calls), (2, 0))
        self.assertEqual(len(coder.prompts), 3)
        self.assertEqual(result.review_acceptance_plan.blockers[0].id, "B1")
        self.assertEqual(result.review_acceptance_plan.blockers[0].category.value, "state_persistence_broken")
        self.assertEqual(result.review_acceptance_plan.blockers[0].severity, "high")
        self.assertEqual(result.diagnostics[0].blocking_unresolved, 1)
        self.assertEqual(result.diagnostics[1].blocking_resolved, 1)
        self.assertEqual(result.diagnostics[1].advisory_count, 1)
        self.assertTrue(result.review_results[1].approved)

    def test_empty_groq_uses_valid_local_review_without_source_repair(self) -> None:
        service, coder, router = self._service(
            [source_response(), tests_response()], [""], [approved_review()],
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertTrue(result.success)
        self.assertEqual(result.review_results[0].reviewer_used, "local")
        self.assertEqual(result.review_results[0].cloud_failure_reason, "empty response")
        self.assertEqual((router.groq_calls, router.local_calls), (1, 1))
        self.assertEqual(len(coder.prompts), 2)

    def test_empty_groq_and_truncated_local_keep_review_retry_fail_closed(self) -> None:
        service, coder, router = self._service(
            [source_response()], ["", ""], [truncated_review(), truncated_review()],
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertFalse(result.success)
        self.assertEqual((router.groq_calls, router.local_calls), (2, 2))
        self.assertEqual(len(coder.prompts), 1)
        self.assertEqual(result.diagnostics[0].stagnation_count, 0)
        self.assertTrue(result.diagnostics[0].reviewer_truncated)

    def _service(
        self,
        coder_responses: list[str],
        groq: list[str],
        local: list[str],
        *,
        max_review_cycles: int = 2,
    ) -> tuple[SafeSkillAuthoringService, FakeCoder, FakeReviewRouter]:
        coder = FakeCoder(coder_responses)
        router = FakeReviewRouter(groq, local)
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            max_seconds=60,
            max_review_cycles=max_review_cycles,
            diagnostic_sink=lambda _message: None,
        )
        return service, coder, router

    def test_valid_groq_does_not_use_local_fallback(self) -> None:
        service, _coder, router = self._service(
            [source_response(), tests_response()], [approved_review()], []
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertTrue(result.success)
        self.assertEqual(router.groq_calls, 1)
        self.assertEqual(router.local_calls, 0)

    def test_invalid_groq_uses_valid_local_without_source_repair(self) -> None:
        service, coder, router = self._service(
            [source_response(), tests_response()],
            ["not structured"],
            [approved_review()],
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertTrue(result.success)
        self.assertEqual(router.groq_calls, 1)
        self.assertEqual(router.local_calls, 1)
        self.assertEqual(len(coder.prompts), 2)
        self.assertEqual(result.review_results[0].reviewer_used, "local")

    def test_invalid_review_retries_without_source_mutation_or_coder_repair(self) -> None:
        invalid = "this is not a structured review"
        service, coder, router = self._service(
            [source_response()],
            [invalid, invalid],
            [invalid, invalid],
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertFalse(result.success)
        self.assertEqual(
            result.failure_reason,
            "Unable to obtain a valid code review for the current source.",
        )
        self.assertEqual(len(coder.prompts), 1)
        self.assertEqual(router.groq_calls, 2)
        self.assertEqual(router.local_calls, 2)
        self.assertEqual(len(result.diagnostics), 1)
        diagnostic = result.diagnostics[0]
        self.assertIsNotNone(diagnostic.source_hash)
        self.assertEqual(diagnostic.stagnation_count, 0)
        self.assertEqual(diagnostic.review_attempts, 4)
        self.assertTrue(diagnostic.review_transport_failed)
        self.assertFalse(diagnostic.reviewer_normalized)

    def test_truncated_review_retries_without_mutating_source_or_stagnating(self) -> None:
        source = "def ejecutar_skill():\n    return 'same'\n"
        service, coder, router = self._service(
            [source_response(source)],
            [truncated_review(), truncated_review()],
            [truncated_review(), truncated_review()],
        )
        expected_hash = service._source_hash(source)
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertFalse(result.success)
        self.assertEqual(len(coder.prompts), 1)
        self.assertEqual(router.groq_calls, 2)
        self.assertEqual(router.local_calls, 2)
        diagnostic = result.diagnostics[0]
        self.assertEqual(diagnostic.source_hash, expected_hash)
        self.assertEqual(diagnostic.stagnation_count, 0)
        self.assertTrue(diagnostic.reviewer_truncated)
        self.assertEqual(
            diagnostic.reviewer_normalization_error,
            "review response truncated before completing structured payload",
        )
    def test_valid_rejection_repairs_source_but_approval_enters_tests(self) -> None:
        repaired = "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'fixed'\n</JARVIS_SOURCE>"
        service, coder, router = self._service(
            [source_response(), repaired, tests_response()],
            [rejected_review(), resolved_review()],
            [],
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertTrue(result.success)
        self.assertEqual(len(coder.prompts), 3)
        self.assertIn("SOURCE REPAIR", coder.prompts[1])
        self.assertIn("Produce TESTS only.", coder.prompts[2])
        self.assertEqual(router.groq_calls, 2)

    def test_review_retry_limit_is_configurable_and_stops_cleanly(self) -> None:
        invalid = "not a review"
        service, coder, router = self._service(
            [source_response()], [invalid], [invalid], max_review_cycles=1
        )
        result = service.author(SkillAuthoringRequest("Create a reviewable skill."))
        self.assertFalse(result.success)
        self.assertEqual(len(coder.prompts), 1)
        self.assertEqual(router.groq_calls, 1)
        self.assertEqual(router.local_calls, 1)
        self.assertEqual(result.diagnostics[0].review_attempts, 2)


if __name__ == "__main__":
    unittest.main()
