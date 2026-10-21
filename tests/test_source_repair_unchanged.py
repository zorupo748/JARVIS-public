from __future__ import annotations

import ast
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jarvis.core.authoring_two_phase as two_phase
from jarvis.core.code_reviewer import CodeReviewer
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService, SkillAuthoringRequest


SOURCE = "def ejecutar_skill():\n    return {}\n"
REPAIRED = "def ejecutar_skill():\n    return {'version': 'v1'}\n"
COMPLETE = "def ejecutar_skill():\n    return {'version': 'v1', 'summary': 'changes'}\n"
TESTS = "<JARVIS_TESTS>\ndef test_summary():\n    assert ejecutar_skill()['summary'] == 'changes'\n</JARVIS_TESTS>"
REQUEST = "Return the requested information and summarize it; remember previous queries."
METADATA = {"skill_name": "repair_skill", "implementation_summary": "Version and summary.", "dependencies": []}


def source_response(source: str = SOURCE, *, metadata: dict | None = None) -> str:
    return (
        "<JARVIS_META>" + json.dumps(METADATA if metadata is None else metadata) + "</JARVIS_META>"
        + repair_response(source)
    )


def repair_response(source: str = SOURCE) -> str:
    return "<JARVIS_SOURCE>\n" + source + "</JARVIS_SOURCE>"


def finding(description: str) -> dict[str, str]:
    return {
        "severity": "high", "category": "user_requirement_unmet",
        "description": description,
        "suggested_fix": "Return the requested value in ejecutar_skill.",
        "evidence": "ejecutar_skill returns a mapping without the requested value.",
        "requirement_relation": "The user explicitly requests the value.",
    }


def initial_review(*, approved: bool = False) -> str:
    return json.dumps({
        "approved": approved,
        "blocking_issues": [finding("Version is absent."), finding("Summary is absent.")],
        "advisory_issues": [],
    })


def followup(b1: str = "resolved", b2: str = "resolved") -> str:
    return json.dumps({
        "approved": True,
        "blocker_statuses": [
            {"id": "B1", "status": b1, "evidence": "Current source version behavior."},
            {"id": "B2", "status": b2, "evidence": "Current source summary behavior."},
        ],
        "regression_blockers": [], "advisory_issues": [],
    })


class Coder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            raise AssertionError("Unexpected coder call.")
        return self.responses.pop(0)


class Router:
    groq_api_key = "configured-for-test"

    def __init__(self, groq: list[str], local: list[str]) -> None:
        self.groq = list(groq)
        self.local = list(local)
        self.groq_calls = 0
        self.local_calls = 0

    def run_groq_code_review(self, _prompt: str) -> str:
        self.groq_calls += 1
        if not self.groq:
            raise AssertionError("Unexpected Groq call.")
        return self.groq.pop(0)

    def run_local_reasoning(self, _prompt: str) -> str:
        self.local_calls += 1
        if not self.local:
            raise AssertionError("Unexpected local reviewer call.")
        return self.local.pop(0)


class Reviewer(CodeReviewer):
    def __init__(self, router: Router) -> None:
        super().__init__(router)
        self.requests = []
        self.rescue_calls = 0

    def review_with_attempts(self, request):
        self.requests.append(request)
        return super().review_with_attempts(request)

    def diagnose_stagnation(self, _request):
        self.rescue_calls += 1
        raise AssertionError("Unchanged repair must not ask another LLM for guidance.")


def service_with(responses: list[str], reviews: list[str], *, local: list[str] | None = None,
                 max_repairs: int = 6, debug_root: Path | None = None):
    coder = Coder(responses)
    router = Router(reviews, local or [])
    reviewer = Reviewer(router)
    service = SafeSkillAuthoringService(
        coder, reviewer=reviewer, max_seconds=60, max_source_repairs=max_repairs,
        debug_root=debug_root, diagnostic_sink=lambda _message: None,
    )
    return service, coder, router, reviewer


class SourceRepairUnchangedTests(unittest.TestCase):
    def test_initial_source_creates_plan_and_first_identical_repair_skips_review(self) -> None:
        service, coder, router, reviewer = service_with(
            [source_response(), repair_response(), repair_response(COMPLETE), TESTS],
            [initial_review(), followup()],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertTrue(result.success)
        self.assertTrue(result.diagnostics[0].review_plan_created)
        self.assertEqual(result.diagnostics[0].blocking_unresolved, 2)
        unchanged = result.diagnostics[1]
        self.assertFalse(unchanged.source_changed)
        self.assertTrue(unchanged.repair_source_unchanged)
        self.assertFalse(unchanged.progress_detected)
        self.assertEqual(unchanged.stagnation_count, 1)
        self.assertEqual(unchanged.blocking_unresolved, 2)
        self.assertEqual(unchanged.repair_blocker_ids, ("B1", "B2"))
        self.assertEqual(unchanged.review_attempts, 0)
        self.assertEqual(unchanged.reviewer_used, "none")
        self.assertEqual(unchanged.review_skipped_reason, "unchanged_source")
        self.assertIsNone(unchanged.review_approved)
        self.assertIsNone(unchanged.reviewer_normalized)
        self.assertFalse(unchanged.review_transport_failed)
        self.assertEqual((router.groq_calls, router.local_calls), (2, 0))
        self.assertEqual(len(reviewer.requests), 2)
        self.assertEqual(len(result.review_results), 2)
        self.assertEqual(reviewer.rescue_calls, 0)
        self.assertIn("Produce TESTS only.", coder.prompts[-1])

    def test_identical_repair_keeps_exact_acceptance_state_object_and_never_assesses(self) -> None:
        service, _coder, router, _reviewer = service_with(
            [source_response(), repair_response(), repair_response(), repair_response()],
            [initial_review()],
        )
        with patch.object(two_phase, "_source_diagnostic", wraps=two_phase._source_diagnostic) as diagnostic, \
             patch.object(two_phase, "apply_assessment", wraps=two_phase.apply_assessment) as assess:
            result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        states = [call.kwargs["acceptance_state"] for call in diagnostic.call_args_list]
        self.assertEqual(len(states), 4)
        self.assertTrue(all(state is states[0] for state in states))
        self.assertEqual(states[0].unresolved_ids, frozenset({"B1", "B2"}))
        self.assertIs(result.review_acceptance_plan, states[0].plan)
        assess.assert_not_called()
        self.assertEqual(router.groq_calls, 1)

    def test_next_prompt_explicitly_rejects_identical_source_and_has_complete_frozen_blockers(self) -> None:
        service, coder, _router, _reviewer = service_with(
            [source_response(), repair_response(), repair_response(COMPLETE), TESTS],
            [initial_review(), followup()],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertTrue(result.success)
        prompt = coder.prompts[2]
        for text in (
            "previous_repair_changed_source=false",
            "same executable Python AST",
            "made zero progress and was rejected",
            "You MUST change the Python source",
            "Returning the same source again is invalid",
            "Do not make whitespace-only, comment-only or unrelated changes",
            "full corrected source, not a diff",
            REQUEST, SOURCE,
        ):
            self.assertIn(text, prompt)
        for blocker in result.review_acceptance_plan.blockers:
            for text in (blocker.id, blocker.category.value, blocker.description, blocker.evidence,
                         blocker.suggested_fix, blocker.requirement_relation):
                self.assertIn(text, prompt)
        metadata = json.loads(prompt.split("--- FROZEN METADATA ---\n", 1)[1].split("\n--- END FROZEN METADATA ---", 1)[0])
        self.assertEqual(metadata, METADATA)
        self.assertNotIn("<JARVIS_TESTS>", prompt)
        self.assertNotIn("<JARVIS_META>", prompt)

    def test_escalation_excludes_already_resolved_blockers(self) -> None:
        service, coder, router, _reviewer = service_with(
            [source_response(), repair_response(REPAIRED), repair_response(REPAIRED),
             repair_response(COMPLETE), TESTS],
            [initial_review(), followup(b2="unresolved"), followup()],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertTrue(result.success)
        unchanged = result.diagnostics[2]
        self.assertEqual((unchanged.blocking_resolved, unchanged.blocking_unresolved), (1, 1))
        self.assertEqual(unchanged.repair_blocker_ids, ("B2",))
        context = coder.prompts[3].split("--- PENDING BLOCKERS FROM FROZEN ACCEPTANCE PLAN ---", 1)[1].split("--- END PENDING BLOCKERS ---", 1)[0]
        self.assertIn("B2", context)
        self.assertIn("Summary is absent.", context)
        self.assertNotIn("B1", context)
        self.assertNotIn("Version is absent.", context)
        self.assertIn("made zero progress and was rejected", coder.prompts[3])
        self.assertEqual(router.groq_calls, 3)

    def test_valid_identical_outputs_count_toward_repair_limit(self) -> None:
        service, coder, router, _reviewer = service_with(
            [source_response(), repair_response(), repair_response()],
            [initial_review()], max_repairs=2,
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        self.assertIn("Source repair limit reached", result.failure_reason)
        self.assertEqual([item.source_repair_count for item in result.diagnostics], [0, 1, 2])
        self.assertEqual(len(coder.prompts), 3)
        self.assertEqual(router.groq_calls, 1)

    def test_three_identical_repairs_fail_closed_at_original_stagnation_limit(self) -> None:
        service, coder, router, reviewer = service_with(
            [source_response(), repair_response(), repair_response(), repair_response()],
            [initial_review()],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        self.assertIsNone(result.proposal)
        self.assertEqual(result.failure_reason,
                         "Source_repair authoring stalled after 3 consecutive iterations without progress.")
        self.assertEqual([item.stagnation_count for item in result.diagnostics], [0, 1, 2, 3])
        self.assertEqual([item.source_repair_count for item in result.diagnostics], [0, 1, 2, 3])
        self.assertEqual([item.progress_detected for item in result.diagnostics], [True, False, False, False])
        self.assertTrue(all(item.blocking_unresolved == 2 for item in result.diagnostics))
        self.assertEqual(router.groq_calls, 1)
        self.assertEqual(reviewer.rescue_calls, 0)
        self.assertTrue(all("Produce TESTS only." not in prompt for prompt in coder.prompts))

    def test_identical_candidate_cannot_consume_queued_approval_or_approve_itself(self) -> None:
        service, _coder, router, _reviewer = service_with(
            [source_response(), repair_response()],
            [initial_review(approved=True), followup()], max_repairs=1,
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        self.assertFalse(result.review_results[0].approved)
        self.assertIsNone(result.diagnostics[1].review_approved)
        self.assertEqual(len(router.groq), 1)
        self.assertEqual(len(result.review_results), 1)

    def test_different_transport_wrapper_with_identical_normalized_source_skips_review(self) -> None:
        fence = chr(96) * 3
        service, _coder, router, _reviewer = service_with(
            [source_response(), fence + "python\n" + SOURCE + fence],
            [initial_review()], max_repairs=1,
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        self.assertEqual(result.diagnostics[0].source_hash, result.diagnostics[1].source_hash)
        self.assertEqual(result.diagnostics[1].review_skipped_reason, "unchanged_source")
        self.assertEqual(result.diagnostics[1].source_repair_count, 1)
        self.assertEqual(router.groq_calls, 1)

    def test_different_repair_reviews_reduces_blockers_and_enters_tests(self) -> None:
        service, coder, router, reviewer = service_with(
            [source_response(), repair_response(), repair_response(REPAIRED),
             repair_response(COMPLETE), TESTS],
            [initial_review(), followup(b2="unresolved"), followup()],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertTrue(result.success)
        self.assertEqual([item.blocking_unresolved for item in result.diagnostics[:4]], [2, 2, 1, 0])
        self.assertEqual([item.stagnation_count for item in result.diagnostics[:4]], [0, 1, 0, 0])
        self.assertEqual([item.source_repair_count for item in result.diagnostics[:4]], [0, 1, 2, 3])
        self.assertEqual([request.code_diff for request in reviewer.requests], [SOURCE, REPAIRED, COMPLETE])
        self.assertEqual(router.groq_calls, 3)
        self.assertEqual(result.proposal.source_code, COMPLETE)
        self.assertIn("Produce TESTS only.", coder.prompts[-1])

    def test_new_hash_alone_never_approves_unresolved_blockers(self) -> None:
        service, coder, router, _reviewer = service_with(
            [source_response(), repair_response(SOURCE.replace("return {}", "return {'unrelated': True}"))],
            [initial_review(), followup("unresolved", "unresolved")], max_repairs=1,
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        self.assertTrue(result.diagnostics[1].source_changed)
        self.assertFalse(result.diagnostics[1].review_approved)
        self.assertEqual(result.diagnostics[1].blocking_unresolved, 2)
        self.assertEqual(router.groq_calls, 2)
        self.assertNotIn("Produce TESTS only.", coder.prompts[-1])

    def test_metadata_and_dependencies_stay_frozen_after_identical_and_changed_repairs(self) -> None:
        metadata = {**METADATA, "dependencies": ["json"]}
        hostile = {"skill_name": "renamed", "implementation_summary": "Changed summary.",
                   "dependencies": ["not_requested_package"]}
        service, coder, _router, _reviewer = service_with(
            [source_response(metadata=metadata), source_response(metadata=hostile),
             source_response(COMPLETE, metadata=hostile), TESTS],
            [initial_review(), followup()],
        )
        with patch.object(service._dependency_resolver, "resolve_many", wraps=service._dependency_resolver.resolve_many) as resolve:
            result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertTrue(result.success)
        self.assertEqual(result.proposal.skill_name, metadata["skill_name"])
        self.assertEqual(result.proposal.implementation_summary, metadata["implementation_summary"])
        self.assertEqual(result.proposal.dependencies, ("json",))
        self.assertEqual(result.declared_dependencies, ("json",))
        resolve.assert_called_once_with(("json",))
        self.assertTrue(result.diagnostics[1].metadata_change_ignored)
        self.assertTrue(result.diagnostics[2].metadata_change_ignored)
        self.assertNotIn("not_requested_package", coder.prompts[2])

    def test_changed_candidate_keeps_groq_local_fallback_and_review_retry(self) -> None:
        truncated = '<JARVIS_DATA>{"approved":false,"blocker_statuses":['
        service, _coder, router, _reviewer = service_with(
            [source_response(), repair_response(), repair_response(COMPLETE), TESTS],
            [initial_review(), "not JSON", followup()], local=[truncated],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertTrue(result.success)
        self.assertEqual(result.diagnostics[1].review_attempts, 0)
        self.assertEqual(result.diagnostics[2].review_attempts, 3)
        self.assertFalse(result.diagnostics[2].review_transport_failed)
        self.assertEqual((router.groq_calls, router.local_calls), (3, 1))

    def test_changed_candidate_with_failed_review_still_fails_closed(self) -> None:
        service, _coder, router, _reviewer = service_with(
            [source_response(), repair_response(), repair_response(COMPLETE)],
            [initial_review(), "invalid", "invalid"], local=["invalid", "invalid"],
        )
        result = service.author(SkillAuthoringRequest(REQUEST))
        self.assertFalse(result.success)
        self.assertEqual(result.failure_reason, "Unable to obtain a valid code review for the current source.")
        self.assertEqual(result.diagnostics[1].review_attempts, 0)
        self.assertEqual(result.diagnostics[2].review_attempts, 4)
        self.assertTrue(result.diagnostics[2].review_transport_failed)
        self.assertEqual((router.groq_calls, router.local_calls), (3, 2))

    def test_debug_has_no_provider_record_or_new_verdict_for_identical_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "authoring-debug"
            service, _coder, _router, _reviewer = service_with(
                [source_response(), repair_response(), repair_response(COMPLETE), TESTS],
                [initial_review(), followup()], debug_root=root,
            )
            with patch.dict(os.environ, {"JARVIS_SKILL_AUTHORING_DEBUG": "true"}):
                result = service.author(SkillAuthoringRequest(REQUEST))
            self.assertTrue(result.success)
            session = next(root.iterdir())
            diagnostics = [json.loads(line) for line in (session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()]
            skipped = diagnostics[1]
            self.assertEqual(skipped["review_attempts"], 0)
            self.assertEqual(skipped["review_skipped_reason"], "unchanged_source")
            self.assertIsNone(skipped["review_approved"])
            self.assertEqual(skipped["repair_blocker_ids"], ["B1", "B2"])
            records = [json.loads(line) for line in (session / "reviewer_responses.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual([record["authoring_iteration"] for record in records], [1, 3])
            message = service._format_diagnostic(result.diagnostics[1])
            self.assertIn("reviewer=none", message)
            self.assertIn("review_skipped_reason=unchanged_source", message)

    def test_historical_four_to_one_to_zero_with_value_return_enters_tests(self) -> None:
        from jarvis.core.llm_output_normalizer import AuthoringPhase, normalize_authoring_output

        fixture_path = Path(__file__).parent / "fixtures" / "source_repairs_4_to_1_to_0_20261003.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        responses = []
        for index, response in enumerate(fixture["source_responses"]):
            phase = AuthoringPhase.SOURCE_INITIAL if index == 0 else AuthoringPhase.SOURCE_REPAIR
            normalized = normalize_authoring_output(response, phase=phase)
            tree = ast.parse(normalized.source_code)
            entry = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "ejecutar_skill")
            # The historical sources only printed. Keep the raw fixture intact;
            # give these acceptance-plan test candidates the required value return.
            entry.body.append(ast.Return(value=ast.Constant("Ollama check completed.")))
            responses.append(response.replace(normalized.source_code, ast.unparse(tree), 1))
        service, coder, router, reviewer = service_with(
            [*responses,
             "<JARVIS_TESTS>\ndef test_entrypoint():\n    assert callable(ejecutar_skill)\n</JARVIS_TESTS>"],
            fixture["groq_responses"],
            local=fixture["local_responses"],
        )
        result = service.author(SkillAuthoringRequest(
            "Return a summary and preserve the values from earlier queries."
        ))
        self.assertTrue(result.success)
        self.assertEqual([item.blocking_unresolved for item in result.diagnostics[:3]], [4, 1, 0])
        self.assertEqual([item.source_repair_count for item in result.diagnostics[:3]], [0, 1, 2])
        self.assertTrue(all(item.source_changed for item in result.diagnostics[:3]))
        self.assertEqual(len(reviewer.requests), 3)
        self.assertEqual((router.groq_calls, router.local_calls), (3, 1))
        self.assertIn("Produce TESTS only.", coder.prompts[-1])


if __name__ == "__main__":
    unittest.main()
