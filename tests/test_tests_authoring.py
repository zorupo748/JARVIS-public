from __future__ import annotations

import json
import unittest
from pathlib import Path

from jarvis.core.authoring_two_phase import build_tests_prompt
from jarvis.core.code_reviewer import CodeReviewResult
from jarvis.core.llm_output_normalizer import (
    AuthoringPhase,
    NormalizedOutputKind,
    normalize_authoring_output,
)
from jarvis.core.safe_skill_authoring import (
    GeneratedSkillProposal,
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
)


SOURCE = "def ejecutar_skill():\n    return 'approved'\n"
TESTS = "def test_requested_result():\n    assert ejecutar_skill() == 'approved'\n"
FENCE = chr(96) * 3
FIXTURE = Path(__file__).parent / "fixtures" / "authoring_tests_truncated_20261003.json"


def real_responses() -> list[dict[str, object]]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def tagged_tests(source: str = TESTS) -> str:
    return "<JARVIS_TESTS>\n" + source + "</JARVIS_TESTS>"


def normalize(raw: str):
    return normalize_authoring_output(raw, phase=AuthoringPhase.TESTS)


class Coder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            raise AssertionError("Unexpected coder call.")
        return self.responses.pop(0)


class Reviewer:
    def __init__(self) -> None:
        self.calls = 0

    def review(self, _request):
        self.calls += 1
        return CodeReviewResult(
            approved=True, issues=(), reviewer_used="fake",
            cloud_attempted=False, cloud_failed=False,
        )


def service_with(test_responses: list[str]):
    metadata = json.dumps({
        "skill_name": "approved_skill", "implementation_summary": "Return requested value.",
        "dependencies": [],
    })
    initial = f"<JARVIS_META>{metadata}</JARVIS_META><JARVIS_SOURCE>\n{SOURCE}</JARVIS_SOURCE>"
    coder = Coder([initial, *test_responses])
    reviewer = Reviewer()
    service = SafeSkillAuthoringService(
        coder, reviewer=reviewer, max_seconds=60,
        diagnostic_sink=lambda _message: None,
    )
    return service, coder, reviewer


class TestsResponseNormalizerTests(unittest.TestCase):
    def test_each_exact_real_response_is_truncated_and_never_repaired(self) -> None:
        lengths = {7: 3789, 8: 3952, 9: 4059, 10: 3727, 11: 3636}
        endings = {
            7: "with patch('oll",
            8: "'body': 'New features and bug fixes.'\n",
            9: "mock_get.return",
            10: 'if __name__ == "__main',
            11: "return_value=('v1.2.3', '2023-04-01T12:34:56Z', '",
        }
        for record in real_responses():
            iteration, raw = record["iteration"], record["raw_response"]
            with self.subTest(iteration=iteration):
                self.assertEqual(len(raw), lengths[iteration])
                self.assertTrue(raw.endswith(endings[iteration]))
                self.assertTrue(raw.startswith(FENCE + "python\n<JARVIS_TESTS>\n"))
                self.assertNotIn("</JARVIS_TESTS>", raw)
                self.assertEqual(raw.count(FENCE), 1)
                self.assertNotIn("<JARVIS_SOURCE>", raw)
                self.assertNotIn("<JARVIS_META>", raw)
                result = normalize(raw)
                self.assertEqual(result.kind, NormalizedOutputKind.TRUNCATED)
                self.assertEqual(result.error, "unclosed JARVIS_TESTS")
                self.assertTrue(result.truncated)
                self.assertFalse(result.success)
                self.assertIsNone(result.tests_source)
                self.assertIsNone(result.source_code)

    def test_closed_tests_tag_is_accepted_verbatim(self) -> None:
        result = normalize(tagged_tests())
        self.assertTrue(result.success)
        self.assertEqual(result.tests_source, TESTS)

    def test_single_closed_python_fence_is_accepted_verbatim(self) -> None:
        result = normalize(FENCE + "python\n" + TESTS + FENCE)
        self.assertTrue(result.success)
        self.assertEqual(result.tests_source, TESTS)

    def test_complete_fence_around_complete_tests_tag_is_innocuous(self) -> None:
        result = normalize(FENCE + "python\n" + tagged_tests() + "\n" + FENCE)
        self.assertTrue(result.success)
        self.assertEqual(result.tests_source, TESTS)
        self.assertEqual(result.extraction_method, "jarvis_tests")

    def test_incomplete_outer_fence_is_not_reconstructed(self) -> None:
        result = normalize(FENCE + "python\n" + tagged_tests())
        self.assertFalse(result.success)
        self.assertTrue(result.truncated)
        self.assertEqual(result.error, "unclosed Markdown fence")

    def test_source_or_metadata_contract_is_not_tests_even_in_a_python_fence(self) -> None:
        for contract in (
            "<JARVIS_SOURCE>\n" + SOURCE + "</JARVIS_SOURCE>",
            '<JARVIS_META>{"skill_name":"wrong_phase"}</JARVIS_META>',
            '<JARVIS_DATA>{"source_code":"wrong_phase"}</JARVIS_DATA>',
        ):
            for raw in (contract, FENCE + "python\n" + contract + "\n" + FENCE):
                with self.subTest(raw=raw):
                    self.assertFalse(normalize(raw).success)
                    self.assertIsNone(normalize(raw).tests_source)

    def test_valid_tests_tag_keeps_priority_over_additional_closed_source(self) -> None:
        raw = "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'drift'\n</JARVIS_SOURCE>" + tagged_tests()
        result = normalize(raw)
        self.assertTrue(result.success)
        self.assertEqual(result.tests_source, TESTS)
        self.assertIsNone(result.source_code)

    def test_review_json_is_rejected(self) -> None:
        for payload in ({"approved": True, "issues": []},
                        {"approved": True, "blocking_issues": [], "advisory_issues": []}):
            with self.subTest(payload=payload):
                self.assertFalse(normalize(json.dumps(payload)).success)

    def test_validation_json_is_rejected(self) -> None:
        result = normalize('{"success":true,"checks":[],"timed_out":false}')
        self.assertFalse(result.success)
        self.assertEqual(result.kind, NormalizedOutputKind.VALIDATION_REPORT)

    def test_multiple_python_fences_are_ambiguous(self) -> None:
        raw = (FENCE + "python\n" + TESTS + FENCE + "\n") * 2
        result = normalize(raw)
        self.assertFalse(result.success)
        self.assertEqual(result.error, "ambiguous Python fences in tests")

    def test_multiple_tests_tags_are_ambiguous(self) -> None:
        result = normalize(tagged_tests() + tagged_tests())
        self.assertFalse(result.success)
        self.assertEqual(result.error, "ambiguous JARVIS_TESTS blocks")

    def test_plain_python_requires_complete_unambiguous_tests(self) -> None:
        self.assertTrue(normalize(TESTS).success)
        for raw in ("def test_cut_off():\n    assert (", 'print("unrelated")',
                    "Here are the tests for the skill."):
            with self.subTest(raw=raw):
                self.assertFalse(normalize(raw).success)
                self.assertIsNone(normalize(raw).tests_source)

    def test_normalization_never_executes_candidate_python(self) -> None:
        source = "raise RuntimeError('normalization must not execute this')\n" + TESTS
        result = normalize(tagged_tests(source))
        self.assertTrue(result.success)
        self.assertEqual(result.tests_source, source)


class TestsAuthoringTests(unittest.TestCase):
    def test_five_real_structural_failures_still_abort_defensively(self) -> None:
        service, coder, reviewer = service_with([record["raw_response"] for record in real_responses()])
        result = service.author(SkillAuthoringRequest("Return the requested value."))
        self.assertFalse(result.success)
        self.assertEqual(result.failure_reason,
                         "Tests authoring aborted after 5 consecutive structural response failures without a valid phase payload.")
        diagnostics = [item for item in result.diagnostics if item.phase == "tests"]
        self.assertEqual([item.structural_retries for item in diagnostics], [1, 2, 3, 4, 5])
        self.assertEqual([item.rescue_triggered for item in diagnostics], [False, False, True, False, False])
        self.assertTrue(all(item.truncated for item in diagnostics))
        self.assertTrue(all(item.source_hash == service._source_hash(SOURCE) for item in diagnostics))
        self.assertEqual(reviewer.calls, 1)
        self.assertEqual(len(coder.prompts), 6)

    def test_rescue_after_third_failure_reaches_next_prompt_and_valid_tests_continue(self) -> None:
        responses = [record["raw_response"] for record in real_responses()[:3]]
        service, coder, reviewer = service_with([*responses, tagged_tests()])
        result = service.author(SkillAuthoringRequest("Return the requested value."))
        self.assertTrue(result.success)
        test_prompts = coder.prompts[1:]
        self.assertTrue(all("TESTS-ONLY FORMAT RESCUE" not in prompt for prompt in test_prompts[:3]))
        self.assertIn("TESTS-ONLY FORMAT RESCUE", test_prompts[3])
        self.assertIn("Detected format error: unclosed JARVIS_TESTS", test_prompts[3])
        self.assertIn("at most 2 compact tests", test_prompts[3])
        self.assertIn("do not continue or reconstruct", test_prompts[3])
        self.assertEqual(result.proposal.source_code, SOURCE)
        self.assertEqual(result.proposal.tests_source, TESTS)
        self.assertEqual(reviewer.calls, 1)
        self.assertTrue(result.validation_reports[-1].success)
        self.assertEqual(result.diagnostics[-1].structural_retries, 0)

    def test_invalid_python_after_rescue_still_requires_tests_validation_and_repair(self) -> None:
        responses = [record["raw_response"] for record in real_responses()[:3]]
        service, coder, reviewer = service_with([
            *responses, tagged_tests("def broken(:\n"), tagged_tests(),
        ])
        result = service.author(SkillAuthoringRequest("Return the requested value."))
        self.assertTrue(result.success)
        self.assertFalse(result.validation_reports[-2].success)
        self.assertTrue(result.validation_reports[-1].success)
        self.assertIn("AST parse failed", coder.prompts[-1])
        self.assertEqual(result.proposal.source_code, SOURCE)
        self.assertEqual(reviewer.calls, 1)

    def test_extra_source_in_tests_response_cannot_replace_approved_source(self) -> None:
        raw = "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'drift'\n</JARVIS_SOURCE>" + tagged_tests()
        service, _coder, reviewer = service_with([raw])
        result = service.author(SkillAuthoringRequest("Return the requested value."))
        self.assertTrue(result.success)
        self.assertEqual(result.proposal.source_code, SOURCE)
        self.assertEqual(result.proposal.tests_source, TESTS)
        self.assertEqual(reviewer.calls, 1)

    def test_tagged_or_fenced_tests_still_pass_static_validation(self) -> None:
        for raw in (tagged_tests(), FENCE + "python\n" + TESTS + FENCE,
                    FENCE + "python\n" + tagged_tests() + "\n" + FENCE):
            service, _coder, _reviewer = service_with([raw])
            with self.subTest(raw=raw):
                result = service.author(SkillAuthoringRequest("Return the requested value."))
                self.assertTrue(result.success)
                self.assertTrue(result.validation_reports[-1].success)
                self.assertEqual(result.proposal.source_code, SOURCE)

    def test_prompt_has_complete_python_example_and_explicit_compact_tests_contract(self) -> None:
        service, _coder, _reviewer = service_with([])
        prompt = build_tests_prompt(
            service, SkillAuthoringRequest("Return the requested value."),
            approved_source=GeneratedSkillProposal("approved_skill", SOURCE, "Return value."),
            iteration=7, previous_tests=None, previous_validation=None, rescue_diagnostic=None,
        )
        self.assertNotIn("Python tests for the immutable approved source", prompt)
        self.assertIn("Do not use Markdown or code fences", prompt)
        self.assertIn("Do not explain", prompt)
        self.assertIn("Do not return metadata, source, JSON", prompt)
        self.assertIn("at most 3 focused tests", prompt)
        self.assertIn("immutable", prompt)
        self.assertIn("<JARVIS_TESTS>...</JARVIS_TESTS>", prompt)
        example = prompt.split("<JARVIS_TESTS>\n", 1)[1].split("</JARVIS_TESTS>", 1)[0]
        self.assertIn("def test_", example)
        self.assertIn("assert callable(ejecutar_skill)", example)
        compile(example, "<prompt_example>", "exec")


if __name__ == "__main__":
    unittest.main()
