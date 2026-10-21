from __future__ import annotations

import json
import unittest

from jarvis.core.code_reviewer import CodeReviewResult, ReviewIssue, ReviewSeverity
from jarvis.core.llm_output_normalizer import (
    AuthoringPhase,
    NormalizedOutputKind,
    normalize_authoring_output,
)
from jarvis.core.safe_skill_authoring import (
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
)


def initial_source(
    *,
    name: str = "frozen_skill",
    summary: str = "Frozen metadata.",
    dependencies: list[str] | None = None,
    source: str = "def ejecutar_skill():\n    return 'initial'\n",
) -> str:
    return (
        "<JARVIS_META>\n"
        + json.dumps(
            {
                "skill_name": name,
                "implementation_summary": summary,
                "dependencies": dependencies or [],
            }
        )
        + "\n</JARVIS_META>\n<JARVIS_SOURCE>\n"
        + source
        + "</JARVIS_SOURCE>"
    )


def tests_payload() -> str:
    return "<JARVIS_TESTS>\ndef test_skill():\n    assert True\n</JARVIS_TESTS>"


class FakeCoder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.responses.pop(0)


class FakeReviewer:
    def __init__(self, results: list[CodeReviewResult]) -> None:
        self.results = list(results)

    def review(self, _request: object) -> CodeReviewResult:
        return self.results.pop(0)


def approved() -> CodeReviewResult:
    return CodeReviewResult(
        approved=True,
        issues=(),
        reviewer_used="fake",
        cloud_attempted=False,
        cloud_failed=False,
    )


def rejected() -> CodeReviewResult:
    return CodeReviewResult(
        approved=False,
        issues=(
            ReviewIssue(
                severity=ReviewSeverity.HIGH,
                description="Semantic repair needed.",
            ),
        ),
        reviewer_used="fake",
        cloud_attempted=False,
        cloud_failed=False,
    )


class SourceRepairMetadataTests(unittest.TestCase):
    def test_initial_source_builds_metadata_but_repair_reuses_frozen_metadata(self) -> None:
        raw = "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'ok'\n</JARVIS_SOURCE>"
        initial = normalize_authoring_output(raw, phase=AuthoringPhase.SOURCE_INITIAL)
        repair = normalize_authoring_output(raw, phase=AuthoringPhase.SOURCE_REPAIR)
        self.assertTrue(initial.success)
        self.assertIsInstance(initial.metadata, dict)
        self.assertTrue(repair.success)
        self.assertEqual(repair.kind, NormalizedOutputKind.SOURCE_PROPOSAL)
        self.assertIsNone(repair.metadata)

    def test_source_repair_accepts_tagged_and_fenced_python_with_prose(self) -> None:
        tagged = normalize_authoring_output(
            "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'tagged'\n</JARVIS_SOURCE>",
            phase=AuthoringPhase.SOURCE_REPAIR,
        )
        fence = chr(96) * 3
        fenced = normalize_authoring_output(
            "Outer prose.\n"
            + fence
            + "python\ndef ejecutar_skill():\n    return 'fenced'\n"
            + fence
            + "\nTrailing prose.",
            phase=AuthoringPhase.SOURCE_REPAIR,
        )
        self.assertEqual(tagged.source_code, "def ejecutar_skill():\n    return 'tagged'\n")
        self.assertEqual(fenced.extraction_method, "markdown_python_source_repair")
        self.assertIn("fenced", fenced.source_code or "")

    def test_frozen_metadata_is_reused_and_source_only_reaches_validation(self) -> None:
        repair = "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'fixed'\n</JARVIS_SOURCE>"
        coder = FakeCoder([initial_source(), repair, tests_payload()])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=FakeReviewer([rejected(), approved()]),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest("Create the requested skill."))
        self.assertTrue(result.success)
        self.assertEqual(result.proposal.skill_name if result.proposal else None, "frozen_skill")
        self.assertEqual(result.proposal.dependencies if result.proposal else None, ())
        self.assertIn("fixed", result.proposal.source_code if result.proposal else "")
        repair_diagnostic = result.diagnostics[1]
        self.assertEqual(repair_diagnostic.phase, "source_repair")
        self.assertTrue(repair_diagnostic.metadata_reused)
        self.assertIsNotNone(repair_diagnostic.source_hash)
        self.assertIn("Do NOT regenerate metadata", coder.prompts[1])
        self.assertNotIn("<JARVIS_TESTS>", coder.prompts[1])

    def test_changed_repair_metadata_is_ignored_and_identical_is_accepted(self) -> None:
        changed = initial_source(
            name="different_skill",
            summary="Changed summary.",
            dependencies=["different-package"],
            source="def ejecutar_skill():\n    return 'changed'\n",
        )
        coder = FakeCoder([initial_source(), changed, tests_payload()])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=FakeReviewer([rejected(), approved()]),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest("Create the requested skill."))
        self.assertTrue(result.success)
        self.assertEqual(result.proposal.skill_name if result.proposal else None, "frozen_skill")
        self.assertEqual(result.proposal.implementation_summary if result.proposal else None, "Frozen metadata.")
        self.assertEqual(result.proposal.dependencies if result.proposal else None, ())
        self.assertTrue(result.diagnostics[1].metadata_change_ignored)
        self.assertFalse(result.diagnostics[1].metadata_reused)

    def test_source_repair_does_not_change_tests_or_trigger_tests_early(self) -> None:
        repair = (
            "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'fixed'\n</JARVIS_SOURCE>"
            "\n<JARVIS_TESTS>\ndef test_untrusted():\n    assert False\n</JARVIS_TESTS>"
        )
        expected_tests = "<JARVIS_TESTS>\ndef test_final():\n    assert True\n</JARVIS_TESTS>"
        coder = FakeCoder([initial_source(), repair, expected_tests])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=FakeReviewer([rejected(), approved()]),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest("Create the requested skill."))
        self.assertTrue(result.success)
        self.assertEqual(
            result.proposal.tests_source if result.proposal else None,
            "def test_final():\n    assert True\n",
        )
        self.assertEqual(len([prompt for prompt in coder.prompts if "Produce TESTS only." in prompt]), 1)


if __name__ == "__main__":
    unittest.main()
