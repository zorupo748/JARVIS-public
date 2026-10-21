from __future__ import annotations

import json
import unittest

from jarvis.core.llm_output_normalizer import (
    AuthoringPhase,
    NormalizedOutputKind,
    normalize_authoring_output,
)


def source_response(*, prefix: str = "", suffix: str = "") -> str:
    metadata = {
        "skill_name": "demo_skill",
        "implementation_summary": "Demonstrates normalization.",
        "dependencies": [],
    }
    return (
        prefix
        + "<JARVIS_META>\n"
        + json.dumps(metadata)
        + "\n</JARVIS_META>\n<JARVIS_SOURCE>\n"
        + "def ejecutar_skill():\n    return 'ok'\n"
        + "</JARVIS_SOURCE>"
        + suffix
    )


class LlmOutputNormalizerTests(unittest.TestCase):
    def test_source_tags_do_not_require_tests(self) -> None:
        result = normalize_authoring_output(
            source_response(),
            phase=AuthoringPhase.SOURCE,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.kind, NormalizedOutputKind.SOURCE_PROPOSAL)
        self.assertIsNone(result.tests_source)

    def test_source_markdown_json_and_python_are_recovered(self) -> None:
        fence = chr(96) * 3
        result = normalize_authoring_output(
            fence
            + "json\n"
            + json.dumps(
                {
                    "skill_name": "demo_skill",
                    "implementation_summary": "Summary.",
                    "dependencies": [],
                }
            )
            + "\n"
            + fence
            + "\n"
            + fence
            + "python\n"
            + "def ejecutar_skill():\n    return 1\n"
            + fence,
            phase=AuthoringPhase.SOURCE,
        )
        self.assertEqual(result.kind, NormalizedOutputKind.SOURCE_PROPOSAL)
        self.assertIn("return 1", result.source_code or "")

    def test_source_allows_outer_prose(self) -> None:
        result = normalize_authoring_output(
            source_response(prefix="Optional prose.\n", suffix="\nMore prose."),
            phase=AuthoringPhase.SOURCE,
        )
        self.assertTrue(result.success)

    def test_source_truncation_is_not_repaired(self) -> None:
        result = normalize_authoring_output(
            "<JARVIS_META>{",
            phase=AuthoringPhase.SOURCE,
        )
        self.assertEqual(result.kind, NormalizedOutputKind.TRUNCATED)
        self.assertTrue(result.truncated)
        self.assertIsNone(result.source_code)

    def test_review_json_is_not_treated_as_source(self) -> None:
        result = normalize_authoring_output(
            '<JARVIS_DATA>{"approved": false, "issues": []}</JARVIS_DATA>',
            phase=AuthoringPhase.SOURCE,
        )
        self.assertEqual(result.kind, NormalizedOutputKind.REVIEW_RESULT)
        self.assertFalse(result.success)

    def test_validation_report_is_not_treated_as_source(self) -> None:
        result = normalize_authoring_output(
            '{"success": false, "checks": [], "timed_out": false}',
            phase=AuthoringPhase.SOURCE,
        )
        self.assertEqual(result.kind, NormalizedOutputKind.VALIDATION_REPORT)

    def test_tests_phase_accepts_literal_tag(self) -> None:
        result = normalize_authoring_output(
            "<JARVIS_TESTS>\ndef test_ok():\n    assert True\n</JARVIS_TESTS>",
            phase=AuthoringPhase.TESTS,
        )
        self.assertEqual(result.kind, NormalizedOutputKind.TESTS)
        self.assertIn("test_ok", result.tests_source or "")

    def test_tests_phase_accepts_python_fence_only_in_tests_phase(self) -> None:
        fence = chr(96) * 3
        raw = fence + "python\ndef test_ok():\n    assert True\n" + fence
        tests = normalize_authoring_output(raw, phase=AuthoringPhase.TESTS)
        source = normalize_authoring_output(raw, phase=AuthoringPhase.SOURCE)
        self.assertEqual(tests.kind, NormalizedOutputKind.TESTS)
        self.assertNotEqual(source.kind, NormalizedOutputKind.SOURCE_PROPOSAL)

    def test_normalizer_does_not_invent_missing_source(self) -> None:
        result = normalize_authoring_output(
            "<JARVIS_META>{\"skill_name\":\"demo_skill\"}</JARVIS_META>",
            phase=AuthoringPhase.SOURCE,
        )
        self.assertFalse(result.success)
        self.assertIsNone(result.source_code)

    def test_legacy_complete_source_remains_recoverable(self) -> None:
        payload = {
            "skill_name": "demo_skill",
            "implementation_summary": "Summary.",
            "dependencies": [],
            "source_code": "def ejecutar_skill():\n    return 'legacy'\n",
            "tests_source": None,
        }
        result = normalize_authoring_output(
            "<JARVIS_DATA>" + json.dumps(payload) + "</JARVIS_DATA>",
            phase=AuthoringPhase.SOURCE,
        )
        self.assertEqual(result.kind, NormalizedOutputKind.SOURCE_PROPOSAL)
        self.assertIn("legacy", result.source_code or "")


class SourceRepairNormalizerTests(unittest.TestCase):
    def test_initial_source_builds_missing_metadata(self) -> None:
        result = normalize_authoring_output(
            "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'ok'\n</JARVIS_SOURCE>",
            phase=AuthoringPhase.SOURCE_INITIAL,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.metadata["dependencies"], [])
        self.assertTrue(result.structurally_recovered)

    def test_repair_accepts_tagged_source_without_metadata(self) -> None:
        source = "def ejecutar_skill():\n    return 'repaired'\n"
        result = normalize_authoring_output(
            "<JARVIS_SOURCE>\n" + source + "</JARVIS_SOURCE>",
            phase=AuthoringPhase.SOURCE_REPAIR,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.kind, NormalizedOutputKind.SOURCE_PROPOSAL)
        self.assertIsNone(result.metadata)
        self.assertEqual(result.source_code, source)

    def test_repair_accepts_one_python_fence_with_outer_prose(self) -> None:
        fence = chr(96) * 3
        source = "def ejecutar_skill():\n    return 'fenced'\n"
        result = normalize_authoring_output(
            "Explicacion exterior.\n" + fence + "python\n" + source + fence + "\nFin.",
            phase=AuthoringPhase.SOURCE_REPAIR,
        )
        self.assertTrue(result.success)
        self.assertEqual(result.extraction_method, "markdown_python_source_repair")
        self.assertEqual(result.source_code, source)

    def test_repair_accepts_metadata_before_or_after_python_fence(self) -> None:
        fence = chr(96) * 3
        metadata = json.dumps(
            {
                "skill_name": "demo_skill",
                "implementation_summary": "Summary.",
                "dependencies": [],
            }
        )
        raw = fence + "python\ndef ejecutar_skill():\n    return 1\n" + fence + "\n" + fence + "json\n" + metadata + "\n" + fence
        result = normalize_authoring_output(raw, phase=AuthoringPhase.SOURCE_REPAIR)
        self.assertTrue(result.success)
        self.assertEqual(result.metadata, json.loads(metadata))


if __name__ == "__main__":
    unittest.main()
