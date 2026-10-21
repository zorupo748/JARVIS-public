from __future__ import annotations

import json
import unittest

from jarvis.core.safe_skill_authoring import (
    SkillProposalParseError,
    parse_generated_skill_proposal,
)
from jarvis.core.structured_response import (
    CodeProposalExtractionMethod,
    ExtractionMethod,
    extract_structured_code_proposal,
    extract_structured_response,
)


def metadata() -> dict[str, object]:
    return {
        "skill_name": "demo_skill",
        "implementation_summary": "A safe demonstration.",
        "dependencies": [],
    }


def legacy_payload() -> dict[str, object]:
    return {
        **metadata(),
        "source_code": "def ejecutar_skill():\n    return 'ok'\n",
        "tests_source": None,
    }


def code_protocol(
    *,
    meta: object | None = None,
    source: str | None = "def ejecutar_skill():\n    return 'ok'\n",
    tests: str | None = "",
    prefix: str = "",
    suffix: str = "",
) -> str:
    meta_payload = json.dumps(metadata() if meta is None else meta)
    response = f"{prefix}<JARVIS_META>\n{meta_payload}\n</JARVIS_META>\n"
    if source is not None:
        response += f"<JARVIS_SOURCE>\n{source}</JARVIS_SOURCE>\n"
    if tests is not None:
        response += f"<JARVIS_TESTS>\n{tests}</JARVIS_TESTS>\n"
    return response + suffix


_NL = chr(10)


def markdown_code_proposal(
    *,
    meta: object | None = None,
    source: str | None = None,
    prefix: str = "",
    suffix: str = "",
) -> str:
    if source is None:
        source = "def ejecutar_skill():" + _NL + "    return 'ok'" + _NL
    fence = chr(96) * 3
    meta_payload = json.dumps(metadata() if meta is None else meta)
    return (
        f"{prefix}{fence}json{_NL}{meta_payload}{_NL}{fence}{_NL}"
        f"{fence}python{_NL}{source}{fence}{_NL}{suffix}"
    )


class StructuredResponseTests(unittest.TestCase):
    def test_clean_json_uses_balanced_fallback(self) -> None:
        result = extract_structured_response(json.dumps({"value": 1}))
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"value": 1})
        self.assertEqual(result.extraction_method, ExtractionMethod.BALANCED_JSON)

    def test_text_before_and_after_json_data_is_ignored(self) -> None:
        result = extract_structured_response(
            "Introduccion." + _NL + '<JARVIS_DATA>{"value": 1}</JARVIS_DATA>' + _NL + "Conclusion."
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"value": 1})
        self.assertEqual(result.extraction_method, ExtractionMethod.JARVIS_DATA)

    def test_markdown_json_is_a_fallback(self) -> None:
        fence = chr(96) * 3
        result = extract_structured_response(
            "Texto" + _NL + fence + "json" + _NL + json.dumps({"value": 1}) + _NL + fence + _NL + "Mas texto"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"value": 1})
        self.assertEqual(result.extraction_method, ExtractionMethod.MARKDOWN_JSON)

    def test_balanced_scanner_handles_braces_and_escaped_quotes(self) -> None:
        payload = {"message": "A quoted value: \"hello\" and braces { }"}
        result = extract_structured_response(json.dumps(payload))
        self.assertTrue(result.success)
        self.assertEqual(result.data, payload)

    def test_meta_source_tests_protocol_is_preferred(self) -> None:
        result = extract_structured_code_proposal(code_protocol())
        self.assertTrue(result.success)
        self.assertEqual(result.metadata, metadata())
        self.assertEqual(result.source_code, "def ejecutar_skill():" + _NL + "    return 'ok'" + _NL)
        self.assertIsNone(result.tests_source)
        self.assertEqual(
            result.extraction_method,
            CodeProposalExtractionMethod.META_SOURCE_TESTS,
        )

    def test_source_multiline_is_literal(self) -> None:
        source = "def ejecutar_skill():" + _NL + "    value = 1" + _NL + "    return value" + _NL
        result = extract_structured_code_proposal(code_protocol(source=source))
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, source)

    def test_source_with_triple_quotes_is_literal(self) -> None:
        source = 'def ejecutar_skill():' + _NL + '    return """line one' + _NL + 'line two"""' + _NL
        result = extract_structured_code_proposal(code_protocol(source=source))
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, source)

    def test_source_with_inner_json_and_braces_is_literal(self) -> None:
        source = (
            "def ejecutar_skill():" + _NL
            + '    payload = {"status": "ok", "template": "{{value}}"}' + _NL
            + "    return payload" + _NL
        )
        result = extract_structured_code_proposal(code_protocol(source=source))
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, source)

    def test_empty_tests_block_becomes_none(self) -> None:
        result = extract_structured_code_proposal(code_protocol(tests=""))
        self.assertTrue(result.success)
        self.assertIsNone(result.tests_source)

    def test_present_tests_block_is_literal(self) -> None:
        tests = "def test_skill():" + _NL + "    assert True" + _NL
        result = extract_structured_code_proposal(code_protocol(tests=tests))
        self.assertTrue(result.success)
        self.assertEqual(result.tests_source, tests)

    def test_outer_text_is_ignored_for_code_protocol(self) -> None:
        result = extract_structured_code_proposal(
            code_protocol(prefix="Claro, aqui tienes." + _NL, suffix="Explicacion final." + _NL)
        )
        self.assertTrue(result.success)
        self.assertEqual(result.metadata, metadata())

    def test_tags_are_preferred_over_markdown_code_proposal(self) -> None:
        markdown = markdown_code_proposal(
            source="def ejecutar_skill():" + _NL + "    return 'markdown'" + _NL
        )
        tagged_source = "def ejecutar_skill():" + _NL + "    return 'tagged'" + _NL
        result = extract_structured_code_proposal(
            markdown + _NL + code_protocol(source=tagged_source)
        )
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, tagged_source)
        self.assertEqual(
            result.extraction_method,
            CodeProposalExtractionMethod.META_SOURCE_TESTS,
        )

    def test_markdown_json_and_python_fences_are_recovered(self) -> None:
        result = extract_structured_code_proposal(markdown_code_proposal())
        self.assertTrue(result.success)
        self.assertEqual(result.metadata, metadata())
        self.assertEqual(
            result.extraction_method,
            CodeProposalExtractionMethod.MARKDOWN_CODE_PROPOSAL,
        )
        proposal = parse_generated_skill_proposal(
            markdown_code_proposal(),
            iteration=1,
        )
        self.assertEqual(proposal.skill_name, "demo_skill")

    def test_markdown_python_source_is_literal_and_tests_marker_splits(self) -> None:
        source = (
            "def ejecutar_skill():" + _NL
            + '    payload = {"answer": 42}' + _NL
            + "    return payload" + _NL
            + "   # JARVIS_TESTS   " + _NL
            + "def test_skill():" + _NL
            + "    assert True" + _NL
        )
        result = extract_structured_code_proposal(
            markdown_code_proposal(source=source)
        )
        expected_source = (
            "def ejecutar_skill():" + _NL
            + '    payload = {"answer": 42}' + _NL
            + "    return payload" + _NL
        )
        expected_tests = "def test_skill():" + _NL + "    assert True" + _NL
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, expected_source)
        self.assertEqual(result.tests_source, expected_tests)

    def test_marker_inside_python_string_does_not_split_markdown_source(self) -> None:
        source = (
            "def ejecutar_skill():" + _NL
            + '    return "# JARVIS_TESTS"' + _NL
        )
        result = extract_structured_code_proposal(
            markdown_code_proposal(source=source)
        )
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, source)
        self.assertIsNone(result.tests_source)

    def test_markdown_without_tests_marker_has_no_tests_source(self) -> None:
        source = "def ejecutar_skill():" + _NL + "    return 'source only'" + _NL
        result = extract_structured_code_proposal(
            markdown_code_proposal(
                source=source,
                prefix="Optional prose before." + _NL,
                suffix="Optional prose after." + _NL,
            )
        )
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, source)
        self.assertIsNone(result.tests_source)

    def test_incomplete_markdown_metadata_and_missing_python_fail_closed(self) -> None:
        fence = chr(96) * 3
        incomplete = {
            "skill_name": "demo_skill",
            "implementation_summary": "missing dependencies",
        }
        incomplete_response = (
            fence + "json" + _NL + json.dumps(incomplete) + _NL + fence + _NL
            + fence + "python" + _NL + "pass" + _NL + fence
        )
        missing_python_response = (
            fence + "json" + _NL + json.dumps(metadata()) + _NL + fence
        )
        for name, raw_response in (
            ("incomplete", incomplete_response),
            ("missing_python", missing_python_response),
        ):
            with self.subTest(name=name):
                result = extract_structured_code_proposal(raw_response)
                self.assertFalse(result.success)
    def test_invalid_metadata_fails(self) -> None:
        response = (
            "<JARVIS_META>{invalid json}</JARVIS_META>\n"
            "<JARVIS_SOURCE>def ejecutar_skill():\n    pass\n</JARVIS_SOURCE>"
        )
        result = extract_structured_code_proposal(response)
        self.assertFalse(result.success)
        self.assertEqual(result.error, "invalid JARVIS_META JSON")

    def test_safe_structural_errors_are_specific_and_closed(self) -> None:
        meta_payload = json.dumps(metadata())
        cases = {
            "empty": ("   ", "empty model response"),
            "missing meta": (
                "<JARVIS_SOURCE>pass</JARVIS_SOURCE>",
                "missing JARVIS_META",
            ),
            "missing source": (
                f"<JARVIS_META>{meta_payload}</JARVIS_META>",
                "missing JARVIS_SOURCE",
            ),
            "unclosed meta": ("<JARVIS_META>{", "unclosed JARVIS_META"),
            "unclosed source": (
                f"<JARVIS_META>{meta_payload}</JARVIS_META><JARVIS_SOURCE>pass",
                "unclosed JARVIS_SOURCE",
            ),
            "unclosed tests": (
                f"<JARVIS_META>{meta_payload}</JARVIS_META>"
                "<JARVIS_SOURCE>pass</JARVIS_SOURCE><JARVIS_TESTS>pass",
                "unclosed JARVIS_TESTS",
            ),
            "invalid legacy": ("<JARVIS_DATA>{bad}</JARVIS_DATA>", "legacy JARVIS_DATA invalid"),
            "unknown": ("ordinary prose only", "unknown structured response format"),
        }
        for name, (raw_response, expected_error) in cases.items():
            with self.subTest(name=name):
                result = extract_structured_code_proposal(raw_response)
                self.assertFalse(result.success)
                self.assertEqual(result.structural_error, expected_error)
                self.assertEqual(result.error, expected_error)
    def test_missing_source_fails(self) -> None:
        result = extract_structured_code_proposal(code_protocol(source=None))
        self.assertFalse(result.success)
        self.assertIn("JARVIS_SOURCE", result.error or "")

    def test_legacy_jarvis_data_remains_readable(self) -> None:
        response = "<JARVIS_DATA>" + json.dumps(legacy_payload()) + "</JARVIS_DATA>"
        result = extract_structured_code_proposal(response)
        self.assertTrue(result.success)
        self.assertEqual(
            result.extraction_method,
            CodeProposalExtractionMethod.LEGACY_JARVIS_DATA,
        )
        proposal = parse_generated_skill_proposal(response, iteration=4)
        self.assertEqual(proposal.skill_name, "demo_skill")
        self.assertEqual(proposal.iteration, 4)

    def test_long_literal_source_needs_no_json_escaping(self) -> None:
        source = "def ejecutar_skill():\n" + "    value = value + 1\n" * 200
        response = code_protocol(source=source)
        self.assertIn(source, response)
        self.assertNotIn(json.dumps(source), response)
        proposal = parse_generated_skill_proposal(response, iteration=1)
        self.assertEqual(proposal.source_code, source)

    def test_missing_metadata_field_is_rejected_by_authoring_contract(self) -> None:
        incomplete = metadata()
        del incomplete["skill_name"]
        response = code_protocol(meta=incomplete)
        with self.assertRaises(SkillProposalParseError):
            parse_generated_skill_proposal(response, iteration=1)

    def test_wrong_metadata_type_is_rejected_by_authoring_contract(self) -> None:
        invalid = metadata()
        invalid["dependencies"] = "not-a-list"
        response = code_protocol(meta=invalid)
        with self.assertRaises(SkillProposalParseError):
            parse_generated_skill_proposal(response, iteration=1)

    def test_tagged_payload_has_priority_over_markdown(self) -> None:
        result = extract_structured_response(
            "```json\n{\"source\": \"markdown\"}\n```\n"
            "<JARVIS_DATA>{\"source\": \"tagged\"}</JARVIS_DATA>"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"source": "tagged"})

    def test_markdown_has_priority_over_balanced_fallback(self) -> None:
        result = extract_structured_response(
            "Before {\"source\": \"balanced\"}\n"
            "```json\n{\"source\": \"markdown\"}\n```"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.data, {"source": "markdown"})

    def test_invalid_json_and_absence_return_structured_failures(self) -> None:
        invalid = extract_structured_response("<JARVIS_DATA>{bad}</JARVIS_DATA>")
        absent = extract_structured_response("No structured content.")
        self.assertFalse(invalid.success)
        self.assertFalse(absent.success)
        self.assertEqual(absent.extraction_method, ExtractionMethod.NONE)


if __name__ == "__main__":
    unittest.main()