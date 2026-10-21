"""Synthetic transport regressions: no LLM calls and no candidate execution."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.core.authoring_two_phase import _source_proposal, _source_structural_rescue
from jarvis.core.code_reviewer import CodeReviewResult
from jarvis.core.code_validation import LocalCodeValidator
from jarvis.core.llm_output_normalizer import AuthoringPhase, normalize_authoring_output
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService, SkillAuthoringRequest


SOURCE = 'def ejecutar_skill(comando=""):\n    return "ok"\n'
TESTS = 'def test_result():\n    assert ejecutar_skill() == "ok"\n'
META = {"skill_name": "transport_demo", "implementation_summary": "Return a result.", "dependencies": []}


def fence(source: str, language: str = "python") -> str:
    return "```" + language + "\n" + source + "```"


def normalize(raw: str, phase=AuthoringPhase.SOURCE_INITIAL, request="Consult an external API."):
    return normalize_authoring_output(raw, phase=phase, user_request=request)


class AuthoringTransportTests(unittest.TestCase):
    def test_complete_legacy_contract(self):
        result = normalize("<JARVIS_META>" + json.dumps(META) + "</JARVIS_META><JARVIS_SOURCE>\n" + SOURCE + "</JARVIS_SOURCE>")
        self.assertTrue(result.success)
        self.assertEqual(result.metadata, META)
        self.assertFalse(result.structurally_recovered)

    def test_single_fence(self):
        result = normalize(fence(SOURCE))
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, SOURCE)
        self.assertEqual(result.extraction_method, "python_fence")
        self.assertTrue(result.structurally_recovered)

    def test_plain_source(self):
        result = normalize(SOURCE)
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, SOURCE)

    def test_transport_markers_inside_plain_python_strings_are_literal_data(self):
        source = 'def ejecutar_skill():\n    return "<JARVIS_META> ```python"\n'
        result = normalize(source)
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, source)

    def test_short_explanation_and_fence(self):
        self.assertTrue(normalize("Here is the implementation.\n" + fence(SOURCE) + "\nDone.").success)

    def test_metadata_and_fence(self):
        result = normalize(fence(json.dumps(META), "json") + "\n" + fence(SOURCE))
        self.assertEqual(result.metadata, META)

    def test_whitespace_tags_preserve_python(self):
        result = normalize("< JARVIS_META >" + json.dumps(META) + "< / JARVIS_META >\n< JARVIS_SOURCE >\n" + SOURCE + "< / JARVIS_SOURCE >")
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, SOURCE)

    def test_fence_inside_source_tag(self):
        result = normalize("<JARVIS_SOURCE>\n" + fence(SOURCE) + "\n</JARVIS_SOURCE>")
        self.assertTrue(result.success)
        self.assertEqual(result.source_code, SOURCE)

    def test_wrapped_metadata_json(self):
        result = normalize("<JARVIS_META>Metadata:\n" + fence(json.dumps(META), "json") + "\nEnd metadata.</JARVIS_META>\n" + fence(SOURCE))
        self.assertTrue(result.success)
        self.assertEqual(result.metadata, META)

    def test_invalid_secondary_metadata_does_not_discard_code(self):
        result = normalize("<JARVIS_META>not JSON</JARVIS_META>\n" + fence(SOURCE))
        self.assertTrue(result.success)
        self.assertEqual(result.metadata["implementation_summary"], "Consult an external API.")

    def test_ambiguous_python_blocks(self):
        result = normalize(fence(SOURCE) + "\n" + fence(SOURCE.replace('"ok"', '"different"')))
        self.assertFalse(result.success)
        self.assertEqual(result.structural_error_code, "ambiguous_python_blocks")

    def test_contradictory_source_tag_and_fence(self):
        result = normalize("<JARVIS_SOURCE>\n" + SOURCE + "</JARVIS_SOURCE>\n" + fence(SOURCE.replace('"ok"', '"different"')))
        self.assertEqual(result.structural_error_code, "ambiguous_python_blocks")

    def test_no_code(self):
        self.assertEqual(normalize("I will implement this feature.").structural_error_code, "no_source_found")

    def test_truncation_has_specific_cause(self):
        for raw in ("```python\n" + SOURCE, "<JARVIS_SOURCE>" + SOURCE,
                    'def ejecutar_skill():\n    return (', '<JARVIS_META>{',
                    '# implementation\ndef ejecutar_skill():\n    return "cut off'):
            with self.subTest(raw=raw):
                result = normalize(raw)
                self.assertFalse(result.success)
                self.assertTrue(result.truncated)
                self.assertEqual(result.structural_error_code, "truncated_response")
                self.assertIsNone(result.source_code)

    def test_syntax_invalid_explicit_source_reaches_validator(self):
        raw = fence("def ejecutar_skill(:\n    return 1\n")
        result = normalize(raw)
        self.assertTrue(result.success)
        self.assertFalse(LocalCodeValidator().validate_python_source(result.source_code, filename="candidate.py").success)

    def test_conflicting_metadata_names(self):
        result = normalize(fence(json.dumps(META), "json") + fence(json.dumps({**META, "skill_name": "another_name"}), "json") + fence(SOURCE))
        self.assertEqual(result.structural_error_code, "ambiguous_metadata")

    def test_duplicate_metadata_keys(self):
        result = normalize('<JARVIS_META>{"skill_name":"one","skill_name":"two"}</JARVIS_META>' + fence(SOURCE))
        self.assertEqual(result.structural_error_code, "ambiguous_metadata")

    def test_tagged_and_fenced_metadata_cannot_conflict(self):
        result = normalize("<JARVIS_META>" + json.dumps(META) + "</JARVIS_META>\n" + fence(json.dumps({**META, "skill_name": "different"}), "json") + fence(SOURCE))
        self.assertEqual(result.structural_error_code, "ambiguous_metadata")

    def test_metadata_dependencies_inferred_and_versions_preserved(self):
        source = "import json\nimport requests\nfrom bs4 import BeautifulSoup\n" + SOURCE
        metadata = {**META, "dependencies": ["requests>=2.0"]}
        result = normalize(fence(json.dumps(metadata), "json") + fence(source))
        self.assertEqual(result.metadata["dependencies"], ["requests>=2.0", "beautifulsoup4"])

    def test_unknown_import_not_silently_omitted(self):
        result = normalize(fence("import unknown_external_package\n" + SOURCE))
        self.assertEqual(result.metadata["dependencies"], ["unknown_external_package"])

    def test_generic_request_names_are_deterministic_and_valid(self):
        requests = ["Check a published API version", "Track my package", "Query hardware temperature",
                    "Parse a simple web page", "Compare the current state with the previous state"]
        for request in requests:
            with self.subTest(request=request):
                result = normalize(SOURCE, request=request)
                self.assertRegex(result.metadata["skill_name"], r"^[a-z][a-z0-9_]{0,63}$")
                self.assertEqual(result.metadata, normalize(fence(SOURCE), request=request).metadata)

    def test_proposed_name_normalization(self):
        result = normalize(fence(json.dumps({**META, "skill_name": "42 ÁPI / Reader " * 12}), "json") + fence(SOURCE))
        self.assertRegex(result.metadata["skill_name"], r"^[a-z][a-z0-9_]{0,63}$")

    def test_existing_skill_reference_is_used_without_model_metadata(self):
        result = normalize_authoring_output(SOURCE, phase=AuthoringPhase.SOURCE_INITIAL,
                                            user_request="Retry the original request.", existing_skill_name="installed_capability")
        self.assertEqual(result.metadata["skill_name"], "installed_capability")

    def test_repairs_accept_equivalent_transports_with_frozen_metadata(self):
        for raw in (SOURCE, fence(SOURCE), "<JARVIS_SOURCE>\n" + SOURCE + "</JARVIS_SOURCE>"):
            with self.subTest(raw=raw):
                result = normalize(raw, AuthoringPhase.SOURCE_REPAIR)
                proposal, reused, ignored = _source_proposal(result, 2, frozen_metadata=META)
                self.assertEqual(proposal.skill_name, META["skill_name"])
                self.assertEqual(proposal.source_code, SOURCE)
                self.assertTrue(reused)
                self.assertFalse(ignored)

    def test_changed_repair_metadata_is_ignored(self):
        changed = {**META, "skill_name": "changed", "dependencies": ["another"]}
        result = normalize(fence(json.dumps(changed), "json") + fence(SOURCE), AuthoringPhase.SOURCE_REPAIR)
        proposal, _, ignored = _source_proposal(result, 2, frozen_metadata=META)
        self.assertTrue(ignored)
        self.assertEqual(proposal.dependencies, ())
        self.assertEqual(proposal.skill_name, META["skill_name"])

    def test_tests_equivalent_transports(self):
        for raw in (TESTS, fence(TESTS), "<JARVIS_TESTS>\n" + TESTS + "</JARVIS_TESTS>"):
            with self.subTest(raw=raw):
                result = normalize(raw, AuthoringPhase.TESTS)
                self.assertTrue(result.success)
                self.assertEqual(result.tests_source, TESTS)

    def test_plain_tests_require_structure_and_completeness(self):
        for raw in ('print("hello")', "Here are some tests.", "def test_partial():\n    assert (", SOURCE):
            with self.subTest(raw=raw):
                self.assertFalse(normalize(raw, AuthoringPhase.TESTS).success)

    def test_tests_fence_cannot_be_a_source_implementation(self):
        self.assertEqual(normalize(fence(SOURCE), AuthoringPhase.TESTS).structural_error_code, "wrong_contract")

    def test_multiple_tests_fences_are_ambiguous(self):
        self.assertEqual(normalize(fence(TESTS) + fence(TESTS), AuthoringPhase.TESTS).structural_error_code, "ambiguous_python_blocks")

    def test_tests_tag_and_different_fence_are_ambiguous(self):
        raw = "<JARVIS_TESTS>\n" + TESTS + "</JARVIS_TESTS>\n" + fence(TESTS.replace('"ok"', '"different"'))
        self.assertEqual(normalize(raw, AuthoringPhase.TESTS).structural_error_code, "ambiguous_python_blocks")

    def test_inseparable_tests_and_source_rejected(self):
        self.assertEqual(normalize(fence(SOURCE + TESTS)).structural_error_code, "mixed_source_tests")

    def test_assert_in_implementation_class_is_not_a_tests_module(self):
        source = 'class Parser:\n    def parse(self, value):\n        assert value\n        return value\n\ndef ejecutar_skill():\n    return Parser().parse("ok")\n'
        self.assertTrue(normalize(fence(source)).success)

    def test_python_data_is_not_review_json(self):
        source = 'def ejecutar_skill():\n    return {"approved": False, "issues": []}\n'
        self.assertTrue(normalize(fence(source)).success)

    def test_extraction_never_imports_or_executes_candidate(self):
        source = 'raise RuntimeError("candidate executed")\n' + SOURCE
        with patch("builtins.exec", side_effect=AssertionError("exec forbidden")):
            self.assertTrue(normalize(source).success)

    def test_rescue_is_deterministic_and_cause_specific(self):
        service = object()  # No reviewer/model access is possible.
        request = SkillAuthoringRequest("Implement a capability.")
        ambiguous = _source_structural_rescue(service, request, "ambiguous Python blocks", repair=False)
        truncated = _source_structural_rescue(service, request, "unclosed Markdown fence", repair=True)
        self.assertIn("one implementation", ambiguous)
        self.assertIn("from scratch", truncated)
        self.assertIn("frozen metadata", truncated)
        self.assertNotIn("JARVIS_META", ambiguous)


class TransportPipelineTests(unittest.TestCase):
    def author(self, sources, existing_skill_name=None):
        class Coder:
            prompts = []
            def run_local_coding(self, prompt):
                self.prompts.append(prompt)
                return sources.pop(0)
        class Reviewer:
            calls = 0
            def review(self, request):
                self.calls += 1
                return CodeReviewResult(approved=True, issues=(), reviewer_used="fake", cloud_attempted=False, cloud_failed=False)
            def diagnose_stagnation(self, request):
                raise AssertionError("Structural rescue must not call a model")
        with tempfile.TemporaryDirectory() as directory:
            coder, reviewer = Coder(), Reviewer()
            service = SafeSkillAuthoringService(coder, reviewer=reviewer, diagnostic_sink=lambda _: None, debug_root=Path(directory), max_seconds=60)
            with patch.dict(os.environ, {"JARVIS_SKILL_AUTHORING_DEBUG": "true"}):
                result = service.author(SkillAuthoringRequest("Return an API result.", existing_skill_name=existing_skill_name))
            paths = list(Path(directory).glob("*/diagnostics.jsonl"))
            debug = [json.loads(line) for line in paths[0].read_text(encoding="utf-8").splitlines()] if paths else []
        return result, coder, reviewer, debug

    def test_recovered_first_response_calls_coder_once_for_source(self):
        result, coder, reviewer, debug = self.author(["Implementation:\n" + fence(SOURCE), TESTS])
        self.assertTrue(result.success)
        self.assertEqual(len(coder.prompts), 2)  # One source + one tests call.
        self.assertEqual(reviewer.calls, 1)
        self.assertTrue(result.diagnostics[0].first_response_structurally_valid)
        self.assertTrue(result.diagnostics[0].structurally_recovered)
        self.assertEqual(result.diagnostics[-1].structural_retry_count, 0)
        self.assertEqual(result.proposal.source_code, SOURCE)
        self.assertTrue(debug[0]["structurally_recovered"])

    def test_rescue_valid_response_continues_and_metrics_count_failures(self):
        result, coder, reviewer, debug = self.author(["No code"] * 3 + [SOURCE, TESTS])
        self.assertTrue(result.success)
        self.assertFalse(result.diagnostics[-1].first_response_structurally_valid)
        self.assertEqual(result.diagnostics[-1].structural_retry_count, 3)
        self.assertIn("SOURCE-ONLY FORMAT RESCUE", coder.prompts[3])
        self.assertEqual(reviewer.calls, 1)
        self.assertEqual(debug[0]["structural_error_code"], "no_source_found")

    def test_existing_capability_identity_survives_source_only_authoring(self):
        result, _, _, _ = self.author([SOURCE, TESTS], existing_skill_name="installed_capability")
        self.assertTrue(result.success)
        self.assertEqual(result.proposal.skill_name, "installed_capability")

    def test_invalid_syntax_is_validation_failure_and_repaired_source_continues(self):
        result, coder, reviewer, _ = self.author([fence("def ejecutar_skill(:\n    return 1\n"), SOURCE, TESTS])
        self.assertTrue(result.success)
        self.assertTrue(result.diagnostics[0].generation_success)
        self.assertFalse(result.diagnostics[0].validation_success)
        self.assertTrue(result.diagnostics[0].first_response_structurally_valid)
        self.assertEqual(result.diagnostics[-1].structural_retry_count, 0)
        self.assertEqual(result.diagnostics[-1].source_repair_count, 1)
        self.assertEqual(result.diagnostics[-1].reviewer_repair_count, 1)
        self.assertIn("AST parse failed", coder.prompts[1])
        self.assertEqual(reviewer.calls, 2)  # Existing review flow also receives failed validation.

    def test_five_true_structural_failures_still_abort(self):
        result, coder, reviewer, _ = self.author(["No code"] * 5)
        self.assertFalse(result.success)
        self.assertIn("5 consecutive structural", result.failure_reason)
        self.assertEqual(len(coder.prompts), 5)
        self.assertEqual(reviewer.calls, 0)


if __name__ == "__main__":
    unittest.main()
