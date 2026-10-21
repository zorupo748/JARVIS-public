from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.core.authoring_debug import AUTHORING_DEBUG_ENV
from jarvis.core.code_reviewer import CodeReviewer
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService, SkillAuthoringRequest


class _Coder:
    def run_local_coding(self, prompt: str) -> str:
        if "Produce TESTS only." in prompt:
            return "<JARVIS_TESTS>\ndef test_ok():\n    assert True\n</JARVIS_TESTS>"
        return (
            '<JARVIS_META>{"skill_name":"debug_review",'
            '"implementation_summary":"debug", "dependencies":[]}</JARVIS_META>'
            "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'ok'\n</JARVIS_SOURCE>"
        )


class _Router:
    groq_api_key = "configured-for-test"

    def run_groq_code_review(self, _prompt: str) -> str:
        return '{"approved":true,"issues":[],"blocking_issues":[],"advisory_issues":[],"api_key":"should-not-persist"}'

    def run_local_reasoning(self, _prompt: str) -> str:
        raise AssertionError("valid Groq must not call local")


class _TruncatedRouter:
    groq_api_key = "configured-for-test"

    @staticmethod
    def _truncated() -> str:
        return '<JARVIS_DATA>{"approved": false, "issues": [{"severity": "high"'

    def run_groq_code_review(self, _prompt: str) -> str:
        return self._truncated()

    def run_local_reasoning(self, _prompt: str) -> str:
        return self._truncated()


class _OptionalBlockerRouter:
    groq_api_key = "configured-for-test"
    local_code_review_num_predict = 1536

    def run_groq_code_review(self, _prompt: str) -> str:
        return ""

    def run_local_code_review(self, _prompt: str) -> str:
        return json.dumps({
            "approved": False, "issues": [], "blocking_issues": [{
                "severity": "high", "category": "user_requirement_unmet",
                "description": "Use Redis for simple state.",
                "suggested_fix": "Replace JSON with Redis.",
                "evidence": "The source uses local state.",
                "requirement_relation": "General hardening.",
            }], "advisory_issues": [],
        })

class AuthoringReviewerDebugTests(unittest.TestCase):
    def test_debug_distinguishes_legacy_and_new_contract_errors(self) -> None:
        cases = (
            ({"approved": False, "issues": [{"severity": "warning", "description": "Legacy finding."}]},
             "legacy_issue_parse_error"),
            ({"approved": False, "blocking_issues": [{"severity": "warning", "description": "Missing category."}]},
             "new_contract_parse_error"),
        )
        for payload, error_kind in cases:
            class Router:
                groq_api_key = "configured-for-test"

                def run_groq_code_review(self, _prompt: str) -> str:
                    return json.dumps(payload)

                def run_local_reasoning(self, _prompt: str) -> str:
                    return json.dumps(payload)

            with self.subTest(error_kind=error_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "authoring-debug"
                service = SafeSkillAuthoringService(
                    _Coder(), reviewer=CodeReviewer(Router()), max_seconds=60,
                    max_review_cycles=1, debug_root=root, diagnostic_sink=lambda _message: None,
                )
                with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}):
                    result = service.author(SkillAuthoringRequest("Create a local skill."))
                self.assertFalse(result.success)
                records = [json.loads(line) for line in
                    (next(root.iterdir()) / "reviewer_responses.jsonl").read_text(encoding="utf-8").splitlines()]
                self.assertEqual(len(records), 2)
                self.assertTrue(all(record["normalization_error_kind"] == error_kind for record in records))

    def test_debug_records_unknown_severity_normalized_without_secrets(self) -> None:
        class Router:
            groq_api_key = "configured-for-test"

            def run_groq_code_review(self, _prompt: str) -> str:
                return json.dumps({
                    "approved": False, "blocking_issues": [], "advisory_issues": [{
                        "description": "Add logs.", "severity": "warning",
                    }, {"description": "Add documentation."}], "api_key": "should-not-persist",
                })

            def run_local_reasoning(self, _prompt: str) -> str:
                raise AssertionError("Normalized Groq must not call local.")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "authoring-debug"
            service = SafeSkillAuthoringService(
                _Coder(), reviewer=CodeReviewer(Router()), max_seconds=60,
                debug_root=root, diagnostic_sink=lambda _message: None,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}):
                result = service.author(SkillAuthoringRequest("Create a local skill."))
            self.assertTrue(result.success)
            record = json.loads((next(root.iterdir()) / "reviewer_responses.jsonl").read_text(encoding="utf-8"))
            self.assertTrue(record["normalization_success"])
            self.assertIsNone(record["normalization_error_kind"])
            self.assertEqual(record["unknown_severity_normalized"],
                             ["advisory_issues[0].severity", "advisory_issues[1].severity"])
            self.assertNotIn("should-not-persist", record["raw_response"])
            self.assertNotIn("prompt", record)

    def test_debug_records_local_budget_and_policy_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".debug" / "skill_authoring"
            service = SafeSkillAuthoringService(
                _Coder(), reviewer=CodeReviewer(_OptionalBlockerRouter()),
                max_seconds=60, debug_root=root, diagnostic_sink=lambda _message: None,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(SkillAuthoringRequest("Create a simple local skill."))
            self.assertTrue(result.success)
            session = next(root.iterdir())
            records = [json.loads(line) for line in
                (session / "reviewer_responses.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(records[1]["provider"], "local")
            self.assertEqual(records[1]["local_review_num_predict"], 1536)
            self.assertIn("user_requirement_unmet:optional redis requirement", records[1]["blockers_downgraded_by_policy"])
            diagnostic = json.loads((session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(diagnostic["local_review_num_predict"], 1536)
            self.assertEqual(diagnostic["blocking_unresolved"], 0)
            self.assertEqual(len(diagnostic["blockers_downgraded_by_policy"]), 1)

    def _service(self, root: Path) -> SafeSkillAuthoringService:
        return SafeSkillAuthoringService(
            _Coder(),
            reviewer=CodeReviewer(_Router()),
            max_seconds=60,
            debug_root=root,
            diagnostic_sink=lambda _message: None,
        )

    def test_debug_records_sanitized_reviewer_response_and_attempt_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".debug" / "skill_authoring"
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = self._service(root).author(SkillAuthoringRequest("Create a debug skill."))
            self.assertTrue(result.success)
            session = next(root.iterdir())
            records = [
                json.loads(line)
                for line in (session / "reviewer_responses.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(records), 1)
            self.assertTrue(records[0]["normalization_success"])
            self.assertNotIn("should-not-persist", records[0]["raw_response"])
            self.assertIn("[REDACTED]", records[0]["raw_response"])
            diagnostic = json.loads((session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(diagnostic["review_attempts"], 1)
            self.assertTrue(diagnostic["reviewer_normalized"])
            self.assertIn("blockers_downgraded_by_policy", diagnostic)
            self.assertIn("local_review_num_predict", diagnostic)

    def test_debug_records_truncation_and_raw_length(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".debug" / "skill_authoring"
            service = SafeSkillAuthoringService(
                _Coder(),
                reviewer=CodeReviewer(_TruncatedRouter()),
                max_seconds=60,
                max_review_cycles=1,
                debug_root=root,
                diagnostic_sink=lambda _message: None,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(SkillAuthoringRequest("Create a debug skill."))
            self.assertFalse(result.success)
            session = next(root.iterdir())
            records = [
                json.loads(line)
                for line in (session / "reviewer_responses.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(records), 2)
            self.assertTrue(all(record["truncated"] for record in records))
            self.assertTrue(all(record["normalization_error_kind"] == "truncated" for record in records))
            self.assertTrue(all(record["raw_length"] > 0 for record in records))
            self.assertTrue(all("local_review_num_predict" in record for record in records))
            self.assertTrue(all("blockers_downgraded_by_policy" in record for record in records))
            self.assertEqual(
                records[0]["normalization_error"],
                "review response truncated before completing structured payload",
            )
    def test_debug_disabled_creates_no_reviewer_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".debug" / "skill_authoring"
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: ""}, clear=False):
                self._service(root).author(SkillAuthoringRequest("Create a debug skill."))
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
