from __future__ import annotations

import inspect
import json
import unittest
from pathlib import Path

from jarvis.core.code_reviewer import (
    CodeReviewRequest,
    CodeReviewer,
    MAX_REVIEW_ADVISORIES,
    MAX_REVIEW_ISSUES,
    ReviewSeverity,
    parse_review_response,
)
from jarvis.core.code_validation import LocalCodeValidator


class FakeReviewRouter:
    def __init__(self) -> None:
        self.groq_api_key: str | None = "test-key"
        self.groq_response = json.dumps({"approved": True, "issues": []})
        self.local_response = json.dumps({"approved": True, "issues": []})
        self.groq_error: Exception | None = None
        self.local_error: Exception | None = None
        self.groq_prompts: list[str] = []
        self.local_prompts: list[str] = []

    def run_groq_code_review(self, prompt: str) -> str:
        self.groq_prompts.append(prompt)
        if self.groq_error is not None:
            raise self.groq_error
        return self.groq_response

    def run_local_reasoning(self, prompt: str) -> str:
        self.local_prompts.append(prompt)
        if self.local_error is not None:
            raise self.local_error
        return self.local_response


class CodeReviewerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = FakeReviewRouter()
        self.reviewer = CodeReviewer(self.router)
        self.request = CodeReviewRequest(
            user_request="Summarize supplied information and preserve values from earlier queries.",
            implementation_summary="Añade una consulta y persistencia del estado.",
            code_diff="+ def consultar():\n+     return estado_anterior\n",
        )

    def test_original_user_request_reaches_groq(self) -> None:
        self.reviewer.review(self.request)
        self.assertIn(self.request.user_request, self.router.groq_prompts[0])

    def test_code_diff_reaches_groq(self) -> None:
        self.reviewer.review(self.request)
        self.assertIn(self.request.code_diff, self.router.groq_prompts[0])

    def test_validation_report_reaches_groq(self) -> None:
        report = LocalCodeValidator().validate_python_source("def ok():\n    return 1\n")
        request = CodeReviewRequest(
            self.request.user_request,
            self.request.implementation_summary,
            self.request.code_diff,
            report,
        )
        self.reviewer.review(request)
        self.assertIn('"success": true', self.router.groq_prompts[0])
        self.assertIn("in_memory_compile", self.router.groq_prompts[0])

    def test_groq_approves_correct_code(self) -> None:
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "groq")
        self.assertFalse(result.cloud_failed)

    def test_groq_detects_functional_noncompliance(self) -> None:
        self.router.groq_response = json.dumps(
            {
                "approved": False,
                "issues": [
                    {
                        "severity": "high",
                        "file": "skill.py",
                        "description": "Consulta el paquete pero no persiste el estado anterior.",
                        "suggested_fix": "Guardar y recuperar el estado antes de responder.",
                    }
                ],
            }
        )
        result = self.reviewer.review(self.request)
        self.assertFalse(result.approved)
        self.assertEqual(result.issues[0].severity, ReviewSeverity.HIGH)
        self.assertIn("no persiste", result.issues[0].description)

    def test_groq_failure_uses_local_fallback(self) -> None:
        self.router.groq_error = RuntimeError("rate limited")
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertTrue(result.cloud_attempted)
        self.assertTrue(result.cloud_failed)
        self.assertEqual(self.router.groq_prompts, self.router.local_prompts)

    def test_missing_groq_key_uses_local_fallback(self) -> None:
        self.router.groq_api_key = None
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertEqual(self.router.groq_prompts, [])
        self.assertEqual(len(self.router.local_prompts), 1)
        self.assertFalse(result.cloud_attempted)

    def test_groq_timeout_uses_local_fallback(self) -> None:
        self.router.groq_error = TimeoutError("timeout")
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertTrue(result.cloud_failed)

    def test_cloud_fallback_keeps_a_safe_failure_reason(self) -> None:
        self.router.groq_error = TimeoutError("transport timeout")
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertEqual(result.cloud_failure_reason, "timeout")

    def test_stagnation_diagnosis_uses_the_same_groq_to_local_path(self) -> None:
        self.router.groq_error = RuntimeError("HTTP 429 rate limit")
        result = self.reviewer.diagnose_stagnation(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertEqual(result.cloud_failure_reason, "HTTP 429")
        self.assertIn("unblock diagnostician", self.router.local_prompts[0])

    def test_invalid_groq_response_uses_local_fallback(self) -> None:
        self.router.groq_response = "not structured JSON"
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertTrue(result.cloud_failed)

    def test_missing_required_json_field_uses_local_fallback(self) -> None:
        self.router.groq_response = json.dumps({"issues": []})
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")

    def test_free_text_after_json_is_ignored_by_the_common_extractor(self) -> None:
        self.router.groq_response = '{"approved": true, "issues": []} explanatory text'
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "groq")
    def test_local_fallback_can_approve(self) -> None:
        self.router.groq_error = RuntimeError("offline")
        self.router.local_response = json.dumps({"approved": True, "issues": []})
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")

    def test_local_fallback_can_detect_problems(self) -> None:
        self.router.groq_error = RuntimeError("offline")
        self.router.local_response = json.dumps(
            {
                "approved": False,
                "issues": [
                    {
                        "severity": "medium",
                        "description": "No hay prueba de persistencia.",
                    }
                ],
            }
        )
        result = self.reviewer.review(self.request)
        self.assertFalse(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        self.assertEqual(result.issues[0].severity, ReviewSeverity.MEDIUM)

    def test_both_reviewers_failing_never_approves(self) -> None:
        self.router.groq_error = RuntimeError("offline")
        self.router.local_error = RuntimeError("local unavailable")
        result = self.reviewer.review(self.request)
        self.assertFalse(result.approved)
        self.assertEqual(result.reviewer_used, "none")
        self.assertEqual(result.issues[0].severity, ReviewSeverity.CRITICAL)

    def test_markdown_json_is_parsed(self) -> None:
        result = parse_review_response(
            "```json\n{\"approved\": true, \"issues\": []}\n```",
            reviewer_used="groq",
            cloud_attempted=True,
            cloud_failed=False,
        )
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "groq")

    def test_issue_severities_are_preserved(self) -> None:
        result = parse_review_response(
            json.dumps(
                {
                    "approved": False,
                    "issues": [
                        {"severity": "info", "description": "note"},
                        {"severity": "low", "description": "minor"},
                        {"severity": "medium", "description": "test gap"},
                        {"severity": "critical", "description": "unsafe"},
                    ],
                }
            ),
            reviewer_used="local",
            cloud_attempted=True,
            cloud_failed=True,
        )
        self.assertEqual(
            [issue.severity for issue in result.issues],
            [
                ReviewSeverity.INFO,
                ReviewSeverity.LOW,
                ReviewSeverity.MEDIUM,
                ReviewSeverity.CRITICAL,
            ],
        )
        self.assertFalse(result.approved)

    def test_failed_validation_is_present_in_reviewer_context(self) -> None:
        report = LocalCodeValidator().validate_python_source("def broken(:\n")
        request = CodeReviewRequest(
            self.request.user_request,
            self.request.implementation_summary,
            self.request.code_diff,
            report,
        )
        self.reviewer.review(request)
        prompt = self.router.groq_prompts[0]
        self.assertIn('"success": false', prompt)
        self.assertIn("AST parse failed", prompt)

    def test_reviewer_does_not_depend_on_dynamic_skill_builder_or_main(self) -> None:
        source = inspect.getsource(CodeReviewer)
        self.assertNotIn("DynamicSkillBuilder", source)
        self.assertNotIn("main.", source)
        self.assertFalse((Path("src/jarvis/skills/skill_builder.py").resolve() == Path(__file__).resolve()))


    def test_prompt_requires_compact_structured_only_response(self) -> None:
        prompt = self.reviewer.build_prompt(self.request)
        self.assertIn("Return ONLY JARVIS_DATA JSON", prompt)
        self.assertIn("No introduction, analysis, Markdown", prompt)
        self.assertIn(f"at most {MAX_REVIEW_ISSUES} blocking issues", prompt)
        self.assertIn(f"at most {MAX_REVIEW_ADVISORIES} concise advisories", prompt)
        self.assertIn("never block approval", prompt)

    def test_parse_deduplicates_and_limits_to_five_issues(self) -> None:
        payload = {
            "approved": False,
            "issues": [
                {
                    "severity": "low",
                    "description": "Duplicate persistence warning.",
                    "suggested_fix": "Persist state.",
                },
                {
                    "severity": "low",
                    "description": "duplicate persistence warning",
                    "suggested_fix": "persist state",
                },
                {
                    "severity": "critical",
                    "description": "Critical unsafe behavior.",
                },
                {
                    "severity": "high",
                    "description": "High failure one.",
                },
                {
                    "severity": "high",
                    "description": "High failure two.",
                },
                {
                    "severity": "medium",
                    "description": "Medium failure.",
                },
                {
                    "severity": "info",
                    "description": "Information only.",
                },
            ],
        }
        result = parse_review_response(
            json.dumps(payload),
            reviewer_used="groq",
            cloud_attempted=True,
            cloud_failed=False,
        )
        self.assertEqual(len(result.issues), MAX_REVIEW_ISSUES)
        self.assertEqual(result.issues[0].severity, ReviewSeverity.CRITICAL)
        self.assertEqual(
            sum(issue.description.lower().startswith("duplicate persistence") for issue in result.issues),
            1,
        )

    def test_truncated_groq_response_uses_local_fallback(self) -> None:
        self.router.groq_response = '<JARVIS_DATA>{"approved": false, "issues": ['
        self.router.local_response = json.dumps({
            "approved": True, "issues": [], "blocking_issues": [], "advisory_issues": [],
        })
        result = self.reviewer.review(self.request)
        self.assertTrue(result.approved)
        self.assertEqual(result.reviewer_used, "local")
        outcome = self.reviewer.review_with_attempts(self.request)
        self.assertTrue(outcome.result is not None)
        self.assertTrue(outcome.provider_attempts[0].truncated)
        self.assertEqual(
            outcome.provider_attempts[0].normalization_error,
            "review response truncated before completing structured payload",
        )

    def test_historic_review_remains_fail_closed_for_two_truncated_reviews(self) -> None:
        truncated = '<JARVIS_DATA>{"approved": false, "issues": ['
        self.router.groq_response = truncated
        self.router.local_response = truncated
        result = self.reviewer.review(self.request)
        self.assertFalse(result.approved)
        self.assertEqual(result.reviewer_used, "none")
        self.assertEqual(result.cloud_failure_reason, "truncated structured response")

if __name__ == "__main__":
    unittest.main()
