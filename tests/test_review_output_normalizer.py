from __future__ import annotations

import json
import unittest

from jarvis.core.review_output_normalizer import normalize_review_output


def review_payload(*, approved: bool = True) -> dict[str, object]:
    return {
        "approved": approved,
        "issues": []
        if approved
        else [
            {
                "severity": "high",
                "description": "A semantic repair is required.",
            }
        ],
    }


class ReviewOutputNormalizerTests(unittest.TestCase):
    def test_jarvis_data_review_is_accepted(self) -> None:
        result = normalize_review_output(
            "<JARVIS_DATA>" + json.dumps(review_payload()) + "</JARVIS_DATA>"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.payload, review_payload())

    def test_open_jarvis_data_is_classified_as_truncated(self) -> None:
        result = normalize_review_output(
            '<JARVIS_DATA>{"approved": false, "issues": [{"severity": "high"'
        )
        self.assertFalse(result.success)
        self.assertTrue(result.truncated)
        self.assertEqual(
            result.error,
            "review response truncated before completing structured payload",
        )

    def test_incomplete_root_json_is_classified_as_truncated(self) -> None:
        result = normalize_review_output(
            '{"approved": false, "issues": [{"severity": "high", "description": "x"}]'
        )
        self.assertFalse(result.success)
        self.assertTrue(result.truncated)
        self.assertEqual(
            result.error,
            "review response truncated before completing structured payload",
        )

    def test_plain_json_review_is_accepted(self) -> None:
        result = normalize_review_output(json.dumps(review_payload()))
        self.assertTrue(result.success)
        self.assertEqual(result.payload, review_payload())

    def test_markdown_json_review_is_accepted(self) -> None:
        fence = chr(96) * 3
        result = normalize_review_output(
            fence + "json\n" + json.dumps(review_payload()) + "\n" + fence
        )
        self.assertTrue(result.success)
        self.assertEqual(result.payload, review_payload())

    def test_prose_with_one_recoverable_json_object_is_accepted(self) -> None:
        result = normalize_review_output(
            "Reviewer notes. " + json.dumps(review_payload(approved=False)) + " End."
        )
        self.assertTrue(result.success)
        self.assertEqual(result.payload, review_payload(approved=False))

    def test_nested_issue_objects_are_not_ambiguous(self) -> None:
        payload = {
            "approved": False,
            "issues": [
                {
                    "severity": "high",
                    "description": f"blocking problem {index}",
                }
                for index in range(5)
            ],
        }
        result = normalize_review_output(json.dumps(payload))
        self.assertTrue(result.success)
        self.assertEqual(result.payload, payload)

    def test_missing_or_non_boolean_approved_is_rejected(self) -> None:
        missing = normalize_review_output(json.dumps({"issues": []}))
        wrong_type = normalize_review_output(json.dumps({"approved": "yes", "issues": []}))
        self.assertFalse(missing.success)
        self.assertIn("approved", missing.error or "")
        self.assertFalse(wrong_type.success)
        self.assertIn("boolean", wrong_type.error or "")

    def test_missing_issues_is_rejected(self) -> None:
        result = normalize_review_output(json.dumps({"approved": True}))
        self.assertFalse(result.success)
        self.assertIn("issues", result.error or "")

    def test_new_review_contract_does_not_need_legacy_issues_field(self) -> None:
        result = normalize_review_output(json.dumps({
            "approved": True,
            "blocking_issues": [],
            "advisory_issues": [],
        }))
        self.assertTrue(result.success)

    def test_followup_contract_does_not_need_legacy_issues_field(self) -> None:
        result = normalize_review_output(json.dumps({
            "approved": False, "blocker_statuses": [],
            "regression_blockers": [], "advisory_issues": [],
        }))
        self.assertTrue(result.success)

    def test_new_contract_ignores_legacy_issues_type(self) -> None:
        for contract in ({"blocking_issues": []}, {"blocker_statuses": []}):
            with self.subTest(contract=contract):
                result = normalize_review_output(json.dumps({
                    "approved": True, "issues": "irrelevant legacy field", **contract,
                }))
                self.assertTrue(result.success)

    def test_legacy_issues_still_must_be_a_list(self) -> None:
        result = normalize_review_output(json.dumps({"approved": True, "issues": "invalid"}))
        self.assertFalse(result.success)
        self.assertIn("must be a list", result.error or "")

    def test_prose_with_multiple_json_objects_is_ambiguous(self) -> None:
        normalized = normalize_review_output(
            'context {"approved": true, "issues": []} then '
            '{"approved": false, "issues": []}'
        )
        self.assertFalse(normalized.success)
        self.assertEqual(
            normalized.error,
            "review response contains ambiguous top-level JSON objects",
        )

    def test_empty_response_is_rejected(self) -> None:
        result = normalize_review_output("  ")
        self.assertFalse(result.success)
        self.assertFalse(result.truncated)
        self.assertEqual(result.error, "review response is empty or not text")

    def test_validation_report_and_python_are_not_reviews(self) -> None:
        validation = normalize_review_output(
            json.dumps({"success": False, "checks": [], "timed_out": False})
        )
        python = normalize_review_output("def ejecutar_skill():\n    return 'not a review'\n")
        proposal = normalize_review_output(
            '<JARVIS_META>{"skill_name":"demo"}</JARVIS_META>'
        )
        self.assertFalse(validation.success)
        self.assertFalse(python.success)
        self.assertFalse(proposal.success)


if __name__ == "__main__":
    unittest.main()
