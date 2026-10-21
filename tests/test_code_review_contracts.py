from __future__ import annotations

import json
import unittest
from dataclasses import replace

from jarvis.core.code_reviewer import (
    CodeReviewParseError,
    CodeReviewRequest,
    CodeReviewer,
    ReviewSeverity,
    parse_review_response,
)
from jarvis.core.review_acceptance import (
    BlockingCategory,
    BlockingFinding,
    apply_assessment,
    create_acceptance_state,
)


def blocker(**changes: object) -> dict[str, object]:
    return {
        "severity": "high",
        "category": "runtime_failure",
        "description": "The requested call crashes on a missing result.",
        "suggested_fix": "Guard the missing result.",
        "evidence": "The source indexes a None result.",
        "requirement_relation": "The requested normal call must execute.",
        **changes,
    }


def regression(**changes: object) -> dict[str, object]:
    return blocker(
        introduced_behavior="Index a missing result.",
        prior_absence="Previous source guarded the result.",
        source_change_evidence="Repair removed the guard before indexing.",
        **changes,
    )


def initial(*findings: dict[str, object], approved: bool = False) -> dict[str, object]:
    return {"approved": approved, "blocking_issues": list(findings), "advisory_issues": []}


def followup() -> dict[str, object]:
    return {
        "approved": False,
        "blocker_statuses": [
            {"id": "B1", "status": "resolved", "evidence": "The call now guards None."},
            {"id": "B2", "status": "unresolved", "evidence": "The requested value is still wrong."},
        ],
        "regression_blockers": [],
        "advisory_issues": [],
    }


def parse(payload: dict[str, object]):
    return parse_review_response(
        json.dumps(payload), reviewer_used="local", cloud_attempted=False, cloud_failed=True,
    )


class Router:
    groq_api_key = "configured-for-test"
    local_code_review_num_predict = 1536

    def __init__(self, groq: dict[str, object] | str, local: dict[str, object] | str):
        self.groq = json.dumps(groq) if isinstance(groq, dict) else groq
        self.local = json.dumps(local) if isinstance(local, dict) else local
        self.groq_calls = 0
        self.local_calls = 0

    def run_groq_code_review(self, _prompt: str) -> str:
        self.groq_calls += 1
        return self.groq

    def run_local_code_review(self, _prompt: str) -> str:
        self.local_calls += 1
        return self.local


class CodeReviewContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = CodeReviewRequest("Make the normal call work.", "Guard the result.", "source")
        self.state = create_acceptance_state((
            BlockingFinding(BlockingCategory.RUNTIME_FAILURE, "Crash", "Guard result", "None result", "Normal call"),
            BlockingFinding(BlockingCategory.INCORRECT_RESULT, "Wrong value", "Parse result", "Raw result", "Normal call"),
        ), "source-hash")

    def test_initial_without_legacy_issues(self) -> None:
        result = parse(initial(blocker()))
        self.assertEqual(result.review_mode, "initial")
        self.assertEqual(len(result.blocking_findings), 1)
        self.assertEqual(result.issues, ())
        self.assertFalse(result.approved)

    def test_followup_without_legacy_issues(self) -> None:
        result = parse(followup())
        self.assertEqual(result.review_mode, "followup")
        self.assertEqual([item.id for item in result.blocker_assessments], ["B1", "B2"])
        self.assertEqual(result.issues, ())

    def test_initial_ignores_invalid_legacy_issues(self) -> None:
        payload = initial(blocker())
        payload["issues"] = [{"severity": "warning", "description": "Legacy finding."}]
        result = parse(payload)
        self.assertEqual(result.review_mode, "initial")
        self.assertEqual(len(result.blocking_findings), 1)
        self.assertEqual(result.issues, ())

    def test_followup_ignores_invalid_legacy_issues(self) -> None:
        payload = followup()
        payload["issues"] = [{"severity": "warning", "description": "Legacy finding."}]
        result = parse(payload)
        self.assertEqual(result.review_mode, "followup")
        self.assertEqual(len(result.blocker_assessments), 2)
        self.assertEqual(result.regression_findings, ())
        self.assertEqual(result.issues, ())

    def test_extra_legacy_issues_cannot_change_new_approval(self) -> None:
        for payload in (initial(approved=True), followup()):
            payload["approved"] = True
            for extra in (None, "invalid list", [{"description": "Missing severity."}],
                          [{"severity": "critical", "description": "Legacy finding."}]):
                with self.subTest(contract=payload.keys(), extra=extra):
                    payload["issues"] = extra
                    result = parse(payload)
                    self.assertTrue(result.approved)
                    self.assertEqual(result.issues, ())
                    self.assertEqual(result.blocking_findings, ())
                    self.assertEqual(result.regression_findings, ())

    def test_initial_contract_takes_precedence_over_followup_fields(self) -> None:
        payload = initial(approved=True)
        payload["blocker_statuses"] = "ignored in initial"
        self.assertEqual(parse(payload).review_mode, "initial")

    def test_legacy_unknown_severity_is_strict(self) -> None:
        for severity in ("warning", "error", "blocker", "major", "minor", "fatal", None):
            with self.subTest(severity=severity), self.assertRaises(CodeReviewParseError) as raised:
                parse({"approved": True, "issues": [{"severity": severity, "description": "Legacy finding."}]})
            self.assertEqual(raised.exception.normalization_error_kind, "legacy_issue_parse_error")

    def test_legacy_missing_severity_is_strict(self) -> None:
        with self.assertRaisesRegex(CodeReviewParseError, "known severity"):
            parse({"approved": True, "issues": [{"description": "Legacy finding."}]})

    def test_legacy_critical_issue_still_prevents_approval(self) -> None:
        result = parse({"approved": True, "issues": [{"severity": "critical", "description": "Crash."}]})
        self.assertFalse(result.approved)
        self.assertEqual(result.issues[0].severity, ReviewSeverity.CRITICAL)

    def test_warning_blocker_normalizes_to_high(self) -> None:
        result = parse(initial(blocker(severity="warning")))
        self.assertEqual(result.blocking_findings[0].severity, "high")
        self.assertEqual(result.unknown_severity_normalized, ("blocking_issues[0].severity",))
        self.assertFalse(result.approved)

    def test_missing_blocker_severity_normalizes_to_high(self) -> None:
        finding = blocker()
        finding.pop("severity")
        self.assertEqual(parse(initial(finding)).blocking_findings[0].severity, "high")

    def test_unknown_regression_severity_normalizes_to_high(self) -> None:
        payload = followup()
        payload["regression_blockers"] = [regression(severity="fatal")]
        result = parse(payload)
        self.assertEqual(result.regression_findings[0].severity, "high")
        self.assertEqual(result.unknown_severity_normalized, ("regression_blockers[0].severity",))

    def test_missing_regression_severity_normalizes_to_high(self) -> None:
        finding = regression()
        finding.pop("severity")
        payload = followup()
        payload["regression_blockers"] = [finding]
        self.assertEqual(parse(payload).regression_findings[0].severity, "high")

    def test_unknown_advisory_severity_normalizes_to_medium(self) -> None:
        for payload in (initial(), followup()):
            payload["advisory_issues"] = [{"severity": "major", "description": "Add logs."}]
            with self.subTest(contract=payload.keys()):
                result = parse(payload)
                self.assertEqual(result.advisory_issues[0].severity, ReviewSeverity.MEDIUM)
                self.assertEqual(result.unknown_severity_normalized, ("advisory_issues[0].severity",))

    def test_missing_advisory_severity_normalizes_to_medium(self) -> None:
        payload = initial()
        payload["advisory_issues"] = [{"description": "Add logs."}]
        result = parse(payload)
        self.assertEqual(result.advisory_issues[0].severity, ReviewSeverity.MEDIUM)
        self.assertFalse(result.approved)

    def test_normalization_never_promotes_advisories(self) -> None:
        for payload in (initial(), followup()):
            payload["advisory_issues"] = [blocker(severity="warning")]
            result = parse(payload)
            self.assertEqual(result.blocking_findings, ())
            self.assertEqual(result.regression_findings, ())
            self.assertEqual(len(result.advisory_issues), 1)

    def test_known_severities_are_preserved_in_all_new_fields(self) -> None:
        for severity in ReviewSeverity:
            with self.subTest(severity=severity):
                payload = initial(blocker(severity=severity.value))
                payload["advisory_issues"] = [{"severity": severity.value, "description": "Add logs."}]
                result = parse(payload)
                self.assertEqual(result.blocking_findings[0].severity, severity.value)
                self.assertEqual(result.advisory_issues[0].severity, severity)
                self.assertEqual(result.unknown_severity_normalized, ())
                payload = followup()
                payload["regression_blockers"] = [regression(severity=severity.value)]
                self.assertEqual(parse(payload).regression_findings[0].severity, severity.value)

    def test_normalization_preserves_category_and_supplied_evidence(self) -> None:
        finding = blocker(severity="warning", category="state_persistence_broken")
        result = parse(initial(finding))
        self.assertEqual(result.blocking_findings[0].category, BlockingCategory.STATE_PERSISTENCE_BROKEN)
        self.assertEqual(result.blocking_findings[0].evidence, finding["evidence"])
        self.assertEqual(result.blocking_findings[0].requirement_relation, finding["requirement_relation"])
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(json.loads(result.raw_response)["blocking_issues"][0], finding)

    def test_normalization_does_not_invent_missing_blocker_fields(self) -> None:
        for field in ("description", "category", "suggested_fix", "evidence", "requirement_relation"):
            for replacement in (None, "", " "):
                with self.subTest(field=field, replacement=replacement):
                    finding = blocker(severity="warning")
                    finding[field] = replacement
                    with self.assertRaises(CodeReviewParseError) as raised:
                        parse(initial(finding, approved=True))
                    self.assertEqual(raised.exception.normalization_error_kind, "new_contract_parse_error")

    def test_normalization_does_not_repair_invalid_category(self) -> None:
        with self.assertRaisesRegex(CodeReviewParseError, "valid category"):
            parse(initial(blocker(severity="warning", category="enterprise_hardening")))

    def test_regression_still_requires_every_introduction_evidence_field(self) -> None:
        for field in ("introduced_behavior", "prior_absence", "source_change_evidence"):
            finding = regression(severity="warning")
            finding.pop(field)
            payload = followup()
            payload["regression_blockers"] = [finding]
            with self.subTest(field=field), self.assertRaises(CodeReviewParseError):
                parse(payload)

    def test_normalization_does_not_change_resolved_or_unresolved_statuses(self) -> None:
        payload = followup()
        payload["regression_blockers"] = [regression(severity="warning")]
        result = parse(payload)
        self.assertEqual([item.status for item in result.blocker_assessments], ["resolved", "unresolved"])
        updated = apply_assessment(self.state, result.blocker_assessments, result.regression_findings, source_changed=True)
        self.assertEqual(updated.plan, self.state.plan)
        self.assertEqual(updated.unresolved_ids, frozenset({"B2", "R1"}))

    def test_normalized_optional_blocker_still_obeys_policy(self) -> None:
        result = parse(initial(blocker(
            severity="warning", category="user_requirement_unmet",
            description="Use Redis for simple JSON state.",
            suggested_fix="Replace JSON with Redis.", evidence="Source writes JSON.",
            requirement_relation="General hardening.",
        )))
        self.assertEqual(result.blocking_findings, ())
        self.assertEqual(result.advisory_issues[0].severity, ReviewSeverity.HIGH)
        self.assertEqual(len(result.blockers_downgraded_by_policy), 1)

    def test_truncated_new_json_is_rejected_without_reconstruction(self) -> None:
        for text in ('{"approved":false,"blocking_issues":[{"severity":"warning"}',
                     '<JARVIS_DATA>{"approved":true,"blocking_issues":[]}'):
            with self.subTest(text=text), self.assertRaises(CodeReviewParseError) as raised:
                parse_review_response(text, reviewer_used="groq", cloud_attempted=True, cloud_failed=False)
            self.assertTrue(raised.exception.truncated)
            self.assertEqual(raised.exception.normalization_error_kind, "truncated")

    def test_ambiguous_json_is_rejected(self) -> None:
        text = json.dumps(initial(approved=True)) + json.dumps(followup())
        with self.assertRaisesRegex(CodeReviewParseError, "ambiguous"):
            parse_review_response(text, reviewer_used="groq", cloud_attempted=True, cloud_failed=False)

    def test_new_contract_requires_boolean_approved(self) -> None:
        for payload in (initial(), followup()):
            for value in (None, "true", 1):
                with self.subTest(contract=payload.keys(), value=value), self.assertRaises(CodeReviewParseError):
                    parse({**payload, "approved": value})
            payload.pop("approved")
            with self.assertRaises(CodeReviewParseError):
                parse(payload)

    def test_duplicate_followup_ids_are_rejected(self) -> None:
        payload = followup()
        payload["blocker_statuses"].append(payload["blocker_statuses"][0])
        with self.assertRaisesRegex(CodeReviewParseError, "exactly once"):
            parse(payload)

    def test_followup_still_requires_valid_status_and_evidence(self) -> None:
        for field, value in (("status", "fixed"), ("evidence", ""), ("id", "")):
            payload = followup()
            payload["blocker_statuses"][0][field] = value
            with self.subTest(field=field), self.assertRaises(CodeReviewParseError):
                parse(payload)

    def test_followup_requires_all_frozen_ids(self) -> None:
        request = replace(self.request, acceptance_state=self.state)
        for statuses in ([], followup()["blocker_statuses"][:1],
                         [{"id": "B3", "status": "resolved", "evidence": "Unknown blocker."}]):
            payload = {**followup(), "blocker_statuses": statuses}
            router = Router(payload, payload)
            with self.subTest(statuses=statuses):
                outcome = CodeReviewer(router).review_with_attempts(request)
                self.assertIsNone(outcome.result)
                self.assertEqual((router.groq_calls, router.local_calls), (1, 1))
                self.assertTrue(all(item.normalization_error_kind == "new_contract_parse_error"
                                    for item in outcome.provider_attempts))

    def test_truncated_groq_uses_valid_new_local_contract(self) -> None:
        router = Router('{"approved":false,"blocking_issues":[', initial(approved=True))
        outcome = CodeReviewer(router).review_with_attempts(self.request)
        self.assertTrue(outcome.result.approved)
        self.assertEqual(outcome.result.reviewer_used, "local")
        self.assertEqual((router.groq_calls, router.local_calls), (1, 1))
        self.assertEqual(outcome.provider_attempts[0].normalization_error_kind, "truncated")

    def test_invalid_groq_uses_local_with_missing_advisory_severity(self) -> None:
        payload = initial(approved=True)
        payload["advisory_issues"] = [{"description": "Add logs."}]
        router = Router("invalid", payload)
        outcome = CodeReviewer(router).review_with_attempts(self.request)
        self.assertTrue(outcome.result.approved)
        self.assertEqual(outcome.result.reviewer_used, "local")
        self.assertEqual(outcome.provider_attempts[1].unknown_severity_normalized,
                         ("advisory_issues[0].severity",))
        self.assertEqual((router.groq_calls, router.local_calls), (1, 1))

    def test_valid_new_groq_does_not_call_local(self) -> None:
        router = Router(initial(approved=True), "local must not be called")
        outcome = CodeReviewer(router).review_with_attempts(self.request)
        self.assertTrue(outcome.result.approved)
        self.assertEqual((router.groq_calls, router.local_calls), (1, 0))

    def test_initial_and_followup_prompt_contracts_exclude_legacy_issues(self) -> None:
        for prompt in (
            CodeReviewer.build_prompt(self.request),
            CodeReviewer.build_followup_prompt(replace(self.request, acceptance_state=self.state)),
        ):
            payload = json.loads(prompt.split("<JARVIS_DATA>", 1)[1].split("</JARVIS_DATA>", 1)[0])
            self.assertNotIn("issues", payload)
            self.assertIn("info | low | medium | high | critical", prompt)


if __name__ == "__main__":
    unittest.main()
