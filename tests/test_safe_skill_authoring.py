from __future__ import annotations

import inspect
import json
import unittest
from dataclasses import dataclass

import jarvis.core.safe_skill_authoring as authoring_module
from jarvis.core.code_reviewer import (
    CodeReviewResult,
    ReviewIssue,
    ReviewSeverity,
)
from jarvis.core.code_validation import ValidationCheck, ValidationReport
from jarvis.core.dependency_resolver import DependencyResolver, DependencyStatus
from jarvis.core.safe_skill_authoring import (
    AUTHORING_MAX_SECONDS_ENV,
    DEFAULT_MAX_AUTHORING_SECONDS,
    GeneratedSkillProposal,
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
    get_skill_authoring_max_seconds,
)


REQUEST_TEXT = "Create a skill to summarize supplied notes and remember the previous summary."


def source_response(
    *,
    source: str = "def ejecutar_skill():\n    return 'source'\n",
    name: str = "seguimiento_paquete",
    summary: str = "Consulta el estado del paquete.",
    dependencies: list[str] | None = None,
    prefix: str = "",
) -> str:
    metadata = {
        "skill_name": name,
        "implementation_summary": summary,
        "dependencies": dependencies or [],
    }
    return (
        prefix
        + "<JARVIS_META>\n"
        + json.dumps(metadata)
        + "\n</JARVIS_META>\n<JARVIS_SOURCE>\n"
        + source
        + "</JARVIS_SOURCE>"
    )


def tests_response(source: str = "def test_ejecutar_skill():\n    assert True\n") -> str:
    return "<JARVIS_TESTS>\n" + source + "</JARVIS_TESTS>"


def markdown_source_response() -> str:
    fence = chr(96) * 3
    metadata = {
        "skill_name": "seguimiento_paquete",
        "implementation_summary": "Consulta el estado.",
        "dependencies": [],
    }
    return (
        "Prosa exterior.\n"
        + fence
        + "json\n"
        + json.dumps(metadata)
        + "\n"
        + fence
        + "\n"
        + fence
        + "python\n"
        + "def ejecutar_skill():\n    return 'markdown'\n"
        + fence
    )


def approved_review() -> CodeReviewResult:
    return CodeReviewResult(
        approved=True,
        issues=(),
        reviewer_used="fake",
        cloud_attempted=False,
        cloud_failed=False,
    )


def rejected_review(description: str = "Falta persistir el estado.") -> CodeReviewResult:
    return CodeReviewResult(
        approved=False,
        issues=(
            ReviewIssue(
                severity=ReviewSeverity.HIGH,
                description=description,
                suggested_fix="Persistir antes de responder.",
            ),
        ),
        reviewer_used="fake",
        cloud_attempted=False,
        cloud_failed=False,
    )


class FakeCoder:
    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            raise AssertionError("Unexpected local coder call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeReviewer:
    def __init__(self, responses: list[CodeReviewResult]) -> None:
        self.responses = list(responses)
        self.requests = []

    def review(self, request):
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("Unexpected reviewer call")
        return self.responses.pop(0)

    def diagnose_stagnation(self, request):
        self.requests.append(request)
        return rejected_review("The source did not change.")


class SequencedValidator:
    def __init__(self, reports: list[ValidationReport]) -> None:
        self.reports = list(reports)
        self.calls: list[tuple[str, str]] = []

    def validate_python_source(self, source: str, *, filename: str) -> ValidationReport:
        self.calls.append((filename, source))
        if not self.reports:
            return validation_report(True, "default success")
        return self.reports.pop(0)


class FixedClock:
    def __init__(self, values: list[float]) -> None:
        self.values = list(values)
        self.last = values[-1] if values else 0.0

    def __call__(self) -> float:
        if self.values:
            self.last = self.values.pop(0)
        return self.last


def validation_report(success: bool, details: str) -> ValidationReport:
    return ValidationReport(
        success=success,
        checks=(ValidationCheck("syntax", success, details),),
    )


@dataclass
class ServiceHarness:
    service: SafeSkillAuthoringService
    coder: FakeCoder
    reviewer: FakeReviewer


class SafeSkillAuthoringTests(unittest.TestCase):
    def test_installed_declared_dependency_is_not_unavailable(self) -> None:
        checker = DependencyResolver(
            distribution_version=lambda name: "2.34.2" if name == "requests" else "0",
            find_spec=lambda name: object() if name == "requests" else None,
            packages_distributions=lambda: {"requests": ["requests"]},
        )
        service = SafeSkillAuthoringService(
            FakeCoder([source_response(dependencies=["requests"]), tests_response()]),
            reviewer=FakeReviewer([approved_review()]),
            dependency_resolver=checker,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(REQUEST_TEXT))
        self.assertTrue(result.success)
        self.assertEqual(result.declared_dependencies, ("requests",))
        self.assertEqual(result.unavailable_dependencies, ())
        self.assertEqual(result.dependency_results[0].status, DependencyStatus.AVAILABLE)

    def test_mixed_available_and_missing_dependencies_are_reported_without_installing(self) -> None:
        import importlib.metadata

        def version(name: str) -> str:
            if name == "requests":
                return "2.34.2"
            raise importlib.metadata.PackageNotFoundError(name)

        checker = DependencyResolver(
            distribution_version=version,
            find_spec=lambda name: object() if name == "requests" else None,
            packages_distributions=lambda: {"requests": ["requests"]},
        )
        service = SafeSkillAuthoringService(
            FakeCoder([source_response(dependencies=["requests", "missing-package"]), tests_response()]),
            reviewer=FakeReviewer([approved_review()]),
            dependency_resolver=checker,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(REQUEST_TEXT))
        self.assertTrue(result.success)
        self.assertEqual(result.unavailable_dependencies, ("missing-package",))
        self.assertEqual(
            tuple(item.status for item in result.dependency_results),
            (DependencyStatus.AVAILABLE, DependencyStatus.MISSING),
        )

    def setUp(self) -> None:
        self.request = SkillAuthoringRequest(
            user_request=REQUEST_TEXT,
            existing_skill_name="seguimiento_paquete",
            relevant_context="El estado debe conservarse entre consultas.",
        )

    def make_service(
        self,
        responses: list[str | Exception],
        reviews: list[CodeReviewResult],
        *,
        validator: object | None = None,
        clock: FixedClock | None = None,
        max_seconds: float = 60.0,
        max_iterations: int | None = None,
    ) -> ServiceHarness:
        coder = FakeCoder(responses)
        reviewer = FakeReviewer(reviews)
        options: dict[str, object] = {
            "reviewer": reviewer,
            "max_seconds": max_seconds,
            "diagnostic_sink": lambda _message: None,
        }
        if validator is not None:
            options["validator"] = validator
        if clock is not None:
            options["clock"] = clock
        if max_iterations is not None:
            options["max_iterations"] = max_iterations
        return ServiceHarness(SafeSkillAuthoringService(coder, **options), coder, reviewer)

    def test_source_phase_does_not_require_tests_and_then_enters_tests(self) -> None:
        harness = self.make_service(
            [source_response(), tests_response()],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertEqual([item.phase for item in result.diagnostics], ["source_initial", "tests"])
        self.assertNotIn("<JARVIS_TESTS>", harness.coder.prompts[0])
        self.assertNotIn("<JARVIS_META>", harness.coder.prompts[0])
        self.assertIn("<JARVIS_SOURCE>", harness.coder.prompts[0])
        self.assertIn("<JARVIS_TESTS>", harness.coder.prompts[1])

    def test_source_markdown_and_outer_prose_are_recoverable(self) -> None:
        harness = self.make_service(
            [markdown_source_response(), tests_response()],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertIn("markdown", result.proposal.source_code if result.proposal else "")

    def test_tests_are_not_requested_before_source_is_approved(self) -> None:
        harness = self.make_service(
            [source_response(), source_response(), source_response()],
            [rejected_review(), rejected_review(), rejected_review()],
        )
        result = harness.service.author(self.request)
        self.assertFalse(result.success)
        self.assertTrue(all("Produce TESTS only." not in prompt for prompt in harness.coder.prompts))
        self.assertEqual(len(result.review_results), 3)

    def test_tests_phase_accepts_python_fence(self) -> None:
        fence = chr(96) * 3
        tests = fence + "python\ndef test_ok():\n    assert True\n" + fence
        harness = self.make_service([source_response(), tests], [approved_review()])
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertIn("test_ok", result.proposal.tests_source if result.proposal else "")

    def test_tests_repair_keeps_source_immutable(self) -> None:
        approved = "def ejecutar_skill():\n    return 'approved-source'\n"
        harness = self.make_service(
            [
                source_response(source=approved),
                tests_response("def broken(:\n"),
                tests_response(),
            ],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertEqual(result.proposal.source_code if result.proposal else None, approved)
        test_prompts = [prompt for prompt in harness.coder.prompts if "Produce TESTS only." in prompt]
        self.assertEqual(len(test_prompts), 2)
        self.assertIn(approved, test_prompts[0])
        self.assertIn(approved, test_prompts[1])
        self.assertNotIn("<JARVIS_SOURCE>", test_prompts[1])

    def test_source_repair_never_requests_tests(self) -> None:
        harness = self.make_service(
            [
                source_response(source="def ejecutar_skill():\n    return 'first'\n"),
                source_response(source="def ejecutar_skill():\n    return 'fixed'\n"),
                tests_response(),
            ],
            [rejected_review(), approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertIn("PRIOR SOURCE TO REPAIR", harness.coder.prompts[1])
        self.assertNotIn("<JARVIS_TESTS>", harness.coder.prompts[1])

    def test_final_contract_preserves_metadata_dependencies_source_and_tests(self) -> None:
        source = "def ejecutar_skill():\n    return 'stable'\n"
        tests = "def test_stable():\n    assert True\n"
        harness = self.make_service(
            [
                source_response(
                    source=source,
                    summary="Stable summary.",
                    dependencies=["declared-package"],
                ),
                tests_response(tests),
            ],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertIsInstance(result.proposal, GeneratedSkillProposal)
        self.assertEqual(result.proposal.source_code if result.proposal else None, source)
        self.assertEqual(result.proposal.tests_source if result.proposal else None, tests)
        self.assertEqual(result.proposal.dependencies if result.proposal else None, ("declared-package",))
        self.assertEqual(result.proposal.implementation_summary if result.proposal else None, "Stable summary.")

    def test_source_review_receives_verbatim_user_request_and_not_tests(self) -> None:
        harness = self.make_service(
            [source_response(), tests_response()],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertEqual(harness.reviewer.requests[0].user_request, REQUEST_TEXT)
        self.assertNotIn("PROPOSED TESTS", harness.reviewer.requests[0].code_diff)

    def test_structural_counters_are_independent_per_phase(self) -> None:
        harness = self.make_service(
            [
                "not structured",
                "still not structured",
                source_response(),
                "not tests",
                tests_response(),
            ],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        source_counters = [
            item.structural_retries for item in result.diagnostics if item.phase in {"source_initial", "source_repair"}
        ]
        tests_counters = [
            item.structural_retries for item in result.diagnostics if item.phase == "tests"
        ]
        self.assertEqual(source_counters, [1, 2, 0])
        self.assertEqual(tests_counters, [1, 0])

    def test_global_deadline_covers_source_and_tests_without_second_budget(self) -> None:
        clock = FixedClock([0.0, 0.0, 0.0, 0.0, 1.0])
        harness = self.make_service(
            [source_response(), tests_response()],
            [approved_review()],
            clock=clock,
            max_seconds=1.0,
        )
        result = harness.service.author(self.request)
        self.assertFalse(result.success)
        self.assertIn("time budget exhausted", result.failure_reason or "")
        self.assertFalse(any("Produce TESTS only." in prompt for prompt in harness.coder.prompts))

    def test_source_stagnation_remains_fail_closed(self) -> None:
        repeated = source_response(source="def ejecutar_skill():\n    return 'same'\n")
        harness = self.make_service(
            [repeated, repeated, repeated, repeated],
            [rejected_review(), rejected_review(), rejected_review(), rejected_review()],
        )
        result = harness.service.author(self.request)
        self.assertFalse(result.success)
        self.assertIn("stalled", result.failure_reason or "")
        self.assertEqual(len(harness.coder.prompts), 4)

    def test_invalid_source_never_reaches_tests(self) -> None:
        invalid = source_response(source="def broken(:\n")
        harness = self.make_service(
            [invalid, invalid, invalid],
            [approved_review(), approved_review(), approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertFalse(result.success)
        self.assertGreaterEqual(len(result.validation_reports), 1)
        self.assertFalse(result.validation_reports[0].success)
        self.assertGreaterEqual(len(harness.reviewer.requests), 1)
        self.assertTrue(all("Produce TESTS only." not in prompt for prompt in harness.coder.prompts))

    def test_local_coder_failure_is_structured(self) -> None:
        harness = self.make_service([RuntimeError("coder unavailable")], [])
        result = harness.service.author(self.request)
        self.assertFalse(result.success)
        self.assertIn("Local coder failed", result.failure_reason or "")
        self.assertEqual(result.validation_reports, ())

    def test_more_than_three_source_repairs_can_succeed_before_deadline(self) -> None:
        responses = [
            source_response(source=f"def ejecutar_skill():\n    return {index}\n")
            for index in range(1, 6)
        ] + [tests_response()]
        harness = self.make_service(
            responses,
            [rejected_review(), rejected_review(), rejected_review(), rejected_review(), approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)
        self.assertEqual(result.iterations, 6)
        self.assertEqual([item.phase for item in result.diagnostics][-1], "tests")

    def test_authoring_budget_configuration_remains_authoring_only(self) -> None:
        self.assertEqual(get_skill_authoring_max_seconds({}), DEFAULT_MAX_AUTHORING_SECONDS)
        self.assertEqual(
            get_skill_authoring_max_seconds({AUTHORING_MAX_SECONDS_ENV: "45"}),
            45.0,
        )
        self.assertEqual(
            get_skill_authoring_max_seconds({AUTHORING_MAX_SECONDS_ENV: "invalid"}),
            DEFAULT_MAX_AUTHORING_SECONDS,
        )

    def test_service_never_deploys_or_executes_candidate_code(self) -> None:
        source = inspect.getsource(authoring_module)
        for forbidden in (
            "exec(",
            "eval(",
            "importlib",
            "subprocess",
            "pip install",
            "DynamicSkillBuilder",
            "SafeSkillDeployment",
            "SkillManager",
            "dynamic_skill_authoring_enabled",
            "requests.",
            "klipper",
        ):
            self.assertNotIn(forbidden, source)
        harness = self.make_service(
            [source_response(source="import missing_package\ndef ejecutar_skill():\n    return 'ok'\n"), tests_response()],
            [approved_review()],
        )
        result = harness.service.author(self.request)
        self.assertTrue(result.success)

    def test_dynamic_interaction_evidence_included_in_coder_prompt(self) -> None:
        from jarvis.core.external_source_research import ExternalSourceResearchResult
        from jarvis.core.safe_skill_authoring import format_dynamic_evidence_prompt

        dynamic_evidence = {
            "interaction_performed": True,
            "probe_value": "OXCGH6082081H",
            "input_selector": "input.el-input__inner",
            "button_selector": "button.el-button--primary",
            "result_selector": ".track-detail-card",
            "result_text_sample": "Paquete entregado en destino",
            "result_dom_subtree": "<div class='track-detail-card'>...</div>",
            "captured_api": {
                "endpoint": "https://api.example.test/v1/track",
                "clean_endpoint": "https://api.example.test/v1/track",
                "http_method": "POST",
                "status": 200,
                "sample_keys": ["code", "transit_list"],
                "json_schema": {"code": "integer", "transit_list": [{"station": "string"}]},
            },
        }

        research = ExternalSourceResearchResult(
            source="https://www.1688track.com/#/",
            access_method="Dynamic SPA interaction probe",
            observed_endpoints=("https://api.example.test/v1/track",),
            response_format="JSON (dynamic API)",
            confidence=0.85,
            research_status="sufficient",
            final_url="https://www.1688track.com/#/track",
            dynamic_interaction_evidence=dynamic_evidence,
        )

        prompt_part = format_dynamic_evidence_prompt(research)
        self.assertIn("input.el-input__inner", prompt_part)
        self.assertIn("button.el-button--primary", prompt_part)
        self.assertIn(".track-detail-card", prompt_part)
        self.assertIn("https://api.example.test/v1/track", prompt_part)
        self.assertIn("SecureWebSession", prompt_part)
        self.assertIn("DO NOT GUESS OR INVENT SELECTORS", prompt_part)

        class Coder:
            def __init__(self):
                self.prompts = []

            def run_local_coding(self, prompt: str) -> str:
                self.prompts.append(prompt)
                return source_response(
                    source="from jarvis.core.security.secure_browser import SecureWebSession\n"
                           "def ejecutar_skill():\n"
                           "    session = SecureWebSession()\n"
                           "    return session.interact_and_capture_sync('https://www.1688track.com/#/', 'OXCGH6082081H')\n"
                )

        class Researcher:
            def research(self, req):
                return research

        coder = Coder()
        service = SafeSkillAuthoringService(
            coder,
            external_source_research=Researcher(),
        )
        req = SkillAuthoringRequest("Rastrea paquete con OXCGH6082081H en https://www.1688track.com/#/")
        result = service.author(req)

        self.assertTrue(len(coder.prompts) >= 1)
        first_prompt = coder.prompts[0]
        self.assertIn("input.el-input__inner", first_prompt)
        self.assertIn("button.el-button--primary", first_prompt)
        self.assertIn(".track-detail-card", first_prompt)
        self.assertIn("https://api.example.test/v1/track", first_prompt)
        self.assertIn("transit_list", first_prompt)


if __name__ == "__main__":
    unittest.main()
