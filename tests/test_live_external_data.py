"""Live external-data authoring gates; all transport and research data are synthetic."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from jarvis.core.code_reviewer import CodeReviewer, CodeReviewRequest
from jarvis.core.code_validation import LocalCodeValidator, ValidationReport
from jarvis.core.external_data_requirements import (
    requires_live_external_data,
)
from jarvis.core.external_source_research import (
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
    requested_external_source,
)
from jarvis.core.safe_skill_authoring import (
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
)


FIXTURES = Path(__file__).parent / "fixtures"
SIMULATED = json.loads(
    (FIXTURES / "live_data_simulated_tracking.json").read_text(encoding="utf-8")
)
RESEARCH_CASES = json.loads(
    (FIXTURES / "external_source_research_cases.json").read_text(encoding="utf-8")
)
RECORDED_SESSION = json.loads(
    (FIXTURES / "source_repair_real_session.json").read_text(encoding="utf-8")
)
LIVE_REQUEST = SIMULATED["user_request"]
SIMULATED_SOURCE = SIMULATED["source"]
APPROVED_REVIEW = json.dumps(
    {"approved": True, "blocking_issues": [], "advisory_issues": []}
)
VALID_TESTS = "<JARVIS_TESTS>\ndef test_result():\n    assert True\n</JARVIS_TESTS>"
LIVE_REQUEST_URL = "Consulta https://tracking.example.test/ para el estado actual."
RESEARCHED_SOURCE = """import requests

def ejecutar_skill(comando: str = ""):
    response = requests.get("https://tracking.example.test/", timeout=10)
    response.raise_for_status()
    return response.text
"""


def research_result(case_name: str) -> ExternalSourceResearchResult:
    values = dict(RESEARCH_CASES[case_name])
    for name in ("observed_endpoints", "required_parameters", "notes"):
        values[name] = tuple(values[name])
    return ExternalSourceResearchResult(**values)


class Coder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            raise AssertionError("Unexpected coder call.")
        return self.responses.pop(0)


class ReviewRouter:
    groq_api_key: str | None = None

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls = 0
        self.prompts: list[str] = []

    def run_groq_code_review(self, prompt: str) -> str:
        self.prompts.append(prompt)
        self.calls += 1
        return self.responses.pop(0)

    def run_local_reasoning(self, prompt: str) -> str:
        self.prompts.append(prompt)
        self.calls += 1
        if not self.responses:
            raise AssertionError("Unexpected reviewer call.")
        return self.responses.pop(0)


class Researcher:
    def __init__(self, result: object) -> None:
        self.result = result
        self.requests: list[ExternalSourceResearchRequest] = []

    def research(self, request: ExternalSourceResearchRequest) -> object:
        self.requests.append(request)
        return self.result


def html_researcher(source: str = "https://tracking.example.test/") -> Researcher:
    return Researcher(
        ExternalSourceResearchResult(
            source=source,
            access_method="HTTP GET of the provided page",
            response_format="HTML",
            confidence=0.8,
        )
    )


class LiveExternalDataTests(unittest.TestCase):
    def validate(self, source: str, request: str = LIVE_REQUEST):
        return LocalCodeValidator().validate_dynamic_skill_source(
            source, user_request=request
        )

    def test_live_request_classifier_distinguishes_live_from_conceptual(self) -> None:
        live = (
            "consulta 1688track",
            "Cuando me pregunten por mi paquete, consultes 1688track usando OXCGH6082081H.",
            "mira la última versión publicada de Ollama",
            "dime el precio actual de BTC",
            "What is the current weather in Paris?",
            "consulta una web de tracking real y dime el estado actual",
        )
        for request in live:
            with self.subTest(request=request):
                self.assertTrue(requires_live_external_data(request))
        self.assertEqual(
            requested_external_source(live[1]),
            "1688track",
        )
        self.assertFalse(requires_live_external_data("Qué es Bitcoin?"))
        self.assertFalse(requires_live_external_data("Explica qué es una API REST."))
        self.assertFalse(requires_live_external_data("Define el concepto de inflación."))

    def test_real_shanghai_tracking_fixture_fails_validation(self) -> None:
        report = self.validate(SIMULATED_SOURCE)
        self.assertFalse(report.success)
        failed = {
            check.name: check.details
            for check in report.checks
            if not check.success
        }
        self.assertEqual(
            failed["dynamic_external_data"],
            "dynamic_external_data: simulated/mock data cannot satisfy a live-data requirement",
        )

    def test_simulated_mock_and_literal_only_sources_fail(self) -> None:
        sources = {
            "mock_comment": (
                "def ejecutar_skill():\n"
                "    # mocked current weather\n"
                "    return {'temperature': 22}\n"
            ),
            "literal_only": (
                "def ejecutar_skill():\n"
                "    location = 'Shanghai, China'\n"
                "    status = 'En route'\n"
                "    eta = '3 days'\n"
                "    return {'location': location, 'status': status, 'eta': eta}\n"
            ),
            "hardcoded_version": (
                "def ejecutar_skill():\n"
                "    return {'version': '9.9.9', 'release_notes': 'Latest release'}\n"
            ),
            "hardcoded_weather": (
                "def ejecutar_skill():\n"
                "    temperature = 22\n"
                "    condition = 'sunny'\n"
                "    return {'temperature': temperature, 'condition': condition}\n"
            ),
        }
        for name, source in sources.items():
            with self.subTest(name=name):
                report = self.validate(source)
                check = next(item for item in report.checks if item.name == "dynamic_external_data")
                self.assertFalse(check.success)
                self.assertIn("dynamic_external_data:", check.details)

    def test_requests_get_acquisition_must_flow_into_result(self) -> None:
        valid_source = """import requests
def ejecutar_skill():
    response = requests.get('https://api.example.test/data', timeout=5)
    response.raise_for_status()
    data = response.json()
    return data
"""
        check = next(
            item for item in self.validate(valid_source).checks
            if item.name == "dynamic_external_data"
        )
        self.assertTrue(check.success, check.details)

        unused_acquisition = """import requests
def ejecutar_skill():
    requests.get('https://api.example.test/data', timeout=5)
    return {'location': 'Shanghai'}
"""
        report = self.validate(unused_acquisition)
        check = next(
            item for item in report.checks if item.name == "dynamic_external_data"
        )
        self.assertFalse(check.success)
        self.assertIn("does not flow into the returned result", check.details)

    def test_urllib_acquisition_can_continue(self) -> None:
        source = """import urllib.request
def ejecutar_skill():
    response = urllib.request.urlopen('https://example.test/data', timeout=5)
    body = response.read().decode('utf-8')
    return body
"""
        check = next(
            item for item in self.validate(source).checks
            if item.name == "dynamic_external_data"
        )
        self.assertTrue(check.success, check.details)

    def test_native_web_search_tool_acquisition_can_continue(self) -> None:
        source = """from jarvis.tools.web.web_search import WebSearchTool
def ejecutar_skill():
    tool = WebSearchTool()
    result = tool.execute(query='current package tracking')
    return result.content
"""
        check = next(
            item for item in self.validate(source).checks
            if item.name == "dynamic_external_data"
        )
        self.assertTrue(check.success, check.details)

    def test_non_live_constants_and_conceptual_explanations_are_not_rejected(self) -> None:
        ordinary = "def ejecutar_skill():\n    return {'meaning': 'a fixed concept'}\n"
        for request in ("Return a fixed greeting.", "Qué es Bitcoin?"):
            with self.subTest(request=request):
                self.assertTrue(self.validate(ordinary, request).success)

    def test_version_checker_with_acquisition_passes_external_data_check(self) -> None:
        source = """import requests
def ejecutar_skill():
    response = requests.get('https://api.example.test/v1/version')
    return response.json()
"""
        check = next(
            item for item in self.validate(
                source, "Comprueba la última versión publicada de Ollama."
            ).checks
            if item.name == "dynamic_external_data"
        )
        self.assertTrue(check.success, check.details)

    def test_authoring_rejects_simulation_before_calling_reviewer(self) -> None:
        coder = Coder([SIMULATED_SOURCE])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=html_researcher(),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST))
        self.assertFalse(result.success)
        self.assertFalse(result.validation_reports[0].success)
        self.assertEqual(router.calls, 0)
        self.assertEqual(result.diagnostics[0].review_attempts, 0)
        self.assertEqual(result.diagnostics[0].review_skipped_reason, "invalid_source_functionality")

    def test_recorded_tracking_simulation_is_rejected_before_any_review(self) -> None:
        first_source = RECORDED_SESSION["sources"][0]
        recorded_request = RECORDED_SESSION["request"]
        coder = Coder([first_source] * 4)
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=html_researcher("https://exampletrack.example.test/"),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(recorded_request))
        self.assertFalse(result.success)
        self.assertGreaterEqual(len(result.validation_reports), 1)
        self.assertTrue(
            any(
                not check.success and check.name == "dynamic_external_data"
                for check in result.validation_reports[0].checks
            )
        )
        self.assertTrue(
            any("no external acquisition path" in check.details
                for check in result.validation_reports[0].checks
                if check.name == "dynamic_external_data")
        )
        self.assertTrue(all(item.review_attempts == 0 for item in result.diagnostics))
        self.assertEqual(router.calls, 0)

    def test_reviewer_cannot_approve_a_live_data_source_without_acquisition(self) -> None:
        router = ReviewRouter([APPROVED_REVIEW])
        reviewer = CodeReviewer(router)
        result = reviewer.review(
            CodeReviewRequest(
                user_request=LIVE_REQUEST,
                implementation_summary="Return current tracking data.",
                code_diff=SIMULATED_SOURCE,
                validation_report=ValidationReport(True, ()),
            )
        )
        self.assertFalse(result.approved)
        self.assertEqual(result.reviewer_used, "deterministic")
        self.assertEqual(router.calls, 0)
        self.assertTrue(result.blocking_findings)

    def test_source_repair_receives_exact_external_data_failure(self) -> None:
        altered_fake = SIMULATED_SOURCE.replace("Shanghai, China", "Paris, France")
        coder = Coder([SIMULATED_SOURCE, altered_fake])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=html_researcher(),
            max_seconds=60,
            max_source_repairs=1,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST))
        self.assertFalse(result.success)
        self.assertEqual(len(result.validation_reports), 2)
        self.assertTrue(all(not report.success for report in result.validation_reports))
        self.assertIn("dynamic_external_data:", coder.prompts[1])
        self.assertIn("MANDATORY LIVE-DATA REPAIR", coder.prompts[1])
        self.assertIn("Do not repair this by changing, moving, or relabeling literal/fake values", coder.prompts[1])
        self.assertEqual(router.calls, 0)

    def test_initial_prompt_warns_against_invented_live_data(self) -> None:
        coder = Coder([])
        service = SafeSkillAuthoringService(coder, diagnostic_sink=lambda _message: None)
        prompt = service.build_coder_prompt(
            SkillAuthoringRequest("dime el precio actual de BTC"),
            iteration=1,
        )
        self.assertIn("LIVE EXTERNAL DATA REQUIREMENT", prompt)
        self.assertIn("Do not invent an endpoint or source interface", prompt)
        self.assertIn("never substitute simulated", " ".join(prompt.lower().split()))

    def test_live_authoring_without_research_provider_fails_before_generation(self) -> None:
        coder = Coder([SIMULATED_SOURCE])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST))
        self.assertFalse(result.success)
        self.assertIn(
            "No hay un proveedor de investigación externa configurado.",
            result.failure_reason or "",
        )
        self.assertEqual(coder.prompts, [])
        self.assertEqual(router.calls, 0)

    def test_research_fixture_shapes_are_synthetic_and_data_only(self) -> None:
        for case_name in ("known_api", "static_html", "spa_known_endpoint"):
            with self.subTest(case=case_name):
                result = research_result(case_name)
                self.assertTrue(result.sufficient)
                self.assertIn('"observed_endpoints"', result.to_prompt_context())
        spa = research_result("spa_known_endpoint")
        self.assertEqual(spa.observed_endpoints, ("https://tracking.example.test/api/track",))
        self.assertEqual(research_result("static_html").observed_endpoints, ())

    def test_verified_research_facts_are_passed_to_coder_without_endpoint_inference(self) -> None:
        html_facts = ExternalSourceResearchResult(
            source="https://tracking.example.test/",
            access_method="HTTP GET of the provided page",
            observed_endpoints=(),
            response_format="HTML",
            notes=("No programmatic tracking endpoint was observed.",),
            confidence=0.8,
            final_url="https://tracking.example.test/",
            http_status=200,
            content_type="text/html",
        )
        researcher = Researcher(html_facts)
        coder = Coder([RESEARCHED_SOURCE, VALID_TESTS])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=researcher,
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST_URL))
        self.assertTrue(result.success, result.failure_reason)
        self.assertEqual(researcher.requests[0].source, "https://tracking.example.test/")
        prompt = coder.prompts[0]
        self.assertIn("VERIFIED EXTERNAL SOURCE FACTS", prompt)
        self.assertIn('"observed_endpoints": []', prompt)
        self.assertIn("do not infer or invent endpoints", prompt)
        self.assertEqual(router.calls, 1)

    def test_research_endpoint_mismatch_fails_validation_before_review(self) -> None:
        researcher = Researcher(research_result("spa_known_endpoint"))
        coder = Coder([RESEARCHED_SOURCE, RESEARCHED_SOURCE])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=researcher,
            max_seconds=60,
            max_source_repairs=1,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST_URL))
        self.assertFalse(result.success)
        external_check = next(
            check
            for check in result.validation_reports[0].checks
            if check.name == "dynamic_external_data"
        )
        self.assertFalse(external_check.success)
        self.assertIn("endpoint not verified", external_check.details)
        self.assertEqual(router.calls, 0)

    def test_observed_endpoint_is_bound_and_can_reach_reviewer(self) -> None:
        researched = ExternalSourceResearchResult(
            source="https://tracking.example.test/",
            access_method="Static first-party JavaScript request to observed route.",
            observed_endpoints=("https://tracking.example.test/api/lookup",),
            response_format="JSON response, observed in synthetic source fixture",
            required_parameters=("tracking_code",),
            confidence=0.8,
        )
        source = """import requests
def ejecutar_skill(comando: str = ""):
    response = requests.get(
        "https://tracking.example.test/api/lookup",
        params={"tracking_code": "TRACK123"},
        timeout=8,
    )
    response.raise_for_status()
    return response.json()
"""
        researcher = Researcher(researched)
        coder = Coder([source, VALID_TESTS])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=researcher,
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(
            SkillAuthoringRequest("Check current tracking at https://tracking.example.test/")
        )
        self.assertTrue(result.success, result.failure_reason)
        self.assertEqual(router.calls, 1)
        self.assertIn('"https://tracking.example.test/api/lookup"', coder.prompts[0])
        self.assertIn('"tracking_code"', coder.prompts[0])
        self.assertIn("VERIFIED EXTERNAL SOURCE FACTS", coder.prompts[0])

    def test_unknown_research_fails_explicitly_without_generating_demo(self) -> None:
        researcher = Researcher(research_result("unknown"))
        coder = Coder([SIMULATED_SOURCE])
        router = ReviewRouter([APPROVED_REVIEW])
        service = SafeSkillAuthoringService(
            coder,
            reviewer=CodeReviewer(router),
            external_source_research=researcher,
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST_URL))
        self.assertFalse(result.success)
        self.assertIn(
            "No pude determinar de forma fiable cómo consultar esta fuente.",
            result.failure_reason or "",
        )
        self.assertEqual(coder.prompts, [])
        self.assertEqual(router.calls, 0)

    def test_research_failure_fails_closed_without_generation(self) -> None:
        class FailedResearch:
            def research(self, request: ExternalSourceResearchRequest):
                self.requested_source = request.source
                raise OSError("offline")

        coder = Coder([SIMULATED_SOURCE])
        service = SafeSkillAuthoringService(
            coder,
            external_source_research=FailedResearch(),
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST_URL))
        self.assertFalse(result.success)
        self.assertIn("OSError: offline", result.failure_reason or "")
        self.assertEqual(coder.prompts, [])

    def test_malformed_research_output_fails_closed(self) -> None:
        researcher = Researcher({"endpoint": "invented"})
        coder = Coder([SIMULATED_SOURCE])
        service = SafeSkillAuthoringService(
            coder,
            external_source_research=researcher,
            max_seconds=60,
            diagnostic_sink=lambda _message: None,
        )
        result = service.author(SkillAuthoringRequest(LIVE_REQUEST_URL))
        self.assertFalse(result.success)
        self.assertIn("External source research failed", result.failure_reason or "")
        self.assertEqual(coder.prompts, [])


if __name__ == "__main__":
    unittest.main()
