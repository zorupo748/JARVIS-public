"""Tests for SkillErrorHandler, model triage routing, and SecureWebSession SPA research."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from jarvis.core.external_source_research import (
    ExternalEndpointObservation,
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
)
from jarvis.core.safe_skill_authoring import (
    SkillAuthoringRequest,
    SkillAuthoringResult,
)
from jarvis.core.safe_skill_execution import (
    ExecutionFailureKind,
    SafeSkillExecutionRequest,
    SafeSkillExecutionResult,
)
from jarvis.core.safe_skill_pipeline import SafeSkillPipeline
from jarvis.core.security.secure_browser import SecureWebSession
from jarvis.core.security.url_validator import URLValidator
from jarvis.core.skill_error_handler import (
    SkillErrorHandler,
    SkillTriageDecision,
    clean_executive_summary,
    generate_fallback_summary,
    sanitize_error_text,
)
from jarvis.core.trusted_external_source_research import (
    TrustedWebExternalSourceResearchProvider,
)
from jarvis.skills.skill_builder import DynamicSkillBuilder
from jarvis.tools.web.http_tool import ResearchFetchResponse


class SkillErrorHandlerTests(unittest.TestCase):
    def test_sanitize_error_text_removes_paths_and_traces(self) -> None:
        raw_error = (
            "Traceback (most recent call last):\n"
            "  File \"E:\\JARVIS\\src\\jarvis\\core\\trusted_external_source_research.py\", line 345, in research\n"
            "    raise ValueError(\"insufficient_research: GET returned HTTP 200 from https://1688track.com/#/\")\n"
            "ValueError: insufficient_research: GET returned HTTP 200 from https://1688track.com/#/"
        )
        cleaned = sanitize_error_text(raw_error)
        self.assertNotIn("Traceback", cleaned)
        self.assertNotIn("E:\\JARVIS", cleaned)
        self.assertNotIn("File \"", cleaned)
        self.assertIn("insufficient_research", cleaned)

    def test_clean_executive_summary_single_paragraph_no_leaks(self) -> None:
        raw = (
            "No he podido consultar el envío.\n\n"
            "Detalles internos en E:\\JARVIS\\main.py line 40.\n"
            "ValueError: error en la API externa."
        )
        summary = clean_executive_summary(raw)
        self.assertNotIn("\n", summary)
        self.assertNotIn("E:\\JARVIS", summary)
        self.assertNotIn("ValueError", summary)
        self.assertTrue(len(summary) > 10)

    def test_generate_fallback_summary_for_insufficient_research(self) -> None:
        summary = generate_fallback_summary(
            "insufficient_research: GET returned HTTP 200 from https://1688track.com",
            user_request="consulta 1688track con OX123",
            skill_name="track_package",
            phase="creación",
        )
        self.assertNotIn("ValueError", summary)
        self.assertNotIn("HTTP 200", summary)
        self.assertIn("alternativa", summary.lower())
        self.assertTrue(len(summary.splitlines()) == 1)

    def test_triage_uses_reasoning_model_when_available(self) -> None:
        mock_router = MagicMock()
        mock_router.route.return_value = (
            '{"can_repair": true, "repair_strategy": "dynamic_browser_inspection", '
            '"root_cause": "SPA JavaScript no ejecutado", '
            '"executive_summary": "La web es una SPA interactiva; se recomienda inspección dinámica."}'
        )
        handler = SkillErrorHandler(model_router=mock_router)
        decision = handler.triage(
            "insufficient_research: GET returned HTTP 200",
            phase="creación",
            user_request="rastrea mi paquete en 1688track",
            skill_name="track_package",
        )
        self.assertTrue(decision.can_repair)
        self.assertEqual(decision.repair_strategy, "dynamic_browser_inspection")
        self.assertIn("SPA interactiva", decision.executive_summary)
        mock_router.route.assert_called_once()

    def test_triage_auto_repair_callback_execution(self) -> None:
        mock_router = MagicMock()
        mock_router.route.return_value = (
            '{"can_repair": true, "repair_strategy": "dynamic_browser_inspection", '
            '"root_cause": "SPA", "executive_summary": "Auto-reparando..."}'
        )
        repair_called = []

        def fake_repair(strategy: str):
            repair_called.append(strategy)
            return "repaired_success"

        handler = SkillErrorHandler(model_router=mock_router)
        decision = handler.triage(
            "insufficient_research",
            auto_repair_callback=fake_repair,
        )
        self.assertEqual(repair_called, ["dynamic_browser_inspection"])
        self.assertEqual(decision.repaired_result, "repaired_success")

    def test_safe_skill_pipeline_intercepts_raw_authoring_exceptions(self) -> None:
        mock_authoring = MagicMock()
        mock_authoring.author.side_effect = ValueError(
            "insufficient_research: GET returned HTTP 200 from https://1688track.com/#/; JavaScript was not executed."
        )
        pipeline = SafeSkillPipeline(
            mock_authoring,
            MagicMock(),
            MagicMock(),
        )
        result = pipeline.author("consulta 1688track")
        self.assertFalse(result.success)
        self.assertNotIn("ValueError", result.failure_reason)
        self.assertNotIn("HTTP 200", result.failure_reason)
        self.assertIn("alternativa", result.failure_reason.lower())

    def test_safe_skill_pipeline_sanitizes_failed_authoring_result_reason(self) -> None:
        mock_authoring = MagicMock()
        mock_authoring.author.return_value = SkillAuthoringResult(
            success=False,
            proposal=None,
            iterations=0,
            validation_reports=(),
            review_results=(),
            failure_reason="External source research failed: ValueError: insufficient_research: GET returned HTTP 200",
        )
        pipeline = SafeSkillPipeline(
            mock_authoring,
            MagicMock(),
            MagicMock(),
        )
        result = pipeline.author("consulta 1688track")
        self.assertFalse(result.success)
        self.assertNotIn("ValueError", result.failure_reason)
        self.assertNotIn("HTTP 200", result.failure_reason)

    def test_safe_skill_pipeline_intercepts_execution_exceptions(self) -> None:
        mock_execution = MagicMock()
        mock_execution.execute.side_effect = RuntimeError(
            "Traceback: File E:\\JARVIS\\src\\skill.py line 12: ZeroDivisionError"
        )
        pipeline = SafeSkillPipeline(
            MagicMock(),
            MagicMock(),
            mock_execution,
        )
        identity = MagicMock()
        identity.user_id = "owner"
        result = pipeline.execute_installed("skill_fallida", identity=identity)
        self.assertFalse(result.executed)
        self.assertEqual(result.failure_kind, ExecutionFailureKind.SKILL_EXCEPTION)
        self.assertNotIn("Traceback", result.failure_reason)
        self.assertNotIn("E:\\JARVIS", result.failure_reason)

    def test_dynamic_skill_builder_handles_errors_gracefully(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            builder = DynamicSkillBuilder(Path(tmpdir))
            summary = builder.generate_and_load_skill(
                "crear skill que falle",
                router=None,
                skill_manager=None,
                simulacion=False,
            )
            self.assertNotIn("Traceback", summary)
            self.assertNotIn("File \"", summary)
            self.assertTrue(len(summary.splitlines()) == 1)


class DynamicSPAResearchTests(unittest.TestCase):
    def test_url_validator_preserves_fragment_when_requested(self) -> None:
        validator = URLValidator()
        url = "https://1688track.com/#/tracking"
        stripped = validator.validate_and_normalize(url, preserve_fragment=False)
        self.assertEqual(stripped, "https://1688track.com/")

        preserved = validator.validate_and_normalize(url, preserve_fragment=True)
        self.assertEqual(preserved, "https://1688track.com/#/tracking")

    def test_trusted_researcher_detects_spa_and_uses_secure_web_session(self) -> None:
        fake_http_response = ResearchFetchResponse(
            requested_url="https://1688track.com/",
            final_url="https://1688track.com/",
            status_code=200,
            content_type="text/html; charset=utf-8",
            body=b"<html><head><script src='/app.js'></script></head><body><div id='app'></div></body></html>",
        )
        mock_http_tool = MagicMock()
        mock_http_tool.fetch_for_research.return_value = fake_http_response

        mock_browser = MagicMock()
        mock_browser.inspect_spa_sync.return_value = {
            "dom_content": (
                "<html><body><div id='app'>"
                "<input id='track_input' name='tracking_number' placeholder='Enter tracking number'>"
                "<button id='track_btn'>Search</button>"
                "</div></body></html>"
            ),
            "final_url": "https://1688track.com/#/track",
            "title": "1688track Logistics Platform",
            "search_fields": [
                {
                    "type": "text",
                    "name": "tracking_number",
                    "id": "track_input",
                    "placeholder": "Enter tracking number",
                    "class": "track-box",
                }
            ],
            "captured_requests": [
                {
                    "url": "https://api.1688track.com/v1/track?code=OX123",
                    "method": "GET",
                    "resource_type": "fetch",
                }
            ],
        }

        provider = TrustedWebExternalSourceResearchProvider(
            http_tool=mock_http_tool,
            browser_session=mock_browser,
        )

        request = ExternalSourceResearchRequest(
            user_request="Consulta mi paquete en https://1688track.com/#/",
            source="https://1688track.com/#/",
            capability="Consultar tracking de 1688track",
        )

        result = provider.research(request)
        self.assertTrue(result.sufficient)
        self.assertEqual(result.research_status, "sufficient")
        self.assertIn("https://api.1688track.com/v1/track", result.observed_endpoints)
        self.assertIn("tracking_number", result.required_parameters)
        self.assertEqual(result.page_kind, "rendered_spa")
        mock_browser.inspect_spa_sync.assert_called_once_with("https://1688track.com/#/")

    def test_trusted_researcher_handles_spa_oversized_assets(self) -> None:
        fake_page = ResearchFetchResponse(
            requested_url="https://spa-service.example.test/",
            final_url="https://spa-service.example.test/",
            status_code=200,
            content_type="text/html; charset=utf-8",
            body=b"<html><head><script src='/big_bundle.js'></script></head><body><div id='root'></div></body></html>",
        )
        fake_js = ResearchFetchResponse(
            requested_url="https://spa-service.example.test/big_bundle.js",
            final_url="https://spa-service.example.test/big_bundle.js",
            status_code=200,
            content_type="application/javascript",
            body=b"x" * 600000,
            truncated=True,
            content_length=1200000,
        )
        mock_http_tool = MagicMock()
        mock_http_tool.fetch_for_research.side_effect = [fake_page, fake_js]

        mock_browser = MagicMock()
        mock_browser.inspect_spa_sync.return_value = {
            "dom_content": (
                "<html><body><div id='root'>"
                "<input name='query_id' placeholder='Search ID'>"
                "</div></body></html>"
            ),
            "final_url": "https://spa-service.example.test/#/dashboard",
            "title": "SPA Service",
            "search_fields": [{"type": "text", "name": "query_id", "placeholder": "Search ID"}],
            "captured_requests": [
                {
                    "url": "https://spa-service.example.test/api/data?id=123",
                    "method": "GET",
                    "resource_type": "xhr",
                }
            ],
        }

        provider = TrustedWebExternalSourceResearchProvider(
            http_tool=mock_http_tool,
            browser_session=mock_browser,
        )

        request = ExternalSourceResearchRequest(
            user_request="Consulta datos en https://spa-service.example.test/#/",
            source="https://spa-service.example.test/#/",
            capability="Consultar datos SPA",
        )

        result = provider.research(request)
        self.assertTrue(result.sufficient)
        self.assertEqual(result.research_status, "sufficient")
        self.assertIn("https://spa-service.example.test/api/data", result.observed_endpoints)
        mock_browser.inspect_spa_sync.assert_called_once()


if __name__ == "__main__":
    unittest.main()
