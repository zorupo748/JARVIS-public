from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.core.authoring_debug import (
    AUTHORING_DEBUG_ENV,
    AuthoringDebugSession,
    _request_slug,
    skill_authoring_debug_enabled,
)
from jarvis.core.code_reviewer import CodeReviewResult
from jarvis.core.safe_skill_authoring import (
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
)


class FakeCoder:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.prompts: list[str] = []

    def run_local_coding(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.responses:
            if "Produce TESTS only." in prompt:
                return tests_response()
            raise AssertionError("Unexpected local coder call")
        return self.responses.pop(0)


class ApprovingReviewer:
    def review(self, _request: object) -> CodeReviewResult:
        return CodeReviewResult(
            approved=True,
            issues=(),
            reviewer_used="fake",
            cloud_attempted=False,
            cloud_failed=False,
        )


def proposal_response(
    *,
    source: str = "def ejecutar_skill():\n    return 'ok'\n",
    tests: str | None = None,
) -> str:
    response = (
        "<JARVIS_META>\n"
        '{"skill_name":"debug_skill","implementation_summary":"debug proposal","dependencies":[]}'
        "\n</JARVIS_META>\n"
        "<JARVIS_SOURCE>\n"
        + source
        + "</JARVIS_SOURCE>\n"
        "<JARVIS_TESTS>\n"
        + (tests or "")
        + "</JARVIS_TESTS>"
    )
    return response


def tests_response(source: str = "def test_debug_skill():\n    assert True\n") -> str:
    return "<JARVIS_TESTS>\n" + source + "</JARVIS_TESTS>"

class SkillAuthoringDebugTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = SkillAuthoringRequest(user_request="Crea una skill de prueba.")
        self.reviewer = ApprovingReviewer()

    def _service(
        self,
        responses: list[str],
        *,
        debug_root: Path,
        lines: list[str] | None = None,
    ) -> SafeSkillAuthoringService:
        return SafeSkillAuthoringService(
            FakeCoder(responses),
            reviewer=self.reviewer,
            max_iterations=10,
            debug_root=debug_root,
            diagnostic_sink=(lines.append if lines is not None else lambda _line: None),
        )

    def _session_directory(self, debug_root: Path) -> Path:
        sessions = list(debug_root.iterdir())
        self.assertEqual(len(sessions), 1)
        return sessions[0]

    def test_debug_is_disabled_by_default_and_creates_no_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            service = self._service([proposal_response()], debug_root=debug_root)
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: ""}, clear=False):
                result = service.author(self.request)
            self.assertTrue(result.success)
            self.assertFalse(debug_root.exists())

    def test_debug_flag_accepts_common_true_values(self) -> None:
        for value in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(value=value):
                self.assertTrue(skill_authoring_debug_enabled({AUTHORING_DEBUG_ENV: value}))
        self.assertFalse(skill_authoring_debug_enabled({AUTHORING_DEBUG_ENV: "false"}))

    def test_debug_creates_one_readable_session_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            lines: list[str] = []
            service = self._service(
                [proposal_response()],
                debug_root=debug_root,
                lines=lines,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(self.request)
            self.assertTrue(result.success)
            session = self._session_directory(debug_root)
            self.assertRegex(session.name, r"^\d{8}-\d{6}_[a-z0-9-]+_[0-9a-f]{8}$")
            self.assertIn("_crea-una-skill-de-prueba_", session.name)
            self.assertEqual(len([line for line in lines if "Session:" in line]), 1)

    def test_request_slug_is_readable_bounded_and_safe(self) -> None:
        slug = _request_slug(
            "Crea una skill para comprobar la última versión publicada de Ollama..."
        )
        self.assertIn("ollama", slug)
        self.assertTrue(slug.startswith("comprobar-la-ultima-version"))
        self.assertNotIn("crea-una-skill-para", slug)
        self.assertEqual(_request_slug("Haz una skill para ÁRBOL / @@ raro!!!"), "arbol-raro")
        self.assertEqual(_request_slug("Crear una skill para " + "á" * 100), "a" * 48)
        self.assertLessEqual(len(slug), 48)
        self.assertEqual(_request_slug(None), "skill-authoring")
        self.assertEqual(_request_slug("  !!!  "), "skill-authoring")

    def test_direct_sessions_without_request_keep_fallback_and_do_not_collide(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "skill_authoring"
            first = AuthoringDebugSession.start(
                enabled=True, warning_sink=lambda _line: None, debug_root=root,
            )
            second = AuthoringDebugSession.start(
                enabled=True, warning_sink=lambda _line: None, debug_root=root,
                original_user_request="Crea una skill para comprobar Ollama",
            )
            self.assertTrue(first.active)
            self.assertTrue(second.active)
            self.assertNotEqual(first.directory, second.directory)
            self.assertRegex(first.directory.name, r"^\d{8}-\d{6}_skill-authoring_[0-9a-f]{8}$")
            self.assertRegex(second.directory.name, r"^\d{8}-\d{6}_comprobar-ollama_[0-9a-f]{8}$")

    def test_raw_response_is_saved_before_structural_generation_failure(self) -> None:
        raw_response = "This model response has no structured proposal."
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            service = self._service([raw_response], debug_root=debug_root)
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(self.request)
            self.assertFalse(result.success)
            session = self._session_directory(debug_root)
            raw_records = [
                json.loads(line)
                for line in (session / "raw_responses.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            self.assertEqual(raw_records[0], {"iteration": 1, "raw_response": raw_response})
            self.assertFalse((session / "iteration_001_source.py").exists())
            self.assertFalse((session / "iteration_001_raw.txt").exists())

    def test_valid_proposal_persists_literal_source_and_tests(self) -> None:
        source = "def ejecutar_skill():\n    return {'answer': 42}\n"
        tests = "def test_debug_skill():\n    assert True\n"
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            service = self._service(
                [proposal_response(source=source), tests_response(tests)],
                debug_root=debug_root,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(self.request)
            self.assertTrue(result.success)
            session = self._session_directory(debug_root)
            self.assertEqual(
                (session / "iteration_001_source.py").read_text(encoding="utf-8"),
                source,
            )
            self.assertEqual(
                (session / "iteration_002_tests.py").read_text(encoding="utf-8"),
                tests,
            )

    def test_structural_failure_is_persisted_as_jsonl_diagnostic(self) -> None:
        raw_response = "<JARVIS_META>{not-json}</JARVIS_META>"
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            service = self._service([raw_response], debug_root=debug_root)
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(self.request)
            self.assertFalse(result.success)
            session = self._session_directory(debug_root)
            lines = (session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(lines), 1)
            diagnostic = json.loads(lines[0])
            self.assertFalse(diagnostic["generation_success"])
            self.assertEqual(diagnostic["structural_error"], "missing identifiable Python source")
            self.assertEqual(diagnostic["structural_error_code"], "no_source_found")
            self.assertEqual(diagnostic["extraction_method"], "none")
            self.assertTrue(diagnostic["has_meta"])
            self.assertFalse(diagnostic["has_source"])
            self.assertEqual(diagnostic["phase"], "source_initial")
            self.assertEqual(diagnostic["normalized_kind"], "unknown")

    def test_multiple_attempts_append_raw_jsonl_without_raw_file_fanout(self) -> None:
        first = "unstructured response one"
        second = "unstructured response two"
        third = proposal_response()
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            service = self._service([first, second, third, tests_response()], debug_root=debug_root)
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(self.request)
            self.assertTrue(result.success)
            session = self._session_directory(debug_root)
            raw_records = [
                json.loads(line)
                for line in (session / "raw_responses.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            self.assertEqual(
                [record["raw_response"] for record in raw_records],
                [first, second, third, tests_response()],
            )
            self.assertEqual(
                [record["iteration"] for record in raw_records],
                [1, 2, 3, 4],
            )
            self.assertFalse(any(session.glob("iteration_*_raw.txt")))
            self.assertTrue((session / "iteration_003_source.py").exists())
            self.assertEqual(
                len((session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()),
                4,
            )

    def test_debug_write_error_does_not_change_authoring_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            blocked_root = Path(temporary) / "blocked"
            blocked_root.write_text("not a directory", encoding="utf-8")
            lines: list[str] = []
            service = self._service(
                [proposal_response()],
                debug_root=blocked_root / "skill_authoring",
                lines=lines,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(self.request)
            self.assertTrue(result.success)
            self.assertTrue(
                any("Persistent artifacts unavailable" in line for line in lines)
            )

    def test_debug_does_not_change_authoring_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            debug_root = Path(temporary) / ".debug" / "skill_authoring"
            without_debug = self._service(
                [proposal_response()],
                debug_root=debug_root,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: ""}, clear=False):
                baseline = without_debug.author(self.request)

            with_debug = self._service(
                [proposal_response()],
                debug_root=debug_root,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                instrumented = with_debug.author(self.request)

            self.assertEqual(baseline.success, instrumented.success)
            self.assertEqual(baseline.proposal, instrumented.proposal)
            self.assertEqual(baseline.iterations, instrumented.iterations)
            self.assertEqual(
                baseline.validation_reports,
                instrumented.validation_reports,
            )
            self.assertEqual(baseline.review_results, instrumented.review_results)

    def test_debug_directory_is_ignored_by_git(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                "git",
                "-c",
                "safe.directory=E:/JARVIS",
                "check-ignore",
                "-q",
                ".debug/skill_authoring/example",
            ],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
