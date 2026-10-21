from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.core.code_validation import LocalCodeValidator


class LocalCodeValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = LocalCodeValidator()
        self.project_root = Path.cwd()

    def test_valid_ast_and_compile(self) -> None:
        report = self.validator.validate_python_source("def add(a, b):\n    return a + b\n")
        self.assertTrue(report.success)
        self.assertEqual(
            [(check.name, check.success) for check in report.checks],
            [("ast_parse", True), ("in_memory_compile", True)],
        )

    def test_invalid_ast_and_compile(self) -> None:
        report = self.validator.validate_python_source("def broken(:\n")
        self.assertFalse(report.success)
        self.assertEqual(report.checks[0].name, "ast_parse")
        self.assertFalse(report.checks[0].success)
        self.assertEqual(report.checks[1].name, "in_memory_compile")
        self.assertFalse(report.checks[1].success)
        self.assertIn("SyntaxError", report.traceback or "")

    def test_controlled_subprocess_captures_stdout(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["python"], returncode=0, stdout="all tests passed", stderr=""
        )
        with patch(
            "jarvis.core.code_validation.subprocess.run", return_value=completed
        ) as run:
            report = self.validator.run_controlled_unittest(
                project_root=self.project_root,
                pattern="test_code_validation.py",
            )
        self.assertTrue(report.success)
        self.assertEqual(report.stdout, "all tests passed")
        self.assertEqual(report.stderr, "")
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], 30.0)

    def test_controlled_subprocess_captures_stderr(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["python"], returncode=1, stdout="", stderr="assertion failed"
        )
        with patch(
            "jarvis.core.code_validation.subprocess.run", return_value=completed
        ):
            report = self.validator.run_controlled_unittest(
                project_root=self.project_root,
                pattern="test_code_validation.py",
            )
        self.assertFalse(report.success)
        self.assertEqual(report.return_code, 1)
        self.assertEqual(report.stderr, "assertion failed")

    def test_timeout_is_reported_without_blocking(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["python"], timeout=0.01, output=b"partial stdout", stderr=b"partial stderr"
        )
        with patch(
            "jarvis.core.code_validation.subprocess.run", side_effect=timeout
        ):
            report = self.validator.run_controlled_unittest(
                project_root=self.project_root,
                pattern="test_code_validation.py",
                timeout_seconds=0.01,
            )
        self.assertFalse(report.success)
        self.assertTrue(report.timed_out)
        self.assertIn("partial stdout", report.stdout)
        self.assertIn("partial stderr", report.stderr)

    def test_controlled_runner_rejects_paths_and_invalid_timeouts(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not contain a path"):
            self.validator.run_controlled_unittest(
                project_root=self.project_root,
                pattern="../untrusted.py",
            )
        with self.assertRaisesRegex(ValueError, "must be positive"):
            self.validator.run_controlled_unittest(
                project_root=self.project_root,
                pattern="test_code_validation.py",
                timeout_seconds=0,
            )

    def test_report_prompt_context_is_structured(self) -> None:
        report = self.validator.validate_python_source("x = 1\n")
        context = report.to_prompt_context()
        self.assertIn('"checks"', context)
        self.assertIn('"success": true', context)
        self.assertIn("ast_parse", context)


if __name__ == "__main__":
    unittest.main()