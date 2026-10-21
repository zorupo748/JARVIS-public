from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jarvis.core.authoring_debug import AUTHORING_DEBUG_ENV
from jarvis.core.code_reviewer import CodeReviewResult, ReviewIssue, ReviewSeverity
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService, SkillAuthoringRequest


class _Coder:
    def __init__(self) -> None:
        self.responses = [
            (
                '<JARVIS_META>{"skill_name":"debug_skill",'
                '"implementation_summary":"debug", "dependencies":[]}</JARVIS_META>'
                "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'first'\n</JARVIS_SOURCE>"
            ),
            "<JARVIS_SOURCE>\ndef ejecutar_skill():\n    return 'fixed'\n</JARVIS_SOURCE>",
            "<JARVIS_TESTS>\ndef test_ok():\n    assert True\n</JARVIS_TESTS>",
        ]

    def run_local_coding(self, _prompt: str) -> str:
        return self.responses.pop(0)


class _Reviewer:
    def __init__(self) -> None:
        self._calls = 0

    def review(self, _request: object) -> CodeReviewResult:
        self._calls += 1
        if self._calls == 1:
            return CodeReviewResult(
                approved=False,
                issues=(ReviewIssue(ReviewSeverity.HIGH, "Repair required."),),
                reviewer_used="fake",
                cloud_attempted=False,
                cloud_failed=False,
            )
        return CodeReviewResult(
            approved=True,
            issues=(),
            reviewer_used="fake",
            cloud_attempted=False,
            cloud_failed=False,
        )


class SourceRepairDebugTests(unittest.TestCase):
    def test_debug_records_reused_frozen_metadata_for_source_only_repair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / ".debug" / "skill_authoring"
            service = SafeSkillAuthoringService(
                _Coder(),
                reviewer=_Reviewer(),
                max_seconds=60,
                debug_root=root,
                diagnostic_sink=lambda _message: None,
            )
            with patch.dict(os.environ, {AUTHORING_DEBUG_ENV: "true"}, clear=False):
                result = service.author(SkillAuthoringRequest("Create a debug skill."))
            self.assertTrue(result.success)
            session = next(root.iterdir())
            records = [
                json.loads(line)
                for line in (session / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            repair = next(record for record in records if record["phase"] == "source_repair")
            self.assertTrue(repair["metadata_reused"])
            self.assertFalse(repair["metadata_change_ignored"])


if __name__ == "__main__":
    unittest.main()
