from __future__ import annotations

import json
import sys
import types
import unittest
from unittest.mock import patch

from jarvis.core.code_reviewer import CodeReviewRequest, CodeReviewer

# ModelRouter imports optional OCR modules at module load time. This test never
# invokes OCR, so provide inert stubs instead of loading those dependencies.
sys.modules.setdefault("pytesseract", types.ModuleType("pytesseract"))
pil_stub = sys.modules.setdefault("PIL", types.ModuleType("PIL"))
image_stub = sys.modules.setdefault("PIL.Image", types.ModuleType("PIL.Image"))
pil_stub.Image = image_stub
from jarvis.core.model_router import (
    DEFAULT_LOCAL_CODE_REVIEW_NUM_PREDICT,
    DEEP_REASONING_INFERENCE_PROFILE,
    ModelRouter,
    get_local_code_review_num_predict,
)


class LocalCodeReviewBudgetTests(unittest.TestCase):
    def test_default_override_and_out_of_range(self) -> None:
        self.assertEqual(get_local_code_review_num_predict({}), 1536)
        self.assertEqual(get_local_code_review_num_predict({"JARVIS_LOCAL_CODE_REVIEW_NUM_PREDICT": "2048"}), 2048)
        for value in ("255", "4097", "bad", ""):
            with self.subTest(value=value):
                self.assertEqual(get_local_code_review_num_predict({"JARVIS_LOCAL_CODE_REVIEW_NUM_PREDICT": value}), 1536)

    def test_review_only_budget_does_not_change_general_reasoning(self) -> None:
        router = ModelRouter.__new__(ModelRouter)
        calls = []
        router._call_ollama = lambda model, prompt, **kwargs: calls.append((model, prompt, kwargs)) or "ok"
        with patch.dict("os.environ", {"JARVIS_LOCAL_CODE_REVIEW_NUM_PREDICT": "2048"}):
            router.run_local_code_review("review")
            router.run_local_reasoning("general")
        self.assertEqual(calls[0][2]["num_predict"], 2048)
        self.assertEqual(calls[1][2]["num_predict"], 768)
        self.assertEqual(DEEP_REASONING_INFERENCE_PROFILE.num_predict, 768)
        self.assertEqual(DEFAULT_LOCAL_CODE_REVIEW_NUM_PREDICT, 1536)

    def test_reviewer_calls_dedicated_route_and_accepts_long_complete_response(self) -> None:
        class Router:
            groq_api_key = None
            local_code_review_num_predict = 1536

            def __init__(self) -> None:
                self.review_calls = 0
                self.general_calls = 0

            def run_local_code_review(self, _prompt: str) -> str:
                self.review_calls += 1
                return "context " * 850 + json.dumps({"approved": True, "issues": [], "blocking_issues": []})

            def run_local_reasoning(self, _prompt: str) -> str:
                self.general_calls += 1
                raise AssertionError("general reasoning route used")

        router = Router()
        outcome = CodeReviewer(router).review_with_attempts(
            CodeReviewRequest("original", "summary", "source")
        )
        self.assertTrue(outcome.result.approved)
        self.assertEqual(router.review_calls, 1)
        self.assertEqual(router.general_calls, 0)
        self.assertEqual(outcome.provider_attempts[0].local_review_num_predict, 1536)


if __name__ == "__main__":
    unittest.main()
