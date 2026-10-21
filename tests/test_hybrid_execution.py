from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


try:
    import pytesseract  # noqa: F401
except ModuleNotFoundError:
    pytesseract_stub = types.ModuleType("pytesseract")
    pytesseract_stub.image_to_string = lambda *_args, **_kwargs: ""
    sys.modules["pytesseract"] = pytesseract_stub

try:
    from PIL import Image  # noqa: F401
except ModuleNotFoundError:
    pil_stub = types.ModuleType("PIL")
    image_stub = types.ModuleType("PIL.Image")
    pil_stub.Image = image_stub
    sys.modules["PIL"] = pil_stub
    sys.modules["PIL.Image"] = image_stub


import jarvis.core.model_router as model_router
from jarvis.core.execution_executor import WorkerStatus
from jarvis.core.execution_planner import (
    CapabilityRequest,
    CloudAvailability,
    ExecutionPlan,
    ExecutionTarget,
    WorkerAssignment,
    WorkerKind,
)
from jarvis.core.hybrid_execution import (
    HybridExecution,
    HybridExecutionConfigurationError,
    WorkerInput,
)
from jarvis.core.vram_manager import VramManager


class FakeResponse:
    status_code = 200

    def __init__(self, data: dict) -> None:
        self._data = data

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._data


class FakeModelRouter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_groq = False
        self.fail_gemini = False

    def route(self, *_args, **_kwargs):
        raise AssertionError("HybridExecution must not call ModelRouter.route()")

    def run_local_coding(self, prompt: str) -> str:
        self.calls.append(("local_coding", prompt))
        return f"local coding: {prompt}"

    def run_local_vision(self, prompt: str, image_bytes: bytes) -> str:
        self.calls.append(("local_vision", prompt))
        return f"local vision: {len(image_bytes)}"

    def run_local_reasoning(self, prompt: str) -> str:
        self.calls.append(("local_reasoning", prompt))
        return f"local reasoning: {prompt}"

    def run_groq_reasoning(self, prompt: str) -> str:
        self.calls.append(("groq_reasoning", prompt))
        if self.fail_groq:
            raise RuntimeError("groq unavailable")
        return f"groq reasoning: {prompt}"

    def run_gemini_vision(self, prompt: str, image_bytes: bytes) -> str:
        self.calls.append(("gemini_vision", prompt))
        if self.fail_gemini:
            raise RuntimeError("gemini unavailable")
        return f"gemini vision: {len(image_bytes)}"


class HybridExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.router = FakeModelRouter()
        self.hybrid = HybridExecution(self.router)

    @staticmethod
    def inputs(*workers: WorkerKind) -> dict[WorkerKind, WorkerInput]:
        return {
            worker: WorkerInput(
                prompt=f"{worker.value} prompt",
                image_bytes=b"image" if worker is WorkerKind.VISION else None,
            )
            for worker in workers
        }

    @staticmethod
    def clouds(**values) -> CloudAvailability:
        return CloudAvailability(**values)

    def test_only_coding_uses_the_explicit_local_method(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(coding=True),
            self.clouds(),
            self.inputs(WorkerKind.CODING),
        )

        self.assertEqual(self.router.calls, [("local_coding", "coding prompt")])
        self.assertEqual(
            result.execution.result_for(WorkerKind.CODING).actual_target,
            ExecutionTarget.LOCAL,
        )

    def test_only_vision_uses_the_explicit_local_method(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(vision=True),
            self.clouds(),
            self.inputs(WorkerKind.VISION),
        )

        self.assertEqual(self.router.calls, [("local_vision", "vision prompt")])
        self.assertEqual(
            result.execution.result_for(WorkerKind.VISION).actual_target,
            ExecutionTarget.LOCAL,
        )

    def test_only_reasoning_uses_the_explicit_local_method(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(reasoning=True),
            self.clouds(),
            self.inputs(WorkerKind.REASONING),
        )

        self.assertEqual(self.router.calls, [("local_reasoning", "reasoning prompt")])
        self.assertEqual(
            result.execution.result_for(WorkerKind.REASONING).actual_target,
            ExecutionTarget.LOCAL,
        )

    def test_coding_and_reasoning_use_groq_when_planned(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(coding=True, reasoning=True),
            self.clouds(groq_available=True, groq_budget_available=True),
            self.inputs(WorkerKind.CODING, WorkerKind.REASONING),
        )

        self.assertEqual(
            result.plan.assignment_for(WorkerKind.REASONING).target,
            ExecutionTarget.GROQ,
        )
        self.assertIn(("local_coding", "coding prompt"), self.router.calls)
        self.assertIn(("groq_reasoning", "reasoning prompt"), self.router.calls)

    def test_coding_and_vision_use_gemini_when_planned(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(coding=True, vision=True),
            self.clouds(gemini_available=True, gemini_budget_available=True),
            self.inputs(WorkerKind.CODING, WorkerKind.VISION),
        )

        self.assertEqual(
            result.plan.assignment_for(WorkerKind.VISION).target,
            ExecutionTarget.GEMINI,
        )
        self.assertIn(("local_coding", "coding prompt"), self.router.calls)
        self.assertIn(("gemini_vision", "vision prompt"), self.router.calls)

    def test_three_workers_use_local_groq_and_gemini_once_each(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(coding=True, vision=True, reasoning=True),
            self.clouds(
                groq_available=True,
                groq_budget_available=True,
                gemini_available=True,
                gemini_budget_available=True,
            ),
            self.inputs(WorkerKind.CODING, WorkerKind.VISION, WorkerKind.REASONING),
        )

        self.assertCountEqual(
            [name for name, _prompt in self.router.calls],
            ["local_coding", "gemini_vision", "groq_reasoning"],
        )
        self.assertEqual(result.execution.cloud_calls_attempted, 2)
        self.assertTrue(result.execution.success)

    def test_groq_failure_falls_back_to_explicit_local_reasoning(self) -> None:
        self.router.fail_groq = True
        result = self.hybrid.execute(
            CapabilityRequest(coding=True, reasoning=True),
            self.clouds(groq_available=True, groq_budget_available=True),
            self.inputs(WorkerKind.CODING, WorkerKind.REASONING),
        )

        reasoning = result.execution.result_for(WorkerKind.REASONING)
        self.assertEqual(reasoning.status, WorkerStatus.FALLBACK_SUCCESS)
        self.assertEqual(reasoning.actual_target, ExecutionTarget.LOCAL)
        self.assertIn(("local_reasoning", "reasoning prompt"), self.router.calls)

    def test_gemini_failure_falls_back_to_explicit_local_vision(self) -> None:
        self.router.fail_gemini = True
        result = self.hybrid.execute(
            CapabilityRequest(coding=True, vision=True),
            self.clouds(gemini_available=True, gemini_budget_available=True),
            self.inputs(WorkerKind.CODING, WorkerKind.VISION),
        )

        vision = result.execution.result_for(WorkerKind.VISION)
        self.assertEqual(vision.status, WorkerStatus.FALLBACK_SUCCESS)
        self.assertEqual(vision.actual_target, ExecutionTarget.LOCAL)
        self.assertIn(("local_vision", "vision prompt"), self.router.calls)

    def test_two_cloud_failures_enter_the_local_queue(self) -> None:
        self.router.fail_groq = True
        self.router.fail_gemini = True
        result = self.hybrid.execute(
            CapabilityRequest(coding=True, vision=True, reasoning=True),
            self.clouds(
                groq_available=True,
                groq_budget_available=True,
                gemini_available=True,
                gemini_budget_available=True,
            ),
            self.inputs(WorkerKind.CODING, WorkerKind.VISION, WorkerKind.REASONING),
        )

        names = [name for name, _prompt in self.router.calls]
        self.assertCountEqual(
            names,
            [
                "gemini_vision",
                "groq_reasoning",
                "local_coding",
                "local_vision",
                "local_reasoning",
            ],
        )
        self.assertEqual(
            [name for name in names if name.startswith("local_")],
            ["local_coding", "local_vision", "local_reasoning"],
        )
        self.assertEqual(result.execution.fallbacks_used, 2)
        self.assertTrue(result.execution.success)

    def test_vision_without_image_bytes_fails_clearly(self) -> None:
        with self.assertRaisesRegex(
            HybridExecutionConfigurationError,
            "VISION requires non-empty image_bytes",
        ):
            self.hybrid.execute(
                CapabilityRequest(vision=True),
                self.clouds(),
                {WorkerKind.VISION: WorkerInput(prompt="vision")},
            )

    def test_unsupported_planned_combination_fails_clearly(self) -> None:
        class UnsupportedPlanner:
            @staticmethod
            def plan(_capabilities, _availability):
                return ExecutionPlan(
                    assignments=(
                        WorkerAssignment(
                            worker=WorkerKind.CODING,
                            target=ExecutionTarget.GROQ,
                            local_order=None,
                            reason="unsupported test assignment",
                            fallback_target=ExecutionTarget.LOCAL,
                            fallback_local_order=1,
                        ),
                    ),
                    local_execution_order=(),
                    cloud_parallelism_possible=False,
                    planned_cloud_calls=1,
                    local_available_at_planning=True,
                )

        hybrid = HybridExecution(self.router, planner=UnsupportedPlanner())
        with self.assertRaisesRegex(
            HybridExecutionConfigurationError,
            "Unsupported planned worker/target combination",
        ):
            hybrid.execute(
                CapabilityRequest(coding=True),
                self.clouds(),
                self.inputs(WorkerKind.CODING),
            )
    def test_hybrid_result_keeps_plan_and_worker_results(self) -> None:
        result = self.hybrid.execute(
            CapabilityRequest(coding=True),
            self.clouds(),
            self.inputs(WorkerKind.CODING),
        )

        self.assertEqual(result.plan.assignments[0].worker, WorkerKind.CODING)
        self.assertEqual(result.execution.results[0].worker, WorkerKind.CODING)
        self.assertEqual(result.execution.results[0].content, "local coding: coding prompt")


class ExplicitModelRouterMethodTests(unittest.TestCase):
    @staticmethod
    def make_router(manager: VramManager | None = None):
        with patch.object(model_router, "FormulaMemory", return_value=object()):
            return model_router.ModelRouter(
                groq_api_key="groq-test",
                gemini_api_key="gemini-test",
                vram_manager=manager,
            )

    def test_explicit_cloud_methods_do_not_fallback_to_local(self) -> None:
        router = self.make_router()
        with patch.object(
            router,
            "_call_groq",
            side_effect=RuntimeError("groq failure"),
        ), patch.object(
            router,
            "_call_gemini_vision",
            side_effect=RuntimeError("gemini failure"),
        ), patch.object(router, "run_local_reasoning") as local_reasoning, patch.object(
            router,
            "run_local_vision",
        ) as local_vision:
            with self.assertRaisesRegex(RuntimeError, "groq failure"):
                router.run_groq_reasoning("reason")
            with self.assertRaisesRegex(RuntimeError, "gemini failure"):
                router.run_gemini_vision("vision", b"image")

        local_reasoning.assert_not_called()
        local_vision.assert_not_called()

    def test_explicit_local_methods_reserve_vram(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)

        with patch.object(
            model_router.requests,
            "post",
            return_value=FakeResponse({"response": "ok"}),
        ), patch.object(manager, "reserve", wraps=manager.reserve) as reserve:
            self.assertEqual(router.run_local_coding("code"), "ok")
            self.assertEqual(router.run_local_vision("vision", b"image"), "ok")
            self.assertEqual(router.run_local_reasoning("reason"), "ok")

        self.assertEqual(reserve.call_count, 3)

    def test_explicit_cloud_method_does_not_reserve_vram(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)

        with patch.object(
            router,
            "_call_groq",
            return_value="cloud",
        ), patch.object(manager, "reserve", wraps=manager.reserve) as reserve:
            self.assertEqual(router.run_groq_reasoning("reason"), "cloud")

        reserve.assert_not_called()

    def test_legacy_route_still_works(self) -> None:
        router = self.make_router(VramManager())
        with patch.object(
            model_router.requests,
            "post",
            return_value=FakeResponse({"response": "legacy"}),
        ):
            self.assertEqual(
                router.route(model_router.ModelRole.SPEECH, "hello"),
                "legacy",
            )


if __name__ == "__main__":
    unittest.main()