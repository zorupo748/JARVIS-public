from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.core.execution_executor import (
    ExecutionExecutor,
    HandlerOutcome,
    WorkerStatus,
)
from jarvis.core.execution_planner import (
    CapabilityRequest,
    CloudAvailability,
    ExecutionPlanner,
    ExecutionTarget,
    WorkerKind,
)


class ExecutionExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = ExecutionPlanner()

    def make_plan(self, **capabilities):
        availability = CloudAvailability(
            groq_available=capabilities.pop("groq_available", False),
            groq_budget_available=capabilities.pop("groq_budget_available", False),
            gemini_available=capabilities.pop("gemini_available", False),
            gemini_budget_available=capabilities.pop("gemini_budget_available", False),
        )
        return self.planner.plan(CapabilityRequest(**capabilities), availability)

    @staticmethod
    def make_executor(local_handlers=None, cloud_handlers=None) -> ExecutionExecutor:
        return ExecutionExecutor(
            local_handlers=local_handlers or {},
            cloud_handlers=cloud_handlers or {},
        )

    def test_one_local_worker_executes_successfully(self) -> None:
        plan = self.make_plan(coding=True)
        result = self.make_executor(
            {WorkerKind.CODING: lambda: "code"}
        ).execute(plan)

        coding = result.result_for(WorkerKind.CODING)
        self.assertEqual(coding.status, WorkerStatus.SUCCESS)
        self.assertEqual(coding.content, "code")
        self.assertEqual(coding.requested_target, ExecutionTarget.LOCAL)
        self.assertEqual(coding.actual_target, ExecutionTarget.LOCAL)
        self.assertTrue(result.success)

    def test_two_local_workers_respect_local_order(self) -> None:
        plan = self.make_plan(coding=True, vision=True)
        calls: list[WorkerKind] = []
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: calls.append(WorkerKind.CODING) or "code",
                WorkerKind.VISION: lambda: calls.append(WorkerKind.VISION) or "vision",
            }
        ).execute(plan)

        self.assertEqual(calls, [WorkerKind.CODING, WorkerKind.VISION])
        self.assertTrue(result.success)

    def test_three_local_workers_respect_canonical_order(self) -> None:
        plan = self.make_plan(coding=True, vision=True, reasoning=True)
        calls: list[WorkerKind] = []
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: calls.append(WorkerKind.CODING) or "code",
                WorkerKind.VISION: lambda: calls.append(WorkerKind.VISION) or "vision",
                WorkerKind.REASONING: lambda: calls.append(WorkerKind.REASONING) or "reason",
            }
        ).execute(plan)

        self.assertEqual(
            calls,
            [WorkerKind.CODING, WorkerKind.VISION, WorkerKind.REASONING],
        )
        self.assertTrue(result.success)

    def test_local_and_groq_start_concurrently(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        barrier = threading.Barrier(2)
        started: list[str] = []
        lock = threading.Lock()

        def local_coding():
            with lock:
                started.append("local")
            barrier.wait(timeout=0.5)
            return "code"

        def groq_reasoning():
            with lock:
                started.append("groq")
            barrier.wait(timeout=0.5)
            return "reason"

        result = self.make_executor(
            {WorkerKind.CODING: local_coding, WorkerKind.REASONING: lambda: "fallback"},
            {ExecutionTarget.GROQ: groq_reasoning},
        ).execute(plan)

        self.assertCountEqual(started, ["local", "groq"])
        self.assertTrue(result.success)

    def test_local_and_gemini_start_concurrently(self) -> None:
        plan = self.make_plan(
            coding=True,
            vision=True,
            gemini_available=True,
            gemini_budget_available=True,
        )
        barrier = threading.Barrier(2)
        started: list[str] = []
        lock = threading.Lock()

        def local_coding():
            with lock:
                started.append("local")
            barrier.wait(timeout=0.5)
            return "code"

        def gemini_vision():
            with lock:
                started.append("gemini")
            barrier.wait(timeout=0.5)
            return "vision"

        result = self.make_executor(
            {WorkerKind.CODING: local_coding, WorkerKind.VISION: lambda: "fallback"},
            {ExecutionTarget.GEMINI: gemini_vision},
        ).execute(plan)

        self.assertCountEqual(started, ["local", "gemini"])
        self.assertTrue(result.success)

    def test_local_groq_and_gemini_start_concurrently(self) -> None:
        plan = self.make_plan(
            coding=True,
            vision=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
            gemini_available=True,
            gemini_budget_available=True,
        )
        barrier = threading.Barrier(3)
        started: list[str] = []
        lock = threading.Lock()

        def handler(name: str):
            def run():
                with lock:
                    started.append(name)
                barrier.wait(timeout=0.5)
                return name

            return run

        result = self.make_executor(
            {
                WorkerKind.CODING: handler("local"),
                WorkerKind.VISION: handler("vision-fallback"),
                WorkerKind.REASONING: handler("reasoning-fallback"),
            },
            {
                ExecutionTarget.GROQ: handler("groq"),
                ExecutionTarget.GEMINI: handler("gemini"),
            },
        ).execute(plan)

        self.assertCountEqual(started, ["local", "groq", "gemini"])
        self.assertTrue(result.success)

    def test_successful_groq_does_not_run_its_local_fallback(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        fallback_calls: list[str] = []
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.REASONING: lambda: fallback_calls.append("fallback") or "reason",
            },
            {ExecutionTarget.GROQ: lambda: "cloud reason"},
        ).execute(plan)

        self.assertEqual(fallback_calls, [])
        self.assertEqual(
            result.result_for(WorkerKind.REASONING).status, WorkerStatus.SUCCESS
        )

    def test_failed_groq_runs_its_local_fallback(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.REASONING: lambda: "local reason",
            },
            {ExecutionTarget.GROQ: lambda: (_ for _ in ()).throw(RuntimeError("offline"))},
        ).execute(plan)

        reasoning = result.result_for(WorkerKind.REASONING)
        self.assertEqual(reasoning.status, WorkerStatus.FALLBACK_SUCCESS)
        self.assertEqual(reasoning.requested_target, ExecutionTarget.GROQ)
        self.assertEqual(reasoning.actual_target, ExecutionTarget.LOCAL)
        self.assertTrue(reasoning.fallback_used)
        self.assertEqual(result.cloud_failures, 1)
        self.assertEqual(result.fallbacks_used, 1)

    def test_failed_gemini_runs_its_local_fallback(self) -> None:
        plan = self.make_plan(
            coding=True,
            vision=True,
            gemini_available=True,
            gemini_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.VISION: lambda: "local vision",
            },
            {ExecutionTarget.GEMINI: lambda: HandlerOutcome.failed("timeout")},
        ).execute(plan)

        vision = result.result_for(WorkerKind.VISION)
        self.assertEqual(vision.status, WorkerStatus.FALLBACK_SUCCESS)
        self.assertEqual(vision.actual_target, ExecutionTarget.LOCAL)
        self.assertIn("timeout", vision.error or "")

    def test_cloud_failure_waits_for_an_occupied_local_order(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        coding_started = threading.Event()
        cloud_failed = threading.Event()
        release_coding = threading.Event()
        fallback_started = threading.Event()
        events: list[str] = []
        holder: dict[str, object] = {}

        def local_coding():
            events.append("coding-start")
            coding_started.set()
            release_coding.wait(timeout=0.5)
            events.append("coding-end")
            return "code"

        def groq_reasoning():
            coding_started.wait(timeout=0.5)
            events.append("groq-failed")
            cloud_failed.set()
            return HandlerOutcome.failed("cloud unavailable")

        def local_reasoning():
            events.append("fallback-start")
            fallback_started.set()
            return "local reason"

        executor = self.make_executor(
            {
                WorkerKind.CODING: local_coding,
                WorkerKind.REASONING: local_reasoning,
            },
            {ExecutionTarget.GROQ: groq_reasoning},
        )
        worker = threading.Thread(
            target=lambda: holder.setdefault("result", executor.execute(plan))
        )
        worker.start()

        self.assertTrue(coding_started.wait(timeout=0.5))
        self.assertTrue(cloud_failed.wait(timeout=0.5))
        self.assertFalse(fallback_started.wait(timeout=0.05))
        release_coding.set()
        worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertLess(events.index("coding-end"), events.index("fallback-start"))
        self.assertEqual(
            holder["result"].result_for(WorkerKind.REASONING).status,
            WorkerStatus.FALLBACK_SUCCESS,
        )

    def test_two_simultaneous_cloud_failures_never_run_locals_together(self) -> None:
        plan = self.make_plan(
            coding=True,
            vision=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
            gemini_available=True,
            gemini_budget_available=True,
        )
        active = 0
        maximum_active = 0
        lock = threading.Lock()

        def guarded_local(name: str):
            def run():
                nonlocal active, maximum_active
                with lock:
                    active += 1
                    maximum_active = max(maximum_active, active)
                time.sleep(0.01)
                with lock:
                    active -= 1
                return name

            return run

        result = self.make_executor(
            {
                WorkerKind.CODING: guarded_local("code"),
                WorkerKind.VISION: guarded_local("vision"),
                WorkerKind.REASONING: guarded_local("reason"),
            },
            {
                ExecutionTarget.GROQ: lambda: HandlerOutcome.failed("groq down"),
                ExecutionTarget.GEMINI: lambda: HandlerOutcome.failed("gemini down"),
            },
        ).execute(plan)

        self.assertEqual(maximum_active, 1)
        self.assertEqual(result.fallbacks_used, 2)
        self.assertTrue(result.success)

    def test_one_worker_failure_does_not_cancel_other_workers(self) -> None:
        plan = self.make_plan(
            coding=True,
            vision=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
            gemini_available=True,
            gemini_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.VISION: lambda: "local vision",
                WorkerKind.REASONING: lambda: "local reason",
            },
            {
                ExecutionTarget.GROQ: lambda: "cloud reason",
                ExecutionTarget.GEMINI: lambda: HandlerOutcome.failed("gemini down"),
            },
        ).execute(plan)

        self.assertEqual(
            result.result_for(WorkerKind.CODING).status, WorkerStatus.SUCCESS
        )
        self.assertEqual(
            result.result_for(WorkerKind.REASONING).status, WorkerStatus.SUCCESS
        )
        self.assertEqual(
            result.result_for(WorkerKind.VISION).status,
            WorkerStatus.FALLBACK_SUCCESS,
        )
        self.assertTrue(result.success)

    def test_fallback_failure_is_reported_without_cancelling_local_work(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.REASONING: lambda: (_ for _ in ()).throw(RuntimeError("local down")),
            },
            {ExecutionTarget.GROQ: lambda: HandlerOutcome.failed("cloud down")},
        ).execute(plan)

        self.assertEqual(
            result.result_for(WorkerKind.CODING).status, WorkerStatus.SUCCESS
        )
        fallback = result.result_for(WorkerKind.REASONING)
        self.assertEqual(fallback.status, WorkerStatus.FALLBACK_FAILED)
        self.assertIn("cloud down", fallback.error or "")
        self.assertIn("local down", fallback.error or "")
        self.assertFalse(result.success)

    def test_total_elapsed_time_tracks_parallel_work_not_the_sum(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: time.sleep(0.05) or "code",
                WorkerKind.REASONING: lambda: "fallback",
            },
            {ExecutionTarget.GROQ: lambda: time.sleep(0.05) or "reason"},
        ).execute(plan)

        self.assertTrue(result.success)
        self.assertLess(result.elapsed_seconds, 0.09)

    def test_worker_result_reports_the_successful_cloud_target(self) -> None:
        plan = self.make_plan(
            coding=True,
            reasoning=True,
            groq_available=True,
            groq_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.REASONING: lambda: "fallback",
            },
            {ExecutionTarget.GROQ: lambda: "cloud reason"},
        ).execute(plan)

        reasoning = result.result_for(WorkerKind.REASONING)
        self.assertEqual(reasoning.requested_target, ExecutionTarget.GROQ)
        self.assertEqual(reasoning.actual_target, ExecutionTarget.GROQ)
        self.assertEqual(reasoning.status, WorkerStatus.SUCCESS)

    def test_fallback_success_status_is_explicit(self) -> None:
        plan = self.make_plan(
            coding=True,
            vision=True,
            gemini_available=True,
            gemini_budget_available=True,
        )
        result = self.make_executor(
            {
                WorkerKind.CODING: lambda: "code",
                WorkerKind.VISION: lambda: "local vision",
            },
            {ExecutionTarget.GEMINI: lambda: HandlerOutcome.failed("provider timeout")},
        ).execute(plan)

        vision = result.result_for(WorkerKind.VISION)
        self.assertEqual(vision.status, WorkerStatus.FALLBACK_SUCCESS)
        self.assertTrue(vision.fallback_used)
    def test_empty_plan_returns_a_valid_execution_result(self) -> None:
        plan = self.make_plan()
        result = self.make_executor().execute(plan)

        self.assertEqual(result.results, ())
        self.assertEqual(result.cloud_calls_attempted, 0)
        self.assertEqual(result.cloud_failures, 0)
        self.assertTrue(result.success)

    def test_same_handlers_produce_a_consistent_result_structure(self) -> None:
        plan = self.make_plan(coding=True)
        executor = self.make_executor({WorkerKind.CODING: lambda: "code"})
        first = executor.execute(plan)
        second = executor.execute(plan)

        def structure(result):
            return [
                (
                    item.worker,
                    item.requested_target,
                    item.actual_target,
                    item.status,
                    item.content,
                    item.error,
                    item.fallback_used,
                )
                for item in result.results
            ]

        self.assertEqual(structure(first), structure(second))


if __name__ == "__main__":
    unittest.main()