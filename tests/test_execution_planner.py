from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.core.execution_planner import (
    CapabilityRequest,
    CloudAvailability,
    ExecutionPlanner,
    ExecutionTarget,
    WorkerKind,
)


class ExecutionPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = ExecutionPlanner()

    def plan(self, **capabilities):
        return self.planner.plan(
            CapabilityRequest(**capabilities), CloudAvailability()
        )

    def plan_with_clouds(self, capabilities: CapabilityRequest, **availability):
        return self.planner.plan(capabilities, CloudAvailability(**availability))

    @staticmethod
    def assignment(plan, worker: WorkerKind):
        return plan.assignment_for(worker)

    def assert_local(self, plan, worker: WorkerKind, order: int) -> None:
        assignment = self.assignment(plan, worker)
        self.assertEqual(assignment.target, ExecutionTarget.LOCAL)
        self.assertEqual(assignment.local_order, order)
        self.assertIsNone(assignment.fallback_target)

    def assert_cloud(
        self,
        plan,
        worker: WorkerKind,
        target: ExecutionTarget,
        fallback_order: int,
    ) -> None:
        assignment = self.assignment(plan, worker)
        self.assertEqual(assignment.target, target)
        self.assertIsNone(assignment.local_order)
        self.assertEqual(assignment.fallback_target, ExecutionTarget.LOCAL)
        self.assertEqual(assignment.fallback_local_order, fallback_order)

    def test_only_coding_stays_local(self) -> None:
        plan = self.plan(coding=True)

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assertFalse(plan.cloud_parallelism_possible)
        self.assertEqual(plan.planned_cloud_calls, 0)

    def test_only_vision_stays_local(self) -> None:
        plan = self.plan(vision=True)

        self.assert_local(plan, WorkerKind.VISION, 1)

    def test_only_reasoning_stays_local(self) -> None:
        plan = self.plan(reasoning=True)

        self.assert_local(plan, WorkerKind.REASONING, 1)

    def test_coding_and_reasoning_use_groq_when_usable(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True, reasoning=True),
            groq_available=True,
            groq_budget_available=True,
        )

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_cloud(plan, WorkerKind.REASONING, ExecutionTarget.GROQ, 2)
        self.assertTrue(plan.cloud_parallelism_possible)

    def test_coding_and_reasoning_queue_locally_without_groq(self) -> None:
        plan = self.plan(coding=True, reasoning=True)

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_local(plan, WorkerKind.REASONING, 2)

    def test_coding_and_vision_use_gemini_when_usable(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True, vision=True),
            gemini_available=True,
            gemini_budget_available=True,
        )

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_cloud(plan, WorkerKind.VISION, ExecutionTarget.GEMINI, 2)

    def test_coding_and_vision_queue_locally_without_gemini(self) -> None:
        plan = self.plan(coding=True, vision=True)

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_local(plan, WorkerKind.VISION, 2)

    def test_vision_and_reasoning_keep_vision_local_and_use_groq(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(vision=True, reasoning=True),
            groq_available=True,
            groq_budget_available=True,
            gemini_available=True,
            gemini_budget_available=True,
        )

        self.assert_local(plan, WorkerKind.VISION, 1)
        self.assert_cloud(plan, WorkerKind.REASONING, ExecutionTarget.GROQ, 2)

    def test_vision_and_reasoning_queue_locally_without_groq(self) -> None:
        plan = self.plan(coding=False, vision=True, reasoning=True)

        self.assert_local(plan, WorkerKind.VISION, 1)
        self.assert_local(plan, WorkerKind.REASONING, 2)

    def test_three_workers_use_both_cloud_accelerators(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True, vision=True, reasoning=True),
            groq_available=True,
            groq_budget_available=True,
            gemini_available=True,
            gemini_budget_available=True,
        )

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_cloud(plan, WorkerKind.VISION, ExecutionTarget.GEMINI, 2)
        self.assert_cloud(plan, WorkerKind.REASONING, ExecutionTarget.GROQ, 3)
        self.assertEqual(plan.planned_cloud_calls, 2)

    def test_three_workers_with_only_groq_queue_coding_and_vision_locally(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True, vision=True, reasoning=True),
            groq_available=True,
            groq_budget_available=True,
        )

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_local(plan, WorkerKind.VISION, 2)
        self.assert_cloud(plan, WorkerKind.REASONING, ExecutionTarget.GROQ, 3)

    def test_three_workers_with_only_gemini_queue_coding_and_reasoning_locally(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True, vision=True, reasoning=True),
            gemini_available=True,
            gemini_budget_available=True,
        )

        self.assert_local(plan, WorkerKind.CODING, 1)
        self.assert_cloud(plan, WorkerKind.VISION, ExecutionTarget.GEMINI, 3)
        self.assert_local(plan, WorkerKind.REASONING, 2)

    def test_three_workers_without_cloud_use_the_canonical_local_order(self) -> None:
        plan = self.plan(coding=True, vision=True, reasoning=True)

        self.assertEqual(
            plan.local_execution_order,
            (WorkerKind.CODING, WorkerKind.VISION, WorkerKind.REASONING),
        )
        self.assertEqual(plan.planned_cloud_calls, 0)

    def test_available_api_without_budget_is_not_usable(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True, vision=True, reasoning=True),
            groq_available=True,
            gemini_available=True,
            groq_budget_available=False,
            gemini_budget_available=False,
        )

        self.assertEqual(
            tuple(assignment.target for assignment in plan.assignments),
            (ExecutionTarget.LOCAL, ExecutionTarget.LOCAL, ExecutionTarget.LOCAL),
        )

    def test_primary_local_orders_are_unique_and_contiguous(self) -> None:
        plan = self.plan(coding=True, vision=True, reasoning=True)
        local_orders = [
            assignment.local_order
            for assignment in plan.assignments
            if assignment.target is ExecutionTarget.LOCAL
        ]

        self.assertEqual(local_orders, [1, 2, 3])
        self.assertEqual(len(local_orders), len(set(local_orders)))

    def test_same_input_always_produces_the_same_plan(self) -> None:
        capabilities = CapabilityRequest(coding=True, vision=True, reasoning=True)
        availability = CloudAvailability(
            groq_available=True,
            groq_budget_available=True,
            gemini_available=True,
            gemini_budget_available=True,
        )

        self.assertEqual(
            self.planner.plan(capabilities, availability),
            self.planner.plan(capabilities, availability),
        )

    def test_no_capabilities_produces_an_empty_valid_plan(self) -> None:
        plan = self.plan()

        self.assertEqual(plan.assignments, ())
        self.assertEqual(plan.local_execution_order, ())
        self.assertEqual(plan.planned_cloud_calls, 0)

    def test_busy_local_slot_is_recorded_without_spending_cloud_for_one_worker(self) -> None:
        plan = self.plan_with_clouds(
            CapabilityRequest(coding=True),
            local_available=False,
            groq_available=True,
            groq_budget_available=True,
        )

        self.assertFalse(plan.local_available_at_planning)
        self.assert_local(plan, WorkerKind.CODING, 1)


if __name__ == "__main__":
    unittest.main()