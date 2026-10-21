"""Unit tests for the Multi-Model Step Orchestrator in JARVIS.

Tests:
1. TaskPlan creation, DAG validation, dependency ordering, and cycle detection.
2. VRAM constraint enforcement (max 2 active local models, LRU eviction, and Groq fallback).
3. Step execution with tool whitelisting, output validation, and SkillErrorHandler triage.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, call, patch

from jarvis.core.model_router import (
    MODEL_CODING_LOCAL,
    MODEL_ORCHESTRATOR_LOCAL,
    MODEL_REASONING_LOCAL,
    MODEL_VISION_LOCAL,
    ModelRole,
)
from jarvis.core.orchestrator.plan_executor import (
    MAX_CONCURRENT_LOCAL_MODELS,
    PlanExecutionResult,
    PlanExecutor,
    StepExecutionResult,
)
from jarvis.core.orchestrator.task_plan import (
    PlanStatus,
    PlanValidationError,
    StepStatus,
    TaskPlan,
    TaskStep,
    create_sequential_plan,
    create_task_plan,
)
from jarvis.core.skill_error_handler import SkillTriageDecision
from jarvis.core.vram_manager import VramManager
from jarvis.tools.base import ToolResult


class TestTaskPlan(unittest.TestCase):
    """Test plan structure, DAG dependencies, serialization, and validation."""

    def test_create_valid_dag_plan(self):
        s1 = TaskStep(
            step_id="step_fetch",
            description="Fetch relevant documentation",
            required_role=ModelRole.SPEECH,
            tools_allowed=["web_search"],
            expected_output="urls",
        )
        s2 = TaskStep(
            step_id="step_code",
            description="Write parser code",
            required_role=ModelRole.CODING,
            dependencies=["step_fetch"],
            tools_allowed=[],
            expected_output="python code",
        )
        s3 = TaskStep(
            step_id="step_review",
            description="Review code quality",
            required_role=ModelRole.DEEP_REASONING,
            dependencies=["step_code"],
            expected_output="approved",
        )

        plan = create_task_plan(
            plan_id="plan_001",
            user_request="Build a parser",
            steps=[s1, s2, s3],
        )

        self.assertEqual(plan.plan_id, "plan_001")
        self.assertEqual(len(plan.steps), 3)
        order = plan.execution_order()
        self.assertEqual([s.step_id for s in order], ["step_fetch", "step_code", "step_review"])
        self.assertEqual(plan.get_ready_steps(), [s1])

    def test_create_sequential_plan_helper(self):
        s1 = TaskStep("s1", "Step 1", ModelRole.SPEECH)
        s2 = TaskStep("s2", "Step 2", ModelRole.CODING)
        s3 = TaskStep("s3", "Step 3", ModelRole.DEEP_REASONING)

        plan = create_sequential_plan("seq_001", "Linear workflow", [s1, s2, s3])
        self.assertEqual(s2.dependencies, ["s1"])
        self.assertEqual(s3.dependencies, ["s2"])
        self.assertEqual([s.step_id for s in plan.execution_order()], ["s1", "s2", "s3"])

    def test_duplicate_step_id_raises_error(self):
        s1 = TaskStep("dup_id", "First step", ModelRole.SPEECH)
        s2 = TaskStep("dup_id", "Second step", ModelRole.CODING)

        with self.assertRaises(PlanValidationError):
            create_task_plan("plan_dup", "Query", [s1, s2])

    def test_missing_dependency_raises_error(self):
        s1 = TaskStep("step_1", "Do something", ModelRole.SPEECH, dependencies=["non_existent_step"])

        with self.assertRaises(PlanValidationError):
            create_task_plan("plan_missing", "Query", [s1])

    def test_self_dependency_raises_error(self):
        s1 = TaskStep("step_1", "Do something", ModelRole.SPEECH, dependencies=["step_1"])

        with self.assertRaises(PlanValidationError):
            create_task_plan("plan_self", "Query", [s1])

    def test_circular_dependency_raises_error(self):
        s1 = TaskStep("s1", "Step 1", ModelRole.SPEECH, dependencies=["s3"])
        s2 = TaskStep("s2", "Step 2", ModelRole.CODING, dependencies=["s1"])
        s3 = TaskStep("s3", "Step 3", ModelRole.DEEP_REASONING, dependencies=["s2"])

        with self.assertRaises(PlanValidationError):
            create_task_plan("plan_cycle", "Cycle", [s1, s2, s3])

    def test_plan_serialization_roundtrip(self):
        s1 = TaskStep(
            step_id="step_1",
            description="Analyze image",
            required_role=ModelRole.VISION,
            tools_allowed=["ocr"],
            expected_output="json",
            metadata={"test_key": "test_val"},
        )
        plan = create_task_plan("plan_serial", "Process receipt", [s1])
        plan_dict = plan.to_dict()

        restored_plan = TaskPlan.from_dict(plan_dict)
        self.assertEqual(restored_plan.plan_id, "plan_serial")
        self.assertEqual(len(restored_plan.steps), 1)
        self.assertEqual(restored_plan.steps[0].required_role, ModelRole.VISION)
        self.assertEqual(restored_plan.steps[0].metadata["test_key"], "test_val")


class TestPlanExecutorVRAMConstraints(unittest.TestCase):
    """Test VRAM capacity management: max 2 local models, LRU eviction, and Groq fallback."""

    def setUp(self):
        self.mock_router = MagicMock()
        self.mock_router.groq_api_key = "gsk-mock-key"
        self.mock_router._unload_ollama_model = MagicMock(return_value=True)
        self.mock_router.route = MagicMock(return_value="Local response content")
        self.mock_router.run_groq_reasoning = MagicMock(return_value="Groq cloud response")
        self.mock_vram_manager = VramManager()

    def test_max_two_concurrent_local_models_enforced_with_lru_eviction(self):
        """Simulate loading 3 distinct local models sequentially with a limit of 2."""
        s1 = TaskStep("step_code", "Code generation", ModelRole.CODING)          # MODEL_CODING_LOCAL
        s2 = TaskStep("step_vision", "Image processing", ModelRole.VISION)       # MODEL_VISION_LOCAL
        s3 = TaskStep("step_reason", "Deep logic", ModelRole.DEEP_REASONING)     # MODEL_REASONING_LOCAL

        plan = create_sequential_plan("plan_vram", "Multi specialist", [s1, s2, s3])
        executor = PlanExecutor(
            plan=plan,
            router=self.mock_router,
            vram_manager=self.mock_vram_manager,
            max_local_models=2,
        )

        # 1. Step 1 runs Coding model
        res1 = executor.execute_step("step_code")
        self.assertTrue(res1.success)
        self.assertEqual(executor.active_local_models, [MODEL_CODING_LOCAL])
        self.assertEqual(len(executor.active_local_models), 1)

        # 2. Step 2 runs Vision model (now 2 active, capacity reached)
        res2 = executor.execute_step("step_vision")
        self.assertTrue(res2.success)
        self.assertEqual(executor.active_local_models, [MODEL_CODING_LOCAL, MODEL_VISION_LOCAL])
        self.assertEqual(len(executor.active_local_models), 2)
        self.mock_router._unload_ollama_model.assert_not_called()

        # 3. Step 3 runs Reasoning model -> must evict LRU model (Coding)
        res3 = executor.execute_step("step_reason")
        self.assertTrue(res3.success)
        # Verify Coding was unloaded from VRAM
        self.mock_router._unload_ollama_model.assert_called_once_with(MODEL_CODING_LOCAL)
        # Active models should now be Vision and Reasoning (still exactly 2)
        self.assertEqual(executor.active_local_models, [MODEL_VISION_LOCAL, MODEL_REASONING_LOCAL])
        self.assertEqual(len(executor.active_local_models), 2)

    def test_reusing_active_model_refreshes_lru_without_eviction(self):
        """Re-using an already active model shouldn't evict, but update LRU priority."""
        s1 = TaskStep("step_1", "Code", ModelRole.CODING)
        s2 = TaskStep("step_2", "Vision", ModelRole.VISION)
        s3 = TaskStep("step_3", "Code again", ModelRole.CODING)
        s4 = TaskStep("step_4", "Reasoning", ModelRole.DEEP_REASONING)

        plan = create_sequential_plan("plan_refresh", "Workflow", [s1, s2, s3, s4])
        executor = PlanExecutor(
            plan=plan,
            router=self.mock_router,
            vram_manager=self.mock_vram_manager,
            max_local_models=2,
        )

        executor.execute_step("step_1")  # Coding
        executor.execute_step("step_2")  # Vision -> Active: [Coding, Vision]
        executor.execute_step("step_3")  # Coding reused -> Active: [Vision, Coding]

        self.mock_router._unload_ollama_model.assert_not_called()
        self.assertEqual(executor.active_local_models, [MODEL_VISION_LOCAL, MODEL_CODING_LOCAL])

        # Step 4 needs Reasoning -> least recently used is now Vision!
        executor.execute_step("step_4")
        self.mock_router._unload_ollama_model.assert_called_once_with(MODEL_VISION_LOCAL)
        self.assertEqual(executor.active_local_models, [MODEL_CODING_LOCAL, MODEL_REASONING_LOCAL])

    def test_vram_limit_diverts_to_groq_when_prefer_cloud_is_set(self):
        """When prefer_groq_on_vram_limit=True, 3rd model routes to Groq cloud."""
        s1 = TaskStep("step_1", "Code", ModelRole.CODING)
        s2 = TaskStep("step_2", "Vision", ModelRole.VISION)
        s3 = TaskStep("step_3", "Reasoning via cloud", ModelRole.DEEP_REASONING)

        plan = create_sequential_plan("plan_groq", "Cloud agile", [s1, s2, s3])
        executor = PlanExecutor(
            plan=plan,
            router=self.mock_router,
            vram_manager=self.mock_vram_manager,
            max_local_models=2,
            prefer_groq_on_vram_limit=True,
        )

        executor.execute_step("step_1")
        executor.execute_step("step_2")
        self.assertEqual(len(executor.active_local_models), 2)

        res3 = executor.execute_step("step_3")
        self.assertTrue(res3.success)
        self.assertTrue(res3.used_groq)
        self.mock_router.run_groq_reasoning.assert_called_once()
        # VRAM stayed at 2 local models, no unload necessary
        self.mock_router._unload_ollama_model.assert_not_called()
        self.assertEqual(executor.active_local_models, [MODEL_CODING_LOCAL, MODEL_VISION_LOCAL])


class TestPlanExecutorExecutionAndTriage(unittest.TestCase):
    """Test step execution, tool permissions, output validation, and triage with SkillErrorHandler."""

    def setUp(self):
        self.mock_router = MagicMock()
        self.mock_router.route = MagicMock(return_value="Respuesta de código exitosa ```python\nprint('hello')\n```")
        self.mock_error_handler = MagicMock()
        self.mock_tools = MagicMock()

    def test_tool_whitelisting_allows_authorized_and_blocks_unauthorized(self):
        # Step with authorized tool
        s_auth = TaskStep(
            step_id="step_calc",
            description="Calculate balance",
            required_role=ModelRole.SPEECH,
            tools_allowed=["calculator"],
            metadata={"tool_name": "calculator", "tool_args": {"expression": "2+2"}},
        )
        self.mock_tools.execute = MagicMock(return_value=ToolResult("calculator", "4", True))

        plan = create_task_plan("plan_tool", "Calculate", [s_auth])
        executor = PlanExecutor(plan=plan, router=self.mock_router, tool_registry=self.mock_tools)
        res_auth = executor.execute_step("step_calc")

        self.assertTrue(res_auth.success)
        self.mock_tools.execute.assert_called_once_with("calculator", expression="2+2")

        # Step attempting unauthorized tool
        s_unauth = TaskStep(
            step_id="step_shell",
            description="Run command",
            required_role=ModelRole.SPEECH,
            tools_allowed=["calculator"],  # 'shell_exec' is NOT authorized
            metadata={"tool_name": "shell_exec", "tool_args": {"cmd": "dir"}},
        )
        plan_blocked = create_task_plan("plan_blocked", "Hack", [s_unauth])
        executor_blocked = PlanExecutor(plan=plan_blocked, router=self.mock_router, tool_registry=self.mock_tools)
        res_unauth = executor_blocked.execute_step("step_shell")

        self.assertFalse(res_unauth.success)
        self.assertIn("forbidden", res_unauth.error.lower())

    def test_expected_output_validation_json_contract(self):
        # 1. Successful JSON output
        s_json = TaskStep(
            step_id="step_json",
            description="Generate JSON data",
            required_role=ModelRole.CODING,
            expected_output="json",
        )
        self.mock_router.route.return_value = '{"status": "ok", "items": [1, 2, 3]}'

        plan = create_task_plan("plan_valid", "JSON task", [s_json])
        executor = PlanExecutor(plan=plan, router=self.mock_router)
        res = executor.execute_step("step_json")
        self.assertTrue(res.success)

        # 2. Failed JSON output (invalid syntax)
        s_invalid_json = TaskStep(
            step_id="step_bad_json",
            description="Generate JSON data",
            required_role=ModelRole.CODING,
            expected_output="json",
        )
        self.mock_router.route.return_value = "Esta es una respuesta en texto plano sin ningún objeto"

        plan_bad = create_task_plan("plan_invalid", "JSON task", [s_invalid_json])
        executor_bad = PlanExecutor(plan=plan_bad, router=self.mock_router)
        res_bad = executor_bad.execute_step("step_bad_json")
        self.assertFalse(res_bad.success)
        self.assertIn("json", res_bad.error.lower())

    def test_step_failure_triggers_skill_error_handler_triage_and_repair(self):
        """Verify SkillErrorHandler.triage is called on error, and can_repair enables self-repair retry."""
        step = TaskStep(
            step_id="step_code_repair",
            description="Write function",
            required_role=ModelRole.CODING,
            expected_output="código",
        )
        plan = create_task_plan("plan_repair", "Write code", [step])

        # First call fails validation (no code block); second call provides proper code
        self.mock_router.route.side_effect = [
            "No he podido escribir el código aún.",
            "```python\ndef saludar():\n    return 'hola'\n```",
        ]

        self.mock_error_handler.triage.return_value = SkillTriageDecision(
            can_repair=True,
            repair_strategy="auto_code_repair",
            root_cause="Missing code block",
            executive_summary="Se ha reintentado la generación de código.",
        )

        executor = PlanExecutor(
            plan=plan,
            router=self.mock_router,
            error_handler=self.mock_error_handler,
            max_retries_per_step=1,
        )

        res = executor.execute_step("step_code_repair")
        self.assertTrue(res.success)
        self.assertEqual(res.retries, 1)
        self.mock_error_handler.triage.assert_called_once()

    def test_full_plan_execution_aborts_dependents_on_unrepairable_failure(self):
        """If step 1 fails unrepairably, step 2 (dependent) is skipped and plan marked FAILED."""
        s1 = TaskStep("s1", "Fetch data", ModelRole.SPEECH)
        s2 = TaskStep("s2", "Process data", ModelRole.CODING, dependencies=["s1"])

        plan = create_task_plan("plan_fail", "Process", [s1, s2])

        self.mock_router.route.side_effect = RuntimeError("Fatal connection error")
        self.mock_error_handler.triage.return_value = SkillTriageDecision(
            can_repair=False,
            repair_strategy="none",
            root_cause="Network unreachable",
            executive_summary="Fallo de red sin posibilidad de autoreparación.",
        )

        executor = PlanExecutor(
            plan=plan,
            router=self.mock_router,
            error_handler=self.mock_error_handler,
            max_retries_per_step=0,
        )

        plan_result = executor.execute_plan()
        self.assertFalse(plan_result.success)
        self.assertEqual(plan_result.status, PlanStatus.FAILED)
        self.assertEqual(plan.get_step("s1").status, StepStatus.FAILED)
        self.assertEqual(plan.get_step("s2").status, StepStatus.SKIPPED)


if __name__ == "__main__":
    unittest.main()
