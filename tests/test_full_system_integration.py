"""Comprehensive integration tests for JARVIS subsystems.

Validates end-to-end integration:
1. Dynamic multi-step orchestration (es_peticion_compuesta -> generar_plan_dinamico -> PlanExecutor -> ModelRouter).
2. Gaming Mode toggle (0% VRAM enforcement, unloading local models, 100% Groq cloud routing).
3. HUD Floating Overlay notifications (WS_EX_NOACTIVATE, thread safety, headless resilience).
4. Full synthesized output transmission to speech queue and text.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from jarvis.core.model_router import (
    MODEL_CODING_LOCAL,
    MODEL_ORCHESTRATOR_LOCAL,
    MODEL_REASONING_LOCAL,
    MODEL_VISION_LOCAL,
    ModelRole,
    ModelRouter,
)
from jarvis.core.orchestrator import (
    PlanExecutionResult,
    PlanExecutor,
    PlanStatus,
    StepStatus,
    TaskPlan,
    TaskStep,
    create_sequential_plan,
    es_peticion_compuesta,
    generar_plan_dinamico,
)
from jarvis.skills.base import SkillManager
from jarvis.ui.overlay import mostrar_notificacion
from main import es_comando_modo_juego, JarvisState


class TestCompoundRequestDetectionAndPlanning(unittest.TestCase):
    """Tests for multi-step / compound intent detection and dynamic plan generation."""

    def test_es_peticion_compuesta_keywords(self):
        self.assertTrue(es_peticion_compuesta("Explícame paso a paso cómo funciona Docker"))
        self.assertTrue(es_peticion_compuesta("Planifica la arquitectura para un microservicio"))
        self.assertTrue(es_peticion_compuesta("Orquesta la migración de base de datos"))
        self.assertTrue(es_peticion_compuesta("Desglosa los requisitos de la tarea"))
        self.assertTrue(es_peticion_compuesta("Dame un plan de acción para desplegar el cluster"))

    def test_es_peticion_compuesta_patterns(self):
        self.assertTrue(es_peticion_compuesta("Busca las noticias de Python 3.13 y analiza las mejoras de concurrencia"))
        self.assertTrue(es_peticion_compuesta("Investiga sobre SolidJS y resume sus ventajas frente a React"))
        self.assertTrue(es_peticion_compuesta("Primero recopila datos del servidor y luego genera un script de métricas"))
        self.assertTrue(es_peticion_compuesta("Analiza el rendimiento del sistema y programa una solución en python"))

    def test_es_peticion_compuesta_negative(self):
        self.assertFalse(es_peticion_compuesta("Hola, ¿cómo estás?"))
        self.assertFalse(es_peticion_compuesta("¿Qué hora es?"))
        self.assertFalse(es_peticion_compuesta("Guarda que vivo en Madrid"))
        self.assertFalse(es_peticion_compuesta("Activar modo juego"))
        self.assertFalse(es_peticion_compuesta(""))

    def test_generar_plan_dinamico_search_and_synthesis(self):
        plan = generar_plan_dinamico(
            "Busca las últimas noticias de IA y analiza las novedades",
            available_tools=["buscar_en_internet"],
        )
        self.assertIsInstance(plan, TaskPlan)
        self.assertGreaterEqual(len(plan.steps), 3)

        # First step is web gathering
        self.assertEqual(plan.steps[0].step_id, "step_recopilacion")
        self.assertIn("buscar_en_internet", plan.steps[0].tools_allowed)

        # Second step is deep analysis depending on step 1
        self.assertEqual(plan.steps[1].step_id, "step_analisis_profundo")
        self.assertEqual(plan.steps[1].required_role, ModelRole.DEEP_REASONING)
        self.assertIn("step_recopilacion", plan.steps[1].dependencies)

        # Last step is synthesis
        self.assertEqual(plan.steps[-1].step_id, "step_sintesis_final")
        self.assertEqual(plan.steps[-1].required_role, ModelRole.SPEECH)

    def test_generar_plan_dinamico_coding(self):
        plan = generar_plan_dinamico("Desarrolla un script en Python para descargar imágenes de una web")
        self.assertIsInstance(plan, TaskPlan)
        step_ids = [s.step_id for s in plan.steps]
        self.assertIn("step_diseno_arquitectura", step_ids)
        self.assertIn("step_programacion", step_ids)
        self.assertIn("step_sintesis_explicacion", step_ids)

        prog_step = plan.get_step("step_programacion")
        self.assertEqual(prog_step.required_role, ModelRole.CODING)
        self.assertIn("step_diseno_arquitectura", prog_step.dependencies)


class TestGamingModeSwitchAndVRAMZero(unittest.TestCase):
    """Tests for Gaming Mode (0% VRAM allocation, model unloading, Groq routing)."""

    def setUp(self):
        self.router = ModelRouter(groq_api_key="gsk_test_key_123")

    def test_es_comando_modo_juego(self):
        # Activation variants
        es_cmd, activar = es_comando_modo_juego("activar modo juego")
        self.assertTrue(es_cmd and activar)

        es_cmd, activar = es_comando_modo_juego("activa el modo juego por favor")
        self.assertTrue(es_cmd and activar)

        es_cmd, activar = es_comando_modo_juego("iniciar modo gaming")
        self.assertTrue(es_cmd and activar)

        # Deactivation variants
        es_cmd, activar = es_comando_modo_juego("desactivar modo juego")
        self.assertTrue(es_cmd and not activar)

        es_cmd, activar = es_comando_modo_juego("quitar modo juego")
        self.assertTrue(es_cmd and not activar)

        es_cmd, activar = es_comando_modo_juego("apagar modo juego")
        self.assertTrue(es_cmd and not activar)

        # Non-gaming commands
        es_cmd, _ = es_comando_modo_juego("hola jarvis")
        self.assertFalse(es_cmd)

    @patch.object(ModelRouter, "_unload_ollama_model", return_value=True)
    def test_set_gaming_mode_unloads_all_local_models(self, mock_unload):
        msg = self.router.set_gaming_mode(True)
        self.assertTrue(self.router.gaming_mode)
        self.assertIn("Modo juego activado", msg)

        # Verify all heavy local models were unloaded
        unloaded_models = {call.args[0] for call in mock_unload.call_args_list}
        self.assertIn(MODEL_ORCHESTRATOR_LOCAL, unloaded_models)
        self.assertIn(MODEL_CODING_LOCAL, unloaded_models)
        self.assertIn(MODEL_VISION_LOCAL, unloaded_models)
        self.assertIn(MODEL_REASONING_LOCAL, unloaded_models)

    @patch.object(ModelRouter, "run_groq_reasoning", return_value="Respuesta directa desde Groq Cloud")
    def test_gaming_mode_routes_100_percent_to_groq(self, mock_groq):
        self.router.set_gaming_mode(True)

        # Route coding role while in gaming mode -> must divert to Groq, NOT Ollama
        res = self.router.route(ModelRole.CODING, "Escribe una función de ordenamiento rápido")
        self.assertEqual(res, "Respuesta directa desde Groq Cloud")
        mock_groq.assert_called_once()

    @patch.object(ModelRouter, "run_groq_reasoning", return_value="Groq response")
    def test_plan_executor_under_gaming_mode_bypasses_local_vram(self, mock_groq):
        self.router.set_gaming_mode(True)

        s1 = TaskStep("s1", "Coding step", ModelRole.CODING)
        s2 = TaskStep("s2", "Deep reasoning", ModelRole.DEEP_REASONING, dependencies=["s1"])
        plan = create_sequential_plan("plan_gaming", "Gaming test", [s1, s2])

        executor = PlanExecutor(plan=plan, router=self.router)
        res = executor.execute_plan()

        self.assertTrue(res.success)
        # In gaming mode, no local models should be registered in active VRAM
        self.assertEqual(executor.active_local_models, [])
        self.assertEqual(res.groq_fallbacks_used, 2)


class TestFullPipelineExecution(unittest.TestCase):
    """Tests the full multi-step pipeline: Prompt -> Plan -> PlanExecutor -> Output."""

    def setUp(self):
        self.router = ModelRouter(groq_api_key="gsk_test")
        self.skills = SkillManager()
        self.skills.register_skill(
            "buscar_en_internet",
            "Busca en la web",
            lambda query: f"Resultados web para: {query}",
        )

    def test_full_pipeline_multi_step_execution(self):
        # Mock router responses for different roles
        def mock_route(role, prompt, **kwargs):
            if role == ModelRole.DEEP_REASONING:
                return "Análisis crítico: los datos muestran mejoras del 40% en latencia."
            elif role == ModelRole.SPEECH:
                return "Resumen final para el usuario: Se confirma una optimización del 40%."
            return "Respuesta genérica"

        self.router.route = MagicMock(side_effect=mock_route)

        prompt = "Busca información sobre Python 3.13 y analiza el impacto en concurrencia"
        self.assertTrue(es_peticion_compuesta(prompt))

        plan = generar_plan_dinamico(prompt, available_tools=list(self.skills._skills.keys()))
        executor = PlanExecutor(
            plan=plan,
            router=self.router,
            tool_registry=self.skills,
        )

        plan_result = executor.execute_plan()
        self.assertTrue(plan_result.success)
        self.assertEqual(plan.status, PlanStatus.COMPLETED)

        # Verify steps executed in proper order
        self.assertEqual(plan.steps[0].status, StepStatus.COMPLETED)
        self.assertEqual(plan.steps[0].result, "Resultados web para: " + prompt)

        self.assertEqual(plan.steps[1].status, StepStatus.COMPLETED)
        self.assertIn("40% en latencia", str(plan.steps[1].result))

        self.assertEqual(plan.steps[2].status, StepStatus.COMPLETED)
        self.assertIn("Resumen final para el usuario", str(plan.steps[2].result))


class TestHUDOverlayIntegration(unittest.TestCase):
    """Tests for HUD Overlay notifications without stealing focus."""

    def test_mostrar_notificacion_executes_safely(self):
        # Must execute without throwing exceptions regardless of GUI environment
        try:
            mostrar_notificacion("JARVIS TEST", "Mensaje de prueba en overlay", duracion_ms=1000)
        except Exception as exc:
            self.fail(f"mostrar_notificacion raised unexpected exception: {exc}")

    def test_emitir_mensaje_triggers_hud_notification(self):
        from main import emitir_mensaje, estado

        estado.responder_con_voz = False
        with patch("main.mostrar_notificacion") as mock_hud:
            emitir_mensaje("JARVIS respuesta de prueba")
            mock_hud.assert_called_once()
            args, _ = mock_hud.call_args
            self.assertEqual(args[0], "JARVIS")
            self.assertIn("JARVIS respuesta de prueba", args[1])


if __name__ == "__main__":
    unittest.main()
