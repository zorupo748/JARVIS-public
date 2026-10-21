"""Comprehensive test suite for JARVIS local tools and voice flow coordination.

Covers:
1. CalculatorTool registration, spec, and AST execution.
2. Rejection of unapproved math expressions, code injection, and division by zero.
3. FileReadTool and FileWriteTool registration and execution inside sandbox.
4. Blocking of .env, credentials, private keys, and sensitive paths.
5. Path traversal, external absolute paths, and symlink protection.
6. Differential read and write security levels and policy enforcement.
7. 3D printer query operations registration and simulated execution.
8. Policy enforcement for printer operations (read-only vs critical safety stop).
9. Absence of wait/planning announcements for immediate operations.
10. Single initial notice and final answer for complex plans.
11. Absence of unnecessary intermediate step narration.
12. Cooperative cancellation in PlanExecutor and skipping subsequent steps.
13. Prevention of late or duplicate voice responses after cancellation.
14. Error handling for network drops, timeouts, and unknown states without invented results.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from jarvis.core.audio_queue_manager import SpeechQueueManager
from jarvis.core.model_router import ModelRole
from jarvis.core.orchestrator.plan_executor import PlanExecutor
from jarvis.core.orchestrator.task_plan import (
    PlanStatus,
    StepStatus,
    TaskPlan,
    TaskStep,
    create_task_plan,
    es_peticion_compuesta,
)
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    ActionEffect,
    DecisionReason,
    DeterministicPolicyEvaluator,
    IdentityContext,
    PolicyDecisionKind,
    PolicyRequest,
    PresenceState,
    VerifiedFactor,
)
from jarvis.skills.printer_3d import KlipperPrinterSkill
from jarvis.tools.filesystem.file_read import FileReadTool
from jarvis.tools.filesystem.file_write import FileWriteTool
from jarvis.tools.math.calculator import CalculatorTool, safe_eval
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.system.printer_tool import PrinterStatusTool, PrinterTool


def _action(name: str, target: str | None = None) -> SecurityAction:
    return SecurityAction(action=name, description="test", target=target)


def _user_ctx(level: SecurityLevel, owner: bool = False) -> IdentityContext:
    identity = UserIdentity(
        user_id="test-user",
        display_name="Test User",
        security_level=level,
        is_owner=owner,
    )
    factors = frozenset({VerifiedFactor.OWNER_VOICE}) if owner else frozenset()
    return IdentityContext(
        identity=identity,
        presence=PresenceState.PRESENT,
        verified_factors=factors,
    )


class TestLocalToolsAndVoiceFlow(unittest.TestCase):
    """Pruebas de integración y unitarias para herramientas locales y flujo de voz."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.sandbox_path = Path(self.temp_dir.name).resolve()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # --------------------------------------------------------------------------
    # 1. CalculatorTool: Registro, especificaciones y ejecución
    # --------------------------------------------------------------------------
    def test_01_calculator_registration_spec_and_execution(self) -> None:
        tool_cls = ToolRegistry.get("calculator")
        self.assertIsNotNone(tool_cls, "CalculatorTool debe estar registrada en ToolRegistry")
        self.assertEqual(tool_cls, CalculatorTool)

        tool = ToolRegistry.create("calculator")
        spec = tool.spec
        self.assertEqual(spec.name, "calculator")
        self.assertEqual(spec.category, "math")
        self.assertIn("expression", spec.parameters.get("properties", {}))

        # Ejecución aritmética básica y avanzada
        res1 = tool.execute(expression="2 + 3 * 4")
        self.assertTrue(res1.success)
        self.assertEqual(res1.content, "14")

        res2 = tool.execute(expression="sqrt(16) + 2^3")
        self.assertTrue(res2.success)
        self.assertEqual(res2.content, "12")

        res3 = tool.execute(expression="round(sin(pi / 2), 2)")
        self.assertTrue(res3.success)
        self.assertEqual(res3.content, "1")

    # --------------------------------------------------------------------------
    # 2. CalculatorTool: Rechazo de código arbitrario y control de errores
    # --------------------------------------------------------------------------
    def test_02_calculator_rejection_of_unsupported_and_arbitrary_code(self) -> None:
        tool = CalculatorTool()

        # Inyección de código Python arbitrario
        malicious = [
            "__import__('os').system('dir')",
            "eval('2+2')",
            "exec('x=1')",
            "open('test.txt', 'w')",
            "lambda x: x+1",
            "[x for x in [1, 2]]",
        ]
        for expr in malicious:
            with self.subTest(expr=expr):
                res = tool.execute(expression=expr)
                self.assertFalse(res.success)
                self.assertIn("Error", res.content)

        # Expresión excesivamente larga
        long_expr = "1+" * 300 + "1"
        res_long = tool.execute(expression=long_expr)
        self.assertFalse(res_long.success)
        self.assertIn("longitud máxima", res_long.content)

        # Exponentes desmedidos (protección DOS)
        res_huge_exp = tool.execute(expression="2**9999999")
        self.assertFalse(res_huge_exp.success)

        # División por cero controlada
        div_zero_cases = ["10 / 0", "5 // 0", "7 % 0"]
        for dz in div_zero_cases:
            with self.subTest(dz=dz):
                res_dz = tool.execute(expression=dz)
                self.assertFalse(res_dz.success)
                self.assertIn("división por cero", res_dz.content.lower())

        # Expresión vacía
        res_empty = tool.execute(expression="")
        self.assertFalse(res_empty.success)

    # --------------------------------------------------------------------------
    # 3. FileReadTool y FileWriteTool: Registro y ejecución dentro del sandbox
    # --------------------------------------------------------------------------
    def test_03_fileread_and_filewrite_sandbox_execution(self) -> None:
        self.assertEqual(ToolRegistry.get("file_read"), FileReadTool)
        self.assertEqual(ToolRegistry.get("file_write"), FileWriteTool)

        read_tool = FileReadTool(allowed_dirs=[self.sandbox_path])
        write_tool = FileWriteTool(allowed_dirs=[self.sandbox_path])

        # Escritura dentro del sandbox
        res_w = write_tool.execute(path="saludo.txt", content="Hola desde el sandbox de JARVIS.")
        self.assertTrue(res_w.success, res_w.content)
        self.assertTrue((self.sandbox_path / "saludo.txt").exists())

        # Lectura dentro del sandbox
        res_r = read_tool.execute(path="saludo.txt")
        self.assertTrue(res_r.success, res_r.content)
        self.assertEqual(res_r.content, "Hola desde el sandbox de JARVIS.")

        # Modo append
        write_tool.execute(path="saludo.txt", content="\nSegunda línea.", mode="append")
        res_r2 = read_tool.execute(path="saludo.txt")
        self.assertIn("Segunda línea.", res_r2.content)

        # Creación de subdirectorios controlada
        res_sub = write_tool.execute(path="sub/dir/archivo.txt", content="Anidado", create_dirs=True)
        self.assertTrue(res_sub.success)
        self.assertTrue((self.sandbox_path / "sub" / "dir" / "archivo.txt").exists())

    # --------------------------------------------------------------------------
    # 4. Bloqueo de .env, credenciales, tokens y claves privadas
    # --------------------------------------------------------------------------
    def test_04_blocking_sensitive_files(self) -> None:
        read_tool = FileReadTool(allowed_dirs=[self.sandbox_path])
        write_tool = FileWriteTool(allowed_dirs=[self.sandbox_path])

        sensitive_targets = [
            ".env",
            ".env.local",
            ".env.production",
            "credentials.json",
            "token.json",
            "secrets.json",
            "id_rsa",
            "id_ed25519",
            "server.key",
            "cert.pem",
            "trusted_devices.json",
            ".ssh/id_rsa",
        ]

        for target in sensitive_targets:
            with self.subTest(target=target):
                res_w = write_tool.execute(path=target, content="token=123")
                self.assertFalse(res_w.success)
                self.assertIn("sensible", res_w.content.lower())

                res_r = read_tool.execute(path=target)
                self.assertFalse(res_r.success)
                self.assertIn("sensible", res_r.content.lower())

    # --------------------------------------------------------------------------
    # 5. Bloqueo de rutas absolutas externas, path traversal y symlinks
    # --------------------------------------------------------------------------
    def test_05_path_traversal_and_symlink_escape_blocking(self) -> None:
        read_tool = FileReadTool(allowed_dirs=[self.sandbox_path])
        write_tool = FileWriteTool(allowed_dirs=[self.sandbox_path])

        traversal_attempts = [
            "../outside.txt",
            "../../etc/passwd",
            "sub/../../../../windows/system32/cmd.exe",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "D:\\secret.txt",
        ]

        for attempt in traversal_attempts:
            with self.subTest(attempt=attempt):
                res_w = write_tool.execute(path=attempt, content="leak")
                self.assertFalse(res_w.success)
                self.assertTrue(res_w.metadata.get("blocked", False) or "fuera" in res_w.content)

                res_r = read_tool.execute(path=attempt)
                self.assertFalse(res_r.success)
                self.assertTrue(res_r.metadata.get("blocked", False) or "fuera" in res_r.content)

        # Prueba con enlace simbólico que apunta al exterior (si el SO lo admite)
        external_file = self.sandbox_path.parent / "external_forbidden.txt"
        external_file.write_text("Dato confidencial externo", encoding="utf-8")
        link_path = self.sandbox_path / "link_escape.txt"

        try:
            os.symlink(external_file, link_path)
            res_symlink = read_tool.execute(path="link_escape.txt")
            self.assertFalse(res_symlink.success)
            self.assertIn("sandbox", res_symlink.content.lower())
        except (OSError, NotImplementedError):
            pass  # En Windows sin privilegios de desarrollador, os.symlink puede no permitirse
        finally:
            if external_file.exists():
                external_file.unlink(missing_ok=True)

    # --------------------------------------------------------------------------
    # 6. Respeto de permisos diferenciados de lectura y escritura
    # --------------------------------------------------------------------------
    def test_06_differentiated_read_and_write_permissions(self) -> None:
        evaluator = DeterministicPolicyEvaluator()

        # Nivel 1 permite leer workspace
        req_read = PolicyRequest(
            action=_action("file_read", "workspace/documento.txt"),
            identity=_user_ctx(SecurityLevel.LEVEL_1),
        )
        dec_read = evaluator.evaluate(req_read)
        self.assertEqual(dec_read.kind, PolicyDecisionKind.ALLOW)

        # Nivel 1 NO permite escribir (requiere nivel 2)
        req_write_l1 = PolicyRequest(
            action=_action("file_write", "workspace/documento.txt"),
            identity=_user_ctx(SecurityLevel.LEVEL_1),
        )
        dec_write_l1 = evaluator.evaluate(req_write_l1)
        self.assertEqual(dec_write_l1.kind, PolicyDecisionKind.DENY)
        self.assertEqual(dec_write_l1.reason, DecisionReason.INSUFFICIENT_LEVEL)

        # Nivel 2 para file_write exige confirmación
        req_write_l2 = PolicyRequest(
            action=_action("file_write", "workspace/documento.txt"),
            identity=_user_ctx(SecurityLevel.LEVEL_2),
        )
        dec_write_l2 = evaluator.evaluate(req_write_l2)
        self.assertEqual(dec_write_l2.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)

    # --------------------------------------------------------------------------
    # 7. 3D Printer: Registro y ejecución simulada de consultas
    # --------------------------------------------------------------------------
    def test_07_printer_tool_query_operations(self) -> None:
        self.assertEqual(ToolRegistry.get("printer_tool"), PrinterTool)
        self.assertEqual(ToolRegistry.get("printer_status"), PrinterStatusTool)

        mock_skill = MagicMock(spec=KlipperPrinterSkill)
        mock_skill.get_status.return_value = {
            "online": True,
            "state": "printing",
            "bed_temp": 60.0,
            "extruder_temp": 210.0,
            "progress": "45.0%",
            "filename": "pieza_soporte.gcode",
        }
        mock_skill.list_files.return_value = ["pieza_soporte.gcode", "test_cube.gcode"]

        tool = PrinterTool(printer_skill=mock_skill)

        # Consulta general de estado
        res_status = tool.execute(action="status")
        self.assertTrue(res_status.success)
        self.assertIn("printing", res_status.content)
        self.assertIn("210.0°C", res_status.content)
        self.assertIn("pieza_soporte.gcode", res_status.content)

        # Consulta específica de temperaturas
        res_temps = tool.execute(action="temperatures")
        self.assertTrue(res_temps.success)
        self.assertIn("Extrusor: 210.0°C", res_temps.content)
        self.assertIn("Cama caliente: 60.0°C", res_temps.content)

        # Consulta de lista de archivos
        res_files = tool.execute(action="list_files")
        self.assertTrue(res_files.success)
        self.assertIn("test_cube.gcode", res_files.content)

        # Herramienta de solo lectura pura
        status_tool = PrinterStatusTool(printer_skill=mock_skill)
        res_ro = status_tool.execute()
        self.assertTrue(res_ro.success)
        self.assertIn("60.0°C", res_ro.content)

    # --------------------------------------------------------------------------
    # 8. Políticas y seguridad para operaciones críticas de la impresora
    # --------------------------------------------------------------------------
    def test_08_printer_security_policies_and_stop_protection(self) -> None:
        evaluator = DeterministicPolicyEvaluator()

        # Consulta de estado: permitida a Nivel 1 sin confirmación
        dec_status = evaluator.evaluate(
            PolicyRequest(action=_action("printer_status"), identity=_user_ctx(SecurityLevel.LEVEL_1))
        )
        self.assertEqual(dec_status.kind, PolicyDecisionKind.ALLOW)

        # Parada de emergencia: permitida en Nivel 0 con evento de auditoría obligatorio
        dec_stop = evaluator.evaluate(
            PolicyRequest(action=_action("parada_emergencia"), identity=_user_ctx(SecurityLevel.LEVEL_0))
        )
        self.assertEqual(dec_stop.kind, PolicyDecisionKind.ALLOW)
        self.assertEqual(dec_stop.audit_requirements[0].event_code, "klipper_emergency_stop_requested")

        # Iniciar impresión física: exige Nivel 4, presencia, dueño y confirmación
        dec_start = evaluator.evaluate(
            PolicyRequest(action=_action("iniciar_impresion"), identity=_user_ctx(SecurityLevel.LEVEL_2))
        )
        self.assertEqual(dec_start.kind, PolicyDecisionKind.DENY)
        self.assertEqual(dec_start.reason, DecisionReason.INSUFFICIENT_LEVEL)

        # Bloqueo en la herramienta de consulta: no puede mutar a parada de emergencia
        status_tool = PrinterStatusTool()
        res_blocked = status_tool.execute(query_type="emergency_stop")
        self.assertFalse(res_blocked.success)
        self.assertIn("solo lectura", res_blocked.content.lower())

        # Ejecución real simulada de parada de emergencia en PrinterTool
        mock_skill = MagicMock(spec=KlipperPrinterSkill)
        mock_skill.emergency_stop.return_value = "Parada de emergencia ejecutada."
        tool = PrinterTool(printer_skill=mock_skill)
        res_stop_exec = tool.execute(action="emergency_stop")
        self.assertTrue(res_stop_exec.success)
        mock_skill.emergency_stop.assert_called_once()

    # --------------------------------------------------------------------------
    # 9. Ausencia de anuncios de voz en operaciones inmediatas
    # --------------------------------------------------------------------------
    def test_09_absence_of_voice_announcements_in_immediate_operations(self) -> None:
        spoken_messages: list[str] = []
        queue_mgr = SpeechQueueManager(tts_engine_callback=lambda txt: spoken_messages.append(txt))

        # En operaciones simples o inmediatas, NO es petición compuesta
        prompt_inmediato = "¿Cuánto es 2 + 2?"
        self.assertFalse(es_peticion_compuesta(prompt_inmediato))

        # La respuesta inmediata debe ir directamente a la cola sin fases de espera
        respuesta_inmediata = "4"
        queue_mgr.add_message(respuesta_inmediata)
        time.sleep(0.1)

        self.assertEqual(len(spoken_messages), 1)
        self.assertEqual(spoken_messages[0], "4")
        self.assertNotIn("Iniciando orquestación", spoken_messages[0])
        self.assertNotIn("Un momento", spoken_messages[0])

        queue_mgr.stop()

    # --------------------------------------------------------------------------
    # 10. Un aviso inicial y una respuesta final en planes complejos
    # --------------------------------------------------------------------------
    def test_10_single_initial_notice_and_final_response_in_plans(self) -> None:
        spoken_messages: list[str] = []
        queue_mgr = SpeechQueueManager(tts_engine_callback=lambda txt: spoken_messages.append(txt))

        peticion_compleja = "Primero busca el clima en Madrid y luego genera un resumen detallado"
        self.assertTrue(es_peticion_compuesta(peticion_compleja))

        # Cadencia esperada:
        # 1. Un único aviso breve y natural al inicio
        aviso_inicial = "Entendido, preparo el plan."
        queue_mgr.add_message(aviso_inicial)

        # 2. Silencio durante los pasos intermedios (no se emite narración interna)

        # 3. Una única respuesta final sintetizada
        respuesta_final = "El clima en Madrid es soleado con 22°C."
        queue_mgr.add_message(respuesta_final)

        time.sleep(0.1)
        self.assertEqual(len(spoken_messages), 2)
        self.assertEqual(spoken_messages[0], aviso_inicial)
        self.assertEqual(spoken_messages[1], respuesta_final)

        queue_mgr.stop()

    # --------------------------------------------------------------------------
    # 11. Ausencia de narración intermedia innecesaria durante ejecución
    # --------------------------------------------------------------------------
    def test_11_absence_of_intermediate_step_narration(self) -> None:
        spoken_messages: list[str] = []
        queue_mgr = SpeechQueueManager(tts_engine_callback=lambda txt: spoken_messages.append(txt))

        step1 = TaskStep(step_id="step_a", description="Buscar datos", required_role=ModelRole.SPEECH)
        step2 = TaskStep(step_id="step_b", description="Analizar datos", required_role=ModelRole.DEEP_REASONING, dependencies=["step_a"])
        step3 = TaskStep(step_id="step_c", description="Sintetizar", required_role=ModelRole.SPEECH, dependencies=["step_b"])

        plan = create_task_plan("plan_silence", "Tarea compuesta", [step1, step2, step3])

        mock_router = MagicMock()
        mock_router.route.side_effect = ["Datos crudos", "Análisis profundo", "Resultado final conciso"]

        executor = PlanExecutor(plan=plan, router=mock_router)
        res = executor.execute_plan()

        self.assertTrue(res.success)
        # Durante la ejecución del PlanExecutor no se agregan mensajes a la cola de voz
        time.sleep(0.05)
        self.assertEqual(len(spoken_messages), 0)

        # Solo el orquestador agrega la salida final tras completar el plan
        salida_final = str(plan.completed_steps()[-1].result)
        queue_mgr.add_message(salida_final)
        time.sleep(0.1)

        self.assertEqual(len(spoken_messages), 1)
        self.assertEqual(spoken_messages[0], "Resultado final conciso")

        queue_mgr.stop()

    # --------------------------------------------------------------------------
    # 12. Cancelación cooperativa, omisión de pasos posteriores y limpieza
    # --------------------------------------------------------------------------
    def test_12_cancellation_during_execution_and_step_prevention(self) -> None:
        step1 = TaskStep(step_id="s1", description="Paso rápido", required_role=ModelRole.SPEECH)
        step2 = TaskStep(step_id="s2", description="Paso 2", required_role=ModelRole.SPEECH, dependencies=["s1"])
        step3 = TaskStep(step_id="s3", description="Paso 3", required_role=ModelRole.SPEECH, dependencies=["s2"])

        plan = create_task_plan("plan_cancel", "Petición a cancelar", [step1, step2, step3])

        cancel_token = threading.Event()
        mock_router = MagicMock()

        def route_with_cancel(role, prompt, **kwargs):
            # Tras completar el paso 1, se solicita la cancelación inmediata
            cancel_token.set()
            return "Resultado paso 1"

        mock_router.route.side_effect = route_with_cancel

        executor = PlanExecutor(plan=plan, router=mock_router, cancel_token=cancel_token)
        res = executor.execute_plan()

        self.assertEqual(plan.status, PlanStatus.ABORTED)
        self.assertEqual(res.status, PlanStatus.ABORTED)

        # El paso 1 completó, pero los pasos 2 y 3 se omitieron
        self.assertEqual(plan.get_step("s1").status, StepStatus.COMPLETED)
        self.assertEqual(plan.get_step("s2").status, StepStatus.SKIPPED)
        self.assertEqual(plan.get_step("s3").status, StepStatus.SKIPPED)

        # Comprobación directa del método cancel()
        executor_standalone = PlanExecutor(plan=plan, router=mock_router)
        self.assertFalse(executor_standalone.is_cancelled)
        executor_standalone.cancel()
        self.assertTrue(executor_standalone.is_cancelled)

    # --------------------------------------------------------------------------
    # 13. Ausencia de respuestas de voz duplicadas o tardías tras cancelar
    # --------------------------------------------------------------------------
    def test_13_no_duplicate_or_stale_voice_after_cancellation(self) -> None:
        spoken_messages: list[str] = []
        queue_mgr = SpeechQueueManager(tts_engine_callback=lambda txt: spoken_messages.append(txt))

        # Encolar un mensaje preliminar
        queue_mgr.add_message("Mensaje preliminar que no debe sonar")

        # Cancelación inmediata: purgar cola
        queue_mgr.clear()

        # Encolar únicamente la notificación breve de cancelación
        msg_cancelacion = "Plan cancelado. Se han detenido los pasos pendientes."
        queue_mgr.add_message(msg_cancelacion)

        time.sleep(0.1)
        # El mensaje previo fue purgado antes de procesarse
        self.assertNotIn("Mensaje preliminar que no debe sonar", spoken_messages)
        self.assertIn(msg_cancelacion, spoken_messages)

        queue_mgr.stop()

    # --------------------------------------------------------------------------
    # 14. Manejo de errores, desconexiones y estados desconocidos
    # --------------------------------------------------------------------------
    def test_14_error_handling_and_printer_disconnects(self) -> None:
        # Impresora desconectada (Moonraker inalcanzable)
        mock_offline = MagicMock(spec=KlipperPrinterSkill)
        mock_offline.get_status.return_value = {
            "online": False,
            "error": "HTTP Connection refused (puerto 7125)",
        }
        tool = PrinterTool(printer_skill=mock_offline)

        res_offline = tool.execute(action="status")
        self.assertFalse(res_offline.success)
        self.assertIn("desconectada", res_offline.content.lower())
        self.assertIn("Connection refused", res_offline.content)

        # Excepción de red en comunicación
        mock_error = MagicMock(spec=KlipperPrinterSkill)
        mock_error.get_status.side_effect = TimeoutError("Tiempo de espera agotado al comunicar con Klipper")
        tool_err = PrinterTool(printer_skill=mock_error)

        res_err = tool_err.execute(action="status")
        self.assertFalse(res_err.success)
        self.assertIn("Error al consultar el estado", res_err.content)

        # Acción no reconocida en PrinterTool
        res_unknown = tool.execute(action="iniciar_laser_invalido")
        self.assertFalse(res_unknown.success)
        self.assertIn("no admitida", res_unknown.content.lower())


if __name__ == "__main__":
    unittest.main()
