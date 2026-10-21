from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import Mock

from jarvis.core.dynamic_skill_response import (
    MAX_MODEL_RESULT_CHARS,
    format_dynamic_skill_result_fallback,
    normalize_dynamic_skill_result,
    synthesize_dynamic_skill_response,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DynamicSkillResponseTests(unittest.TestCase):
    def test_dict_is_serialized_as_utf8_json(self) -> None:
        normalized = normalize_dynamic_skill_result({"estado": "Correcto", "versión": "1.2"})

        self.assertIn('"versión":"1.2"', normalized.model_data)
        self.assertNotIn("\\u", normalized.model_data)
        self.assertEqual(json.loads(normalized.model_data)["estado"], "Correcto")

    def test_list_is_normalized_as_json(self) -> None:
        normalized = normalize_dynamic_skill_result(["uno", 2, False])

        self.assertEqual(json.loads(normalized.model_data), ["uno", 2, False])

    def test_string_is_used_without_dict_style_conversion(self) -> None:
        normalized = normalize_dynamic_skill_result("respuesta directa")

        self.assertEqual(normalized.model_data, "respuesta directa")
        self.assertEqual(normalized.fallback_response, "respuesta directa")

    def test_none_has_clear_fallback(self) -> None:
        fallback = format_dynamic_skill_result_fallback(None)

        self.assertIn("no devolvió ningún resultado", fallback)

    def test_large_result_is_bounded_for_model(self) -> None:
        normalized = normalize_dynamic_skill_result({"contenido": "á" * 9000})

        self.assertTrue(normalized.truncated)
        self.assertEqual(len(normalized.model_data), MAX_MODEL_RESULT_CHARS)
        self.assertGreater(len(normalized.fallback_response), MAX_MODEL_RESULT_CHARS)

    def test_synthesizer_passes_request_skill_data_and_speech_role(self) -> None:
        router = Mock()
        router.route.return_value = "La versión disponible es 2.4."

        answer = synthesize_dynamic_skill_response(
            router,
            "comprobar_version",
            "¿Qué versión está disponible?",
            {"version": "2.4"},
        )

        self.assertEqual(answer, "La versión disponible es 2.4.")
        role, prompt = router.route.call_args.args
        self.assertEqual(role.value, "speech")
        self.assertIn("¿Qué versión está disponible?", prompt)
        self.assertIn("comprobar_version", prompt)
        self.assertIn('"version":"2.4"', prompt)
        self.assertIn("No inventes información", prompt)

    def test_empty_model_response_uses_deterministic_fallback(self) -> None:
        router = Mock()
        router.route.return_value = "  \n"
        result = {"estado": "Listo"}

        answer = synthesize_dynamic_skill_response(router, "estado", "Consulta", result)

        self.assertEqual(answer, format_dynamic_skill_result_fallback(result))

    def test_model_exception_uses_deterministic_fallback(self) -> None:
        router = Mock()
        router.route.side_effect = RuntimeError("model unavailable")
        result = ["primero", "segundo"]

        answer = synthesize_dynamic_skill_response(router, "lista", "Consulta", result)

        self.assertEqual(answer, format_dynamic_skill_result_fallback(result))

    def test_original_result_is_not_modified(self) -> None:
        result = {"estado": ["á", {"valor": 3}]}
        original = copy.deepcopy(result)

        normalize_dynamic_skill_result(result)

        self.assertEqual(result, original)

    def test_returned_content_is_never_executed(self) -> None:
        router = Mock()
        router.route.return_value = "Texto recibido."
        payload = "__import__('builtins').print('SHOULD_NOT_RUN')"

        answer = synthesize_dynamic_skill_response(router, "texto", "Muestra datos", payload)

        self.assertEqual(answer, "Texto recibido.")
        self.assertIn(payload, router.route.call_args.args[1])


class MainDynamicSkillResponseIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_confirmed_execution_uses_frozen_command_not_confirmation_text(self) -> None:
        calls = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "responder_dynamic_skill"
        ]
        call_sources = [ast.unparse(call) for call in calls]

        self.assertTrue(
            any(
                "pending_to_execute.skill_name" in call
                and "pending_to_execute.parameters.get('comando', '')" in call
                and "execution_result" in call
                and "usuario_limpio" not in call
                for call in call_sources
            ),
            call_sources,
        )

    def test_immediate_execution_uses_original_user_text(self) -> None:
        calls = [
            ast.unparse(node)
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "responder_dynamic_skill"
        ]

        self.assertTrue(any(
            "skill_a_ejecutar, usuario_limpio, resultado_skill" in call
            for call in calls
        ))

    def test_execution_failures_are_not_sent_to_synthesizer(self) -> None:
        execution_if = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "execution_result.executed"
        )
        self.assertTrue(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "responder_dynamic_skill"
                for statement in execution_if.body
                for node in ast.walk(statement)
            )
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "responder_dynamic_skill"
                for statement in execution_if.orelse
                for node in ast.walk(statement)
            )
        )

        immediate_failure_if = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "not resultado_skill.executed"
        )
        self.assertTrue(
            any(
                isinstance(node, ast.Continue)
                for statement in immediate_failure_if.body
                for node in ast.walk(statement)
            )
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "responder_dynamic_skill"
                for statement in immediate_failure_if.body
                for node in ast.walk(statement)
            )
        )

    def test_synthesized_text_is_forwarded_to_speech_history_and_memory(self) -> None:
        response_helper = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.FunctionDef) and node.name == "responder_dynamic_skill"
        )
        helper_source = ast.unparse(response_helper)
        self.assertIn("synthesize_dynamic_skill_response", helper_source)
        self.assertIn("speech_queue.add_message(respuesta)", helper_source)
        self.assertIn("registrar_en_historial(", helper_source)
        self.assertIn("memory.add_interaction(", helper_source)
        self.assertIn("respuesta)", helper_source)


if __name__ == "__main__":
    unittest.main()