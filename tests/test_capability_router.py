from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

from jarvis.core.capability_router import (
    CapabilityDecision,
    CapabilityRouter,
    NATIVE_CAPABILITIES,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAIN_SOURCE = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
MODEL_ROUTER_SOURCE = (
    PROJECT_ROOT / "src" / "jarvis" / "core" / "model_router.py"
).read_text(encoding="utf-8")


def model_response(decision: str, *, confidence: float = 0.96) -> str:
    return json.dumps(
        {
            "decision": decision,
            "reason": "reusable missing capability",
            "confidence": confidence,
        }
    )


class CapabilityRouterTests(unittest.TestCase):
    PACKAGE_REQUEST = (
        "Cuando te pregunte dónde está mi paquete quiero que consultes 1688track "
        "usando el código OXCGH6082081H, me expliques en español dónde está, qué "
        "ha pasado, qué se espera que ocurra después, recuerdes el estado anterior "
        "y me digas si ha cambiado desde la última vez."
    )

    def test_knowledge_question_is_a_direct_response(self) -> None:
        route = CapabilityRouter().decide("¿Qué es un transistor?")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_simple_calculation_is_a_direct_response(self) -> None:
        route = CapabilityRouter().decide("¿Cuánto es 5+7?")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_installed_skill_match_wins(self) -> None:
        route = CapabilityRouter().decide(
            "Busca el precio actual de bitcoin",
            existing_skill_name="bitcoin_price",
        )
        self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_SKILL)
        self.assertEqual(route.skill_name, "bitcoin_price")

    def test_native_web_search_is_selected(self) -> None:
        route = CapabilityRouter().decide("Busca en internet el horario de hoy")
        self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_TOOL)
        self.assertEqual(route.native_tool_name, "buscar_en_internet")

    def test_reusable_missing_capability_can_create_skill(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("CREATE_SKILL"))
        route = router.decide("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(route.decision, CapabilityDecision.CREATE_SKILL)

    def test_tracking_with_future_memory_can_create_skill(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("CREATE_SKILL"))
        route = router.decide(
            self.PACKAGE_REQUEST
        )
        self.assertEqual(route.decision, CapabilityDecision.CREATE_SKILL)

    def test_package_tracking_is_created_deterministically_without_model(self) -> None:
        router = CapabilityRouter(
            lambda _prompt: self.fail("clear public tracking intent should use the rule")
        )
        route = router.route(self.PACKAGE_REQUEST)

        self.assertEqual(route.decision, CapabilityDecision.CREATE_SKILL)
        self.assertEqual(route.reason, "reusable_external_tracking")
        self.assertEqual(route.source, "rule")

    def test_reusable_public_web_api_and_package_tracking_requests_create_skill(self) -> None:
        requests = (
            "Quiero que cada vez que te pregunte consultes una web pública concreta "
            "y recuerdes si el resultado ha cambiado.",
            "Consulta periódicamente una API pública de un proyecto y recuerda la "
            "última versión que vimos.",
            "Quiero poder preguntarte dónde está mi paquete y que recuerdes el "
            "último estado.",
        )
        for request in requests:
            with self.subTest(request=request):
                route = CapabilityRouter().route(request)
                self.assertEqual(route.decision, CapabilityDecision.CREATE_SKILL)
                self.assertEqual(route.source, "rule")

    def test_one_off_web_lookup_never_creates_skill(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("CREATE_SKILL"))
        route = router.decide("Busca la versión actual de Python.")
        self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_TOOL)
        self.assertNotEqual(route.decision, CapabilityDecision.CREATE_SKILL)

    def test_public_one_off_search_remains_existing_tool(self) -> None:
        route = CapabilityRouter().route("Busca ahora mismo qué versión de Python es la última.")
        self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_TOOL)
        self.assertNotEqual(route.decision, CapabilityDecision.CREATE_SKILL)

    def test_package_tracking_knowledge_question_is_direct(self) -> None:
        route = CapabilityRouter().route("¿Qué es el seguimiento de paquetes?")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_model_output_records_model_as_decision_source(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("CREATE_SKILL"))
        route = router.route("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(route.source, "model")

    def test_explicitly_unavailable_requirement_is_unsupported(self) -> None:
        router = CapabilityRouter(lambda _prompt: self.fail("model should not be called"))
        route = router.decide("No tengo acceso al hardware que hace falta para hacerlo.")
        self.assertEqual(route.decision, CapabilityDecision.UNSUPPORTED)

    def test_disconnected_hardware_without_interface_is_unsupported(self) -> None:
        router = CapabilityRouter(lambda _prompt: self.fail("model should not be called"))
        route = router.route(
            "Controla físicamente un dispositivo que no está conectado a JARVIS "
            "y para el que no existe ninguna interfaz."
        )
        self.assertEqual(route.decision, CapabilityDecision.UNSUPPORTED)
        self.assertEqual(route.source, "rule")

    def test_missing_mandatory_private_credentials_are_unsupported(self) -> None:
        router = CapabilityRouter(lambda _prompt: self.fail("model should not be called"))
        route = router.route(
            "La petición requiere credenciales privadas obligatorias que no he "
            "proporcionado y no existe ningún mecanismo para obtenerlas."
        )
        self.assertEqual(route.decision, CapabilityDecision.UNSUPPORTED)

    def test_invalid_model_output_fails_closed(self) -> None:
        router = CapabilityRouter(lambda _prompt: "not-json")
        route = router.decide("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_empty_model_output_fails_closed(self) -> None:
        router = CapabilityRouter(lambda _prompt: "")
        route = router.decide("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_unknown_decision_fails_closed(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("RUN_CODE"))
        route = router.decide("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_existing_skill_precedes_create_classification(self) -> None:
        router = CapabilityRouter(lambda _prompt: self.fail("must not classify"))
        route = router.decide(
            "Cada vez que te pregunte por bitcoin, consulta el precio.",
            existing_skill_name="Bitcoin_price",
        )
        self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_SKILL)

    def test_native_tool_precedes_create_classification(self) -> None:
        router = CapabilityRouter(lambda _prompt: self.fail("must not classify"))
        route = router.decide("Busca en internet la versión actual de Python.")
        self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_TOOL)

    def test_model_output_must_be_complete_valid_json(self) -> None:
        self.assertIsNone(CapabilityRouter.normalize_model_output("```json\n{} \n```"))
        self.assertIsNone(
            CapabilityRouter.normalize_model_output(
                json.dumps(
                    {
                        "decision": "CREATE_SKILL",
                        "reason": "valid",
                        "confidence": True,
                    }
                )
            )
        )

    def test_low_confidence_create_is_demoted_to_direct(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("CREATE_SKILL", confidence=0.79))
        route = router.decide("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_reusable_intent_is_required_even_if_model_requests_creation(self) -> None:
        router = CapabilityRouter(lambda _prompt: model_response("CREATE_SKILL"))
        route = router.decide("Dime dónde está mi paquete.")
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_internal_messages_never_invoke_classifier(self) -> None:
        router = CapabilityRouter(lambda _prompt: self.fail("internal message reached model"))
        route = router.decide(
            "Cada vez que te pregunte, sigue mi paquete.",
            external_user_request=False,
        )
        self.assertEqual(route.decision, CapabilityDecision.DIRECT_RESPONSE)
        self.assertEqual(route.reason, "internal_input")

    def test_classifier_receives_catalog_and_installed_skills(self) -> None:
        prompts: list[str] = []
        router = CapabilityRouter(
            lambda prompt: prompts.append(prompt) or model_response("DIRECT_RESPONSE")
        )
        router.decide(
            "Cada vez que te pregunte, sigue mi paquete.",
            installed_skills={"track_package": "Consulta 1688track."},
        )
        self.assertIn("web_search", prompts[0])
        self.assertIn("track_package", prompts[0])

    def test_native_catalog_only_names_runtime_capabilities(self) -> None:
        names = {capability.name for capability in NATIVE_CAPABILITIES}
        self.assertEqual(
            names,
            {
                "conversation",
                "web_search",
                "vision",
                "reminders",
                "scheduler",
                "workspace",
                "klipper",
            },
        )

    def test_full_original_request_is_passed_to_authoring(self) -> None:
        tree = ast.parse(MAIN_SOURCE)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "autorizar_skill_solicitada"
        )
        author_call = next(
            node
            for node in ast.walk(helper)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ejecutar_cancelable"
            and node.args
            and isinstance(node.args[0], ast.Attribute)
            and node.args[0].attr == "author"
        )
        self.assertIsInstance(author_call.args[1], ast.Name)
        self.assertEqual(author_call.args[1].id, "solicitud_original")

    def test_package_create_route_flows_to_common_safe_authoring_helper(self) -> None:
        self.assertEqual(
            CapabilityRouter().route(self.PACKAGE_REQUEST).decision,
            CapabilityDecision.CREATE_SKILL,
        )
        tree = ast.parse(MAIN_SOURCE)
        automatic_create_branch = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Attribute)
            and node.test.left.attr == "decision"
            and any(
                isinstance(comparator, ast.Attribute)
                and comparator.attr == "CREATE_SKILL"
                for comparator in node.test.comparators
            )
        )
        calls = [
            node
            for node in ast.walk(automatic_create_branch)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "autorizar_skill_solicitada"
        ]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].args[0].id, "usuario")

        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "autorizar_skill_solicitada"
        )
        called_methods = {
            node.attr for node in ast.walk(helper) if isinstance(node, ast.Attribute)
        }
        self.assertIn("author", called_methods)
        self.assertIn("prepare_installation", called_methods)
        self.assertNotIn("confirm_installation", called_methods)
        self.assertNotIn("execute_installed", called_methods)
        self.assertNotIn("prepare_execution", called_methods)

    def test_create_route_does_not_install_or_execute_automatically(self) -> None:
        tree = ast.parse(MAIN_SOURCE)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "autorizar_skill_solicitada"
        )
        called_methods = {
            node.attr for node in ast.walk(helper) if isinstance(node, ast.Attribute)
        }
        self.assertIn("prepare_installation", called_methods)
        self.assertNotIn("confirm_installation", called_methods)
        self.assertNotIn("execute_installed", called_methods)
        self.assertNotIn("prepare_execution", called_methods)

    def test_explicit_skill_command_and_detection_are_preserved(self) -> None:
        self.assertIn('usuario_limpio.lower().startswith("/skill ")', MAIN_SOURCE)
        self.assertIn("elif es_peticion_de_skill(usuario_limpio):", MAIN_SOURCE)
        self.assertIn('"crea una skill"', MAIN_SOURCE)

    def test_authoring_helper_cannot_reenter_capability_router(self) -> None:
        tree = ast.parse(MAIN_SOURCE)
        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "autorizar_skill_solicitada"
        )
        names = {
            node.id for node in ast.walk(helper) if isinstance(node, ast.Name)
        }
        self.assertNotIn("capability_router", names)

    def test_classification_uses_orchestrator_speech_route_not_coder(self) -> None:
        self.assertIn(
            "model_classifier=lambda prompt: router.route(ModelRole.SPEECH, prompt)",
            MAIN_SOURCE,
        )
        self.assertIn('MODEL_ORCHESTRATOR_LOCAL = "qwen3.5:4b"', MODEL_ROUTER_SOURCE)
        self.assertIn('MODEL_CODING_LOCAL = "qwen2.5-coder:7b-instruct-q4_K_M"', MODEL_ROUTER_SOURCE)
        self.assertNotIn("MODEL_CODING_LOCAL", MAIN_SOURCE.split("capability_router =", 1)[1].split("skills =", 1)[0])

    def test_classifier_tests_use_only_fakes_and_never_call_ollama(self) -> None:
        calls: list[str] = []
        router = CapabilityRouter(
            lambda prompt: calls.append(prompt) or model_response("CREATE_SKILL")
        )
        result = router.decide("Cada vez que te pregunte, sigue mi paquete.")
        self.assertEqual(result.decision, CapabilityDecision.CREATE_SKILL)
        self.assertEqual(len(calls), 1)

    def test_router_log_includes_decision_source_without_prompt(self) -> None:
        self.assertIn(
            'f"reason={safe_reason} source={capability_route.source}"',
            MAIN_SOURCE,
        )

    def test_session_grants_and_dynamic_state_flows_remain_in_main(self) -> None:
        for expected in (
            "SessionSkillGrantStore",
            "DynamicSkillStateStore",
            "session_skill_grants.authorization_for",
            "session_skill_grants.grant_from_confirmed_execution",
            "dynamic_skill_state_store",
        ):
            self.assertIn(expected, MAIN_SOURCE)

    def test_repair_and_existing_dynamic_execution_flows_remain_in_main(self) -> None:
        for expected in (
            "DynamicSkillRepairCoordinator",
            "intentar_autorreparacion_dynamic_skill(",
            "safe_skill_pipeline.prepare_execution",
            "safe_skill_pipeline.execute_installed",
        ):
            self.assertIn(expected, MAIN_SOURCE)


if __name__ == "__main__":
    unittest.main()
