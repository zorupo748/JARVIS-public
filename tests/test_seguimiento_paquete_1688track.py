"""Unit tests for seguimiento_paquete_1688track (no real network access)."""

import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from jarvis.core.capability_router import CapabilityDecision, CapabilityRouter
from jarvis.core.dynamic_skill_state import DynamicSkillStateStore
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import ActionEffect, get_action_policy
from jarvis.security.skill_dispatch import SKILL_ACTIONS
from jarvis.skills.base import SkillManager
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.web.tracking_tool import TrackingTool
from jarvis.skills.seguimiento_paquete_1688track import (
    BUTTON_SELECTORS,
    DEFAULT_TRACKING_CODE,
    INPUT_SELECTORS,
    RESULT_SELECTORS,
    SKILL_NAME,
    TRACKING_URL,
    SeguimientoPaquete1688Track,
    TrackingError,
    compare_snapshots,
    extract_tracking_code,
    register_seguimiento_paquete_1688track_skill,
    validate_tracking_code,
)

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def api_response(events, status="In transit"):
    return {
        "responses": [{
            "url": "https://www.1688track.com/api/track",
            "status": 200,
            "method": "POST",
            "body": json.dumps({"data": {"status": status, "events": events}}),
        }],
        "result_text": "",
    }


EVENT_A = {"time": "2026-10-18 10:00", "desc": "Salida del centro", "city": "Shenzhen"}
EVENT_B = {"time": "2026-10-19 09:30", "desc": "Llegada a destino", "city": "Madrid"}


class SeguimientoPaqueteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = DynamicSkillStateStore(Path(self._tmp.name))
        self.session = MagicMock()
        self.skill = SeguimientoPaquete1688Track(
            session=self.session, state_store=self.store, now=lambda: NOW
        )

    def test_validate_code_default_and_normalization(self):
        self.assertEqual(validate_tracking_code(None), DEFAULT_TRACKING_CODE)
        self.assertEqual(validate_tracking_code("  "), DEFAULT_TRACKING_CODE)
        self.assertEqual(validate_tracking_code(" oxcgh6082081h "), "OXCGH6082081H")

    def test_validate_code_rejects_invalid_values(self):
        for bad in ("abc", "AB CD EF GH IJ", "code;rm -rf /", "A" * 41, 12345678):
            with self.subTest(bad=bad), self.assertRaises(TrackingError):
                validate_tracking_code(bad)

    def test_invalid_code_never_opens_browser(self):
        self.assertIn("No pude", self.skill.responder("x"))
        self.session.interact_and_capture_sync.assert_not_called()

    def test_first_query_extracts_fields_and_uses_expected_url(self):
        self.session.interact_and_capture_sync.return_value = api_response([EVENT_B, EVENT_A])
        result = self.skill.consultar()
        args, kwargs = self.session.interact_and_capture_sync.call_args
        self.assertEqual(args, (TRACKING_URL, DEFAULT_TRACKING_CODE))
        self.assertIn('input[type="text"]', kwargs["input_selectors"])
        self.assertEqual(result["estado"], "In transit")
        self.assertEqual(result["ubicacion"], "Madrid")
        self.assertEqual(result["fecha"], "2026-10-19 09:30")
        self.assertEqual(len(result["eventos"]), 2)
        self.assertEqual(result["comparacion"]["resultado"], "primera_consulta")

    def test_state_is_persisted_as_json(self):
        self.session.interact_and_capture_sync.return_value = api_response([EVENT_A])
        self.skill.consultar("OXCGH6082081H")
        saved = self.store.load(SKILL_NAME)
        entry = saved["trackings"]["OXCGH6082081H"]
        self.assertEqual(entry["consultado_en"], NOW.isoformat())
        self.assertTrue((Path(self._tmp.name) / f"{SKILL_NAME}.json").exists())

    def test_second_identical_query_reports_no_changes(self):
        self.session.interact_and_capture_sync.return_value = api_response([EVENT_A])
        self.skill.consultar()
        result = self.skill.consultar()
        self.assertEqual(result["comparacion"]["resultado"], "sin_cambios")

    def test_changes_are_detailed(self):
        self.session.interact_and_capture_sync.return_value = api_response([EVENT_A], "Shipped")
        self.skill.consultar()
        self.session.interact_and_capture_sync.return_value = api_response(
            [EVENT_B, EVENT_A], "Delivered"
        )
        comparison = self.skill.consultar()["comparacion"]
        self.assertEqual(comparison["resultado"], "con_cambios")
        self.assertIn("Shipped", comparison["detalle"])
        self.assertIn("Delivered", comparison["detalle"])
        self.assertIn("Llegada a destino", comparison["detalle"])

    def test_dom_text_fallback_when_no_api_response(self):
        self.session.interact_and_capture_sync.return_value = {
            "responses": [],
            "result_text": "2026-10-19 09:30\nEntregado en buzón\n2026-10-18 10:00\nEn reparto",
        }
        result = self.skill.consultar()
        self.assertEqual(result["estado"], "Entregado en buzón")
        self.assertEqual(result["eventos"][1]["descripcion"], "En reparto")

    def test_errors_are_friendly_and_do_not_overwrite_last_valid_state(self):
        self.session.interact_and_capture_sync.return_value = api_response([EVENT_A])
        self.skill.consultar()
        before = self.store.load(SKILL_NAME)
        failures = (
            LookupError("selector missing"),
            TimeoutError("boom"),
            PermissionError("domain"),
            RuntimeError("Traceback (most recent call last): C:\\secret\\file.py"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                self.session.interact_and_capture_sync.side_effect = failure
                message = self.skill.responder()
                self.assertTrue(message.startswith("No pude consultar"))
                for leak in ("Traceback", "secret", "Error", "selector"):
                    self.assertNotIn(leak, message)
        self.assertEqual(self.store.load(SKILL_NAME), before)

    def test_empty_result_raises_and_registration_works(self):
        self.session.interact_and_capture_sync.return_value = {"responses": [], "result_text": ""}
        with self.assertRaises(TrackingError):
            self.skill.consultar()
        self.assertEqual(self.store.load(SKILL_NAME), {})
        manager = SkillManager()
        register_seguimiento_paquete_1688track_skill(manager)
        self.assertIn(SKILL_NAME, manager.get_catalog())
        self.assertEqual(compare_snapshots(None, {"estado": "x"})["resultado"], "primera_consulta")


# Payload recortado de la respuesta real observada en vivo (POST ...WebsiteApi?op=Track).
REAL_API_PAYLOAD = {
    "code": 200,
    "tracks": [{
        "key_name": "DJ260826208143SE",
        "channel_entity": "海派",
        "review_state": "已到港",
        "country": "西班牙",
        "track": [
            {"review_state": {"key_name": "已到港"}, "track_time": "2026-10-16",
             "remark": "Vessel arrived at last port,waiting for discharge",
             "site": {"key_name": "NL"}, "is_push": {"id": 1}},
            {"review_state": {"key_name": "推迟到港"}, "track_time": "2026-10-13",
             "remark": "ETA delay to 2026/10/16", "site": {"key_name": "NL"}, "is_push": {"id": 1}},
            {"review_state": {"key_name": "出口放行"}, "track_time": "2026-09-12",
             "remark": "Customs release ETD:2026-09-16\tby CMA", "site": {"key_name": "SZ"},
             "is_push": {"id": 1}},
            {"review_state": {"key_name": "待审核"}, "track_time": "2026-09-11",
             "site": {"key_name": "SZ"}, "is_push": {"id": 0}, "ref_no": "OXCGH6082081H"},
        ],
    }],
}


def real_response():
    return {
        "responses": [
            {"url": "https://www.1688track.com/api/other", "status": 200, "method": "GET", "body": "{}"},
            {
                "url": "https://sys.chaodajian.com//cloud/app/tms/transit/api/WebsiteApi?op=Track",
                "status": 200,
                "method": "POST",
                "body": json.dumps(REAL_API_PAYLOAD, ensure_ascii=False),
            },
        ],
        "result_text": "",
    }


class RealSchemaTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = DynamicSkillStateStore(Path(self._tmp.name))
        self.session = MagicMock()
        self.session.interact_and_capture_sync.return_value = real_response()
        self.skill = SeguimientoPaquete1688Track(
            session=self.session, state_store=self.store, now=lambda: NOW
        )

    def test_real_selectors_are_the_observed_dom(self):
        self.assertEqual(INPUT_SELECTORS[0], "input.el-input__inner")
        self.assertEqual(BUTTON_SELECTORS[0], "button.el-button--primary")
        self.assertEqual(RESULT_SELECTORS[0], ".el-timeline")

    def test_real_payload_is_parsed_and_translated(self):
        result = self.skill.consultar()
        self.assertEqual(result["estado"], "Llegado a puerto (已到港)")
        self.assertEqual(result["albaran"], "DJ260826208143SE")
        self.assertEqual(result["destino"], "España")
        self.assertEqual(result["ubicacion"], "NL")
        self.assertEqual(result["fecha"], "2026-10-16")

    def test_carrier_confirmed_events_are_separated_from_estimates_and_admin_steps(self):
        events = self.skill.consultar()["eventos"]
        by_state = {e["descripcion"].split(":")[0]: e for e in events}
        self.assertEqual(by_state["Llegado a puerto (已到港)"]["origen"], "transportista")
        self.assertEqual(by_state["Llegado a puerto (已到港)"]["tipo"], "confirmado")
        self.assertEqual(by_state["Llegada retrasada (推迟到港)"]["tipo"], "estimacion")
        self.assertEqual(by_state["Pendiente de revisión (待审核)"]["origen"], "administrativo")
        self.assertNotIn("\t", " ".join(e["descripcion"] for e in events))

    def test_legacy_formatear_labels_confirmed_estimates_and_internal_steps(self):
        text = self.skill.responder(use_synthesis=False)
        self.assertIn("Confirmado por el transportista", text)
        self.assertIn("Estimaciones (no confirmadas)", text)
        self.assertIn("Pasos administrativos internos registrados: 1", text)
        self.assertIn("Primera consulta", text)

    def test_responder_uses_clean_synthesis_fallback_by_default(self):
        text = self.skill.responder()
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", text), "No debe contener caracteres chinos")
        self.assertNotIn("|", text, "No debe contener plecas de concatenación técnica")
        self.assertIn("OXCGH6082081H", text)
        self.assertIn("Países Bajos", text)
        self.assertIn("España", text)
        self.assertIn("descarga", text.lower())
        self.assertIn("aduanera", text.lower())
        # Debe ser un texto fluido y conciso (un único párrafo)
        self.assertEqual(len(text.strip().splitlines()), 1)

    def test_sintesis_with_llm_caller(self):
        captured_prompt = []

        def fake_llm(prompt: str) -> str:
            captured_prompt.append(prompt)
            return (
                "El paquete OXCGH6082081H ha llegado al puerto de transbordo de Países Bajos (Rotterdam). "
                "Actualmente se encuentra a la espera de descarga del contenedor e inspección aduanera "
                "antes de iniciar el transporte terrestre hacia su destino final en España."
            )

        skill_llm = SeguimientoPaquete1688Track(
            session=self.session,
            state_store=self.store,
            now=lambda: NOW,
            llm_caller=fake_llm,
        )
        res = skill_llm.responder()
        self.assertEqual(len(captured_prompt), 1)
        prompt_text = captured_prompt[0]
        self.assertIn("OXCGH6082081H", prompt_text)
        self.assertIn("Llegado a puerto", prompt_text)
        self.assertIn("Países Bajos", prompt_text)
        self.assertIn("España", prompt_text)
        self.assertIn("Actualmente se encuentra a la espera de descarga", res)
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", res))

    def test_sintesis_llm_fallback_on_error_or_chinese_leak(self):
        def error_llm(_prompt: str) -> str:
            raise RuntimeError("Ollama service unavailable")

        skill_err = SeguimientoPaquete1688Track(
            session=self.session,
            state_store=self.store,
            now=lambda: NOW,
            llm_caller=error_llm,
        )
        res_err = skill_err.responder()
        self.assertIn("Países Bajos", res_err)
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", res_err))

        def chinese_leak_llm(_prompt: str) -> str:
            return "El paquete ha llegado al puerto (已到港) en Rotterdam."

        skill_leak = SeguimientoPaquete1688Track(
            session=self.session,
            state_store=self.store,
            now=lambda: NOW,
            llm_caller=chinese_leak_llm,
        )
        res_leak = skill_leak.responder()
        # Al filtrar la respuesta con caracteres chinos, usa el fallback limpio
        self.assertFalse(re.search(r"[\u4e00-\u9fff]", res_leak))
        self.assertIn("Países Bajos", res_leak)


    def test_failed_api_payload_is_not_persisted(self):
        self.session.interact_and_capture_sync.return_value = {
            "responses": [{"url": "x?op=Track", "status": 200, "method": "POST",
                           "body": json.dumps({"code": 500, "tracks": []})}],
            "result_text": "",
        }
        with self.assertRaises(TrackingError):
            self.skill.consultar()
        self.assertEqual(self.store.load(SKILL_NAME), {})

    def test_extract_tracking_code(self):
        self.assertEqual(extract_tracking_code("estado del paquete oxcgh6082081h por favor"), "OXCGH6082081H")
        self.assertIsNone(extract_tracking_code("dónde está mi paquete"))


class IntegrationTests(unittest.TestCase):
    def test_router_sends_tracking_requests_to_installed_skill(self):
        router = CapabilityRouter(tracking_skill_name=SKILL_NAME)
        for text in (
            "¿Dónde está mi paquete?",
            "rastrea el envío",
            "estado del paquete OXCGH6082081H",
            "Cuando te pregunte dónde está mi paquete consulta 1688track y dime si ha cambiado",
        ):
            with self.subTest(text=text):
                route = router.decide(text)
                self.assertEqual(route.decision, CapabilityDecision.USE_EXISTING_SKILL)
                self.assertEqual(route.skill_name, SKILL_NAME)

    def test_router_ignores_software_packages_and_default_behavior_is_unchanged(self):
        router = CapabilityRouter(tracking_skill_name=SKILL_NAME)
        self.assertNotEqual(
            router.decide("¿Dónde está instalado el paquete numpy de python?").decision,
            CapabilityDecision.USE_EXISTING_SKILL,
        )
        self.assertNotEqual(
            CapabilityRouter().decide("¿Dónde está mi paquete?").decision,
            CapabilityDecision.USE_EXISTING_SKILL,
        )

    def test_policy_and_dispatch_registration(self):
        for action in (SKILL_NAME, "consultar_seguimiento_1688track", "tracking_1688track"):
            with self.subTest(action=action):
                policy = get_action_policy(action)
                self.assertIsNotNone(policy)
                self.assertEqual(policy.required_level, SecurityLevel.LEVEL_1)
                self.assertEqual(policy.effect, ActionEffect.WEB_READ)
                self.assertEqual(SKILL_ACTIONS[action], action)

    def test_tool_exposes_spec_and_returns_formatted_result(self):
        skill = MagicMock()
        skill.consultar.return_value = {"codigo": "OXCGH6082081H"}
        skill.formatear.return_value = "Paquete OXCGH6082081H: ok"
        tool = TrackingTool(skill=skill)
        self.assertIn("tracking_code", tool.spec.parameters["properties"])
        result = tool.execute(tracking_code="OXCGH6082081H")
        skill.consultar.assert_called_once_with("OXCGH6082081H")
        self.assertTrue(result.success)
        self.assertEqual(result.content, "Paquete OXCGH6082081H: ok")
        skill.consultar.side_effect = TrackingError("sin datos")
        failure = tool.execute()
        self.assertFalse(failure.success)
        self.assertIn("sin datos", failure.content)
        for alias in (SKILL_NAME, "tracking_1688track", "consultar_seguimiento_1688track"):
            self.assertIs(ToolRegistry.get(alias), TrackingTool)


if __name__ == "__main__":
    unittest.main()
