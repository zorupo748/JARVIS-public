from __future__ import annotations

import os
import sys
import threading
import time
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
from jarvis.core.vram_manager import VramManager


class FakeResponse:
    def __init__(self, data: dict) -> None:
        self._data = data
        self.status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._data


class ModelRouterVramIntegrationTests(unittest.TestCase):
    def make_router(self, manager: VramManager | None = None):
        with patch.object(model_router, "FormulaMemory", return_value=object()):
            return model_router.ModelRouter(vram_manager=manager)

    @staticmethod
    def successful_local_post(payloads: list[dict]):
        def post(_url, *, json, timeout):
            payloads.append(json)
            return FakeResponse({"response": "ok"})

        return post

    @staticmethod
    def local_payload(payloads: list[dict]) -> dict:
        return next(payload for payload in payloads if "prompt" in payload)

    def assert_profile(self, payload: dict, *, temperature, num_predict) -> None:
        self.assertFalse(payload["think"])
        self.assertEqual(payload["options"]["temperature"], temperature)
        self.assertEqual(payload["options"]["num_predict"], num_predict)
        self.assertEqual(payload["options"]["num_ctx"], 4096)

    def test_code_review_uses_its_dedicated_max_tokens_setting(self) -> None:
        router = self.make_router()
        router.groq_api_key = "configured-for-test"
        payloads: list[dict] = []

        def groq_post(_url, *, headers, json, timeout):
            self.assertIn("Authorization", headers)
            self.assertEqual(timeout, 15)
            payloads.append(json)
            return FakeResponse({"choices": [{"message": {"content": "ok"}}]})

        with patch.dict(
            os.environ,
            {"JARVIS_GROQ_CODE_REVIEW_MAX_TOKENS": "640"},
            clear=False,
        ), patch.object(model_router.requests, "post", side_effect=groq_post):
            self.assertEqual(router.run_groq_code_review("review this"), "ok")

        self.assertEqual(payloads[0]["max_tokens"], 640)
        self.assertEqual(payloads[0]["model"], model_router.MODEL_GROQ_CODE_REVIEW)
        self.assertEqual(payloads[0]["temperature"], 0.0)
    def test_normal_routers_share_the_default_vram_manager(self) -> None:
        first = self.make_router()
        second = self.make_router()

        self.assertIs(first.vram_manager, model_router.DEFAULT_VRAM_MANAGER)
        self.assertIs(second.vram_manager, model_router.DEFAULT_VRAM_MANAGER)
        self.assertIs(first.vram_manager, second.vram_manager)

        with first.vram_manager.reserve("qwen3.5:4b"):
            self.assertFalse(second.vram_manager.try_acquire("qwen3.5:9b"))
            self.assertEqual(second.vram_manager.current_model_id, "qwen3.5:4b")

    def test_concurrent_local_requests_never_run_the_request_section_together(self) -> None:
        manager = VramManager()
        first = self.make_router(manager)
        second = self.make_router(manager)
        start = threading.Barrier(2)
        active_lock = threading.Lock()
        active = 0
        maximum_active = 0
        errors: list[BaseException] = []

        def post(_url, *, json, timeout):
            nonlocal active, maximum_active
            if "prompt" not in json:
                return FakeResponse({"response": ""})
            with active_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.05)
            with active_lock:
                active -= 1
            return FakeResponse({"response": "ok"})

        def call(router, role: model_router.ModelRole) -> None:
            try:
                start.wait(timeout=1)
                router.route(role, "prompt")
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        with patch.object(model_router.requests, "post", side_effect=post):
            workers = [
                threading.Thread(target=call, args=(first, model_router.ModelRole.SPEECH)),
                threading.Thread(target=call, args=(second, model_router.ModelRole.DEEP_REASONING)),
            ]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=2)

        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertEqual(maximum_active, 1)
        self.assertIsNone(manager.current_model_id)

    def test_switch_unloads_a_different_resident_model_before_inference(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)
        events: list[str] = []

        def post(_url, *, json, timeout):
            if "prompt" in json:
                events.append(f"infer:{json['model']}")
            return FakeResponse({"response": "ok"})

        def unload(model_id: str) -> bool:
            events.append(f"unload:{model_id}")
            return True

        with patch.object(model_router.requests, "post", side_effect=post), patch.object(
            router,
            "_unload_ollama_model",
            side_effect=unload,
        ):
            router.route(model_router.ModelRole.SPEECH, "first")
            router.route(model_router.ModelRole.CODING, "second")

        self.assertEqual(
            events,
            [
                "infer:qwen3.5:4b",
                "unload:qwen3.5:4b",
                "infer:qwen2.5-coder:7b-instruct-q4_K_M",
                "unload:qwen2.5-coder:7b-instruct-q4_K_M",
            ],
        )
        self.assertIsNone(manager.resident_model_id)

    def test_reusing_the_same_model_does_not_unload_it(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)
        payloads: list[dict] = []

        with patch.object(
            model_router.requests,
            "post",
            side_effect=self.successful_local_post(payloads),
        ), patch.object(router, "_unload_ollama_model", return_value=True) as unload:
            router.route(model_router.ModelRole.SPEECH, "first")
            router.route(model_router.ModelRole.SPEECH, "second")

        unload.assert_not_called()
        self.assertEqual(manager.resident_model_id, "qwen3.5:4b")

    def test_speech_model_remains_resident_after_a_normal_request(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)

        with patch.object(
            model_router.requests,
            "post",
            return_value=FakeResponse({"response": "ok"}),
        ), patch.object(router, "_unload_ollama_model", return_value=True) as unload:
            self.assertEqual(router.route(model_router.ModelRole.SPEECH, "hola"), "ok")

        unload.assert_not_called()
        self.assertEqual(manager.resident_model_id, "qwen3.5:4b")

    def test_coding_model_is_unloaded_after_inference(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)
        events: list[str] = []

        def post(_url, *, json, timeout):
            event = "infer" if "prompt" in json else "unload"
            events.append(f"{event}:{json['model']}")
            return FakeResponse({"response": "ok"})

        with patch.object(model_router.requests, "post", side_effect=post):
            self.assertEqual(router.route(model_router.ModelRole.CODING, "codigo"), "ok")

        self.assertEqual(
            events,
            [
                "infer:qwen2.5-coder:7b-instruct-q4_K_M",
                "unload:qwen2.5-coder:7b-instruct-q4_K_M",
            ],
        )
        self.assertIsNone(manager.resident_model_id)

    def test_vision_model_is_unloaded_after_inference(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)
        events: list[str] = []

        def post(_url, *, json, timeout):
            event = "infer" if "prompt" in json else "unload"
            events.append(f"{event}:{json['model']}")
            return FakeResponse({"response": "ok"})

        with patch.object(model_router.requests, "post", side_effect=post):
            self.assertEqual(
                router.route(model_router.ModelRole.VISION, "mira", b"image"),
                "ok",
            )

        self.assertEqual(events, ["infer:qwen3-vl:4b", "unload:qwen3-vl:4b"])
        self.assertIsNone(manager.resident_model_id)

    def test_deep_reasoning_model_is_unloaded_after_inference(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)
        events: list[str] = []

        def post(_url, *, json, timeout):
            event = "infer" if "prompt" in json else "unload"
            events.append(f"{event}:{json['model']}")
            return FakeResponse({"response": "ok"})

        with patch.object(model_router.requests, "post", side_effect=post):
            self.assertEqual(
                router.route(model_router.ModelRole.DEEP_REASONING, "razona"),
                "ok",
            )

        self.assertEqual(events, ["infer:qwen3.5:9b", "unload:qwen3.5:9b"])
        self.assertIsNone(manager.resident_model_id)

    def test_failed_specialist_unload_keeps_residency_conservative(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)

        def post(_url, *, json, timeout):
            if "prompt" in json:
                return FakeResponse({"response": "ok"})
            raise model_router.requests.exceptions.ConnectionError("unload unavailable")

        with patch.object(model_router.requests, "post", side_effect=post):
            self.assertEqual(router.route(model_router.ModelRole.CODING, "codigo"), "ok")

        self.assertEqual(
            manager.resident_model_id,
            "qwen2.5-coder:7b-instruct-q4_K_M",
        )

    def test_exception_in_protected_request_releases_the_slot(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)

        with self.assertRaisesRegex(RuntimeError, "inference failure"):
            router._execute_local_heavy_request(
                "qwen3.5:4b",
                lambda: (_ for _ in ()).throw(RuntimeError("inference failure")),
            )

        self.assertIsNone(manager.current_model_id)

    def test_cloud_calls_do_not_acquire_the_local_slot(self) -> None:
        manager = VramManager()
        router = self.make_router(manager)
        router.groq_api_key = "test-key"

        with patch.object(
            model_router.requests,
            "post",
            return_value=FakeResponse(
                {"choices": [{"message": {"content": "cloud"}}]}
            ),
        ):
            self.assertEqual(router._call_groq_fallback("prompt"), "cloud")

        self.assertIsNone(manager.current_model_id)
        self.assertIsNone(manager.resident_model_id)

    def test_architect_uses_its_bounded_profile(self) -> None:
        router = self.make_router(VramManager())
        payloads: list[dict] = []

        with patch.object(
            model_router.requests,
            "post",
            side_effect=lambda _url, *, json, timeout: (
                payloads.append(json)
                or FakeResponse(
                    {
                        "response": (
                            '{"rol_principal": "speech", '
                            '"requiere_codigo": false, '
                            '"archivo_a_leer": null, "razon": "ok"}'
                        )
                    }
                )
            ),
        ):
            router.route_inteligente("clasifica esto")

        self.assert_profile(
            self.local_payload(payloads),
            temperature=0.1,
            num_predict=128,
        )

    def test_speech_and_coding_use_their_profiles(self) -> None:
        speech_router = self.make_router(VramManager())
        coding_router = self.make_router(VramManager())
        speech_payloads: list[dict] = []
        coding_payloads: list[dict] = []

        with patch.object(
            model_router.requests,
            "post",
            side_effect=self.successful_local_post(speech_payloads),
        ):
            speech_router.route(model_router.ModelRole.SPEECH, "hola")
        with patch.object(
            model_router.requests,
            "post",
            side_effect=self.successful_local_post(coding_payloads),
        ):
            coding_router.route(model_router.ModelRole.CODING, "codigo")

        self.assert_profile(
            self.local_payload(speech_payloads),
            temperature=0.5,
            num_predict=512,
        )
        self.assert_profile(
            self.local_payload(coding_payloads),
            temperature=0.2,
            num_predict=1024,
        )

    def test_deep_reasoning_and_vision_use_their_profiles(self) -> None:
        reasoning_router = self.make_router(VramManager())
        vision_router = self.make_router(VramManager())
        reasoning_payloads: list[dict] = []
        vision_payloads: list[dict] = []

        with patch.object(
            model_router.requests,
            "post",
            side_effect=self.successful_local_post(reasoning_payloads),
        ):
            reasoning_router.route(model_router.ModelRole.DEEP_REASONING, "razona")
        with patch.object(
            model_router.requests,
            "post",
            side_effect=self.successful_local_post(vision_payloads),
        ):
            vision_router.route(model_router.ModelRole.VISION, "mira", b"image")

        self.assert_profile(
            self.local_payload(reasoning_payloads),
            temperature=0.2,
            num_predict=768,
        )
        self.assert_profile(
            self.local_payload(vision_payloads),
            temperature=0.0,
            num_predict=400,
        )

    def test_active_router_no_longer_contains_the_global_temperature_profile(self) -> None:
        source = (
            PROJECT_ROOT / "src" / "jarvis" / "core" / "model_router.py"
        ).read_text(encoding="utf-8")

        self.assertNotIn("temperature\": 0.85", source)
        self.assertNotIn("keep_alive=0", source)


if __name__ == "__main__":
    unittest.main()