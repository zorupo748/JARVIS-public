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


from jarvis.core.vram_manager import (
    GPU_BASELINE_VRAM_MIB,
    KNOWN_LOCAL_HEAVY_MODELS,
    MAX_LOCAL_HEAVY_MODELS,
    VRAM_SAFETY_MARGIN_MIB,
    VramManager,
    VramReservationTimeout,
)


class VramManagerTests(unittest.TestCase):
    def test_model_can_acquire_and_release_the_slot(self) -> None:
        manager = VramManager()

        self.assertTrue(manager.acquire("qwen3.5:4b"))
        self.assertEqual(manager.current_model_id, "qwen3.5:4b")
        self.assertFalse(manager.can_run_local_now())
        self.assertTrue(manager.release("qwen3.5:4b"))
        self.assertIsNone(manager.current_model_id)
        self.assertTrue(manager.can_run_local_now())

    def test_second_model_cannot_acquire_immediately_while_slot_is_owned(self) -> None:
        manager = VramManager()
        self.assertTrue(manager.acquire("qwen3.5:4b"))

        self.assertFalse(manager.try_acquire("qwen2.5-coder:7b-instruct-q4_K_M"))
        self.assertEqual(manager.owner_model_id, "qwen3.5:4b")

    def test_another_model_can_acquire_after_release(self) -> None:
        manager = VramManager()
        self.assertTrue(manager.acquire("qwen3.5:4b"))
        self.assertTrue(manager.release("qwen3.5:4b"))

        self.assertTrue(manager.try_acquire("qwen3-vl:4b"))
        self.assertEqual(manager.current_model_id, "qwen3-vl:4b")

    def test_concurrent_threads_never_hold_the_slot_simultaneously(self) -> None:
        manager = VramManager()
        start = threading.Barrier(2)
        active_lock = threading.Lock()
        active = 0
        maximum_active = 0
        errors: list[BaseException] = []

        def reserve_for(model_id: str) -> None:
            nonlocal active, maximum_active
            try:
                start.wait(timeout=1)
                with manager.reserve(model_id, timeout=1):
                    with active_lock:
                        active += 1
                        maximum_active = max(maximum_active, active)
                    time.sleep(0.05)
                    with active_lock:
                        active -= 1
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        workers = [
            threading.Thread(target=reserve_for, args=("qwen3.5:4b",)),
            threading.Thread(target=reserve_for, args=("qwen3.5:9b",)),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=2)

        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertEqual(maximum_active, 1)
        self.assertIsNone(manager.current_model_id)

    def test_timeout_returns_false_without_changing_owner(self) -> None:
        manager = VramManager()
        self.assertTrue(manager.acquire("qwen3.5:4b"))

        self.assertFalse(manager.acquire("qwen3.5:9b", timeout=0.02))
        self.assertEqual(manager.current_model_id, "qwen3.5:4b")

        with self.assertRaises(VramReservationTimeout):
            with manager.reserve("qwen3.5:9b", timeout=0):
                self.fail("A timed-out reservation must not enter its body.")

    def test_incorrect_release_does_not_corrupt_state(self) -> None:
        manager = VramManager()
        self.assertTrue(manager.acquire("qwen3.5:4b"))

        self.assertFalse(manager.release("qwen3-vl:4b"))
        self.assertEqual(manager.current_model_id, "qwen3.5:4b")
        self.assertFalse(manager.status().local_available)

    def test_context_manager_releases_after_an_exception(self) -> None:
        manager = VramManager()

        with self.assertRaisesRegex(RuntimeError, "caller failure"):
            with manager.reserve("qwen3.5:4b"):
                raise RuntimeError("caller failure")

        self.assertIsNone(manager.current_model_id)
        self.assertTrue(manager.try_acquire("qwen2.5-coder:7b-instruct-q4_K_M"))

    def test_known_model_metadata_contains_all_current_local_models(self) -> None:
        expected = {
            "qwen3.5:4b": (2.91, 5205),
            "qwen2.5-coder:7b-instruct-q4_K_M": (4.42, 5999),
            "qwen3-vl:4b": (3.29, 5954),
            "qwen3.5:9b": (5.11, 7660),
        }

        self.assertEqual(set(KNOWN_LOCAL_HEAVY_MODELS), set(expected))
        self.assertEqual(MAX_LOCAL_HEAVY_MODELS, 1)
        self.assertEqual(GPU_BASELINE_VRAM_MIB, 1350)
        self.assertEqual(VRAM_SAFETY_MARGIN_MIB, 768)
        for model_id, (size_gib, observed_mib) in expected.items():
            metadata = KNOWN_LOCAL_HEAVY_MODELS[model_id]
            self.assertEqual(metadata.ollama_size_vram_gib, size_gib)
            self.assertEqual(metadata.observed_total_vram_mib, observed_mib)


if __name__ == "__main__":
    unittest.main()