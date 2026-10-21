"""Unit and integration tests for automatic background GameDetector."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, call, patch

from jarvis.core.game_detector import (
    DEFAULT_EXCLUDED_PROCESSES,
    DEFAULT_GAME_PROCESSES,
    GameDetector,
    is_game_process,
    is_window_fullscreen,
)


class TestGameDetectorHeuristics(unittest.TestCase):
    """Test pure functions for fullscreen bounds and process classification."""

    def test_is_window_fullscreen(self):
        screen_w, screen_h = 2560, 1440

        # Exact match
        self.assertTrue(is_window_fullscreen((0, 0, 2560, 1440), screen_w, screen_h))

        # Borderless window with small offset within tolerance
        self.assertTrue(is_window_fullscreen((-2, -2, 2562, 1442), screen_w, screen_h))

        # Standard windowed mode
        self.assertFalse(is_window_fullscreen((100, 100, 1920, 1080), screen_w, screen_h))

        # Zero or invalid screen
        self.assertFalse(is_window_fullscreen((0, 0, 1920, 1080), 0, 0))

    def test_is_game_process_exclusions(self):
        screen_res = (1920, 1080)
        fullscreen_rect = (0, 0, 1920, 1080)
        excluded = {"explorer.exe", "chrome.exe", "code.exe"}
        known_games = {"cyberpunk2077.exe"}

        # Even if maximized/fullscreen, browsers/IDEs/desktop shell must NOT be classified as games
        is_game, name = is_game_process(
            proc_name="chrome.exe",
            exe_path="c:\\program files\\google\\chrome\\chrome.exe",
            rect=fullscreen_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertFalse(is_game)
        self.assertEqual(name, "chrome.exe")

        is_game, name = is_game_process(
            proc_name="code.exe",
            exe_path="c:\\users\\user\\appdata\\local\\programs\\vscode\\code.exe",
            rect=fullscreen_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertFalse(is_game)

    def test_is_game_process_whitelist(self):
        screen_res = (1920, 1080)
        windowed_rect = (200, 200, 1400, 900)
        excluded = {"explorer.exe"}
        known_games = {"cyberpunk2077.exe", "valorant.exe"}

        # Known game is recognized even in windowed mode
        is_game, name = is_game_process(
            proc_name="cyberpunk2077.exe",
            exe_path="d:\\games\\cyberpunk2077\\bin\\x64\\cyberpunk2077.exe",
            rect=windowed_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertTrue(is_game)
        self.assertEqual(name, "cyberpunk2077.exe")

    def test_is_game_process_path_indicators(self):
        screen_res = (1920, 1080)
        windowed_rect = (200, 200, 1400, 900)
        excluded = {"explorer.exe"}
        known_games = {"cyberpunk2077.exe"}

        # Executable inside Steam library
        is_game, name = is_game_process(
            proc_name="indie_title.exe",
            exe_path="d:\\steam\\steamapps\\common\\indie_title\\indie_title.exe",
            rect=windowed_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertTrue(is_game)
        self.assertEqual(name, "indie_title.exe")

        # Executable inside Epic Games directory
        is_game, name = is_game_process(
            proc_name="epic_game.exe",
            exe_path="c:\\program files\\epic games\\gamefolder\\epic_game.exe",
            rect=windowed_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertTrue(is_game)

    def test_is_game_process_fullscreen_unclassified(self):
        screen_res = (1920, 1080)
        fullscreen_rect = (0, 0, 1920, 1080)
        windowed_rect = (100, 100, 800, 600)
        excluded = {"explorer.exe", "chrome.exe"}
        known_games = set()

        # Non-excluded unclassified process in fullscreen -> classified as game
        is_game, name = is_game_process(
            proc_name="custom_game_win64.exe",
            exe_path="c:\\games\\custom\\custom_game_win64.exe",
            rect=fullscreen_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertTrue(is_game)
        self.assertEqual(name, "custom_game_win64.exe")

        # Non-excluded unclassified process in regular small window -> not game
        is_game, name = is_game_process(
            proc_name="calculator_app.exe",
            exe_path="c:\\tools\\calculator_app.exe",
            rect=windowed_rect,
            screen_res=screen_res,
            excluded_processes=excluded,
            known_game_processes=known_games,
        )
        self.assertFalse(is_game)


class TestGameDetectorTransitions(unittest.TestCase):
    """Test GameDetector state machine transitions and interaction with ModelRouter and HUD."""

    def setUp(self):
        self.mock_router = MagicMock()
        self.mock_notifier = MagicMock()
        self.mock_state_callback = MagicMock()

        self.detector = GameDetector(
            model_router=self.mock_router,
            overlay_notifier=self.mock_notifier,
            check_interval_seconds=0.1,
            state_callback=self.mock_state_callback,
            consecutive_misses_to_stop=2,
        )

    def test_on_game_start_and_stop_events(self):
        # Trigger start
        self.detector.on_game_start("witcher3.exe")
        self.assertTrue(self.detector.is_game_active)
        self.assertEqual(self.detector.current_game_name, "witcher3.exe")

        # ModelRouter must be switched to gaming_mode=True (0% VRAM)
        self.mock_router.set_gaming_mode.assert_called_with(True)
        self.mock_state_callback.assert_called_with(True)

        # HUD notification must be emitted
        self.mock_notifier.assert_called_once()
        args, _ = self.mock_notifier.call_args
        self.assertIn("Modo Juego activo", args[1])
        self.assertIn("witcher3.exe", args[1])

        # Trigger stop
        self.mock_notifier.reset_mock()
        self.detector.on_game_stop()
        self.assertFalse(self.detector.is_game_active)
        self.assertIsNone(self.detector.current_game_name)

        # ModelRouter restored to normal
        self.mock_router.set_gaming_mode.assert_called_with(False)
        self.mock_state_callback.assert_called_with(False)

        # HUD notification of deactivation
        self.mock_notifier.assert_called_once()
        args, _ = self.mock_notifier.call_args
        self.assertIn("Modo Juego desactivado", args[1])

    @patch("jarvis.core.game_detector.get_screen_resolution", return_value=(1920, 1080))
    @patch("jarvis.core.game_detector.get_foreground_window_info")
    def test_check_cycle_auto_detects_game_and_debounces_alt_tab(self, mock_fg, mock_res):
        # 1. First cycle: Foreground is desktop explorer.exe -> No game
        mock_fg.return_value = (101, (0, 0, 1920, 1080), "explorer.exe", "c:\\windows\\explorer.exe")
        active = self.detector.check_cycle()
        self.assertFalse(active)
        self.assertFalse(self.detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_not_called()

        # 2. Second cycle: Foreground switches to Cyberpunk 2077 -> Game detected
        mock_fg.return_value = (202, (0, 0, 1920, 1080), "cyberpunk2077.exe", "d:\\cyberpunk2077.exe")
        active = self.detector.check_cycle()
        self.assertTrue(active)
        self.assertTrue(self.detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_called_once_with(True)

        # 3. Third cycle: User briefly alt-tabs to Discord (1 miss)
        # Hysteresis requires 2 misses before disabling gaming mode
        mock_fg.return_value = (303, (100, 100, 900, 700), "discord.exe", "c:\\discord\\discord.exe")
        active = self.detector.check_cycle()
        self.assertFalse(active)
        # Game mode must still be retained during brief alt-tab!
        self.assertTrue(self.detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_called_once_with(True)

        # 4. Fourth cycle: User returns to game -> misses reset to 0
        mock_fg.return_value = (202, (0, 0, 1920, 1080), "cyberpunk2077.exe", "d:\\cyberpunk2077.exe")
        active = self.detector.check_cycle()
        self.assertTrue(active)
        self.assertTrue(self.detector.is_game_active)

        # 5. Fifth cycle: Game exits, desktop is active (miss 1)
        mock_fg.return_value = (101, (0, 0, 1920, 1080), "explorer.exe", "c:\\windows\\explorer.exe")
        self.detector.check_cycle()
        self.assertTrue(self.detector.is_game_active)

        # 6. Sixth cycle: Still desktop (miss 2) -> Gaming mode deactivated!
        self.detector.check_cycle()
        self.assertFalse(self.detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_called_with(False)

    def test_daemon_thread_start_and_clean_stop(self):
        self.detector.start()
        self.assertIsNotNone(self.detector._thread)
        self.assertTrue(self.detector._thread.is_alive())

        # Second start is idempotent
        self.detector.start()

        # Stop cleanly
        self.detector.stop(timeout=1.0)
        self.assertIsNone(self.detector._thread)

    def test_vram_unloader_callback_called_on_game_start(self):
        mock_unloader = MagicMock()
        detector = GameDetector(
            model_router=self.mock_router,
            overlay_notifier=self.mock_notifier,
            vram_unloader=mock_unloader,
        )
        detector.on_game_start("eldenring.exe")
        self.mock_router.set_gaming_mode.assert_called_with(True)
        mock_unloader.assert_called_once()

    @patch("jarvis.core.game_detector.get_screen_resolution", return_value=(1920, 1080))
    @patch("jarvis.core.game_detector.get_foreground_window_info")
    def test_fullscreen_unclassified_game_triggers_gaming_mode_and_vram_unload(self, mock_fg, mock_res):
        mock_unloader = MagicMock()
        detector = GameDetector(
            model_router=self.mock_router,
            overlay_notifier=self.mock_notifier,
            vram_unloader=mock_unloader,
            consecutive_misses_to_stop=1,
        )

        # 1. Start on desktop browser (chrome.exe) -> No gaming mode
        mock_fg.return_value = (10, (0, 0, 1920, 1080), "chrome.exe", "c:\\chrome\\chrome.exe")
        detector.check_cycle()
        self.assertFalse(detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_not_called()
        mock_unloader.assert_not_called()

        # 2. Transition to full screen custom game -> gaming mode + vram unload
        mock_fg.return_value = (20, (0, 0, 1920, 1080), "unreal_engine_game.exe", "d:\\games\\unreal_engine_game.exe")
        detector.check_cycle()
        self.assertTrue(detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_called_once_with(True)
        mock_unloader.assert_called_once()
        self.mock_notifier.assert_called_once()
        args, _ = self.mock_notifier.call_args
        self.assertIn("Modo Juego activo (0% VRAM)", args[1])

        # 3. Transition back to browser -> gaming mode deactivated
        mock_fg.return_value = (10, (0, 0, 1920, 1080), "chrome.exe", "c:\\chrome\\chrome.exe")
        detector.check_cycle()
        self.assertFalse(detector.is_game_active)
        self.mock_router.set_gaming_mode.assert_called_with(False)


class TestGameDetectorWithModelRouterIntegration(unittest.TestCase):
    """Integration test with ModelRouter confirming Ollama VRAM discharge upon game detection."""

    @patch("requests.post")
    def test_game_detector_triggers_real_model_router_vram_unload(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"response": "ok"}

        from jarvis.core.model_router import ModelRouter
        mock_vram_mgr = MagicMock()
        router = ModelRouter(vram_manager=mock_vram_mgr)

        notifier = MagicMock()
        detector = GameDetector(
            model_router=router,
            overlay_notifier=notifier,
        )

        self.assertFalse(router.gaming_mode)

        # Trigger game start
        detector.on_game_start("eldenring.exe")

        self.assertTrue(router.gaming_mode)
        # Ollama unload calls must be performed with keep_alive=0 to discharge GPU VRAM
        unloaded_models = []
        for call_item in mock_post.call_args_list:
            _, kwargs = call_item
            payload = kwargs.get("json", {})
            if payload.get("keep_alive") == 0:
                unloaded_models.append(payload.get("model"))

        self.assertGreater(len(unloaded_models), 0)
        mock_vram_mgr.clear_resident_model.assert_called_once()

        # Stop game
        detector.on_game_stop()
        self.assertFalse(router.gaming_mode)


if __name__ == "__main__":
    unittest.main()

