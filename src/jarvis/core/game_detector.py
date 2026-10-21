"""Automatic background game detector for JARVIS.

Monitors running foreground applications to automatically toggle Gaming Mode (0% VRAM):
- Unloads all local heavy models from Ollama to ensure GPU memory is 100% available for games.
- Routes all inference to Groq Cloud API while games are active.
- Emits HUD overlay notifications without stealing focus (WS_EX_NOACTIVATE).
- Restores local models when the game session ends.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import os
import sys
import threading
from typing import Any, Callable, Optional, Sequence, Set, Tuple

import psutil

logger = logging.getLogger(__name__)

# Native user32 reference on Windows
_user32 = ctypes.windll.user32 if sys.platform == "win32" else None

# Common desktop, browser, and developer applications to exclude from fullscreen game heuristics
DEFAULT_EXCLUDED_PROCESSES: Set[str] = {
    # Windows Shell & System
    "explorer.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "searchapp.exe",
    "searchhost.exe",
    "taskmgr.exe",
    "systemsettings.exe",
    "applicationframehost.exe",
    "lockapp.exe",
    "dwm.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "securityhealthsystray.exe",
    # Web Browsers
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "tor.exe",
    # IDEs, Code Editors & Development Tools
    "code.exe",
    "cursor.exe",
    "antigravity.exe",
    "pycharm64.exe",
    "idea64.exe",
    "devenv.exe",
    "sublime_text.exe",
    "notepad.exe",
    "notepad++.exe",
    # Terminals
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "windowsterminal.exe",
    "conhost.exe",
    "mintty.exe",
    "alacritty.exe",
    "wezterm-gui.exe",
    # Python & Build Tools
    "python.exe",
    "pythonw.exe",
    "git.exe",
    # Communication & Media Tools
    "discord.exe",
    "spotify.exe",
    "slack.exe",
    "teams.exe",
    "telegram.exe",
    "vlc.exe",
    "obs64.exe",
    "obs.exe",
    "zoom.exe",
}

# Known game executables and common game processes
DEFAULT_GAME_PROCESSES: Set[str] = {
    "cyberpunk2077.exe",
    "witcher3.exe",
    "gta5.exe",
    "gtav.exe",
    "rdr2.exe",
    "valorant.exe",
    "cs2.exe",
    "csgo.exe",
    "dota2.exe",
    "leagueclientux.exe",
    "league of legends.exe",
    "fortniteclient-win64-shipping.exe",
    "overwatch.exe",
    "rocketleague.exe",
    "minecraft.exe",
    "genshinimpact.exe",
    "starrail.exe",
    "honkaistarrail.exe",
    "apexlegends.exe",
    "r5apex.exe",
    "eldenring.exe",
    "dark souls.exe",
    "sekiro.exe",
    "baldursgate3.exe",
    "bg3.exe",
    "bg3_dx11.exe",
    "destiny2.exe",
    "fallguys_client.exe",
    "helldivers2.exe",
    "monsterhunterwilds.exe",
    "mhw.exe",
    "eurotrucks2.exe",
    "forzahorizon5.exe",
    "fifa23.exe",
    "fc24.exe",
    "fc25.exe",
    "arma3_x64.exe",
    "starfield.exe",
}

# Path substrings indicating game platform library installations
GAME_PATH_INDICATORS: Tuple[str, ...] = (
    "steamapps",
    "epic games",
    "riot games",
    "ubisoft game launcher",
    "gog galaxy",
    "xboxgames",
    "origin games",
    "battlenet",
)


def get_foreground_window_info() -> Tuple[int, Tuple[int, int, int, int], str, str]:
    """Retrieve foreground window HWND, bounding rectangle, process name, and executable path.

    Returns:
        (hwnd, (left, top, right, bottom), process_name, executable_path)
    """
    if sys.platform != "win32" or _user32 is None:
        return 0, (0, 0, 0, 0), "", ""

    try:
        hwnd = _user32.GetForegroundWindow()
        if not hwnd:
            return 0, (0, 0, 0, 0), "", ""

        rect = wintypes.RECT()
        if not _user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return hwnd, (0, 0, 0, 0), "", ""

        pid = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return hwnd, (rect.left, rect.top, rect.right, rect.bottom), "", ""

        proc = psutil.Process(pid.value)
        proc_name = proc.name().lower()
        try:
            exe_path = proc.exe().lower()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe_path = ""

        return hwnd, (rect.left, rect.top, rect.right, rect.bottom), proc_name, exe_path
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
        return 0, (0, 0, 0, 0), "", ""
    except Exception as exc:
        logger.debug("Error getting foreground window info: %s", exc)
        return 0, (0, 0, 0, 0), "", ""


def get_screen_resolution() -> Tuple[int, int]:
    """Return primary monitor resolution (width, height) in pixels."""
    if sys.platform != "win32" or _user32 is None:
        return 0, 0
    try:
        w = _user32.GetSystemMetrics(0)  # SM_CXSCREEN
        h = _user32.GetSystemMetrics(1)  # SM_CYSCREEN
        return w, h
    except Exception as exc:
        logger.debug("Error getting screen resolution: %s", exc)
        return 0, 0


def is_window_fullscreen(rect: Tuple[int, int, int, int], screen_w: int, screen_h: int) -> bool:
    """Check if window bounds cover the entire primary screen resolution."""
    if screen_w <= 0 or screen_h <= 0:
        return False
    left, top, right, bottom = rect
    width = right - left
    height = bottom - top
    # Tolerate small border differences (up to 4px) common in borderless windows
    return left <= 4 and top <= 4 and width >= (screen_w - 8) and height >= (screen_h - 8)


def is_game_process(
    proc_name: str,
    exe_path: str,
    rect: Tuple[int, int, int, int],
    screen_res: Tuple[int, int],
    excluded_processes: Set[str],
    known_game_processes: Set[str],
) -> Tuple[bool, str]:
    """Evaluates whether the foreground window represents an active game."""
    if not proc_name:
        return False, ""

    # 1. Filter out common desktop and productivity tools
    if proc_name in excluded_processes:
        return False, proc_name

    # 2. Match known game executables
    if proc_name in known_game_processes:
        return True, proc_name

    # 3. Match game installation directories (Steam, Epic, Riot, etc.)
    if exe_path:
        for indicator in GAME_PATH_INDICATORS:
            if indicator in exe_path:
                return True, proc_name

    # 4. Fullscreen heuristic for unclassified applications
    screen_w, screen_h = screen_res
    if is_window_fullscreen(rect, screen_w, screen_h):
        return True, proc_name

    return False, proc_name


class GameDetector:
    """Background daemon monitor that detects games and manages 0% VRAM gaming mode."""

    def __init__(
        self,
        model_router: Any,
        overlay_notifier: Optional[Callable[[str, str, int], None]] = None,
        check_interval_seconds: float = 3.0,
        custom_excluded_processes: Optional[Sequence[str]] = None,
        custom_game_processes: Optional[Sequence[str]] = None,
        state_callback: Optional[Callable[[bool], None]] = None,
        consecutive_misses_to_stop: int = 2,
        vram_unloader: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.model_router = model_router
        self.overlay_notifier = overlay_notifier
        self.check_interval_seconds = max(0.5, float(check_interval_seconds))
        self.state_callback = state_callback
        self.consecutive_misses_to_stop = max(1, int(consecutive_misses_to_stop))
        self.vram_unloader = vram_unloader

        self.excluded_processes: Set[str] = set(DEFAULT_EXCLUDED_PROCESSES)
        if custom_excluded_processes:
            self.excluded_processes.update(p.lower().strip() for p in custom_excluded_processes)

        self.known_game_processes: Set[str] = set(DEFAULT_GAME_PROCESSES)
        if custom_game_processes:
            self.known_game_processes.update(p.lower().strip() for p in custom_game_processes)

        self._is_game_active: bool = False
        self._current_game_name: Optional[str] = None
        self._missed_checks: int = 0
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def is_game_active(self) -> bool:
        """Returns True if a game session is currently active."""
        with self._lock:
            return self._is_game_active

    @property
    def current_game_name(self) -> Optional[str]:
        """Returns the process name of the detected game, or None."""
        with self._lock:
            return self._current_game_name

    def check_cycle(self) -> bool:
        """Execute one inspection cycle. Returns True if a game is currently detected."""
        hwnd, rect, proc_name, exe_path = get_foreground_window_info()
        screen_res = get_screen_resolution()

        is_game, game_name = is_game_process(
            proc_name=proc_name,
            exe_path=exe_path,
            rect=rect,
            screen_res=screen_res,
            excluded_processes=self.excluded_processes,
            known_game_processes=self.known_game_processes,
        )

        with self._lock:
            if is_game:
                self._missed_checks = 0
                if not self._is_game_active:
                    self.on_game_start(game_name)
                return True
            else:
                if self._is_game_active:
                    self._missed_checks += 1
                    # Require consecutive non-game checks to prevent flicker when alt-tabbing briefly
                    if self._missed_checks >= self.consecutive_misses_to_stop:
                        self.on_game_stop()
                return False

    def on_game_start(self, game_name: str) -> None:
        """Triggered automatically when a game is detected in the foreground."""
        logger.info("Game detected: '%s'. Activating Gaming Mode (0%% VRAM).", game_name)
        self._is_game_active = True
        self._current_game_name = game_name
        self._missed_checks = 0

        # 1. Unload local models from GPU and route 100% to Groq Cloud
        if hasattr(self.model_router, "set_gaming_mode"):
            try:
                self.model_router.set_gaming_mode(True)
            except Exception as exc:
                logger.error("Failed to set gaming mode on router: %s", exc)

        # 2. Invoke explicit vram_unloader if registered
        if callable(self.vram_unloader):
            try:
                self.vram_unloader()
            except Exception as exc:
                logger.error("Failed to execute explicit vram_unloader: %s", exc)

        # 3. Notify system state
        if callable(self.state_callback):
            try:
                self.state_callback(True)
            except Exception as exc:
                logger.debug("State callback error: %s", exc)

        # 3. Emit HUD notification without stealing focus
        if callable(self.overlay_notifier):
            try:
                titulo = "JARVIS - Modo Juego"
                mensaje = f"Modo Juego activo (0% VRAM): {game_name}"
                self.overlay_notifier(titulo, mensaje, 5000)
            except Exception as exc:
                logger.debug("Overlay notification error: %s", exc)

    def on_game_stop(self) -> None:
        """Triggered automatically when the game session ends."""
        logger.info("Game session ended. Restoring standard local AI mode.")
        self._is_game_active = False
        self._current_game_name = None
        self._missed_checks = 0

        # 1. Restore local model availability
        if hasattr(self.model_router, "set_gaming_mode"):
            try:
                self.model_router.set_gaming_mode(False)
            except Exception as exc:
                logger.error("Failed to disable gaming mode on router: %s", exc)

        # 2. Notify system state
        if callable(self.state_callback):
            try:
                self.state_callback(False)
            except Exception as exc:
                logger.debug("State callback error: %s", exc)

        # 3. Emit HUD notification without stealing focus
        if callable(self.overlay_notifier):
            try:
                titulo = "JARVIS - Modo Juego"
                mensaje = "Modo Juego desactivado. Modelos locales listos."
                self.overlay_notifier(titulo, mensaje, 5000)
            except Exception as exc:
                logger.debug("Overlay notification error: %s", exc)

    def start(self) -> None:
        """Starts the background detector daemon thread."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="JARVIS-GameDetector",
                daemon=True,
            )
            self._thread.start()
            logger.info("GameDetector started in background (interval: %.1fs).", self.check_interval_seconds)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.check_cycle()
            except Exception as exc:
                logger.debug("Error in GameDetector check_cycle: %s", exc)
            self._stop_event.wait(self.check_interval_seconds)

    def stop(self, timeout: float = 2.0) -> None:
        """Stops the background detector daemon thread cleanly."""
        self._stop_event.set()
        with self._lock:
            thread = self._thread
            self._thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        logger.info("GameDetector stopped.")


__all__ = [
    "DEFAULT_EXCLUDED_PROCESSES",
    "DEFAULT_GAME_PROCESSES",
    "GAME_PATH_INDICATORS",
    "GameDetector",
    "get_foreground_window_info",
    "get_screen_resolution",
    "is_game_process",
    "is_window_fullscreen",
]
