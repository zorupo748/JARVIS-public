"""Floating translucent HUD Overlay window for JARVIS notifications.

Features:
- Frameless, translucent dark modern aesthetic with rounded corners and glowing borders.
- Stays on top without stealing focus or interrupting foreground games/apps (WS_EX_NOACTIVATE).
- Thread-safe `mostrar_notificacion()` callable from any background or worker thread.
- Auto-dismissing with fade animations and queue management.
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# Windows Constants for non-activating topmost tool window
GWL_EXSTYLE = -20
WS_EX_NOACTIVATE = 0x08000000
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_TOPMOST = 0x00000008

_PYSIDE_AVAILABLE = False
try:
    from PySide6.QtCore import QEasingCurve, QObject, QPoint, QPropertyAnimation, Qt, QTimer, Signal
    from PySide6.QtGui import QColor, QFont
    from PySide6.QtWidgets import (
        QApplication,
        QFrame,
        QGraphicsOpacityEffect,
        QHBoxLayout,
        QLabel,
        QVBoxLayout,
        QWidget,
    )

    _PYSIDE_AVAILABLE = True
except ImportError:
    logger.warning("PySide6 is not installed. HUD Overlay will operate in headless fallback mode.")


if _PYSIDE_AVAILABLE:

    class HUDNotificationCard(QFrame):
        """A single translucent notification card with glow effect and smooth dismissal."""

        def __init__(
            self,
            title: str,
            message: str,
            duration_ms: int = 5000,
            parent: Optional[QWidget] = None,
        ) -> None:
            super().__init__(parent)
            self.setObjectName("hudCard")
            self.duration_ms = duration_ms

            # Styling
            self.setStyleSheet(
                """
                QFrame#hudCard {
                    background-color: rgba(15, 23, 42, 0.92);
                    border: 1px solid rgba(56, 189, 248, 0.6);
                    border-radius: 12px;
                }
                QLabel#hudBadge {
                    color: #0ea5e9;
                    font-size: 11px;
                    font-weight: bold;
                }
                QLabel#hudTitle {
                    color: #38bdf8;
                    font-size: 13px;
                    font-weight: bold;
                }
                QLabel#hudMessage {
                    color: #f1f5f9;
                    font-size: 12px;
                    line-height: 1.4;
                }
                """
            )

            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 12, 16, 14)
            layout.setSpacing(4)

            # Header row
            header_layout = QHBoxLayout()
            badge_label = QLabel("⚡ JARVIS HUD")
            badge_label.setObjectName("hudBadge")
            header_layout.addWidget(badge_label)
            header_layout.addStretch()

            self.title_label = QLabel(title)
            self.title_label.setObjectName("hudTitle")
            self.title_label.setWordWrap(True)

            self.msg_label = QLabel(message)
            self.msg_label.setObjectName("hudMessage")
            self.msg_label.setWordWrap(True)

            layout.addLayout(header_layout)
            layout.addWidget(self.title_label)
            layout.addWidget(self.msg_label)

            self.setFixedWidth(360)

            # Opacity effect for fade out
            self.opacity_effect = QGraphicsOpacityEffect(self)
            self.setGraphicsEffect(self.opacity_effect)
            self.opacity_effect.setOpacity(1.0)

            # Dismiss timer
            self.timer = QTimer(self)
            self.timer.setSingleShot(True)
            self.timer.timeout.connect(self._fade_out)
            self.timer.start(max(1000, self.duration_ms))

        def _fade_out(self) -> None:
            self.anim = QPropertyAnimation(self.opacity_effect, b"opacity")
            self.anim.setDuration(400)
            self.anim.setStartValue(1.0)
            self.anim.setEndValue(0.0)
            self.anim.setEasingCurve(QEasingCurve.OutCubic)
            self.anim.finished.connect(self.deleteLater)
            self.anim.start()


    class HUDOverlayWindow(QWidget):
        """Topmost, non-activating desktop container for JARVIS HUD cards."""

        def __init__(self) -> None:
            super().__init__()
            self._setup_window_flags()
            self._setup_layout()

        def _setup_window_flags(self) -> None:
            # Base Qt flags: frameless, topmost, tool window
            flags = (
                Qt.FramelessWindowHint
                | Qt.WindowStaysOnTopHint
                | Qt.Tool
                | Qt.SubWindow
            )
            self.setWindowFlags(flags)
            self.setAttribute(Qt.WA_TranslucentBackground, True)
            self.setAttribute(Qt.WA_ShowWithoutActivating, True)

        def _apply_windows_noactivate(self) -> None:
            """Configure Windows win32 style WS_EX_NOACTIVATE to prevent stealing focus."""
            if sys.platform != "win32":
                return
            try:
                hwnd = int(self.winId())
                user32 = ctypes.windll.user32
                style = user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                new_style = style | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST
                user32.SetWindowLongW(hwnd, GWL_EXSTYLE, new_style)
            except Exception as exc:
                logger.debug("Non-fatal: could not apply WS_EX_NOACTIVATE on win32: %s", exc)

        def _setup_layout(self) -> None:
            self.main_layout = QVBoxLayout(self)
            self.main_layout.setContentsMargins(10, 10, 10, 10)
            self.main_layout.setSpacing(10)
            self.main_layout.setAlignment(Qt.AlignTop | Qt.AlignRight)

            self._reposition()

        def _reposition(self) -> None:
            """Position window at top right of the primary desktop screen."""
            screen = QApplication.primaryScreen()
            if screen is not None:
                geo = screen.availableGeometry()
                width = 400
                height = geo.height() - 80
                self.setGeometry(geo.width() - width - 20, 40, width, height)

        def add_notification(self, title: str, message: str, duration_ms: int = 5000) -> None:
            card = HUDNotificationCard(title, message, duration_ms, parent=self)
            self.main_layout.insertWidget(0, card)
            self.show()
            self._apply_windows_noactivate()


    class HUDController(QObject):
        """Thread-safe signal dispatcher for HUD notifications."""

        notification_signal = Signal(str, str, int)

        def __init__(self) -> None:
            super().__init__()
            self._window: Optional[HUDOverlayWindow] = None
            self.notification_signal.connect(self._handle_notification)

        def _ensure_window(self) -> HUDOverlayWindow:
            if self._window is None:
                self._window = HUDOverlayWindow()
            return self._window

        def _handle_notification(self, title: str, message: str, duration_ms: int) -> None:
            window = self._ensure_window()
            window.add_notification(title, message, duration_ms)


    class _HUDManager:
        """Global manager ensuring QApplication background thread and notification routing."""

        def __init__(self) -> None:
            self._lock = threading.Lock()
            self._app: Optional[QApplication] = None
            self._controller: Optional[HUDController] = None
            self._thread: Optional[threading.Thread] = None
            self._ready_event = threading.Event()

        def _run_app(self) -> None:
            self._app = QApplication.instance()
            if self._app is None:
                self._app = QApplication(["JARVIS_HUD"])
                self._app.setQuitOnLastWindowClosed(False)

            self._controller = HUDController()
            self._ready_event.set()
            self._app.exec()

        def ensure_started(self) -> None:
            if "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("JARVIS_HEADLESS") == "1":
                return

            with self._lock:
                if self._thread is not None and self._thread.is_alive():
                    return

                # If QApplication is already running in main thread
                current_app = QApplication.instance()
                if current_app is not None:
                    if self._controller is None:
                        self._controller = HUDController()
                    return

                # Start dedicated Qt GUI event loop in background thread
                self._ready_event.clear()
                self._thread = threading.Thread(target=self._run_app, name="JARVIS_HUD_Thread", daemon=True)
                self._thread.start()
                self._ready_event.wait(timeout=2.0)

        def show(self, title: str, message: str, duration_ms: int = 5000) -> None:
            self.last_notification = (title, message, duration_ms)
            if "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("JARVIS_HEADLESS") == "1":
                logger.debug("[HUD TEST/HEADLESS] %s: %s", title, message)
                return

            self.ensure_started()
            if self._controller is not None:
                self._controller.notification_signal.emit(title, message, duration_ms)
            else:
                logger.info("[HUD FALLBACK] %s: %s", title, message)

    _GLOBAL_HUD_MANAGER = _HUDManager()

else:
    # Headless stub when PySide6 is unavailable
    class _StubHUDManager:
        def show(self, title: str, message: str, duration_ms: int = 5000) -> None:
            logger.info("[HUD STUB] %s: %s", title, message)

    _GLOBAL_HUD_MANAGER = _StubHUDManager()


def mostrar_notificacion(
    titulo: str,
    mensaje: str,
    duracion_ms: int = 5000,
) -> None:
    """Muestra una notificación en el HUD flotante sin robar el foco de la pantalla.

    Args:
        titulo: Encabezado de la notificación (ej. "JARVIS", "Orquestador", "Modo Juego").
        mensaje: Texto descriptivo de la notificación.
        duracion_ms: Tiempo en milisegundos antes de desaparecer (default: 5000 ms).
    """
    try:
        _GLOBAL_HUD_MANAGER.show(titulo, mensaje, duracion_ms)
    except Exception as exc:
        logger.debug("No se pudo mostrar la notificación en el HUD: %s", exc)


__all__ = [
    "HUDController",
    "HUDNotificationCard",
    "HUDOverlayWindow",
    "mostrar_notificacion",
]
