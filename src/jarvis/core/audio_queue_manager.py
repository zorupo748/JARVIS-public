import queue
import threading

class SpeechQueueManager:
    def __init__(self, tts_engine_callback):
        self.queue = queue.Queue()
        self.tts_callback = tts_engine_callback
        self.is_running = True
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start()

    def add_message(self, texto: str):
        self.queue.put(texto)

    def _process_queue(self):
        while self.is_running:
            try:
                texto = self.queue.get(timeout=0.5)
                if texto:
                    self.tts_callback(texto)
                self.queue.task_done()
            except queue.Empty:
                continue

    def clear(self) -> None:
        """Vacía todos los mensajes pendientes de la cola de voz."""
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except (queue.Empty, ValueError):
                break

    def purge_and_stop(self) -> None:
        """Descarta mensajes encolados y detiene la reproducción activa si es posible."""
        self.clear()
        if hasattr(self.tts_callback, "stop") and callable(self.tts_callback.stop):
            try:
                self.tts_callback.stop()
            except Exception:
                pass

    def stop(self):
        self.is_running = False
        self.clear()