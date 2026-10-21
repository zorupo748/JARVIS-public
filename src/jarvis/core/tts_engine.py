import os
import wave
import asyncio
import tempfile
import pygame
import edge_tts
from piper.voice import PiperVoice

class HybridTTS:
    def __init__(self, edge_voice="es-ES-AlvaroNeural", piper_model_path="voices/es_ES-davefx-medium.onnx"):
        self.edge_voice = edge_voice
        self.piper_model_path = piper_model_path
        self.piper_voice = None
        
        # Cargar modelo neuronal local de Piper si existe
        if os.path.exists(self.piper_model_path):
            try:
                self.piper_voice = PiperVoice.load(self.piper_model_path)
                print("[OK] Piper TTS (Voz neuronal local) cargado correctamente.")
            except Exception as e:
                print(f"[WARN] No se pudo cargar Piper TTS: {e}")
        else:
            print(f"[WARN] No se encontró el modelo de Piper en '{self.piper_model_path}'.")

        if not pygame.mixer.get_init():
            pygame.mixer.init()

    def stop(self) -> None:
        """Detiene de inmediato cualquier audio que se esté reproduciendo."""
        try:
            if pygame.mixer.get_init():
                pygame.mixer.music.stop()
        except Exception:
            pass

    def speak(self, text: str):
        if not text or not text.strip():
            return

        try:
            # Intento 1: Edge TTS (Nube)
            asyncio.run(self._speak_edge(text))
        except Exception as e:
            print(f" > [TTS WARNING] Edge TTS no disponible ({e}). Activando Piper TTS (Local)...")
            self._speak_piper(text)

    async def _speak_edge(self, text: str):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp3") as temp_file:
            temp_path = temp_file.name

        try:
            communicate = edge_tts.Communicate(text, self.edge_voice)
            await communicate.save(temp_path)

            pygame.mixer.music.load(temp_path)
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                pygame.time.Clock().tick(10)
        finally:
            pygame.mixer.music.unload()
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def _speak_piper(self, text: str):
        if not self.piper_voice:
            print(" > [ERROR] No hay motor de voz local disponible.")
            return

        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as temp_file:
            temp_path = temp_file.name

        try:
            audio_chunks = self.piper_voice.synthesize(text)
            audio_bytes = bytearray()

            for chunk in audio_chunks:
                if isinstance(chunk, (bytes, bytearray, memoryview)):
                    audio_bytes.extend(chunk)
                    continue

                audio_data = getattr(chunk, "audio", None)
                if isinstance(audio_data, (bytes, bytearray, memoryview)):
                    audio_bytes.extend(audio_data)
                    continue

                # Piper's AudioChunk objects usually expose .audio as the actual
                # byte payload. Avoid converting the whole chunk object to bytes,
                # because that may be an AudioChunk instance rather than a raw buffer.
                if audio_data is None:
                    continue

                if hasattr(audio_data, "__iter__") and not isinstance(audio_data, (str, bytes, bytearray, memoryview)):
                    try:
                        audio_bytes.extend(bytes(audio_data))
                    except (TypeError, ValueError):
                        pass

            with wave.open(temp_path, "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(22050)
                wav_file.writeframes(audio_bytes)

            pygame.mixer.music.load(temp_path)
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                pygame.time.Clock().tick(10)
        finally:
            pygame.mixer.music.unload()
            if os.path.exists(temp_path):
                os.remove(temp_path)