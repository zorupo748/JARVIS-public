from __future__ import annotations

import os

import easyocr


OCR_DEVICE_ENV = "JARVIS_OCR_DEVICE"


def get_ocr_device() -> str:
    """Return the explicitly configured EasyOCR device, defaulting to CPU."""

    requested_device = os.getenv(OCR_DEVICE_ENV, "cpu").strip().lower()
    return "cuda" if requested_device == "cuda" else "cpu"


class OCREngine:
    _reader = None

    @classmethod
    def get_reader(cls):
        if cls._reader is None:
            device = get_ocr_device()
            if device == "cuda":
                print(" > [OCR] EasyOCR configurado en GPU (CUDA).")
            else:
                print(" > [OCR] EasyOCR configurado en CPU.")
            cls._reader = easyocr.Reader(
                ["es", "en"],
                gpu=device == "cuda",
            )
        return cls._reader

    @staticmethod
    def extraer_texto(image_path: str) -> str:
        try:
            reader = OCREngine.get_reader()
            resultados = reader.readtext(image_path, detail=0)
            texto_limpio = "\n".join(str(resultado) for resultado in resultados)
            return texto_limpio if texto_limpio.strip() else "[OCR sin texto legible detectado]"
        except Exception as e:
            return f"[Error crítico en motor OCR]: {e}"