from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


# Tests must never import or initialise the real EasyOCR package.
easyocr_stub = types.ModuleType("easyocr")
easyocr_stub.Reader = Mock()
sys.modules["easyocr"] = easyocr_stub


import jarvis.core.ocr_engine as ocr_engine


class OCREngineTests(unittest.TestCase):
    def tearDown(self) -> None:
        ocr_engine.OCREngine._reader = None

    def test_cpu_is_the_default_and_reaches_easyocr_as_gpu_false(self) -> None:
        reader = Mock()
        with patch.dict(ocr_engine.os.environ, {}, clear=True), patch.object(
            ocr_engine.easyocr,
            "Reader",
            return_value=reader,
        ) as reader_factory, patch("builtins.print") as printer:
            result = ocr_engine.OCREngine.get_reader()
            self.assertEqual(ocr_engine.get_ocr_device(), "cpu")

        self.assertIs(result, reader)
        reader_factory.assert_called_once_with(["es", "en"], gpu=False)
        printer.assert_called_once_with(" > [OCR] EasyOCR configurado en CPU.")

    def test_cuda_configuration_reaches_easyocr_as_gpu_true(self) -> None:
        reader = Mock()
        with patch.dict(
            ocr_engine.os.environ,
            {"JARVIS_OCR_DEVICE": "cuda"},
            clear=True,
        ), patch.object(
            ocr_engine.easyocr,
            "Reader",
            return_value=reader,
        ) as reader_factory, patch("builtins.print") as printer:
            result = ocr_engine.OCREngine.get_reader()

        self.assertIs(result, reader)
        reader_factory.assert_called_once_with(["es", "en"], gpu=True)
        printer.assert_called_once_with(" > [OCR] EasyOCR configurado en GPU (CUDA).")

    def test_text_extraction_behavior_is_unchanged(self) -> None:
        reader = Mock()
        reader.readtext.return_value = ["hola", "mundo"]
        ocr_engine.OCREngine._reader = reader

        result = ocr_engine.OCREngine.extraer_texto("captura.png")

        self.assertEqual(result, "hola\nmundo")
        reader.readtext.assert_called_once_with("captura.png", detail=0)

    def test_empty_or_failing_extraction_keeps_existing_messages(self) -> None:
        empty_reader = Mock()
        empty_reader.readtext.return_value = []
        ocr_engine.OCREngine._reader = empty_reader
        self.assertEqual(
            ocr_engine.OCREngine.extraer_texto("vacia.png"),
            "[OCR sin texto legible detectado]",
        )

        failing_reader = Mock()
        failing_reader.readtext.side_effect = RuntimeError("fallo")
        ocr_engine.OCREngine._reader = failing_reader
        self.assertEqual(
            ocr_engine.OCREngine.extraer_texto("rota.png"),
            "[Error crítico en motor OCR]: fallo",
        )


if __name__ == "__main__":
    unittest.main()