from __future__ import annotations

import ast
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class MainVoiceFlowTests(unittest.TestCase):
    def test_main_captures_audio_once_and_reuses_it_for_transcription(
        self,
    ) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)

        stt_listen_calls = []
        capture_assignments = []
        transcribe_calls = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "stt"
                ):
                    if node.func.attr == "listen":
                        stt_listen_calls.append(node)

                    if node.func.attr == "transcribe":
                        transcribe_calls.append(node)

            if isinstance(node, ast.Assign):
                value = node.value

                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Attribute)
                    and isinstance(value.func.value, ast.Name)
                    and value.func.value.id == "stt"
                    and value.func.attr == "capture"
                ):
                    capture_assignments.append(node)

        self.assertEqual(
            stt_listen_calls,
            [],
            "main.py no debe volver a ocultar la captura dentro de stt.listen().",
        )

        self.assertEqual(
            len(capture_assignments),
            1,
            "La rama de voz debe capturar exactamente una muestra.",
        )

        assignment = capture_assignments[0]

        self.assertEqual(len(assignment.targets), 1)
        self.assertIsInstance(assignment.targets[0], ast.Name)
        self.assertEqual(
            assignment.targets[0].id,
            "voice_utterance",
        )

        self.assertEqual(
            len(transcribe_calls),
            1,
            "La rama activa debe transcribir exactamente una muestra.",
        )

        call = transcribe_calls[0]

        self.assertEqual(len(call.args), 1)
        self.assertIsInstance(call.args[0], ast.Name)
        self.assertEqual(
            call.args[0].id,
            "voice_utterance",
        )

    def test_voice_sample_is_preserved_before_security_context_is_built(
        self,
    ) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(
            encoding="utf-8"
        )

        capture_position = source.index(
            "voice_utterance = stt.capture()"
        )
        security_position = source.index(
            "security_session.begin_interaction()"
        )

        self.assertLess(
            capture_position,
            security_position,
        )


if __name__ == "__main__":
    unittest.main()
