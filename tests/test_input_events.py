from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from jarvis.core.input_events import (
    InputSource,
    classify_stdin_source,
)


class FakeStdin:
    def __init__(self, is_terminal: bool) -> None:
        self._is_terminal = is_terminal

    def isatty(self) -> bool:
        return self._is_terminal


class BrokenStdin:
    def isatty(self) -> bool:
        raise OSError("cannot determine terminal state")


class InputSecurityTests(unittest.TestCase):
    def test_real_terminal_is_local_console(self) -> None:
        self.assertIs(
            classify_stdin_source(FakeStdin(True)),
            InputSource.LOCAL_CONSOLE,
        )

    def test_redirected_stdin_is_untrusted(self) -> None:
        self.assertIs(
            classify_stdin_source(FakeStdin(False)),
            InputSource.UNTRUSTED_STDIN,
        )

    def test_unknown_stdin_state_fails_closed(self) -> None:
        self.assertIs(
            classify_stdin_source(BrokenStdin()),
            InputSource.UNTRUSTED_STDIN,
        )

    def test_main_authenticates_device_only_for_nonempty_local_console_input(
        self,
    ) -> None:
        main_path = PROJECT_ROOT / "main.py"
        source = main_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        verify_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "verify"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "local_console_verifier"
        ]

        self.assertEqual(
            len(verify_calls),
            1,
            "Debe existir exactamente una llamada al verificador local.",
        )

        verify_call = verify_calls[0]
        guarding_ifs = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue

            body_nodes = {
                id(descendant)
                for statement in node.body
                for descendant in ast.walk(statement)
            }

            if id(verify_call) in body_nodes:
                guarding_ifs.append(node)

        self.assertTrue(
            guarding_ifs,
            "La verificación local debe estar protegida por un if.",
        )

        guard = ast.unparse(guarding_ifs[-1].test)

        self.assertIn(
            "input_source is InputSource.LOCAL_CONSOLE",
            guard,
        )
        self.assertIn("entrada", guard)

        self.assertIn(
            "input_source = classify_stdin_source(sys.stdin)",
            source,
        )
        self.assertIn(
            "PendingInput(prompt, InputSource.RECOVERY)",
            source,
        )


if __name__ == "__main__":
    unittest.main()
