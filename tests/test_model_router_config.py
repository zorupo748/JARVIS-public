from __future__ import annotations

import ast
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "jarvis" / "core" / "model_router.py"
SOURCE = MODULE_PATH.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE, filename=str(MODULE_PATH))


class ModelRouterConfigurationTests(unittest.TestCase):
    @staticmethod
    def _constants() -> dict[str, str]:
        constants: dict[str, str] = {}
        for node in TREE.body:
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
                continue
            if not isinstance(node.value.value, str):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    constants[target.id] = node.value.value
        return constants

    @staticmethod
    def _method(name: str) -> ast.FunctionDef:
        router_class = next(
            node for node in TREE.body
            if isinstance(node, ast.ClassDef) and node.name == "ModelRouter"
        )
        return next(
            node for node in router_class.body
            if isinstance(node, ast.FunctionDef) and node.name == name
        )

    @staticmethod
    def _ollama_model_names(method: ast.FunctionDef) -> list[str]:
        return [
            call.args[0].id
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "_call_ollama"
            and call.args
            and isinstance(call.args[0], ast.Name)
        ]

    def test_declares_target_multi_model_configuration(self) -> None:
        self.assertEqual(
            self._constants(),
            {
                "MODEL_ORCHESTRATOR_LOCAL": "qwen3.5:4b",
                "MODEL_CODING_LOCAL": "qwen2.5-coder:7b-instruct-q4_K_M",
                "MODEL_VISION_LOCAL": "qwen3-vl:4b",
                "MODEL_REASONING_LOCAL": "qwen3.5:9b",
                "MODEL_GROQ_CLOUD": "qwen/qwen3.6-27b",
                "MODEL_GEMINI_CLOUD": "gemini-3.8-flash",
            },
        )

    def test_speech_role_remains_and_uses_the_orchestrator_model(self) -> None:
        role_class = next(
            node for node in TREE.body
            if isinstance(node, ast.ClassDef) and node.name == "ModelRole"
        )
        role_names = {
            target.id
            for node in role_class.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        self.assertIn("SPEECH", role_names)
        self.assertNotIn("MODEL_SPEECH", SOURCE)
        self.assertIn(
            "MODEL_ORCHESTRATOR_LOCAL",
            self._ollama_model_names(self._method("route")),
        )

    def test_orchestration_and_fallbacks_share_the_orchestrator_model(self) -> None:
        for method_name in ("route_inteligente", "_fallback_with_notice"):
            self.assertIn(
                "MODEL_ORCHESTRATOR_LOCAL",
                self._ollama_model_names(self._method(method_name)),
            )
        self.assertIn("Razonamiento local Qwen3.5 9B", SOURCE)

    def test_code_review_output_budget_is_dedicated(self) -> None:
        method = self._method("run_groq_code_review")
        call = next(
            call
            for call in ast.walk(method)
            if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "_call_groq"
        )
        keyword_names = {keyword.arg for keyword in call.keywords}
        self.assertIn("JARVIS_GROQ_CODE_REVIEW_MAX_TOKENS", SOURCE)
        self.assertIn("get_groq_code_review_max_tokens", SOURCE)
        self.assertIn("max_tokens", keyword_names)
    def test_code_review_route_is_explicit_and_configurable(self) -> None:
        method = self._method("run_groq_code_review")
        called_methods = {
            call.func.attr
            for call in ast.walk(method)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
        }
        self.assertIn("JARVIS_GROQ_CODE_REVIEW_MODEL", SOURCE)
        self.assertIn("MODEL_GROQ_CODE_REVIEW", SOURCE)
        self.assertIn("_call_groq", called_methods)
        self.assertNotIn("_call_groq_fallback", called_methods)
        self.assertNotIn("run_local_reasoning", called_methods)

if __name__ == "__main__":
    unittest.main()
