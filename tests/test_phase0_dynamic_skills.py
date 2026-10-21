from __future__ import annotations

import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from jarvis.core.config import (
    DYNAMIC_SKILL_EXTERNAL_LOAD_DISABLED_MESSAGE,
    dynamic_skill_authoring_enabled,
    dynamic_skills_enabled,
    get_gemini_api_key,
)
from jarvis.skills.base import SkillManager
from jarvis.skills.dynamic_runtime import (
    DynamicSkillsDisabledError,
    execute_existing_dynamic_skill,
)
from jarvis.skills.skill_builder import DynamicSkillBuilder

DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE = DynamicSkillBuilder._pedir_modelo(
    None, None, ""
)


class Phase0DynamicSkillsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dynamic_env = patch.dict(
            os.environ,
            {"JARVIS_ENABLE_DYNAMIC_SKILLS": ""},
            clear=False,
        )
        self.dynamic_env.start()
        self.addCleanup(self.dynamic_env.stop)

    def test_gemini_configuration_is_optional(self) -> None:
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}, clear=False):
            self.assertIsNone(get_gemini_api_key())

    def test_dynamic_execution_is_blocked_before_module_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            dynamic_dir = Path(temporary_dir)
            (dynamic_dir / "blocked.py").write_text(
                "raise AssertionError('This module must not run')\n",
                encoding="utf-8",
            )

            with patch(
                "jarvis.skills.dynamic_runtime.importlib.util.spec_from_file_location"
            ) as module_loader:
                with self.assertRaisesRegex(
                    DynamicSkillsDisabledError,
                    "skills dinámicas están desactivadas",
                ):
                    execute_existing_dynamic_skill("blocked", dynamic_dir)

            module_loader.assert_not_called()

    def test_skill_builder_import_is_lazy_when_dynamic_skills_are_disabled(self) -> None:
        environment = os.environ.copy()
        environment["JARVIS_ENABLE_DYNAMIC_SKILLS"] = ""
        environment["PYTHONPATH"] = os.pathsep.join(
            filter(None, [str(SRC_ROOT), environment.get("PYTHONPATH", "")])
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "import jarvis.skills.skill_builder; "
                    "print('jarvis.core.model_router' in sys.modules)"
                ),
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "False")

    def test_authoring_paths_are_unconditionally_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            builder = DynamicSkillBuilder(Path(temporary_dir) / "skills")
            source = "def ejecutar_skill():\n    return 'ok'\n"

            with patch("builtins.exec") as execute_code:
                self.assertEqual(
                    builder.audit_and_test_skill(source),
                    (False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE),
                )
                self.assertEqual(
                    builder._probar_en_sandbox(source),
                    (False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE),
                )
            execute_code.assert_not_called()

            with patch("subprocess.run") as install_package:
                self.assertEqual(
                    builder._ensure_dependencies("import psutil"),
                    (False, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE),
                )
            install_package.assert_not_called()

            created, message = builder.create_skill_file("blocked", source)
            self.assertFalse(created)
            self.assertEqual(message, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE)
            self.assertFalse((builder.dynamic_dir / "blocked.py").exists())

            router = Mock()
            skill_manager = Mock()
            self.assertFalse(
                builder.reparar_skill_en_runtime(
                    "blocked",
                    "simulated failure",
                    router,
                    skill_manager,
                )
            )
            router.assert_not_called()
            skill_manager.assert_not_called()

            with patch("builtins.input") as prompt:
                builder.generate_and_load_skill(
                    "create a blocked skill",
                    router,
                    skill_manager,
                    simulacion=False,
                )
            prompt.assert_not_called()

    def test_generated_skill_intent_is_blocked_for_every_runtime_flag_value(self) -> None:
        request = (
            "Crea una skill dinámica en Python que abra una ventana gráfica temporal, "
            "capture la pantalla y analice la captura con el subsistema de visión."
        )

        for runtime_flag in (None, "", "false", "true"):
            with self.subTest(runtime_flag=runtime_flag), patch.dict(
                os.environ, {}, clear=False
            ):
                if runtime_flag is None:
                    os.environ.pop("JARVIS_ENABLE_DYNAMIC_SKILLS", None)
                else:
                    os.environ["JARVIS_ENABLE_DYNAMIC_SKILLS"] = runtime_flag

                self.assertFalse(dynamic_skill_authoring_enabled())
                builder = object.__new__(DynamicSkillBuilder)
                router = Mock()
                skill_manager = Mock()

                with (
                    patch.object(DynamicSkillBuilder, "_pedir_modelo") as model,
                    patch.object(DynamicSkillBuilder, "_diseñar_arquitectura") as design,
                    patch.object(DynamicSkillBuilder, "_generar_codigo") as generate,
                    patch.object(DynamicSkillBuilder, "_corregir_codigo") as repair,
                    patch.object(DynamicSkillBuilder, "reparar_skill_en_runtime") as runtime_repair,
                    patch.object(DynamicSkillBuilder, "validate_code_safety") as tester,
                    patch.object(DynamicSkillBuilder, "_ensure_dependencies") as dependencies,
                    patch.object(DynamicSkillBuilder, "_probar_en_sandbox") as sandbox,
                    patch.object(DynamicSkillBuilder, "audit_and_test_skill") as audit,
                    patch.object(DynamicSkillBuilder, "create_skill_file") as create_file,
                    patch("pathlib.Path.write_text") as write_file,
                    patch("builtins.exec") as execute_code,
                    patch("subprocess.run") as run_process,
                ):
                    result = builder.generate_and_load_skill(
                        request, router, skill_manager, simulacion=False
                    )

                self.assertEqual(result, DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE)
                for blocked_call in (
                    model,
                    design,
                    generate,
                    repair,
                    runtime_repair,
                    tester,
                    dependencies,
                    sandbox,
                    audit,
                    create_file,
                    write_file,
                    execute_code,
                    run_process,
                ):
                    blocked_call.assert_not_called()
                router.assert_not_called()
                skill_manager.assert_not_called()

    def test_builder_model_methods_are_unconditionally_blocked(self) -> None:
        builder = object.__new__(DynamicSkillBuilder)
        router = Mock()

        self.assertEqual(
            DynamicSkillBuilder._pedir_modelo(router, object(), "prompt"),
            DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE,
        )
        self.assertEqual(
            builder._diseñar_arquitectura("request", router),
            DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE,
        )
        self.assertEqual(
            builder._generar_codigo("request", "design", router),
            DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE,
        )
        self.assertEqual(
            builder._corregir_codigo("request", "code", "error", router),
            DYNAMIC_SKILL_AUTHORING_DISABLED_MESSAGE,
        )
        router.assert_not_called()

    def test_skill_manager_rejects_external_file_loading_for_every_runtime_flag(self) -> None:
        for runtime_flag in ("", "true"):
            with self.subTest(runtime_flag=runtime_flag), patch.dict(
                os.environ,
                {"JARVIS_ENABLE_DYNAMIC_SKILLS": runtime_flag},
                clear=False,
            ):
                manager = SkillManager()
                with patch(
                    "jarvis.skills.base.importlib.util.spec_from_file_location"
                ) as module_loader, patch("builtins.print") as report:
                    self.assertFalse(
                        manager.load_skill_from_file("untrusted", "C:/external/untrusted.py")
                    )

                module_loader.assert_not_called()
                report.assert_called_once_with(
                    f"[SKILL] {DYNAMIC_SKILL_EXTERNAL_LOAD_DISABLED_MESSAGE}"
                )
                self.assertNotIn("untrusted", manager._skills)
    def test_static_skill_registration_remains_available(self) -> None:
        skills = SkillManager()
        skills.register_skill("static_example", "Static test skill", lambda: "ok")
        self.assertEqual(skills.execute("static_example"), "ok")

    def test_main_uses_environment_configuration_and_the_safe_runtime_boundary(self) -> None:
        main_tree = ast.parse((PROJECT_ROOT / "main.py").read_text(encoding="utf-8"))

        router_calls = [
            node
            for node in ast.walk(main_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ModelRouter"
        ]
        self.assertEqual(len(router_calls), 1)
        gemini_keyword = next(
            keyword
            for keyword in router_calls[0].keywords
            if keyword.arg == "gemini_api_key"
        )
        gemini_value = gemini_keyword.value
        if not isinstance(gemini_value, ast.Call):
            self.fail("gemini_api_key must be set by a function call")
        gemini_func = gemini_value.func
        if not isinstance(gemini_func, ast.Name):
            self.fail("gemini_api_key must be set by a named function")
        self.assertEqual(gemini_func.id, "get_gemini_api_key")

        dynamic_executor = next(
            node
            for node in ast.walk(main_tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "ejecutar_skill_existente"
        )
        self.assertIn(
            "safe_skill_pipeline.execute_installed",
            ast.unparse(dynamic_executor),
        )

    def test_main_authoring_uses_the_safe_pipeline_without_reenabling_legacy_authoring(self) -> None:
        main_tree = ast.parse((PROJECT_ROOT / "main.py").read_text(encoding="utf-8"))
        intent_detector = next(
            node
            for node in ast.walk(main_tree)
            if isinstance(node, ast.FunctionDef) and node.name == "es_peticion_de_skill"
        )
        self.assertIn("crea una skill", ast.unparse(intent_detector).lower())

        main_source = ast.unparse(main_tree)
        self.assertIn("safe_skill_pipeline.author", main_source)
        self.assertIn("safe_skill_pipeline.prepare_installation", main_source)
        self.assertIn("safe_skill_pipeline.confirm_installation", main_source)
        self.assertNotIn("DynamicSkillBuilder", main_source)
        self.assertNotIn("generate_and_load_skill", main_source)
        self.assertNotIn("reparar_skill_en_runtime", main_source)

    def test_dynamic_skills_are_enabled_by_default_and_can_be_disabled(self) -> None:
        with patch.dict(
            os.environ,
            {"JARVIS_ENABLE_DYNAMIC_SKILLS": ""},
            clear=False,
        ):
            self.assertTrue(dynamic_skills_enabled())

        with patch.dict(
            os.environ,
            {"JARVIS_ENABLE_DYNAMIC_SKILLS": "false"},
            clear=False,
        ):
            self.assertFalse(dynamic_skills_enabled())

        with patch.dict(
            os.environ,
            {"JARVIS_ENABLE_DYNAMIC_SKILLS": "true"},
            clear=False,
        ):
            self.assertTrue(dynamic_skills_enabled())


if __name__ == "__main__":
    unittest.main()
