from __future__ import annotations

import ast
import json
import re
import tempfile
import unittest
import unicodedata
from pathlib import Path
from typing import Callable

from jarvis.core.capability_router import CapabilityDecision, CapabilityRouter


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAIN_SOURCE_PATH = PROJECT_ROOT / "main.py"
SKILL_RESOLVER_FUNCTIONS = {
    "_tokens_semanticos_skill",
    "es_peticion_de_skill",
    "indexar_skills_dinamicas",
    "obtener_skill_a_ejecutar",
    "resolver_intencion_skill",
    "resolver_skill_prioritaria",
}

PACKAGE_TRACKING_REQUEST = (
    "Cuando te pregunte dónde está mi paquete quiero que consultes 1688track "
    "usando el código OXCGH6082081H, me expliques en español dónde está, qué "
    "ha pasado, qué se espera que ocurra después, recuerdes el estado anterior "
    "y me digas si ha cambiado desde la última vez."
)


def load_skill_resolver(dynamic_dir: Path) -> dict[str, object]:
    source = MAIN_SOURCE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    selected_nodes = [
        node
        for node in tree.body
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in SKILL_RESOLVER_FUNCTIONS
        )
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "_TOKENS_GENERICOS_SKILL"
                for target in node.targets
            )
        )
    ]
    namespace: dict[str, object] = {
        "ast": ast,
        "re": re,
        "unicodedata": unicodedata,
        "Path": Path,
        "DYNAMIC_SKILLS_DIR": dynamic_dir,
        "print": lambda *_args, **_kwargs: None,
    }
    module = ast.Module(body=selected_nodes, type_ignores=[])
    exec(compile(module, str(MAIN_SOURCE_PATH), "exec"), namespace)
    return namespace


class SkillIntentResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.dynamic_dir = Path(self.temporary_dir.name)
        self.namespace = load_skill_resolver(self.dynamic_dir)

    def write_skill(self, name: str, source: str = "") -> None:
        (self.dynamic_dir / f"{name}.py").write_text(source, encoding="utf-8")

    def resolver(self, name: str) -> Callable[..., object]:
        resolver = self.namespace[name]
        assert callable(resolver)
        return resolver

    def test_ollama_product_name_is_a_strong_name_anchor(self) -> None:
        self.write_skill("comprobar_ollama")

        self.assertEqual(
            self.resolver("resolver_skill_prioritaria")(
                "Hay alguna actualización para Ollama?"
            ),
            "comprobar_ollama",
        )
        self.assertEqual(
            self.resolver("resolver_skill_prioritaria")(
                "mira la versión de ollama"
            ),
            "comprobar_ollama",
        )

    def test_package_tracking_request_does_not_match_ollama_skill(self) -> None:
        self.write_skill("comprobar_ollama")
        self.assertIsNone(
            self.resolver("resolver_skill_prioritaria")(PACKAGE_TRACKING_REQUEST)
        )

    def test_generic_state_and_change_words_do_not_select_ollama(self) -> None:
        self.write_skill("comprobar_ollama")
        self.assertIsNone(
            self.resolver("resolver_skill_prioritaria")(
                "quiero guardar el estado anterior y comprobar si algo ha cambiado"
            )
        )
        self.assertIsNone(
            self.resolver("resolver_skill_prioritaria")(
                "consulta el estado de mi paquete"
            )
        )

    def test_index_uses_only_filename_and_explicit_skill_documentation(self) -> None:
        self.write_skill(
            "weather_report",
            '''"""Consulta meteorológica documentada."""
import internal_module
SECRET = "paquete estado cambio datos"
cache.ultima_version = SECRET

def helper():
    """Descripción interna no destinada a activar la skill."""
    return "consulta resultado guardar"

def ejecutar_skill():
    """Obtiene el pronóstico de una ciudad."""
    response = internal_module.fetch("secret value")
    return response
''',
        )

        index = self.resolver("indexar_skills_dinamicas")()
        description = index["weather_report"]
        self.assertEqual(
            description,
            "weather report Consulta meteorológica documentada. "
            "Obtiene el pronóstico de una ciudad.",
        )
        for implementation_detail in (
            "internal_module",
            "ultima_version",
            "paquete",
            "helper",
            "Descripción interna",
            "resultado",
        ):
            self.assertNotIn(implementation_detail, description)

    def test_generic_documentation_matches_are_not_enough(self) -> None:
        self.write_skill(
            "comprobar_estado",
            '"""Consultar estado anterior y cambios."""\n',
        )
        self.write_skill(
            "revisar_datos",
            '"""Consultar estado anterior y cambios."""\n',
        )
        self.assertIsNone(
            self.resolver("resolver_skill_prioritaria")(
                "consulta el estado anterior y comprueba si hubo cambios"
            )
        )

    def test_close_duplicate_documentation_matches_fail_closed(self) -> None:
        self.write_skill(
            "monitor_service_alpha",
            '"""Monitoriza servicios locales para detectar incidencias."""\n',
        )
        self.write_skill(
            "monitor_service_beta",
            '"""Monitoriza servicios locales para detectar incidencias."""\n',
        )
        self.assertIsNone(
            self.resolver("resolver_skill_prioritaria")(
                "monitoriza los servicios locales y detecta incidencias"
            )
        )

    def test_explicit_skill_execution_command_still_resolves(self) -> None:
        self.write_skill("comprobar_ollama")
        self.assertEqual(
            self.resolver("resolver_skill_prioritaria")(
                "ejecuta comprobar_ollama"
            ),
            "comprobar_ollama",
        )

    def test_hardware_special_case_remains_available_for_hardware_intent(self) -> None:
        self.write_skill("hardwae_monitoring")
        self.assertEqual(
            self.resolver("resolver_skill_prioritaria")(
                "comprueba la temperatura del hardware"
            ),
            "hardwae_monitoring",
        )
        self.assertIsNone(
            self.resolver("resolver_skill_prioritaria")(
                "consulta el estado de mi paquete"
            )
        )

    def test_package_request_continues_to_capability_router_without_execution(self) -> None:
        self.write_skill("comprobar_ollama")
        prioritized_skill = self.resolver("resolver_skill_prioritaria")(
            PACKAGE_TRACKING_REQUEST
        )
        self.assertIsNone(prioritized_skill)

        index = self.resolver("indexar_skills_dinamicas")()
        prompts: list[str] = []

        def fake_classifier(prompt: str) -> str:
            prompts.append(prompt)
            return json.dumps(
                {
                    "decision": "CREATE_SKILL",
                    "reason": "reusable package tracking with persistent history",
                    "confidence": 0.96,
                }
            )

        route = CapabilityRouter(fake_classifier).route(
            PACKAGE_TRACKING_REQUEST,
            installed_skills=index,
        )

        self.assertEqual(route.decision, CapabilityDecision.CREATE_SKILL)
        self.assertEqual(route.source, "rule")
        self.assertEqual(len(prompts), 0)
        self.assertIsNone(prioritized_skill)


if __name__ == "__main__":
    unittest.main()
