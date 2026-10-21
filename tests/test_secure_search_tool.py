"""Unit tests for SecureSearchTool and adapters."""

import unittest
from unittest.mock import AsyncMock, patch

from jarvis.skills.base import SkillManager
from jarvis.skills.secure_search_skill import (
    register_secure_search_skill,
    secure_search_adapter,
)
from jarvis.tools.base import ToolResult
from jarvis.tools.executor import ToolExecutor
from jarvis.tools.registry import ToolRegistry
from jarvis.tools.web.secure_search import SecureSearchTool


class TestSecureSearchTool(unittest.TestCase):
    def test_registry_contains_secure_search(self):
        tool_cls = ToolRegistry.get("secure_search")
        self.assertIsNotNone(tool_cls)
        self.assertEqual(tool_cls, SecureSearchTool)

        # Alias secure_web_search
        alias_cls = ToolRegistry.get("secure_web_search")
        self.assertEqual(alias_cls, SecureSearchTool)

    def test_specification_format(self):
        tool = SecureSearchTool()
        spec = tool.specification()
        self.assertEqual(spec["name"], "secure_search")
        self.assertIn("parameters", spec)
        self.assertIn("query", spec["parameters"]["properties"])
        self.assertIn("query", spec["parameters"]["required"])

    @patch("jarvis.skills.secure_search_skill.SecureSearchSkill.search_topic", new_callable=AsyncMock)
    def test_execute_success(self, mock_search):
        mock_search.return_value = "Python es un lenguaje de programación de alto nivel."

        tool = SecureSearchTool()
        result = tool.execute(query="Python", lang="es")

        self.assertIsInstance(result, ToolResult)
        self.assertTrue(result.success)
        self.assertIn("Resumen de consulta segura: Python (ES)", result.content)
        self.assertIn("Python es un lenguaje de programación", result.content)
        self.assertIn("Fuente verificada", result.content)
        mock_search.assert_called_once_with("Python")

    def test_execute_empty_query(self):
        tool = SecureSearchTool()
        result = tool.execute(query="")
        self.assertFalse(result.success)
        self.assertIn("No se proporcionó ningún término", result.content)

    @patch("jarvis.skills.secure_search_skill.SecureSearchSkill.search_topic", new_callable=AsyncMock)
    def test_execute_permission_error_handled(self, mock_search):
        mock_search.side_effect = PermissionError("Dominio no permitido")

        tool = SecureSearchTool()
        result = tool.execute(query="https://evil.com/test")

        self.assertFalse(result.success)
        self.assertIn("[Error de Seguridad]", result.content)
        self.assertTrue(result.metadata.get("blocked"))

    @patch("jarvis.skills.secure_search_skill.SecureSearchSkill.search_topic", new_callable=AsyncMock)
    def test_execute_timeout_error_handled(self, mock_search):
        mock_search.side_effect = TimeoutError("Navigation timeout")

        tool = SecureSearchTool()
        result = tool.execute(query="SlowTopic")

        self.assertFalse(result.success)
        self.assertIn("[Tiempo Excedido]", result.content)
        self.assertTrue(result.metadata.get("timeout"))

    @patch("jarvis.skills.secure_search_skill.SecureSearchSkill.search_topic", new_callable=AsyncMock)
    def test_tool_executor_integration(self, mock_search):
        mock_search.return_value = "Información sobre robótica autónoma."

        executor = ToolExecutor()
        exec_result = executor.execute(
            user=None,
            tool_name="secure_search",
            arguments={"query": "Robotics", "lang": "es"},
        )

        self.assertTrue(exec_result.success)
        self.assertIn("Robotics", exec_result.message)
        self.assertIn("Información sobre robótica autónoma.", exec_result.message)

    @patch("jarvis.skills.secure_search_skill.SecureSearchSkill.search_topic", new_callable=AsyncMock)
    def test_skill_manager_adapter(self, mock_search):
        mock_search.return_value = "Resumen extraído de prueba."

        manager = SkillManager()
        register_secure_search_skill(manager)

        self.assertIn("buscar_en_internet_seguro", manager._skills)
        res = manager.execute("buscar_en_internet_seguro", query="TestTopic", lang="es")

        self.assertIn("Resumen extraído de prueba.", res)
        self.assertIn("TestTopic", res)


if __name__ == "__main__":
    unittest.main()
