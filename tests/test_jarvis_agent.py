"""Unit tests for JarvisAgent and its integration with ToolRegistry and SecureSearchTool."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
from typing import Any, List, Optional

from jarvis.core.agent import JarvisAgent
from jarvis.intelligence.engine import AIResponse, IntelligenceEngine
from jarvis.security.levels import SecurityLevel
from jarvis.tools.base import ToolResult
from jarvis.tools.registry import ToolRegistry


class DummyMockEngine(IntelligenceEngine):
    """Engine mock that simulates a ReAct loop: tool call followed by final response."""

    def __init__(self, tool_to_call: str = "secure_search", tool_args: Optional[dict] = None) -> None:
        self.step = 0
        self.tool_to_call = tool_to_call
        self.tool_args = tool_args or {"query": "Alan Turing", "lang": "es"}
        self.last_messages: List[dict[str, Any]] = []
        self.last_tools: Optional[List[dict[str, Any]]] = None

    def generate(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        model: Optional[str] = None,
    ) -> AIResponse:
        self.last_messages = list(messages)
        self.last_tools = tools

        if self.step == 0:
            self.step += 1
            return AIResponse(
                content="",
                model="test-model",
                tool_calls=[{
                    "id": "call_abc123",
                    "name": self.tool_to_call,
                    "parameters": self.tool_args,
                }],
            )
        return AIResponse(
            content=f"Respuesta final sintetizada basada en {self.tool_to_call}.",
            model="test-model",
        )

    def health(self) -> bool:
        return True


class TestJarvisAgentToolIntegration(unittest.TestCase):
    def test_default_initialization_loads_tool_registry_and_executor(self):
        engine = DummyMockEngine()
        agent = JarvisAgent(engine)

        self.assertIsNotNone(agent.registry)
        self.assertIsNotNone(agent.executor)

        # Verify secure_search tool class is registered and accessible
        tool_cls = agent._get_tool("secure_search")
        self.assertIsNotNone(tool_cls)
        self.assertEqual(tool_cls.__name__, "SecureSearchTool")

        # Verify secure_web_search alias is also accessible
        alias_cls = agent._get_tool("secure_web_search")
        self.assertIsNotNone(alias_cls)
        self.assertEqual(alias_cls.__name__, "SecureSearchTool")

    def test_tool_specifications_contain_secure_search_without_duplicates(self):
        engine = DummyMockEngine()
        agent = JarvisAgent(engine)

        specs = agent._get_tool_specifications()
        self.assertIsInstance(specs, list)
        self.assertGreater(len(specs), 0)

        names = [s.get("name") for s in specs]
        self.assertIn("secure_search", names)

        # Check deduplication: secure_search must appear exactly once
        self.assertEqual(names.count("secure_search"), 1)

        # Verify specification structure
        secure_search_spec = next(s for s in specs if s.get("name") == "secure_search")
        self.assertIn("parameters", secure_search_spec)
        self.assertIn("description", secure_search_spec)

    @patch("jarvis.tools.web.secure_search.SecureSearchTool.execute")
    def test_agent_run_executes_secure_search_autonomously(self, mock_execute):
        mock_execute.return_value = ToolResult(
            tool_name="secure_search",
            content="Alan Turing fue un célebre matemático y pionero de la informática.",
            success=True,
        )

        engine = DummyMockEngine(tool_to_call="secure_search", tool_args={"query": "Alan Turing", "lang": "es"})
        agent = JarvisAgent(engine)

        final_answer = agent.run("¿Quién fue Alan Turing?")

        # Verify engine received tool specs including secure_search
        self.assertIsNotNone(engine.last_tools)
        tool_names = [t.get("name") for t in engine.last_tools]
        self.assertIn("secure_search", tool_names)

        # Verify tool was invoked by executor
        mock_execute.assert_called_once()
        call_kwargs = mock_execute.call_args[1]
        self.assertEqual(call_kwargs.get("query"), "Alan Turing")
        self.assertEqual(call_kwargs.get("lang"), "es")

        # Verify agent produced final synthesis
        self.assertIn("Respuesta final sintetizada basada en secure_search", final_answer)

    def test_security_authorization_denial(self):
        engine = DummyMockEngine(tool_to_call="secure_search")
        mock_security = MagicMock()
        mock_security.authorize.return_value = False

        agent = JarvisAgent(engine, security_gateway=mock_security)
        final_answer = agent.run("Consulta información confidencial")

        mock_security.authorize.assert_called_once()
        # Even with tool denial, the agent continues and does not crash
        self.assertIsNotNone(final_answer)


if __name__ == "__main__":
    unittest.main()
