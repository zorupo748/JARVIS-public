from __future__ import annotations

from jarvis.identity.models import UserIdentity
from jarvis.security import SecurityAction, SecurityLevel
from jarvis.security.action_executor import ActionExecutor

from ..base import BaseTool, ToolParameter
from ..registry import ToolRegistry


@ToolRegistry.register("create_file")
class CreateFileTool(BaseTool):

    name = "create_file"

    description = (
        "Create a text file inside an allowed workspace."
    )

    required_level = SecurityLevel.LEVEL_1

    @property
    def parameters(self) -> list[ToolParameter]:
        return [
            ToolParameter(
                name="target",
                description="Target file path",
            ),
            ToolParameter(
                name="content",
                description="File contents",
                required=False,
            ),
            ToolParameter(
                name="user",
                description="Authenticated user",
            ),
        ]

    def execute(self, **kwargs):
        user: UserIdentity = kwargs["user"]
        target: str = kwargs["target"]
        content: str = kwargs.get("content", "")

        action = SecurityAction(
            action="create_file",
            description=f"Create file {target}",
            required_level=self.required_level,
            target=target,
            metadata={
                "content": content,
            },
        )

        executor = ActionExecutor()

        return executor.execute(
            user=user,
            action=action,
        )