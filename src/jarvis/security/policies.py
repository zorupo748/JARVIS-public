"""Compatibility helpers backed by the deterministic policy registry."""

from .levels import SecurityLevel
from .policy_core import ACTION_POLICIES, ActionPolicy, get_action_policy


# Kept for existing callers such as SecurityManager. It is derived from the
# sole action-policy registry instead of being a second permission table.
ACTION_LEVELS: dict[str, SecurityLevel] = {
    action_name: policy.required_level
    for action_name, policy in ACTION_POLICIES.items()
}


# Operations that can NEVER be authorized through normal security levels.
SUPER_ACTIONS: set[str] = {
    "modify_jarvis_security",
    "modify_jarvis_core",
    "modify_jarvis_code",
    "modify_system_file",
}


def get_required_level(action: str) -> SecurityLevel:
    """Return the legacy level view of a known action.

    Unknown actions still receive the old conservative Level 5 result for
    compatibility. The deterministic evaluator denies them outright.
    """

    return ACTION_LEVELS.get(action, SecurityLevel.LEVEL_5)


def is_super_action(action: str) -> bool:
    """Return True if an action requires owner-only SUPER authority."""

    return action in SUPER_ACTIONS


__all__ = [
    "ACTION_LEVELS",
    "ActionPolicy",
    "SUPER_ACTIONS",
    "get_action_policy",
    "get_required_level",
    "is_super_action",
]