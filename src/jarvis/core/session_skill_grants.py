"""Process-local grants for repeatedly executing one verified skill version."""

from __future__ import annotations

import re

from jarvis.security.policy_core import (
    PolicyDecisionKind,
    SessionSkillAuthorization,
)

_SKILL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class SessionSkillGrantStore:
    """Keep explicit execution approvals in RAM until this process exits."""

    def __init__(self) -> None:
        self._grants: set[tuple[str, str, str | None]] = set()

    def grant(
        self,
        skill_name: str,
        source_hash: str,
        user_id: str | None = None,
    ) -> None:
        skill_name, source_hash = self._validate_key(skill_name, source_hash)
        if user_id is not None and (not isinstance(user_id, str) or not user_id.strip()):
            raise ValueError("user_id must be a non-empty string or None")
        self._grants.add((skill_name, source_hash, user_id))

    def is_granted(
        self,
        skill_name: str,
        source_hash: str,
        user_id: str | None = None,
    ) -> bool:
        skill_name, source_hash = self._validate_key(skill_name, source_hash)
        if user_id is None:
            return any(
                granted_name == skill_name and granted_hash == source_hash
                for granted_name, granted_hash, _granted_user in self._grants
            )
        return (skill_name, source_hash, user_id) in self._grants

    def authorization_for(
        self,
        skill_name: str,
        source_hash: str,
        user_id: str | None,
    ) -> SessionSkillAuthorization | None:
        skill_name, source_hash = self._validate_key(skill_name, source_hash)
        if not isinstance(user_id, str) or not user_id.strip():
            return None
        if not self.is_granted(skill_name, source_hash, user_id):
            return None
        return SessionSkillAuthorization(skill_name, source_hash, user_id)

    def grant_from_confirmed_execution(
        self,
        execution_result: object,
        user_id: str | None,
    ) -> bool:
        """Grant only after a positive confirmation produced a policy ALLOW."""
        if not isinstance(user_id, str) or not user_id.strip():
            return False
        if not getattr(execution_result, "allowed", False):
            return False
        if not getattr(execution_result, "hash_verified", False):
            return False
        decision = getattr(execution_result, "policy_decision", None)
        if decision is None or decision.kind is not PolicyDecisionKind.ALLOW:
            return False
        action = getattr(execution_result, "action", None)
        skill_name = getattr(execution_result, "skill_name", None)
        if action is None or action.action != "execute_dynamic_skill":
            return False
        source_hash = action.metadata.get("source_hash")
        if action.metadata.get("skill_name") != skill_name:
            return False
        if action.target != f"dynamic/{skill_name}.py#sha256-{source_hash}":
            return False
        try:
            self.grant(skill_name, source_hash, user_id)
        except ValueError:
            return False
        return True

    def revoke(
        self,
        skill_name: str,
        source_hash: str,
        user_id: str | None = None,
    ) -> None:
        skill_name, source_hash = self._validate_key(skill_name, source_hash)
        if user_id is None:
            self._grants = {
                grant for grant in self._grants
                if grant[:2] != (skill_name, source_hash)
            }
        else:
            self._grants.discard((skill_name, source_hash, user_id))

    def clear(self) -> None:
        self._grants.clear()

    @staticmethod
    def _validate_key(skill_name: str, source_hash: str) -> tuple[str, str]:
        if not isinstance(skill_name, str) or not _SKILL_NAME_PATTERN.fullmatch(skill_name):
            raise ValueError("skill_name is invalid")
        if not isinstance(source_hash, str) or not _SHA256_PATTERN.fullmatch(source_hash):
            raise ValueError("source_hash must be a lowercase SHA-256 digest")
        return skill_name, source_hash