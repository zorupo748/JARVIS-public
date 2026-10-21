from __future__ import annotations

import json
from pathlib import Path

from jarvis.security.levels import SecurityLevel

from .models import UserIdentity


class UserRegistry:
    """
    Persistent registry of JARVIS users.

    Unknown people are never automatically registered as privileged
    users. New users always start at Level 0.
    """

    def __init__(self, path: str | Path = "data/users.json"):
        self.path = Path(path)
        self.users: dict[str, UserIdentity] = {}

        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return

        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        for raw in data:
            try:
                user = UserIdentity(
                    user_id=raw["user_id"],
                    display_name=raw["display_name"],
                    security_level=SecurityLevel(
                        raw.get("security_level", 0)
                    ),
                    is_owner=raw.get("is_owner", False),
                    voice_profile_id=raw.get("voice_profile_id"),
                    created_at=raw.get("created_at"),
                )

                self.users[user.user_id] = user

            except (KeyError, ValueError, TypeError):
                continue

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

        data = [
            {
                "user_id": user.user_id,
                "display_name": user.display_name,
                "security_level": int(user.security_level),
                "is_owner": user.is_owner,
                "voice_profile_id": user.voice_profile_id,
                "created_at": user.created_at,
            }
            for user in self.users.values()
        ]

        self.path.write_text(
            json.dumps(data, indent=4, ensure_ascii=False),
            encoding="utf-8",
        )

    def get(self, user_id: str) -> UserIdentity | None:
        return self.users.get(user_id)

    def add(self, user: UserIdentity) -> None:
        if user.user_id in self.users:
            raise ValueError(
                f"User already exists: {user.user_id}"
            )

        self.users[user.user_id] = user
        self.save()

    def remove(self, user_id: str) -> None:
        if user_id in self.users:
            del self.users[user_id]
            self.save()

    def all(self) -> list[UserIdentity]:
        return list(self.users.values())