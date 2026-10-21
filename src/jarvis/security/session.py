"""Runtime security session for the active JARVIS interaction."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Iterable

from jarvis.identity.models import UserIdentity
from jarvis.identity.registry import UserRegistry

from .policy_core import IdentityContext, PresenceState, VerifiedFactor
from .verification import VerificationIssuer, VerificationResult


_OWNER_FACTORS = frozenset(
    {
        VerifiedFactor.OWNER_VOICE,
        VerifiedFactor.OWNER_DEVICE,
        VerifiedFactor.OWNER_SECRET,
        VerifiedFactor.OWNER_FACE,
    }
)


class SecuritySession:
    """
    Holds verified security facts for the current interaction.

    Claims do not grant identity. Only results from trusted verifier
    capabilities may establish identity or verified factors.
    """

    def __init__(
        self,
        *,
        registry: UserRegistry | None = None,
        trusted_issuers: Iterable[VerificationIssuer] = (),
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry or UserRegistry()
        self._trusted_issuers = {
            issuer.issuer_id: issuer
            for issuer in trusted_issuers
        }
        self._now = now or (lambda: datetime.now(timezone.utc))

        self._claimed_user_id: str | None = None
        self._presence = PresenceState.UNKNOWN
        self._identity: UserIdentity | None = None
        self._verified_factors: set[VerifiedFactor] = set()
        self._consumed_verification_ids: set[str] = set()

    @property
    def claimed_user_id(self) -> str | None:
        return self._claimed_user_id

    @property
    def presence(self) -> PresenceState:
        return self._presence

    def begin_interaction(self, claimed_user_id: str | None = None) -> None:
        """
        Start a fresh interactive request.

        Verification does not leak automatically from the previous
        interaction.
        """

        self._presence = PresenceState.PRESENT
        self._identity = None
        self._verified_factors.clear()

        if claimed_user_id is None:
            self._claimed_user_id = None
            return

        normalized = claimed_user_id.strip()
        self._claimed_user_id = normalized or None

    def apply_verification(self, result: VerificationResult) -> bool:
        """Accept a fresh, one-use assertion from a trusted verifier."""

        if result.verification_id in self._consumed_verification_ids:
            return False

        issuer = self._trusted_issuers.get(result.issuer_id)
        if issuer is None:
            return False

        if not issuer.validates(result, now=self._now()):
            return False

        user = self._registry.get(result.user_id)
        if user is None:
            return False

        if self._claimed_user_id is not None and self._claimed_user_id != user.user_id:
            return False

        if result.factor in _OWNER_FACTORS and not user.is_owner:
            return False

        if self._identity is not None and self._identity.user_id != user.user_id:
            return False

        self._identity = user
        self._verified_factors.add(result.factor)
        self._consumed_verification_ids.add(result.verification_id)
        return True

    def context(self) -> IdentityContext:
        return IdentityContext(
            identity=self._identity,
            presence=self._presence,
            verified_factors=frozenset(self._verified_factors),
            claimed_user_id=self._claimed_user_id,
        )

    def clear(self) -> None:
        self._claimed_user_id = None
        self._presence = PresenceState.UNKNOWN
        self._identity = None
        self._verified_factors.clear()


__all__ = ["SecuritySession"]
