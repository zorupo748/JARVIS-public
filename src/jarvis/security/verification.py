"""Trusted verification results consumed by the runtime security session."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable
from uuid import uuid4

from .policy_core import VerifiedFactor


DEFAULT_VERIFICATION_TTL = timedelta(seconds=60)


@dataclass(frozen=True)
class VerificationResult:
    """One short-lived assertion emitted by a trusted verifier."""

    verification_id: str
    issuer_id: str
    user_id: str
    factor: VerifiedFactor
    issued_at: datetime
    _capability: object = field(repr=False, compare=False)


class VerificationIssuer:
    """
    Capability held by one trusted verifier.

    Creating a VerificationResult manually is insufficient: the result
    must contain this issuer's private capability object.
    """

    def __init__(
        self,
        issuer_id: str,
        allowed_factors: Iterable[VerifiedFactor],
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        normalized = issuer_id.strip()
        if not normalized:
            raise ValueError("issuer_id no puede estar vacío.")

        factors = frozenset(allowed_factors)
        if not factors:
            raise ValueError("El verificador debe permitir al menos un factor.")

        self.issuer_id = normalized
        self.allowed_factors = factors
        self._capability = object()
        self._now = now or (lambda: datetime.now(timezone.utc))

    def issue(self, user_id: str, factor: VerifiedFactor) -> VerificationResult:
        if factor not in self.allowed_factors:
            raise ValueError(
                f"El verificador '{self.issuer_id}' no puede emitir {factor.value}."
            )

        normalized_user = user_id.strip()
        if not normalized_user:
            raise ValueError("user_id no puede estar vacío.")

        return VerificationResult(
            verification_id=str(uuid4()),
            issuer_id=self.issuer_id,
            user_id=normalized_user,
            factor=factor,
            issued_at=self._now(),
            _capability=self._capability,
        )

    def validates(
        self,
        result: VerificationResult,
        *,
        now: datetime,
        ttl: timedelta = DEFAULT_VERIFICATION_TTL,
    ) -> bool:
        if result.issuer_id != self.issuer_id:
            return False

        if result._capability is not self._capability:
            return False

        if result.factor not in self.allowed_factors:
            return False

        issued = _as_utc(result.issued_at)
        current = _as_utc(now)
        age = current - issued

        return timedelta(0) <= age <= ttl


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


__all__ = [
    "DEFAULT_VERIFICATION_TTL",
    "VerificationIssuer",
    "VerificationResult",
]
