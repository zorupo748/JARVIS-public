"""Immutable structural references for observed browser operation attribution.

Trusted infrastructure must supply non-secret local IDs and retain provenance
in its registry. Construction validates shape alone, without establishing
authorization, causality, functional success or research sufficiency.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["BrowserCapabilityAttributionEvidence"]

_ATTRIBUTION_BASES = frozenset({
    "INITIAL_NAVIGATION",
    "CONTROLLED_NAVIGATION",
    "CONTROLLED_SUBMISSION",
    "OBSERVED_OPERATION_DISPATCH",
})
_MAX_ID_LENGTH = 128
_MAX_EXCHANGE_PATH_LENGTH = 64


def _normalize_id(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a non-empty local identifier")
    normalized = str.strip(value)
    if not normalized:
        raise ValueError(f"{field_name} must be a non-empty local identifier")
    if len(normalized) > _MAX_ID_LENGTH:
        raise ValueError(f"{field_name} must be <= 128 characters")
    return normalized


@dataclass(frozen=True, slots=True)
class BrowserCapabilityAttributionEvidence:
    """An observed association between an operation and a concrete exchange path.

    INITIAL_NAVIGATION identifies the initial controlled navigation exchange.
    CONTROLLED_NAVIGATION links an authorized navigation to its exchange.
    CONTROLLED_SUBMISSION links an authorized native submission to the request
    produced by the browser lifecycle. OBSERVED_OPERATION_DISPATCH explicitly
    links an approved operation's dispatch to its exchange.

    Those meanings describe infrastructure observations, not guarantees made
    by this record. Session, interaction, contract and exchange existence,
    interaction kind compatibility, path order, redirect links, sequences,
    completeness and phase membership belong to a future evaluator. No URL
    correlation or temporal inference is performed. Multiple exchanges remain
    representable; V1 sufficiency restrictions belong to that evaluator too.
    """

    session_id: str
    exchange_path: tuple[str, ...]
    interaction_id: str | None
    operation_contract_id: str
    attribution_basis: str

    def __post_init__(self) -> None:
        session_id = _normalize_id(self.session_id, "session_id")
        contract_id = _normalize_id(self.operation_contract_id, "operation_contract_id")
        interaction_id = (
            None if self.interaction_id is None
            else _normalize_id(self.interaction_id, "interaction_id")
        )
        if type(self.exchange_path) is not tuple:
            raise ValueError("exchange_path must be exactly tuple")
        if not 1 <= len(self.exchange_path) <= _MAX_EXCHANGE_PATH_LENGTH:
            raise ValueError("exchange_path must contain 1..64 exchanges")
        path: list[str] = []
        seen: set[str] = set()
        for exchange_id in self.exchange_path:
            if type(exchange_id) is not str:
                raise ValueError("exchange_path members must be exactly str")
            normalized = _normalize_id(exchange_id, "exchange_path member")
            if normalized in seen:
                raise ValueError("exchange_path IDs must be unique after stripping")
            seen.add(normalized)
            path.append(normalized)

        message = "attribution_basis must be one of: " + ", ".join(sorted(_ATTRIBUTION_BASES))
        if not isinstance(self.attribution_basis, str):
            raise ValueError(message)
        basis = str.__str__(self.attribution_basis)
        if basis not in _ATTRIBUTION_BASES:
            raise ValueError(message)
        if basis == "INITIAL_NAVIGATION":
            if interaction_id is not None:
                raise ValueError("INITIAL_NAVIGATION requires interaction_id=None")
        elif interaction_id is None:
            raise ValueError(f"{basis} requires interaction_id")

        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "exchange_path", tuple(path))
        object.__setattr__(self, "interaction_id", interaction_id)
        object.__setattr__(self, "operation_contract_id", contract_id)
        object.__setattr__(self, "attribution_basis", basis)
