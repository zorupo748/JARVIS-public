"""External research coordinator.

This module provides :class:`ExternalResearchCoordinator` which implements the
:class:`~jarvis.core.external_source_research.ExternalSourceResearch` protocol.
It delegates to a static provider first and, if the result is insufficient,
to a fallback provider.
"""

from __future__ import annotations

# from typing import Any

from jarvis.core.external_source_research import (
    ExternalSourceResearch,
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
)

class ExternalResearchCoordinator(ExternalSourceResearch):
    """Delegate research to a static provider and, if needed, a fallback.

    Parameters
    ----------
    static_provider:
        A provider that performs reliable static research.
    fallback_provider:
        A provider that performs research using a browser when the static
        provider is insufficient.
    """

    def __init__(
        self,
        static_provider: ExternalSourceResearch,
        fallback_provider: ExternalSourceResearch,
    ) -> None:
        self._static_provider = static_provider
        self._fallback_provider = fallback_provider

    def research(
        self, request: ExternalSourceResearchRequest
    ) -> ExternalSourceResearchResult:
        # First attempt using the static provider.
        static_result: ExternalSourceResearchResult = self._static_provider.research(
            request
        )
        # If the static result is sufficient, return it unchanged.
        if static_result.sufficient:
            return static_result
        # Otherwise delegate to the fallback provider.
        fallback_result: ExternalSourceResearchResult = self._fallback_provider.research(
            request
        )
        return fallback_result
