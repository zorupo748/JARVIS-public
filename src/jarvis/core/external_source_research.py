"""Injectable, data-only source research contract for skill authoring."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ExternalSourceResearchRequest:
    user_request: str
    source: str
    capability: str


@dataclass(frozen=True)
class ExternalEndpointObservation:
    endpoint: str
    source_asset: str
    context: str
    observation_type: str
    url_kind: str
    http_method: str = ""
    parameters: tuple[str, ...] = ()
    consulted: bool = False


@dataclass(frozen=True)
class ExternalSourceResearchResult:
    source: str
    access_method: str
    observed_endpoints: tuple[str, ...] = ()
    response_format: str = ""
    required_parameters: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    confidence: float = 0.0
    research_status: str = "sufficient"
    final_url: str = ""
    http_status: int | None = None
    content_type: str = ""
    page_kind: str = "unknown"
    evidence: tuple[str, ...] = ()
    observed_assets: tuple[str, ...] = ()
    endpoint_observations: tuple[ExternalEndpointObservation, ...] = ()
    dynamic_interaction_evidence: Mapping[str, object] | None = None

    @property
    def sufficient(self) -> bool:
        return (
            self.research_status == "sufficient"
            and bool(self.source.strip())
            and bool(self.access_method.strip())
            and bool(self.response_format.strip())
            and 0.0 <= self.confidence <= 1.0
            and self.confidence >= 0.65
        )

    @property
    def direct_page_fetch_verified(self) -> bool:
        return (
            bool(self.final_url)
            and self.http_status is not None
            and 200 <= self.http_status < 300
            and bool(re.search(r"\bhtml\b", self.response_format, re.IGNORECASE))
            and bool(re.search(r"\b(?:http\s*)?get\b", self.access_method, re.IGNORECASE))
        )

    def to_prompt_context(self) -> str:
        return json.dumps(
            {
                "source": self.source,
                "access_method": self.access_method,
                "observed_endpoints": list(self.observed_endpoints),
                "response_format": self.response_format,
                "required_parameters": list(self.required_parameters),
                "notes": list(self.notes),
                "confidence": self.confidence,
                "research_status": self.research_status,
                "final_url": self.final_url,
                "http_status": self.http_status,
                "content_type": self.content_type,
                "page_kind": self.page_kind,
                "evidence": list(self.evidence),
                "observed_assets": list(self.observed_assets),
                "endpoint_observations": [
                    {
                        "endpoint": item.endpoint,
                        "source_asset": item.source_asset,
                        "context": item.context,
                        "observation_type": item.observation_type,
                        "url_kind": item.url_kind,
                        "http_method": item.http_method,
                        "parameters": list(item.parameters),
                        "consulted": item.consulted,
                    }
                    for item in self.endpoint_observations
                ],
                "dynamic_interaction_evidence": (
                    dict(self.dynamic_interaction_evidence)
                    if self.dynamic_interaction_evidence is not None
                    else None
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        )


class ExternalSourceResearch(Protocol):
    """Optional trusted provider; returned facts are data, never executable code."""

    def research(
        self, request: ExternalSourceResearchRequest
    ) -> object: ...


_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def requested_external_source(user_request: str) -> str:
    """Return an explicitly supplied URL or a conservative source name."""

    match = _URL_PATTERN.search(user_request)
    if match is not None:
        return match.group(0).rstrip(".,;)")
    named = re.search(
        r"\b(?:consulta(?:r|s|n)?|consult(?:a|as|an|ar|e|es|en)?|"
        r"check|mira|busca(?:r|s|n)?)\s+(?:en\s+)?"
        r"([A-Za-z0-9][A-Za-z0-9_.-]{1,80})",
        user_request,
        re.IGNORECASE,
    )
    if named is not None and named.group(1).casefold() not in {
        "una", "un", "la", "el", "web", "pagina", "sitio", "site", "website",
    }:
        return named.group(1)
    named = re.search(
        r"\b(?:de|del|from|on|in)\s+([A-Za-z0-9][A-Za-z0-9_.-]{1,80})",
        user_request,
        re.IGNORECASE,
    )
    return named.group(1) if named is not None else "unspecified external source"


def research_source_matches(requested_source: str, researched_source: str) -> bool:
    """Ensure returned research belongs to the source explicitly named by the user."""

    requested = requested_source.strip().casefold()
    if requested == "unspecified external source":
        return True
    researched = urlsplit(researched_source.strip())
    if not researched.hostname:
        return False
    if requested.startswith(("http://", "https://")):
        expected_host = urlsplit(requested).hostname
        return expected_host is not None and researched.hostname.casefold() == expected_host.casefold()
    compact_name = re.sub(r"[^a-z0-9]", "", requested)
    compact_host = re.sub(r"[^a-z0-9]", "", researched.hostname.casefold())
    return bool(compact_name and compact_name in compact_host)


def validate_research_result(
    result: object,
) -> ExternalSourceResearchResult:
    if not isinstance(result, ExternalSourceResearchResult):
        raise TypeError("research must return ExternalSourceResearchResult")
    text_fields = (
        result.source,
        result.access_method,
        result.response_format,
        *result.observed_endpoints,
        *result.required_parameters,
        *result.notes,
    )
    if any(not isinstance(value, str) for value in text_fields):
        raise TypeError("research facts must contain only strings")
    if (
        not isinstance(result.confidence, (int, float))
        or isinstance(result.confidence, bool)
    ):
        raise TypeError("research confidence must be numeric")
    if result.research_status not in {"sufficient", "insufficient_research"}:
        raise ValueError("research_status must be sufficient or insufficient_research")
    if result.http_status is not None and (
        not isinstance(result.http_status, int) or isinstance(result.http_status, bool)
    ):
        raise TypeError("HTTP status must be an integer or None")
    for value in (result.source, result.final_url, *result.observed_assets):
        if value and not urlsplit(value).scheme.lower() in {"http", "https"}:
            raise ValueError("Research URLs must use HTTP(S)")
    for observation in result.endpoint_observations:
        if (
            not isinstance(observation, ExternalEndpointObservation)
            or not isinstance(observation.consulted, bool)
            or observation.url_kind not in {"absolute", "relative"}
            or not isinstance(observation.parameters, tuple)
            or not all(isinstance(value, str) for value in observation.parameters)
            or not all(
                isinstance(value, str)
                for value in (
                    observation.endpoint,
                    observation.source_asset,
                    observation.context,
                    observation.observation_type,
                    observation.http_method,
                )
            )
            or urlsplit(observation.endpoint).scheme.lower() not in {"http", "https"}
        ):
            raise ValueError("Endpoint observations must contain bounded HTTP(S) facts")
    if result.dynamic_interaction_evidence is not None and not isinstance(
        result.dynamic_interaction_evidence, Mapping
    ):
        raise TypeError("dynamic_interaction_evidence must be a mapping or None")
    return result
