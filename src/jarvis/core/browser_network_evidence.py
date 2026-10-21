"""Evidence of browser network requests.

This module defines a tiny immutable dataclass used to store a *structural* snapshot of an HTTP request observed by a monitored browser.

All values are sanitized to avoid accidental leakage of secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

_ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
}

_MAX_NAME_LENGTH = 64
_MAX_TOTAL_NAMES = 64


def _is_absolute_http(url: str) -> bool:
    """Return True if url is absolute, http/https scheme and no userinfo"""
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return bool(parsed.netloc)




def _extract_query_names(query: str) -> Tuple[str, ...]:
    """Return tuple of unique, stripped query parameter names preserving order."""
    if not query:
        return ()
    names: list[str] = []
    seen = set()
    for part in query.split("&"):
        if not part:
            continue
        name = part.split("=", 1)[0].strip()
        if not name:
            raise ValueError("Query parameter name cannot be empty")
        if len(name) > _MAX_NAME_LENGTH:
            raise ValueError("Query parameter names must be <= 64 chars")
        if name not in seen:
            seen.add(name)
            names.append(name)
            if len(names) > _MAX_TOTAL_NAMES:
                raise ValueError("Too many query parameters (max 64)")
    return tuple(names)


def _validate_name_list(
    names: Optional[Tuple[str, ...] | list[str] | None], max_total: int = _MAX_TOTAL_NAMES
) -> Tuple[str, ...]:
    """Normalise a collection of names.

    Accepts a tuple, list, or None.  Returns a deduplicated tuple preserving order.
    Raises ValueError for invalid entries.
    """
    if names is None:
        return ()
    cleaned: list[str] = []
    seen = set()
    for name in names:
        if not isinstance(name, str):
            raise ValueError(f"Parameter name must be a string, got {type(name)}")
        name_str = name.strip()
        if not name_str:
            raise ValueError("Parameter name cannot be empty")
        if len(name_str) > _MAX_NAME_LENGTH:
            raise ValueError("Parameter names must be <= 64 chars")
        if name_str not in seen:
            seen.add(name_str)
            cleaned.append(name_str)
            if len(cleaned) > max_total:
                raise ValueError("Too many parameters (max 64)")
    return tuple(cleaned)


@dataclass(frozen=True)
class BrowserRequestEvidence:
    page_url: str
    endpoint_url: str
    method: str
    query_parameter_names: Tuple[str, ...]
    body_parameter_names: Tuple[str, ...]
    source_asset: Optional[str]
    consulted: bool

    def to_mapping(self) -> dict:
        """Return a JSON-serialisable representation with safe fields.

        Includes query_parameter_names but does NOT expose query values.
        """
        return {
            "page_url": self.page_url,
            "endpoint_url": self.endpoint_url,
            "method": self.method,
            "query_parameter_names": list(self.query_parameter_names),
            "body_parameter_names": list(self.body_parameter_names),
            "source_asset": self.source_asset,
            "consulted": self.consulted,
        }


def build_browser_request_evidence(
    *,
    page_url: str,
    request_url: str,
    method: str,
    body_parameter_names: Optional[list[str] | tuple[str, ...]] = None,
    source_asset: Optional[str] = None,
    consulted: bool = False,
) -> BrowserRequestEvidence:
    """Construct a BrowserRequestEvidence from raw inputs.

    Validation rules are documented in the module docstring for each parameter.
    """
    # Validate URLs
    if not _is_absolute_http(page_url):
        raise ValueError("page_url must be an absolute http/https URL without credentials")
    if not _is_absolute_http(request_url):
        raise ValueError("request_url must be an absolute http/https URL without credentials")

    # Normalize page_url: drop query and fragment
    parsed_p = urlsplit(page_url)
    page_url_norm = urlunsplit((parsed_p.scheme, parsed_p.netloc, parsed_p.path, "", ""))
    clean_method = method.strip().upper()
    if clean_method not in _ALLOWED_METHODS:
        raise ValueError(f"Unsupported HTTP method: {method}")

    # Parse request_url: keep scheme, netloc, path; drop query and fragment
    parsed = urlsplit(request_url)
    endpoint_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))

    # Extract query parameter names from request_url
    query_names = _extract_query_names(parsed.query)

    # Validate body parameter names
    body_names = _validate_name_list(body_parameter_names)

    # Validate source_asset if provided
    src = None
    if source_asset is not None:
        if not _is_absolute_http(source_asset):
            raise ValueError("source_asset must be an absolute http/https URL without credentials")
        # remove fragment and query
        src_parsed = urlsplit(source_asset)
        src = urlunsplit((src_parsed.scheme, src_parsed.netloc, src_parsed.path, "", ""))



    # Ensure consulted is bool
    if not isinstance(consulted, bool):
        raise ValueError("consulted must be a bool")
    consulted_bool = consulted



    return BrowserRequestEvidence(
        page_url=page_url_norm,
        endpoint_url=endpoint_url,
        method=clean_method,
        query_parameter_names=query_names,
        body_parameter_names=body_names,
        source_asset=src,
        consulted=consulted_bool,
    )
