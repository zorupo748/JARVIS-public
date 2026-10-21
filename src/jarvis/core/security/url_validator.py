"""URL Validation and Normalization Module for JARVIS.

This module provides strict, defensive URL validation, enforcement of secure protocols (HTTPS),
prevention of credential embedding/phishing attacks, and wildcard domain allowlisting.
"""

from typing import List, Optional, Set
import urllib.parse


class URLValidator:
    """Validates, sanitizes, and normalizes URLs against strict security policies.

    Enforces HTTPS schemes, prevents phishing via embedded userinfo (@), ensures hostnames
    are valid, and optionally filters against a configurable domain allowlist with wildcard
    subdomain matching.
    """

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        allow_http: bool = False,
    ) -> None:
        """Initialize the URL validator with an optional domain allowlist.

        Args:
            allowed_domains: Optional list of authorized domain patterns (e.g.,
                ["wikipedia.org", "*.github.com"]). Wildcard patterns beginning with
                "*." match both the parent domain and all subdomains. If None or empty,
                all domains are permitted provided they pass security constraints.
            allow_http: If True, permits http scheme in addition to https. Defaults to False.
        """
        self.allow_http: bool = allow_http
        self.allowed_domains: Optional[Set[str]] = None
        if allowed_domains is not None:
            cleaned_domains: Set[str] = set()
            for pattern in allowed_domains:
                if isinstance(pattern, str):
                    stripped = pattern.strip().lower()
                    if stripped:
                        cleaned_domains.add(stripped)
            self.allowed_domains = cleaned_domains

    def _is_domain_authorized(self, domain: str) -> bool:
        """Check if a normalized domain conforms to the configured allowlist.

        Args:
            domain: The normalized (lowercase, port-stripped) hostname to verify.

        Returns:
            True if the domain is authorized or if no allowlist is configured, False otherwise.
        """
        if self.allowed_domains is None:
            return True

        normalized_domain = domain.lower()

        for pattern in self.allowed_domains:
            if pattern.startswith("*."):
                base_domain = pattern[2:]
                # Matches either the base domain directly or any subordinate subdomain
                if normalized_domain == base_domain or normalized_domain.endswith("." + base_domain):
                    return True
            elif normalized_domain == pattern:
                return True

        return False

    def validate_and_normalize(
        self,
        raw_url: str,
        preserve_fragment: bool = False,
        allow_http: Optional[bool] = None,
    ) -> str:
        """Validate, sanitize, and canonicalize a raw URL string.

        Execution steps:
            1. Ensure raw_url is a non-empty, non-whitespace string.
            2. Parse components via urllib.parse.urlparse.
            3. Strictly enforce secure schemes (default: https only; http if permit_http is enabled).
            4. Extract and validate netloc and hostname (must not be empty).
            5. Detect and reject embedded user credentials or '@' characters.
            6. Enforce domain allowlist restrictions (if configured).
            7. Handle fragments (stripped by default, preserved if preserve_fragment=True for SPA routing).
            8. Reconstruct the clean URL.

        Args:
            raw_url: The unverified URL string input.
            preserve_fragment: If True, retains safe URL fragments (e.g. for SPA hash routing).
            allow_http: Optional override to permit http scheme. Defaults to self.allow_http.

        Returns:
            The normalized, sanitized URL string.

        Raises:
            ValueError: If the URL is empty, malformed, non-HTTPS (unless permit_http),
                lacks a valid host, or contains embedded credentials/characters like '@'.
            PermissionError: If the URL's domain is not authorized by the allowlist.
        """
        # Step 1: Validate non-empty string
        if not isinstance(raw_url, str):
            raise ValueError(f"Invalid URL type: expected str, received {type(raw_url).__name__}.")

        stripped_url = raw_url.strip()
        if not stripped_url:
            raise ValueError("URL cannot be empty or contain only whitespace.")

        # Step 2: Parse URL components
        try:
            parsed = urllib.parse.urlparse(stripped_url)
        except Exception as exc:
            raise ValueError(f"Failed to parse URL '{stripped_url}': {exc}") from exc

        # Step 3: Strictly enforce allowed scheme
        permit_http = self.allow_http if allow_http is None else allow_http
        valid_schemes = {"https", "http"} if permit_http else {"https"}
        scheme = parsed.scheme.lower()
        if scheme not in valid_schemes:
            raise ValueError(
                f"Insecure or invalid URL scheme '{parsed.scheme}'. Only 'https' is permitted."
            )

        # Step 4: Extract and validate netloc (domain / authority)
        raw_netloc = parsed.netloc.strip()
        if not raw_netloc:
            raise ValueError(f"URL '{stripped_url}' is missing a valid network authority (netloc).")

        # Step 5: Prevent embedded credentials or phishing (@ character in authority)
        if "@" in raw_netloc or parsed.username is not None or parsed.password is not None:
            raise ValueError(
                "Embedded user credentials or '@' character detected in URL authority. "
                "Possible phishing/credential injection attempt."
            )

        # Extract hostname and optional port
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"URL '{stripped_url}' contains an invalid or empty hostname.")

        normalized_host = hostname.lower()

        # Step 6: Verify domain against allowlist (if configured)
        if not self._is_domain_authorized(normalized_host):
            raise PermissionError(
                f"Access denied: domain '{normalized_host}' is not present in the allowed domains list."
            )

        # Step 7: Canonicalize and reconstruct URL
        default_port = 80 if scheme == "http" else 443
        if parsed.port and parsed.port != default_port:
            canonical_netloc = f"{normalized_host}:{parsed.port}"
        else:
            canonical_netloc = normalized_host

        # Ensure canonical path representation (default to '/' if path is empty)
        canonical_path = parsed.path if parsed.path else "/"

        # Retain fragment only if requested for safe SPA routing
        fragment_to_keep = ""
        if preserve_fragment and parsed.fragment:
            if "@" in parsed.fragment:
                raise ValueError("Embedded credentials in URL fragment are forbidden.")
            fragment_to_keep = parsed.fragment

        clean_url = urllib.parse.urlunparse((
            scheme,
            canonical_netloc,
            canonical_path,
            parsed.params,
            parsed.query,
            fragment_to_keep,
        ))

        return clean_url
