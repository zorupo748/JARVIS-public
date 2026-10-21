"""Secure Search Skill for JARVIS.

Provides safe, sandboxed information retrieval from approved knowledge repositories
(such as Wikipedia) utilizing SecureWebSession and strict domain allowlisting.
"""

import logging
import re
from typing import Any, List, Optional
import urllib.parse
from bs4 import BeautifulSoup

from jarvis.core.security.secure_browser import SecureWebSession

logger = logging.getLogger(__name__)


class SecureSearchSkill:
    """Skill for executing sandboxed queries against authorized knowledge bases.

    Enforces HTTPS protocol, domain allowlisting (defaulting to *.wikipedia.org),
    resource-level network filtering, and DOM content extraction of primary article
    summaries while stripping sidebars, navigation menus, and metadata tables.
    """

    DEFAULT_ALLOWED_DOMAINS: List[str] = ["*.wikipedia.org", "wikipedia.org"]

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        timeout_ms: int = 15000,
        lang: str = "en",
    ) -> None:
        """Initialize the SecureSearchSkill.

        Args:
            allowed_domains: Optional list of permitted domain patterns. Defaults to
                ["*.wikipedia.org", "wikipedia.org"].
            timeout_ms: Maximum navigation timeout in milliseconds (default: 15000).
            lang: Language subcode for default Wikipedia URL formatting (e.g., "en", "es").
        """
        self.allowed_domains: List[str] = (
            list(allowed_domains) if allowed_domains is not None else list(self.DEFAULT_ALLOWED_DOMAINS)
        )
        self.timeout_ms: int = timeout_ms
        self.lang: str = lang.strip().lower() if lang else "en"
        self.session: SecureWebSession = SecureWebSession(
            allowed_domains=self.allowed_domains,
            timeout_ms=self.timeout_ms,
        )

    def _build_wikipedia_url(self, topic: str, use_search_route: bool = False) -> str:
        """Construct a normalized, canonical Wikipedia article or search URL.

        Handles standard MediaWiki title normalization (capitalizing the initial character,
        normalizing spaces to underscores) and supports the Special:Search route.

        Args:
            topic: The topic phrase, article title, or search query.
            use_search_route: If True, produces a Special:Search query URL instead of a direct title URL.

        Returns:
            The canonical Wikipedia HTTPS URL.
        """
        clean_topic = topic.strip()
        if not clean_topic:
            return f"https://{self.lang}.wikipedia.org"

        # Check if Special:Search route is requested or query explicitly indicates search
        lower_topic = clean_topic.lower()
        if use_search_route or lower_topic.startswith("special:search"):
            if lower_topic.startswith("special:search?search="):
                query_val = clean_topic.split("=", 1)[1]
            elif lower_topic.startswith("special:search"):
                query_val = clean_topic[len("special:search"):].lstrip("/:? ")
            else:
                query_val = clean_topic
            encoded_query = urllib.parse.quote_plus(query_val)
            return f"https://{self.lang}.wikipedia.org/wiki/Special:Search?search={encoded_query}"

        # Standard Wikipedia article title formatting:
        # 1. Normalize multiple spaces into single space.
        # 2. Capitalize initial letter (standard MediaWiki title convention).
        # 3. Replace spaces with underscores.
        # 4. Safely URL-quote characters while preserving standard title symbols.
        words = clean_topic.split()
        normalized = " ".join(words)
        capitalized = normalized[0].upper() + normalized[1:] if normalized else ""
        encoded_topic = urllib.parse.quote(capitalized.replace(" ", "_"), safe="/()")
        return f"https://{self.lang}.wikipedia.org/wiki/{encoded_topic}"

    def _extract_summary(self, html_content: str, topic_name: str) -> str:
        """Extract sanitized summary text from raw Wikipedia DOM content.

        Strips non-content elements including navigation menus, infobox tables,
        reference superscripts, hatnotes, and edit section buttons.

        Args:
            html_content: Rendered HTML DOM string.
            topic_name: The queried topic name for reporting fallback messages.

        Returns:
            Sanitized text summary paragraphs joined by newlines.
        """
        if not html_content or not html_content.strip():
            return f"No content available for topic '{topic_name}'."

        soup = BeautifulSoup(html_content, "html.parser")

        # Locate Wikipedia's main content body container.
        # In modern MediaWiki HTML, top-level indicators (e.g., mw-indicator-pp-default)
        # contain an empty div.mw-parser-output before the actual content. We prioritize #mw-content-text
        # and search for the inner parser output container that contains substantive paragraphs.
        content_container = None
        mw_content = soup.find(id="mw-content-text")
        if mw_content:
            for po in mw_content.find_all("div", class_="mw-parser-output"):
                if po.find("p"):
                    content_container = po
                    break
            if not content_container:
                content_container = mw_content
        else:
            for po in soup.find_all("div", class_="mw-parser-output"):
                if po.find("p"):
                    content_container = po
                    break
            if not content_container:
                content_container = soup.find("main") or soup.find("article") or soup.body

        if not content_container:
            return f"No readable content found for topic '{topic_name}'."

        # Decompose non-content or interactive HTML tags
        unwanted_tags = [
            "table", "nav", "style", "script", "figure", "sup", "noscript", "aside", "form"
        ]
        for tag in content_container.find_all(unwanted_tags):
            tag.decompose()

        # Decompose Wikipedia specific UI chrome classes
        unwanted_classes = [
            "mw-editsection",
            "hatnote",
            "shortdescription",
            "toc",
            "navbox",
            "reflist",
            "reference",
            "infobox",
            "ambox",
            "metadata",
            "mw-indicator",
            "mw-empty-elt",
        ]
        for element in content_container.find_all(class_=unwanted_classes):
            element.decompose()

        # Extract substantive paragraphs (discarding empty or trivial tags)
        extracted_paragraphs: List[str] = []
        for paragraph in content_container.find_all("p"):
            text = paragraph.get_text(separator=" ", strip=True)
            text = re.sub(r"\s+", " ", text)
            text = re.sub(r"\s+([,.:;?!])", r"\1", text)
            text = re.sub(r"\(\s+", "(", text)
            text = re.sub(r"\s+\)", ")", text)
            if len(text) >= 35:
                extracted_paragraphs.append(text)
            if len(extracted_paragraphs) >= 4:
                break

        if extracted_paragraphs:
            return "\n\n".join(extracted_paragraphs)

        # Fallback 1: check if landing page is a search result page (e.g., Special:Search)
        search_snippets: List[str] = []
        for result_item in content_container.find_all(class_=["searchresult", "mw-search-result-snippet"]):
            snippet_text = result_item.get_text(separator=" ", strip=True)
            snippet_text = re.sub(r"\s+", " ", snippet_text)
            snippet_text = re.sub(r"\s+([,.:;?!])", r"\1", snippet_text)
            if len(snippet_text) >= 20:
                parent_li = result_item.find_parent("li")
                heading = parent_li.find(class_="mw-search-result-heading") if parent_li else None
                title_prefix = f"[{heading.get_text(strip=True)}]: " if heading else ""
                search_snippets.append(f"{title_prefix}{snippet_text}")
            if len(search_snippets) >= 4:
                break

        if search_snippets:
            return "\n\n".join(search_snippets)

        # Fallback 2: gather clean text lines if paragraph tags were non-standard
        fallback_text = content_container.get_text(separator="\n", strip=True)
        if fallback_text:
            substantive_lines = [
                line.strip() for line in fallback_text.splitlines() if len(line.strip()) >= 35
            ]
            if substantive_lines:
                return "\n\n".join(substantive_lines[:4])

        return f"No summary paragraphs found for topic '{topic_name}'."

    async def search_topic(
        self,
        topic_query: str,
        custom_url: Optional[str] = None,
        use_search_route: bool = False,
    ) -> str:
        """Search and extract summary text for a given topic securely.

        Args:
            topic_query: Topic or query term (e.g., 'Artificial intelligence').
                If topic_query is an absolute URL starting with 'https://', it will be accessed directly.
            custom_url: Optional explicit target URL overriding default Wikipedia URL synthesis.
            use_search_route: If True, uses Wikipedia's Special:Search route.

        Returns:
            Extracted text summary composed of the primary article paragraphs.

        Raises:
            ValueError: If topic_query is empty, malformed, or fails URL structure validation.
            PermissionError: If the destination domain is unauthorized by the allowlist.
            TimeoutError: If the browser navigation exceeds the configured timeout threshold.
            RuntimeError: If a network, browser lifecycle, or page retrieval failure occurs.
        """
        if not isinstance(topic_query, str) or not topic_query.strip():
            raise ValueError("topic_query must be a non-empty string.")

        clean_topic = topic_query.strip()

        # Determine target URL destination
        if custom_url is not None:
            target_url = custom_url.strip()
        elif clean_topic.lower().startswith("https://"):
            target_url = clean_topic
        else:
            target_url = self._build_wikipedia_url(clean_topic, use_search_route=use_search_route)

        logger.info("Executing secure search for '%s' via '%s'", clean_topic, target_url)

        try:
            dom_html = await self.session.fetch_dom(target_url)
        except PermissionError as exc:
            logger.error("Secure search rejected unauthorized domain '%s': %s", target_url, exc)
            raise PermissionError(
                f"Unauthorized domain: search request to '{target_url}' was denied by security policy."
            ) from exc
        except TimeoutError as exc:
            logger.error("Secure search timed out retrieving '%s': %s", target_url, exc)
            raise TimeoutError(
                f"Secure search timeout: could not retrieve '{target_url}' within {self.timeout_ms} ms."
            ) from exc
        except RuntimeError as exc:
            logger.error("Secure search failed with runtime error for '%s': %s", target_url, exc)
            raise RuntimeError(
                f"Secure search browser or network error while accessing '{target_url}': {exc}"
            ) from exc
        except Exception as exc:
            logger.error("Unexpected error during secure search for '%s': %s", target_url, exc)
            raise RuntimeError(f"Unexpected search failure for '{target_url}': {exc}") from exc

        return self._extract_summary(dom_html, clean_topic)


def secure_search_adapter(query: str, lang: str = "es") -> str:
    """Synchronous adapter function for direct invocation by SkillManager or LLM orchestrators.

    Args:
        query: Search term or topic.
        lang: Wikipedia language code (default: 'es').

    Returns:
        Clean, formatted text summary ready for LLM consumption.
    """
    from jarvis.tools.web.secure_search import SecureSearchTool

    tool = SecureSearchTool(default_lang=lang)
    result = tool.execute(query=query, lang=lang)
    return result.content


def register_secure_search_skill(skill_manager: Any) -> None:
    """Register the secure search capability into a SkillManager instance.

    Args:
        skill_manager: An instance of jarvis.skills.base.SkillManager.
    """
    skill_manager.register_skill(
        name="buscar_en_internet_seguro",
        description="Consulta enciclopédica segura en Wikipedia en entorno aislado sin rastreo.",
        func=secure_search_adapter,
    )
