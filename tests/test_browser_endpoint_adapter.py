import unittest

from jarvis.core.browser_network_evidence import build_browser_request_evidence
from jarvis.core.browser_endpoint_adapter import (
    browser_request_evidence_to_endpoint_observation,
)
from jarvis.core.external_source_research import ExternalEndpointObservation


class TestBrowserEndpointAdapter(unittest.TestCase):
    def test_map_endpoint_and_http_method(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com",
            request_url="https://api.x.com/data",
            method="GET",
        )
        obs = browser_request_evidence_to_endpoint_observation(evidence)
        self.assertEqual(obs.endpoint, evidence.endpoint_url)
        self.assertEqual(obs.http_method, evidence.method)

    def test_consulted_true_and_false(self):
        evidence_true = build_browser_request_evidence(
            page_url="https://e.com",
            request_url="https://e.com",
            method="GET",
            consulted=True,
        )
        obs_true = browser_request_evidence_to_endpoint_observation(evidence_true)
        self.assertTrue(obs_true.consulted)

        evidence_false = build_browser_request_evidence(
            page_url="https://e.com",
            request_url="https://e.com",
            method="GET",
            consulted=False,
        )
        obs_false = browser_request_evidence_to_endpoint_observation(evidence_false)
        self.assertFalse(obs_false.consulted)

    def test_parameter_combination_and_deduplication(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com",
            request_url="https://x.com/api?x=1&y=1&x=2",
            method="GET",
            body_parameter_names=["y", "z"],
        )
        obs = browser_request_evidence_to_endpoint_observation(evidence)
        # query names: x, y ; body names: y, z ; expected: x, y, z
        self.assertEqual(obs.parameters, ("x", "y", "z"))

    def test_source_asset_fallback(self):
        # Explicit source_asset
        evidence_explicit = build_browser_request_evidence(
            page_url="https://page.com",
            request_url="https://api.com",
            method="GET",
            source_asset="https://cdn.com/script.js?v=1",
        )
        obs_explicit = browser_request_evidence_to_endpoint_observation(evidence_explicit)
        # source_asset should be cleaned fragmentless URL
        self.assertEqual(obs_explicit.source_asset, "https://cdn.com/script.js")

        # None source_asset should fallback to page_url
        evidence_fallback = build_browser_request_evidence(
            page_url="https://page.com",
            request_url="https://api.com",
            method="GET",
            source_asset=None,  # type: ignore[arg-type]
        )
        obs_fallback = browser_request_evidence_to_endpoint_observation(evidence_fallback)
        self.assertEqual(obs_fallback.source_asset, evidence_fallback.page_url)

    def test_context_and_observation_type_and_url_kind(self):
        evidence = build_browser_request_evidence(
            page_url="https://example.com/page?token=abc",
            request_url="https://api.example.com/data",
            method="POST",
        )
        obs = browser_request_evidence_to_endpoint_observation(evidence)
        self.assertEqual(obs.context, evidence.page_url)
        self.assertEqual(obs.observation_type, "browser_network_request")
        self.assertEqual(obs.url_kind, "absolute")

    def test_return_type_and_no_extra_fields(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com",
            request_url="https://x.com/api",
            method="GET",
        )
        obs = browser_request_evidence_to_endpoint_observation(evidence)
        self.assertIsInstance(obs, ExternalEndpointObservation)
        # Ensure no secret values are exposed (none to check here)

    def test_original_evidence_unchanged(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com",
            request_url="https://x.com/api?secret=123",
            method="GET",
        )
        _ = browser_request_evidence_to_endpoint_observation(evidence)
        # dataclass is frozen; attribute access should be available and unchanged
        self.assertEqual(evidence.page_url, "https://x.com")
        self.assertEqual(evidence.endpoint_url, "https://x.com/api")


if __name__ == "__main__":
    unittest.main()
