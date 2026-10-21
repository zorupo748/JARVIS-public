import unittest

from jarvis.core.browser_network_evidence import build_browser_request_evidence, BrowserRequestEvidence

class TestBrowserNetworkEvidence(unittest.TestCase):
    # Body parameters tests
    def test_body_params_unique(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com", request_url="https://x.com/api?x=1&y=2", method="GET", body_parameter_names=["a", "b"]
        )
        self.assertEqual(evidence.body_parameter_names, ("a", "b"))

    def test_body_params_duplicates_removed(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com", request_url="https://x.com/api?x=1&y=2", method="GET", body_parameter_names=["a", "b", "a"]
        )
        self.assertEqual(evidence.body_parameter_names, ("a", "b"))

    def test_body_params_non_str_rejected(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://p.com",
                request_url="https://p.com/api",
                method="POST",
                body_parameter_names=["a", 123, "b"]  # type: ignore
            )

    # Consulted tests
    def test_consulted_true(self):
        evidence = build_browser_request_evidence(
            page_url="https://e.com", request_url="https://e.com", method="GET", consulted=True
        )
        self.assertTrue(evidence.consulted)

    def test_consulted_false(self):
        evidence = build_browser_request_evidence(
            page_url="https://e.com", request_url="https://e.com", method="GET", consulted=False
        )
        self.assertFalse(evidence.consulted)

    def test_consulted_default(self):
        evidence = build_browser_request_evidence(
            page_url="https://e.com", request_url="https://e.com", method="GET"
        )
        self.assertFalse(evidence.consulted)

    def test_consulted_none(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://e.com", request_url="https://e.com", method="GET",             consulted=None  # type: ignore

            )

    def test_consulted_numeric(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://e.com", request_url="https://e.com", method="GET",             consulted=0  # type: ignore

            )
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://e.com", request_url="https://e.com", method="GET",             consulted=1  # type: ignore

            )

    def test_consulted_string(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://e.com", request_url="https://e.com", method="GET",             consulted="true"  # type: ignore

            )
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://e.com", request_url="https://e.com", method="GET",             consulted="false"  # type: ignore

            )

    def test_get_simple(self):
        evidence = build_browser_request_evidence(
            page_url="https://example.com/home", request_url="https://api.example.com/data", method="GET"
        )
        self.assertEqual(evidence.page_url, "https://example.com/home")
        self.assertEqual(evidence.endpoint_url, "https://api.example.com/data")
        self.assertEqual(evidence.query_parameter_names, ())

    def test_method_normalisation(self):
        evidence = build_browser_request_evidence(
            page_url="https://example.com", request_url="https://api.example.com", method="   post   "
        )
        self.assertEqual(evidence.method, "POST")

    def test_extract_query_names(self):
        evidence = build_browser_request_evidence(
            page_url="https://e.com", request_url="https://e.com/api?code=SECRET&lang=es", method="GET"
        )
        self.assertEqual(evidence.query_parameter_names, ("code", "lang"))

    def test_eliminate_values_and_fragment(self):
        evidence = build_browser_request_evidence(
            page_url="https://a.com", request_url="https://a.com/test?foo=1&bar=2#section", method="GET"
        )
        self.assertEqual(evidence.endpoint_url, "https://a.com/test")
        self.assertEqual(evidence.query_parameter_names, ("foo", "bar"))

    def test_repeated_query(self):
        evidence = build_browser_request_evidence(
            page_url="https://x.com", request_url="https://x.com/api?x=1&x=2&y=3", method="GET"
        )
        self.assertEqual(evidence.query_parameter_names, ("x", "y"))

    def test_rejected_relative_url(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="/home", request_url="https://e.com", method="GET")

    def test_rejected_file_scheme(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="file://c:/data", request_url="https://e.com", method="GET")

    def test_rejected_credentials(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://user:pass@example.com", request_url="https://e.com", method="GET")

    def test_rejected_invalid_method(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com", method="CONNECT")

    def test_empty_param_name(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com?=1", method="GET")

    def test_long_param_name(self):
        long_name = "a" * 65
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://e.com", request_url=f"https://e.com?{long_name}=x", method="GET")

    def test_too_many_body_params(self):
        params = [f"p{i}" for i in range(65)]
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com", method="POST", body_parameter_names=params)

    def test_source_asset_valid(self):
        evidence = build_browser_request_evidence(
            page_url="https://e.com", request_url="https://e.com", method="GET", source_asset="https://cdn.example.com/script.js?v=1"
        )
        self.assertEqual(evidence.source_asset, "https://cdn.example.com/script.js")

    def test_source_asset_invalid(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com", method="GET", source_asset="ftp://cdn.example.com/script.js")

    def test_to_mapping_json_serialisable(self):
        evidence = build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com", method="GET")
        mapping = evidence.to_mapping()
        import json
        json.dumps(mapping)

    def test_secret_in_query_not_in_mapping(self):
        evidence = build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com/api?secret=12345", method="GET")
        mapping = evidence.to_mapping()
        self.assertNotIn("12345", str(mapping))
        self.assertIn("secret", mapping["query_parameter_names"])  # ensure name preserved

    def test_page_url_secret_removed(self):
        evidence = build_browser_request_evidence(
            page_url="https://a.com/page?token=PAGE_SECRET#section", request_url="https://a.com/api", method="GET"
        )
        self.assertEqual(evidence.page_url, "https://a.com/page")
        mapping = evidence.to_mapping()
        self.assertNotIn("PAGE_SECRET", mapping["page_url"])

    def test_to_mapping_prohibited_fields(self):
        evidence = build_browser_request_evidence(page_url="https://e.com", request_url="https://e.com", method="GET")
        mapping = evidence.to_mapping()
        self.assertFalse("headers" in mapping)
        self.assertFalse("cookies" in mapping)
        self.assertFalse("authorization" in mapping)

    def test_rejected_credentials_in_page_url(self):
        with self.assertRaises(ValueError):
            build_browser_request_evidence(
                page_url="https://@example.com/api",
                request_url="https://example.com",
                method="GET"
            )
        with self.assertRaises(ValueError):
            build_browser_request_evidence(page_url="https://a.com", request_url="https://user:pass@example.com/api", method="GET")

    def test_source_asset_fragment_removed(self):
        evidence = build_browser_request_evidence(
            page_url="https://e.com", request_url="https://e.com", method="GET", source_asset="https://cdn.example.com/script.js?v=1#section"
        )
        self.assertEqual(evidence.source_asset, "https://cdn.example.com/script.js")

if __name__ == "__main__":
    unittest.main()
