import unittest

from jarvis.core.external_source_research import (
    ExternalSourceResearchRequest,
    ExternalSourceResearchResult,
)
from jarvis.core.external_research_coordinator import ExternalResearchCoordinator

# Minimal concrete provider for testing.
class FakeProvider:
    def __init__(self, result):
        self._result = result
        self.calls = []

    def research(self, request: ExternalSourceResearchRequest):
        self.calls.append(request)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result

# Helper to build results.
def make_result(sufficient: bool) -> ExternalSourceResearchResult:
    status = "sufficient" if sufficient else "insufficient_research"
    return ExternalSourceResearchResult(
        source="https://example.com",
        access_method="get",
        response_format="application/json",
        confidence=0.9,
        research_status=status,
        final_url="",
    )

class ExternalResearchCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.request = ExternalSourceResearchRequest(
            user_request="Retrieve data.",
            source="https://example.com",
            capability="Read data",
        )

    def test_static_sufficient(self):
        static_res = make_result(True)
        static = FakeProvider(static_res)
        fallback = FakeProvider(make_result(False))  # unused
        coord = ExternalResearchCoordinator(static, fallback)
        result = coord.research(self.request)
        self.assertIs(result, static_res)
        self.assertEqual(len(static.calls), 1)
        self.assertIs(static.calls[0], self.request)
        self.assertEqual(len(fallback.calls), 0)

    def test_static_insufficient_fallback_sufficient(self):
        static_res = make_result(False)
        fallback_res = make_result(True)
        static = FakeProvider(static_res)
        fallback = FakeProvider(fallback_res)
        coord = ExternalResearchCoordinator(static, fallback)
        result = coord.research(self.request)
        self.assertIs(result, fallback_res)
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(len(fallback.calls), 1)
        self.assertIs(static.calls[0], self.request)
        self.assertIs(fallback.calls[0], self.request)

    def test_static_insufficient_fallback_insufficient(self):
        static_res = make_result(False)
        fallback_res = make_result(False)
        static = FakeProvider(static_res)
        fallback = FakeProvider(fallback_res)
        coord = ExternalResearchCoordinator(static, fallback)
        result = coord.research(self.request)
        self.assertIs(result, fallback_res)
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(len(fallback.calls), 1)

    def test_static_provider_raises(self):
        static = FakeProvider(RuntimeError("static error"))
        fallback = FakeProvider(make_result(True))
        coord = ExternalResearchCoordinator(static, fallback)
        with self.assertRaises(RuntimeError):
            coord.research(self.request)
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(len(fallback.calls), 0)

    def test_fallback_provider_raises(self):
        static = FakeProvider(make_result(False))
        fallback = FakeProvider(RuntimeError("fallback error"))
        coord = ExternalResearchCoordinator(static, fallback)
        with self.assertRaises(RuntimeError):
            coord.research(self.request)
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(len(fallback.calls), 1)

    def test_static_invalid_result_does_not_fallback(self):
        static_res = object()  # no sufficient attribute
        static = FakeProvider(static_res)
        fallback = FakeProvider(make_result(False))
        coord = ExternalResearchCoordinator(static, fallback)
        with self.assertRaises(AttributeError):
            coord.research(self.request)
        self.assertEqual(len(static.calls), 1)
        self.assertEqual(len(fallback.calls), 0)

    def test_request_unchanged(self):
        static_res = make_result(False)
        fallback_res = make_result(True)
        static = FakeProvider(static_res)
        fallback = FakeProvider(fallback_res)
        coord = ExternalResearchCoordinator(static, fallback)
        original = ExternalSourceResearchRequest(
            user_request=self.request.user_request,
            source=self.request.source,
            capability=self.request.capability,
        )
        coord.research(self.request)
        self.assertEqual(self.request, original)

    def test_conforms_to_interface(self):
        static = FakeProvider(make_result(True))
        fallback = FakeProvider(make_result(True))
        coord = ExternalResearchCoordinator(static, fallback)
        result = coord.research(self.request)
        self.assertIsInstance(result, ExternalSourceResearchResult)

if __name__ == "__main__":
    unittest.main()
