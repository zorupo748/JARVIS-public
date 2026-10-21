import copy
import unittest
from contextlib import ExitStack
from dataclasses import FrozenInstanceError, fields, replace
from unittest.mock import patch

from jarvis.core.browser_http_transport import BrowserHTTPRequest
from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_request_authorization import (
    BrowserRequestPermission as Permission,
    BrowserRequestAuthorizationSnapshot as Snapshot,
    BrowserRequestAuthorizationContext as Context,
    BrowserRequestAuthorizationDecision as Decision,
    evaluate_browser_request_authorization as evaluate,
)


ORIGIN = BrowserOrigin("https", "example.com", 443)
REQUEST = BrowserHTTPRequest(ORIGIN, "GET", "/page", (("q", "DO_NOT_LEAK"),))


def permission(**changes):
    return replace(Permission("permission-1", "session-1", "operation", "operation-1",
                              REQUEST, 10, 90, False), **changes)


def snapshot(**changes):
    return replace(Snapshot("session-1", (permission(),), 0, 100, False,
                            0, 3, 0, 100, 50), **changes)


CONTEXT = Context("session-1", "permission-1", "operation", "operation-1")


def run(request=REQUEST, state=None, context=CONTEXT, **kwargs):
    return evaluate(request, snapshot() if state is None else state, context,
                    now_ms=kwargs.get("now_ms", 20),
                    response_byte_budget=kwargs.get("response_byte_budget", 50))


def forged(record, **changes):
    result = copy.copy(record)
    for name, value in changes.items():
        object.__setattr__(result, name, value)
    return result


class Hostile:
    def fail(self, *args, **kwargs):
        raise AssertionError("input callback executed")

    __str__ = __hash__ = __eq__ = __len__ = __iter__ = __call__ = fail


class StringSubclass(str):
    pass


class TupleSubclass(tuple):
    pass


class IntSubclass(int):
    pass


class RequestAuthorizationTests(unittest.TestCase):
    def assert_denied(self, reason, **kwargs):
        result = run(**kwargs)
        self.assertEqual(result, Decision(False, reason))
        self.assertNotIn("DO_NOT_LEAK", repr(result))

    def test_valid_get_and_head(self):
        for method in ("GET", "HEAD"):
            with self.subTest(method=method):
                request = replace(REQUEST, method=method)
                state = snapshot(permissions=(permission(request=request),))
                self.assertEqual(run(request, state), Decision(True, "allowed"))

    def test_resource_binding_is_distinct_from_operation(self):
        grant = permission(binding_kind="resource", binding_id="asset-1")
        state = snapshot(permissions=(grant,))
        context = replace(CONTEXT, binding_kind="resource", binding_id="asset-1")
        self.assertTrue(run(state=state, context=context).allowed)
        self.assert_denied("binding_mismatch", state=state)

    def test_session_and_binding_mismatches(self):
        for changes, reason in (({"session_id": "other"}, "session_mismatch"),
                                ({"binding_id": "other"}, "binding_mismatch"),
                                ({"binding_kind": "resource"}, "binding_mismatch"),
                                ({"permission_id": "other"}, "unknown_permission")):
            with self.subTest(changes=changes):
                self.assert_denied(reason, context=replace(CONTEXT, **changes))

    def test_empty_registry_does_not_grant_by_id(self):
        self.assert_denied("unknown_permission", state=snapshot(permissions=()))

    def test_session_and_permission_revocation(self):
        self.assert_denied("session_revoked", state=snapshot(revoked=True))
        self.assert_denied("permission_revoked", state=snapshot(permissions=(permission(revoked=True),)))

    def test_validity_is_half_open_and_uses_supplied_time(self):
        for now, reason in ((0, "permission_not_current"), (9, "permission_not_current"),
                            (90, "permission_not_current"), (100, "session_not_current")):
            with self.subTest(now=now):
                self.assert_denied(reason, now_ms=now)
        for now in (10, 89):
            self.assertTrue(run(now_ms=now).allowed)
        self.assert_denied("session_not_current", state=snapshot(valid_from_ms=30))

    def test_origin_method_and_path_match_exactly(self):
        for changes, reason in (
            ({"origin": BrowserOrigin("https", "other.example", 443)}, "origin_mismatch"),
            ({"method": "HEAD"}, "method_mismatch"),
            ({"static_path": "/Page"}, "path_mismatch"),
            ({"static_path": "/page/"}, "path_mismatch"),
        ):
            with self.subTest(changes=changes):
                self.assert_denied(reason, request=replace(REQUEST, **changes))

    def test_query_names_values_order_and_duplicates_are_exact(self):
        approved = (("q", "café & %0d%0a"), ("q", ""), ("page", "1"))
        request = replace(REQUEST, query_parameters=approved)
        state = snapshot(permissions=(permission(request=request),))
        self.assertTrue(run(request, state).allowed)
        for query in ((), (("q", "other"),), approved[::-1], approved[:1],
                      approved + (("extra", "1"),),
                      (("q", "caf%C3%A9 & %0d%0a"),) + approved[1:]):
            with self.subTest(query=query):
                self.assert_denied("query_mismatch", request=replace(request, query_parameters=query), state=state)

    def test_request_limit_checks_prospective_attempt(self):
        self.assertTrue(run(state=snapshot(requests_used=2)).allowed)
        for used in (3, 4):
            self.assert_denied("request_limit", state=snapshot(requests_used=used))

    def test_bytes_are_reserved_before_dispatch_not_after_success(self):
        self.assertTrue(run(state=snapshot(response_bytes_used=50)).allowed)
        for used in (51, 100, 101):
            self.assert_denied("byte_limit", state=snapshot(response_bytes_used=used))
        self.assert_denied("response_limit", response_byte_budget=51)
        self.assertTrue(run(response_byte_budget=1).allowed)

    def test_invalid_request_is_revalidated_and_never_authorized(self):
        for changes in (
            {"origin": BrowserOrigin("http", "example.com", 80)},
            {"origin": BrowserOrigin("https", "example.com", 8443)},
            {"method": "POST"}, {"method": "GET\r\nX: yes"},
            {"static_path": "https://other.example/"}, {"static_path": "//other.example"},
            {"static_path": "/%2e%2e/"}, {"static_path": "/a/../b"},
            {"static_path": "/page?q=x"}, {"static_path": "/page#x"},
            {"query_parameters": [("q", "x")]},
            {"query_parameters": (("q", "x\r\nInjected: yes"),)},
            {"query_parameters": (("q", "\x00"),)},
            {"query_parameters": (("q", "\ud800"),)},
            {"query_parameters": (("q", Hostile()),)},
            {"query_parameters": ((StringSubclass("q"), "x"),)},
        ):
            with self.subTest(fields=tuple(changes)):
                self.assert_denied("invalid_input", request=forged(REQUEST, **changes))

    def test_wrong_api_types_and_subclasses_are_denied_without_callbacks(self):
        class RequestSubclass(BrowserHTTPRequest):
            __slots__ = ()

        for argument in ("request", "state", "context"):
            for value in (None, True, {}, Hostile()):
                with self.subTest(argument=argument, value_type=type(value)):
                    # state=None is the helper's default, so call API directly.
                    args = dict(request=REQUEST, snapshot=snapshot(), context=CONTEXT)
                    args["snapshot" if argument == "state" else argument] = value
                    self.assertEqual(evaluate(**args, now_ms=20, response_byte_budget=50),
                                     Decision(False, "invalid_input"))
        self.assert_denied("invalid_input", request=RequestSubclass(ORIGIN, "GET"))

    def test_forged_nested_state_is_revalidated(self):
        for state in (
            forged(snapshot(), permissions=(permission(), permission())),
            forged(snapshot(), permissions=(forged(permission(), session_id="other"),)),
            forged(snapshot(), permissions=(forged(permission(), request=forged(REQUEST, method="POST")),)),
            forged(snapshot(), revoked=Hostile()),
            forged(snapshot(), max_requests=True),
            forged(snapshot(), permissions=TupleSubclass((permission(),))),
        ):
            self.assert_denied("invalid_input", state=state)

    def test_time_and_budget_types_and_bounds(self):
        for name in ("now_ms", "response_byte_budget"):
            for value in (True, False, -1, 2**63, 1.0, "20", None, IntSubclass(20), Hostile()):
                with self.subTest(name=name, value_type=type(value)):
                    self.assert_denied("invalid_input", **{name: value})
        for value in (0, 33_554_433):
            self.assert_denied("invalid_input", response_byte_budget=value)

    def test_constructors_reject_incomplete_ambiguous_state(self):
        for change in ({"permissions": []}, {"permissions": (permission(),) * 65},
                       {"permissions": (permission(), permission())},
                       {"permissions": (permission(session_id="other"),)},
                       {"valid_until_ms": 0}, {"revoked": 1}, {"max_requests": 0},
                       {"max_total_response_bytes": 0}, {"max_response_bytes": 33_554_433}):
            with self.subTest(fields=tuple(change)), self.assertRaises(ValueError):
                snapshot(**change)
        for change in ({"permission_id": ""}, {"binding_id": "x" * 129},
                       {"session_id": " DO_NOT_LEAK "}, {"binding_kind": "unknown"},
                       {"valid_until_ms": 10}, {"revoked": None}, {"request": None}):
            with self.subTest(fields=tuple(change)), self.assertRaises(ValueError) as caught:
                permission(**change)
            self.assertNotIn("DO_NOT_LEAK", str(caught.exception))

    def test_decision_coherence_and_no_sensitive_output(self):
        self.assertEqual(tuple(item.name for item in fields(Decision)), ("allowed", "reason"))
        for args in ((True, "unknown_permission"), (False, "allowed"), (1, "allowed"),
                     (False, "DO_NOT_LEAK"), (False, StringSubclass("invalid_input"))):
            with self.assertRaises(ValueError) as caught:
                Decision(*args)
            self.assertNotIn("DO_NOT_LEAK", str(caught.exception))
        for record in (permission(), snapshot(), run()):
            self.assertNotIn("DO_NOT_LEAK", repr(record))

    def test_all_trusted_counters_and_times_require_exact_bounded_integers(self):
        for name in ("valid_from_ms", "valid_until_ms", "requests_used", "max_requests",
                     "response_bytes_used", "max_total_response_bytes", "max_response_bytes"):
            for value in (True, False, -1, 2**63, 1.0, None, IntSubclass(1), Hostile()):
                with self.subTest(name=name, value_type=type(value)), self.assertRaises(ValueError):
                    snapshot(**{name: value})
        maximum = 2**63 - 1
        state = snapshot(max_requests=maximum, max_total_response_bytes=maximum,
                         valid_until_ms=maximum)
        self.assertTrue(run(state=state).allowed)
        self.assert_denied("byte_limit", state=replace(state, response_bytes_used=maximum))

    def test_registry_bound_and_hostile_context_are_fail_closed(self):
        grants = tuple(permission(permission_id=f"permission-{i}") for i in range(64))
        self.assertTrue(run(state=snapshot(permissions=grants)).allowed)
        for field_name in ("session_id", "permission_id", "binding_kind", "binding_id"):
            for value in (Hostile(), StringSubclass("session-1")):
                self.assert_denied("invalid_input", context=forged(CONTEXT, **{field_name: value}))
        absent = object.__new__(Snapshot)
        self.assert_denied("invalid_input", state=absent)

    def test_immutable_deterministic_and_does_not_reserve_or_mutate(self):
        state = snapshot()
        before = (state, REQUEST, CONTEXT)
        for record in before + (permission(), run()):
            self.assertFalse(hasattr(record, "__dict__"))
            self.assertEqual(hash(record), hash(replace(record)))
            with self.assertRaises(FrozenInstanceError):
                setattr(record, fields(record)[0].name, None)
        self.assertEqual(run(state=state), run(state=state))
        self.assertEqual(before, (state, REQUEST, CONTEXT))
        self.assertEqual(state.requests_used, 0)

    def test_no_io_dns_network_clock_or_callbacks(self):
        targets = (
            "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
            "socket.socket", "socket.create_connection", "urllib.request.urlopen",
            "http.client.HTTPConnection.connect", "http.client.HTTPSConnection.connect",
            "builtins.open", "os.open", "os.stat", "subprocess.run", "subprocess.Popen",
            "time.monotonic_ns", "time.monotonic", "time.time", "time.perf_counter",
            "logging.Logger._log",
        )
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(target, side_effect=AssertionError("unexpected I/O")))
                      for target in targets]
            self.assertTrue(run().allowed)
            self.assert_denied("unknown_permission", state=snapshot(permissions=()))
            self.assert_denied("invalid_input", request=Hostile())
            for guard in guards:
                guard.assert_not_called()

    def test_same_binding_label_cannot_cross_operation_resource_namespaces(self):
        grant = permission(binding_kind="resource", binding_id=CONTEXT.binding_id)
        state = snapshot(permissions=(grant,))
        self.assert_denied("binding_mismatch", state=state)
        self.assertTrue(run(state=state, context=replace(CONTEXT, binding_kind="resource")).allowed)

    def test_same_permission_label_in_another_session_does_not_transfer_grant(self):
        state = snapshot(session_id="session-2", permissions=(permission(session_id="session-2"),))
        self.assert_denied("session_mismatch", state=state)
        inconsistent = forged(state, permissions=(permission(),))
        self.assert_denied("invalid_input", state=inconsistent,
                           context=replace(CONTEXT, session_id="session-2"))

    def test_invalid_unused_permission_invalidates_entire_snapshot(self):
        unused = forged(permission(permission_id="unused"), revoked=1)
        self.assert_denied("invalid_input", state=forged(snapshot(), permissions=(permission(), unused)))

    def test_all_record_subclasses_and_missing_slots_fail_closed(self):
        class SnapshotSubclass(Snapshot):
            __slots__ = ()

        class PermissionSubclass(Permission):
            __slots__ = ()

        class ContextSubclass(Context):
            __slots__ = ()

        def as_subclass(record, cls):
            return cls(**{item.name: getattr(record, item.name) for item in fields(record)})

        self.assert_denied("invalid_input", state=as_subclass(snapshot(), SnapshotSubclass))
        self.assert_denied("invalid_input", context=as_subclass(CONTEXT, ContextSubclass))
        self.assert_denied("invalid_input", state=forged(snapshot(), permissions=(
            as_subclass(permission(), PermissionSubclass),)))
        self.assert_denied("invalid_input", state=forged(snapshot(), permissions=(object.__new__(Permission),)))
        self.assert_denied("invalid_input", request=object.__new__(BrowserHTTPRequest))
        self.assert_denied("invalid_input", context=object.__new__(Context))

    def test_percent_unicode_and_special_characters_never_normalize_into_permission(self):
        for approved, different in (
            ("%2f", "/"), ("%2f", "%2F"), ("%252f", "%2f"),
            ("+", " "), ("%0d%0a", "\r\n"),
            ("é", "e\u0301"), ("a&other=1", "a"),
        ):
            with self.subTest(approved=approved):
                request = replace(REQUEST, query_parameters=(("q", approved),))
                state = snapshot(permissions=(permission(request=request),))
                self.assertTrue(run(request, state).allowed)
                proposed = forged(request, query_parameters=(("q", different),))
                self.assert_denied("invalid_input" if different == "\r\n" else "query_mismatch",
                                   request=proposed, state=state)
        approved = (("q", "a"), ("q", "b"))
        request = replace(REQUEST, query_parameters=approved)
        state = snapshot(permissions=(permission(request=request),))
        self.assert_denied("query_mismatch", request=replace(request, query_parameters=approved[::-1]), state=state)

    def test_signed_maximum_addition_cannot_wrap_into_byte_permission(self):
        maximum = 2**63 - 1
        state = snapshot(max_total_response_bytes=maximum, response_bytes_used=maximum - 50)
        self.assertTrue(run(state=state).allowed)
        self.assert_denied("byte_limit", state=replace(state, response_bytes_used=maximum - 49))
        self.assert_denied("byte_limit", state=replace(state, response_bytes_used=maximum))

    def test_nested_origin_corruption_is_denied_without_hostile_callbacks(self):
        for changes in ({"scheme": StringSubclass("https")}, {"hostname": Hostile()},
                        {"effective_port": True}, {"hostname": "127.0.0.1"},
                        {"hostname": "example.com\r\nInjected: yes"}):
            with self.subTest(fields=tuple(changes)):
                request = forged(REQUEST, origin=forged(ORIGIN, **changes))
                self.assert_denied("invalid_input", request=request)
                state = forged(snapshot(), permissions=(forged(permission(), request=request),))
                self.assert_denied("invalid_input", state=state)

    def test_decision_is_not_a_quota_reservation_or_provenance_credential(self):
        state = snapshot(max_requests=1)
        self.assertTrue(run(state=state).allowed)
        self.assertTrue(run(state=state).allowed)
        self.assert_denied("request_limit", state=replace(state, requests_used=1))
        # Shape cannot authenticate authority: substituting a coherent grant
        # changes the policy. A supervisor must never accept caller snapshots.
        alternate = replace(REQUEST, static_path="/other")
        self.assert_denied("path_mismatch", request=alternate, state=state)
        supplied_grant = snapshot(permissions=(permission(request=alternate),))
        self.assertTrue(run(alternate, supplied_grant).allowed)


if __name__ == "__main__":
    unittest.main()
