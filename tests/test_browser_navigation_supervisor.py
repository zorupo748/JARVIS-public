import copy
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
from threading import Barrier
from unittest.mock import patch

from jarvis.core.browser_http_transport import BrowserHTTPRequest
from jarvis.core.browser_operation_contract import BrowserOrigin
from jarvis.core.browser_request_authorization import (
    BrowserRequestPermission, BrowserRequestAuthorizationSnapshot, BrowserRequestAuthorizationContext,
)
from jarvis.core.browser_navigation_supervisor import (
    create_browser_navigation_supervisor, BrowserNavigationAuthority,
    NavigationSessionHandle, NavigationReservationHandle, NavigationSupervisorError,
    NavigationReason as Reason, ReservationState as State,
)


REQUEST = BrowserHTTPRequest(BrowserOrigin("https", "example.com", 443), "GET", "/page", (("q", "DO_NOT_LEAK"),))
CONTEXT = BrowserRequestAuthorizationContext("session-1", "permission-1", "operation", "operation-1")


def snapshot(**kwargs):
    permission = BrowserRequestPermission("permission-1", "session-1", "operation", "operation-1", REQUEST, 0, 90, False)
    return replace(BrowserRequestAuthorizationSnapshot("session-1", (permission,), 0, 100, False,
                                                      0, 2, 0, 100, 50), **kwargs)


class Hostile:
    def fail(self, *args, **kwargs):
        raise AssertionError("untrusted callback")
    __str__ = __iter__ = __eq__ = __hash__ = __call__ = fail


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.now = 10
        self.owner, self.authority = create_browser_navigation_supervisor(clock=lambda: self.now)
        self.session = self.authority.register_session(snapshot())
        self.addCleanup(self.owner.close)

    def reserve(self, request_id="request-1", **kwargs):
        arguments = dict(session=self.session, request_id=request_id, request=REQUEST,
                         context=CONTEXT, response_byte_budget=50)
        arguments.update(kwargs)
        return self.owner.reserve(**arguments)

    def test_reserve_start_exact_binding_and_finish(self):
        result = self.reserve()
        self.assertTrue(result.accepted)
        self.assertIs(result.state, State.RESERVED)
        with self.assertRaises(NavigationSupervisorError):
            self.authority.binding(result.reservation)
        self.assertTrue(self.owner.start(result.reservation).accepted)
        binding = self.authority.binding(result.reservation)
        self.assertEqual(binding.request, REQUEST)
        self.assertEqual(binding.context, CONTEXT)
        self.assertEqual(binding.response_byte_budget, 50)
        self.assertNotIn("DO_NOT_LEAK", repr(binding))
        self.assertIs(self.owner.finish(result.reservation).state, State.COMPLETED)

    def test_unknown_permission_and_cross_session_denied(self):
        for context, reason in ((replace(CONTEXT, permission_id="unknown"), Reason.UNKNOWN_PERMISSION),
                                (replace(CONTEXT, session_id="other"), Reason.SESSION_MISMATCH),
                                (replace(CONTEXT, binding_id="other"), Reason.BINDING_MISMATCH),
                                (replace(CONTEXT, binding_kind="resource"), Reason.BINDING_MISMATCH)):
            with self.subTest(reason=reason):
                self.assertIs(self.reserve(context=context).reason, reason)
        self.assertTrue(self.reserve().accepted)  # Denials did not charge quota.

    def test_ids_or_constructed_records_are_not_session_authority(self):
        for session in ("session-1", snapshot(), NavigationSessionHandle(), copy.copy(self.session), Hostile()):
            self.assertIs(self.reserve(session=session).reason, Reason.UNKNOWN_SESSION)
        for handle in ("request-1", NavigationReservationHandle(), Hostile()):
            self.assertIs(self.owner.start(handle).reason, Reason.UNKNOWN_RESERVATION)
        fake = BrowserNavigationAuthority(self.owner, object())
        with self.assertRaises(NavigationSupervisorError) as caught:
            fake.register_session(snapshot(session_id="other", permissions=()))
        self.assertIs(caught.exception.reason, Reason.INVALID_INPUT)
        self.assertFalse(hasattr(self.owner, "register_session"))

    def test_permission_revocation_blocks_new_and_active_reservations(self):
        token = self.reserve().reservation
        self.owner.start(token)
        self.authority.revoke_permission(self.session, "permission-1")
        self.assertIs(self.reserve("request-2").reason, Reason.PERMISSION_REVOKED)
        self.assertIs(self.owner.inspect(token).state, State.REVOKED)
        self.assertFalse(self.owner.finish(token).accepted)
        with self.assertRaises(NavigationSupervisorError):
            self.authority.binding(token)

    def test_session_revocation_is_idempotent_and_no_reenrollment(self):
        token = self.reserve().reservation
        self.authority.revoke_session(self.session)
        self.authority.revoke_session(self.session)
        self.assertIs(self.reserve("request-2").reason, Reason.SESSION_REVOKED)
        self.assertIs(self.owner.inspect(token).state, State.REVOKED)
        with self.assertRaises(NavigationSupervisorError) as caught:
            self.authority.register_session(snapshot())
        self.assertIs(caught.exception.reason, Reason.DUPLICATE_SESSION)

    def test_expiry_rechecked_at_start_binding_and_finish(self):
        token = self.reserve().reservation
        self.now = 90
        self.assertIs(self.owner.start(token).reason, Reason.PERMISSION_NOT_CURRENT)
        self.assertIs(self.owner.inspect(token).state, State.EXPIRED)
        self.assertIs(self.reserve("request-2").reason, Reason.PERMISSION_NOT_CURRENT)
        self.now = 100
        self.assertIs(self.reserve("request-3").reason, Reason.SESSION_NOT_CURRENT)

    def test_active_expiry_cannot_be_finalized_as_completed(self):
        token = self.reserve().reservation
        self.owner.start(token)
        self.now = 90
        self.assertIs(self.owner.finish(token).reason, Reason.PERMISSION_NOT_CURRENT)
        self.assertIs(self.owner.inspect(token).state, State.EXPIRED)

    def test_cancel_during_active_operation_consumes_quota_permanently(self):
        token = self.reserve().reservation
        self.owner.start(token)
        self.assertIs(self.owner.cancel(token).state, State.CANCELLED)
        self.assertTrue(self.reserve("request-2").accepted)
        self.assertIs(self.reserve("request-3").reason, Reason.REQUEST_LIMIT)
        self.assertIs(self.reserve().reason, Reason.DUPLICATE_REQUEST)

    def test_byte_limit_and_no_cancellation_refund(self):
        owner, authority = create_browser_navigation_supervisor(clock=lambda: 10)
        self.addCleanup(owner.close)
        session = authority.register_session(snapshot(max_requests=10, max_total_response_bytes=50))
        result = owner.reserve(session, "a", REQUEST, CONTEXT, response_byte_budget=50)
        owner.cancel(result.reservation)
        self.assertIs(owner.reserve(session, "b", REQUEST, CONTEXT, response_byte_budget=1).reason, Reason.BYTE_LIMIT)

    def test_duplicate_reserve_start_finish_cancel(self):
        token = self.reserve().reservation
        self.assertIs(self.reserve().reason, Reason.DUPLICATE_REQUEST)
        self.assertIs(self.owner.finish(token).reason, Reason.STATE_CONFLICT)
        self.assertTrue(self.owner.start(token).accepted)
        self.assertIs(self.owner.start(token).reason, Reason.STATE_CONFLICT)
        self.assertTrue(self.owner.finish(token).accepted)
        self.assertIs(self.owner.finish(token).reason, Reason.STATE_CONFLICT)
        self.assertIs(self.owner.cancel(token).reason, Reason.STATE_CONFLICT)

    def test_concurrent_requests_reserve_atomically(self):
        barrier = Barrier(12)
        def worker(index):
            barrier.wait(timeout=5)
            return self.reserve("concurrent-" + str(index))
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(worker, range(12)))
        self.assertEqual(sum(result.accepted for result in results), 2)
        self.assertTrue(all(result.accepted or result.reason is Reason.REQUEST_LIMIT for result in results))
        # Existing reservations can still start at an otherwise exhausted quota.
        for result in results:
            if result.accepted:
                self.assertTrue(self.owner.start(result.reservation).accepted)

    def test_concurrent_duplicate_has_one_winner(self):
        barrier = Barrier(8)
        def worker(_):
            barrier.wait(timeout=5)
            return self.reserve()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(sum(result.accepted for result in results), 1)
        self.assertTrue(all(result.accepted or result.reason is Reason.DUPLICATE_REQUEST for result in results))

    def test_concurrent_byte_budget_is_atomic_independently_of_request_limit(self):
        owner, authority = create_browser_navigation_supervisor(clock=lambda: 10)
        self.addCleanup(owner.close)
        session = authority.register_session(snapshot(max_requests=12, max_total_response_bytes=50))
        barrier = Barrier(8)
        def worker(index):
            barrier.wait(timeout=5)
            return owner.reserve(session, "bytes-" + str(index), REQUEST, CONTEXT, response_byte_budget=50)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        self.assertEqual(sum(result.accepted for result in results), 1)
        self.assertTrue(all(result.accepted or result.reason is Reason.BYTE_LIMIT for result in results))

    def test_concurrent_finish_cancel_has_one_terminal_transition(self):
        token = self.reserve().reservation
        self.owner.start(token)
        barrier = Barrier(2)
        def settle(cancel):
            barrier.wait(timeout=5)
            return self.owner.cancel(token) if cancel else self.owner.finish(token)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(settle, (True, False)))
        self.assertEqual(sum(result.accepted for result in results), 1)

    def test_concurrent_revocation_invalidates_prior_grants_and_denies_later_work(self):
        barrier = Barrier(8)
        def worker(index):
            barrier.wait(timeout=5)
            if index == 0:
                self.authority.revoke_session(self.session)
                return None
            return self.reserve("race-" + str(index))
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(worker, range(8)))
        for result in results:
            if result and result.accepted:
                self.assertIs(self.owner.inspect(result.reservation).state, State.REVOKED)
                self.assertFalse(self.owner.start(result.reservation).accepted)
        self.assertIs(self.reserve("after-revoke").reason, Reason.SESSION_REVOKED)

    def test_interrupted_commit_invalidates_registry_instead_of_using_partial_quota(self):
        token = self.reserve().reservation
        class AllocationFailure(dict):
            def __setitem__(self, key, value):
                raise MemoryError("simulated allocation failure")
        self.owner._reservations = AllocationFailure(self.owner._reservations)
        with self.assertRaises(MemoryError):
            self.reserve("interrupted")
        self.assertIs(self.reserve("later").reason, Reason.SUPERVISOR_FAILED)
        self.assertIs(self.owner.inspect(token).state, State.INVALIDATED)

    def test_client_cannot_supply_clock_snapshot_or_accounting(self):
        for name, value in (("now_ms", 1), ("snapshot", snapshot()), ("requests_used", 0),
                            ("response_bytes_used", 0), ("revoked", False)):
            with self.subTest(name=name), self.assertRaises(TypeError):
                self.reserve(**{name: value})
        self.assertTrue(self.reserve().accepted)

    def test_trusted_registration_rejects_malformed_records_without_leaking(self):
        for value in (None, {}, Hostile()):
            with self.assertRaises(NavigationSupervisorError) as caught:
                self.authority.register_session(value)
            self.assertIs(caught.exception.reason, Reason.INVALID_INPUT)
            self.assertNotIn("DO_NOT_LEAK", str(caught.exception))

    def test_clock_failure_and_rollback_latch_closed_for_new_work(self):
        token = self.reserve().reservation
        self.now = 9
        self.assertIs(self.owner.start(token).reason, Reason.CLOCK_FAILED)
        self.now = 20
        self.assertIs(self.reserve("next").reason, Reason.CLOCK_FAILED)
        self.assertIs(self.owner.inspect(token).state, State.INVALIDATED)

    def test_malformed_and_throwing_clock_never_approves(self):
        for value in (True, None, -1, 2**63, "10"):
            self.now = value
            owner, authority = create_browser_navigation_supervisor(clock=lambda: value)
            session = authority.register_session(snapshot())
            self.assertIs(owner.reserve(session, "a", REQUEST, CONTEXT, response_byte_budget=1).reason, Reason.CLOCK_FAILED)
            owner.close()
        def broken():
            raise RuntimeError("DO_NOT_LEAK")
        owner, authority = create_browser_navigation_supervisor(clock=broken)
        session = authority.register_session(snapshot())
        result = owner.reserve(session, "a", REQUEST, CONTEXT, response_byte_budget=1)
        self.assertIs(result.reason, Reason.CLOCK_FAILED)
        self.assertNotIn("DO_NOT_LEAK", repr(result))
        owner.close()

    def test_caller_mutation_cannot_change_registered_or_reserved_request(self):
        original = snapshot()
        owner, authority = create_browser_navigation_supervisor(clock=lambda: 10)
        self.addCleanup(owner.close)
        session = authority.register_session(original)
        object.__setattr__(original, "max_requests", 100)
        request = replace(REQUEST)
        result = owner.reserve(session, "a", request, CONTEXT, response_byte_budget=50)
        object.__setattr__(request, "static_path", "/other")
        owner.start(result.reservation)
        binding = authority.binding(result.reservation)
        self.assertEqual(binding.request.static_path, "/page")
        object.__setattr__(binding.request, "static_path", "/other")
        self.assertEqual(authority.binding(result.reservation).request.static_path, "/page")

    def test_bad_inputs_never_consume_quota_or_execute_callbacks(self):
        for arguments in ({"request_id": Hostile()}, {"request_id": "DO_NOT_LEAK/"},
                          {"request": Hostile()}, {"context": Hostile()},
                          {"response_byte_budget": True}, {"response_byte_budget": 51}):
            result = self.reserve(**arguments)
            self.assertFalse(result.accepted)
            self.assertNotIn("DO_NOT_LEAK", repr(result))
        self.assertTrue(self.reserve().accepted)
        self.assertTrue(self.reserve("second").accepted)

    def test_foreign_handles_unknown_permission_and_fake_authority(self):
        other, authority = create_browser_navigation_supervisor(clock=lambda: 10)
        self.addCleanup(other.close)
        foreign_session = authority.register_session(snapshot())
        self.assertIs(self.reserve(session=foreign_session).reason, Reason.UNKNOWN_SESSION)
        token = self.reserve().reservation
        self.assertIs(other.start(token).reason, Reason.UNKNOWN_RESERVATION)
        with self.assertRaises(NavigationSupervisorError) as caught:
            self.authority.revoke_permission(self.session, "unknown")
        self.assertIs(caught.exception.reason, Reason.UNKNOWN_PERMISSION)

    def test_bounded_registry_and_terminal_tombstones(self):
        owner, authority = create_browser_navigation_supervisor(clock=lambda: 10, max_sessions=1, max_reservations=1)
        self.addCleanup(owner.close)
        session = authority.register_session(snapshot())
        with self.assertRaises(NavigationSupervisorError) as caught:
            authority.register_session(snapshot(session_id="other", permissions=()))
        self.assertIs(caught.exception.reason, Reason.REGISTRY_FULL)
        token = owner.reserve(session, "a", REQUEST, CONTEXT, response_byte_budget=1).reservation
        owner.cancel(token)
        self.assertIs(owner.reserve(session, "b", REQUEST, CONTEXT, response_byte_budget=1).reason, Reason.REGISTRY_FULL)

    def test_close_idempotent_rejects_all_new_actions(self):
        token = self.reserve().reservation
        self.owner.close()
        self.owner.close()
        self.assertIs(self.reserve("new").reason, Reason.CLOSED)
        self.assertIs(self.owner.start(token).reason, Reason.CLOSED)
        with self.assertRaises(NavigationSupervisorError) as caught:
            self.authority.register_session(snapshot())
        self.assertIs(caught.exception.reason, Reason.CLOSED)

    def test_no_network_filesystem_logging_or_external_effects(self):
        targets = ("socket.socket", "socket.getaddrinfo", "socket.create_connection",
                   "urllib.request.urlopen", "http.client.HTTPConnection.connect",
                   "http.client.HTTPSConnection.connect", "builtins.open", "os.open", "os.stat",
                   "subprocess.run", "subprocess.Popen", "logging.Logger._log", "time.time")
        with ExitStack() as stack:
            guards = [stack.enter_context(patch(name, side_effect=AssertionError("external effect"))) for name in targets]
            result = self.reserve()
            self.owner.start(result.reservation)
            self.authority.binding(result.reservation)
            self.owner.cancel(result.reservation)
            self.authority.revoke_session(self.session)
            self.owner.close()
            for guard in guards:
                guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
