from __future__ import annotations

import hashlib
import json
import inspect
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core.safe_skill_deployment import (
    DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
    EXECUTION_ACTION_NAME,
    DynamicSkillDeploymentMetadata,
    execution_target_for,
)
from jarvis.core.safe_skill_execution import (
    RuntimeExecutionResult,
    SafeSkillExecutionRequest,
    SafeSkillExecutionService,
)
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import (
    ConfirmationLedger,
    DeterministicPolicyEvaluator,
    FreshConfirmation,
    IdentityContext,
    PolicyDecisionKind,
    PresenceState,
    VerifiedFactor,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager


SOURCE = "def ejecutar_skill(**kwargs):\n    return kwargs\n"
SKILL_NAME = "resumir_documento"
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


class FakeRuntime:
    def __init__(self, outcome: RuntimeExecutionResult | Exception | None = None) -> None:
        self.outcome = outcome or RuntimeExecutionResult(success=True, result="runtime-ok")
        self.calls: list[dict[str, object]] = []

    def execute(self, **kwargs) -> RuntimeExecutionResult:
        self.calls.append(kwargs)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class SafeSkillExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.dynamic_dir = Path(self.temporary_dir.name) / "src" / "jarvis" / "skills" / "dynamic"
        self.dynamic_dir.mkdir(parents=True)
        self.owner = IdentityContext(
            identity=UserIdentity(
                user_id="owner-42",
                display_name="Owner",
                security_level=SecurityLevel.LEVEL_3,
                is_owner=True,
            ),
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_VOICE}),
        )

    def make_service(self, runtime: FakeRuntime) -> SafeSkillExecutionService:
        ledger = ConfirmationLedger()
        dispatcher = SkillDispatcher(
            SkillManager(),
            evaluator=DeterministicPolicyEvaluator(
                confirmation_ledger=ledger,
                now=lambda: NOW,
            ),
            confirmation_ledger=ledger,
        )
        return SafeSkillExecutionService(
            dispatcher,
            dynamic_skills_dir=self.dynamic_dir,
            runtime=runtime,
        )

    def install_artifact(
        self,
        *,
        source: str = SOURCE,
        action_name: str = EXECUTION_ACTION_NAME,
        metadata_hash: str | None = None,
    ) -> str:
        source_hash = metadata_hash or hashlib.sha256(source.encode("utf-8")).hexdigest()
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_bytes(source.encode("utf-8"))
        target = execution_target_for(SKILL_NAME, source_hash)
        payload = {
            "schema_version": DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
            "skill_name": SKILL_NAME,
            "source_hash": source_hash,
            "execution_action_name": action_name,
            "execution_target": target,
        }
        (self.dynamic_dir / f"{SKILL_NAME}.skill.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return source_hash

    def confirmation(self, source_hash: str) -> FreshConfirmation:
        return FreshConfirmation(
            confirmation_id=f"confirmation-{source_hash[:8]}",
            action_name=EXECUTION_ACTION_NAME,
            user_id="owner-42",
            target=execution_target_for(SKILL_NAME, source_hash),
            confirmed_at=NOW,
        )

    def request(
        self,
        *,
        identity: IdentityContext | None = None,
        parameters: dict[str, object] | None = None,
        confirmations: tuple[FreshConfirmation, ...] = (),
        skill_name: str = SKILL_NAME,
    ) -> SafeSkillExecutionRequest:
        return SafeSkillExecutionRequest(
            skill_name=skill_name,
            identity=identity or self.owner,
            parameters=parameters or {},
            confirmations=confirmations,
        )

    def test_valid_skill_and_policy_allow_reaches_runtime(self) -> None:
        source_hash = self.install_artifact()
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(
            self.request(parameters={"query": "hola"}, confirmations=(self.confirmation(source_hash),))
        )
        self.assertTrue(result.executed)
        self.assertTrue(result.allowed)
        self.assertTrue(result.hash_verified)
        self.assertEqual(result.result, "runtime-ok")
        self.assertEqual(len(runtime.calls), 1)
        self.assertEqual(runtime.calls[0]["expected_hash"], source_hash)
        self.assertEqual(runtime.calls[0]["parameters"], {"query": "hola", "estado": {}})

    def test_policy_deny_never_calls_runtime(self) -> None:
        self.install_artifact()
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(
            self.request(identity=IdentityContext.unknown_voice())
        )
        self.assertFalse(result.executed)
        self.assertFalse(result.allowed)
        self.assertEqual(result.policy_decision.kind, PolicyDecisionKind.DENY)
        runtime_calls = runtime.calls
        self.assertEqual(runtime_calls, [])

    def test_pending_confirmation_never_calls_runtime(self) -> None:
        self.install_artifact()
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(self.request())
        self.assertFalse(result.executed)
        self.assertEqual(result.policy_decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        self.assertIsNotNone(result.action)
        self.assertEqual(result.action.action, EXECUTION_ACTION_NAME)
        self.assertEqual(runtime.calls, [])

    def test_wrong_identity_never_calls_runtime(self) -> None:
        source_hash = self.install_artifact()
        other = IdentityContext(
            identity=UserIdentity(
                user_id="other", display_name="Other", security_level=SecurityLevel.LEVEL_3
            ),
            presence=PresenceState.PRESENT,
        )
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(
            self.request(identity=other, confirmations=(self.confirmation(source_hash),))
        )
        self.assertFalse(result.executed)
        self.assertEqual(runtime.calls, [])

    def test_missing_source_is_rejected_before_metadata_or_runtime(self) -> None:
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(self.request())
        self.assertFalse(result.executed)
        self.assertIn("source is missing", result.failure_reason or "")
        self.assertEqual(runtime.calls, [])

    def test_missing_metadata_is_rejected_before_runtime(self) -> None:
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_text(SOURCE, encoding="utf-8")
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(self.request())
        self.assertFalse(result.executed)
        self.assertIn("metadata is missing", result.failure_reason or "")
        self.assertEqual(runtime.calls, [])

    def test_correct_hash_allows_policy_evaluation(self) -> None:
        source_hash = self.install_artifact()
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(
            self.request(confirmations=(self.confirmation(source_hash),))
        )
        self.assertTrue(result.hash_verified)
        self.assertTrue(result.executed)

    def test_manually_altered_source_hash_is_rejected(self) -> None:
        self.install_artifact()
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_text("changed", encoding="utf-8")
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(self.request())
        self.assertFalse(result.executed)
        self.assertFalse(result.hash_verified)
        self.assertIn("hash", result.failure_reason or "")
        self.assertEqual(runtime.calls, [])

    def test_traversal_and_absolute_names_are_rejected(self) -> None:
        for unsafe_name in ("../main", "..\\security", "C:\\temp", "/tmp/skill"):
            with self.subTest(unsafe_name=unsafe_name):
                runtime = FakeRuntime()
                result = self.make_service(runtime).execute(self.request(skill_name=unsafe_name))
                self.assertFalse(result.executed)
                self.assertEqual(runtime.calls, [])

    def test_parameters_cannot_change_route_or_policy(self) -> None:
        source_hash = self.install_artifact()
        for reserved in ("path", "policy_action", "source_hash", "dynamic_dir"):
            with self.subTest(reserved=reserved):
                runtime = FakeRuntime()
                result = self.make_service(runtime).execute(
                    self.request(
                        parameters={reserved: "attempted override"},
                        confirmations=(self.confirmation(source_hash),),
                    )
                )
                self.assertFalse(result.executed)
                self.assertIn("may not alter", result.failure_reason or "")
                self.assertEqual(runtime.calls, [])

    def test_runtime_failure_is_structured_after_allow(self) -> None:
        source_hash = self.install_artifact()
        runtime = FakeRuntime(RuntimeExecutionResult(success=False, error="worker failed", stderr="trace"))
        result = self.make_service(runtime).execute(
            self.request(confirmations=(self.confirmation(source_hash),))
        )
        self.assertFalse(result.executed)
        self.assertTrue(result.allowed)
        self.assertEqual(result.failure_reason, "worker failed")
        self.assertEqual(result.stderr, "trace")

    def test_runtime_timeout_is_structured_after_allow(self) -> None:
        source_hash = self.install_artifact()
        runtime = FakeRuntime(
            RuntimeExecutionResult(success=False, error="timeout", timed_out=True, stdout="partial")
        )
        result = self.make_service(runtime).execute(
            self.request(confirmations=(self.confirmation(source_hash),))
        )
        self.assertFalse(result.executed)
        self.assertTrue(result.allowed)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, "partial")

    def test_unregistered_execution_policy_never_calls_runtime(self) -> None:
        self.install_artifact(action_name="not_registered")
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(self.request())
        self.assertFalse(result.executed)
        self.assertIn("execution policy", result.failure_reason or "")
        self.assertEqual(runtime.calls, [])

    def test_denial_has_no_direct_runtime_fallback(self) -> None:
        self.install_artifact()
        runtime = FakeRuntime()
        result = self.make_service(runtime).execute(self.request())
        self.assertFalse(result.executed)
        self.assertEqual(runtime.calls, [])

    def test_legacy_runtime_entrypoint_fails_closed(self) -> None:
        from jarvis.skills.dynamic_runtime import (
            DynamicSkillAuthorizationRequiredError,
            execute_existing_dynamic_skill,
        )

        with self.assertRaises(DynamicSkillAuthorizationRequiredError):
            execute_existing_dynamic_skill("valid_skill", self.dynamic_dir)

    def test_source_contains_no_direct_candidate_execution_or_main_integration(self) -> None:
        import jarvis.core.safe_skill_execution as execution_module

        source = inspect.getsource(execution_module)
        for forbidden in (
            "exec(",
            "eval(",
            "pip install",
            "DynamicSkillBuilder",
            "SkillManager.execute",
            "main.py",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()