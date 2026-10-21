from __future__ import annotations

import ast
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core.safe_skill_deployment import (
    DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
    EXECUTION_ACTION_NAME,
    execution_target_for,
)
from jarvis.core.safe_skill_execution import (
    RuntimeExecutionResult,
    SafeSkillExecutionResult,
    SafeSkillExecutionService,
)
from jarvis.core.safe_skill_pipeline import SafeSkillPipeline
from jarvis.core.session_skill_grants import SessionSkillGrantStore
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    ConfirmationLedger,
    DecisionReason,
    DeterministicPolicyEvaluator,
    IdentityContext,
    PolicyDecision,
    PolicyDecisionKind,
    PresenceState,
    SessionSkillAuthorization,
    VerifiedFactor,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "comprobar_ollama"
SOURCE = "def ejecutar_skill(comando=''):\n    return {'version': '1.2'}\n"
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
SOURCE_HASH = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()


class FakeRuntime:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def execute(self, **kwargs) -> RuntimeExecutionResult:
        self.calls.append(kwargs)
        return RuntimeExecutionResult(success=True, result={"version": "1.2"})


class RecordingExecutionService:
    def __init__(self, service: SafeSkillExecutionService) -> None:
        self.service = service
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        return self.service.execute(request)


class FakeAuthoring:
    def author(self, _request):
        raise AssertionError("authoring is not used in execution tests")


class FakeDeployment:
    def stage(self, _request):
        raise AssertionError("deployment is not used in execution tests")

    def deploy(self, _request):
        raise AssertionError("deployment is not used in execution tests")


class SessionSkillGrantStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SessionSkillGrantStore()
        self.source_hash = "a" * 64

    def test_store_starts_empty(self) -> None:
        self.assertFalse(self.store.is_granted(SKILL_NAME, self.source_hash))

    def test_skill_and_hash_grant_is_recognized(self) -> None:
        self.store.grant(SKILL_NAME, self.source_hash)

        self.assertTrue(self.store.is_granted(SKILL_NAME, self.source_hash))

    def test_different_hash_is_not_granted(self) -> None:
        self.store.grant(SKILL_NAME, self.source_hash)

        self.assertFalse(self.store.is_granted(SKILL_NAME, "b" * 64))

    def test_different_skill_is_not_granted(self) -> None:
        self.store.grant(SKILL_NAME, self.source_hash)

        self.assertFalse(self.store.is_granted("otra_skill", self.source_hash))

    def test_clear_removes_grants(self) -> None:
        self.store.grant(SKILL_NAME, self.source_hash)
        self.store.clear()

        self.assertFalse(self.store.is_granted(SKILL_NAME, self.source_hash))

    def test_store_has_no_disk_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            before = set(Path(temporary_dir).iterdir())
            self.store.grant(SKILL_NAME, self.source_hash, "owner-1")
            self.assertEqual(set(Path(temporary_dir).iterdir()), before)
        self.assertEqual(set(vars(self.store)), {"_grants"})

    def test_inputs_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            self.store.grant("../skill", self.source_hash)
        with self.assertRaises(ValueError):
            self.store.grant(SKILL_NAME, "not-a-hash")


class SessionSkillGrantExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.dynamic_dir = Path(self.temporary_dir.name) / "dynamic"
        self.dynamic_dir.mkdir()
        self.owner = IdentityContext(
            identity=UserIdentity(
                user_id="owner-1",
                display_name="Owner",
                security_level=SecurityLevel.LEVEL_3,
                is_owner=True,
            ),
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
        )
        self.runtime = FakeRuntime()
        self.ledger = ConfirmationLedger()
        dispatcher = SkillDispatcher(
            SkillManager(),
            evaluator=DeterministicPolicyEvaluator(
                confirmation_ledger=self.ledger,
                now=lambda: NOW,
            ),
            confirmation_ledger=self.ledger,
        )
        execution_service = SafeSkillExecutionService(
            dispatcher,
            dynamic_skills_dir=self.dynamic_dir,
            runtime=self.runtime,
        )
        self.recording_execution = RecordingExecutionService(execution_service)
        confirmation_number = 0

        def next_confirmation_id() -> str:
            nonlocal confirmation_number
            confirmation_number += 1
            return f"fresh-{confirmation_number}"

        self.pipeline = SafeSkillPipeline(
            FakeAuthoring(),
            FakeDeployment(),
            self.recording_execution,
            confirmation_id_factory=next_confirmation_id,
            now=lambda: NOW,
        )
        self.grants = SessionSkillGrantStore()
        self.install_artifact()

    def install_artifact(self, source: str = SOURCE, metadata_hash: str | None = None) -> str:
        source_hash = metadata_hash or hashlib.sha256(source.encode("utf-8")).hexdigest()
        target = execution_target_for(SKILL_NAME, source_hash)
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_bytes(source.encode("utf-8"))
        payload = {
            "schema_version": DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
            "skill_name": SKILL_NAME,
            "source_hash": source_hash,
            "execution_action_name": EXECUTION_ACTION_NAME,
            "execution_target": target,
        }
        (self.dynamic_dir / f"{SKILL_NAME}.skill.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return source_hash

    def prepare(self):
        return self.pipeline.prepare_execution(
            SKILL_NAME,
            identity=self.owner,
            parameters={"comando": "consulta versión"},
        )

    def test_first_execution_requires_confirmation(self) -> None:
        preparation = self.prepare()

        self.assertTrue(preparation.confirmation_required)
        self.assertIsNotNone(preparation.pending)
        self.assertEqual(preparation.execution_result.policy_decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        self.assertEqual(self.runtime.calls, [])

    def test_positive_confirmation_authorized_by_policy_creates_grant(self) -> None:
        pending = self.prepare().pending
        confirmed = self.pipeline.confirm_execution(pending, identity=self.owner)

        self.assertTrue(confirmed.executed)
        self.assertTrue(
            self.grants.grant_from_confirmed_execution(confirmed, self.owner.user_id)
        )
        self.assertTrue(self.grants.is_granted(SKILL_NAME, SOURCE_HASH, self.owner.user_id))

    def test_declining_confirmation_does_not_create_grant(self) -> None:
        pending = self.prepare().pending
        self.assertIsNotNone(pending)
        # The "no" branch discards pending without calling confirm_execution.
        self.assertFalse(self.grants.is_granted(SKILL_NAME, SOURCE_HASH))
        self.assertEqual(self.runtime.calls, [])

    def test_second_same_hash_execution_uses_policy_without_confirmation_prompt(self) -> None:
        first_pending = self.prepare().pending
        first_result = self.pipeline.confirm_execution(first_pending, identity=self.owner)
        self.assertTrue(self.grants.grant_from_confirmed_execution(first_result, self.owner.user_id))

        second_preparation = self.prepare()
        self.assertTrue(second_preparation.confirmation_required)
        pending = second_preparation.pending
        source_hash = pending.action.metadata["source_hash"]
        authorization = self.grants.authorization_for(
            pending.skill_name,
            source_hash,
            self.owner.user_id,
        )
        self.assertIsNotNone(authorization)
        second_result = self.pipeline.execute_installed(
            pending.skill_name,
            identity=self.owner,
            parameters=pending.parameters,
            session_skill_authorization=authorization,
        )

        self.assertTrue(second_result.executed)
        self.assertEqual(len(self.runtime.calls), 2)
        self.assertEqual(self.recording_execution.requests[-1].confirmations, ())
        self.assertIsNotNone(self.recording_execution.requests[-1].session_skill_authorization)

    def test_new_process_store_requires_confirmation_again(self) -> None:
        self.grants.grant(SKILL_NAME, SOURCE_HASH, self.owner.user_id)
        restarted_store = SessionSkillGrantStore()
        preparation = self.prepare()

        self.assertTrue(preparation.confirmation_required)
        self.assertIsNone(
            restarted_store.authorization_for(SKILL_NAME, SOURCE_HASH, self.owner.user_id)
        )

    def test_modified_hash_requires_confirmation_again(self) -> None:
        self.grants.grant(SKILL_NAME, SOURCE_HASH, self.owner.user_id)
        changed_source = SOURCE + "# changed\n"
        changed_hash = self.install_artifact(changed_source)
        preparation = self.prepare()

        self.assertTrue(preparation.confirmation_required)
        self.assertNotEqual(changed_hash, SOURCE_HASH)
        self.assertFalse(self.grants.is_granted(SKILL_NAME, changed_hash, self.owner.user_id))
        self.assertIsNone(
            self.grants.authorization_for(SKILL_NAME, changed_hash, self.owner.user_id)
        )

    def test_policy_deny_is_not_overridden_by_existing_grant(self) -> None:
        preparation = self.prepare()
        pending = preparation.pending
        source_hash = pending.action.metadata["source_hash"]
        self.grants.grant(SKILL_NAME, source_hash, self.owner.user_id)
        authorization = self.grants.authorization_for(
            SKILL_NAME, source_hash, self.owner.user_id
        )
        unknown_identity = IdentityContext.unknown_voice()

        result = self.pipeline.execute_installed(
            SKILL_NAME,
            identity=unknown_identity,
            parameters=pending.parameters,
            session_skill_authorization=authorization,
        )

        self.assertFalse(result.executed)
        self.assertEqual(result.policy_decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(self.runtime.calls, [])

    def test_hash_mismatch_remains_blocked_even_with_grant(self) -> None:
        self.grants.grant(SKILL_NAME, SOURCE_HASH, self.owner.user_id)
        authorization = self.grants.authorization_for(
            SKILL_NAME, SOURCE_HASH, self.owner.user_id
        )
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_text("changed", encoding="utf-8")

        result = self.pipeline.execute_installed(
            SKILL_NAME,
            identity=self.owner,
            session_skill_authorization=authorization,
        )

        self.assertFalse(result.executed)
        self.assertFalse(result.hash_verified)
        self.assertIn("hash", result.failure_reason.lower())
        self.assertEqual(self.runtime.calls, [])

    def test_invalid_metadata_remains_blocked_even_with_grant(self) -> None:
        self.grants.grant(SKILL_NAME, SOURCE_HASH, self.owner.user_id)
        authorization = self.grants.authorization_for(
            SKILL_NAME, SOURCE_HASH, self.owner.user_id
        )
        (self.dynamic_dir / f"{SKILL_NAME}.skill.json").write_text("{}", encoding="utf-8")

        result = self.pipeline.execute_installed(
            SKILL_NAME,
            identity=self.owner,
            session_skill_authorization=authorization,
        )

        self.assertFalse(result.executed)
        self.assertFalse(result.hash_verified)
        self.assertIn("metadata", result.failure_reason.lower())
        self.assertEqual(self.runtime.calls, [])

    def test_fresh_confirmation_is_not_reused_for_session_execution(self) -> None:
        pending = self.prepare().pending
        confirmed = self.pipeline.confirm_execution(pending, identity=self.owner)
        consumed_ids = confirmed.policy_decision.confirmation_ids_to_consume
        self.assertEqual(consumed_ids, ("fresh-1",))
        self.assertTrue(self.grants.grant_from_confirmed_execution(confirmed, self.owner.user_id))

        next_pending = self.prepare().pending
        authorization = self.grants.authorization_for(
            SKILL_NAME,
            next_pending.action.metadata["source_hash"],
            self.owner.user_id,
        )
        result = self.pipeline.execute_installed(
            SKILL_NAME,
            identity=self.owner,
            parameters=next_pending.parameters,
            session_skill_authorization=authorization,
        )

        session_request = self.recording_execution.requests[-1]
        self.assertTrue(result.executed)
        self.assertEqual(session_request.confirmations, ())
        self.assertIsInstance(session_request.session_skill_authorization, SessionSkillAuthorization)
        self.assertEqual(consumed_ids, ("fresh-1",))

    def test_unverified_or_denied_result_cannot_create_grant(self) -> None:
        denied = SafeSkillExecutionResult(
            executed=False,
            allowed=False,
            skill_name=SKILL_NAME,
            result=None,
            policy_decision=PolicyDecision(
                kind=PolicyDecisionKind.DENY,
                reason=DecisionReason.INSUFFICIENT_LEVEL,
                action_name=EXECUTION_ACTION_NAME,
                policy=None,
            ),
            hash_verified=True,
            action=SecurityAction(
                action=EXECUTION_ACTION_NAME,
                description="execute",
                target=execution_target_for(SKILL_NAME, SOURCE_HASH),
                metadata={"skill_name": SKILL_NAME, "source_hash": SOURCE_HASH},
            ),
        )
        self.assertFalse(self.grants.grant_from_confirmed_execution(denied, self.owner.user_id))
        self.assertFalse(self.grants.is_granted(SKILL_NAME, SOURCE_HASH))


class MainSessionSkillGrantIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source)

    def test_main_creates_one_process_local_store(self) -> None:
        assignments = [
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "session_skill_grants"
                for target in node.targets
            )
        ]
        self.assertEqual(len(assignments), 1)
        self.assertEqual(ast.unparse(assignments[0].value), "SessionSkillGrantStore()")

    def test_negative_confirmation_branch_does_not_grant(self) -> None:
        refusal = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "not confirmation_choice"
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "grant_from_confirmed_execution"
                for statement in refusal.body
                for node in ast.walk(statement)
            )
        )

    def test_confirmed_authorized_result_records_session_grant(self) -> None:
        positive_confirmation = next(
            node
            for node in ast.walk(self.tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "confirmation_choice is not None"
            and any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "confirm_execution"
                for statement in node.body
                for child in ast.walk(statement)
            )
        )
        self.assertTrue(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "grant_from_confirmed_execution"
                for statement in positive_confirmation.body
                for node in ast.walk(statement)
            )
        )

    def test_repeat_uses_session_authorization_through_safe_pipeline(self) -> None:
        self.assertIn("session_skill_grants.authorization_for(", self.source)
        self.assertIn("safe_skill_pipeline.execute_installed(", self.source)
        self.assertIn("session_skill_authorization=session_authorization", self.source)
        self.assertIn("safe_skill_pipeline.prepare_execution", self.source)


if __name__ == "__main__":
    unittest.main()