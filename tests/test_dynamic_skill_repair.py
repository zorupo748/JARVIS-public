from __future__ import annotations

import ast
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from jarvis.core.code_reviewer import CodeReviewResult
from jarvis.core.code_validation import ValidationCheck, ValidationReport
from jarvis.core.dynamic_skill_repair import (
    DynamicSkillRepairCoordinator,
    DynamicSkillRepairContext,
    PendingDynamicSkillRepairRetry,
)
from jarvis.core.dynamic_skill_state import DynamicSkillStateStore
from jarvis.core.safe_skill_deployment import (
    DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
    EXECUTION_ACTION_NAME,
    SafeSkillDeploymentService,
    execution_target_for,
)
from jarvis.core.safe_skill_execution import (
    ExecutionFailureKind,
    RuntimeExecutionResult,
    SafeSkillExecutionRequest,
    SafeSkillExecutionResult,
    SafeSkillExecutionService,
    SubprocessDynamicSkillRuntime,
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
    FreshConfirmation,
    IdentityContext,
    PolicyDecision,
    PolicyDecisionKind,
    PresenceState,
    VerifiedFactor,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "repair_counter"
ORIGINAL_COMMAND = "Comprueba y actualiza el contador solicitado."
INSTALLED_SOURCE = (
    "def ejecutar_skill(comando='', estado=None):\n"
    "    return estado['ultima_version']\n"
)
REPAIRED_SOURCE = (
    "def ejecutar_skill(comando='', estado=None):\n"
    "    estado = dict(estado or {})\n"
    "    return {'__jarvis_data__': estado.get('ultima_version', 'sin datos'),\n"
    "            '__jarvis_state__': estado}\n"
)
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def make_execution_failure(
    *,
    error: str = "KeyError: 'ultima_version'",
    failure_kind: ExecutionFailureKind = ExecutionFailureKind.SKILL_EXCEPTION,
    allowed: bool = True,
    hash_verified: bool = True,
    source_hash: str | None = None,
    runtime_state=None,
) -> SafeSkillExecutionResult:
    source_hash = source_hash or hashlib.sha256(INSTALLED_SOURCE.encode("utf-8")).hexdigest()
    action = SecurityAction(
        action=EXECUTION_ACTION_NAME,
        description="Execute dynamic skill",
        target=execution_target_for(SKILL_NAME, source_hash),
        metadata={"skill_name": SKILL_NAME, "source_hash": source_hash},
    )
    policy_kind = PolicyDecisionKind.ALLOW if allowed else PolicyDecisionKind.DENY
    decision = PolicyDecision(
        kind=policy_kind,
        reason=DecisionReason.ALLOWED if allowed else DecisionReason.INSUFFICIENT_LEVEL,
        action_name=EXECUTION_ACTION_NAME,
        policy=None,
    )
    return SafeSkillExecutionResult(
        executed=False,
        allowed=allowed,
        skill_name=SKILL_NAME,
        result=None,
        policy_decision=decision,
        hash_verified=hash_verified,
        failure_reason=error,
        action=action,
        failure_kind=failure_kind,
        runtime_state={} if runtime_state is None else runtime_state,
    )


class FakeRuntime:
    def __init__(self, result: RuntimeExecutionResult | None = None) -> None:
        self.result = result or RuntimeExecutionResult(success=True, result="ok")
        self.calls: list[dict[str, object]] = []

    def execute(self, **kwargs) -> RuntimeExecutionResult:
        self.calls.append(kwargs)
        return self.result


class FakeAuthoring:
    def __init__(self, proposal_source: str = REPAIRED_SOURCE) -> None:
        self.proposal_source = proposal_source
        self.requests = []

    def author(self, request):
        self.requests.append(request)
        proposal = GeneratedResultFactory.proposal(self.proposal_source)
        if self.proposal_source is None:
            return GeneratedResultFactory.failed_authoring()
        return GeneratedResultFactory.approved_authoring(proposal)


class GeneratedResultFactory:
    @staticmethod
    def proposal(source: str):
        from jarvis.core.safe_skill_authoring import GeneratedSkillProposal

        return GeneratedSkillProposal(
            skill_name=SKILL_NAME,
            source_code=source,
            implementation_summary="Repair the installed counter behavior.",
            dependencies=(),
        )

    @staticmethod
    def approved_authoring(proposal):
        from jarvis.core.safe_skill_authoring import SkillAuthoringResult

        return SkillAuthoringResult(
            success=True,
            proposal=proposal,
            iterations=1,
            validation_reports=(ValidationReport(True, (ValidationCheck("valid", True, "ok"),)),),
            review_results=(CodeReviewResult(
                approved=True,
                issues=(),
                reviewer_used="fake",
                cloud_attempted=False,
                cloud_failed=False,
            ),),
        )

    @staticmethod
    def failed_authoring():
        from jarvis.core.safe_skill_authoring import SkillAuthoringResult

        return SkillAuthoringResult(
            success=False,
            proposal=None,
            iterations=1,
            validation_reports=(),
            review_results=(),
            failure_reason="fake authoring failure",
        )


class DynamicSkillRepairTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dynamic_dir = self.root / "dynamic"
        self.dynamic_dir.mkdir()
        self.state_store = DynamicSkillStateStore(self.root / "data" / "dynamic_skill_state")
        self.ledger = ConfirmationLedger()
        self.evaluator = DeterministicPolicyEvaluator(confirmation_ledger=self.ledger, now=lambda: NOW)
        self.owner = IdentityContext(
            identity=UserIdentity(
                user_id="repair-owner",
                display_name="Owner",
                security_level=SecurityLevel.LEVEL_3,
                is_owner=True,
            ),
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
        )
        self.runtime = FakeRuntime(RuntimeExecutionResult(success=True, result="unused"))
        self.fake_authoring = FakeAuthoring()
        self.deployment = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            evaluator=self.evaluator,
            confirmation_ledger=self.ledger,
        )
        self.execution = SafeSkillExecutionService(
            SkillDispatcher(SkillManager(), evaluator=self.evaluator, confirmation_ledger=self.ledger),
            dynamic_skills_dir=self.dynamic_dir,
            runtime=self.runtime,
            state_store=self.state_store,
        )
        self.pipeline = SafeSkillPipeline(
            self.fake_authoring,
            self.deployment,
            self.execution,
            confirmation_id_factory=self._next_confirmation,
            now=lambda: NOW,
        )
        self.coordinator = DynamicSkillRepairCoordinator(
            self.pipeline,
            dynamic_skills_dir=self.dynamic_dir,
            state_store=self.state_store,
        )
        self.installed_hash = self.install_source(INSTALLED_SOURCE)
        self.state_store.save(SKILL_NAME, {})
        self.confirmation_number = 0

    def _next_confirmation(self) -> str:
        self.confirmation_number += 1
        return f"fresh-repair-{self.confirmation_number}"

    def install_source(self, source: str) -> str:
        encoded = source.encode("utf-8")
        source_hash = hashlib.sha256(encoded).hexdigest()
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_bytes(encoded)
        metadata = {
            "schema_version": DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
            "skill_name": SKILL_NAME,
            "source_hash": source_hash,
            "execution_action_name": EXECUTION_ACTION_NAME,
            "execution_target": execution_target_for(SKILL_NAME, source_hash),
        }
        (self.dynamic_dir / f"{SKILL_NAME}.skill.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        return source_hash

    def test_key_error_after_allow_and_hash_verification_is_repairable(self) -> None:
        result = make_execution_failure(source_hash=self.installed_hash)

        self.assertTrue(self.coordinator.is_repairable_failure(result))

    def test_internal_type_error_is_repairable(self) -> None:
        result = make_execution_failure(
            error="TypeError: invalid internal operation",
            source_hash=self.installed_hash,
        )

        self.assertTrue(self.coordinator.is_repairable_failure(result))

    def test_empty_state_keyerror_is_structured_by_real_child_worker(self) -> None:
        actual_execution = SafeSkillExecutionService(
            SkillDispatcher(SkillManager(), evaluator=self.evaluator, confirmation_ledger=self.ledger),
            dynamic_skills_dir=self.dynamic_dir,
            runtime=SubprocessDynamicSkillRuntime(
                project_root=PROJECT_ROOT,
                timeout_seconds=10,
            ),
            state_store=self.state_store,
        )
        pipeline = SafeSkillPipeline(
            self.fake_authoring,
            self.deployment,
            actual_execution,
            confirmation_id_factory=self._next_confirmation,
            now=lambda: NOW,
        )
        with patch.dict(os.environ, {"JARVIS_ENABLE_DYNAMIC_SKILLS": "true"}, clear=False):
            pending = pipeline.prepare_execution(
                SKILL_NAME,
                identity=self.owner,
                parameters={"comando": ORIGINAL_COMMAND},
            ).pending
            result = pipeline.confirm_execution(pending, identity=self.owner)

        self.assertFalse(result.executed)
        self.assertTrue(result.allowed)
        self.assertTrue(result.hash_verified)
        self.assertEqual(result.failure_kind, ExecutionFailureKind.SKILL_EXCEPTION)
        self.assertEqual(result.failure_reason, "KeyError: 'ultima_version'")
        self.assertEqual(result.runtime_state, {})
        self.assertTrue(self.coordinator.is_repairable_failure(result))

    def test_policy_deny_is_not_repairable(self) -> None:
        result = make_execution_failure(allowed=False, source_hash=self.installed_hash)

        self.assertFalse(self.coordinator.is_repairable_failure(result))

    def test_hash_mismatch_is_not_repairable(self) -> None:
        result = make_execution_failure(hash_verified=False, source_hash=self.installed_hash)

        self.assertFalse(self.coordinator.is_repairable_failure(result))

    def test_worker_infrastructure_and_timeout_are_not_repairable(self) -> None:
        for kind in (
            ExecutionFailureKind.RUNTIME_TIMEOUT,
            ExecutionFailureKind.WORKER_INFRASTRUCTURE,
            ExecutionFailureKind.PREFLIGHT,
            ExecutionFailureKind.POLICY,
        ):
            with self.subTest(kind=kind):
                self.assertFalse(self.coordinator.is_repairable_failure(
                    make_execution_failure(failure_kind=kind, source_hash=self.installed_hash)
                ))

    def test_metadata_invalid_is_not_repairable_and_blocks_context(self) -> None:
        (self.dynamic_dir / f"{SKILL_NAME}.skill.json").write_text("{}", encoding="utf-8")
        result = make_execution_failure(source_hash=self.installed_hash)

        prepared = self.coordinator.prepare_repair(
            result,
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertFalse(prepared.ready_for_confirmation)
        self.assertIn("source instalado", prepared.failure_reason)
        self.assertEqual(self.fake_authoring.requests, [])

    def test_repair_context_preserves_original_command_error_source_and_empty_state(self) -> None:
        result = make_execution_failure(
            error="KeyError: 'ultima_version'",
            source_hash=self.installed_hash,
            runtime_state={},
        )

        prepared = self.coordinator.prepare_repair(
            result,
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertTrue(prepared.ready_for_confirmation, prepared.failure_reason)
        context = prepared.context
        self.assertEqual(context.skill_name, SKILL_NAME)
        self.assertEqual(context.source_hash, self.installed_hash)
        self.assertEqual(context.original_command, ORIGINAL_COMMAND)
        self.assertEqual(context.runtime_error, "KeyError: 'ultima_version'")
        self.assertEqual(context.source_code, INSTALLED_SOURCE)
        self.assertEqual(context.current_state, {})
        rendered = context.to_authoring_context()
        self.assertIn("KeyError: 'ultima_version'", rendered)
        self.assertIn("Original user command (verbatim): " + ORIGINAL_COMMAND, rendered)
        self.assertIn("Initial\nstate may validly be {}", rendered)

    def test_context_bounds_runtime_streams_and_never_executes_them(self) -> None:
        result = replace(
            make_execution_failure(source_hash=self.installed_hash),
            stdout="x" * 12000,
            stderr="y" * 12000,
        )
        prepared = self.coordinator.prepare_repair(
            result,
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertEqual(len(prepared.context.stdout), 8000)
        self.assertEqual(len(prepared.context.stderr), 8000)
        self.assertEqual(len(self.fake_authoring.requests), 1)

    def test_authoring_uses_existing_skill_and_runtime_relevant_context(self) -> None:
        before_source = (self.dynamic_dir / f"{SKILL_NAME}.py").read_bytes()
        before_metadata = (self.dynamic_dir / f"{SKILL_NAME}.skill.json").read_bytes()
        prepared = self.coordinator.prepare_repair(
            make_execution_failure(source_hash=self.installed_hash, runtime_state={}),
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertTrue(prepared.ready_for_confirmation, prepared.failure_reason)
        authoring_request = self.fake_authoring.requests[0]
        self.assertEqual(authoring_request.existing_skill_name, SKILL_NAME)
        self.assertIn("KeyError: 'ultima_version'", authoring_request.relevant_context)
        self.assertIn("comando/optional estado ABI", authoring_request.relevant_context)
        self.assertIn("Verified source SHA-256", authoring_request.relevant_context)
        self.assertTrue(authoring_request.relevant_context.find(INSTALLED_SOURCE) >= 0)
        self.assertEqual((self.dynamic_dir / f"{SKILL_NAME}.py").read_bytes(), before_source)
        self.assertEqual((self.dynamic_dir / f"{SKILL_NAME}.skill.json").read_bytes(), before_metadata)

    def test_authoring_failure_returns_controlled_reason(self) -> None:
        self.fake_authoring.proposal_source = None

        prepared = self.coordinator.prepare_repair(
            make_execution_failure(source_hash=self.installed_hash),
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertFalse(prepared.ready_for_confirmation)
        self.assertIn("fake authoring failure", prepared.failure_reason)

    def test_repair_uses_full_existing_authoring_validation_review_and_tests_pipeline(self) -> None:
        from test_source_repair_unchanged import service_with, source_response, TESTS

        repair_name = "repair_skill"
        original_request = "Return the version and remember previous queries."
        existing_source = "def ejecutar_skill(comando=''):\n    return {}\n"
        repaired_source = (
            "def ejecutar_skill(comando='', estado=None):\n"
            "    estado = dict(estado or {})\n"
            "    return {'__jarvis_data__': {'version': estado.get('version', 'v2')}, "
            "'__jarvis_state__': {'version': estado.get('version', 'v2')}}\n"
        )
        dynamic_dir = self.root / "full-authoring-skills"
        dynamic_dir.mkdir()
        source_hash = self.install_named_source(dynamic_dir, repair_name, existing_source)
        authoring_service, coder, _router, reviewer = service_with(
            [source_response(repaired_source), TESTS],
            [json.dumps({"approved": True, "blocking_issues": [], "advisory_issues": []})],
        )
        deployment = SafeSkillDeploymentService(
            dynamic_skills_dir=dynamic_dir,
            evaluator=self.evaluator,
            confirmation_ledger=self.ledger,
        )
        pipeline = SafeSkillPipeline(
            authoring_service,
            deployment,
            self.execution,
            confirmation_id_factory=self._next_confirmation,
            now=lambda: NOW,
        )
        coordinator = DynamicSkillRepairCoordinator(
            pipeline,
            dynamic_skills_dir=dynamic_dir,
            state_store=self.state_store,
        )
        failed = replace(
            make_execution_failure(source_hash=source_hash, runtime_state={}),
            skill_name=repair_name,
            action=SecurityAction(
                action=EXECUTION_ACTION_NAME,
                description="Execute dynamic skill",
                target=execution_target_for(repair_name, source_hash),
                metadata={"skill_name": repair_name, "source_hash": source_hash},
            ),
        )

        prepared = coordinator.prepare_repair(
            failed,
            original_command=original_request,
            identity=self.owner,
        )

        self.assertTrue(prepared.ready_for_confirmation, prepared.failure_reason)
        self.assertEqual(len(coder.prompts), 2)
        self.assertEqual(len(reviewer.requests), 1)
        self.assertTrue(all(report.success for report in prepared.pending_installation.authoring_result.validation_reports))
        self.assertTrue(prepared.pending_installation.authoring_result.review_results[-1].approved)
        self.assertIn("EXISTING SKILL REFERENCE", coder.prompts[0])
        self.assertIn(repair_name, coder.prompts[0])
        self.assertEqual(
            (dynamic_dir / f"{repair_name}.py").read_text(encoding="utf-8"),
            existing_source,
        )

    def install_named_source(self, directory: Path, skill_name: str, source: str) -> str:
        encoded = source.encode("utf-8")
        source_hash = hashlib.sha256(encoded).hexdigest()
        (directory / f"{skill_name}.py").write_bytes(encoded)
        (directory / f"{skill_name}.skill.json").write_text(
            json.dumps({
                "schema_version": DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
                "skill_name": skill_name,
                "source_hash": source_hash,
                "execution_action_name": EXECUTION_ACTION_NAME,
                "execution_target": execution_target_for(skill_name, source_hash),
            }),
            encoding="utf-8",
        )
        return source_hash

    def test_deployment_preparation_requires_confirmation_and_writes_nothing(self) -> None:
        prepared = self.coordinator.prepare_repair(
            make_execution_failure(source_hash=self.installed_hash),
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertTrue(prepared.ready_for_confirmation)
        self.assertEqual(
            prepared.installation_preparation.deployment_result.decision.kind,
            PolicyDecisionKind.REQUIRE_CONFIRMATION,
        )
        self.assertEqual(
            (self.dynamic_dir / f"{SKILL_NAME}.py").read_text(encoding="utf-8"),
            INSTALLED_SOURCE,
        )

    def test_deployment_confirmation_is_not_execution_confirmation(self) -> None:
        prepared = self.coordinator.prepare_repair(
            make_execution_failure(source_hash=self.installed_hash),
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )
        deployed = self.pipeline.confirm_installation(
            prepared.pending_installation,
            identity=self.owner,
        )
        self.assertTrue(deployed.installed, deployed.failure_reason)

        execution_preparation = self.pipeline.prepare_execution(
            SKILL_NAME,
            identity=self.owner,
            parameters={"comando": ORIGINAL_COMMAND},
        )

        self.assertTrue(execution_preparation.confirmation_required)
        self.assertFalse(execution_preparation.execution_result.executed)
        self.assertEqual(self.runtime.calls, [])
        self.assertEqual(execution_preparation.pending.parameters["comando"], ORIGINAL_COMMAND)

    def test_retry_confirmation_uses_a_new_fresh_confirmation_and_original_command(self) -> None:
        prepared = self.coordinator.prepare_repair(
            make_execution_failure(source_hash=self.installed_hash),
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )
        deployment_result = self.pipeline.confirm_installation(
            prepared.pending_installation,
            identity=self.owner,
        )
        retry_pending = self.pipeline.prepare_execution(
            SKILL_NAME,
            identity=self.owner,
            parameters={"comando": ORIGINAL_COMMAND},
        ).pending
        retry_result = self.pipeline.confirm_execution(retry_pending, identity=self.owner)

        self.assertTrue(deployment_result.installed)
        self.assertTrue(retry_result.executed)
        self.assertEqual(retry_result.action.metadata["parameters"], {"comando": ORIGINAL_COMMAND})
        confirmation_ids = retry_result.policy_decision.confirmation_ids_to_consume
        self.assertEqual(confirmation_ids, ("fresh-repair-2",))

    def test_repair_retry_records_new_hash_and_preserves_original_command(self) -> None:
        retry = PendingDynamicSkillRepairRetry(
            skill_name=SKILL_NAME,
            failed_source_hash=self.installed_hash,
            installed_source_hash=hashlib.sha256(REPAIRED_SOURCE.encode("utf-8")).hexdigest(),
            original_command=ORIGINAL_COMMAND,
        )

        self.assertEqual(retry.original_command, ORIGINAL_COMMAND)
        self.assertNotEqual(retry.failed_source_hash, retry.installed_source_hash)

    def test_old_session_grant_does_not_authorize_new_hash(self) -> None:
        grants = SessionSkillGrantStore()
        new_hash = hashlib.sha256(REPAIRED_SOURCE.encode("utf-8")).hexdigest()
        grants.grant(SKILL_NAME, self.installed_hash, self.owner.user_id)

        self.assertIsNone(grants.authorization_for(SKILL_NAME, new_hash, self.owner.user_id))

    def test_main_invalidates_old_grant_and_retry_uses_original_command(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("session_skill_grants.revoke(", source)
        self.assertIn("failed_source_hash=repair_context.source_hash", source)
        self.assertIn('parameters={"comando": repair_context.original_command}', source)
        self.assertIn("pending_dynamic_skill_repair_retry", source)

    def test_main_does_not_repair_retry_failure_again(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        retry_guard = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "repair_retry is not None"
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "intentar_autorreparacion_dynamic_skill"
                for statement in retry_guard.body
                for node in ast.walk(statement)
            )
        )
        self.assertIn("La skill sigue fallando después de la reparación automática", source)

    def test_user_refusal_does_not_call_installation_or_repair(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        refusal = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "not confirmation_choice"
            and any(
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and "Instalacion de la reparacion cancelada" in child.value
                for statement in node.body
                for child in ast.walk(statement)
            )
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "confirm_installation"
                for statement in refusal.body
                for node in ast.walk(statement)
            )
        )

    def test_user_refusal_of_execution_never_starts_repair(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        refusal = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "not confirmation_choice"
            and any(
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and "Ejecucion de skill cancelada" in child.value
                for statement in node.body
                for child in ast.walk(statement)
            )
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "intentar_autorreparacion_dynamic_skill"
                for statement in refusal.body
                for node in ast.walk(statement)
            )
        )

    def test_successful_retry_uses_the_normal_dynamic_skill_response_helper(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn("def responder_dynamic_skill(", source)
        self.assertIn("synthesize_dynamic_skill_response(", source)
        self.assertIn("responder_dynamic_skill(\n                            repair_context.skill_name", source)

    def test_state_empty_direct_index_is_diagnosed_without_skill_specific_rules(self) -> None:
        report = LocalSkillValidator().validate_dynamic_skill_source(
            INSTALLED_SOURCE,
            user_request=(
                ORIGINAL_COMMAND
                + "\nCross-execution state is needed. Initial state may validly be {}."
            ),
        )

        persistence = next(
            check for check in report.checks if check.name == "dynamic_persistence_state"
        )
        self.assertFalse(persistence.success)
        self.assertIn("ultima_version", persistence.details)
        self.assertIn("KeyError", persistence.details)

    def test_repair_does_not_clear_existing_state(self) -> None:
        store = DynamicSkillStateStore(self.root / "data" / "dynamic_skill_state")
        existing_state = {"ultima_version": "1.0", "last_checked": "yesterday"}
        store.save(SKILL_NAME, existing_state)
        before = store.load(SKILL_NAME)

        self.coordinator.prepare_repair(
            make_execution_failure(source_hash=self.installed_hash, runtime_state=before),
            original_command=ORIGINAL_COMMAND,
            identity=self.owner,
        )

        self.assertEqual(store.load(SKILL_NAME), existing_state)


class LocalSkillValidator:
    """Use the real validator under an explicit local alias for this test."""

    def validate_dynamic_skill_source(self, source, *, user_request):
        from jarvis.core.code_validation import LocalCodeValidator

        return LocalCodeValidator().validate_dynamic_skill_source(
            source,
            user_request=user_request,
        )


if __name__ == "__main__":
    unittest.main()
