from __future__ import annotations

import ast
import tempfile
import unittest
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from jarvis.core.code_reviewer import CodeReviewResult
from jarvis.core.code_validation import ValidationCheck, ValidationReport
from jarvis.core.dependency_resolver import DependencyResolver, DependencyStatus
from jarvis.core.safe_skill_authoring import (
    GeneratedSkillProposal,
    SkillAuthoringRequest,
    SkillAuthoringResult,
)
from jarvis.core.safe_skill_deployment import SafeSkillDeploymentService
from jarvis.core.safe_skill_execution import SafeSkillExecutionResult
from jarvis.core.safe_skill_pipeline import SafeSkillPipeline
from jarvis.identity.models import UserIdentity
from jarvis.security.models import SecurityAction
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import (
    ConfirmationLedger,
    DecisionReason,
    PolicyDecision,
    DeterministicPolicyEvaluator,
    IdentityContext,
    PolicyDecisionKind,
    PresenceState,
    VerifiedFactor,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
ORIGINAL_REQUEST = "crea una skill para resumir documentos locales"


def approved_authoring_result(
    *,
    dependencies: tuple[str, ...] = (),
    unavailable_dependencies: tuple[str, ...] = (),
) -> SkillAuthoringResult:
    return SkillAuthoringResult(
        success=True,
        proposal=GeneratedSkillProposal(
            skill_name="resumir_documentos",
            source_code="def ejecutar_skill():\n    return 'proposal only'\n",
            implementation_summary="Resume documentos locales.",
            dependencies=dependencies,
        ),
        iterations=1,
        validation_reports=(
            ValidationReport(
                success=True,
                checks=(ValidationCheck("syntax", True, "valid"),),
            ),
        ),
        review_results=(
            CodeReviewResult(
                approved=True,
                issues=(),
                reviewer_used="fake",
                cloud_attempted=False,
                cloud_failed=False,
            ),
        ),
        declared_dependencies=dependencies,
        unavailable_dependencies=unavailable_dependencies,
    )


class FakeAuthoringService:
    def __init__(self, result: SkillAuthoringResult) -> None:
        self.result = result
        self.requests: list[SkillAuthoringRequest] = []

    def author(self, request: SkillAuthoringRequest) -> SkillAuthoringResult:
        self.requests.append(request)
        return self.result


@dataclass
class FakeExecutionService:
    result: SafeSkillExecutionResult

    def __post_init__(self) -> None:
        self.requests = []

    def execute(self, request):
        self.requests.append(request)
        return self.result


class MainSafeSkillIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.dynamic_dir = Path(self.temporary_dir.name) / "dynamic"
        self.ledger = ConfirmationLedger()
        self.evaluator = DeterministicPolicyEvaluator(
            confirmation_ledger=self.ledger,
            now=lambda: NOW,
        )
        self.deployment = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            evaluator=self.evaluator,
            confirmation_ledger=self.ledger,
        )
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
        self.unknown = IdentityContext.unknown_voice()

    def pipeline(
        self,
        authoring_result: SkillAuthoringResult | None = None,
        execution_result: SafeSkillExecutionResult | None = None,
    ) -> tuple[SafeSkillPipeline, FakeAuthoringService, FakeExecutionService]:
        authoring = FakeAuthoringService(authoring_result or approved_authoring_result())
        execution = FakeExecutionService(
            execution_result
            or SafeSkillExecutionResult(
                executed=False,
                allowed=False,
                skill_name="resumir_documentos",
                result=None,
                policy_decision=None,
                hash_verified=False,
                failure_reason="metadata missing",
            )
        )
        return (
            SafeSkillPipeline(
                authoring,
                self.deployment,
                execution,
                confirmation_id_factory=lambda: "fresh-confirmation",
                now=lambda: NOW,
            ),
            authoring,
            execution,
        )

    def test_authoring_receives_the_original_request_verbatim(self) -> None:
        pipeline, authoring, _execution = self.pipeline()
        result = pipeline.author(ORIGINAL_REQUEST)
        self.assertTrue(result.success)
        self.assertEqual(authoring.requests[0].user_request, ORIGINAL_REQUEST)

    def test_failed_authoring_never_reaches_deployment(self) -> None:
        failed = replace(approved_authoring_result(), success=False, proposal=None)
        pipeline, _authoring, _execution = self.pipeline(failed)
        result = pipeline.author(ORIGINAL_REQUEST)
        preparation = pipeline.prepare_installation(
            result,
            original_user_request=ORIGINAL_REQUEST,
            identity=self.owner,
        )
        self.assertIsNone(preparation.pending)
        self.assertFalse(preparation.deployment_result.installed)

    def test_approved_authoring_requires_a_fresh_policy_confirmation(self) -> None:
        pipeline, _authoring, _execution = self.pipeline()
        preparation = pipeline.prepare_installation(
            pipeline.author(ORIGINAL_REQUEST),
            original_user_request=ORIGINAL_REQUEST,
            identity=self.owner,
        )
        self.assertTrue(preparation.confirmation_required)
        self.assertIsNotNone(preparation.pending)
        self.assertEqual(
            preparation.deployment_result.decision.kind,
            PolicyDecisionKind.REQUIRE_CONFIRMATION,
        )
        self.assertFalse((self.dynamic_dir / "resumir_documentos.py").exists())

    def test_valid_confirmation_is_evaluated_by_policy_and_installs_without_execution(self) -> None:
        pipeline, _authoring, execution = self.pipeline()
        preparation = pipeline.prepare_installation(
            pipeline.author(ORIGINAL_REQUEST),
            original_user_request=ORIGINAL_REQUEST,
            identity=self.owner,
        )
        result = pipeline.confirm_installation(preparation.pending, identity=self.owner)
        self.assertTrue(result.installed)
        self.assertTrue((self.dynamic_dir / "resumir_documentos.py").is_file())
        self.assertTrue((self.dynamic_dir / "resumir_documentos.skill.json").is_file())
        self.assertEqual(execution.requests, [])

    def test_unknown_identity_is_denied_before_a_confirmation_is_pending(self) -> None:
        pipeline, _authoring, _execution = self.pipeline()
        preparation = pipeline.prepare_installation(
            pipeline.author(ORIGINAL_REQUEST),
            original_user_request=ORIGINAL_REQUEST,
            identity=self.unknown,
        )
        self.assertIsNone(preparation.pending)
        self.assertEqual(preparation.deployment_result.decision.kind, PolicyDecisionKind.DENY)

    def test_missing_dependencies_never_reach_installation(self) -> None:
        result = approved_authoring_result(
            dependencies=("missing-package",),
            unavailable_dependencies=("missing-package",),
        )
        pipeline, _authoring, _execution = self.pipeline(result)
        preparation = pipeline.prepare_installation(
            pipeline.author(ORIGINAL_REQUEST),
            original_user_request=ORIGINAL_REQUEST,
            identity=self.owner,
        )
        self.assertIsNone(preparation.pending)
        self.assertFalse((self.dynamic_dir / "resumir_documentos.py").exists())

    def test_available_dependency_reaches_policy_preflight_without_installing(self) -> None:
        checker = DependencyResolver(
            distribution_version=lambda _name: "2.34.2",
            find_spec=lambda _name: object(),
            packages_distributions=lambda: {"requests": ["requests"]},
        )
        resolved = checker.resolve("requests")
        self.assertEqual(resolved.status, DependencyStatus.AVAILABLE)
        result = replace(
            approved_authoring_result(dependencies=("requests",)),
            dependency_results=(resolved,),
        )
        pipeline, _authoring, _execution = self.pipeline(result)
        preparation = pipeline.prepare_installation(
            pipeline.author(ORIGINAL_REQUEST),
            original_user_request=ORIGINAL_REQUEST,
            identity=self.owner,
        )
        self.assertTrue(preparation.confirmation_required)
        self.assertIsNotNone(preparation.pending)
        self.assertFalse((self.dynamic_dir / "resumir_documentos.py").exists())

    def test_existing_skill_execution_is_delegated_to_safe_execution_only(self) -> None:
        expected = SafeSkillExecutionResult(
            executed=False,
            allowed=False,
            skill_name="resumir_documentos",
            result=None,
            policy_decision=None,
            hash_verified=False,
            failure_reason="source hash mismatch",
        )
        pipeline, _authoring, execution = self.pipeline(execution_result=expected)
        result = pipeline.execute_installed(
            "resumir_documentos",
            identity=self.unknown,
            parameters={"query": "documento"},
        )
        self.assertIs(result, expected)
        self.assertEqual(execution.requests[0].skill_name, "resumir_documentos")
        self.assertEqual(execution.requests[0].parameters, {"query": "documento"})

    def test_existing_execution_confirmation_is_bound_to_the_verified_action(self) -> None:
        action = SecurityAction(
            action="execute_dynamic_skill",
            description="Execute installed dynamic skill",
            target="dynamic/resumir_documentos.py#sha256-" + "a" * 64,
        )
        pending_result = SafeSkillExecutionResult(
            executed=False,
            allowed=False,
            skill_name="resumir_documentos",
            result=None,
            policy_decision=PolicyDecision(
                kind=PolicyDecisionKind.REQUIRE_CONFIRMATION,
                reason=DecisionReason.CONFIRMATION_REQUIRED,
                action_name=action.action,
                policy=None,
                required_confirmations=1,
            ),
            hash_verified=True,
            failure_reason="confirmation required",
            action=action,
        )
        pipeline, _authoring, execution = self.pipeline(execution_result=pending_result)
        preparation = pipeline.prepare_execution(
            "resumir_documentos",
            identity=self.owner,
            parameters={"query": "estado"},
        )
        self.assertTrue(preparation.confirmation_required)
        self.assertIsNotNone(preparation.pending)

        execution.result = SafeSkillExecutionResult(
            executed=True,
            allowed=True,
            skill_name="resumir_documentos",
            result="ok",
            policy_decision=None,
            hash_verified=True,
        )
        confirmed = pipeline.confirm_execution(preparation.pending, identity=self.owner)
        self.assertTrue(confirmed.executed)
        confirmation = execution.requests[-1].confirmations[0]
        self.assertEqual(confirmation.action_name, action.action)
        self.assertEqual(confirmation.target, action.target)
        self.assertEqual(confirmation.user_id, self.owner.user_id)
    def test_main_routes_skill_commands_without_legacy_builder_or_runtime(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertIn("safe_skill_pipeline.author", source)
        self.assertIn("safe_skill_pipeline.prepare_installation", source)
        self.assertIn("safe_skill_pipeline.confirm_installation", source)
        self.assertIn("safe_skill_pipeline.execute_installed", source)
        self.assertIn("safe_skill_pipeline.prepare_execution", source)
        self.assertIn("safe_skill_pipeline.confirm_execution", source)
        self.assertIn('usuario_limpio.lower().startswith("/skill ")', source)
        self.assertNotIn("DynamicSkillBuilder", source)
        self.assertNotIn("generate_and_load_skill", source)
        self.assertNotIn("reparar_skill_en_runtime", source)
        self.assertNotIn("execute_existing_dynamic_skill", source)
        self.assertNotIn("pip install", source)
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"exec", "eval"}
                for node in ast.walk(tree)
            )
        )

    def test_console_input_voice_and_interrupt_primitives_remain_in_main(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        for required in (
            "pending_inputs",
            "console_prompt_active",
            "InputSource.LOCAL_CONSOLE",
            "stt.capture()",
            "ejecutar_cancelable",
            "if not texto and not console_prompt_active.is_set()",
            "cancel_event.set()",
        ):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
