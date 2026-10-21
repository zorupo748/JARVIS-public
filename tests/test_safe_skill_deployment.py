from __future__ import annotations

import hashlib
import json
import inspect
from datetime import datetime, timezone
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from jarvis.core.code_reviewer import CodeReviewResult
from jarvis.core.code_validation import ValidationCheck, ValidationReport
from jarvis.core.safe_skill_authoring import GeneratedSkillProposal, SkillAuthoringResult
from jarvis.core.safe_skill_deployment import (
    DEPLOYMENT_ACTION_NAME,
    EXECUTION_ACTION_NAME,
    SafeSkillDeploymentService,
    SkillDeploymentRequest,
)
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    ActionEffect,
    ActionPolicy,
    ConfirmationLedger,
    FreshConfirmation,
    DeterministicPolicyEvaluator,
    IdentityContext,
    PolicyDecisionKind,
    PresenceState,
    VerifiedFactor,
)


SOURCE = "def ejecutar_skill():\n    return 'proposal only'\n"
ORIGINAL_REQUEST = "Crea una skill para resumir un documento local."


def successful_validation() -> ValidationReport:
    return ValidationReport(
        success=True,
        checks=(ValidationCheck("syntax", True, "valid"),),
    )


def approved_review() -> CodeReviewResult:
    return CodeReviewResult(
        approved=True,
        issues=(),
        reviewer_used="fake",
        cloud_attempted=False,
        cloud_failed=False,
    )


def approved_authoring_result(
    *,
    name: str = "resumir_documento",
    source: str = SOURCE,
    unavailable_dependencies: tuple[str, ...] = (),
) -> SkillAuthoringResult:
    proposal = GeneratedSkillProposal(
        skill_name=name,
        source_code=source,
        implementation_summary="Resume el documento solicitado.",
        dependencies=("declared-package",) if unavailable_dependencies else (),
    )
    return SkillAuthoringResult(
        success=True,
        proposal=proposal,
        iterations=1,
        validation_reports=(successful_validation(),),
        review_results=(approved_review(),),
        declared_dependencies=proposal.dependencies,
        unavailable_dependencies=unavailable_dependencies,
    )


class SafeSkillDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.dynamic_dir = Path(self.temporary_dir.name) / "src" / "jarvis" / "skills" / "dynamic"

        self.ledger = ConfirmationLedger()
        deployment_policy = ActionPolicy(
            action_name=DEPLOYMENT_ACTION_NAME,
            required_level=SecurityLevel.LEVEL_3,
            effect=ActionEffect.MODIFY,
            requires_owner=True,
            requires_presence=True,
        )
        self.evaluator = DeterministicPolicyEvaluator(
            {DEPLOYMENT_ACTION_NAME: deployment_policy},
            confirmation_ledger=self.ledger,
        )
        self.service = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            evaluator=self.evaluator,
            confirmation_ledger=self.ledger,
        )
        owner = UserIdentity(
            user_id="owner-42",
            display_name="Propietario",
            security_level=SecurityLevel.LEVEL_3,
            is_owner=True,
        )
        self.identity = IdentityContext(
            identity=owner,
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_VOICE}),
        )

    def request(
        self,
        result: SkillAuthoringResult | None = None,
        *,
        authorized: bool = True,
        action_name: str = DEPLOYMENT_ACTION_NAME,
        confirmations: tuple[FreshConfirmation, ...] = (),
        replace_existing_source_hash: str | None = None,
    ) -> SkillDeploymentRequest:
        return SkillDeploymentRequest(
            authoring_result=result or approved_authoring_result(),
            identity=self.identity,
            explicit_authorization=authorized,
            policy_action=SecurityAction(action_name, "Deploy an approved proposal"),
            original_user_request=ORIGINAL_REQUEST,
            confirmations=confirmations,
            replace_existing_source_hash=replace_existing_source_hash,
        )

    def _fresh_deployment_confirmation(self, source_hash: str, confirmation_id: str) -> FreshConfirmation:
        return FreshConfirmation(
            confirmation_id=confirmation_id,
            action_name=DEPLOYMENT_ACTION_NAME,
            user_id="owner-42",
            target=f"dynamic/resumir_documento.py#sha256-{source_hash}",
            confirmed_at=datetime.now(timezone.utc),
        )

    def test_approved_authoring_result_can_be_staged_but_not_activated(self) -> None:
        result = self.service.stage(self.request())
        self.assertTrue(result.success)
        self.assertFalse(result.installed)
        self.assertIsNotNone(result.staged)
        self.assertFalse((self.dynamic_dir / "resumir_documento.py").exists())

    def test_failed_authoring_result_is_rejected(self) -> None:
        authoring = replace(approved_authoring_result(), success=False)
        result = self.service.deploy(self.request(authoring))
        self.assertFalse(result.success)
        self.assertIn("Authoring", result.failure_reason or "")

    def test_unsuccessful_final_validation_is_rejected(self) -> None:
        invalid_report = ValidationReport(
            success=False,
            checks=(ValidationCheck("syntax", False, "invalid"),),
        )
        authoring = replace(approved_authoring_result(), validation_reports=(invalid_report,))
        result = self.service.deploy(self.request(authoring))
        self.assertFalse(result.success)
        self.assertIn("validation", result.failure_reason or "")

    def test_unapproved_final_review_is_rejected(self) -> None:
        review = replace(approved_review(), approved=False)
        authoring = replace(approved_authoring_result(), review_results=(review,))
        result = self.service.deploy(self.request(authoring))
        self.assertFalse(result.success)
        self.assertIn("review", result.failure_reason or "")

    def test_unavailable_dependencies_are_rejected_without_installing_them(self) -> None:
        authoring = approved_authoring_result(unavailable_dependencies=("missing-package",))
        with patch("subprocess.run") as install_package:
            result = self.service.deploy(self.request(authoring))
        self.assertFalse(result.success)
        self.assertIn("dependencies", result.failure_reason or "")
        install_package.assert_not_called()

    def test_explicit_authorization_is_independent_from_code_review(self) -> None:
        result = self.service.deploy(self.request(authorized=False))
        self.assertFalse(result.success)
        self.assertTrue(result.authorization_required)
        self.assertFalse(result.policy_prepared)

    def test_authorized_request_with_valid_policy_can_install(self) -> None:
        result = self.service.deploy(self.request())
        self.assertTrue(result.success)
        self.assertTrue(result.installed)
        self.assertTrue(result.policy_registered)
        self.assertEqual((self.dynamic_dir / "resumir_documento.py").read_text(encoding="utf-8"), SOURCE)

    def test_normal_skill_name_and_destination_are_confined_to_dynamic_directory(self) -> None:
        result = self.service.stage(self.request())
        self.assertTrue(result.success)
        self.assertEqual(result.skill_name, "resumir_documento")
        self.assertIsNotNone(result.destination)
        self.assertEqual(result.destination.parent.resolve(), self.dynamic_dir.resolve())

    def test_path_traversal_absolute_paths_and_separators_are_rejected(self) -> None:
        for unsafe_name in ("../../main", "..\\security\\policy", "C:\\algo", "/foo", "nested/name", "nested\\name"):
            with self.subTest(unsafe_name=unsafe_name):
                authoring = approved_authoring_result(name=unsafe_name)
                result = self.service.deploy(self.request(authoring))
                self.assertFalse(result.success)
                self.assertFalse(result.installed)
                self.assertFalse((self.dynamic_dir / "main.py").exists())

    def test_staging_binds_the_exact_source_hash_and_original_request(self) -> None:
        result = self.service.stage(self.request())
        self.assertTrue(result.success)
        self.assertIsNotNone(result.staged)
        staged = result.staged
        self.assertEqual(staged.source_hash, hashlib.sha256(SOURCE.encode("utf-8")).hexdigest())
        self.assertEqual(staged.original_user_request, ORIGINAL_REQUEST)
        self.assertIn(staged.source_hash, staged.policy_target)

    def test_hash_mismatch_after_authorization_is_detected_before_write(self) -> None:
        real_hash = self.service._source_hash
        with patch.object(self.service, "_source_hash", side_effect=[real_hash(SOURCE), "changed"]):
            result = self.service.deploy(self.request())
        self.assertFalse(result.success)
        self.assertFalse(result.installed)
        self.assertIn("SHA-256", result.failure_reason or "")
        self.assertFalse((self.dynamic_dir / "resumir_documento.py").exists())

    def test_installation_writes_atomically_and_leaves_no_temporary_file(self) -> None:
        result = self.service.deploy(self.request())
        self.assertTrue(result.success)
        self.assertEqual((self.dynamic_dir / "resumir_documento.py").read_text(encoding="utf-8"), SOURCE)
        self.assertEqual(list(self.dynamic_dir.glob(".resumir_documento.py.*.tmp")), [])

    def test_installation_persists_hash_bound_execution_metadata(self) -> None:
        result = self.service.deploy(self.request())
        self.assertTrue(result.success)
        payload = json.loads(
            (self.dynamic_dir / "resumir_documento.skill.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["skill_name"], "resumir_documento")
        self.assertEqual(payload["source_hash"], result.source_hash)
        self.assertEqual(payload["execution_action_name"], EXECUTION_ACTION_NAME)
        self.assertIn(result.source_hash or "", payload["execution_target"])
    def test_write_failure_cleans_the_temporary_file(self) -> None:
        with patch("jarvis.core.safe_skill_deployment.os.link", side_effect=OSError("disk full")):
            result = self.service.deploy(self.request())
        self.assertFalse(result.success)
        self.assertFalse(result.installed)
        self.assertEqual(list(self.dynamic_dir.glob(".resumir_documento.py.*.tmp")), [])

    def test_existing_skill_is_a_conflict_and_is_never_overwritten(self) -> None:
        self.dynamic_dir.mkdir(parents=True)
        destination = self.dynamic_dir / "resumir_documento.py"
        destination.write_text("ORIGINAL", encoding="utf-8")
        result = self.service.deploy(self.request())
        self.assertFalse(result.success)
        self.assertTrue(result.conflict)
        self.assertEqual(destination.read_text(encoding="utf-8"), "ORIGINAL")

    def test_repair_replacement_requires_old_hash_and_fresh_new_hash_confirmation(self) -> None:
        repaired_source = "def ejecutar_skill():\n    return 'repaired'\n"
        old_hash = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
        new_hash = hashlib.sha256(repaired_source.encode("utf-8")).hexdigest()
        ledger = ConfirmationLedger()
        service = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            confirmation_ledger=ledger,
        )
        installed = service.deploy(self.request(
            approved_authoring_result(),
            confirmations=(self._fresh_deployment_confirmation(old_hash, "initial-install"),),
        ))
        self.assertTrue(installed.installed)

        repaired_authoring = approved_authoring_result(source=repaired_source)
        staged = service.stage(self.request(
            repaired_authoring,
            replace_existing_source_hash=old_hash,
        ))
        self.assertEqual(staged.decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        self.assertFalse(staged.installed)
        self.assertEqual((self.dynamic_dir / "resumir_documento.py").read_text(encoding="utf-8"), SOURCE)

        deployed = service.deploy(self.request(
            repaired_authoring,
            confirmations=(self._fresh_deployment_confirmation(new_hash, "repair-install"),),
            replace_existing_source_hash=old_hash,
        ))
        self.assertTrue(deployed.installed, deployed.failure_reason)
        self.assertEqual(deployed.source_hash, new_hash)
        self.assertEqual(
            (self.dynamic_dir / "resumir_documento.py").read_text(encoding="utf-8"),
            repaired_source,
        )

    def test_repair_replacement_fails_if_old_artifact_changes_after_stage(self) -> None:
        repaired_source = "def ejecutar_skill():\n    return 'repaired'\n"
        old_hash = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
        new_hash = hashlib.sha256(repaired_source.encode("utf-8")).hexdigest()
        ledger = ConfirmationLedger()
        service = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            confirmation_ledger=ledger,
        )
        self.assertTrue(service.deploy(self.request(
            approved_authoring_result(),
            confirmations=(self._fresh_deployment_confirmation(old_hash, "initial-install"),),
        )).installed)
        repaired_authoring = approved_authoring_result(source=repaired_source)
        staged = service.stage(self.request(
            repaired_authoring,
            replace_existing_source_hash=old_hash,
        ))
        self.assertEqual(staged.decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        destination = self.dynamic_dir / "resumir_documento.py"
        destination.write_text("external change", encoding="utf-8")

        deployed = service.deploy(self.request(
            repaired_authoring,
            confirmations=(self._fresh_deployment_confirmation(new_hash, "repair-install"),),
            replace_existing_source_hash=old_hash,
        ))

        self.assertFalse(deployed.installed)
        self.assertTrue(deployed.conflict)
        self.assertEqual(destination.read_text(encoding="utf-8"), "external change")

    def test_default_policy_requires_a_source_bound_fresh_confirmation(self) -> None:
        source_hash = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
        target = f"dynamic/resumir_documento.py#sha256-{source_hash}"
        confirmation = FreshConfirmation(
            confirmation_id="deploy-confirmation",
            action_name=DEPLOYMENT_ACTION_NAME,
            user_id="owner-42",
            target=target,
            confirmed_at=datetime.now(timezone.utc),
        )
        default_ledger = ConfirmationLedger()
        default_service = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            confirmation_ledger=default_ledger,
        )
        result = default_service.deploy(self.request(confirmations=(confirmation,)))
        self.assertTrue(result.success)
        self.assertTrue(result.installed)
    def test_missing_or_unrelated_policy_is_rejected(self) -> None:
        empty_ledger = ConfirmationLedger()
        no_policy_service = SafeSkillDeploymentService(
            dynamic_skills_dir=self.dynamic_dir,
            evaluator=DeterministicPolicyEvaluator({}, confirmation_ledger=empty_ledger),
            confirmation_ledger=empty_ledger,
        )
        result = no_policy_service.deploy(self.request())
        self.assertFalse(result.success)
        self.assertTrue(result.authorization_required)
        self.assertIn("unknown_action", result.failure_reason or "")

        unrelated = self.service.deploy(self.request(action_name="guardar_hecho"))
        self.assertFalse(unrelated.success)
        self.assertIn("dedicated", unrelated.failure_reason or "")

    def test_non_owner_or_unverified_identity_cannot_deploy(self) -> None:
        unknown = replace(self.request(), identity=IdentityContext.unknown_voice())
        result = self.service.deploy(unknown)
        self.assertFalse(result.success)
        self.assertTrue(result.authorization_required)

    def test_service_never_executes_imports_or_installs_candidate_code(self) -> None:
        with (
            patch("builtins.exec") as execute_candidate,
            patch("builtins.eval") as evaluate_candidate,
            patch("importlib.util.spec_from_file_location") as import_candidate,
            patch("subprocess.run") as install_package,
        ):
            result = self.service.deploy(self.request())
        self.assertTrue(result.success)
        execute_candidate.assert_not_called()
        evaluate_candidate.assert_not_called()
        import_candidate.assert_not_called()
        install_package.assert_not_called()

    def test_source_has_no_main_integration_or_runtime_activation_path(self) -> None:
        import jarvis.core.safe_skill_deployment as deployment_module

        source = inspect.getsource(deployment_module)
        for forbidden in (
            "exec(",
            "eval(",
            "importlib",
            "subprocess",
            "pip install",
            "DynamicSkillBuilder",
            "SkillManager",
            "dynamic_skill_authoring_enabled",
            "requests.",
            "klipper",
            "main.py",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()