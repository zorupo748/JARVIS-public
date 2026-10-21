from __future__ import annotations

from datetime import datetime, timezone
import unittest

from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    AuthorizedTask,
    ConfirmationLedger,
    DecisionReason,
    DeterministicPolicyEvaluator,
    FreshConfirmation,
    IdentityContext,
    PolicyDecisionKind,
    PolicyRequest,
    PresenceState,
    VerifiedFactor,
)


NOW = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)


def action(name: str, target: str | None = None, **metadata: object) -> SecurityAction:
    return SecurityAction(
        action=name,
        description="policy test action",
        target=target,
        metadata=metadata,
    )


def person(
    user_id: str,
    level: SecurityLevel,
    *,
    owner: bool = False,
    display_name: str | None = None,
) -> UserIdentity:
    return UserIdentity(
        user_id=user_id,
        display_name=display_name or user_id.title(),
        security_level=level,
        is_owner=owner,
    )


def verified_owner(
    level: SecurityLevel,
    *,
    user_id: str = "owner-42",
    presence: PresenceState = PresenceState.PRESENT,
    factors: set[VerifiedFactor] | None = None,
) -> IdentityContext:
    return IdentityContext(
        identity=person(user_id, level, owner=True),
        presence=presence,
        verified_factors=frozenset(factors if factors is not None else {VerifiedFactor.OWNER_VOICE}),
    )


def confirmation(identifier: str, requested_action: SecurityAction, context: IdentityContext) -> FreshConfirmation:
    assert context.user_id is not None
    return FreshConfirmation(
        confirmation_id=identifier,
        action_name=requested_action.action,
        user_id=context.user_id,
        target=requested_action.target,
        confirmed_at=NOW,
    )


class DeterministicSecurityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evaluator = DeterministicPolicyEvaluator(now=lambda: NOW)

    def evaluate(self, requested_action: SecurityAction, context: IdentityContext, **kwargs: object):
        return self.evaluator.evaluate(PolicyRequest(requested_action, context, **kwargs))

    def test_unknown_voice_starts_at_level_zero(self) -> None:
        unknown = IdentityContext.unknown_voice()

        self.assertEqual(unknown.effective_level, SecurityLevel.LEVEL_0)
        self.assertTrue(self.evaluate(action("buscar_en_internet"), unknown).allowed)

    def test_unknown_voice_cannot_assign_itself_a_level(self) -> None:
        unknown = IdentityContext.unknown_voice()
        decision = self.evaluate(
            action("asignar_identidad_nivel"),
            unknown,
            identity_assignment=person("unknown", SecurityLevel.LEVEL_2),
        )

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)

    def test_only_verified_owner_can_assign_identity_and_level(self) -> None:
        requested = action("asignar_identidad_nivel")
        assignment = person("alex", SecurityLevel.LEVEL_2)
        unverified_owner = IdentityContext(
            identity=person("owner-42", SecurityLevel.LEVEL_3, owner=True),
            presence=PresenceState.PRESENT,
        )

        denied = self.evaluate(requested, unverified_owner, identity_assignment=assignment)
        self.assertEqual(denied.reason, DecisionReason.OWNER_VERIFICATION_REQUIRED)

        owner = verified_owner(SecurityLevel.LEVEL_3)
        allowed = self.evaluate(
            requested,
            owner,
            identity_assignment=assignment,
            confirmations=(confirmation("identity-1", requested, owner),),
        )
        self.assertTrue(allowed.allowed)

    def test_non_owner_never_receives_level_three_or_higher(self) -> None:
        requested = action("asignar_identidad_nivel")
        owner = verified_owner(SecurityLevel.LEVEL_3)
        decision = self.evaluate(
            requested,
            owner,
            identity_assignment=person("alex", SecurityLevel.LEVEL_3),
            confirmations=(confirmation("identity-2", requested, owner),),
        )

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.NON_OWNER_LEVEL_CAP)

        forged_context = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_5),
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_VOICE}),
        )
        self.assertEqual(forged_context.effective_level, SecurityLevel.LEVEL_2)

    def test_owner_with_a_non_literal_identifier_can_receive_privileges(self) -> None:
        requested = action("iniciar_impresion")
        owner = verified_owner(SecurityLevel.LEVEL_4, user_id="principal-901")
        decision = self.evaluate(
            requested,
            owner,
            confirmations=(confirmation("owner-print", requested, owner),),
        )

        self.assertTrue(decision.allowed)

    def test_name_matching_diego_does_not_grant_privileges(self) -> None:
        named_diego = IdentityContext(
            identity=person("guest-17", SecurityLevel.LEVEL_5, display_name="Diego"),
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_VOICE}),
        )
        decision = self.evaluate(action("shell_exec"), named_diego)

        self.assertEqual(named_diego.effective_level, SecurityLevel.LEVEL_2)
        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)

    def test_unknown_skill_is_denied(self) -> None:
        decision = self.evaluate(action("unknown_skill"), IdentityContext.unknown_voice())

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.UNKNOWN_ACTION)

    def test_web_search_is_allowed_at_level_zero(self) -> None:
        decision = self.evaluate(action("buscar_en_internet"), IdentityContext.unknown_voice())

        self.assertEqual(decision.kind, PolicyDecisionKind.ALLOW)

    def test_local_read_is_denied_at_level_zero(self) -> None:
        decision = self.evaluate(
            action("leer_archivo_workspace", "workspace/readme.md"),
            IdentityContext.unknown_voice(),
        )

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.INSUFFICIENT_LEVEL)

    def test_level_two_non_owner_can_create_a_non_protected_file(self) -> None:
        level_two_user = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_2),
            presence=PresenceState.PRESENT,
        )
        decision = self.evaluate(action("crear_archivo", "workspace/new.txt"), level_two_user)

        self.assertTrue(decision.allowed)

    def test_level_two_non_owner_may_modify_only_after_fresh_confirmation(self) -> None:
        requested = action("modificar_archivo", "workspace/note.txt")
        level_two_user = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_2),
            presence=PresenceState.PRESENT,
        )
        pending = self.evaluate(requested, level_two_user)
        self.assertEqual(pending.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        self.assertEqual(pending.required_confirmations, 1)

        ledger = ConfirmationLedger()
        evaluator = DeterministicPolicyEvaluator(confirmation_ledger=ledger, now=lambda: NOW)
        proof = confirmation("modify-1", requested, level_two_user)
        allowed = evaluator.evaluate(PolicyRequest(requested, level_two_user, confirmations=(proof,)))
        self.assertTrue(allowed.allowed)
        self.assertTrue(ledger.consume(allowed))

        reused = evaluator.evaluate(PolicyRequest(requested, level_two_user, confirmations=(proof,)))
        self.assertEqual(reused.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        self.assertEqual(reused.reason, DecisionReason.CONFIRMATION_INVALID)

    def test_level_two_non_owner_cannot_delete_a_file(self) -> None:
        level_two_user = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_2),
            presence=PresenceState.PRESENT,
        )
        decision = self.evaluate(action("delete_file", "workspace/note.txt"), level_two_user)

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.INSUFFICIENT_LEVEL)

    def test_protected_information_requires_owner_and_confirmation(self) -> None:
        requested = action("guardar_hecho")
        non_owner = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_2),
            presence=PresenceState.PRESENT,
        )
        self.assertEqual(
            self.evaluate(requested, non_owner).reason,
            DecisionReason.INSUFFICIENT_LEVEL,
        )

        owner = verified_owner(SecurityLevel.LEVEL_3)
        pending = self.evaluate(requested, owner)
        self.assertEqual(pending.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        allowed = self.evaluate(
            requested,
            owner,
            confirmations=(confirmation("memory-1", requested, owner),),
        )
        self.assertTrue(allowed.allowed)

    def test_shell_is_denied_for_a_non_owner(self) -> None:
        other = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_5),
            presence=PresenceState.PRESENT,
        )
        decision = self.evaluate(action("shell_exec"), other)

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)

    def test_normal_print_requires_level_four_and_confirmation(self) -> None:
        requested = action("iniciar_impresion")
        level_three = verified_owner(SecurityLevel.LEVEL_3)
        self.assertEqual(
            self.evaluate(requested, level_three).reason,
            DecisionReason.INSUFFICIENT_LEVEL,
        )

        level_four = verified_owner(SecurityLevel.LEVEL_4)
        pending = self.evaluate(requested, level_four)
        self.assertEqual(pending.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)

        allowed = self.evaluate(
            requested,
            level_four,
            confirmations=(confirmation("print-1", requested, level_four),),
        )
        self.assertTrue(allowed.allowed)

    def test_emergency_stop_is_immediate_and_requires_audit(self) -> None:
        decision = self.evaluate(action("parada_emergencia"), IdentityContext.unknown_voice())

        self.assertTrue(decision.allowed)
        self.assertEqual(len(decision.audit_requirements), 1)
        self.assertEqual(decision.audit_requirements[0].event_code, "klipper_emergency_stop_requested")

    def test_c_drive_is_denied_when_any_owner_factor_is_missing(self) -> None:
        requested = action("file_read", r"C:\Users\owner\document.txt")
        all_factors = {
            VerifiedFactor.OWNER_VOICE,
            VerifiedFactor.OWNER_SECRET,
            VerifiedFactor.OWNER_FACE,
        }

        for missing_factor in all_factors:
            with self.subTest(missing_factor=missing_factor):
                context = verified_owner(
                    SecurityLevel.LEVEL_5,
                    factors=all_factors - {missing_factor},
                )
                decision = self.evaluate(requested, context)
                self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
                self.assertEqual(decision.reason, DecisionReason.C_DRIVE_OWNER_FACTORS_REQUIRED)

    def test_level_five_alone_does_not_allow_c_drive(self) -> None:
        requested = action("file_read", r"C:\Windows\example.txt")
        decision = self.evaluate(requested, verified_owner(SecurityLevel.LEVEL_5))

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.C_DRIVE_OWNER_FACTORS_REQUIRED)

    def test_level_three_does_not_allow_c_drive_even_with_all_factors(self) -> None:
        requested = action("file_read", r"C:\Users\owner\document.txt")
        context = verified_owner(
            SecurityLevel.LEVEL_3,
            factors={
                VerifiedFactor.OWNER_VOICE,
                VerifiedFactor.OWNER_SECRET,
                VerifiedFactor.OWNER_FACE,
            },
        )
        decision = self.evaluate(requested, context)

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.INSUFFICIENT_LEVEL)

    def test_c_drive_read_requires_two_fresh_confirmations(self) -> None:
        requested = action("file_read", r"C:\Users\owner\document.txt")
        context = verified_owner(
            SecurityLevel.LEVEL_5,
            factors={
                VerifiedFactor.OWNER_VOICE,
                VerifiedFactor.OWNER_SECRET,
                VerifiedFactor.OWNER_FACE,
            },
        )
        one_confirmation = self.evaluate(
            requested,
            context,
            confirmations=(confirmation("c-1", requested, context),),
        )
        self.assertEqual(one_confirmation.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        self.assertEqual(one_confirmation.required_confirmations, 2)

        two_confirmations = self.evaluate(
            requested,
            context,
            confirmations=(
                confirmation("c-1", requested, context),
                confirmation("c-2", requested, context),
            ),
        )
        self.assertTrue(two_confirmations.allowed)

    def test_learning_metadata_never_changes_permissions(self) -> None:
        learned_action = action(
            "guardar_hecho",
            learned_level=5,
            learned_authorization=True,
            remembered_owner="owner-42",
        )
        decision = self.evaluate(learned_action, IdentityContext.unknown_voice())

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.INSUFFICIENT_LEVEL)

    def test_absence_blocks_level_three_or_higher(self) -> None:
        requested = action("shell_exec")
        absent_owner = verified_owner(SecurityLevel.LEVEL_3, presence=PresenceState.ABSENT)
        decision = self.evaluate(
            requested,
            absent_owner,
            confirmations=(confirmation("shell-1", requested, absent_owner),),
        )

        self.assertEqual(decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(decision.reason, DecisionReason.PRESENCE_REQUIRED)

    def test_other_person_requires_reauthentication_for_continued_task(self) -> None:
        requested = action("subir_e_imprimir")
        task = AuthorizedTask(
            task_id="print-task",
            action_name="subir_e_imprimir",
            authorized_for_user_id="owner-42",
            authorized_by_verified_owner=True,
            may_continue_without_presence=True,
        )
        other_person = IdentityContext(
            identity=person("alex", SecurityLevel.LEVEL_0),
            presence=PresenceState.OTHER_PERSON_PRESENT,
        )
        decision = self.evaluate(requested, other_person, continuation_task=task)

        self.assertEqual(decision.kind, PolicyDecisionKind.REAUTHENTICATE)
        self.assertEqual(decision.reason, DecisionReason.TASK_REAUTHENTICATION_REQUIRED)

    def test_authorized_task_can_be_modeled_as_continuing_when_owner_is_absent(self) -> None:
        requested = action("subir_e_imprimir")
        task = AuthorizedTask(
            task_id="print-task",
            action_name="subir_e_imprimir",
            authorized_for_user_id="owner-42",
            authorized_by_verified_owner=True,
            may_continue_without_presence=True,
        )
        absent = IdentityContext(presence=PresenceState.ABSENT)
        decision = self.evaluate(requested, absent, continuation_task=task)

        self.assertTrue(decision.allowed)


    def test_owner_device_factor_can_verify_owner_identity(self) -> None:
        owner = UserIdentity(
            user_id="owner-device",
            display_name="Owner",
            security_level=SecurityLevel.LEVEL_3,
            is_owner=True,
        )
        context = IdentityContext(
            identity=owner,
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
        )

        self.assertTrue(context.is_verified_owner)
        self.assertEqual(context.effective_level, SecurityLevel.LEVEL_3)

    def test_owner_device_factor_never_promotes_a_non_owner(self) -> None:
        user = UserIdentity(
            user_id="ordinary-user",
            display_name="User",
            security_level=SecurityLevel.LEVEL_5,
            is_owner=False,
        )
        context = IdentityContext(
            identity=user,
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
        )

        self.assertFalse(context.is_verified_owner)
        self.assertEqual(context.effective_level, SecurityLevel.LEVEL_2)


if __name__ == "__main__":
    unittest.main()