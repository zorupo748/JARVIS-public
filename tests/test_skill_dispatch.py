from __future__ import annotations

from datetime import datetime, timezone
import sys
import ast
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

try:
    import apscheduler.schedulers.background  # type: ignore[import-not-found]
except ModuleNotFoundError:
    class _ApschedulerStub:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

    apscheduler = types.ModuleType("apscheduler")
    schedulers = types.ModuleType("apscheduler.schedulers")
    background = types.ModuleType("apscheduler.schedulers.background")
    triggers = types.ModuleType("apscheduler.triggers")
    cron = types.ModuleType("apscheduler.triggers.cron")
    interval = types.ModuleType("apscheduler.triggers.interval")
    setattr(background, "BackgroundScheduler", _ApschedulerStub)
    setattr(cron, "CronTrigger", _ApschedulerStub)
    setattr(interval, "IntervalTrigger", _ApschedulerStub)
    sys.modules.update(
        {
            "apscheduler": apscheduler,
            "apscheduler.schedulers": schedulers,
            "apscheduler.schedulers.background": background,
            "apscheduler.triggers": triggers,
            "apscheduler.triggers.cron": cron,
            "apscheduler.triggers.interval": interval,
        }
    )

from jarvis.identity.models import UserIdentity
from jarvis.scheduler.task_scheduler import TaskScheduler
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import (
    AuthorizedTask,
    ConfirmationLedger,
    DeterministicPolicyEvaluator,
    FreshConfirmation,
    IdentityContext,
    PolicyDecisionKind,
    PresenceState,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager


NOW = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)


class CapturingScheduler:
    def __init__(self) -> None:
        self.jobs: list[object] = []

    def add_job(self, callback, **_kwargs: object) -> None:
        self.jobs.append(callback)

    def get_jobs(self) -> list[object]:
        return self.jobs


class SkillDispatchTests(unittest.TestCase):
    def make_dispatcher(
        self,
        manager: SkillManager,
        *,
        skill_actions: dict[str, str] | None = None,
    ) -> SkillDispatcher:
        ledger = ConfirmationLedger()
        evaluator = DeterministicPolicyEvaluator(
            confirmation_ledger=ledger,
            now=lambda: NOW,
        )
        return SkillDispatcher(
            manager,
            evaluator=evaluator,
            confirmation_ledger=ledger,
            skill_actions=skill_actions or {
                "buscar_en_internet": "buscar_en_internet",
                "estado_impresora": "estado_impresora",
                "subir_e_imprimir": "subir_e_imprimir",
                "parada_emergencia": "parada_emergencia",
            },
            now=lambda: NOW,
        )

    @staticmethod
    def level_two_identity(user_id: str = "alex") -> IdentityContext:
        return IdentityContext(
            identity=UserIdentity(
                user_id=user_id,
                display_name=user_id,
                security_level=SecurityLevel.LEVEL_2,
            ),
            presence=PresenceState.PRESENT,
        )

    @staticmethod
    def confirmation(
        identifier: str,
        action_name: str,
        user_id: str,
        target: str,
    ) -> FreshConfirmation:
        return FreshConfirmation(
            confirmation_id=identifier,
            action_name=action_name,
            user_id=user_id,
            target=target,
            confirmed_at=NOW,
        )

    def test_unknown_skill_is_denied_without_invoking_callable(self) -> None:
        manager = SkillManager()
        callable_skill = Mock(return_value="must not run")
        manager.register_skill("unmapped", "test", callable_skill)

        result = self.make_dispatcher(manager).dispatch("unmapped")

        self.assertFalse(result.executed)
        self.assertEqual(result.decision.kind, PolicyDecisionKind.DENY)
        callable_skill.assert_not_called()

    def test_level_zero_skill_executes_with_unknown_identity(self) -> None:
        manager = SkillManager()
        callable_skill = Mock(return_value="search result")
        manager.register_skill("buscar_en_internet", "test", callable_skill)

        result = self.make_dispatcher(manager).dispatch(
            "buscar_en_internet", {"query": "consulta publica"}
        )

        self.assertTrue(result.executed)
        self.assertEqual(result.result, "search result")
        callable_skill.assert_called_once_with(query="consulta publica")

    def test_confirmation_pending_never_executes_the_callable(self) -> None:
        manager = SkillManager()
        callable_skill = Mock()
        manager.register_skill("modify_note", "test", callable_skill)
        dispatcher = self.make_dispatcher(
            manager,
            skill_actions={"modify_note": "modificar_archivo"},
        )

        result = dispatcher.dispatch(
            "modify_note",
            {"path": "workspace/note.txt"},
            identity=self.level_two_identity(),
        )

        self.assertFalse(result.executed)
        self.assertEqual(result.decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        pending_confirmation = result.pending_confirmation
        self.assertIsNotNone(pending_confirmation)
        assert pending_confirmation is not None
        self.assertEqual(pending_confirmation.required_confirmations, 1)
        callable_skill.assert_not_called()

    def test_deny_and_reauthenticate_never_execute_the_callable(self) -> None:
        manager = SkillManager()
        callable_skill = Mock()
        manager.register_skill("subir_e_imprimir", "test", callable_skill)
        dispatcher = self.make_dispatcher(manager)

        denied = dispatcher.dispatch("subir_e_imprimir")
        self.assertFalse(denied.executed)
        self.assertEqual(denied.decision.kind, PolicyDecisionKind.DENY)

        continuation = AuthorizedTask(
            task_id="task-1",
            action_name="subir_e_imprimir",
            authorized_for_user_id="owner-previously-verified",
            authorized_by_verified_owner=True,
            may_continue_without_presence=True,
        )
        reauthenticate = dispatcher.dispatch(
            "subir_e_imprimir",
            identity=IdentityContext(
                identity=UserIdentity(
                    user_id="other-person",
                    display_name="Other",
                    security_level=SecurityLevel.LEVEL_0,
                ),
                presence=PresenceState.OTHER_PERSON_PRESENT,
            ),
            continuation_task=continuation,
        )
        self.assertFalse(reauthenticate.executed)
        self.assertEqual(reauthenticate.decision.kind, PolicyDecisionKind.REAUTHENTICATE)
        callable_skill.assert_not_called()

    def test_confirmation_is_bound_to_user_action_target_and_single_use(self) -> None:
        manager = SkillManager()
        first_callable = Mock(return_value="modified")
        alias_callable = Mock(return_value="alias modified")
        manager.register_skill("modify_note", "test", first_callable)
        manager.register_skill("modify_alias", "test", alias_callable)
        dispatcher = self.make_dispatcher(
            manager,
            skill_actions={
                "modify_note": "modificar_archivo",
                "modify_alias": "modify_file",
            },
        )
        proof = self.confirmation(
            "confirmation-1",
            "modificar_archivo",
            "alex",
            "workspace/note.txt",
        )

        wrong_user = dispatcher.dispatch(
            "modify_note",
            {"path": "workspace/note.txt"},
            identity=self.level_two_identity("other"),
            confirmations=(proof,),
        )
        wrong_action = dispatcher.dispatch(
            "modify_alias",
            {"path": "workspace/note.txt"},
            identity=self.level_two_identity(),
            confirmations=(proof,),
        )
        wrong_target = dispatcher.dispatch(
            "modify_note",
            {"path": "workspace/other.txt"},
            identity=self.level_two_identity(),
            confirmations=(proof,),
        )

        for result in (wrong_user, wrong_action, wrong_target):
            self.assertFalse(result.executed)
            self.assertEqual(result.decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)

        allowed = dispatcher.dispatch(
            "modify_note",
            {"path": "workspace/note.txt"},
            identity=self.level_two_identity(),
            confirmations=(proof,),
        )
        reused = dispatcher.dispatch(
            "modify_note",
            {"path": "workspace/note.txt"},
            identity=self.level_two_identity(),
            confirmations=(proof,),
        )

        self.assertTrue(allowed.executed)
        self.assertFalse(reused.executed)
        self.assertEqual(reused.decision.kind, PolicyDecisionKind.REQUIRE_CONFIRMATION)
        first_callable.assert_called_once_with(path="workspace/note.txt")
        alias_callable.assert_not_called()

    def test_scheduler_dispatches_through_the_same_policy_boundary(self) -> None:
        manager = SkillManager()
        callable_skill = Mock(return_value="must not run")
        manager.register_skill("unmapped", "test", callable_skill)
        dispatcher = self.make_dispatcher(manager)

        with patch(
            "jarvis.scheduler.task_scheduler.BackgroundScheduler",
            CapturingScheduler,
        ):
            scheduler = TaskScheduler()
            with patch("builtins.print"):
                scheduler.add_skill_job_daily("job-1", "unmapped", dispatcher, 12, 0)
                scheduler._scheduler.get_jobs()[0]()

        callable_skill.assert_not_called()

    def test_direct_tool_scheduling_is_closed_until_it_has_a_dispatcher(self) -> None:
        with patch(
            "jarvis.scheduler.task_scheduler.BackgroundScheduler",
            CapturingScheduler,
        ):
            scheduler = TaskScheduler()
            with self.assertRaises(PermissionError):
                scheduler.add_tool_job_interval("tool-job", "web_search", {}, minutes=1)

    def test_main_routes_skills_through_dispatcher_only(self) -> None:
        main_tree = ast.parse((PROJECT_ROOT / "main.py").read_text(encoding="utf-8"))
        direct_skill_manager_calls = [
            node
            for node in ast.walk(main_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "skills"
            and node.func.attr == "execute"
        ]
        dispatcher_calls = [
            node
            for node in ast.walk(main_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "skill_dispatcher"
            and node.func.attr == "dispatch"
        ]

        self.assertEqual(direct_skill_manager_calls, [])
        self.assertGreaterEqual(len(dispatcher_calls), 3)
    def test_normal_printer_action_is_blocked_without_real_requirements(self) -> None:
        manager = SkillManager()
        callable_skill = Mock()
        manager.register_skill("subir_e_imprimir", "test", callable_skill)

        result = self.make_dispatcher(manager).dispatch("subir_e_imprimir")

        self.assertFalse(result.executed)
        self.assertEqual(result.decision.kind, PolicyDecisionKind.DENY)
        callable_skill.assert_not_called()

    def test_emergency_stop_executes_immediately_and_records_audit_event(self) -> None:
        manager = SkillManager()
        callable_skill = Mock(return_value="stopped")
        manager.register_skill("parada_emergencia", "test", callable_skill)
        dispatcher = self.make_dispatcher(manager)

        result = dispatcher.dispatch("parada_emergencia")

        self.assertTrue(result.executed)
        self.assertEqual(result.result, "stopped")
        self.assertEqual(len(result.audit_events), 1)
        self.assertEqual(result.audit_events[0].event_code, "klipper_emergency_stop_requested")
        self.assertEqual(dispatcher.audit_events, list(result.audit_events))
        callable_skill.assert_called_once_with()

    def test_scheduled_dispatch_cannot_reuse_interactive_confirmation(self) -> None:
        manager = SkillManager()
        callable_skill = Mock(return_value="modified")
        manager.register_skill("modify_note", "test", callable_skill)

        dispatcher = self.make_dispatcher(
            manager,
            skill_actions={"modify_note": "modificar_archivo"},
        )

        proof = self.confirmation(
            "confirmation-scheduled",
            "modificar_archivo",
            "alex",
            "workspace/note.txt",
        )

        result = dispatcher.dispatch(
            "modify_note",
            {"path": "workspace/note.txt"},
            identity=self.level_two_identity(),
            confirmations=(proof,),
            scheduled=True,
        )

        self.assertFalse(result.executed)
        self.assertEqual(
            result.decision.kind,
            PolicyDecisionKind.REQUIRE_CONFIRMATION,
        )
        callable_skill.assert_not_called()


    def test_main_passes_session_identity_to_interactive_dispatches(self) -> None:
        main_tree = ast.parse((PROJECT_ROOT / "main.py").read_text(encoding="utf-8"))

        dispatcher_calls = [
            node
            for node in ast.walk(main_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "skill_dispatcher"
            and node.func.attr == "dispatch"
        ]

        self.assertGreaterEqual(len(dispatcher_calls), 3)

        for call in dispatcher_calls:
            keyword_names = {keyword.arg for keyword in call.keywords}
            self.assertIn("identity", keyword_names)


if __name__ == "__main__":
    unittest.main()
