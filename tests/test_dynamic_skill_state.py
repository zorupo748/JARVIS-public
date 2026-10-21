from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from jarvis.core.code_validation import LocalCodeValidator
from jarvis.core.dynamic_skill_contract import (
    FUNCTIONAL_REVIEW_CONTRACT,
    SOURCE_ENTRYPOINT_CONTRACT,
    prepare_entrypoint_call,
)
from jarvis.core.dynamic_skill_response import synthesize_dynamic_skill_response
from jarvis.core.dynamic_skill_state import (
    DynamicSkillStateError,
    DynamicSkillStateStore,
    MAX_DYNAMIC_SKILL_STATE_BYTES,
    extract_dynamic_skill_envelope,
)
from jarvis.core.safe_skill_deployment import (
    DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
    EXECUTION_ACTION_NAME,
    SafeSkillDeploymentService,
    execution_target_for,
)
from jarvis.core.safe_skill_execution import (
    RuntimeExecutionResult,
    SafeSkillExecutionService,
    SubprocessDynamicSkillRuntime,
)
from jarvis.skills.dynamic_runtime_worker import _json_value as worker_json_value
from jarvis.core.safe_skill_pipeline import SafeSkillPipeline
from jarvis.core.session_skill_grants import SessionSkillGrantStore
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import (
    ConfirmationLedger,
    DeterministicPolicyEvaluator,
    IdentityContext,
    PolicyDecisionKind,
    PresenceState,
    VerifiedFactor,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "state_counter"
SOURCE = "def ejecutar_skill(comando='', estado=None):\n    return comando\n"
SOURCE_HASH = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


class FakeRuntime:
    def __init__(self, outcome: RuntimeExecutionResult) -> None:
        self.outcome = outcome
        self.calls: list[dict[str, object]] = []

    def execute(self, **kwargs) -> RuntimeExecutionResult:
        self.calls.append(kwargs)
        return self.outcome


class FakeAuthoring:
    def author(self, _request):
        raise AssertionError("authoring is not used")


class StateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.directory = Path(self.temporary_dir.name) / "dynamic_skill_state"
        self.store = DynamicSkillStateStore(self.directory)

    def test_missing_skill_loads_empty_state(self) -> None:
        self.assertEqual(self.store.load("state_counter"), {})

    def test_save_load_roundtrip_and_new_store_restart(self) -> None:
        state = {"counter": 3, "items": ["a", "b"]}
        self.store.save("state_counter", state)

        self.assertEqual(self.store.load("state_counter"), state)
        self.assertEqual(DynamicSkillStateStore(self.directory).load("state_counter"), state)

    def test_state_is_written_as_utf8(self) -> None:
        self.store.save("state_counter", {"mensaje": "versión española: acción"})

        raw = (self.directory / "state_counter.json").read_bytes()
        self.assertIn("versión española: acción".encode("utf-8"), raw)
        self.assertNotIn(b"\\u", raw)

    def test_save_uses_atomic_replace_in_state_directory(self) -> None:
        real_replace = os.replace
        observed: list[tuple[Path, Path]] = []

        def replace(source, target):
            source_path = Path(source)
            target_path = Path(target)
            self.assertTrue(source_path.is_file())
            self.assertEqual(source_path.parent, self.directory)
            observed.append((source_path, target_path))
            real_replace(source, target)

        with patch("jarvis.core.dynamic_skill_state.os.replace", side_effect=replace):
            self.store.save("state_counter", {"counter": 1})

        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][1], self.directory / "state_counter.json")
        self.assertEqual(list(self.directory.glob("*.tmp")), [])

    def test_path_traversal_and_invalid_names_are_rejected(self) -> None:
        for name in ("../outside", "sub/name", "UPPER", "", ".."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.store.load(name)

    def test_corrupt_json_fails_closed_without_executing_content(self) -> None:
        marker = Path(self.temporary_dir.name) / "should_not_exist"
        self.directory.mkdir()
        (self.directory / "state_counter.json").write_text(
            "{'__reduce__': '" + str(marker) + "'", encoding="utf-8"
        )

        self.assertEqual(self.store.load("state_counter"), {})
        self.assertFalse(marker.exists())

    def test_oversized_state_is_rejected(self) -> None:
        with self.assertRaises(DynamicSkillStateError):
            self.store.save("state_counter", {"large": "x" * MAX_DYNAMIC_SKILL_STATE_BYTES})

    def test_non_json_safe_state_is_rejected(self) -> None:
        invalid_values = (
            {"value": object()},
            {"value": math.nan},
            {1: "non-string key"},
        )
        for state in invalid_values:
            with self.subTest(state=state), self.assertRaises(DynamicSkillStateError):
                self.store.save("state_counter", state)

    def test_circular_state_is_rejected(self) -> None:
        state = {}
        state["self"] = state
        with self.assertRaises(DynamicSkillStateError):
            self.store.save("state_counter", state)

    def test_delete_removes_only_skill_state(self) -> None:
        self.store.save("state_counter", {"counter": 1})
        self.store.save("other", {"counter": 2})

        self.store.delete("state_counter")

        self.assertEqual(self.store.load("state_counter"), {})
        self.assertEqual(self.store.load("other"), {"counter": 2})


class DynamicSkillStateAbiTests(unittest.TestCase):
    def test_legacy_entrypoint_does_not_receive_state(self) -> None:
        def ejecutar_skill(comando=""):
            return comando

        arguments = prepare_entrypoint_call(
            ejecutar_skill,
            {"comando": "hola", "estado": {"contador": 4}},
        )

        self.assertEqual(arguments, {"comando": "hola"})

    def test_positional_or_keyword_estado_receives_both_arguments(self) -> None:
        def ejecutar_skill(comando="", estado=None):
            return comando, estado

        arguments = prepare_entrypoint_call(
            ejecutar_skill,
            {"comando": "hola", "estado": {"contador": 4}},
        )

        self.assertEqual(ejecutar_skill(**arguments), ("hola", {"contador": 4}))

    def test_keyword_only_estado_receives_state(self) -> None:
        def ejecutar_skill(comando="", *, estado=None):
            return comando, estado

        arguments = prepare_entrypoint_call(
            ejecutar_skill,
            {"comando": "hola", "estado": {"contador": 4}},
        )

        self.assertEqual(ejecutar_skill(**arguments), ("hola", {"contador": 4}))

    def test_kwargs_receives_state(self) -> None:
        def ejecutar_skill(**kwargs):
            return kwargs

        arguments = prepare_entrypoint_call(
            ejecutar_skill,
            {"comando": "hola", "estado": {"contador": 4}},
        )

        self.assertEqual(ejecutar_skill(**arguments)["estado"], {"contador": 4})

    def test_internal_type_error_is_not_retried(self) -> None:
        calls = 0

        def ejecutar_skill(comando="", estado=None):
            nonlocal calls
            calls += 1
            raise TypeError("inside skill")

        arguments = prepare_entrypoint_call(
            ejecutar_skill,
            {"comando": "hola", "estado": {}},
        )
        with self.assertRaisesRegex(TypeError, "inside skill"):
            ejecutar_skill(**arguments)
        self.assertEqual(calls, 1)

    def test_ordinary_results_keep_legacy_behavior(self) -> None:
        result = {"status": "ok"}

        visible, state = extract_dynamic_skill_envelope(result)

        self.assertIs(visible, result)
        self.assertIsNone(state)

    def test_envelope_extracts_visible_data_and_state(self) -> None:
        visible, state = extract_dynamic_skill_envelope(
            {"__jarvis_data__": {"version": "1.2"}, "__jarvis_state__": {"seen": True}}
        )

        self.assertEqual(visible, {"version": "1.2"})
        self.assertEqual(state, {"seen": True})

    def test_data_only_envelope_does_not_invent_state(self) -> None:
        visible, state = extract_dynamic_skill_envelope({"__jarvis_data__": "ok"})

        self.assertEqual(visible, "ok")
        self.assertIsNone(state)

    def test_state_only_reserved_key_is_never_exposed(self) -> None:
        self.assertEqual(
            extract_dynamic_skill_envelope({"__jarvis_state__": {"secret": True}}),
            (None, None),
        )

    def test_non_mapping_state_is_discarded_without_exposing_envelope(self) -> None:
        visible, state = extract_dynamic_skill_envelope(
            {"__jarvis_data__": {"answer": 42}, "__jarvis_state__": "not-a-mapping"}
        )

        self.assertEqual(visible, {"answer": 42})
        self.assertIsNone(state)

    def test_worker_keeps_visible_data_when_state_is_not_serializable(self) -> None:
        transported = worker_json_value(
            {"__jarvis_data__": {"answer": 42}, "__jarvis_state__": {"bad": object()}}
        )

        self.assertEqual(transported, {"__jarvis_data__": {"answer": 42}, "__jarvis_state__": None})
        self.assertEqual(extract_dynamic_skill_envelope(transported), ({"answer": 42}, None))

    def test_authoring_and_reviewer_contract_explains_optional_state_abi(self) -> None:
        for text in (SOURCE_ENTRYPOINT_CONTRACT, FUNCTIONAL_REVIEW_CONTRACT):
            self.assertIn("estado", text)
            self.assertIn("__jarvis_state__", text)
            self.assertIn("subprocess", text)
            self.assertIn("globals", text)

    def test_requested_persistence_rejects_function_attribute_storage(self) -> None:
        source = (
            "def ejecutar_skill(comando='', estado=None):\n"
            "    ejecutar_skill.last_checked_version = '1.2'\n"
            "    return {'__jarvis_data__': 'ok', '__jarvis_state__': {}}\n"
        )
        report = LocalCodeValidator().validate_dynamic_skill_source(
            source,
            user_request="Recuerda la versión entre ejecuciones.",
        )

        persistence_check = next(
            check for check in report.checks if check.name == "dynamic_persistence_state"
        )
        self.assertFalse(persistence_check.success)
        self.assertIn("central estado ABI", persistence_check.details)

    def test_requested_persistence_rejects_function_dict_pattern(self) -> None:
        source = (
            "def ejecutar_skill(comando='', estado=None):\n"
            "    if 'last' not in ejecutar_skill.__dict__:\n"
            "        return {'__jarvis_data__': 'new', '__jarvis_state__': {}}\n"
            "    return {'__jarvis_data__': 'old', '__jarvis_state__': {}}\n"
        )
        report = LocalCodeValidator().validate_dynamic_skill_source(
            source,
            user_request="Remember state between future executions.",
        )

        self.assertFalse(report.success)
        self.assertFalse(next(
            check for check in report.checks if check.name == "dynamic_persistence_state"
        ).success)

    def test_function_attributes_are_not_flagged_without_persistence_request(self) -> None:
        source = "def ejecutar_skill():\n    ejecutar_skill.cache = 1\n    return 'ok'\n"
        report = LocalCodeValidator().validate_dynamic_skill_source(source)

        self.assertTrue(next(
            check for check in report.checks if check.name == "dynamic_persistence_state"
        ).success)


class DynamicSkillStateExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_dir.cleanup)
        self.root = Path(self.temporary_dir.name)
        self.dynamic_dir = self.root / "skills"
        self.dynamic_dir.mkdir()
        self.state_dir = self.root / "data" / "dynamic_skill_state"
        self.state_store = DynamicSkillStateStore(self.state_dir)
        self.owner = IdentityContext(
            identity=UserIdentity(
                user_id="owner-state",
                display_name="Owner",
                security_level=SecurityLevel.LEVEL_3,
                is_owner=True,
            ),
            presence=PresenceState.PRESENT,
            verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
        )
        self.ledger = ConfirmationLedger()
        self.dispatcher = SkillDispatcher(
            SkillManager(),
            evaluator=DeterministicPolicyEvaluator(
                confirmation_ledger=self.ledger,
                now=lambda: NOW,
            ),
            confirmation_ledger=self.ledger,
        )
        self.runtime = FakeRuntime(RuntimeExecutionResult(success=True, result="ok"))
        self.execution = SafeSkillExecutionService(
            self.dispatcher,
            dynamic_skills_dir=self.dynamic_dir,
            runtime=self.runtime,
            state_store=self.state_store,
        )
        self.confirmation_number = 0
        self.pipeline = SafeSkillPipeline(
            FakeAuthoring(),
            SafeSkillDeploymentService(
                dynamic_skills_dir=self.dynamic_dir,
                evaluator=DeterministicPolicyEvaluator(
                    confirmation_ledger=self.ledger,
                    now=lambda: NOW,
                ),
                confirmation_ledger=self.ledger,
            ),
            self.execution,
            confirmation_id_factory=self.next_confirmation_id,
            now=lambda: NOW,
        )
        self.install(SOURCE)

    def next_confirmation_id(self) -> str:
        self.confirmation_number += 1
        return f"state-confirmation-{self.confirmation_number}"

    def install(self, source: str) -> str:
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

    def prepare(self):
        return self.pipeline.prepare_execution(
            SKILL_NAME,
            identity=self.owner,
            parameters={"comando": "consulta"},
        )

    def confirm(self):
        pending = self.prepare().pending
        self.assertIsNotNone(pending)
        return self.pipeline.confirm_execution(pending, identity=self.owner)

    def test_state_load_occurs_only_after_policy_allow_and_is_passed_to_worker(self) -> None:
        self.state_store.save(SKILL_NAME, {"saved": "á"})
        with patch.object(self.state_store, "load", wraps=self.state_store.load) as load_state:
            preparation = self.prepare()
            self.assertEqual(
                preparation.execution_result.policy_decision.kind,
                PolicyDecisionKind.REQUIRE_CONFIRMATION,
            )
            load_state.assert_not_called()
            self.assertEqual(self.runtime.calls, [])
            result = self.pipeline.confirm_execution(preparation.pending, identity=self.owner)

        self.assertTrue(result.executed)
        load_state.assert_called_once_with(SKILL_NAME)
        self.assertEqual(self.runtime.calls[0]["parameters"]["estado"], {"saved": "á"})

    def test_policy_deny_does_not_read_state(self) -> None:
        unknown = IdentityContext.unknown_voice()
        with patch.object(self.state_store, "load", wraps=self.state_store.load) as load_state:
            preparation = self.pipeline.prepare_execution(
                SKILL_NAME,
                identity=unknown,
                parameters={"comando": "consulta"},
            )

        self.assertEqual(preparation.execution_result.policy_decision.kind, PolicyDecisionKind.DENY)
        load_state.assert_not_called()
        self.assertEqual(self.runtime.calls, [])

    def test_hash_mismatch_does_not_read_or_save_state(self) -> None:
        self.state_store.save(SKILL_NAME, {"counter": 10})
        (self.dynamic_dir / f"{SKILL_NAME}.py").write_text("alterado", encoding="utf-8")

        with patch.object(self.state_store, "load", wraps=self.state_store.load) as load_state:
            preparation = self.prepare()

        self.assertFalse(preparation.execution_result.hash_verified)
        load_state.assert_not_called()
        self.assertEqual(self.state_store.load(SKILL_NAME), {"counter": 10})

    def test_invalid_metadata_does_not_read_or_save_state(self) -> None:
        self.state_store.save(SKILL_NAME, {"counter": 10})
        (self.dynamic_dir / f"{SKILL_NAME}.skill.json").write_text("{}", encoding="utf-8")

        with patch.object(self.state_store, "load", wraps=self.state_store.load) as load_state:
            preparation = self.prepare()

        self.assertFalse(preparation.execution_result.hash_verified)
        load_state.assert_not_called()
        self.assertEqual(self.state_store.load(SKILL_NAME), {"counter": 10})

    def test_successful_envelope_saves_state_and_returns_only_visible_data(self) -> None:
        self.runtime.outcome = RuntimeExecutionResult(
            success=True,
            result={
                "__jarvis_data__": {"contador": 1},
                "__jarvis_state__": {"contador": 1, "versión": "1"},
            },
        )

        result = self.confirm()

        self.assertEqual(result.result, {"contador": 1})
        self.assertEqual(self.state_store.load(SKILL_NAME), {"contador": 1, "versión": "1"})
        self.assertNotIn("__jarvis_state__", json.dumps(result.result, ensure_ascii=False))

    def test_normal_result_does_not_write_state(self) -> None:
        self.runtime.outcome = RuntimeExecutionResult(success=True, result={"legacy": "ok"})

        result = self.confirm()

        self.assertEqual(result.result, {"legacy": "ok"})
        self.assertEqual(self.state_store.load(SKILL_NAME), {})

    def test_failed_execution_does_not_save_or_expose_envelope(self) -> None:
        self.runtime.outcome = RuntimeExecutionResult(
            success=False,
            result={"__jarvis_data__": "partial", "__jarvis_state__": {"counter": 9}},
            error="worker failed",
        )

        result = self.confirm()

        self.assertFalse(result.executed)
        self.assertIsNone(result.result)
        self.assertEqual(self.state_store.load(SKILL_NAME), {})

    def test_invalid_state_is_not_persisted_but_data_is_returned(self) -> None:
        self.runtime.outcome = RuntimeExecutionResult(
            success=True,
            result={"__jarvis_data__": {"answer": 5}, "__jarvis_state__": {"bad": object()}},
        )

        result = self.confirm()

        self.assertTrue(result.executed)
        self.assertEqual(result.result, {"answer": 5})
        self.assertEqual(self.state_store.load(SKILL_NAME), {})

    def test_oversized_state_is_not_persisted(self) -> None:
        self.runtime.outcome = RuntimeExecutionResult(
            success=True,
            result={
                "__jarvis_data__": "done",
                "__jarvis_state__": {"huge": "x" * MAX_DYNAMIC_SKILL_STATE_BYTES},
            },
        )

        result = self.confirm()

        self.assertTrue(result.executed)
        self.assertEqual(result.result, "done")
        self.assertEqual(self.state_store.load(SKILL_NAME), {})

    def test_synthesizer_receives_only_envelope_data(self) -> None:
        self.runtime.outcome = RuntimeExecutionResult(
            success=True,
            result={
                "__jarvis_data__": {"contador": 2},
                "__jarvis_state__": {"secret": "not for display"},
            },
        )
        execution_result = self.confirm()
        router = Mock()
        router.route.return_value = "El contador es dos."

        response = synthesize_dynamic_skill_response(
            router,
            SKILL_NAME,
            "¿Qué contador hay?",
            execution_result.result,
        )

        self.assertEqual(response, "El contador es dos.")
        prompt = router.route.call_args.args[1]
        self.assertIn('"contador":2', prompt)
        self.assertNotIn("__jarvis_state__", prompt)
        self.assertNotIn("not for display", prompt)


class DynamicSkillStateSubprocessIntegrationTests(unittest.TestCase):
    def test_main_injects_one_central_state_store(self) -> None:
        source = (PROJECT_ROOT / "main.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        stores = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "dynamic_skill_state_store"
                for target in node.targets
            )
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == "DynamicSkillStateStore"
        ]
        execution_setup = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "safe_skill_execution" for target in node.targets)
        )

        self.assertEqual(len(stores), 1)
        self.assertIn(
            "state_store=dynamic_skill_state_store",
            ast.unparse(execution_setup.value),
        )

    def test_two_fresh_workers_increment_through_central_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir, patch.dict(
            os.environ, {"JARVIS_ENABLE_DYNAMIC_SKILLS": "true"}, clear=False
        ):
            root = Path(temporary_dir)
            dynamic_dir = root / "skills"
            dynamic_dir.mkdir()
            state_store = DynamicSkillStateStore(root / "data" / "dynamic_skill_state")
            source = (
                "def ejecutar_skill(comando='', estado=None):\n"
                "    estado = dict(estado or {})\n"
                "    contador = int(estado.get('contador', 0)) + 1\n"
                "    return {\n"
                "        '__jarvis_data__': {'contador': contador},\n"
                "        '__jarvis_state__': {'contador': contador},\n"
                "    }\n"
            )
            encoded = source.encode("utf-8")
            source_hash = hashlib.sha256(encoded).hexdigest()
            (dynamic_dir / f"{SKILL_NAME}.py").write_bytes(encoded)
            metadata = {
                "schema_version": DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
                "skill_name": SKILL_NAME,
                "source_hash": source_hash,
                "execution_action_name": EXECUTION_ACTION_NAME,
                "execution_target": execution_target_for(SKILL_NAME, source_hash),
            }
            (dynamic_dir / f"{SKILL_NAME}.skill.json").write_text(
                json.dumps(metadata), encoding="utf-8"
            )

            owner = IdentityContext(
                identity=UserIdentity(
                    user_id="subprocess-owner",
                    display_name="Owner",
                    security_level=SecurityLevel.LEVEL_3,
                    is_owner=True,
                ),
                presence=PresenceState.PRESENT,
                verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
            )
            ledger = ConfirmationLedger()
            evaluator = DeterministicPolicyEvaluator(
                confirmation_ledger=ledger,
                now=lambda: NOW,
            )
            execution = SafeSkillExecutionService(
                SkillDispatcher(SkillManager(), evaluator=evaluator, confirmation_ledger=ledger),
                dynamic_skills_dir=dynamic_dir,
                runtime=SubprocessDynamicSkillRuntime(
                    project_root=PROJECT_ROOT,
                    timeout_seconds=10,
                ),
                state_store=state_store,
            )
            pipeline = SafeSkillPipeline(
                FakeAuthoring(),
                SafeSkillDeploymentService(
                    dynamic_skills_dir=dynamic_dir,
                    evaluator=evaluator,
                    confirmation_ledger=ledger,
                ),
                execution,
                confirmation_id_factory=iter(("confirm-first", "unused-confirm" )).__next__,
                now=lambda: NOW,
            )
            grants = SessionSkillGrantStore()

            first_pending = pipeline.prepare_execution(
                SKILL_NAME,
                identity=owner,
                parameters={"comando": "incrementa"},
            ).pending
            first = pipeline.confirm_execution(first_pending, identity=owner)
            self.assertTrue(first.executed, first.failure_reason)
            self.assertEqual(first.result, {"contador": 1})
            self.assertTrue(grants.grant_from_confirmed_execution(first, owner.user_id))

            second_preparation = pipeline.prepare_execution(
                SKILL_NAME,
                identity=owner,
                parameters={"comando": "incrementa"},
            )
            self.assertTrue(second_preparation.confirmation_required)
            pending = second_preparation.pending
            authorization = grants.authorization_for(
                SKILL_NAME,
                pending.action.metadata["source_hash"],
                owner.user_id,
            )
            second = pipeline.execute_installed(
                SKILL_NAME,
                identity=owner,
                parameters=pending.parameters,
                session_skill_authorization=authorization,
            )

            self.assertTrue(second.executed, second.failure_reason)
            self.assertEqual(second.result, {"contador": 2})
            self.assertEqual(state_store.load(SKILL_NAME), {"contador": 2})


if __name__ == "__main__":
    unittest.main()
