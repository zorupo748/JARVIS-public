"""No external calls: trusted fixtures execute only through the policy gateway."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from jarvis.core.authoring_two_phase import build_source_prompt
from jarvis.core.code_reviewer import CodeReviewRequest, CodeReviewer
from jarvis.core.code_validation import LocalCodeValidator
from jarvis.core.dynamic_skill_contract import (
    FUNCTIONAL_REVIEW_CONTRACT, SOURCE_ENTRYPOINT_CONTRACT, prepare_entrypoint_call,
)
from jarvis.core.capability_router import CapabilityRouter, CapabilityDecision
from jarvis.core.input_events import InputSource
from jarvis.core.dynamic_skill_input import (
    DynamicSkillInputError, DynamicSkillInputRequest, DynamicSkillInputSession,
    MAX_INPUT_CONTINUATIONS, MAX_INPUT_PROMPT_CHARS, extract_dynamic_skill_result,
    validate_dynamic_skill_entries,
)
from jarvis.core.dynamic_skill_repair import DynamicSkillRepairCoordinator
from jarvis.core.dynamic_skill_response import normalize_dynamic_skill_result, synthesize_dynamic_skill_response
from jarvis.core.dynamic_skill_state import DynamicSkillStateStore
from jarvis.core.response_grounding import DIRECT_RESPONSE_EVIDENCE_CONTRACT, unbound_identifier_response
from jarvis.core.safe_skill_authoring import SafeSkillAuthoringService, SkillAuthoringRequest
from jarvis.core.safe_skill_deployment import (
    DYNAMIC_SKILL_METADATA_SCHEMA_VERSION, EXECUTION_ACTION_NAME,
    SafeSkillDeploymentService, execution_target_for,
)
from jarvis.core.safe_skill_execution import (
    ExecutionFailureKind, RuntimeExecutionResult, SafeSkillExecutionService, SubprocessDynamicSkillRuntime,
)
from jarvis.core.safe_skill_pipeline import SafeSkillPipeline
from jarvis.core.session_skill_grants import SessionSkillGrantStore
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import (
    ConfirmationLedger, DeterministicPolicyEvaluator, IdentityContext, PolicyDecisionKind,
    PresenceState, VerifiedFactor,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager
from jarvis.skills.dynamic_runtime_worker import _json_value

PROJECT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
VARIABLE = (FIXTURES / "dynamic_input_variable.py.txt").read_text(encoding="utf-8")
FIXED = (FIXTURES / "dynamic_input_fixed.py.txt").read_text(encoding="utf-8")
COMMAND = "¿Dónde está mi paquete?"
NOW = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
INPUT = {"field": "tracking_code", "prompt": "Necesito el código de seguimiento.", "kind": "text"}


def envelope(request=None, state=None):
    return {"__jarvis_data__": None, "__jarvis_state__": state if state is not None else {"seen": True},
            "__jarvis_input_request__": INPUT if request is None else request}


class InputProtocolTests(unittest.TestCase):
    def test_valid_request_is_normalized_and_worker_preserves_it(self):
        data, state, request = extract_dynamic_skill_result(envelope())
        self.assertIsNone(data)
        self.assertEqual(state, {"seen": True})
        self.assertEqual(request.field, "tracking_code")
        self.assertEqual(_json_value(envelope()), envelope())

    def test_malformed_and_unknown_request_fields_fail_closed(self):
        for request in ([], None, {}, {"field": "code", "prompt": "Missing kind"},
                        {**INPUT, "callback": "run"}, {**INPUT, "path": "../x"},
                        {**INPUT, "action": "execute"}, {**INPUT, "kind": "python"}):
            with self.subTest(request=request), self.assertRaises(ValueError):
                value = envelope()
                value["__jarvis_input_request__"] = request
                extract_dynamic_skill_result(value)

    def test_invalid_fields_fail_closed(self):
        for field in ("../file", "UPPER", "__private", "comando", "estado", "source_hash", "a" * 65, 12):
            with self.subTest(field=field), self.assertRaises(DynamicSkillInputError):
                DynamicSkillInputRequest(field, "Question")

    def test_prompt_bounds_and_controls(self):
        for prompt in ("", " ", "x" * (MAX_INPUT_PROMPT_CHARS + 1), "Question\x1b[31m", "x\u202ey"):
            with self.subTest(prompt=prompt), self.assertRaises(DynamicSkillInputError):
                DynamicSkillInputRequest("code", prompt)
        self.assertEqual(DynamicSkillInputRequest("code", " Question ").prompt, "Question")

    def test_unknown_or_ambiguous_envelope_is_rejected(self):
        for value in ({**envelope(), "other": 1}, {**envelope(), "__jarvis_data__": "Final answer"},
                      {**envelope(), "__jarvis_state__": []},
                      {"__jarvis_input_request__": INPUT},
                      {"__jarvis_data__": None, "__jarvis_input_unknown__": INPUT}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                extract_dynamic_skill_result(value)

    def test_entries_are_bounded_text_not_routing_or_code_objects(self):
        self.assertEqual(validate_dynamic_skill_entries({"tracking_code": "TRACK123"}), {"tracking_code": "TRACK123"})
        for entries in ([], {"source_hash": "override"}, {"code": {"callback": "exec"}}, {"code": object()}, {"code": "x" * 4097}):
            with self.subTest(entries=entries), self.assertRaises(DynamicSkillInputError):
                validate_dynamic_skill_entries(entries)

    def test_credentials_cannot_be_requested_through_ordinary_input_fields(self):
        for field in ("api_key", "access_token", "password", "credentials"):
            with self.subTest(field=field), self.assertRaises(DynamicSkillInputError):
                DynamicSkillInputRequest(field, "Provide a credential")

    def test_input_request_bypasses_speech_synthesis(self):
        router = Mock()
        self.assertEqual(synthesize_dynamic_skill_response(router, "demo", COMMAND, envelope()), INPUT["prompt"])
        router.route.assert_not_called()

    def test_final_result_uses_synthesis_and_hides_state(self):
        router = Mock()
        router.route.return_value = "Resultado confirmado."
        result = {"__jarvis_data__": {"answer": 42}, "__jarvis_state__": {"private": "INTERNAL_STATE"}}
        self.assertEqual(synthesize_dynamic_skill_response(router, "demo", COMMAND, result), "Resultado confirmado.")
        self.assertNotIn("INTERNAL_STATE", router.route.call_args.args[1])
        normalized = normalize_dynamic_skill_result(result)
        self.assertNotIn("__jarvis_state__", normalized.fallback_response)
        self.assertNotIn("INTERNAL_STATE", normalized.model_data)


class InputABITests(unittest.TestCase):
    def test_legacy_variants_drop_only_canonical_inputs(self):
        parameters = {"comando": COMMAND, "estado": {}, "entradas": {"tracking_code": "TRACK123"}}
        functions = [lambda: "ok", lambda comando: comando,
                     lambda comando="", estado=None: comando,
                     lambda *, comando="", estado=None: comando]
        for function in functions:
            with self.subTest(function=function):
                bound = prepare_entrypoint_call(function, parameters)
                self.assertNotIn("entradas", bound)
                self.assertIn(function(**bound), ("ok", COMMAND))

    def test_optional_entries_and_keyword_only_variants(self):
        def ejecutar_skill(*, comando="", estado=None, entradas=None):
            return comando, entradas
        bound = prepare_entrypoint_call(ejecutar_skill, {"comando": COMMAND, "entradas": {"code": "TRACK123"}})
        self.assertEqual(ejecutar_skill(**bound), (COMMAND, {"code": "TRACK123"}))

    def test_kwargs_receives_inputs(self):
        def ejecutar_skill(**kwargs):
            return kwargs
        bound = prepare_entrypoint_call(ejecutar_skill, {"comando": COMMAND, "entradas": {"code": "TRACK123"}})
        self.assertEqual(ejecutar_skill(**bound)["entradas"], {"code": "TRACK123"})

    def test_internal_type_error_has_no_second_invocation(self):
        calls = []
        def ejecutar_skill(comando="", entradas=None):
            calls.append(entradas)
            raise TypeError("real internal failure")
        bound = prepare_entrypoint_call(ejecutar_skill, {"entradas": {"code": "TRACK123"}})
        with self.assertRaisesRegex(TypeError, "real internal failure"):
            ejecutar_skill(**bound)
        self.assertEqual(len(calls), 1)

    def test_authoring_ast_accepts_optional_inputs_and_rejects_required_or_positional_only(self):
        validator = LocalCodeValidator()
        for signature, valid in (("comando='', entradas=None", True), ("*, comando='', estado=None, entradas=None", True),
                                 ("**kwargs", True), ("comando, entradas", False), ("entradas=None, /", False)):
            with self.subTest(signature=signature):
                report = validator.validate_dynamic_skill_source(f"def ejecutar_skill({signature}):\n    return 'ok'\n")
                self.assertEqual(report.success, valid)


class RecordingRuntime:
    def __init__(self):
        self.results = [envelope(), {"answer": "verified"}]
        self.calls = []
    def execute(self, **kwargs):
        self.calls.append(kwargs)
        return RuntimeExecutionResult(success=True, result=self.results.pop(0))


class InputExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "dynamic"
        self.directory.mkdir()
        self.state_store = DynamicSkillStateStore(self.root / "state")
        self.owner = IdentityContext(identity=UserIdentity(user_id="owner-input", display_name="Owner", security_level=SecurityLevel.LEVEL_3, is_owner=True),
                                     presence=PresenceState.PRESENT, verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}))
        ledger = ConfirmationLedger()
        evaluator = DeterministicPolicyEvaluator(confirmation_ledger=ledger, now=lambda: NOW)
        self.runtime = RecordingRuntime()
        self.service = SafeSkillExecutionService(SkillDispatcher(SkillManager(), evaluator=evaluator, confirmation_ledger=ledger),
                                                 dynamic_skills_dir=self.directory, runtime=self.runtime, state_store=self.state_store)
        self.pipeline = SafeSkillPipeline(Mock(), SafeSkillDeploymentService(dynamic_skills_dir=self.directory, evaluator=evaluator, confirmation_ledger=ledger),
                                          self.service, confirmation_id_factory=lambda: f"confirmation-{len(self.runtime.calls)}", now=lambda: NOW)
        self.grants = SessionSkillGrantStore()
        self.session = DynamicSkillInputSession(clock=lambda: 100)
        self.install(VARIABLE)

    def install(self, source):
        source_hash = hashlib.sha256(source.encode()).hexdigest()
        (self.directory / "input_demo.py").write_text(source, encoding="utf-8", newline="\n")
        metadata = {"schema_version": DYNAMIC_SKILL_METADATA_SCHEMA_VERSION, "skill_name": "input_demo", "source_hash": source_hash,
                    "execution_action_name": EXECUTION_ACTION_NAME, "execution_target": execution_target_for("input_demo", source_hash)}
        (self.directory / "input_demo.skill.json").write_text(json.dumps(metadata), encoding="utf-8")
        return source_hash

    def start(self, *, grant=True):
        preparation = self.pipeline.prepare_execution("input_demo", identity=self.owner, parameters={"comando": COMMAND})
        self.assertTrue(preparation.confirmation_required)
        result = self.pipeline.confirm_execution(preparation.pending, identity=self.owner)
        self.assertTrue(result.executed, result.failure_reason)
        if grant:
            self.grants.grant_from_confirmed_execution(result, self.owner.user_id)
        self.session.accept_result(result, original_command=COMMAND, user_id=self.owner.user_id)
        return result

    def reply(self, text="TRACK123", identity=None):
        return self.session.handle_message(text, pipeline=self.pipeline, grants=self.grants, identity=identity or self.owner)

    def test_state_is_persisted_before_input_is_exposed(self):
        self.start()
        self.assertEqual(self.state_store.load("input_demo"), {"seen": True})
        self.assertEqual(dict(self.session.pending.state), {"seen": True})
        self.assertEqual(self.session.pending.input_request.prompt, INPUT["prompt"])

    def test_next_message_reenters_same_skill_with_original_command_and_inputs(self):
        self.start()
        turn = self.reply()
        self.assertTrue(turn.handled)
        self.assertTrue(turn.execution_result.executed)
        self.assertEqual(self.runtime.calls[-1]["skill_name"], "input_demo")
        self.assertEqual(self.runtime.calls[-1]["parameters"], {"comando": COMMAND, "entradas": {"tracking_code": "TRACK123"}, "estado": {"seen": True}})

    def test_general_repository_field_uses_same_infrastructure(self):
        self.runtime.results = [envelope({"field": "repository", "prompt": "¿Qué repositorio?", "kind": "text"}), {"answer": "verified"}]
        self.start()
        self.reply("owner/project")
        self.assertEqual(self.runtime.calls[-1]["parameters"]["entradas"], {"repository": "owner/project"})

    def test_accept_result_uses_bound_command_instead_of_confirmation_text(self):
        self.runtime.results = [envelope(), envelope()]
        self.start()
        result = self.reply().execution_result
        self.session.accept_result(result, original_command="si", user_id=self.owner.user_id)
        self.assertEqual(self.session.pending.original_command, COMMAND)

    def test_source_hash_change_cancels_even_with_matching_new_metadata(self):
        self.start()
        self.install(VARIABLE + "\n# changed version\n")
        turn = self.reply()
        self.assertFalse(turn.execution_result.executed)
        self.assertIn("changed", turn.execution_result.failure_reason)
        self.assertEqual(len(self.runtime.calls), 1)
        self.assertIsNone(self.session.pending)

    def test_source_hash_mismatch_is_still_blocked(self):
        self.start()
        (self.directory / "input_demo.py").write_text("def ejecutar_skill():\n    return 1\n", encoding="utf-8")
        self.assertFalse(self.reply().execution_result.executed)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_metadata_bytes_change_cancels(self):
        self.start()
        path = self.directory / "input_demo.skill.json"
        path.write_text(path.read_text() + "\n", encoding="utf-8")
        self.assertFalse(self.reply().execution_result.executed)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_missing_metadata_cancels(self):
        self.start()
        (self.directory / "input_demo.skill.json").unlink()
        self.assertFalse(self.reply().execution_result.executed)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_wrong_user_cancels_before_runtime(self):
        self.start()
        turn = self.reply(identity=IdentityContext.unknown_voice())
        self.assertTrue(turn.handled)
        self.assertIsNone(turn.execution_result)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_policy_denial_is_not_bypassed_by_input_wait_or_grant(self):
        self.start()
        unverified = replace(self.owner, verified_factors=frozenset())
        turn = self.reply(identity=unverified)
        self.assertFalse(turn.execution_result.executed)
        self.assertEqual(turn.execution_result.policy_decision.kind, PolicyDecisionKind.DENY)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_wrong_hash_grant_requires_fresh_confirmation(self):
        self.start(grant=False)
        self.grants.grant("input_demo", "f" * 64, self.owner.user_id)
        turn = self.reply()
        self.assertIsNotNone(turn.pending_execution)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_wait_is_not_authorization_confirmation_preserves_inputs(self):
        self.start(grant=False)
        turn = self.reply()
        self.assertIsNotNone(turn.pending_execution)
        self.assertEqual(len(self.runtime.calls), 1)
        result = self.pipeline.confirm_execution(turn.pending_execution, identity=self.owner)
        self.assertTrue(result.executed)
        self.assertEqual(result.action.metadata["parameters"], {"comando": COMMAND, "entradas": {"tracking_code": "TRACK123"}})

    def test_hash_change_while_confirmation_pending_still_cancels(self):
        self.start(grant=False)
        turn = self.reply()
        self.install(VARIABLE + "\n# replacement\n")
        result = self.pipeline.confirm_execution(turn.pending_execution, identity=self.owner)
        self.assertFalse(result.executed)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_metadata_change_while_confirmation_pending_cancels(self):
        self.start(grant=False)
        turn = self.reply()
        path = self.directory / "input_demo.skill.json"
        path.write_text(path.read_text() + "\n", encoding="utf-8")
        self.assertFalse(self.pipeline.confirm_execution(turn.pending_execution, identity=self.owner).executed)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_confirmation_from_another_user_cannot_resume_input(self):
        self.start(grant=False)
        turn = self.reply()
        other = replace(self.owner, identity=replace(self.owner.identity, user_id="another-owner"))
        result = self.pipeline.confirm_execution(turn.pending_execution, identity=other)
        self.assertFalse(result.executed)
        self.assertIn("identity changed", result.failure_reason)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_expiry_cancels_without_execution(self):
        self.start()
        self.session._clock = lambda: 1000
        self.assertIsNone(self.reply().execution_result)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_cancel_commands_clear_wait_without_execution(self):
        for text in ("cancelar", "cancela", "olvídalo", "olvidalo"):
            with self.subTest(text=text):
                self.runtime.results.insert(0, envelope())
                self.start()
                calls = len(self.runtime.calls)
                turn = self.reply(text)
                self.assertTrue(turn.handled)
                self.assertIsNone(self.session.pending)
                self.assertEqual(len(self.runtime.calls), calls)

    def test_explicit_new_skill_directive_cancels_wait_and_returns_to_router(self):
        self.start()
        _, intents, capability, _ = self.run_actual_input_branch("/skill consultar un repositorio")
        self.assertIsNone(self.session.pending)
        self.assertEqual(len(self.runtime.calls), 1)
        intents.assert_called_once()
        capability.decide.assert_called_once()

    def test_restart_has_no_pending_input(self):
        self.start()
        restarted = DynamicSkillInputSession()
        self.assertIsNone(restarted.pending)
        self.assertFalse(restarted.handle_message("TRACK123", pipeline=self.pipeline, grants=self.grants, identity=self.owner).handled)

    def test_continuation_limit_stops_repeated_requests(self):
        self.runtime.results = [envelope()] * (MAX_INPUT_CONTINUATIONS + 1)
        self.start()
        for _ in range(MAX_INPUT_CONTINUATIONS):
            turn = self.reply()
            message = self.session.accept_result(turn.execution_result, original_command=COMMAND, user_id=self.owner.user_id)
        self.assertIsNone(self.session.pending)
        self.assertIn("3 continuaciones", message)
        self.assertEqual(len(self.runtime.calls), MAX_INPUT_CONTINUATIONS + 1)

    def test_loop_counter_survives_fresh_confirmation(self):
        self.runtime.results = [envelope()] * 2
        self.start(grant=False)
        turn = self.reply()
        result = self.pipeline.confirm_execution(turn.pending_execution, identity=self.owner)
        self.session.accept_result(result, original_command=COMMAND, user_id=self.owner.user_id)
        self.assertEqual(self.session.pending.continuation_count, 1)

    def test_input_request_does_not_start_self_repair(self):
        result = self.start()
        self.assertFalse(DynamicSkillRepairCoordinator.is_repairable_failure(result))
        self.assertIsNone(result.failure_kind)

    def test_malformed_request_fails_before_state_update(self):
        self.runtime.results = [envelope({**INPUT, "callback": "bad"}, {"must_not_save": True})]
        preparation = self.pipeline.prepare_execution("input_demo", identity=self.owner)
        result = self.pipeline.confirm_execution(preparation.pending, identity=self.owner)
        self.assertFalse(result.executed)
        self.assertEqual(result.failure_kind, ExecutionFailureKind.RESULT_CONTRACT)
        self.assertEqual(self.state_store.load("input_demo"), {})

    def test_failed_state_save_does_not_publish_input_wait(self):
        preparation = self.pipeline.prepare_execution("input_demo", identity=self.owner)
        with patch.object(self.state_store, "save", side_effect=OSError("disk error")):
            result = self.pipeline.confirm_execution(preparation.pending, identity=self.owner)
        self.assertFalse(result.executed)
        self.assertIsNone(result.input_request)

    def test_real_child_variable_fixture_continues_without_external_services(self):
        self.service._runtime = SubprocessDynamicSkillRuntime(timeout_seconds=10)
        first = self.start()
        self.assertIsNotNone(first.input_request)
        turn = self.reply()
        self.assertTrue(turn.execution_result.executed, turn.execution_result.failure_reason)
        self.assertEqual(turn.execution_result.result["identifier"], "TRACK123")
        self.assertEqual(turn.execution_result.result["command"], COMMAND)
        self.assertEqual(self.state_store.load("input_demo")["tracking_code"], "TRACK123")
        final = turn.execution_result
        self.session.accept_result(final, original_command=COMMAND, user_id=self.owner.user_id)
        authorization = self.grants.authorization_for("input_demo", final.action.metadata["source_hash"], self.owner.user_id)
        repeated = self.pipeline.execute_installed("input_demo", identity=self.owner,
                                                   parameters={"comando": COMMAND}, session_skill_authorization=authorization)
        self.assertTrue(repeated.executed)
        self.assertIsNone(repeated.input_request)
        self.assertFalse(repeated.result["changed"])

    def test_real_child_fixed_fixture_uses_config_without_requesting_input(self):
        self.install(FIXED)
        self.service._runtime = SubprocessDynamicSkillRuntime(timeout_seconds=10)
        result = self.start()
        self.assertIsNone(result.input_request)
        self.assertIsNone(self.session.pending)
        self.assertEqual(result.result["identifier"], "TRACK123")

    def test_real_child_malformed_input_is_contract_failure_not_self_repair(self):
        self.install("def ejecutar_skill():\n    return " + repr(envelope({**INPUT, "callback": "forbidden"})) + "\n")
        self.service._runtime = SubprocessDynamicSkillRuntime(timeout_seconds=10)
        preparation = self.pipeline.prepare_execution("input_demo", identity=self.owner)
        result = self.pipeline.confirm_execution(preparation.pending, identity=self.owner)
        self.assertFalse(result.executed)
        self.assertEqual(result.failure_kind, ExecutionFailureKind.RESULT_CONTRACT)
        self.assertFalse(DynamicSkillRepairCoordinator.is_repairable_failure(result))
        self.assertEqual(self.state_store.load("input_demo"), {})

    def run_actual_responder(self, result):
        tree = ast.parse((PROJECT / "main.py").read_text(encoding="utf-8"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "responder_dynamic_skill")
        scope = {"dynamic_skill_input_session": self.session,
                 "security_session": SimpleNamespace(context=lambda: self.owner),
                 "synthesize_dynamic_skill_response": Mock(return_value="Resultado final."),
                 "router": Mock(), "speech_queue": Mock(), "registrar_en_historial": Mock(), "memory": Mock()}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<trusted main responder>", "exec"), scope)
        with redirect_stdout(io.StringIO()) as output:
            response = scope["responder_dynamic_skill"]("input_demo", COMMAND, result)
        return scope, response, output.getvalue()

    def test_actual_main_responder_exposes_only_prompt_without_synthesizer(self):
        result = self.start()
        scope, response, output = self.run_actual_responder(result)
        self.assertEqual(response, INPUT["prompt"])
        scope["synthesize_dynamic_skill_response"].assert_not_called()
        scope["speech_queue"].add_message.assert_called_once_with(INPUT["prompt"])
        scope["memory"].add_interaction.assert_called_once_with("jarvis", INPUT["prompt"])
        self.assertNotIn("__jarvis_", output)
        self.assertNotIn("seen", output)

    def test_actual_main_responder_synthesizes_final_visible_result(self):
        self.start()
        result = self.reply().execution_result
        scope, response, _ = self.run_actual_responder(result)
        self.assertEqual(response, "Resultado final.")
        scope["synthesize_dynamic_skill_response"].assert_called_once_with(scope["router"], "input_demo", COMMAND, {"answer": "verified"})
        self.assertIsNone(self.session.pending)

    def run_actual_input_branch(self, text, source=InputSource.LOCAL_CONSOLE, pending_execution=None):
        """Run only the trusted main input branch, without starting main's UI."""
        tree = ast.parse((PROJECT / "main.py").read_text(encoding="utf-8"))
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and any(
            isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "handle_message"
            for c in ast.walk(n)
        ) and ast.unparse(n.test) == "input_source is not InputSource.RECOVERY")
        intents = Mock(return_value=None)
        capability = Mock()
        responder = Mock()
        body = [branch, ast.parse("resolver_skill_prioritaria(usuario_limpio)\ncapability_router.decide(usuario_limpio)").body[0],
                ast.parse("capability_router.decide(usuario_limpio)").body[0]]
        loop = ast.For(target=ast.Name(id="_turn", ctx=ast.Store()), iter=ast.List(elts=[ast.Constant(1)], ctx=ast.Load()), body=body, orelse=[])
        module = ast.fix_missing_locations(ast.Module(body=[loop], type_ignores=[]))
        scope = {"input_source": source, "InputSource": InputSource, "usuario_limpio": text,
                 "dynamic_skill_input_session": self.session, "safe_skill_pipeline": self.pipeline,
                 "session_skill_grants": self.grants, "identity_context": self.owner,
                 "pending_skill_execution": pending_execution, "responder_dynamic_skill": responder,
                 "intentar_autorreparacion_dynamic_skill": Mock(return_value=False),
                 "speech_queue": Mock(), "registrar_en_historial": Mock(),
                 "resolver_skill_prioritaria": intents, "capability_router": capability}
        exec(compile(module, "<trusted main input branch>", "exec"), scope)
        return scope, intents, capability, responder

    def test_actual_main_input_branch_does_not_call_either_router(self):
        self.start()
        scope, intents, capability, responder = self.run_actual_input_branch("TRACK123")
        intents.assert_not_called()
        capability.decide.assert_not_called()
        scope["intentar_autorreparacion_dynamic_skill"].assert_not_called()
        self.assertEqual(responder.call_args.args[1], COMMAND)

    def test_no_pending_input_allows_normal_capability_and_intent_routing(self):
        _, intents, capability, responder = self.run_actual_input_branch("Hola")
        intents.assert_called_once_with("Hola")
        capability.decide.assert_called_once_with("Hola")
        responder.assert_not_called()
        self.assertEqual(CapabilityRouter().decide("Hola").decision, CapabilityDecision.DIRECT_RESPONSE)

    def test_recovery_does_not_answer_or_replace_pending_input(self):
        self.start()
        pending = self.session.pending
        _, intents, capability, _ = self.run_actual_input_branch("automatic replay", InputSource.RECOVERY)
        self.assertIs(self.session.pending, pending)
        self.assertEqual(len(self.runtime.calls), 1)
        intents.assert_not_called()
        capability.decide.assert_not_called()

    def test_recovery_does_not_consume_pending_continuation_confirmation(self):
        self.start(grant=False)
        turn = self.reply()
        self.assertIsNotNone(turn.pending_execution)
        self.assertIsNone(self.session.pending)
        self.assertTrue(self.session.has_pending_interaction)
        scope, intents, capability, responder = self.run_actual_input_branch(
            "si", InputSource.RECOVERY, pending_execution=turn.pending_execution,
        )
        self.assertIs(scope["pending_skill_execution"], turn.pending_execution)
        intents.assert_not_called()
        capability.decide.assert_not_called()
        responder.assert_not_called()
        self.assertEqual(len(self.runtime.calls), 1)
        confirmed = self.pipeline.confirm_execution(turn.pending_execution, identity=self.owner)
        self.assertTrue(confirmed.executed)
        self.assertEqual(confirmed.action.metadata["parameters"]["entradas"], {"tracking_code": "TRACK123"})
        self.session.accept_result(confirmed, original_command=COMMAND, user_id=self.owner.user_id)
        self.assertFalse(self.session.has_pending_interaction)


class InputAuthoringAndRoutingTests(unittest.TestCase):
    def test_prompt_requires_fixed_configuration_and_distinguishes_secrets(self):
        request = SkillAuthoringRequest("Cuando te pregunte por mi paquete usa el código TRACK123 y recuerda cambios.")
        prompt = build_source_prompt(Mock(), request, iteration=1, previous_proposal=None, previous_validation=None, previous_review=None, rescue_diagnostic=None)
        self.assertIn(request.user_request, prompt)
        self.assertIn("FIXED CONFIGURATION", prompt)
        self.assertIn("Do not ask again", prompt)
        for text in (SOURCE_ENTRYPOINT_CONTRACT, FUNCTIONAL_REVIEW_CONTRACT):
            self.assertIn("__jarvis_input_request__", text)
            self.assertIn("entradas", text)
            self.assertIn("passwords", text)
            self.assertIn("secrets", text)

    def test_configured_and_legitimately_variable_fixtures_pass_static_validation(self):
        for source, request in (
            (FIXED, "Usa TRACK123 y recuerda cambios."),
            (VARIABLE, "Collect any identifier and remember changes."),
        ):
            with self.subTest(request=request):
                self.assertTrue(LocalCodeValidator().validate_dynamic_skill_source(source, user_request=request).success)

    def test_reviewer_contract_and_existing_blocker_for_ignored_fixed_parameter(self):
        request = CodeReviewRequest("Usa el código TRACK123 para mi paquete.", "tracking", VARIABLE)
        router = Mock()
        router.groq_api_key = "fake-test-key"
        router.run_groq_code_review.return_value = json.dumps({"approved": False, "blocking_issues": [{
            "category": "user_requirement_unmet", "description": "Ignores the configured identifier and asks for it again.",
            "evidence": 'identifier = (entradas or {}).get("tracking_code") or estado.get("tracking_code")',
            "requirement_relation": "The user explicitly required the fixed identifier TRACK123.",
            "suggested_fix": "Use the configured non-secret identifier.", "severity": "high"}], "advisory_issues": []})
        result = CodeReviewer(router).review(request)
        self.assertFalse(result.approved)
        self.assertEqual(result.blocking_findings[0].category.value, "user_requirement_unmet")
        prompt = router.run_groq_code_review.call_args.args[0]
        self.assertIn("report a user_requirement_unmet blocker", prompt)
        self.assertIn(request.user_request, prompt)

    def test_ignored_fixed_parameter_enters_source_repair_then_approved_source_uses_it(self):
        initial = {"approved": False, "blocking_issues": [{
            "category": "user_requirement_unmet", "description": "Asks again for the configured identifier.",
            "evidence": 'identifier = (entradas or {}).get("tracking_code") or estado.get("tracking_code")',
            "requirement_relation": "Original request explicitly specifies TRACK123.",
            "suggested_fix": "Use the fixed non-secret configuration.", "severity": "high"}], "advisory_issues": []}
        followup = {"approved": True, "blocker_statuses": [{"id": "B1", "status": "resolved",
            "evidence": 'CONFIGURED_IDENTIFIER = "TRACK123" and identifier = CONFIGURED_IDENTIFIER are now present.'}],
            "regression_blockers": [], "advisory_issues": []}
        router = Mock()
        router.groq_api_key = "fake-test-key"
        router.run_groq_code_review.side_effect = [json.dumps(initial), json.dumps(followup)]
        coder = Mock()
        coder.run_local_coding.side_effect = [VARIABLE, FIXED, "def test_entrypoint():\n    assert callable(ejecutar_skill)\n"]
        with tempfile.TemporaryDirectory() as directory:
            service = SafeSkillAuthoringService(coder, reviewer=CodeReviewer(router), max_seconds=60,
                                               debug_root=Path(directory), diagnostic_sink=lambda _: None)
            result = service.author(SkillAuthoringRequest("Cuando te pregunte por mi paquete usa el código TRACK123 y recuerda cambios."))
        self.assertTrue(result.success, result.failure_reason)
        self.assertFalse(result.review_results[0].approved)
        self.assertEqual(result.diagnostics[1].phase, "source_repair")
        self.assertEqual(result.diagnostics[-1].source_repair_count, 1)
        self.assertIn('CONFIGURED_IDENTIFIER = "TRACK123"', result.proposal.source_code)
        self.assertIn("Use the fixed non-secret configuration", coder.run_local_coding.call_args_list[1].args[0])

    def test_pending_handler_is_before_intents_and_capability_router_and_has_continue(self):
        tree = ast.parse((PROJECT / "main.py").read_text(encoding="utf-8"))
        handle = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "handle_message")
        intents = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "resolver_skill_prioritaria"]
        capability = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "decide" and isinstance(n.func.value, ast.Name) and n.func.value.id == "capability_router"]
        self.assertTrue(all(handle.lineno < n.lineno for n in intents + capability))
        branch = next(n for n in ast.walk(tree) if isinstance(n, ast.If) and ast.unparse(n.test) == "input_turn.handled")
        self.assertIsInstance(branch.body[-1], ast.Continue)
        self.assertNotIn("capability_router", ast.unparse(branch))
        self.assertNotIn("resolver_skill_prioritaria", ast.unparse(branch))

    def test_main_displays_input_without_synthesis_or_self_repair(self):
        tree = ast.parse((PROJECT / "main.py").read_text(encoding="utf-8"))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "responder_dynamic_skill")
        branch = next(n for n in ast.walk(function) if isinstance(n, ast.If) and ast.unparse(n.test) == "respuesta is None")
        self.assertIn("synthesize_dynamic_skill_response", ast.unparse(branch))
        self.assertNotIn("intentar_autorreparacion", ast.unparse(function))

    def test_unbound_identifier_has_no_factual_claim_or_model_call(self):
        response = unbound_identifier_response("TRACK123")
        self.assertIn("no tengo una consulta verificada", response)
        self.assertNotIn("centro de clasificación", response)
        self.assertIsNone(unbound_identifier_response("Hola, ¿cómo estás?"))
        self.assertIn("No afirmes datos externos actuales", DIRECT_RESPONSE_EVIDENCE_CONTRACT)


if __name__ == "__main__":
    unittest.main()
