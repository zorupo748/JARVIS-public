"""ABI regression tests through static validation and the policy-gated child."""

from __future__ import annotations

import ast
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from jarvis.core.code_validation import LocalCodeValidator
from jarvis.core.safe_skill_deployment import SafeSkillDeploymentService, execution_target_for
from jarvis.core.safe_skill_execution import (
    SafeSkillExecutionRequest, SafeSkillExecutionService, SubprocessDynamicSkillRuntime,
)
from jarvis.core.safe_skill_pipeline import SafeSkillPipeline
from jarvis.identity.models import UserIdentity
from jarvis.security.levels import SecurityLevel
from jarvis.security.policy_core import (
    ConfirmationLedger, DeterministicPolicyEvaluator, IdentityContext,
    PolicyDecisionKind, PresenceState, VerifiedFactor,
)
from jarvis.security.skill_dispatch import SkillDispatcher
from jarvis.skills.base import SkillManager

from test_main_safe_skill_integration import FakeAuthoringService, approved_authoring_result
from test_source_repair_unchanged import (
    COMPLETE, METADATA, REQUEST, SOURCE, TESTS, followup, initial_review,
    repair_response, service_with, source_response,
)
from jarvis.core.safe_skill_authoring import GeneratedSkillProposal, SkillAuthoringRequest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMMAND = "Mira si hay una nueva versión de Ollama."
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
OLLAMA_HASH = "c48d9827e21a62321c8740e5f81486eddce8cf750b3c5da65f2f75e98b4078d6"
OLLAMA_METADATA_HASH = "7bd9a909745f12628b28f034f8d5a22c68991e4f8d32ba9672c3fcc89667d230"


@pytest.fixture
def execution_stack(tmp_path, monkeypatch):
    monkeypatch.setenv("JARVIS_ENABLE_DYNAMIC_SKILLS", "true")
    owner = IdentityContext(
        identity=UserIdentity(user_id="owner-abi", display_name="Owner",
                              security_level=SecurityLevel.LEVEL_3, is_owner=True),
        presence=PresenceState.PRESENT,
        verified_factors=frozenset({VerifiedFactor.OWNER_DEVICE}),
    )
    ledger = ConfirmationLedger()
    evaluator = DeterministicPolicyEvaluator(confirmation_ledger=ledger, now=lambda: NOW)
    dispatcher = SkillDispatcher(SkillManager(), evaluator=evaluator, confirmation_ledger=ledger)
    dynamic_dir = tmp_path / "dynamic"
    dynamic_dir.mkdir()
    runtime = SubprocessDynamicSkillRuntime(project_root=PROJECT_ROOT, timeout_seconds=10)
    execution = SafeSkillExecutionService(dispatcher, dynamic_skills_dir=dynamic_dir, runtime=runtime)
    pipeline = SafeSkillPipeline(
        FakeAuthoringService(approved_authoring_result()),
        SafeSkillDeploymentService(dynamic_skills_dir=dynamic_dir, evaluator=evaluator,
                                   confirmation_ledger=ledger),
        execution, confirmation_id_factory=lambda: "fresh-abi-confirmation", now=lambda: NOW,
    )
    return pipeline, execution, owner, dynamic_dir, dispatcher, runtime


def install_fixture(directory, source, name="abi_skill"):
    source_bytes = source.encode("utf-8")
    digest = hashlib.sha256(source_bytes).hexdigest()
    (directory / f"{name}.py").write_bytes(source_bytes)
    (directory / f"{name}.skill.json").write_text(json.dumps({
        "schema_version": 1, "skill_name": name, "source_hash": digest,
        "execution_action_name": "execute_dynamic_skill",
        "execution_target": execution_target_for(name, digest),
    }), encoding="utf-8")


def confirmed_run(stack, source, parameters=None):
    pipeline, _execution, owner, directory, *_rest = stack
    install_fixture(directory, source)
    prepared = pipeline.prepare_execution("abi_skill", identity=owner,
                                          parameters={"comando": COMMAND} if parameters is None else parameters)
    assert prepared.confirmation_required
    assert not prepared.execution_result.executed
    return pipeline.confirm_execution(prepared.pending, identity=owner)


@pytest.mark.parametrize("signature,expression", [
    ("", "None"),
    ("comando", "comando"),
    ('comando: str = ""', "comando"),
    ('comando: str = "", estado: dict | None = None', "comando"),
    ('*, comando: str = "", estado: dict | None = None', "comando"),
    ('comando: str = "", *, estado: dict | None = None', "comando"),
    ("**kwargs", "kwargs['comando']"),
    ("*, comando", "comando"),
    ('comando="", *, query=None', "comando"),
])
def test_canonical_command_reaches_child_once(execution_stack, signature, expression):
    source = f"calls = 0\ndef ejecutar_skill({signature}):\n    global calls\n    calls += 1\n    return {{'calls': calls, 'command': {expression}}}\n"
    result = confirmed_run(execution_stack, source)
    assert result.executed, result.failure_reason
    assert result.policy_decision.kind is PolicyDecisionKind.ALLOW
    assert result.hash_verified
    assert result.result == {"calls": 1, "command": None if not signature else COMMAND}


@pytest.mark.parametrize("signature,error", [
    ("query", "requires unsupported parameter(s): query"),
    ("comando, query", "requires unsupported parameter(s): query"),
    ("*, usuario, texto", "requires unsupported parameter(s): usuario, texto"),
    ("*args, **kwargs", "may not use *args"),
    ("comando, /", "comando must accept a keyword argument"),
    ("repo, /, comando=''", "requires unsupported parameter(s): repo"),
])
def test_historical_incompatible_signature_has_clear_error(execution_stack, signature, error):
    result = confirmed_run(execution_stack,
                           f"def ejecutar_skill({signature}):\n    raise AssertionError('entrypoint was invoked')\n")
    assert not result.executed
    assert result.allowed
    assert result.failure_reason == f"DynamicSkillContractError: ejecutar_skill {error}"
    assert "entrypoint was invoked" not in result.stderr


def test_explicit_optional_parameters_are_preserved(execution_stack):
    result = confirmed_run(execution_stack,
                           "def ejecutar_skill(comando='', query=None):\n    return [comando, query]\n",
                           {"comando": COMMAND, "query": "explicit input"})
    assert result.executed
    assert result.result == [COMMAND, "explicit input"]


def test_zero_args_does_not_silently_drop_explicit_parameters(execution_stack):
    result = confirmed_run(execution_stack, "def ejecutar_skill():\n    return 'wrong'\n",
                           {"comando": COMMAND, "query": "explicit input"})
    assert not result.executed
    assert "DynamicSkillContractError" in result.failure_reason
    assert "unexpected keyword argument 'query'" in result.failure_reason


def test_missing_required_command_fails_before_invocation(execution_stack):
    result = confirmed_run(execution_stack, "def ejecutar_skill(comando):\n    raise AssertionError('called')\n", {})
    assert not result.executed
    assert "DynamicSkillContractError" in result.failure_reason
    assert "missing a required argument: 'comando'" in result.failure_reason


def test_internal_type_error_is_not_retried(execution_stack, tmp_path):
    marker = tmp_path / "invocations.txt"
    source = (
        "from pathlib import Path\ndef ejecutar_skill(comando=''):\n"
        f"    with Path({str(marker)!r}).open('a') as stream:\n        stream.write('called\\n')\n"
        "    raise TypeError('internal skill failure')\n"
    )
    result = confirmed_run(execution_stack, source)
    assert not result.executed
    assert result.failure_reason == "TypeError: internal skill failure"
    assert marker.read_text() == "called\n"


def _main_assignment(target, call_attribute=None):
    tree = ast.parse((PROJECT_ROOT / "main.py").read_text(encoding="utf-8"))
    return next(node for node in ast.walk(tree)
                if isinstance(node, ast.Assign) and any(isinstance(item, ast.Name) and item.id == target for item in node.targets)
                and isinstance(node.value, ast.Call)
                and (call_attribute is None or any(
                    isinstance(expression, ast.Attribute) and expression.attr == call_attribute
                    for expression in (node.value.func, *node.value.args)
                )))


def _invoke_main_call(call, bindings):
    """Read the actual call's names and literal mapping without eval or exec."""

    def resolve(node):
        if isinstance(node, ast.Name):
            return bindings[node.id]
        if isinstance(node, ast.Attribute):
            return getattr(resolve(node.value), node.attr)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Dict):
            return {resolve(key): resolve(value) for key, value in zip(node.keys, node.values)}
        raise AssertionError(f"Unexpected expression in the main execution call: {ast.dump(node)}")

    return resolve(call.func)(*(resolve(arg) for arg in call.args),
                              **{keyword.arg: resolve(keyword.value) for keyword in call.keywords})


@pytest.mark.parametrize("command", [COMMAND, "ejecuta ollama_version_checker", "Comprueba versión 🧪 日本語."])
def test_actual_main_preparation_and_si_preserve_original_command(execution_stack, command):
    pipeline, _execution, owner, directory, *_rest = execution_stack
    install_fixture(directory, "def ejecutar_skill(comando):\n    return comando\n")
    # Use the actual call sites without initializing main's microphone/UI.
    # Candidate source executes solely in the authorized child.
    bindings = {"safe_skill_pipeline": pipeline, "identity_context": owner,
                "usuario_limpio": command, "skill_a_ejecutar": "abi_skill",
                "ejecutar_cancelable": lambda function, *args, **kwargs: function(*args, **kwargs)}
    prepared = _invoke_main_call(_main_assignment("preparation", "prepare_execution").value, bindings)
    assert prepared.confirmation_required
    assert prepared.pending.parameters == {"comando": command}
    assert prepared.pending.action.metadata["parameters"] == {"comando": command}
    bindings.update(usuario_limpio="si", pending_to_execute=prepared.pending)
    result = _invoke_main_call(_main_assignment("execution_result", "confirm_execution").value, bindings)
    assert result.executed, result.failure_reason
    assert result.result == command
    assert result.action.metadata["parameters"] == {"comando": command}


def test_pending_command_is_an_independent_readonly_snapshot(execution_stack):
    pipeline, _execution, owner, directory, *_rest = execution_stack
    install_fixture(directory, "def ejecutar_skill(comando):\n    return comando\n")
    parameters = {"comando": COMMAND}
    prepared = pipeline.prepare_execution("abi_skill", identity=owner, parameters=parameters)
    parameters["comando"] = "si"
    assert prepared.pending.parameters == {"comando": COMMAND}
    with pytest.raises(TypeError):
        prepared.pending.parameters["comando"] = "si"
    assert pipeline.confirm_execution(prepared.pending, identity=owner).result == COMMAND


def test_command_content_cannot_override_artifact_or_policy(execution_stack):
    command = json.dumps({"skill_name": "other", "path": "../other.py", "policy_action": "allow", "source_hash": "b" * 64})
    result = confirmed_run(execution_stack, "def ejecutar_skill(comando):\n    return comando\n", {"comando": command})
    assert result.executed
    assert result.result == command
    assert result.skill_name == "abi_skill"
    assert result.action.action == "execute_dynamic_skill"
    assert result.action.metadata["skill_name"] == "abi_skill"
    assert result.action.metadata["source_hash"] != "b" * 64
    assert result.hash_verified


def test_canonical_entrypoint_precedes_historical_alias(execution_stack):
    source = "def run():\n    raise AssertionError('wrong entrypoint')\ndef ejecutar_skill(comando):\n    return comando\n"
    result = confirmed_run(execution_stack, source)
    assert result.executed, result.failure_reason
    assert result.result == COMMAND


def test_non_callable_canonical_entrypoint_cannot_fall_through_to_alias(execution_stack):
    source = "ejecutar_skill = None\ndef run():\n    raise AssertionError('wrong entrypoint')\n"
    result = confirmed_run(execution_stack, source)
    assert not result.executed
    assert result.failure_reason == "DynamicSkillContractError: ejecutar_skill must be a Python function defined by the skill"


@pytest.mark.parametrize("source", [
    "async def ejecutar_skill(comando=''):\n    return comando\n",
    "def ejecutar_skill(comando=''):\n    yield comando\n",
    "async def ejecutar_skill(comando=''):\n    yield comando\n",
])
def test_async_or_generator_entrypoint_fails_before_invocation(execution_stack, source):
    result = confirmed_run(execution_stack, source)
    assert not result.executed
    assert "DynamicSkillContractError: ejecutar_skill must be a synchronous non-generator function" == result.failure_reason


@pytest.mark.parametrize("name", ["run", "main"])
def test_historical_zero_arg_alias_remains_compatible(execution_stack, name):
    result = confirmed_run(execution_stack, f"def {name}():\n    return 'historical'\n")
    assert result.executed, result.failure_reason
    assert result.result == "historical"


@pytest.mark.parametrize("parameters", [
    {"comando": "text", "path": "other.py"},
    {"comando": "text", "source_hash": "0" * 64},
    {"comando": {"skill_name": "other"}},
    {"comando": "text", "extra": object()},
    {"comando": "text", "extra": float("nan")},
])
def test_invalid_parameters_never_reach_policy_or_runtime(execution_stack, parameters):
    _pipeline, execution, owner, directory, *_rest = execution_stack
    install_fixture(directory, "def ejecutar_skill(**kwargs):\n    raise AssertionError('must not execute')\n")
    result = execution.execute(SafeSkillExecutionRequest("abi_skill", owner, parameters))
    assert not result.executed
    assert not result.allowed
    assert result.policy_decision is None


@pytest.mark.parametrize("signature", ["", "comando", "comando: str = ''", "**kwargs", "*, comando", "comando='', query=None"])
def test_authoring_accepts_canonical_signatures_without_execution(signature):
    source = f"raise AssertionError('never import candidate')\ndef ejecutar_skill({signature}):\n    return 'ok'\n"
    report = LocalCodeValidator().validate_dynamic_skill_source(source)
    assert report.success, report.to_prompt_context()
    assert report.checks[-1].name == "dynamic_entrypoint"


def test_authoring_prompt_documents_optional_state_abi():
    from jarvis.core.dynamic_skill_contract import SOURCE_ENTRYPOINT_CONTRACT

    assert "estado: dict | None = None" in SOURCE_ENTRYPOINT_CONTRACT
    assert "__jarvis_data__" in SOURCE_ENTRYPOINT_CONTRACT
    assert "__jarvis_state__" in SOURCE_ENTRYPOINT_CONTRACT
    assert "Function attributes or globals" in SOURCE_ENTRYPOINT_CONTRACT or "function attributes or globals" in SOURCE_ENTRYPOINT_CONTRACT


@pytest.mark.parametrize("source,error", [
    ("def ejecutar_skill(query):\n    pass\n", "unsupported parameter(s): query"),
    ("def ejecutar_skill(comando, query):\n    pass\n", "unsupported parameter(s): query"),
    ("def ejecutar_skill(*, usuario):\n    pass\n", "unsupported parameter(s): usuario"),
    ("def ejecutar_skill(repo, /):\n    pass\n", "unsupported parameter(s): repo"),
    ("def ejecutar_skill(comando, /):\n    pass\n", "must accept a keyword argument"),
    ("def ejecutar_skill(*args):\n    pass\n", "may not use *args"),
    ("def helper():\n    pass\n", "exactly one module-level"),
    ("ejecutar_skill = lambda: None\n", "exactly one module-level"),
    ("from somewhere import ejecutar_skill\n", "exactly one module-level"),
    ("async def ejecutar_skill():\n    pass\n", "synchronous function"),
    ("def ejecutar_skill():\n    yield 1\n", "must not be a generator"),
    ("@unknown\ndef ejecutar_skill():\n    pass\n", "must not be decorated"),
    ("def ejecutar_skill():\n    pass\nejecutar_skill = None\n", "rebound"),
    ("def ejecutar_skill():\n    pass\ndef ejecutar_skill(query):\n    pass\n", "exactly one module-level"),
    ("class Skill:\n    def ejecutar_skill(self):\n        pass\n", "module-level"),
])
def test_authoring_rejects_incompatible_entrypoint(source, error):
    report = LocalCodeValidator().validate_dynamic_skill_source(source)
    assert not report.success
    assert report.checks[-1].name == "dynamic_entrypoint"
    assert error in report.checks[-1].details


def test_dynamic_validation_keeps_syntax_failure_and_generic_tests_validation():
    validator = LocalCodeValidator()
    assert not validator.validate_dynamic_skill_source("def broken(:\n").success
    assert validator.validate_python_source("def test_skill():\n    assert True\n").success


def test_nested_generator_helper_is_not_mistaken_for_generator_entrypoint():
    source = "def ejecutar_skill(comando=''):\n    def helper():\n        yield comando\n    return list(helper())\n"
    assert LocalCodeValidator().validate_dynamic_skill_source(source).success


def test_invalid_entrypoint_repaired_before_first_review():
    invalid = "def ejecutar_skill(query):\n    return query\n"
    valid = "def ejecutar_skill(comando=''):\n    return comando\n"
    service, coder, router, reviewer = service_with(
        [source_response(invalid), repair_response(valid), TESTS],
        [json.dumps({"approved": True, "blocking_issues": [], "advisory_issues": []})],
    )
    result = service.author(SkillAuthoringRequest(REQUEST))
    assert result.success, result.failure_reason
    assert len(reviewer.requests) == 1
    assert valid in reviewer.requests[0].code_diff
    assert router.groq_calls == 1
    assert result.diagnostics[0].review_skipped_reason == "invalid_entrypoint"
    assert result.diagnostics[0].review_approved is None
    assert result.diagnostics[1].source_repair_count == 1
    assert "unsupported parameter(s): query" in coder.prompts[1]
    for prompt in coder.prompts[:2]:
        assert "def ejecutar_skill(comando: str = \"\"):" in prompt
        assert "No other required parameter is allowed" in prompt
    assert result.proposal.skill_name == METADATA["skill_name"]


def test_incompatible_source_repair_preserves_frozen_plan_and_reviewed_baseline():
    invalid = "def ejecutar_skill(query):\n    return query\n"
    service, coder, router, reviewer = service_with(
        [source_response(), repair_response(invalid), repair_response(COMPLETE), TESTS],
        [initial_review(), followup()],
    )
    result = service.author(SkillAuthoringRequest(REQUEST))
    assert result.success, result.failure_reason
    assert [d.blocking_unresolved for d in result.diagnostics[:3]] == [2, 2, 0]
    assert result.diagnostics[1].review_skipped_reason == "invalid_entrypoint"
    assert result.diagnostics[1].source_repair_count == 1
    assert result.diagnostics[2].source_repair_count == 2
    assert len(reviewer.requests) == 2
    assert reviewer.requests[1].previous_source == SOURCE
    assert result.proposal.skill_name == METADATA["skill_name"]
    assert "B1" in coder.prompts[2] and "B2" in coder.prompts[2]
    assert router.groq_calls == 2


def test_repeated_incompatible_repairs_stop_without_review():
    invalid = "def ejecutar_skill(query):\n    return query\n"
    service, _coder, router, reviewer = service_with(
        [source_response(invalid), repair_response(invalid), repair_response(invalid)], [], max_repairs=2,
    )
    result = service.author(SkillAuthoringRequest(REQUEST))
    assert not result.success
    assert "SOURCE_REPAIR limit reached" in result.failure_reason
    assert result.diagnostics[-1].source_repair_count == 2
    assert result.diagnostics[-1].review_approved is None
    assert router.groq_calls == 0
    assert not reviewer.requests


def test_legacy_proposal_validation_also_enforces_entrypoint_abi():
    service, *_rest = service_with([], [])
    proposal = GeneratedSkillProposal("invalid_skill", "def ejecutar_skill(query):\n    return query\n", "Invalid ABI")
    report = service._validate_proposal(proposal)
    assert not report.success
    assert any(check.name == "source.dynamic_entrypoint" and not check.success for check in report.checks)


def test_create_install_execute_uses_canonical_abi_with_separate_confirmations(execution_stack):
    stack_pipeline, execution, owner, directory, *_rest = execution_stack
    source = "def ejecutar_skill(comando):\n    return {'command': comando}\n"
    service, _coder, _router, reviewer = service_with(
        [source_response(source), "<JARVIS_TESTS>\ndef test_command():\n    assert ejecutar_skill('hello') == {'command': 'hello'}\n</JARVIS_TESTS>"],
        [json.dumps({"approved": True, "blocking_issues": [], "advisory_issues": []})],
    )
    confirmation_ids = iter(("fresh-install", "fresh-execute"))
    pipeline = SafeSkillPipeline(service, stack_pipeline._deployment, execution,
                                 confirmation_id_factory=lambda: next(confirmation_ids), now=lambda: NOW)
    authored = pipeline.author(REQUEST)
    assert authored.success, authored.failure_reason
    assert len(reviewer.requests) == 1
    assert all(report.success for report in authored.validation_reports)
    installation = pipeline.prepare_installation(authored, original_user_request=REQUEST, identity=owner)
    assert installation.confirmation_required
    assert not (directory / "repair_skill.py").exists()
    deployed = pipeline.confirm_installation(installation.pending, identity=owner)
    assert deployed.installed, deployed.failure_reason
    assert (directory / "repair_skill.skill.json").is_file()
    prepared = pipeline.prepare_execution("repair_skill", identity=owner, parameters={"comando": COMMAND})
    assert prepared.confirmation_required  # Installation consent cannot execute.
    assert not prepared.execution_result.executed
    result = pipeline.confirm_execution(prepared.pending, identity=owner)
    assert result.executed, result.failure_reason
    assert result.result == {"command": COMMAND}
    assert result.hash_verified


def test_child_timeout_and_minimal_environment_are_preserved(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "must-not-reach-child")
    captured = {}

    def timed_out(command, **kwargs):
        captured.update(kwargs)
        assert command[-1] == "jarvis.skills.dynamic_runtime_worker"
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial output")

    monkeypatch.setattr("jarvis.core.safe_skill_execution.subprocess.run", timed_out)
    result = SubprocessDynamicSkillRuntime(project_root=PROJECT_ROOT, timeout_seconds=0.1).execute(
        skill_name="abi_skill", dynamic_skills_dir=PROJECT_ROOT / "src" / "jarvis" / "skills" / "dynamic",
        parameters={"comando": COMMAND}, expected_hash="a" * 64,
    )
    assert not result.success
    assert result.timed_out
    assert result.stdout == "partial output"
    assert captured["shell"] is False
    assert captured["encoding"] == "utf-8"
    assert "GROQ_API_KEY" not in captured["env"]
    assert set(captured["env"]) <= {"PYTHONPATH", "PYTHONUTF8", "SYSTEMROOT", "WINDIR", "COMSPEC", "JARVIS_ENABLE_DYNAMIC_SKILLS"}
    assert json.loads(captured["input"])["parameters"] == {"comando": COMMAND}


def test_installed_ollama_runs_through_policy_confirmation_and_real_child_unchanged(execution_stack):
    pipeline, execution, owner, _directory, dispatcher, runtime = execution_stack
    installed = PROJECT_ROOT / "src" / "jarvis" / "skills" / "dynamic"
    source = installed / "ollama_version_checker.py"
    metadata = installed / "ollama_version_checker.skill.json"
    # This local artifact is intentionally not created, edited, or imported in
    # the parent. The exact command takes its no-network, unrecognized branch.
    if not source.is_file() or not metadata.is_file():
        pytest.skip("The local installed Ollama artifact is not present")
    before = (source.read_bytes(), metadata.read_bytes())
    assert hashlib.sha256(before[0]).hexdigest() == OLLAMA_HASH
    assert hashlib.sha256(before[1]).hexdigest() == OLLAMA_METADATA_HASH
    assert json.loads(before[1])["source_hash"] == OLLAMA_HASH
    installed_execution = SafeSkillExecutionService(dispatcher, dynamic_skills_dir=installed, runtime=runtime)
    installed_pipeline = SafeSkillPipeline(
        pipeline._authoring, pipeline._deployment, installed_execution,
        confirmation_id_factory=lambda: "fresh-installed-ollama", now=lambda: NOW,
    )
    prepared = installed_pipeline.prepare_execution("ollama_version_checker", identity=owner,
                                                    parameters={"comando": COMMAND})
    assert prepared.confirmation_required
    assert not prepared.execution_result.executed
    assert prepared.pending.parameters == {"comando": COMMAND}
    result = installed_pipeline.confirm_execution(prepared.pending, identity=owner)
    assert result.executed, result.failure_reason
    assert result.hash_verified
    assert result.policy_decision.kind is PolicyDecisionKind.ALLOW
    assert result.result is None
    assert result.stdout.strip() == "Comando no reconocido."
    assert (source.read_bytes(), metadata.read_bytes()) == before
