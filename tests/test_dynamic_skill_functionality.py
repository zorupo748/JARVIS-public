"""Static regressions from the installed broken Ollama source; never execute it."""

import hashlib
import json
from pathlib import Path

import pytest

from jarvis.core.code_reviewer import CodeReviewer
from jarvis.core.code_validation import LocalCodeValidator
from jarvis.core.safe_skill_authoring import SkillAuthoringRequest
from test_source_repair_unchanged import (
    COMPLETE, SOURCE, TESTS, followup, initial_review, repair_response, service_with, source_response,
)


FIXTURE = Path(__file__).parent / "fixtures" / "ollama_version_checker_broken.txt"
ORIGINAL_HASH = "c48d9827e21a62321c8740e5f81486eddce8cf750b3c5da65f2f75e98b4078d6"
# These tests exercise general source-validation/repair flow; live-data
# acquisition policy has dedicated tests in test_live_external_data.py.
REQUEST = "Summarize the version information supplied by the user and report changes."


def validate(source):
    return LocalCodeValidator().validate_dynamic_skill_source(source)


def test_exact_ollama_fixture_fails_all_three_checks():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == ORIGINAL_HASH
    report = validate(FIXTURE.read_text(encoding="utf-8"))
    failures = {check.name: check.details for check in report.checks if not check.success}
    assert set(failures) == {"dynamic_command_gate", "dynamic_text_index", "dynamic_result"}
    assert "literal phrase" in failures["dynamic_command_gate"]
    assert "Loop variable 'item' is text from split()" in failures["dynamic_text_index"]
    assert "string key 'body'" in failures["dynamic_text_index"]
    assert "print() is not a result" in failures["dynamic_result"]


@pytest.mark.parametrize("condition", [
    'comando == "frase exacta"', '"frase exacta" == comando',
    '"frase exacta" in comando', 'comando != "frase exacta"',
])
@pytest.mark.parametrize("answer", ["consultar_version()", "'version v1'"])
def test_literal_activation_gate_fails(condition, answer):
    source = f"def ejecutar_skill(comando=''):\n    if {condition}:\n        return {answer}\n    else:\n        return 'Comando no reconocido.'\n"
    report = validate(source)
    assert not report.success
    assert any(check.name == "dynamic_command_gate" and not check.success for check in report.checks)


@pytest.mark.parametrize("source", [
    "def ejecutar_skill():\n    return 'ok'\n",
    "def ejecutar_skill(comando=''):\n    return consultar_version()\n",
    "def ejecutar_skill(comando=''):\n    texto = comando.lower()\n    return resultado\n",
    "def ejecutar_skill(comando=''):\n    if comando == 'compacto':\n        formato = 'short'\n    else:\n        formato = 'full'\n    return consultar_version(formato)\n",
    "def ejecutar_skill(comando=''):\n    resultado = consultar_version()\n    if comando == 'compacto':\n        return str(resultado)\n    return resultado\n",
    "def ejecutar_skill(comando=''):\n    if comando == 'compacto':\n        consultar_version()\n        return 'ok'\n    return consultar_version()\n",
    "def ejecutar_skill(comando=''):\n    for line in body.splitlines():\n        if 'fix' in line.lower():\n            print(line)\n    return 'ok'\n",
    "def ejecutar_skill():\n    for item in [{'body': 'fix'}]:\n        return item['body']\n    return 'empty'\n",
    "def ejecutar_skill():\n    for item in text.splitlines():\n        item = json.loads(item)\n        print(item['body'])\n    return 'ok'\n",
])
def test_valid_code_is_not_rejected(source):
    report = validate(source)
    assert report.success, report.to_prompt_context()


@pytest.mark.parametrize("expression", [
    "[item['body'] for item in text.splitlines()]",
    "[item['x'] for item in text.split()]",
])
def test_text_comprehension_string_index_fails(expression):
    report = validate(f"def ejecutar_skill():\n    return {expression}\n")
    assert not report.success
    assert any(check.name == "dynamic_text_index" and not check.success for check in report.checks)


def test_text_for_loop_string_index_fails():
    report = validate("def ejecutar_skill():\n    for item in text.splitlines():\n        print(item['body'])\n    return 'ok'\n")
    assert not report.success
    assert "Loop variable 'item' is text from splitlines()" in report.to_prompt_context()


@pytest.mark.parametrize("body", [
    "    print('ok')\n", "    return None\n",
    "    return print('ok')\n", "    def helper():\n        return 'ok'\n    print(helper())\n",
])
def test_print_or_nested_return_is_not_an_entrypoint_result(body):
    report = validate("def ejecutar_skill():\n" + body)
    assert not report.success
    assert any(check.name == "dynamic_result" and not check.success for check in report.checks)


def test_real_fixture_fails_before_review_and_diagnostics_reach_full_source_repair():
    source = FIXTURE.read_text(encoding="utf-8")
    service, coder, router, reviewer = service_with(
        [source_response(source), repair_response(COMPLETE), TESTS],
        [json.dumps({"approved": True, "blocking_issues": [], "advisory_issues": []})],
    )
    result = service.author(SkillAuthoringRequest(REQUEST))
    assert result.success, result.failure_reason
    assert not result.validation_reports[0].success
    assert result.diagnostics[0].review_skipped_reason == "invalid_source_functionality"
    assert result.diagnostics[0].review_approved is None
    assert result.diagnostics[0].review_attempts == 0
    assert len(reviewer.requests) == router.groq_calls == 1
    assert COMPLETE in reviewer.requests[0].code_diff
    repair = coder.prompts[1]
    for message in ("literal phrase", "Loop variable 'item' is text from split()", "string key 'body'", "print() is not a result"):
        assert message in repair
    assert source in repair
    assert "Return the full corrected source" in repair
    assert "not a password" in repair and "Return the requested result" in repair


def test_functional_failure_preserves_existing_frozen_plan():
    service, _coder, router, reviewer = service_with(
        [source_response(SOURCE), repair_response(FIXTURE.read_text(encoding="utf-8")), repair_response(COMPLETE), TESTS],
        [initial_review(), followup()],
    )
    result = service.author(SkillAuthoringRequest(REQUEST))
    assert result.success, result.failure_reason
    assert [item.blocking_unresolved for item in result.diagnostics[:3]] == [2, 2, 0]
    assert result.diagnostics[1].review_skipped_reason == "invalid_source_functionality"
    assert reviewer.requests[1].previous_source == SOURCE
    assert len(reviewer.requests) == router.groq_calls == 2
    initial_prompt = CodeReviewer.build_prompt(reviewer.requests[0])
    followup_prompt = CodeReviewer.build_followup_prompt(reviewer.requests[1])
    for prompt in (initial_prompt, followup_prompt):
        assert "second intent router" in prompt
        assert "runtime_failure or incorrect_result" in prompt
        assert "print-only output or None" in prompt
    assert "frozen-plan and regression-proof rules" in followup_prompt
