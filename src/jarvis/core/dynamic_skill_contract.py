"""Deterministic ABI shared by dynamic-skill validation and invocation."""

from __future__ import annotations

import inspect
from typing import Callable, Mapping

from jarvis.core.dynamic_skill_input import validate_dynamic_skill_entries


class DynamicSkillContractError(ValueError):
    """The entrypoint cannot be invoked through the canonical dynamic ABI."""


SOURCE_ENTRYPOINT_CONTRACT = """The public entrypoint must be a module-level synchronous Python function named
ejecutar_skill. Its canonical natural-language input is comando, the original
user request passed unchanged by JARVIS. If input is needed, prefer the signature
def ejecutar_skill(comando: str = ""):
If no input is needed, use the signature
def ejecutar_skill():
A required comando is also allowed, including a
keyword-only comando. No other required parameter is allowed: do not require
query, usuario, prompt, texto, repo, or any other name. Do not use *args,
positional-only comando, decorators, async functions, or generators for this
entrypoint. Optional explicit keyword parameters and **kwargs are allowed.
Only when the user requests memory across separate executions, the entrypoint
may additionally accept estado=None, for example
def ejecutar_skill(comando: str = "", estado: dict | None = None):
or the keyword-only equivalent. For this opt-in state ABI, return an envelope
with __jarvis_data__ for the user-visible result and __jarvis_state__ for the
new JSON-safe state. Skills that do not need persistence do not need to accept
estado or return an envelope. Never persist with function attributes or globals;
the worker subprocess ends after each execution. Do not write skill-owned files
for ordinary cross-execution state: use estado and __jarvis_state__ instead.
The first state value may be an empty dict: do not assume estado["key"] exists;
use estado.get("key"), a presence check, or initialize it before reading.
Do not replace or rebind ejecutar_skill after its definition.
JARVIS already selected this skill: comando is context, not a password or a
second intent router. Execute the skill's capability directly; do not gate it
on equality or containment of an exact phrase. Harmless variations in casing,
punctuation and wording must not prevent execution of the selected capability.
Return the requested result to JARVIS, preferably a str or JSON-serializable
dict/list. print() is only diagnostic output and must not be the sole response.
Do not normally finish with None when the user needs an answer. Use strings and
dictionaries according to their actual structure: split()/splitlines() produce
text lines, not dictionaries with a 'body' key."""

SOURCE_ENTRYPOINT_CONTRACT += """
If necessary data is genuinely missing, use the optional entradas=None ABI:
def ejecutar_skill(comando: str = "", estado=None, entradas=None):
entradas is a JARVIS-controlled dict of text answers. The original comando stays
unchanged across continuations. Keyword-only variants and **kwargs are supported.
Request an input by returning exactly an envelope with __jarvis_data__ set to
None, optional __jarvis_state__ for the JSON-safe state, and
__jarvis_input_request__ = {"field": "identifier", "prompt": "Question for the user", "kind": "text"}.
field must be a lowercase identifier of at most 64 characters, not a routing or
ABI parameter; prompt is non-empty and at most 600 characters; kind is text.
No callbacks, code, paths or action objects are allowed in the input request.
Read the answer from (entradas or {}).get(field). Never encode a request only as
a question in a final string. When finished, omit __jarvis_input_request__ and
return the real result. Input requests are bounded to 3 continuations.
FIXED CONFIGURATION IN THE ORIGINAL USER REQUEST:
Use non-secret identifiers/configuration explicitly supplied by the original
request (repository, tracking code, URL, playlist, device ID, concrete parameters)
directly, or preserve them through the central estado ABI if appropriate.
Do not ask again for a configured value unless it is expired, invalid, explicitly
variable, or there is a concrete functional reason. Check configured values,
then existing state/entradas, before requesting genuinely missing input.
Distinguish configuration from credentials: never bake API keys, tokens,
passwords or other secrets into source, ordinary state, summaries or logs.
Missing credentials need an established secure mechanism; do not treat them
as ordinary fixed configuration or request them through this text-input ABI.
"""


FUNCTIONAL_REVIEW_CONTRACT = """FUNCTIONALITY AGAINST THE ORIGINAL REQUEST:
JARVIS already selected the skill. It must execute its capability without an
unnecessary exact-phrase password or second intent router; harmless casing,
punctuation and wording changes must not prevent the requested operation.
Check concrete types and data paths constructed by the source: split/splitlines
items are strings, not dictionaries. Obvious current type/data-path failures
are runtime_failure or incorrect_result blockers. The entrypoint must return
the requested result to its caller; print-only output or None when an answer
is required is user_requirement_unmet or incorrect_result. Use concrete source
evidence and the original requirement, not hypothetical hardening concerns.
Every dynamic-skill execution runs in a fresh subprocess. Function attributes
and globals do not persist across executions. If the original requirement asks
to remember data between executions, require the optional central estado ABI
and __jarvis_state__ envelope; do not approve function attributes or globals as
persistence and do not require skill-owned state files. The initial state may be
{}; direct estado["key"] access without a guard can raise KeyError and is a
runtime_failure blocker. Require .get(), a membership check, or initialization."""

FUNCTIONAL_REVIEW_CONTRACT += """
Check FIXED CONFIGURATION against the original request. If the user supplied a
necessary non-secret identifier or parameter and the implementation ignores it
and asks the user to provide it again without a concrete functional reason,
report a user_requirement_unmet blocker, with the exact source evidence and
requirement relation. This applies generically to repositories, tracking codes,
URLs, playlists and device IDs, without special-casing any service or identifier.
Legitimately variable, invalid or expired values may require input.
Necessary missing input must use the structured __jarvis_input_request__ envelope
with null __jarvis_data__, optional JSON-safe __jarvis_state__, and exactly field,
prompt and kind=text. Verify that optional entradas is consumed on continuation,
that the original comando is preserved, and that completion returns a result.
An input request is not a runtime failure. Do not require another reviewer or
self-repair simply because the skill needs a user answer. Credentials/API keys/
tokens/passwords are secrets, never ordinary fixed configuration to hardcode or
log. Do not approve prompting for credentials through ordinary text inputs.
"""


def validate_entrypoint_signature(
    signature: inspect.Signature, *, entrypoint_name: str = "ejecutar_skill"
) -> None:
    """Reject unsupported required inputs independently of supplied parameters."""

    parameters = tuple(signature.parameters.values())
    unsupported = [
        item.name for item in parameters
        if item.default is inspect.Parameter.empty
        and item.kind not in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        and item.name != "comando"
    ]
    if unsupported:
        raise DynamicSkillContractError(
            f"{entrypoint_name} requires unsupported parameter(s): " + ", ".join(unsupported)
        )
    if any(item.kind is inspect.Parameter.VAR_POSITIONAL for item in parameters):
        raise DynamicSkillContractError(f"{entrypoint_name} may not use *args")
    if any(
        item.name == "comando" and item.kind is inspect.Parameter.POSITIONAL_ONLY
        for item in parameters
    ):
        raise DynamicSkillContractError(f"{entrypoint_name} comando must accept a keyword argument")
    if any(
        item.name in {"estado", "entradas"} and item.kind is inspect.Parameter.POSITIONAL_ONLY
        for item in parameters
    ):
        raise DynamicSkillContractError(f"{entrypoint_name} estado and entradas must accept keyword arguments")


def prepare_entrypoint_call(
    entrypoint: Callable[..., object], parameters: Mapping[str, object]
) -> dict[str, object]:
    """Bind once before invocation; never retry an entrypoint after TypeError."""

    name = getattr(entrypoint, "__name__", "ejecutar_skill")
    if (inspect.iscoroutinefunction(entrypoint) or inspect.isgeneratorfunction(entrypoint)
            or inspect.isasyncgenfunction(entrypoint)):
        raise DynamicSkillContractError(f"{name} must be a synchronous non-generator function")
    try:
        signature = inspect.signature(entrypoint, follow_wrapped=False)
    except (TypeError, ValueError) as exc:
        raise DynamicSkillContractError(f"Cannot inspect {name} signature: {exc}") from exc
    validate_entrypoint_signature(signature, entrypoint_name=name)
    arguments = dict(parameters)
    if "comando" in arguments and not isinstance(arguments["comando"], str):
        raise DynamicSkillContractError("comando must be a string")
    if "entradas" in arguments:
        arguments["entradas"] = validate_dynamic_skill_entries(arguments["entradas"])
    accepts_kwargs = any(
        item.kind is inspect.Parameter.VAR_KEYWORD
        for item in signature.parameters.values()
    )
    command_parameter = signature.parameters.get("comando")
    accepts_command = command_parameter is not None and command_parameter.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY
    )
    state_parameter = signature.parameters.get("estado")
    accepts_state = state_parameter is not None and state_parameter.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY
    )
    accepts_state = accepts_state or accepts_kwargs
    if not accepts_state:
        # State is JARVIS-owned context. Its absence from a legacy ABI is
        # compatible and must not turn an otherwise valid call into an error.
        arguments.pop("estado", None)
    inputs_parameter = signature.parameters.get("entradas")
    accepts_inputs = inputs_parameter is not None and inputs_parameter.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY
    )
    if not accepts_inputs and not accepts_kwargs:
        arguments.pop("entradas", None)
    if not accepts_command and not accepts_kwargs:
        # Only the canonical context may be omitted. Explicit inputs still bind
        # strictly and must not silently disappear for a zero-argument skill.
        arguments.pop("comando", None)
    try:
        signature.bind(**arguments)
    except TypeError as exc:
        raise DynamicSkillContractError(f"{name} parameters do not match its signature: {exc}") from exc
    return arguments
