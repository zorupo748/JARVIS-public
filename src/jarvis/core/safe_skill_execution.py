"""Policy-gated execution for installed dynamic skills.

The service verifies the deployed artifact before it asks SkillDispatcher to
consult PolicyCore.  Only an ALLOW reaches the injected runtime.  The default
runtime uses a child process for timeout and output containment; it is not an
operating-system sandbox and does not restrict a permitted skill's privileges.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Mapping, Protocol

from jarvis.core.safe_skill_deployment import (
    EXECUTION_ACTION_NAME,
    DynamicSkillDeploymentMetadata,
    load_dynamic_skill_metadata,
    resolve_dynamic_skill_paths,
)
from jarvis.core.dynamic_skill_state import (
    DynamicSkillStateStore,
)
from jarvis.core.dynamic_skill_input import (
    DynamicSkillInputRequest, extract_dynamic_skill_result, validate_dynamic_skill_entries,
)
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    AuthorizedTask,
    FreshConfirmation,
    IdentityContext,
    PolicyDecision,
    PolicyDecisionKind,
    SessionSkillAuthorization,
)
from jarvis.security.skill_dispatch import SkillDispatcher


DEFAULT_DYNAMIC_RUNTIME_TIMEOUT_SECONDS = 30.0


class ExecutionFailureKind(str, Enum):
    PREFLIGHT = "preflight"
    POLICY = "policy"
    SKILL_EXCEPTION = "skill_exception"
    RUNTIME_TIMEOUT = "runtime_timeout"
    WORKER_INFRASTRUCTURE = "worker_infrastructure"
    RESULT_CONTRACT = "result_contract"


_RESERVED_PARAMETER_NAMES = frozenset(
    {
        "skill_name",
        "name",
        "module",
        "module_name",
        "path",
        "ruta",
        "dynamic_dir",
        "policy_action",
        "action",
        "source_hash",
        "hash",
        "metadata",
        "estado",
    }
)
_DEFAULT_DYNAMIC_SKILLS_DIR = Path(__file__).resolve().parents[1] / "skills" / "dynamic"
_DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class RuntimeExecutionResult:
    """One bounded child-runtime outcome; not a security authorization result."""

    success: bool
    result: object | None = None
    error: str | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    failure_kind: ExecutionFailureKind | None = None
    action: SecurityAction | None = None


class DynamicSkillRuntime(Protocol):
    def execute(
        self,
        *,
        skill_name: str,
        dynamic_skills_dir: Path,
        parameters: Mapping[str, object],
        expected_hash: str,
    ) -> RuntimeExecutionResult: ...


@dataclass(frozen=True)
class SafeSkillExecutionRequest:
    """Data-only request; artifact location and policy come from metadata, never params."""

    skill_name: str
    identity: IdentityContext
    parameters: Mapping[str, object] = field(default_factory=dict)
    confirmations: tuple[FreshConfirmation, ...] = ()
    continuation_task: AuthorizedTask | None = None
    session_skill_authorization: SessionSkillAuthorization | None = None
    expected_source_hash: str | None = None
    expected_metadata_hash: str | None = None
    expected_user_id: str | None = None


@dataclass(frozen=True)
class SafeSkillExecutionResult:
    executed: bool
    allowed: bool
    skill_name: str | None
    result: object | None
    policy_decision: PolicyDecision | None
    hash_verified: bool
    failure_reason: str | None = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    action: SecurityAction | None = None
    failure_kind: ExecutionFailureKind | None = None
    runtime_state: Mapping[str, object] | None = None
    input_request: DynamicSkillInputRequest | None = None


class SubprocessDynamicSkillRuntime:
    """Failure-contained child runtime, explicitly not an OS sandbox.

    The child inherits only the Python import root, Windows process essentials,
    and an already-present dynamic-skill opt-in.  It receives no cloud/API keys
    from this adapter.  A malicious or unsafe permitted skill can still access
    the user's account and operating system; a real sandbox is future work.
    """

    def __init__(
        self,
        *,
        project_root: Path | str | None = None,
        timeout_seconds: float = DEFAULT_DYNAMIC_RUNTIME_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._project_root = Path(project_root or _DEFAULT_PROJECT_ROOT).resolve()
        self._timeout_seconds = float(timeout_seconds)

    def execute(
        self,
        *,
        skill_name: str,
        dynamic_skills_dir: Path,
        parameters: Mapping[str, object],
        expected_hash: str,
    ) -> RuntimeExecutionResult:
        try:
            request_text = json.dumps(
                {
                    "skill_name": skill_name,
                    "dynamic_dir": str(dynamic_skills_dir),
                    "parameters": dict(parameters),
                    "expected_hash": expected_hash,
                },
                ensure_ascii=False,
            )
        except (TypeError, ValueError) as exc:
            return RuntimeExecutionResult(
                success=False,
                error=f"Dynamic skill parameters are not JSON serializable: {exc}",
            )

        command = (
            sys.executable,
            "-B",
            "-m",
            "jarvis.skills.dynamic_runtime_worker",
        )
        try:
            completed = subprocess.run(
                command,
                cwd=self._project_root,
                input=request_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=self._timeout_seconds,
                check=False,
                shell=False,
                env=self._minimal_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            return RuntimeExecutionResult(
                success=False,
                error=f"Dynamic runtime timed out after {self._timeout_seconds:g} seconds.",
                timed_out=True,
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
                failure_kind=ExecutionFailureKind.RUNTIME_TIMEOUT,
            )
        except OSError as exc:
            return RuntimeExecutionResult(
                success=False,
                error=f"Dynamic runtime could not start: {type(exc).__name__}: {exc}",
                failure_kind=ExecutionFailureKind.WORKER_INFRASTRUCTURE,
            )

        if completed.returncode != 0:
            return RuntimeExecutionResult(
                success=False,
                error=f"Dynamic runtime worker exited with code {completed.returncode}.",
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                failure_kind=ExecutionFailureKind.WORKER_INFRASTRUCTURE,
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return RuntimeExecutionResult(
                success=False,
                error="Dynamic runtime worker returned invalid structured output.",
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                failure_kind=ExecutionFailureKind.WORKER_INFRASTRUCTURE,
            )
        if not isinstance(payload, dict) or not isinstance(payload.get("ok"), bool):
            return RuntimeExecutionResult(
                success=False,
                error="Dynamic runtime worker returned an invalid result envelope.",
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
                failure_kind=ExecutionFailureKind.WORKER_INFRASTRUCTURE,
            )
        worker_stdout = payload.get("stdout", "")
        worker_stderr = payload.get("stderr", "")
        if not isinstance(worker_stdout, str) or not isinstance(worker_stderr, str):
            return RuntimeExecutionResult(
                success=False,
                error="Dynamic runtime worker returned invalid captured streams.",
                stdout=completed.stdout,
                stderr=completed.stderr,
                exit_code=completed.returncode,
            )
        if payload["ok"]:
            return RuntimeExecutionResult(
                success=True,
                result=payload.get("result"),
                stdout=worker_stdout,
                stderr=worker_stderr,
                exit_code=completed.returncode,
            )
        error = payload.get("error")
        return RuntimeExecutionResult(
            success=False,
            error=error if isinstance(error, str) else "Dynamic runtime failed without an error message.",
            stdout=worker_stdout,
            stderr=worker_stderr,
            exit_code=completed.returncode,
            failure_kind=(
                ExecutionFailureKind.SKILL_EXCEPTION
                if payload.get("failure_kind") == ExecutionFailureKind.SKILL_EXCEPTION.value
                else ExecutionFailureKind.RESULT_CONTRACT
                if payload.get("failure_kind") == ExecutionFailureKind.RESULT_CONTRACT.value
                else ExecutionFailureKind.WORKER_INFRASTRUCTURE
            ),
        )

    def _minimal_environment(self) -> dict[str, str]:
        environment = {
            "PYTHONPATH": str(self._project_root / "src"),
            "PYTHONUTF8": "1",
        }
        for variable in ("SYSTEMROOT", "WINDIR", "COMSPEC", "JARVIS_ENABLE_DYNAMIC_SKILLS"):
            value = os.environ.get(variable)
            if value:
                environment[variable] = value
        return environment


class SafeSkillExecutionService:
    """The single policy-gated path for an installed dynamic artifact.

    It performs artifact verification before calling ``SkillDispatcher``'s
    policy-only authorization method.  There is intentionally no direct runtime
    fallback for a denied, unregistered, altered, or malformed skill.
    """

    def __init__(
        self,
        dispatcher: SkillDispatcher,
        *,
        dynamic_skills_dir: Path | str | None = None,
        runtime: DynamicSkillRuntime | None = None,
        state_store: DynamicSkillStateStore | None = None,
    ) -> None:
        if not isinstance(dispatcher, SkillDispatcher):
            raise TypeError("dispatcher must be a SkillDispatcher")
        self._dispatcher = dispatcher
        self._dynamic_skills_dir = Path(dynamic_skills_dir or _DEFAULT_DYNAMIC_SKILLS_DIR)
        self._runtime = runtime or SubprocessDynamicSkillRuntime()
        self._state_store = state_store or DynamicSkillStateStore()

    def execute(self, request: SafeSkillExecutionRequest) -> SafeSkillExecutionResult:
        """Verify artifact, authorize through SkillDispatcher, then invoke runtime."""

        try:
            self._validate_request(request)
            paths = resolve_dynamic_skill_paths(self._dynamic_skills_dir, request.skill_name)
        except (TypeError, ValueError) as exc:
            return self._failure(request.skill_name if isinstance(request, SafeSkillExecutionRequest) else None, str(exc))

        if not paths.source.is_file() or paths.source.is_symlink():
            return self._failure(
                request.skill_name,
                "Installed dynamic skill source is missing.",
                failure_kind=ExecutionFailureKind.PREFLIGHT,
            )
        try:
            if not paths.metadata.is_file():
                raise ValueError("Installed dynamic skill metadata is missing.")
            metadata_hash = hashlib.sha256(paths.metadata.read_bytes()).hexdigest()
            metadata = load_dynamic_skill_metadata(self._dynamic_skills_dir, request.skill_name)
            if hashlib.sha256(paths.metadata.read_bytes()).hexdigest() != metadata_hash:
                raise ValueError("Dynamic skill metadata changed during verification.")
        except (OSError, ValueError) as exc:
            return self._failure(
                request.skill_name,
                str(exc),
                failure_kind=ExecutionFailureKind.PREFLIGHT,
            )

        try:
            actual_hash = hashlib.sha256(paths.source.read_bytes()).hexdigest()
        except OSError as exc:
            return self._failure(request.skill_name, f"Cannot verify dynamic skill source: {exc}")
        if actual_hash != metadata.source_hash:
            return self._failure(
                request.skill_name,
                "Installed dynamic skill source hash does not match deployed metadata.",
                hash_verified=False,
                failure_kind=ExecutionFailureKind.PREFLIGHT,
            )
        if metadata.execution_action_name != EXECUTION_ACTION_NAME:
            return self._failure(
                request.skill_name,
                "Installed dynamic skill has no registered execution action.",
                failure_kind=ExecutionFailureKind.PREFLIGHT,
            )
        if ((request.expected_source_hash is not None and actual_hash != request.expected_source_hash)
                or (request.expected_metadata_hash is not None and metadata_hash != request.expected_metadata_hash)):
            return self._failure(request.skill_name, "Pending input cancelled: dynamic skill source or metadata changed.")
        if request.expected_user_id is not None and request.identity.user_id != request.expected_user_id:
            return self._failure(request.skill_name, "Pending input cancelled: user identity changed.")

        action = SecurityAction(
            action=metadata.execution_action_name,
            description=f"Execute installed dynamic skill '{request.skill_name}'",
            target=metadata.execution_target,
            metadata={
                "skill_name": request.skill_name,
                "source_hash": actual_hash,
                "deployment_metadata_hash": metadata_hash,
                "parameters": dict(request.parameters),
            },
        )
        authorization = self._dispatcher.authorize_action(
            action,
            identity=request.identity,
            confirmations=request.confirmations,
            continuation_task=request.continuation_task,
            session_skill_authorization=request.session_skill_authorization,
        )
        if authorization.decision.kind is not PolicyDecisionKind.ALLOW:
            return SafeSkillExecutionResult(
                executed=False,
                allowed=False,
                skill_name=request.skill_name,
                result=None,
                policy_decision=authorization.decision,
                hash_verified=True,
                failure_reason=authorization.message,
                action=action,
                failure_kind=ExecutionFailureKind.POLICY,
            )

        runtime_state = self._state_store.load(request.skill_name)
        try:
            runtime_parameters = dict(request.parameters)
            runtime_parameters["estado"] = runtime_state
            runtime_result = self._runtime.execute(
                skill_name=request.skill_name,
                dynamic_skills_dir=paths.root,
                parameters=runtime_parameters,
                expected_hash=actual_hash,
            )
        except Exception as exc:
            return SafeSkillExecutionResult(
                executed=False,
                allowed=True,
                skill_name=request.skill_name,
                result=None,
                policy_decision=authorization.decision,
                hash_verified=True,
                failure_reason=f"Dynamic runtime raised {type(exc).__name__}: {exc}",
                action=action,
                failure_kind=ExecutionFailureKind.WORKER_INFRASTRUCTURE,
                runtime_state=runtime_state,
            )

        visible_result = None
        input_request = None
        if runtime_result.success:
            try:
                visible_result, new_state, input_request = extract_dynamic_skill_result(runtime_result.result)
            except ValueError as exc:
                return SafeSkillExecutionResult(
                    executed=False, allowed=True, skill_name=request.skill_name, result=None,
                    policy_decision=authorization.decision, hash_verified=True,
                    failure_reason=f"Invalid dynamic skill input envelope: {exc}", action=action,
                    failure_kind=ExecutionFailureKind.RESULT_CONTRACT, runtime_state=runtime_state,
                )
            if new_state is not None:
                try:
                    self._state_store.save(request.skill_name, new_state)
                except (OSError, ValueError) as exc:
                    if input_request is not None:
                        return SafeSkillExecutionResult(
                            executed=False, allowed=True, skill_name=request.skill_name, result=None,
                            policy_decision=authorization.decision, hash_verified=True,
                            failure_reason=f"Cannot persist input-request state: {exc}", action=action,
                            failure_kind=ExecutionFailureKind.RESULT_CONTRACT, runtime_state=runtime_state,
                        )
                else:
                    if input_request is not None:
                        runtime_state = new_state

        return SafeSkillExecutionResult(
            executed=runtime_result.success,
            allowed=True,
            skill_name=request.skill_name,
            result=visible_result,
            policy_decision=authorization.decision,
            hash_verified=True,
            failure_reason=runtime_result.error,
            timed_out=runtime_result.timed_out,
            stdout=runtime_result.stdout,
            stderr=runtime_result.stderr,
            exit_code=runtime_result.exit_code,
            action=action,
            failure_kind=runtime_result.failure_kind,
            runtime_state=runtime_state,
            input_request=input_request,
        )

    @staticmethod
    def _validate_request(request: SafeSkillExecutionRequest) -> None:
        if not isinstance(request, SafeSkillExecutionRequest):
            raise TypeError("request must be a SafeSkillExecutionRequest")
        if not isinstance(request.identity, IdentityContext):
            raise TypeError("identity must be an IdentityContext")
        if not isinstance(request.parameters, Mapping) or any(
            not isinstance(key, str) for key in request.parameters
        ):
            raise TypeError("parameters must be a mapping with string keys")
        reserved = _RESERVED_PARAMETER_NAMES.intersection(request.parameters)
        if reserved:
            raise ValueError(
                "parameters may not alter artifact routing or policy: " + ", ".join(sorted(reserved))
            )
        if "comando" in request.parameters and not isinstance(request.parameters["comando"], str):
            raise ValueError("comando must be a string")
        if "entradas" in request.parameters:
            validate_dynamic_skill_entries(request.parameters["entradas"])
        for digest in (request.expected_source_hash, request.expected_metadata_hash):
            if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
                raise ValueError("Expected artifact binding must be a lowercase SHA-256 digest.")
        if request.expected_user_id is not None and (not isinstance(request.expected_user_id, str) or not request.expected_user_id.strip()):
            raise ValueError("Expected user binding must be a non-empty string.")
        try:
            json.dumps(dict(request.parameters), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Dynamic skill parameters are not JSON serializable: {exc}") from exc
        if not isinstance(request.confirmations, tuple) or not all(
            isinstance(item, FreshConfirmation) for item in request.confirmations
        ):
            raise TypeError("confirmations must be a tuple of FreshConfirmation values")
        if request.continuation_task is not None and not isinstance(request.continuation_task, AuthorizedTask):
            raise TypeError("continuation_task must be an AuthorizedTask or None")
        if request.session_skill_authorization is not None and not isinstance(
            request.session_skill_authorization, SessionSkillAuthorization
        ):
            raise TypeError("session_skill_authorization must be a SessionSkillAuthorization or None")

    @staticmethod
    def _failure(
        skill_name: str | None,
        reason: str,
        *,
        hash_verified: bool = False,
        failure_kind: ExecutionFailureKind = ExecutionFailureKind.PREFLIGHT,
    ) -> SafeSkillExecutionResult:
        return SafeSkillExecutionResult(
            executed=False,
            allowed=False,
            skill_name=skill_name,
            result=None,
            policy_decision=None,
            hash_verified=hash_verified,
            failure_reason=reason,
            failure_kind=failure_kind,
        )


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


__all__ = [
    "DEFAULT_DYNAMIC_RUNTIME_TIMEOUT_SECONDS",
    "DynamicSkillRuntime",
    "RuntimeExecutionResult",
    "SafeSkillExecutionRequest",
    "SafeSkillExecutionResult",
    "SafeSkillExecutionService",
    "SubprocessDynamicSkillRuntime",
    "ExecutionFailureKind",
]
