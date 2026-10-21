"""Fail-closed staging and installation for reviewed dynamic-skill proposals.

Deployment writes reviewed bytes and a verifiable sidecar only.  It never
imports, registers, executes, tests, repairs, or otherwise activates a skill.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Mapping

from jarvis.core.safe_skill_authoring import SkillAuthoringResult
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    ConfirmationLedger,
    DeterministicPolicyEvaluator,
    FreshConfirmation,
    IdentityContext,
    PolicyDecision,
    PolicyDecisionKind,
    PolicyRequest,
)


DEPLOYMENT_ACTION_NAME = "deploy_dynamic_skill"
EXECUTION_ACTION_NAME = "execute_dynamic_skill"
DYNAMIC_SKILL_METADATA_SCHEMA_VERSION = 1
DYNAMIC_SKILL_METADATA_SUFFIX = ".skill.json"
_SKILL_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "con", "prn", "aux", "nul",
        *(f"com{number}" for number in range(1, 10)),
        *(f"lpt{number}" for number in range(1, 10)),
    }
)
_DEFAULT_DYNAMIC_SKILLS_DIR = Path(__file__).resolve().parents[1] / "skills" / "dynamic"


@dataclass(frozen=True)
class DynamicSkillPaths:
    """Resolved paths inside one dynamic-skill directory."""

    root: Path
    source: Path
    metadata: Path


@dataclass(frozen=True)
class DynamicSkillDeploymentMetadata:
    """Minimal persisted authorization binding for an installed skill."""

    schema_version: int
    skill_name: str
    source_hash: str
    execution_action_name: str
    execution_target: str

    @classmethod
    def from_mapping(cls, payload: object) -> "DynamicSkillDeploymentMetadata":
        if not isinstance(payload, dict):
            raise ValueError("Dynamic skill metadata must be a JSON object.")
        schema_version = payload.get("schema_version")
        skill_name = payload.get("skill_name")
        source_hash = payload.get("source_hash")
        execution_action_name = payload.get("execution_action_name")
        execution_target = payload.get("execution_target")
        if schema_version != DYNAMIC_SKILL_METADATA_SCHEMA_VERSION:
            raise ValueError("Dynamic skill metadata schema version is not supported.")
        _validate_skill_name(skill_name)
        if not isinstance(source_hash, str) or not _SHA256_PATTERN.fullmatch(source_hash):
            raise ValueError("Dynamic skill metadata has an invalid SHA-256 hash.")
        if execution_action_name != EXECUTION_ACTION_NAME:
            raise ValueError("Dynamic skill metadata has no allowed execution policy action.")
        expected_target = execution_target_for(skill_name, source_hash)
        if execution_target != expected_target:
            raise ValueError("Dynamic skill metadata target does not match its name and hash.")
        return cls(
            schema_version=schema_version,
            skill_name=skill_name,
            source_hash=source_hash,
            execution_action_name=execution_action_name,
            execution_target=execution_target,
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "schema_version": self.schema_version,
                "skill_name": self.skill_name,
                "source_hash": self.source_hash,
                "execution_action_name": self.execution_action_name,
                "execution_target": self.execution_target,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class SkillDeploymentRequest:
    """A reviewed proposal plus the independent facts needed to deploy it."""

    authoring_result: SkillAuthoringResult
    identity: IdentityContext
    explicit_authorization: bool
    policy_action: SecurityAction
    original_user_request: str
    confirmations: tuple[FreshConfirmation, ...] = ()
    replace_existing_source_hash: str | None = None


@dataclass(frozen=True)
class StagedSkill:
    """Immutable deployment bytes and security bindings for one skill."""

    skill_name: str
    source_code: str
    source_hash: str
    implementation_summary: str
    dependencies: tuple[str, ...]
    original_user_request: str
    authoring_iterations: int
    policy_action_name: str
    policy_target: str
    execution_action_name: str
    execution_target: str
    policy_metadata: Mapping[str, object]
    destination: Path
    metadata_destination: Path
    replace_existing_source_hash: str | None = None


@dataclass(frozen=True)
class SkillDeploymentResult:
    """Structured deployment outcome; installation never implies activation."""

    success: bool
    staged: StagedSkill | None
    installed: bool
    skill_name: str | None
    destination: Path | None
    source_hash: str | None
    policy_prepared: bool
    failure_reason: str | None = None
    conflict: bool = False
    authorization_required: bool = False
    decision: PolicyDecision | None = None

    @property
    def policy_registered(self) -> bool:
        return self.policy_prepared


def execution_target_for(skill_name: str, source_hash: str) -> str:
    """Create the policy target that binds an execution confirmation to bytes."""

    _validate_skill_name(skill_name)
    if not isinstance(source_hash, str) or not _SHA256_PATTERN.fullmatch(source_hash):
        raise ValueError("source_hash must be a lowercase SHA-256 hex digest.")
    return f"dynamic/{skill_name}.py#sha256-{source_hash}"


def resolve_dynamic_skill_paths(
    dynamic_skills_dir: Path | str,
    skill_name: str,
    *,
    create_directory: bool = False,
) -> DynamicSkillPaths:
    """Resolve source and metadata paths while rejecting escapes and symlinks."""

    _validate_skill_name(skill_name)
    raw_root = Path(dynamic_skills_dir)
    if create_directory:
        raw_root.mkdir(parents=True, exist_ok=True)
    if not raw_root.is_dir():
        raise ValueError("The dynamic skills directory does not exist.")
    if raw_root.is_symlink():
        raise ValueError("The configured dynamic skills directory must not be a symlink.")

    root = raw_root.resolve(strict=True)
    source = _resolve_child(root, raw_root / f"{skill_name}.py")
    metadata = _resolve_child(root, raw_root / f"{skill_name}{DYNAMIC_SKILL_METADATA_SUFFIX}")
    return DynamicSkillPaths(root=root, source=source, metadata=metadata)


def load_dynamic_skill_metadata(
    dynamic_skills_dir: Path | str,
    skill_name: str,
) -> DynamicSkillDeploymentMetadata:
    """Read only authenticated-format deployment metadata; never import a skill."""

    paths = resolve_dynamic_skill_paths(dynamic_skills_dir, skill_name)
    if not paths.metadata.is_file() or paths.metadata.is_symlink():
        raise ValueError("Dynamic skill deployment metadata is missing.")
    try:
        payload = json.loads(paths.metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Dynamic skill deployment metadata cannot be read.") from exc
    metadata = DynamicSkillDeploymentMetadata.from_mapping(payload)
    if metadata.skill_name != skill_name:
        raise ValueError("Dynamic skill metadata belongs to a different skill.")
    return metadata


class SafeSkillDeploymentService:
    """Stage and atomically install a reviewed proposal without activation.

    The existing deterministic policy registry controls deployment.  Every
    successful installation also persists an execution action bound to the
    source SHA-256; execution is a distinct, stricter action in PolicyCore.
    """

    def __init__(
        self,
        *,
        dynamic_skills_dir: Path | str | None = None,
        evaluator: DeterministicPolicyEvaluator | None = None,
        confirmation_ledger: ConfirmationLedger | None = None,
    ) -> None:
        if evaluator is not None and confirmation_ledger is None:
            raise ValueError("An injected evaluator must share its ConfirmationLedger.")
        self._dynamic_skills_dir = Path(dynamic_skills_dir or _DEFAULT_DYNAMIC_SKILLS_DIR)
        self._confirmation_ledger = confirmation_ledger or ConfirmationLedger()
        self._evaluator = evaluator or DeterministicPolicyEvaluator(
            confirmation_ledger=self._confirmation_ledger
        )

    def stage(self, request: SkillDeploymentRequest) -> SkillDeploymentResult:
        """Validate and prepare the exact bytes without writing a skill or metadata."""

        return self._prepare(request, consume_confirmation=False)

    def deploy(self, request: SkillDeploymentRequest) -> SkillDeploymentResult:
        """Authorize, stage, and atomically publish source plus sidecar metadata."""

        prepared = self._prepare(request, consume_confirmation=True)
        if not prepared.success or prepared.staged is None:
            return prepared
        staged = prepared.staged
        if self._source_hash(staged.source_code) != staged.source_hash:
            return self._failure(
                staged=staged,
                reason="The staged source no longer matches its authorized SHA-256 hash.",
                policy_prepared=True,
                decision=prepared.decision,
            )
        if staged.replace_existing_source_hash is None and (
            staged.destination.exists()
            or staged.destination.is_symlink()
            or staged.metadata_destination.exists()
            or staged.metadata_destination.is_symlink()
        ):
            return self._failure(
                staged=staged,
                reason="A skill or deployment metadata with this name already exists; overwrite is not enabled.",
                policy_prepared=True,
                decision=prepared.decision,
                conflict=True,
            )

        replacement_backup: tuple[bytes, str] | None = None
        if staged.replace_existing_source_hash is not None:
            try:
                self._verify_replacement_target(staged)
                replacement_backup = (
                    staged.destination.read_bytes(),
                    staged.metadata_destination.read_text(encoding="utf-8"),
                )
            except (OSError, ValueError) as exc:
                return self._failure(
                    staged=staged,
                    reason=f"The installed skill changed before repair deployment: {exc}",
                    policy_prepared=True,
                    decision=prepared.decision,
                    conflict=True,
                )

        source_published = False
        try:
            if replacement_backup is None:
                self._atomic_write(staged.destination, staged.source_code)
            else:
                self._atomic_replace(staged.destination, staged.source_code)
            source_published = True
            metadata = DynamicSkillDeploymentMetadata(
                schema_version=DYNAMIC_SKILL_METADATA_SCHEMA_VERSION,
                skill_name=staged.skill_name,
                source_hash=staged.source_hash,
                execution_action_name=staged.execution_action_name,
                execution_target=staged.execution_target,
            )
            if replacement_backup is None:
                self._atomic_write(staged.metadata_destination, metadata.to_json())
            else:
                self._atomic_replace(staged.metadata_destination, metadata.to_json())
        except OSError as exc:
            if replacement_backup is not None:
                try:
                    self._atomic_replace(staged.destination, replacement_backup[0].decode("utf-8"))
                    self._atomic_replace(staged.metadata_destination, replacement_backup[1])
                except (OSError, UnicodeError):
                    pass
            else:
                if source_published:
                    try:
                        staged.destination.unlink(missing_ok=True)
                    except OSError:
                        pass
                try:
                    staged.metadata_destination.unlink(missing_ok=True)
                except OSError:
                    pass
            return self._failure(
                staged=staged,
                reason=f"Atomic installation failed: {type(exc).__name__}: {exc}",
                policy_prepared=True,
                decision=prepared.decision,
            )

        return SkillDeploymentResult(
            success=True,
            staged=staged,
            installed=True,
            skill_name=staged.skill_name,
            destination=staged.destination,
            source_hash=staged.source_hash,
            policy_prepared=True,
            decision=prepared.decision,
        )

    def _prepare(
        self,
        request: SkillDeploymentRequest,
        *,
        consume_confirmation: bool,
    ) -> SkillDeploymentResult:
        try:
            self._validate_request_shape(request)
            authoring = request.authoring_result
            proposal = self._validated_proposal(authoring)
            paths = resolve_dynamic_skill_paths(
                self._dynamic_skills_dir,
                proposal.skill_name,
                create_directory=True,
            )
        except (TypeError, ValueError) as exc:
            return self._failure(reason=str(exc))

        source_hash = self._source_hash(proposal.source_code)
        replacement_hash = request.replace_existing_source_hash
        if replacement_hash is not None:
            if not isinstance(replacement_hash, str) or not _SHA256_PATTERN.fullmatch(replacement_hash):
                return self._failure(
                    skill_name=proposal.skill_name,
                    destination=paths.source,
                    source_hash=source_hash,
                    reason="The expected existing source hash is invalid.",
                    conflict=True,
                )
            try:
                self._verify_replacement_target(
                    StagedSkill(
                        skill_name=proposal.skill_name,
                        source_code=proposal.source_code,
                        source_hash=source_hash,
                        implementation_summary=proposal.implementation_summary,
                        dependencies=proposal.dependencies,
                        original_user_request=request.original_user_request,
                        authoring_iterations=authoring.iterations,
                        policy_action_name=DEPLOYMENT_ACTION_NAME,
                        policy_target="",
                        execution_action_name=EXECUTION_ACTION_NAME,
                        execution_target=execution_target_for(proposal.skill_name, source_hash),
                        policy_metadata=MappingProxyType({}),
                        destination=paths.source,
                        metadata_destination=paths.metadata,
                        replace_existing_source_hash=replacement_hash,
                    )
                )
            except (OSError, ValueError) as exc:
                return self._failure(
                    skill_name=proposal.skill_name,
                    destination=paths.source,
                    source_hash=source_hash,
                    reason=f"The existing skill is not eligible for safe replacement: {exc}",
                    conflict=True,
                )
        if not request.explicit_authorization:
            return self._failure(
                skill_name=proposal.skill_name,
                destination=paths.source,
                source_hash=source_hash,
                reason="Explicit security authorization is required before deployment.",
                authorization_required=True,
            )

        action = self._build_deployment_action(request.policy_action, proposal.skill_name, source_hash)
        if action is None:
            return self._failure(
                skill_name=proposal.skill_name,
                destination=paths.source,
                source_hash=source_hash,
                reason="A dedicated deploy_dynamic_skill policy action is required; unrelated actions cannot authorize deployment.",
                authorization_required=True,
            )

        decision = self._evaluator.evaluate(
            PolicyRequest(
                action=action,
                identity=request.identity,
                confirmations=tuple(request.confirmations),
            )
        )
        if decision.kind is not PolicyDecisionKind.ALLOW:
            return self._failure(
                skill_name=proposal.skill_name,
                destination=paths.source,
                source_hash=source_hash,
                reason=f"Deployment denied by policy: {decision.reason.value}.",
                authorization_required=True,
                decision=decision,
            )
        if consume_confirmation and decision.confirmation_ids_to_consume:
            if not self._confirmation_ledger.consume(decision):
                return self._failure(
                    skill_name=proposal.skill_name,
                    destination=paths.source,
                    source_hash=source_hash,
                    reason="The required confirmation is no longer available.",
                    authorization_required=True,
                    decision=decision,
                )

        execution_target = execution_target_for(proposal.skill_name, source_hash)
        staged = StagedSkill(
            skill_name=proposal.skill_name,
            source_code=proposal.source_code,
            source_hash=source_hash,
            implementation_summary=proposal.implementation_summary,
            dependencies=proposal.dependencies,
            original_user_request=request.original_user_request,
            authoring_iterations=authoring.iterations,
            policy_action_name=action.action,
            policy_target=action.target or "",
            execution_action_name=EXECUTION_ACTION_NAME,
            execution_target=execution_target,
            policy_metadata=MappingProxyType(dict(action.metadata)),
            destination=paths.source,
            metadata_destination=paths.metadata,
            replace_existing_source_hash=replacement_hash,
        )
        return SkillDeploymentResult(
            success=True,
            staged=staged,
            installed=False,
            skill_name=staged.skill_name,
            destination=paths.source,
            source_hash=source_hash,
            policy_prepared=True,
            decision=decision,
        )

    @staticmethod
    def _validated_proposal(authoring: SkillAuthoringResult):
        if not isinstance(authoring, SkillAuthoringResult):
            raise TypeError("authoring_result must be a SkillAuthoringResult.")
        if not authoring.success:
            raise ValueError("Authoring did not complete successfully.")
        if authoring.proposal is None:
            raise ValueError("A successful authoring result requires a final proposal.")
        if not authoring.validation_reports or not authoring.validation_reports[-1].success:
            raise ValueError("The final local validation report is not successful.")
        if not authoring.review_results or not authoring.review_results[-1].approved:
            raise ValueError("The final code review is not approved.")
        if authoring.unavailable_dependencies:
            raise ValueError("Required dependencies are not available; installation is forbidden.")
        return authoring.proposal

    @staticmethod
    def _validate_request_shape(request: SkillDeploymentRequest) -> None:
        if not isinstance(request, SkillDeploymentRequest):
            raise TypeError("request must be a SkillDeploymentRequest.")
        if not isinstance(request.identity, IdentityContext):
            raise TypeError("identity must be an IdentityContext.")
        if not isinstance(request.explicit_authorization, bool):
            raise TypeError("explicit_authorization must be a bool.")
        if not isinstance(request.policy_action, SecurityAction):
            raise TypeError("policy_action must be a SecurityAction.")
        if not isinstance(request.original_user_request, str) or not request.original_user_request:
            raise ValueError("original_user_request must be non-empty text from authoring.")
        if not isinstance(request.confirmations, tuple) or not all(
            isinstance(item, FreshConfirmation) for item in request.confirmations
        ):
            raise TypeError("confirmations must be a tuple of FreshConfirmation values.")
        if request.replace_existing_source_hash is not None and (
            not isinstance(request.replace_existing_source_hash, str)
            or not _SHA256_PATTERN.fullmatch(request.replace_existing_source_hash)
        ):
            raise ValueError("replace_existing_source_hash must be a lowercase SHA-256 digest.")

    @staticmethod
    def _build_deployment_action(
        descriptor: SecurityAction,
        skill_name: str,
        source_hash: str,
    ) -> SecurityAction | None:
        if descriptor.action != DEPLOYMENT_ACTION_NAME:
            return None
        target = execution_target_for(skill_name, source_hash)
        metadata = dict(descriptor.metadata)
        metadata.update({"skill_name": skill_name, "source_hash": source_hash})
        return SecurityAction(
            action=DEPLOYMENT_ACTION_NAME,
            description=descriptor.description or "Deploy reviewed dynamic skill",
            target=target,
            execution_channel=descriptor.execution_channel,
            metadata=metadata,
        )

    @staticmethod
    def _source_hash(source_code: str) -> str:
        return hashlib.sha256(source_code.encode("utf-8")).hexdigest()

    @staticmethod
    def _atomic_write(destination: Path, contents: str) -> None:
        """Write a sibling temporary file, then publish it without overwrite."""

        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, destination)
            temporary.unlink()
        except OSError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    @staticmethod
    def _atomic_replace(destination: Path, contents: str) -> None:
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _verify_replacement_target(self, staged: StagedSkill) -> None:
        expected_hash = staged.replace_existing_source_hash
        if expected_hash is None:
            raise ValueError("No existing source hash was supplied.")
        if (
            not staged.destination.is_file()
            or staged.destination.is_symlink()
            or not staged.metadata_destination.is_file()
            or staged.metadata_destination.is_symlink()
        ):
            raise ValueError("The installed source or metadata is missing or unsafe.")
        metadata = load_dynamic_skill_metadata(self._dynamic_skills_dir, staged.skill_name)
        actual_hash = hashlib.sha256(staged.destination.read_bytes()).hexdigest()
        if metadata.source_hash != expected_hash or actual_hash != expected_hash:
            raise ValueError("The installed source no longer matches its verified hash.")

    @staticmethod
    def _failure(
        *,
        staged: StagedSkill | None = None,
        skill_name: str | None = None,
        destination: Path | None = None,
        source_hash: str | None = None,
        reason: str,
        policy_prepared: bool = False,
        conflict: bool = False,
        authorization_required: bool = False,
        decision: PolicyDecision | None = None,
    ) -> SkillDeploymentResult:
        return SkillDeploymentResult(
            success=False,
            staged=staged,
            installed=False,
            skill_name=skill_name or (staged.skill_name if staged else None),
            destination=destination or (staged.destination if staged else None),
            source_hash=source_hash or (staged.source_hash if staged else None),
            policy_prepared=policy_prepared,
            failure_reason=reason,
            conflict=conflict,
            authorization_required=authorization_required,
            decision=decision,
        )


def _resolve_child(root: Path, candidate: Path) -> Path:
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("The dynamic skill path escapes the allowed directory.") from exc
    if resolved.parent != root:
        raise ValueError("Dynamic skills and metadata must be direct children of the allowed directory.")
    if resolved.exists() and resolved.is_symlink():
        raise ValueError("A symlink cannot be used as a dynamic skill path.")
    return resolved


def _validate_skill_name(skill_name: object) -> None:
    if not isinstance(skill_name, str) or not _SKILL_NAME_PATTERN.fullmatch(skill_name):
        raise ValueError("Skill name must be a lowercase identifier without path separators.")
    if skill_name.casefold() in _WINDOWS_RESERVED_NAMES:
        raise ValueError("Skill name is reserved by Windows.")
    path = Path(skill_name)
    windows_path = PureWindowsPath(skill_name)
    if (
        path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or "/" in skill_name
        or "\\" in skill_name
        or skill_name in {".", ".."}
    ):
        raise ValueError("Skill name must not contain a path or drive.")


__all__ = [
    "DEPLOYMENT_ACTION_NAME",
    "DYNAMIC_SKILL_METADATA_SCHEMA_VERSION",
    "DYNAMIC_SKILL_METADATA_SUFFIX",
    "EXECUTION_ACTION_NAME",
    "DynamicSkillDeploymentMetadata",
    "DynamicSkillPaths",
    "SafeSkillDeploymentService",
    "SkillDeploymentRequest",
    "SkillDeploymentResult",
    "StagedSkill",
    "execution_target_for",
    "load_dynamic_skill_metadata",
    "resolve_dynamic_skill_paths",
]