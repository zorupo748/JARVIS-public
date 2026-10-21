"""Interaction-safe orchestration for dynamic skill authoring and deployment.

This module keeps a reviewed proposal in memory until a subsequent, fresh user
confirmation is evaluated by the existing deterministic policy engine.  It
never imports, registers, or executes a newly deployed artifact.
"""

from __future__ import annotations

import secrets
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from jarvis.core.safe_skill_authoring import (
    SafeSkillAuthoringService,
    SkillAuthoringRequest,
    SkillAuthoringResult,
)
from jarvis.core.safe_skill_deployment import (
    DEPLOYMENT_ACTION_NAME,
    SafeSkillDeploymentService,
    SkillDeploymentRequest,
    SkillDeploymentResult,
    execution_target_for,
)
from jarvis.core.safe_skill_execution import (
    ExecutionFailureKind,
    SafeSkillExecutionRequest,
    SafeSkillExecutionResult,
    SafeSkillExecutionService,
)
from jarvis.core.skill_error_handler import SkillErrorHandler
from jarvis.security.models import SecurityAction
from jarvis.security.policy_core import (
    FreshConfirmation,
    IdentityContext,
    PolicyDecisionKind,
    SessionSkillAuthorization,
)


class AuthoringService(Protocol):
    def author(self, request: SkillAuthoringRequest) -> SkillAuthoringResult: ...


class DeploymentService(Protocol):
    def stage(self, request: SkillDeploymentRequest) -> SkillDeploymentResult: ...

    def deploy(self, request: SkillDeploymentRequest) -> SkillDeploymentResult: ...


class ExecutionService(Protocol):
    def execute(self, request: SafeSkillExecutionRequest) -> SafeSkillExecutionResult: ...


@dataclass(frozen=True)
class PendingSkillInstallation:
    """An approved proposal awaiting one user/action/hash-bound confirmation."""

    authoring_result: SkillAuthoringResult
    original_user_request: str
    source_hash: str
    action: SecurityAction
    replace_existing_source_hash: str | None = None

    @property
    def skill_name(self) -> str:
        proposal = self.authoring_result.proposal
        if proposal is None:  # Defensive; construction validates this invariant.
            raise RuntimeError("Pending installation has no proposal.")
        return proposal.skill_name


@dataclass(frozen=True)
class InstallationPreparation:
    """Preflight outcome without a write or confirmation consumption."""

    pending: PendingSkillInstallation | None
    deployment_result: SkillDeploymentResult

    @property
    def confirmation_required(self) -> bool:
        decision = self.deployment_result.decision
        return bool(
            self.pending is not None
            and decision is not None
            and decision.kind is PolicyDecisionKind.REQUIRE_CONFIRMATION
        )

@dataclass(frozen=True)
class PendingSkillExecution:
    """A verified artifact awaiting its own one-use execution confirmation."""

    skill_name: str
    parameters: Mapping[str, object]
    action: SecurityAction
    expected_source_hash: str | None = None
    expected_metadata_hash: str | None = None
    expected_user_id: str | None = None

    def __post_init__(self) -> None:
        # Keep the original command through confirmation, independently of the
        # caller's mapping. Prevent accidental replacement with the reply "si".
        object.__setattr__(self, "parameters", MappingProxyType(deepcopy(dict(self.parameters))))


@dataclass(frozen=True)
class ExecutionPreparation:
    """Execution preflight outcome; no runtime is reached while confirmation is pending."""

    pending: PendingSkillExecution | None
    execution_result: SafeSkillExecutionResult

    @property
    def confirmation_required(self) -> bool:
        return bool(
            self.pending is not None
            and self.execution_result.policy_decision is not None
            and self.execution_result.policy_decision.kind
            is PolicyDecisionKind.REQUIRE_CONFIRMATION
        )


class SafeSkillPipeline:
    """Connect the three safe services without adding a second policy engine."""

    def __init__(
        self,
        authoring: AuthoringService,
        deployment: DeploymentService,
        execution: ExecutionService,
        *,
        error_handler: SkillErrorHandler | None = None,
        model_router: object | None = None,
        confirmation_id_factory: Callable[[], str] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._authoring = authoring
        self._deployment = deployment
        self._execution = execution
        self._error_handler = error_handler or SkillErrorHandler(model_router=model_router)
        self.error_handler = self._error_handler
        self._confirmation_id_factory = confirmation_id_factory or (lambda: secrets.token_urlsafe(24))
        self._now = now or (lambda: datetime.now(timezone.utc))

    def author(
        self,
        original_user_request: str,
        *,
        existing_skill_name: str | None = None,
        relevant_context: str | None = None,
    ) -> SkillAuthoringResult:
        """Forward the original request verbatim to the local-coder pipeline with error interception."""
        try:
            result = self._authoring.author(
                SkillAuthoringRequest(
                    user_request=original_user_request,
                    existing_skill_name=existing_skill_name,
                    relevant_context=relevant_context,
                )
            )
            if not result.success and result.failure_reason:
                raw_keywords = ("ValueError", "insufficient_research", "HTTP 200", "Traceback", "Exception")
                if any(kw in result.failure_reason for kw in raw_keywords):
                    decision = self._error_handler.triage(
                        result.failure_reason,
                        phase="creación",
                        user_request=original_user_request,
                        skill_name=existing_skill_name,
                    )
                    return replace(result, failure_reason=decision.executive_summary)
            return result
        except Exception as exc:
            decision = self._error_handler.triage(
                exc,
                phase="creación",
                user_request=original_user_request,
                skill_name=existing_skill_name,
            )
            return SkillAuthoringResult(
                success=False,
                proposal=None,
                iterations=0,
                validation_reports=(),
                review_results=(),
                failure_reason=decision.executive_summary,
            )

    def prepare_installation(
        self,
        authoring_result: SkillAuthoringResult,
        *,
        original_user_request: str,
        identity: IdentityContext,
        replace_existing_source_hash: str | None = None,
    ) -> InstallationPreparation:
        """Ask PolicyCore what it requires before asking the user to confirm."""

        request = SkillDeploymentRequest(
            authoring_result=authoring_result,
            identity=identity,
            explicit_authorization=True,
            policy_action=self._deployment_action_descriptor(),
            original_user_request=original_user_request,
            replace_existing_source_hash=replace_existing_source_hash,
        )
        preflight = self._deployment.stage(request)
        proposal = authoring_result.proposal
        if (
            proposal is None
            or preflight.source_hash is None
            or preflight.decision is None
            or preflight.decision.kind is not PolicyDecisionKind.REQUIRE_CONFIRMATION
        ):
            return InstallationPreparation(pending=None, deployment_result=preflight)

        action = SecurityAction(
            action=DEPLOYMENT_ACTION_NAME,
            description="Deploy reviewed dynamic skill",
            target=execution_target_for(proposal.skill_name, preflight.source_hash),
            metadata={
                "skill_name": proposal.skill_name,
                "source_hash": preflight.source_hash,
            },
        )
        return InstallationPreparation(
            pending=PendingSkillInstallation(
                authoring_result=authoring_result,
                original_user_request=original_user_request,
                source_hash=preflight.source_hash,
                action=action,
                replace_existing_source_hash=replace_existing_source_hash,
            ),
            deployment_result=preflight,
        )

    def confirm_installation(
        self,
        pending: PendingSkillInstallation,
        *,
        identity: IdentityContext,
    ) -> SkillDeploymentResult:
        """Create one fresh bound confirmation and let PolicyCore decide deployment."""

        if not isinstance(pending, PendingSkillInstallation):
            raise TypeError("pending must be a PendingSkillInstallation")
        if not isinstance(identity, IdentityContext):
            raise TypeError("identity must be an IdentityContext")
        if identity.user_id is None:
            return self._deployment.stage(
                SkillDeploymentRequest(
                    authoring_result=pending.authoring_result,
                    identity=identity,
                    explicit_authorization=True,
                    policy_action=pending.action,
                    original_user_request=pending.original_user_request,
                    replace_existing_source_hash=pending.replace_existing_source_hash,
                )
            )

        confirmation = FreshConfirmation(
            confirmation_id=self._confirmation_id_factory(),
            action_name=pending.action.action,
            user_id=identity.user_id,
            target=pending.action.target,
            confirmed_at=self._now(),
        )
        return self._deployment.deploy(
            SkillDeploymentRequest(
                authoring_result=pending.authoring_result,
                identity=identity,
                explicit_authorization=True,
                policy_action=pending.action,
                original_user_request=pending.original_user_request,
                confirmations=(confirmation,),
                replace_existing_source_hash=pending.replace_existing_source_hash,
            )
        )

    def execute_installed(
        self,
        skill_name: str,
        *,
        identity: IdentityContext,
        parameters: Mapping[str, object] | None = None,
        confirmations: tuple[FreshConfirmation, ...] = (),
        session_skill_authorization: SessionSkillAuthorization | None = None,
        expected_source_hash: str | None = None,
        expected_metadata_hash: str | None = None,
        expected_user_id: str | None = None,
    ) -> SafeSkillExecutionResult:
        """Delegate all installed-artifact execution to the hash/policy gateway with error interception."""
        try:
            return self._execution.execute(
                SafeSkillExecutionRequest(
                    skill_name=skill_name,
                    identity=identity,
                    parameters=dict(parameters or {}),
                    confirmations=confirmations,
                    session_skill_authorization=session_skill_authorization,
                    expected_source_hash=expected_source_hash,
                    expected_metadata_hash=expected_metadata_hash,
                    expected_user_id=expected_user_id,
                )
            )
        except Exception as exc:
            decision = self._error_handler.triage(
                exc,
                phase="ejecución",
                user_request=str((parameters or {}).get("comando", skill_name)),
                skill_name=skill_name,
            )
            return SafeSkillExecutionResult(
                executed=False,
                allowed=False,
                skill_name=skill_name,
                result=None,
                policy_decision=None,
                hash_verified=False,
                failure_kind=ExecutionFailureKind.SKILL_EXCEPTION,
                failure_reason=decision.executive_summary,
            )

    def prepare_execution(
        self,
        skill_name: str,
        *,
        identity: IdentityContext,
        parameters: Mapping[str, object] | None = None,
    ) -> ExecutionPreparation:
        """Verify the artifact and ask PolicyCore whether confirmation is needed."""

        safe_parameters = dict(parameters or {})
        result = self.execute_installed(
            skill_name,
            identity=identity,
            parameters=safe_parameters,
        )
        if (
            result.policy_decision is not None
            and result.policy_decision.kind is PolicyDecisionKind.REQUIRE_CONFIRMATION
            and result.action is not None
        ):
            return ExecutionPreparation(
                pending=PendingSkillExecution(
                    skill_name=skill_name,
                    parameters=safe_parameters,
                    action=result.action,
                ),
                execution_result=result,
            )
        return ExecutionPreparation(pending=None, execution_result=result)

    def confirm_execution(
        self,
        pending: PendingSkillExecution,
        *,
        identity: IdentityContext,
    ) -> SafeSkillExecutionResult:
        """Bind a fresh confirmation to the previously verified action and target."""

        if not isinstance(pending, PendingSkillExecution):
            raise TypeError("pending must be a PendingSkillExecution")
        if not isinstance(identity, IdentityContext):
            raise TypeError("identity must be an IdentityContext")
        if identity.user_id is None:
            return self.execute_installed(
                pending.skill_name,
                identity=identity,
                parameters=pending.parameters,
                expected_source_hash=pending.expected_source_hash,
                expected_metadata_hash=pending.expected_metadata_hash,
                expected_user_id=pending.expected_user_id,
            )

        confirmation = FreshConfirmation(
            confirmation_id=self._confirmation_id_factory(),
            action_name=pending.action.action,
            user_id=identity.user_id,
            target=pending.action.target,
            confirmed_at=self._now(),
        )
        return self.execute_installed(
            pending.skill_name,
            identity=identity,
            parameters=pending.parameters,
            confirmations=(confirmation,),
            expected_source_hash=pending.expected_source_hash,
            expected_metadata_hash=pending.expected_metadata_hash,
            expected_user_id=pending.expected_user_id,
        )

    @staticmethod
    def _deployment_action_descriptor() -> SecurityAction:
        return SecurityAction(
            action=DEPLOYMENT_ACTION_NAME,
            description="Deploy reviewed dynamic skill",
        )


__all__ = [
    "ExecutionPreparation",
    "InstallationPreparation",
    "PendingSkillExecution",
    "PendingSkillInstallation",
    "SafeSkillPipeline",
]
