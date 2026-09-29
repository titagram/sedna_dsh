"""Ports for dependencies owned by later planning/lifecycle milestones."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_validator

from sedna.engagement import (
    EngagementSettlementOutcome,
    EngagementSettlementPort,
    EngagementStatus,
    ExecutionLaneKey,
    JournalRevision,
    SettlementReason,
)
from sedna.engagement.lifecycle import EngagementLifecycleService
from sedna.engagement.reporting.service import ReportClosureFinalizer, ReportManagementService
from sedna.engagement.service import EngagementJournalService
from sedna.planning.models import (
    FailedSettlementResult,
    IncompleteSettlementResult,
    PlanningResult,
    ProofRequirementId,
    SettlementResult,
    SituationProjection,
    WriteupAuthorizationGrant,
)
from sedna.planning.retrieval import HindsightCandidateContext

KnowledgeRootResolver = Callable[[], Path]


class PlanningOperations(Protocol):
    def settle_pending_evidence(
        self, engagement_id: UUID, *, reason: SettlementReason
    ) -> SettlementResult: ...

    def reconcile_attested_proofs(
        self, engagement_id: UUID, *, reason: str
    ) -> SituationProjection: ...

    def plan_next(
        self,
        lane: ExecutionLaneKey,
        *,
        max_proposals: int = 5,
        writeup_authorization: WriteupAuthorizationGrant | None = None,
        hindsight_candidates: tuple[HindsightCandidateContext, ...] = (),
    ) -> PlanningResult: ...


class OwnedPlanningRuntime(Protocol):
    planning: PlanningOperations


class PromotionRecoveryResult(Protocol):
    disposition: str
    reason_code: str | None


class PromotionRecoveryOperations(Protocol):
    def resume_for_engagement(self, engagement_id: UUID) -> PromotionRecoveryResult: ...


class OwnedSednaRuntime(OwnedPlanningRuntime, Protocol):
    """One invocation-owned runtime exposing all cross-domain service surfaces."""

    journal: EngagementJournalService
    engagements: EngagementLifecycleService
    reporting: ReportManagementService
    report_finalizer: ReportClosureFinalizer
    promotion: PromotionRecoveryOperations | None


SednaRuntimeFactory = Callable[[Path], AbstractContextManager[OwnedSednaRuntime]]
PlanningRuntimeFactory = Callable[[Path], AbstractContextManager[OwnedPlanningRuntime]]


class PlanningSettlementAdapter:
    def __init__(self, *, planning: PlanningOperations) -> None:
        self._planning = planning

    def settle(
        self, engagement_id: UUID, *, reason: SettlementReason
    ) -> EngagementSettlementOutcome:
        result = self._planning.settle_pending_evidence(engagement_id, reason=reason)
        return settlement_outcome(result)


def settlement_outcome(result: SettlementResult) -> EngagementSettlementOutcome:
    """Map one direct planning result to the stable host settlement envelope."""
    if result.status in {"settled", "nothing_pending"}:
        return EngagementSettlementOutcome(status="complete", pending_range_count=0)
    if isinstance(result, IncompleteSettlementResult):
        return EngagementSettlementOutcome(
            status="incomplete",
            pending_range_count=result.pending_total_count,
            next_pending_offset=min(item.start for item in result.pending_ranges),
            next_pending_subject=result.next_pending_subject,
            pending_inventory_sha256=result.pending_inventory_sha256,
            safe_code=(
                "evidence_budget_exhausted"
                if result.incomplete_reason == "budget_exhausted"
                else "interpretation_incomplete"
            ),
        )
    if not isinstance(result, FailedSettlementResult):
        raise TypeError("unknown settlement result")
    if result.failure_code in {"journal_unavailable", "journal_corrupt"}:
        return EngagementSettlementOutcome(
            status="unavailable",
            pending_range_count=0,
            safe_code=(
                "journal_unavailable"
                if result.failure_code == "journal_unavailable"
                else "journal_corrupt"
            ),
        )
    if result.failure_code == "terminal_reconciliation_failed":
        return EngagementSettlementOutcome(
            status="unavailable",
            pending_range_count=0,
            safe_code="settlement_unavailable",
        )
    return EngagementSettlementOutcome(
        status="failed",
        pending_range_count=result.pending_total_count,
        next_pending_offset=(
            min(item.start for item in result.pending_ranges) if result.pending_ranges else None
        ),
        next_pending_subject=result.next_pending_subject,
        pending_inventory_sha256=result.pending_inventory_sha256,
        safe_code="interpretation_failed",
    )


class PlanningSettlementPortFactory:
    def __init__(self, planning_runtime_factory: PlanningRuntimeFactory) -> None:
        self._planning_runtime_factory = planning_runtime_factory

    @contextmanager
    def open(self, resolved_root: Path) -> Iterator[EngagementSettlementPort]:
        with self._planning_runtime_factory(resolved_root) as runtime:
            yield PlanningSettlementAdapter(planning=runtime.planning)


class TerminalReconciliationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    action: Literal[
        "unchanged",
        "proof_close_requested",
        "proof_close_cancelled",
        "proof_close_finalized",
        "failed",
    ]
    authoritative_journal_revision: JournalRevision
    lifecycle_status: EngagementStatus
    safe_code: Literal["terminal_reconciliation_failed"] | None = None

    @model_validator(mode="after")
    def _validate_action_state(self) -> TerminalReconciliationResult:
        if (self.action == "failed") != (self.safe_code is not None):
            raise ValueError("terminal_reconciliation_failure_policy")
        allowed_statuses = {
            "proof_close_requested": {EngagementStatus.CLOSING},
            "proof_close_cancelled": {EngagementStatus.ACTIVE},
            "proof_close_finalized": {
                EngagementStatus.CLOSED_UNVERIFIED,
                EngagementStatus.CLOSED_VERIFIED,
            },
        }
        allowed = allowed_statuses.get(self.action)
        if allowed is not None and self.lifecycle_status not in allowed:
            raise ValueError("terminal_reconciliation_status_policy")
        return self


class TerminalSettlementPort(Protocol):
    def reconcile(
        self,
        *,
        engagement_id: UUID,
        situation: SituationProjection,
        requirement_ids: tuple[ProofRequirementId, ...],
        authoritative_revision: JournalRevision,
        reason: str,
        all_required_proofs_satisfied: bool,
    ) -> TerminalReconciliationResult: ...
