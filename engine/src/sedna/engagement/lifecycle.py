"""Planning-aware terminal lifecycle orchestration for engagement journals."""

from __future__ import annotations

from typing import Annotated, Literal, Protocol
from uuid import UUID

from pydantic import Field

from sedna.engagement.events import (
    EngagementReopenedPayload,
    EngagementVerifiedPayload,
    FlagRejectedPayload,
    JournalEventDraft,
    SystemCorrelation,
)
from sedna.engagement.models import (
    EngagementStatus,
    ExecutionLaneKey,
    JournalRevision,
    PromotionSagaInProgressError,
)
from sedna.engagement.service import EngagementMutationResult, SettledProofRejectionReceipt


class PromotionRecoveryPort(Protocol):
    """Dependency-neutral recovery hook invoked after canonical verification."""

    def recover_after_verification(self, engagement_id: UUID) -> None: ...


class PromotionRevocationPort(Protocol):
    """Dependency-neutral revocation hook for verified lifecycle mutations."""

    def revoke_after_settlement(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        expected_revision: JournalRevision,
        operation: Literal["reject", "reopen"],
        reason: Annotated[str, Field(min_length=1, max_length=2048)],
        proof_rejection: SettledProofRejectionReceipt | None = None,
    ) -> EngagementMutationResult: ...


class EngagementLifecycleService:
    """Settle pending evidence before every terminal lifecycle mutation."""

    def __init__(
        self,
        *,
        journal,
        planning,
        closure_finalizer,
        lifecycle_commits,
        promotion_recovery: PromotionRecoveryPort | None = None,
        promotion_revocation: PromotionRevocationPort | None = None,
    ) -> None:
        self._journal = journal
        self._planning = planning
        self._closure_finalizer = closure_finalizer
        self._lifecycle_commits = lifecycle_commits
        self._promotion_recovery = promotion_recovery
        self._promotion_revocation = promotion_revocation

    @staticmethod
    def _status(snapshot) -> str:
        status = snapshot.state.status
        return status.value if hasattr(status, "value") else str(status)

    def _settle(self, engagement_id: UUID, reason: str):
        result = self._planning.settle_pending_evidence(engagement_id, reason=reason)
        if result.status not in {"settled", "nothing_pending"}:
            raise ValueError(f"terminal_settlement_{result.status}")
        return result

    def close(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        reason: str,
        allow_unsettled_evidence: bool = False,
    ) -> EngagementMutationResult:
        if allow_unsettled_evidence:
            self._planning.reconcile_attested_proofs(engagement_id, reason=reason)
        else:
            self._settle(engagement_id, "close")
        snapshot = self._journal.load_snapshot(engagement_id)
        if self._status(snapshot) == "active":
            snapshot = self._journal.request_close(
                engagement_id,
                lane=lane,
                reason=reason,
                expected_revision=snapshot.revision,
            ).snapshot
        if self._status(snapshot) == "closing" and snapshot.state.closure_ready:
            snapshot = self._closure_finalizer.finalize(snapshot=snapshot)
        return EngagementMutationResult(snapshot=snapshot)

    def verify(
        self,
        engagement_id: UUID,
        *,
        verification_kind: Literal["platform", "user"],
        verification_reference: str,
    ) -> EngagementMutationResult:
        snapshot = self._journal.load_snapshot(engagement_id)
        if self._status(snapshot) not in {"closed_unverified", "closed_verified"}:
            self._settle(engagement_id, "verify")
            snapshot = self._journal.load_snapshot(engagement_id)
        if self._status(snapshot) == "closed_verified":
            verification = next(
                (
                    event
                    for event in reversed(snapshot.events)
                    if getattr(event.type, "value", event.type) == "engagement_verified"
                ),
                None,
            )
            if (
                verification is None
                or verification.payload.verification_kind != verification_kind
                or verification.payload.verification_reference != verification_reference
            ):
                raise ValueError("verification_conflict")
            if self._promotion_recovery is not None:
                self._promotion_recovery.recover_after_verification(engagement_id)
                snapshot = self._journal.load_snapshot(engagement_id)
            return EngagementMutationResult(
                snapshot=snapshot,
                existing_event_ids=(verification.event_id,),
            )
        if self._status(snapshot) != "closed_unverified" or snapshot.state.active_report is None:
            raise ValueError("verification_requires_closed_report")
        report = snapshot.state.active_report
        draft = JournalEventDraft(
            actor="system",
            type="engagement_verified",
            payload=EngagementVerifiedPayload(
                report_id=report.report_id,
                report_revision=report.report_revision,
                verification_kind=verification_kind,
                verification_reference=verification_reference,
            ),
            system_correlation=SystemCorrelation(
                source="lifecycle",
                operation_id=UUID(int=report.report_id.int ^ snapshot.revision.sequence),
            ),
        )
        result = self._lifecycle_commits.commit_verified(
            engagement_id,
            draft,
            expected_revision=snapshot.revision,
        )
        if self._promotion_recovery is not None:
            self._promotion_recovery.recover_after_verification(engagement_id)
            return result.model_copy(
                update={"snapshot": self._journal.load_snapshot(engagement_id)}
            )
        return result

    def reopen(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        reason: str,
    ) -> EngagementMutationResult:
        snapshot = self._journal.load_snapshot(engagement_id)
        if getattr(getattr(snapshot.state, "promotion", None), "active_attempt", None) is not None:
            raise PromotionSagaInProgressError()
        self._settle(engagement_id, "reopen")
        snapshot = self._journal.load_snapshot(engagement_id)
        status = self._status(snapshot)
        if status == "closed_verified":
            if self._promotion_revocation is not None:
                return self._promotion_revocation.revoke_after_settlement(
                    engagement_id,
                    lane=lane,
                    expected_revision=snapshot.revision,
                    operation="reopen",
                    reason=reason,
                    proof_rejection=None,
                )
            raise ValueError("canonical_revocation_required")
        if status not in {"closing", "closed_unverified", "closed_verified", "abandoned"}:
            raise ValueError("reopen_requires_terminal_state")
        operation_id = UUID(int=snapshot.revision.sequence + 1)
        draft = JournalEventDraft(
            actor="system",
            type="engagement_reopened",
            payload=EngagementReopenedPayload(
                reason=reason,
                prior_status=status,
                proof_revalidation="invalidate_all",
            ),
            system_correlation=SystemCorrelation(source="lifecycle", operation_id=operation_id),
        )
        return self._lifecycle_commits.commit_reopen(
            engagement_id, lane, draft, expected_revision=snapshot.revision
        )

    def reject_flag(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        flag_event_id: UUID,
        reason: str,
    ) -> EngagementMutationResult:
        snapshot = self._journal.load_snapshot(engagement_id)
        if getattr(getattr(snapshot.state, "promotion", None), "active_attempt", None) is not None:
            raise PromotionSagaInProgressError()
        settled = self._settle(engagement_id, "reject")
        snapshot = self._journal.load_snapshot(engagement_id)
        status = self._status(snapshot)
        if status == "closed_verified":
            if self._promotion_revocation is not None:
                receipt = self._lifecycle_commits.rejection_receipt(settled, flag_event_id)
                return self._promotion_revocation.revoke_after_settlement(
                    engagement_id,
                    lane=lane,
                    expected_revision=snapshot.revision,
                    operation="reject",
                    reason=reason,
                    proof_rejection=receipt,
                )
            raise ValueError("canonical_revocation_required")
        if status not in {"closed_unverified", "closed_verified"}:
            raise ValueError("rejection_requires_closed_engagement")
        receipt = self._lifecycle_commits.rejection_receipt(settled, flag_event_id)
        operation_id = UUID(int=snapshot.revision.sequence + 1)
        drafts = (
            JournalEventDraft(
                actor="system",
                type="flag_rejected",
                payload=FlagRejectedPayload(
                    flag_event_id=flag_event_id,
                    rejected_value_sha256=receipt.rejected_value_sha256,
                    reason=reason,
                ),
                system_correlation=SystemCorrelation(source="lifecycle", operation_id=operation_id),
            ),
            JournalEventDraft(
                actor="system",
                type="engagement_reopened",
                payload=EngagementReopenedPayload(
                    reason=reason,
                    prior_status=status,
                    proof_revalidation="retain_rejections",
                ),
                system_correlation=SystemCorrelation(source="lifecycle", operation_id=operation_id),
            ),
        )
        return self._lifecycle_commits.commit_rejection_and_reopen(
            engagement_id,
            lane,
            drafts[0],
            drafts[1],
            proof_rejection=receipt,
            expected_revision=snapshot.revision,
        )


class TerminalSettlementCoordinator:
    """Reconcile settled objective proofs with the sole journal closure barrier."""

    def __init__(self, *, journal, proof_closure, finalizer) -> None:
        self._journal = journal
        self._proof_closure = proof_closure
        self._finalizer = finalizer

    @staticmethod
    def _result(*, action: str, snapshot, failed: bool = False):
        from sedna.planning.ports import TerminalReconciliationResult

        return TerminalReconciliationResult(
            action="failed" if failed else action,
            authoritative_journal_revision=snapshot.revision,
            lifecycle_status=snapshot.state.status,
            safe_code="terminal_reconciliation_failed" if failed else None,
        )

    def reconcile(
        self,
        *,
        engagement_id: UUID,
        situation,
        requirement_ids: tuple[str, ...],
        authoritative_revision,
        reason: str,
        all_required_proofs_satisfied: bool,
    ):
        snapshot = self._journal.load_snapshot(engagement_id)
        projected_ids = tuple(
            item.proof_requirement_id for item in situation.objective_progress.requirements
        )
        malformed = (
            not requirement_ids
            or situation.engagement_id != engagement_id
            or situation.authoritative_journal_revision != authoritative_revision
            or snapshot.revision != authoritative_revision
            or tuple(sorted(requirement_ids)) != tuple(sorted(projected_ids))
            or len(requirement_ids) != len(set(requirement_ids))
        )
        if malformed:
            return self._result(action="failed", snapshot=snapshot, failed=True)

        status = snapshot.state.status
        if status is EngagementStatus.ACTIVE:
            if not all_required_proofs_satisfied:
                return self._result(action="unchanged", snapshot=snapshot)
            requested = self._proof_closure.request_proof_close(
                engagement_id,
                authoritative_revision=authoritative_revision,
                lane=None,
                reason=reason,
            ).snapshot
            return self._result(action="proof_close_requested", snapshot=requested)

        if status is EngagementStatus.CLOSING:
            barrier = snapshot.state.closure
            if barrier is None:
                return self._result(action="failed", snapshot=snapshot, failed=True)
            if barrier.origin != "proof_settlement":
                return self._result(action="unchanged", snapshot=snapshot)
            if not all_required_proofs_satisfied:
                cancelled = self._proof_closure.cancel_proof_close(
                    engagement_id,
                    authoritative_revision=authoritative_revision,
                    reason=reason,
                ).snapshot
                return self._result(action="proof_close_cancelled", snapshot=cancelled)
            if not snapshot.state.closure_ready:
                return self._result(action="proof_close_requested", snapshot=snapshot)
            closed = self._finalizer.finalize(snapshot=snapshot)
            return self._result(action="proof_close_finalized", snapshot=closed)

        if status in {
            EngagementStatus.CLOSED_UNVERIFIED,
            EngagementStatus.CLOSED_VERIFIED,
            EngagementStatus.ABANDONED,
        }:
            return self._result(action="unchanged", snapshot=snapshot)
        return self._result(action="failed", snapshot=snapshot, failed=True)


__all__ = ["EngagementLifecycleService", "TerminalSettlementCoordinator"]
