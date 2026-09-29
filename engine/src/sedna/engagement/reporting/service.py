"""Report closure and immutable revision orchestration."""

from __future__ import annotations

from typing import Literal, Protocol
from uuid import UUID

from sedna.engagement.events import EngagementSnapshot
from sedna.engagement.models import JournalRevision, PromotionSagaInProgressError
from sedna.engagement.reporting.markdown import render_operational_report
from sedna.engagement.reporting.models import OperationalReport, ReportCommitResult, ReportRef
from sedna.engagement.reporting.projector import OperationalReportProjector


class ReportCommitCapability(Protocol):
    def commit_report_snapshot(
        self,
        engagement_id: UUID,
        report: OperationalReport,
        markdown: str,
        *,
        expected_revision: JournalRevision,
    ) -> ReportCommitResult: ...

    def commit_report_revision(
        self,
        engagement_id: UUID,
        report: OperationalReport,
        markdown: str,
        *,
        generation_reason: Literal["repair_json", "manual_report"],
        expected_revision: JournalRevision,
    ) -> ReportCommitResult: ...

    def repair_markdown(
        self, engagement_id: UUID, report_revision: int, *, expected_revision: JournalRevision
    ) -> ReportRef: ...


class ReportClosureFinalizer:
    """Project and atomically bind the first immutable report to closure."""

    def __init__(self, journal, commit_capability: ReportCommitCapability, projector=None) -> None:
        self._journal = journal
        self._commit = commit_capability
        self._projector = projector or OperationalReportProjector()

    def finalize(self, *, snapshot: EngagementSnapshot) -> EngagementSnapshot:
        if snapshot.state.status.value != "closing" or not snapshot.state.closure_ready:
            raise ValueError("closure barrier is not ready")
        evidence = self._all_evidence(snapshot)
        report = self._projector.project(
            snapshot=snapshot,
            events=snapshot.events,
            evidence=evidence,
            evidence_reader=self._journal.read_evidence_slice,
            report_revision=len(snapshot.state.reports) + 1,
            generated_at=snapshot.events[-1].occurred_at,
        )
        return self._commit.commit_report_snapshot(
            snapshot.engagement_id,
            report,
            render_operational_report(report),
            expected_revision=snapshot.revision,
        ).snapshot

    def commit_later_revision(
        self,
        *,
        snapshot: EngagementSnapshot,
        reason: Literal["repair_json", "manual_report"],
    ) -> ReportRef:
        if snapshot.state.status.value not in {"closed_unverified", "closed_verified"}:
            raise ValueError("report revision requires closed engagement")
        report = self._projector.project(
            snapshot=snapshot,
            events=snapshot.events,
            evidence=self._all_evidence(snapshot),
            evidence_reader=self._journal.read_evidence_slice,
            report_revision=len(snapshot.state.reports) + 1,
            generated_at=snapshot.events[-1].occurred_at,
        )
        return self._commit.commit_report_revision(
            snapshot.engagement_id,
            report,
            render_operational_report(report),
            generation_reason=reason,
            expected_revision=snapshot.revision,
        ).report

    def repair_markdown(self, *, snapshot: EngagementSnapshot, report_revision: int) -> ReportRef:
        return self._commit.repair_markdown(
            snapshot.engagement_id, report_revision, expected_revision=snapshot.revision
        )

    def _all_evidence(self, snapshot: EngagementSnapshot):
        items = []
        cursor = 0
        while True:
            page = self._journal.list_evidence_descriptors(
                snapshot.engagement_id,
                after_sequence=cursor,
                through_revision=snapshot.revision,
                limit=256,
            )
            if page.authoritative_revision != snapshot.revision:
                raise ValueError("evidence page does not match report revision")
            items.extend(page.items)
            if page.complete:
                return tuple(items)
            if page.next_after_sequence <= cursor:
                raise ValueError("evidence paging cursor did not advance")
            cursor = page.next_after_sequence


class ReportManagementService:
    """Planning-aware management for later immutable report revisions."""

    def __init__(self, *, journal, finalizer: ReportClosureFinalizer, planning) -> None:
        self._journal = journal
        self._finalizer = finalizer
        self._planning = planning

    def request_close(self, engagement_id: UUID, *, lane, reason: str):
        self._require_no_active_promotion(engagement_id)
        self._settle(engagement_id)
        snapshot = self._journal.load_snapshot(engagement_id)
        closing = self._journal.request_close(
            engagement_id,
            lane=lane,
            reason=reason,
            expected_revision=snapshot.revision,
        ).snapshot
        if closing.state.closure_ready:
            return self._finalizer.finalize(snapshot=closing)
        return closing

    def generate_report_revision(
        self, engagement_id: UUID, *, reason: Literal["repair_json", "manual_report"]
    ) -> ReportRef:
        self._require_no_active_promotion(engagement_id)
        self._settle(engagement_id)
        snapshot = self._journal.load_snapshot(engagement_id)
        if snapshot.state.status.value not in {"closed_unverified", "closed_verified"}:
            raise ValueError("report_revision_requires_closed_engagement")
        return self._finalizer.commit_later_revision(snapshot=snapshot, reason=reason)

    def regenerate_markdown(self, engagement_id: UUID, report_revision: int) -> ReportRef:
        self._require_no_active_promotion(engagement_id)
        self._settle(engagement_id)
        snapshot = self._journal.load_snapshot(engagement_id)
        if snapshot.state.status.value not in {"closed_unverified", "closed_verified"}:
            raise ValueError("report_revision_requires_closed_engagement")
        return self._finalizer.repair_markdown(snapshot=snapshot, report_revision=report_revision)

    def report(self, engagement_id: UUID) -> ReportRef:
        """Settle once, then triage the current immutable report artifacts."""
        self._require_no_active_promotion(engagement_id)
        self._settle(engagement_id)
        snapshot = self._journal.load_snapshot(engagement_id)
        if snapshot.state.status.value not in {"closed_unverified", "closed_verified"}:
            raise ValueError("report_revision_requires_closed_engagement")
        current = snapshot.state.active_report
        if current is None:
            raise ValueError("report_revision_requires_active_report")
        json_valid, markdown_valid = self._journal.report_artifact_status(engagement_id, current)
        if not json_valid:
            return self._finalizer.commit_later_revision(snapshot=snapshot, reason="repair_json")
        if not markdown_valid:
            return self._finalizer.repair_markdown(
                snapshot=snapshot, report_revision=current.report_revision
            )
        return self._finalizer.commit_later_revision(snapshot=snapshot, reason="manual_report")

    def _settle(self, engagement_id: UUID) -> None:
        result = self._planning.settle_pending_evidence(engagement_id, reason="report")
        if result.status not in {"settled", "nothing_pending"}:
            raise ValueError("report_requires_complete_settlement")

    def _require_no_active_promotion(self, engagement_id: UUID) -> None:
        snapshot = self._journal.load_snapshot(engagement_id)
        if getattr(getattr(snapshot.state, "promotion", None), "active_attempt", None) is not None:
            raise PromotionSagaInProgressError()


__all__ = ["ReportClosureFinalizer", "ReportManagementService"]
