"""Pure deterministic replay for engagement journal lifecycle state."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from uuid import UUID

from sedna.engagement.events import (
    CasePromotedPayload,
    CasePromotionRevokedPayload,
    CasePromotionSupersededPayload,
    ClosureCancelledPayload,
    ClosureRequestedPayload,
    DecisionRecordedPayload,
    EngagementClosedPayload,
    EngagementOpenedPayload,
    EngagementVerifiedPayload,
    EventType,
    JournalEvent,
    LaneBoundPayload,
    LaneUnboundPayload,
    PromotionAttemptCancellationRequestedPayload,
    PromotionAttemptTerminatedPayload,
    PromotionCandidateReadyPayload,
    PromotionIndexPendingPayload,
    PromotionIndexRetryFailedPayload,
    PromotionRequestedPayload,
    PromotionRevocationRequestedPayload,
    PromotionSemanticCommittedPayload,
    PromotionSourceCommittedPayload,
    ReportGeneratedPayload,
    ScopeChangedPayload,
    ToolCallCompletedPayload,
    ToolCallStartedPayload,
    ToolCallTerminatedPayload,
    canonical_event_hash,
)
from sedna.engagement.models import (
    ActiveDecision,
    ClosureBarrier,
    EngagementManifest,
    EngagementState,
    EngagementStatus,
    ExecutionLaneKey,
    JournalRevision,
    LaneBinding,
    PromotionAttemptState,
    PromotionPublicationLineage,
    PromotionState,
    ScopeReference,
    scope_references,
)


class EngagementReplayError(ValueError):
    """The journal is structurally valid but cannot be replayed consistently."""


class LifecycleEffect(StrEnum):
    """Closed lifecycle families used by the replay status matrix."""

    OPEN = "open"
    RECOVERY = "recovery"
    CONTROL_PLANE = "control_plane"
    NEW_WORK = "new_work"
    TOOL_START = "tool_start"
    TOOL_TERMINAL = "tool_terminal"
    BOOKKEEPING = "bookkeeping"
    SETTLEMENT_BOOKKEEPING = "settlement_bookkeeping"
    ACTIVE_PLANNING = "active_planning"
    CLOSURE_REQUEST = "closure_request"
    CLOSURE_CANCEL = "closure_cancel"
    REOPEN = "reopen"
    ABANDON = "abandon"
    REPORT = "report"
    CLOSE = "close"
    VERIFY = "verify"
    REJECT = "reject"


EVENT_LIFECYCLE_EFFECTS: Mapping[EventType, LifecycleEffect] = MappingProxyType(
    {
        EventType.ENGAGEMENT_OPENED: LifecycleEffect.OPEN,
        EventType.ENGAGEMENT_RESUMED: LifecycleEffect.RECOVERY,
        EventType.LANE_BOUND: LifecycleEffect.CONTROL_PLANE,
        EventType.LANE_UNBOUND: LifecycleEffect.CONTROL_PLANE,
        EventType.CHILD_LANE_LINKED: LifecycleEffect.NEW_WORK,
        EventType.SESSION_STARTED: LifecycleEffect.CONTROL_PLANE,
        EventType.SESSION_CHECKPOINTED: LifecycleEffect.CONTROL_PLANE,
        EventType.SESSION_FINALIZED: LifecycleEffect.CONTROL_PLANE,
        EventType.OBJECTIVE_CHANGED: LifecycleEffect.NEW_WORK,
        EventType.SCOPE_CHANGED: LifecycleEffect.NEW_WORK,
        EventType.DECISION_RECORDED: LifecycleEffect.NEW_WORK,
        EventType.AGENT_DEVIATION_RECORDED: LifecycleEffect.NEW_WORK,
        EventType.TOOL_CALL_STARTED: LifecycleEffect.TOOL_START,
        EventType.TOOL_CALL_COMPLETED: LifecycleEffect.TOOL_TERMINAL,
        EventType.TOOL_CALL_TERMINATED: LifecycleEffect.TOOL_TERMINAL,
        EventType.EVIDENCE_ATTACHED: LifecycleEffect.BOOKKEEPING,
        EventType.EVIDENCE_CAPTURE_FAILED: LifecycleEffect.BOOKKEEPING,
        EventType.UNMATCHED_TOOL_COMPLETION: LifecycleEffect.BOOKKEEPING,
        EventType.UNPLANNED_ACTION: LifecycleEffect.BOOKKEEPING,
        EventType.CONTROL_TOOL_INVOKED: LifecycleEffect.CONTROL_PLANE,
        EventType.CLOSURE_REQUESTED: LifecycleEffect.CLOSURE_REQUEST,
        EventType.CLOSURE_CANCELLED: LifecycleEffect.CLOSURE_CANCEL,
        EventType.ENGAGEMENT_VERIFIED: LifecycleEffect.VERIFY,
        EventType.FLAG_REJECTED: LifecycleEffect.REJECT,
        EventType.ENGAGEMENT_REOPENED: LifecycleEffect.REOPEN,
        EventType.ENGAGEMENT_ABANDONED: LifecycleEffect.ABANDON,
        EventType.SOURCE_SUGGESTED: LifecycleEffect.NEW_WORK,
        EventType.RECOVERY_WARNING: LifecycleEffect.BOOKKEEPING,
        EventType.UNCERTAIN_CORRELATION: LifecycleEffect.BOOKKEEPING,
        EventType.USER_NOTE: LifecycleEffect.BOOKKEEPING,
        EventType.JOURNAL_CORRECTION_RECORDED: LifecycleEffect.BOOKKEEPING,
        EventType.OBSERVATION_EXTRACTED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.HYPOTHESIS_FORMED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.MISSING_INFORMATION_IDENTIFIED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.OUTCOME_ASSESSED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.OBJECTIVE_PROOF_OBSERVED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.INTERPRETATION_SUCCEEDED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.INTERPRETATION_FAILED: LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        EventType.PLAN_REQUESTED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.FRONTIER_PROPOSED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.FRONTIER_CRITICIZED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.FRONTIER_REPAIRED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.FRONTIER_REJECTED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.PLANNING_GAP_RECORDED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.STRATEGY_RECONCILED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.STRATEGY_ARCHIVED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.STRATEGY_REACTIVATED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.RESEARCH_QUERY_PROPOSED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.RESEARCH_SOURCE_CONSULTED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.RESEARCH_SOURCE_ASSESSED: LifecycleEffect.ACTIVE_PLANNING,
        EventType.REPORT_GENERATED: LifecycleEffect.REPORT,
        EventType.ENGAGEMENT_CLOSED: LifecycleEffect.CLOSE,
        EventType.REPORT_COMMIT_ABANDONED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_REQUESTED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_CANDIDATE_READY: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_SOURCE_COMMITTED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_SEMANTIC_COMMITTED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_INDEX_PENDING: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_INDEX_RETRY_FAILED: LifecycleEffect.BOOKKEEPING,
        EventType.CASE_PROMOTED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_ATTEMPT_TERMINATED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_ATTEMPT_CANCELLATION_REQUESTED: LifecycleEffect.BOOKKEEPING,
        EventType.PROMOTION_REVOCATION_REQUESTED: LifecycleEffect.BOOKKEEPING,
        EventType.CASE_PROMOTION_REVOKED: LifecycleEffect.BOOKKEEPING,
        EventType.CASE_PROMOTION_SUPERSEDED: LifecycleEffect.BOOKKEEPING,
    }
)

SETTLEMENT_BOOKKEEPING_EVENT_TYPES = frozenset(
    {
        EventType.OBSERVATION_EXTRACTED,
        EventType.HYPOTHESIS_FORMED,
        EventType.MISSING_INFORMATION_IDENTIFIED,
        EventType.OUTCOME_ASSESSED,
        EventType.OBJECTIVE_PROOF_OBSERVED,
        EventType.INTERPRETATION_SUCCEEDED,
        EventType.INTERPRETATION_FAILED,
    }
)
ACTIVE_PLANNING_EVENT_TYPES = frozenset(
    {
        EventType.PLAN_REQUESTED,
        EventType.FRONTIER_PROPOSED,
        EventType.FRONTIER_CRITICIZED,
        EventType.FRONTIER_REPAIRED,
        EventType.FRONTIER_REJECTED,
        EventType.PLANNING_GAP_RECORDED,
        EventType.STRATEGY_RECONCILED,
        EventType.STRATEGY_ARCHIVED,
        EventType.STRATEGY_REACTIVATED,
        EventType.RESEARCH_QUERY_PROPOSED,
        EventType.RESEARCH_SOURCE_CONSULTED,
        EventType.RESEARCH_SOURCE_ASSESSED,
    }
)
PLANNING_EVENT_TYPES = SETTLEMENT_BOOKKEEPING_EVENT_TYPES | ACTIVE_PLANNING_EVENT_TYPES
PROMOTION_EVENT_TYPES = frozenset(
    {
        EventType.PROMOTION_REQUESTED,
        EventType.PROMOTION_CANDIDATE_READY,
        EventType.PROMOTION_SOURCE_COMMITTED,
        EventType.PROMOTION_SEMANTIC_COMMITTED,
        EventType.PROMOTION_INDEX_PENDING,
        EventType.PROMOTION_INDEX_RETRY_FAILED,
        EventType.CASE_PROMOTED,
        EventType.PROMOTION_ATTEMPT_TERMINATED,
        EventType.PROMOTION_ATTEMPT_CANCELLATION_REQUESTED,
        EventType.PROMOTION_REVOCATION_REQUESTED,
        EventType.CASE_PROMOTION_REVOKED,
        EventType.CASE_PROMOTION_SUPERSEDED,
    }
)


RESUMABLE_STATUSES = frozenset(
    {
        EngagementStatus.ACTIVE,
        EngagementStatus.CLOSING,
        EngagementStatus.ABANDONED,
    }
)

_ACTIVE_EFFECTS = frozenset(
    {
        LifecycleEffect.RECOVERY,
        LifecycleEffect.CONTROL_PLANE,
        LifecycleEffect.NEW_WORK,
        LifecycleEffect.TOOL_START,
        LifecycleEffect.TOOL_TERMINAL,
        LifecycleEffect.BOOKKEEPING,
        LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        LifecycleEffect.ACTIVE_PLANNING,
        LifecycleEffect.CLOSURE_REQUEST,
        LifecycleEffect.ABANDON,
    }
)
_CLOSING_EFFECTS = frozenset(
    {
        LifecycleEffect.RECOVERY,
        LifecycleEffect.CONTROL_PLANE,
        LifecycleEffect.TOOL_TERMINAL,
        LifecycleEffect.BOOKKEEPING,
        LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        LifecycleEffect.CLOSURE_CANCEL,
        LifecycleEffect.REOPEN,
        LifecycleEffect.ABANDON,
        LifecycleEffect.REPORT,
        LifecycleEffect.CLOSE,
    }
)
_ABANDONED_EFFECTS = frozenset(
    {
        LifecycleEffect.RECOVERY,
        LifecycleEffect.CONTROL_PLANE,
        LifecycleEffect.TOOL_TERMINAL,
        LifecycleEffect.BOOKKEEPING,
        LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        LifecycleEffect.REOPEN,
    }
)
_CLOSED_EFFECTS = frozenset(
    {
        LifecycleEffect.BOOKKEEPING,
        LifecycleEffect.CONTROL_PLANE,
        LifecycleEffect.SETTLEMENT_BOOKKEEPING,
        LifecycleEffect.REOPEN,
        LifecycleEffect.REPORT,
        LifecycleEffect.VERIFY,
        LifecycleEffect.REJECT,
    }
)

STATUS_LIFECYCLE_MATRIX: Mapping[EngagementStatus, frozenset[LifecycleEffect]] = MappingProxyType(
    {
        EngagementStatus.ACTIVE: _ACTIVE_EFFECTS,
        EngagementStatus.CLOSING: _CLOSING_EFFECTS,
        EngagementStatus.ABANDONED: _ABANDONED_EFFECTS,
        EngagementStatus.CLOSED_UNVERIFIED: _CLOSED_EFFECTS,
        EngagementStatus.CLOSED_VERIFIED: _CLOSED_EFFECTS,
    }
)

_BOUND_LANE_TYPES = frozenset(
    {
        EventType.CHILD_LANE_LINKED,
        EventType.SESSION_STARTED,
        EventType.SESSION_CHECKPOINTED,
        EventType.SESSION_FINALIZED,
        EventType.DECISION_RECORDED,
        EventType.AGENT_DEVIATION_RECORDED,
        EventType.TOOL_CALL_STARTED,
        EventType.CONTROL_TOOL_INVOKED,
    }
)
_ATOMIC_RESTART_ERROR = "closure_cancelled must be immediately followed by tool_call_started"


def _canonical_event_hash(item: JournalEvent) -> str:
    """Hash an event's canonical envelope, byte-identical to creation.

    Delegates to ``events.canonical_event_hash`` so creation and validation can
    never diverge again. The previous inline ``json.dumps`` used
    ``ensure_ascii=True`` while creation used ``ensure_ascii=False``, so any
    event whose canonical form contained a non-ASCII character produced two
    different digests and every append to that engagement was refused with
    "event hash does not match its canonical envelope".
    """
    return canonical_event_hash(item)


def validate_event_chain(engagement_id: UUID, events: Sequence[JournalEvent]) -> None:
    """Validate identity, sequence, links, hashes, and unique event identities."""

    previous: JournalEvent | None = None
    seen_event_ids: set[UUID] = set()
    for expected_sequence, item in enumerate(events, start=1):
        if item.sequence != expected_sequence:
            raise EngagementReplayError("event sequence must start at one and be contiguous")
        if item.engagement_id != engagement_id:
            raise EngagementReplayError("event engagement ID does not match the manifest")
        if item.event_id in seen_event_ids:
            raise EngagementReplayError("event IDs must be unique")
        seen_event_ids.add(item.event_id)
        expected_previous_hash = previous.event_hash if previous is not None else None
        if item.previous_hash != expected_previous_hash:
            raise EngagementReplayError("event hash link does not match the prior event")
        if item.event_hash != _canonical_event_hash(item):
            raise EngagementReplayError("event hash does not match its canonical envelope")
        previous = item


@dataclass
class _CallState:
    lane: ExecutionLaneKey
    started_sequence: int
    terminal_sequence: int | None = None


@dataclass
class _Accumulator:
    manifest: EngagementManifest
    status: EngagementStatus = EngagementStatus.ACTIVE
    current_scope_references: tuple[ScopeReference, ...] = ()
    opened: bool = False
    bound_lanes: dict[str, ExecutionLaneKey] = field(default_factory=dict)
    active_decisions: dict[str, ActiveDecision] = field(default_factory=dict)
    calls: dict[str, _CallState] = field(default_factory=dict)
    closure: ClosureBarrier | None = None
    operational_restart_required: bool = False
    reports: list[object] = field(default_factory=list)
    active_report: object | None = None
    pending_report: object | None = None
    promotion_attempts: list[PromotionAttemptState] = field(default_factory=list)
    promotion_attempt_count: int = 0
    promotion_verification_event_id: UUID | None = None
    promotion_attempt_ordinal: int = 0
    promotion_folded_count: int = 0
    promotion_folded_sha256: str | None = None
    latest_successful_publication: PromotionPublicationLineage | None = None
    revision: JournalRevision = field(
        default_factory=lambda: JournalRevision(sequence=0, event_hash="0" * 64)
    )

    @classmethod
    def from_manifest(cls, manifest: EngagementManifest) -> _Accumulator:
        return cls(
            manifest=manifest,
            current_scope_references=scope_references(manifest.initial_scope),
        )

    def apply(self, item: JournalEvent) -> None:
        if not self.opened:
            self._apply_opening(item)
            self._advance_revision(item)
            return

        if item.type is EventType.CLOSURE_CANCELLED:
            payload = item.payload
            if (
                not isinstance(payload, ClosureCancelledPayload)
                or self.closure is None
                or payload.closure_event_id != self.closure.event_id
            ):
                raise EngagementReplayError(
                    "closure cancellation must cite the current closure barrier"
                )

        if self.operational_restart_required and item.type is not EventType.TOOL_CALL_STARTED:
            raise EngagementReplayError(_ATOMIC_RESTART_ERROR)

        effect = EVENT_LIFECYCLE_EFFECTS[item.type]
        if effect not in STATUS_LIFECYCLE_MATRIX[self.status]:
            if self.status is EngagementStatus.CLOSING and item.type is EventType.TOOL_CALL_STARTED:
                raise EngagementReplayError(
                    "closure must be cancelled before a new operational call starts"
                )
            raise EngagementReplayError(
                f"{item.type.value} is not permitted while engagement is {self.status.value}"
            )

        if item.type in _BOUND_LANE_TYPES:
            self._require_bound(item)

        handler = {
            EventType.ENGAGEMENT_RESUMED: self._apply_inert,
            EventType.LANE_BOUND: self._apply_lane_bound,
            EventType.LANE_UNBOUND: self._apply_lane_unbound,
            EventType.CHILD_LANE_LINKED: self._apply_inert,
            EventType.SESSION_STARTED: self._apply_inert,
            EventType.SESSION_CHECKPOINTED: self._apply_inert,
            EventType.SESSION_FINALIZED: self._apply_inert,
            EventType.OBJECTIVE_CHANGED: self._apply_inert,
            EventType.SCOPE_CHANGED: self._apply_scope_changed,
            EventType.DECISION_RECORDED: self._apply_decision,
            EventType.AGENT_DEVIATION_RECORDED: self._apply_inert,
            EventType.TOOL_CALL_STARTED: self._apply_tool_started,
            EventType.TOOL_CALL_COMPLETED: self._apply_tool_terminal,
            EventType.TOOL_CALL_TERMINATED: self._apply_tool_terminal,
            EventType.EVIDENCE_ATTACHED: self._apply_inert,
            EventType.EVIDENCE_CAPTURE_FAILED: self._apply_inert,
            EventType.UNMATCHED_TOOL_COMPLETION: self._apply_inert,
            EventType.UNPLANNED_ACTION: self._apply_inert,
            EventType.CONTROL_TOOL_INVOKED: self._apply_inert,
            EventType.CLOSURE_REQUESTED: self._apply_closure_requested,
            EventType.CLOSURE_CANCELLED: self._apply_closure_cancelled,
            EventType.ENGAGEMENT_VERIFIED: self._apply_verified,
            EventType.FLAG_REJECTED: self._apply_inert,
            EventType.ENGAGEMENT_REOPENED: self._apply_reopened,
            EventType.ENGAGEMENT_ABANDONED: self._apply_abandoned,
            EventType.SOURCE_SUGGESTED: self._apply_inert,
            EventType.RECOVERY_WARNING: self._apply_inert,
            EventType.UNCERTAIN_CORRELATION: self._apply_inert,
            EventType.USER_NOTE: self._apply_inert,
            EventType.JOURNAL_CORRECTION_RECORDED: self._apply_inert,
            EventType.REPORT_GENERATED: self._apply_report_generated,
            EventType.ENGAGEMENT_CLOSED: self._apply_engagement_closed,
            EventType.REPORT_COMMIT_ABANDONED: self._apply_inert,
        }.get(item.type)
        if item.type in PLANNING_EVENT_TYPES:
            handler = self._apply_inert
        if item.type in PROMOTION_EVENT_TYPES:
            handler = self._apply_promotion
        if handler is None:
            raise EngagementReplayError(f"unsupported event type: {item.type.value}")
        handler(item)
        self._advance_revision(item)

    def _apply_opening(self, item: JournalEvent) -> None:
        if item.type is not EventType.ENGAGEMENT_OPENED:
            raise EngagementReplayError("the first event must be engagement_opened")
        if (
            not isinstance(item.payload, EngagementOpenedPayload)
            or item.payload.scope_references != self.current_scope_references
        ):
            raise EngagementReplayError("opening event does not match the manifest scope")
        self.opened = True

    def _advance_revision(self, item: JournalEvent) -> None:
        self.revision = JournalRevision(
            sequence=item.sequence,
            event_hash=item.event_hash,
        )

    def _lane(self, item: JournalEvent) -> ExecutionLaneKey:
        if item.lane is None:
            raise EngagementReplayError(f"{item.type.value} requires an execution lane")
        return item.lane

    def _require_bound(self, item: JournalEvent) -> None:
        lane = self._lane(item)
        if lane.stable_key not in self.bound_lanes:
            raise EngagementReplayError(
                f"{item.type.value} requires a lane currently bound to this engagement"
            )

    def _apply_inert(self, item: JournalEvent) -> None:
        del item

    def _active_promotion(self, item: JournalEvent) -> PromotionAttemptState:
        if not self.promotion_attempts:
            raise EngagementReplayError(f"{item.type.value} requires an active promotion")
        attempt = self.promotion_attempts[-1]
        if (
            attempt.stage in {"promoted", "terminated", "revoked", "superseded"}
            or attempt.attempt_id != getattr(item.payload, "attempt_id", None)
            or attempt.promotion_revision != getattr(item.payload, "promotion_revision", None)
        ):
            raise EngagementReplayError(f"{item.type.value} does not match the active promotion")
        return attempt

    def _replace_promotion(self, attempt: PromotionAttemptState, **changes: object) -> None:
        self.promotion_attempts[-1] = attempt.model_copy(update=changes)

    def _fold_terminal_promotion(self, item: JournalEvent) -> None:
        del item
        if len(self.promotion_attempts) <= 64:
            return
        evicted = self.promotion_attempts.pop(0)
        terminal_record = json.dumps(
            evicted.model_dump(mode="json", warnings="error"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        previous = (self.promotion_folded_sha256 or "").encode("ascii")
        self.promotion_folded_sha256 = sha256(previous + b"\x00" + terminal_record).hexdigest()
        self.promotion_folded_count += 1

    def _apply_promotion(self, item: JournalEvent) -> None:
        payload = item.payload
        if isinstance(payload, PromotionRequestedPayload):
            if self.promotion_attempts and self.promotion_attempts[-1].stage not in {
                "promoted",
                "terminated",
                "revoked",
                "superseded",
            }:
                raise EngagementReplayError("only one promotion attempt may be active")
            expected_revision = self.promotion_attempt_count + 1
            expected_ordinal = (
                self.promotion_attempt_ordinal + 1
                if payload.verification_event_id == self.promotion_verification_event_id
                else 1
            )
            if (
                payload.attempt_ordinal != expected_ordinal
                or payload.promotion_revision != expected_revision
            ):
                raise EngagementReplayError("promotion ordinal and revision must increase exactly")
            self.promotion_attempts.append(
                PromotionAttemptState(
                    attempt_id=payload.attempt_id,
                    attempt_ordinal=payload.attempt_ordinal,
                    promotion_revision=payload.promotion_revision,
                    idempotency_key=payload.idempotency_key,
                    verified_revision=payload.verified_revision,
                    verification_event_id=payload.verification_event_id,
                    claim_event_id=item.event_id,
                    claim_expires_at=payload.claim_expires_at,
                    stage="requested",
                )
            )
            self.promotion_attempt_count = expected_revision
            self.promotion_verification_event_id = payload.verification_event_id
            self.promotion_attempt_ordinal = expected_ordinal
            return

        if isinstance(payload, PromotionRevocationRequestedPayload):
            if not self.promotion_attempts:
                raise EngagementReplayError("promotion revocation requires a published attempt")
            promoted = self.promotion_attempts[-1]
            lineage = self.latest_successful_publication
            if (
                promoted.stage != "promoted"
                or promoted.disposition != "promoted"
                or promoted.attempt_id != payload.attempt_id
                or promoted.source_id != payload.source_id
                or promoted.case_ids != payload.promoted_case_ids
                or lineage is None
                or lineage.attempt_id != payload.attempt_id
                or lineage.source_id != payload.source_id
                or lineage.case_ids != payload.promoted_case_ids
            ):
                raise EngagementReplayError(
                    "promotion revocation does not match pinned publication"
                )
            self.promotion_attempts.append(
                promoted.model_copy(
                    update={
                        "stage": "revocation_requested",
                        "disposition": None,
                        "revocation_request_event_id": item.event_id,
                    }
                )
            )
            return

        if isinstance(payload, CasePromotionRevokedPayload):
            if not self.promotion_attempts:
                raise EngagementReplayError("promotion cleanup requires a revocation request")
            attempt = self.promotion_attempts[-1]
            if (
                attempt.stage != "revocation_requested"
                or attempt.attempt_id != payload.attempt_id
                or attempt.source_id != payload.source_id
                or attempt.case_ids != payload.removed_case_ids
            ):
                raise EngagementReplayError("promotion cleanup does not match revocation request")
            self._replace_promotion(
                attempt,
                stage="revoked",
                disposition="cancelled",
                cleanup_event_id=item.event_id,
                cleanup_canonical_revision=payload.canonical_revision,
            )
            self._fold_terminal_promotion(item)
            return

        if isinstance(payload, CasePromotionSupersededPayload):
            if not self.promotion_attempts:
                raise EngagementReplayError("promotion supersession requires a replacement")
            replacement = self.promotion_attempts[-1]
            prior_index = next(
                (
                    index
                    for index in range(len(self.promotion_attempts) - 2, -1, -1)
                    if self.promotion_attempts[index].attempt_id == payload.prior_attempt_id
                ),
                None,
            )
            if prior_index is None:
                lineage = self.latest_successful_publication
                if (
                    lineage is None
                    or lineage.attempt_id != payload.prior_attempt_id
                    or lineage.source_id != payload.source_id
                    or lineage.case_ids != payload.removed_case_ids
                    or replacement.attempt_id != payload.replacement_attempt_id
                    or replacement.source_id != payload.source_id
                    or replacement.stage not in {"index_pending", "retry_failed"}
                    or replacement.promotion_revision <= lineage.promotion_revision
                ):
                    raise EngagementReplayError(
                        "promotion supersession folded lineage does not match"
                    )
                return
            prior = self.promotion_attempts[prior_index]
            if (
                prior.stage not in {"promoted", "revoked"}
                or prior.source_id != payload.source_id
                or prior.case_ids != payload.removed_case_ids
                or replacement.attempt_id != payload.replacement_attempt_id
                or replacement.source_id != payload.source_id
                or replacement.stage not in {"index_pending", "retry_failed"}
                or replacement.promotion_revision <= prior.promotion_revision
            ):
                raise EngagementReplayError("promotion supersession identity does not match")
            self.promotion_attempts[prior_index] = prior.model_copy(
                update={
                    "stage": "superseded",
                    "replacement_attempt_id": replacement.attempt_id,
                }
            )
            return

        attempt = self._active_promotion(item)
        if isinstance(payload, PromotionAttemptCancellationRequestedPayload):
            if (
                attempt.stage != payload.stage
                or attempt.verification_event_id != payload.verification_event_id
            ):
                raise EngagementReplayError("promotion cancellation does not match active stage")
            self._replace_promotion(
                attempt,
                stage="cancellation_requested",
                cancellation_request_event_id=item.event_id,
            )
        elif isinstance(payload, PromotionCandidateReadyPayload):
            if attempt.stage != "requested":
                raise EngagementReplayError("promotion candidate is out of order")
            self._replace_promotion(
                attempt,
                stage="candidate_ready",
                candidate_relative_path=payload.candidate_relative_path,
                candidate_sha256=payload.candidate_sha256,
                repair_count=payload.repair_count,
            )
        elif isinstance(payload, PromotionSourceCommittedPayload):
            if attempt.stage != "candidate_ready":
                raise EngagementReplayError("promotion source commit is out of order")
            self._replace_promotion(attempt, stage="source_committed", source_id=payload.source_id)
        elif isinstance(payload, PromotionSemanticCommittedPayload):
            if attempt.stage != "source_committed" or payload.source_id != attempt.source_id:
                raise EngagementReplayError("promotion semantic commit is out of order")
            self._replace_promotion(
                attempt, stage="semantic_committed", artifact_ids=payload.artifact_ids
            )
        elif isinstance(payload, PromotionIndexPendingPayload):
            if attempt.stage != "semantic_committed" or payload.source_id != attempt.source_id:
                raise EngagementReplayError("promotion index publication is out of order")
            self._replace_promotion(attempt, stage="index_pending")
        elif isinstance(payload, PromotionIndexRetryFailedPayload):
            if attempt.stage not in {"index_pending", "retry_failed"}:
                raise EngagementReplayError("promotion retry failure is out of order")
            if payload.retry_count != attempt.index_retry_count + 1:
                raise EngagementReplayError("promotion retry count must increase exactly")
            self._replace_promotion(
                attempt,
                stage="retry_failed",
                index_retry_count=payload.retry_count,
                reason_code=payload.reason_code,
            )
        elif isinstance(payload, CasePromotedPayload):
            if attempt.stage not in {"index_pending", "retry_failed"}:
                raise EngagementReplayError("case promotion is out of order")
            if payload.source_id != attempt.source_id:
                raise EngagementReplayError("case promotion source does not match")
            self._replace_promotion(
                attempt,
                stage="promoted",
                case_ids=payload.case_ids,
                disposition="promoted",
            )
            self.latest_successful_publication = PromotionPublicationLineage(
                attempt_id=payload.attempt_id,
                promotion_revision=payload.promotion_revision,
                source_id=payload.source_id,
                case_ids=payload.case_ids,
            )
            self._fold_terminal_promotion(item)
        elif isinstance(payload, PromotionAttemptTerminatedPayload):
            self._replace_promotion(
                attempt,
                stage="terminated",
                disposition=payload.disposition,
                reason_code=payload.reason_code,
            )
            self._fold_terminal_promotion(item)
        else:
            raise EngagementReplayError("invalid promotion payload")

    def _apply_lane_bound(self, item: JournalEvent) -> None:
        lane = self._lane(item)
        payload = item.payload
        if not isinstance(payload, LaneBoundPayload) or payload.lane != lane:
            raise EngagementReplayError("lane binding does not match the event lane")
        self.bound_lanes[lane.stable_key] = lane

    def _apply_lane_unbound(self, item: JournalEvent) -> None:
        lane = self._lane(item)
        payload = item.payload
        if not isinstance(payload, LaneUnboundPayload) or payload.lane != lane:
            raise EngagementReplayError("lane unbinding does not match the event lane")
        if lane.stable_key not in self.bound_lanes:
            raise EngagementReplayError(
                "lane_unbound requires a lane currently bound to this engagement"
            )
        del self.bound_lanes[lane.stable_key]
        self.active_decisions.pop(lane.stable_key, None)

    def _apply_scope_changed(self, item: JournalEvent) -> None:
        payload = item.payload
        if not isinstance(payload, ScopeChangedPayload):
            raise EngagementReplayError("scope change payload is invalid")
        self.current_scope_references = payload.scope_references

    def _apply_decision(self, item: JournalEvent) -> None:
        lane = self._lane(item)
        payload = item.payload
        if not isinstance(payload, DecisionRecordedPayload):
            raise EngagementReplayError("decision payload is invalid")
        self.active_decisions[lane.stable_key] = ActiveDecision(
            lane=lane,
            decision_id=payload.decision_id,
            proposal_id=payload.proposal_id,
            strategy=payload.strategy,
            rationale=payload.rationale,
            host_adapted_command=payload.host_adapted_command,
        )

    def _apply_tool_started(self, item: JournalEvent) -> None:
        lane = self._lane(item)
        payload = item.payload
        if not isinstance(payload, ToolCallStartedPayload):
            raise EngagementReplayError("tool start payload is invalid")
        if payload.call_id in self.calls:
            raise EngagementReplayError("tool call ID has already been started")
        self.calls[payload.call_id] = _CallState(
            lane=lane,
            started_sequence=item.sequence,
        )
        self.operational_restart_required = False

    def _apply_tool_terminal(self, item: JournalEvent) -> None:
        payload = item.payload
        if not isinstance(payload, (ToolCallCompletedPayload, ToolCallTerminatedPayload)):
            raise EngagementReplayError("tool terminal payload is invalid")
        call = self.calls.get(payload.call_id)
        if call is None:
            raise EngagementReplayError("tool terminal event has no matching started call")
        if call.terminal_sequence is not None:
            raise EngagementReplayError("tool call is already terminal")
        if item.lane != call.lane:
            raise EngagementReplayError("tool terminal event does not match the starting lane")
        call.terminal_sequence = item.sequence

    def _apply_closure_requested(self, item: JournalEvent) -> None:
        payload = item.payload
        if not isinstance(payload, ClosureRequestedPayload):
            raise EngagementReplayError("closure request payload is invalid")
        expected_calls = tuple(
            sorted(
                call_id for call_id, call in self.calls.items() if call.terminal_sequence is None
            )
        )
        if (
            payload.terminal_watermark != item.sequence - 1
            or payload.in_flight_call_ids != expected_calls
        ):
            raise EngagementReplayError(
                "closure snapshot must match the exact terminal prefix and in-flight calls"
            )
        self.closure = ClosureBarrier(
            event_id=item.event_id,
            terminal_watermark=payload.terminal_watermark,
            in_flight_call_ids=payload.in_flight_call_ids,
            origin=payload.origin,
        )
        self.status = EngagementStatus.CLOSING

    def _apply_closure_cancelled(self, item: JournalEvent) -> None:
        # The durable payload proves barrier identity, not which sealed service issued it.
        # Origin-specific authority is enforced before append by the capability layer.
        payload = item.payload
        if not isinstance(payload, ClosureCancelledPayload):
            raise EngagementReplayError("closure cancellation payload is invalid")
        if self.closure is None or payload.closure_event_id != self.closure.event_id:
            raise EngagementReplayError(
                "closure cancellation must cite the current closure barrier"
            )
        self.closure = None
        self.status = EngagementStatus.ACTIVE
        self.operational_restart_required = True

    def _apply_reopened(self, item: JournalEvent) -> None:
        del item
        self.closure = None
        self.status = EngagementStatus.ACTIVE
        self.active_report = None

    def _apply_verified(self, item: JournalEvent) -> None:
        payload = item.payload
        if (
            not isinstance(payload, EngagementVerifiedPayload)
            or self.status is not EngagementStatus.CLOSED_UNVERIFIED
            or self.active_report is None
            or payload.report_id != self.active_report.report_id
            or payload.report_revision != self.active_report.report_revision
        ):
            raise EngagementReplayError("verification requires the active closed report")
        self.status = EngagementStatus.CLOSED_VERIFIED

    def _apply_abandoned(self, item: JournalEvent) -> None:
        del item
        self.status = EngagementStatus.ABANDONED

    def _apply_report_generated(self, item: JournalEvent) -> None:
        payload = item.payload
        if not isinstance(payload, ReportGeneratedPayload):
            raise EngagementReplayError("report payload is invalid")
        report = payload.report
        if payload.generation_reason == "closure":
            if self.status is not EngagementStatus.CLOSING or self.closure is None:
                raise EngagementReplayError("report closure barrier is not ready")
            if not self.closure_ready or report.journal_revision != self.revision:
                raise EngagementReplayError("report does not match a ready closure barrier")
            if self.pending_report is not None or report.report_revision != len(self.reports) + 1:
                raise EngagementReplayError("closure report revision has already been used")
            self.pending_report = report
            return
        if self.status not in {
            EngagementStatus.CLOSED_UNVERIFIED,
            EngagementStatus.CLOSED_VERIFIED,
        }:
            raise EngagementReplayError("later report revision requires a closed engagement")
        if self.pending_report is not None or report.report_revision != len(self.reports) + 1:
            raise EngagementReplayError("report revisions must increase exactly")
        self.reports.append(report)
        self.active_report = report

    def _apply_engagement_closed(self, item: JournalEvent) -> None:
        payload = item.payload
        report = self.pending_report
        if not isinstance(payload, EngagementClosedPayload) or report is None:
            raise EngagementReplayError(
                "engagement close requires the immediately committed report"
            )
        if self.closure is None or (
            payload.report_id != report.report_id
            or payload.report_revision != report.report_revision
            or payload.closure_request_event_id != self.closure.event_id
            or payload.terminal_watermark != self.closure.terminal_watermark
        ):
            raise EngagementReplayError(
                "engagement close does not match report and closure barrier"
            )
        self.reports.append(report)
        self.active_report = report
        self.pending_report = None
        self.closure = None
        self.status = EngagementStatus.CLOSED_UNVERIFIED

    @property
    def closure_ready(self) -> bool:
        return self.closure is not None and all(
            self.calls[call_id].terminal_sequence is not None
            for call_id in self.closure.in_flight_call_ids
        )

    def freeze(self) -> EngagementState:
        if self.operational_restart_required:
            raise EngagementReplayError(_ATOMIC_RESTART_ERROR)
        bindings = tuple(
            LaneBinding(lane=lane, engagement_id=self.manifest.engagement_id)
            for _, lane in sorted(self.bound_lanes.items())
        )
        decisions = tuple(decision for _, decision in sorted(self.active_decisions.items()))
        in_flight_call_ids = tuple(
            sorted(
                call_id for call_id, call in self.calls.items() if call.terminal_sequence is None
            )
        )
        closure_ready = self.closure_ready
        active_promotion = None
        terminal_promotions = tuple(self.promotion_attempts)
        if terminal_promotions and terminal_promotions[-1].disposition is None:
            active_promotion = terminal_promotions[-1]
            terminal_promotions = terminal_promotions[:-1]
        return EngagementState(
            revision=self.revision,
            status=self.status,
            scope_references=self.current_scope_references,
            bound_lanes=bindings,
            active_decisions=decisions,
            in_flight_call_ids=in_flight_call_ids,
            closure=self.closure,
            closure_ready=closure_ready,
            reports=tuple(self.reports),
            active_report=self.active_report,
            promotion=PromotionState(
                active_attempt=active_promotion,
                recent_terminal_attempts=terminal_promotions,
                folded_terminal_count=self.promotion_folded_count,
                folded_terminal_sha256=self.promotion_folded_sha256,
                latest_successful_publication=self.latest_successful_publication,
            ),
        )


def reduce_engagement(
    manifest: EngagementManifest,
    events: Sequence[JournalEvent],
) -> EngagementState:
    """Replay a complete engagement journal into immutable lifecycle state."""

    validate_event_chain(manifest.engagement_id, events)
    accumulator = _Accumulator.from_manifest(manifest)
    for item in events:
        accumulator.apply(item)
    return accumulator.freeze()


__all__ = [
    "EVENT_LIFECYCLE_EFFECTS",
    "RESUMABLE_STATUSES",
    "STATUS_LIFECYCLE_MATRIX",
    "EngagementReplayError",
    "LifecycleEffect",
    "reduce_engagement",
    "validate_event_chain",
]
