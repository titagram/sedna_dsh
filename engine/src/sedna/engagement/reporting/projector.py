"""Deterministic journal-to-private-report projection."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from hashlib import sha256
from typing import Any
from uuid import uuid5

from sedna.engagement.events import (
    DecisionRecordedPayload,
    EngagementSnapshot,
    EventType,
    EvidenceAttachedPayload,
    EvidenceCaptureFailedPayload,
    FrontierProposedEventPayload,
    FrontierRepairedEventPayload,
    HypothesisFormedEventPayload,
    JournalEvent,
    ObjectiveChangedPayload,
    ObjectiveProofObservedEventPayload,
    ObservationExtractedEventPayload,
    OutcomeAssessedEventPayload,
    ResearchQueryProposedEventPayload,
    ResearchSourceAssessedEventPayload,
    ResearchSourceConsultedEventPayload,
    ScopeChangedPayload,
    SessionFinalizedPayload,
    SessionStartedPayload,
    ToolCallCompletedPayload,
    ToolCallStartedPayload,
    ToolCallTerminatedPayload,
)
from sedna.engagement.models import EvidenceSlice, scope_references
from sedna.engagement.reporting.markdown import render_operational_report
from sedna.engagement.reporting.models import (
    MAX_REPORT_INLINE_TEXT_BYTES,
    MAX_REPORT_JSON_BYTES,
    MAX_REPORT_MARKDOWN_BYTES,
    OperationalReport,
    ReportCapturedOutput,
    ReportCompletion,
    ReportDecision,
    ReportEvidenceRef,
    ReportFrontierChange,
    ReportHypothesis,
    ReportObservation,
    ReportOverflowSummary,
    ReportSecret,
    ReportSession,
    ReportSource,
    ReportToolExecution,
)
from sedna.engagement.service import EvidenceDescriptor

EvidenceReader = Callable[..., EvidenceSlice]

REPORT_IGNORED_EVENT_TYPES = frozenset(
    {
        EventType.REPORT_GENERATED,
        EventType.ENGAGEMENT_CLOSED,
        EventType.REPORT_COMMIT_ABANDONED,
        EventType.PROMOTION_REQUESTED,
        EventType.PROMOTION_CANDIDATE_READY,
        EventType.PROMOTION_SOURCE_COMMITTED,
        EventType.PROMOTION_SEMANTIC_COMMITTED,
        EventType.PROMOTION_INDEX_PENDING,
        EventType.PROMOTION_INDEX_RETRY_FAILED,
        EventType.PROMOTION_ATTEMPT_TERMINATED,
        EventType.PROMOTION_ATTEMPT_CANCELLATION_REQUESTED,
        EventType.PROMOTION_REVOCATION_REQUESTED,
    }
)
REPORT_PROJECTED_EVENT_TYPES = frozenset(
    {
        EventType.ENGAGEMENT_OPENED,
        EventType.ENGAGEMENT_RESUMED,
        EventType.LANE_BOUND,
        EventType.LANE_UNBOUND,
        EventType.CHILD_LANE_LINKED,
        EventType.SESSION_STARTED,
        EventType.SESSION_CHECKPOINTED,
        EventType.SESSION_FINALIZED,
        EventType.OBJECTIVE_CHANGED,
        EventType.SCOPE_CHANGED,
        EventType.DECISION_RECORDED,
        EventType.AGENT_DEVIATION_RECORDED,
        EventType.TOOL_CALL_STARTED,
        EventType.TOOL_CALL_COMPLETED,
        EventType.TOOL_CALL_TERMINATED,
        EventType.EVIDENCE_ATTACHED,
        EventType.EVIDENCE_CAPTURE_FAILED,
        EventType.UNMATCHED_TOOL_COMPLETION,
        EventType.UNPLANNED_ACTION,
        EventType.CONTROL_TOOL_INVOKED,
        EventType.CLOSURE_REQUESTED,
        EventType.CLOSURE_CANCELLED,
        EventType.ENGAGEMENT_VERIFIED,
        EventType.CASE_PROMOTED,
        EventType.CASE_PROMOTION_REVOKED,
        EventType.CASE_PROMOTION_SUPERSEDED,
        EventType.FLAG_REJECTED,
        EventType.ENGAGEMENT_REOPENED,
        EventType.ENGAGEMENT_ABANDONED,
        EventType.SOURCE_SUGGESTED,
        EventType.RECOVERY_WARNING,
        EventType.UNCERTAIN_CORRELATION,
        EventType.USER_NOTE,
        EventType.JOURNAL_CORRECTION_RECORDED,
        EventType.OBSERVATION_EXTRACTED,
        EventType.HYPOTHESIS_FORMED,
        EventType.MISSING_INFORMATION_IDENTIFIED,
        EventType.OUTCOME_ASSESSED,
        EventType.OBJECTIVE_PROOF_OBSERVED,
        EventType.INTERPRETATION_SUCCEEDED,
        EventType.INTERPRETATION_FAILED,
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


class OperationalReportProjector:
    """Build an immutable report from one exact journal watermark."""

    def project(
        self,
        *,
        snapshot: EngagementSnapshot,
        events: tuple[JournalEvent, ...],
        evidence: tuple[EvidenceDescriptor, ...],
        evidence_reader: EvidenceReader,
        report_revision: int,
        generated_at: datetime,
    ) -> OperationalReport:
        if snapshot.state.status.value not in {"closing", "closed_unverified", "closed_verified"}:
            raise ValueError("report projection requires closing or closed engagement")
        bounded = tuple(item for item in events if item.sequence <= snapshot.revision.sequence)
        if not bounded or bounded[-1].event_hash != snapshot.revision.event_hash:
            raise ValueError("report events do not match the requested journal revision")
        if tuple(item.event_id for item in bounded) != tuple(
            item.event_id for item in snapshot.events
        ):
            raise ValueError("report event sequence does not match snapshot")
        unclassified = {item.type for item in bounded} - (
            REPORT_PROJECTED_EVENT_TYPES | REPORT_IGNORED_EVENT_TYPES
        )
        if unclassified:
            raise ValueError("report event type is not classified")
        objective = snapshot.manifest.initial_objective
        scope = scope_references(snapshot.manifest.initial_scope)
        for item in bounded:
            if isinstance(item.payload, ObjectiveChangedPayload):
                objective = item.payload.objective
            elif isinstance(item.payload, ScopeChangedPayload):
                scope = item.payload.scope_references
        descriptors = {item.attachment_event_id: item for item in evidence}
        # Declaration order is the budget priority from lowest to highest.
        sections = {
            "sessions": self._sessions(bounded),
            "timeline": self._timeline(bounded),
            "observations": self._observations(bounded),
            "hypotheses": self._hypotheses(bounded),
            "decisions": self._decisions(bounded),
            "frontier_changes": self._frontier_changes(bounded),
            "tool_executions": self._executions(
                snapshot.engagement_id, bounded, descriptors, evidence_reader, failed=False
            ),
            "failed_attempts": self._executions(
                snapshot.engagement_id, bounded, descriptors, evidence_reader, failed=True
            ),
            "secrets": self._secrets(snapshot.engagement_id, bounded, evidence_reader),
            "sources": self._sources(bounded),
        }
        report = OperationalReport(
            report_id=uuid5(snapshot.engagement_id, f"report:{report_revision}"),
            report_revision=report_revision,
            engagement_id=snapshot.engagement_id,
            display_name=snapshot.manifest.display_name,
            journal_revision=snapshot.revision,
            generated_at=generated_at,
            lifecycle_status=(
                "closed_unverified"
                if snapshot.state.status.value == "closing"
                else snapshot.state.status.value
            ),
            objective=objective,
            scope=tuple(f"{item.kind}: {item.value}" for item in scope),
            completion=self._completion(snapshot, bounded),
        )
        return self._bounded_report(report, sections, bounded)

    @classmethod
    def _bounded_report(
        cls,
        report: OperationalReport,
        sections: dict[str, tuple[Any, ...]],
        events: tuple[JournalEvent, ...],
    ) -> OperationalReport:
        by_id = {item.event_id: item for item in events}
        section_order = tuple(sections)
        overflow_by_section: dict[str, ReportOverflowSummary] = {}
        bounded = report
        for section in reversed(section_order):
            items = sections[section]
            low = 0
            high = len(items)
            while low < high:
                kept_count = (low + high + 1) // 2
                omitted = items[kept_count:]
                trial_overflow = dict(overflow_by_section)
                if omitted:
                    trial_overflow[section] = cls._overflow_summary(section, omitted, by_id)
                try:
                    trial = cls._replace_report(
                        bounded,
                        **{
                            section: items[:kept_count],
                            "overflow": tuple(
                                trial_overflow[name]
                                for name in section_order
                                if name in trial_overflow
                            ),
                        },
                    )
                    fits = cls._fits_envelopes(trial)
                except ValueError:
                    fits = False
                if fits:
                    low = kept_count
                else:
                    high = kept_count - 1
            omitted = items[low:]
            if omitted:
                overflow_by_section[section] = cls._overflow_summary(section, omitted, by_id)
            bounded = cls._replace_report(
                bounded,
                **{
                    section: items[:low],
                    "overflow": tuple(
                        overflow_by_section[name]
                        for name in section_order
                        if name in overflow_by_section
                    ),
                },
            )
            if not cls._fits_envelopes(bounded):
                raise ValueError("report metadata exceeds its byte envelopes")
        if not cls._fits_envelopes(bounded):
            raise ValueError("report exceeds its byte envelopes")
        return bounded

    @staticmethod
    def _replace_report(report: OperationalReport, **changes: Any) -> OperationalReport:
        return OperationalReport.model_validate(
            report.model_copy(update=changes).model_dump(mode="python")
        )

    @staticmethod
    def _overflow_summary(
        section: str,
        omitted: tuple[Any, ...],
        events_by_id: dict[Any, JournalEvent],
    ) -> ReportOverflowSummary:
        referenced_ids = {
            event_id for item in omitted for event_id in getattr(item, "event_ids", ())
        }
        omitted_events = tuple(
            item for item in events_by_id.values() if item.event_id in referenced_ids
        )
        if not omitted_events:
            raise ValueError("omitted report items must reference journal events")
        digest_input = json.dumps(
            [
                {
                    "event_hash": item.event_hash,
                    "event_id": str(item.event_id),
                    "sequence": item.sequence,
                }
                for item in omitted_events
            ],
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return ReportOverflowSummary(
            section=section,
            omitted_count=len(omitted_events),
            first_omitted_sequence=omitted_events[0].sequence,
            last_omitted_sequence=omitted_events[-1].sequence,
            omitted_event_digest=sha256(digest_input).hexdigest(),
        )

    @staticmethod
    def _fits_envelopes(report: OperationalReport) -> bool:
        json_size = len(report.model_dump_json().encode("utf-8"))
        if json_size > MAX_REPORT_JSON_BYTES:
            return False
        return len(render_operational_report(report).encode("utf-8")) <= MAX_REPORT_MARKDOWN_BYTES

    @staticmethod
    def _completion(
        snapshot: EngagementSnapshot, events: tuple[JournalEvent, ...]
    ) -> ReportCompletion:
        assessments: dict[str, str] = {}
        for item in events:
            if isinstance(item.payload, ObjectiveProofObservedEventPayload):
                assessments[item.payload.proof_requirement_id] = item.payload.assessment
        required = tuple(item.proof_id for item in snapshot.manifest.required_proofs)
        unresolved = tuple(
            f"Required proof not supported: {proof_id}"
            for proof_id in required
            if assessments.get(proof_id) != "supported"
        )
        return ReportCompletion(
            objective_satisfied=bool(required) and not unresolved,
            final_access=(),
            unresolved_issues=unresolved,
        )

    @staticmethod
    def _sessions(events: tuple[JournalEvent, ...]) -> tuple[ReportSession, ...]:
        open_sessions: dict[str, list[JournalEvent]] = {}
        completed: list[ReportSession] = []
        for item in events:
            if item.lane is None:
                continue
            session_id = item.lane.session_id
            if isinstance(item.payload, SessionStartedPayload):
                open_sessions[session_id] = [item]
            elif session_id in open_sessions:
                open_sessions[session_id].append(item)
                if isinstance(item.payload, SessionFinalizedPayload):
                    completed.extend(
                        OperationalReportProjector._session_chunks(
                            session_id,
                            open_sessions.pop(session_id),
                            ended_at=item.occurred_at,
                        )
                    )
        for session_id, session_events in open_sessions.items():
            completed.extend(OperationalReportProjector._session_chunks(session_id, session_events))
        return tuple(completed)

    @staticmethod
    def _session_chunks(
        session_id: str,
        events: list[JournalEvent],
        *,
        ended_at: datetime | None = None,
    ) -> tuple[ReportSession, ...]:
        chunks = tuple(events[offset : offset + 128] for offset in range(0, len(events), 128))
        return tuple(
            ReportSession(
                session_id=session_id,
                started_at=chunk[0].occurred_at,
                ended_at=ended_at if index == len(chunks) - 1 else None,
                event_ids=tuple(item.event_id for item in chunk),
            )
            for index, chunk in enumerate(chunks)
        )

    @staticmethod
    def _timeline(events: tuple[JournalEvent, ...]) -> tuple[ReportObservation, ...]:
        return tuple(
            ReportObservation(
                summary=f"{item.type.value} at sequence {item.sequence}",
                confidence=1.0,
                event_ids=(item.event_id,),
            )
            for item in events
            if item.type in REPORT_PROJECTED_EVENT_TYPES
        )

    @staticmethod
    def _observations(events: tuple[JournalEvent, ...]) -> tuple[ReportObservation, ...]:
        return tuple(
            ReportObservation(
                summary=item.payload.summary,
                confidence=item.payload.confidence,
                event_ids=(item.event_id,),
                evidence_ids=tuple(
                    dict.fromkeys(
                        reference.evidence_id for reference in item.payload.evidence_slices
                    )
                ),
            )
            for item in events
            if isinstance(item.payload, ObservationExtractedEventPayload)
        )

    @staticmethod
    def _hypotheses(events: tuple[JournalEvent, ...]) -> tuple[ReportHypothesis, ...]:
        return tuple(
            ReportHypothesis(
                statement=item.payload.statement,
                status="weakened" if item.payload.contradicting_event_ids else "open",
                event_ids=(
                    item.event_id,
                    *item.payload.supporting_event_ids,
                    *item.payload.contradicting_event_ids,
                ),
            )
            for item in events
            if isinstance(item.payload, HypothesisFormedEventPayload)
        )

    @staticmethod
    def _decisions(events: tuple[JournalEvent, ...]) -> tuple[ReportDecision, ...]:
        return tuple(
            ReportDecision(
                strategy=item.payload.strategy,
                rationale=item.payload.rationale,
                proposal_id=item.payload.proposal_id,
                event_ids=(item.event_id,),
            )
            for item in events
            if isinstance(item.payload, DecisionRecordedPayload)
        )

    @staticmethod
    def _frontier_changes(
        events: tuple[JournalEvent, ...],
    ) -> tuple[ReportFrontierChange, ...]:
        scores: dict[str, int] = {}
        results: list[ReportFrontierChange] = []
        for item in events:
            payload = item.payload
            if not isinstance(
                payload, (FrontierProposedEventPayload, FrontierRepairedEventPayload)
            ):
                continue
            proposal = payload.proposal
            if proposal.variant_id is not None:
                strategy_key = f"variant:{proposal.variant_id}"
            elif proposal.family_id is not None:
                strategy_key = f"family:{proposal.family_id}"
            else:
                strategy_key = f"proposal:{proposal.proposal_id}"
            results.append(
                ReportFrontierChange(
                    strategy_key=strategy_key,
                    previous_score=scores.get(strategy_key),
                    score=proposal.score,
                    reason=proposal.rationale,
                    event_ids=(item.event_id,),
                )
            )
            scores[strategy_key] = proposal.score
        return tuple(results)

    @classmethod
    def _executions(
        cls,
        engagement_id,
        events: tuple[JournalEvent, ...],
        descriptors: dict[Any, EvidenceDescriptor],
        evidence_reader: EvidenceReader,
        *,
        failed: bool,
    ) -> tuple[ReportToolExecution, ...]:
        starts = {
            item.payload.call_id: item
            for item in events
            if isinstance(item.payload, ToolCallStartedPayload)
        }
        decisions = {
            item.payload.decision_id: item.payload
            for item in events
            if isinstance(item.payload, DecisionRecordedPayload)
        }
        proposals = {
            item.payload.proposal.proposal_id: item.payload.proposal
            for item in events
            if isinstance(
                item.payload, (FrontierProposedEventPayload, FrontierRepairedEventPayload)
            )
        }
        capture_failures = {
            item.payload.call_id
            for item in events
            if isinstance(item.payload, EvidenceCaptureFailedPayload)
            and item.payload.capture_role == "result"
        }
        assessed_outcomes = {
            item.payload.terminal_tool_event_id: item
            for item in events
            if isinstance(item.payload, OutcomeAssessedEventPayload)
        }
        results: list[ReportToolExecution] = []
        for item in events:
            payload = item.payload
            if not isinstance(payload, (ToolCallCompletedPayload, ToolCallTerminatedPayload)):
                continue
            assessed = assessed_outcomes.get(item.event_id)
            is_failed = isinstance(payload, ToolCallTerminatedPayload) or (
                isinstance(payload, ToolCallCompletedPayload)
                and payload.technical_status != "returned"
            )
            if assessed is not None and isinstance(assessed.payload, OutcomeAssessedEventPayload):
                is_failed = assessed.payload.category not in {
                    "progress",
                    "partial_progress",
                }
            if is_failed != failed:
                continue
            start = starts.get(payload.call_id)
            if start is None or not isinstance(start.payload, ToolCallStartedPayload):
                continue
            started = start.payload
            decision = (
                decisions.get(started.decision_id) if started.decision_id is not None else None
            )
            proposal = (
                proposals.get(decision.proposal_id)
                if decision is not None and decision.proposal_id is not None
                else None
            )
            if payload.call_id in capture_failures:
                absence_reason = "capture_failed"
            elif isinstance(payload, ToolCallTerminatedPayload):
                absence_reason = payload.resolution
            elif payload.technical_status == "returned" or payload.technical_status == "unknown":
                absence_reason = "host_returned_no_result"
            else:
                absence_reason = payload.technical_status
            output = ReportCapturedOutput(disposition="absent", absence_reason=absence_reason)
            if (
                isinstance(payload, ToolCallCompletedPayload)
                and payload.evidence_attachment_event_id is not None
            ):
                descriptor = descriptors.get(payload.evidence_attachment_event_id)
                if descriptor is None:
                    raise ValueError("report evidence descriptor is missing")
                output = cls._capture(engagement_id, descriptor, evidence_reader)
            results.append(
                ReportToolExecution(
                    call_id=payload.call_id,
                    tool_name=started.tool_name,
                    suggested_commands=(
                        tuple(command.rendered_preview for command in proposal.commands)
                        if proposal is not None
                        else ()
                    ),
                    executed_command=(
                        decision.host_adapted_command.command_template
                        if decision is not None and decision.host_adapted_command is not None
                        else None
                    ),
                    outcome=(
                        assessed.payload.category
                        if assessed is not None
                        and isinstance(assessed.payload, OutcomeAssessedEventPayload)
                        else (
                            payload.technical_status
                            if isinstance(payload, ToolCallCompletedPayload)
                            else payload.resolution
                        )
                    ),
                    output=output,
                    event_ids=(
                        start.event_id,
                        item.event_id,
                        *((assessed.event_id,) if assessed is not None else ()),
                    ),
                )
            )
        return tuple(results)

    @staticmethod
    def _sources(events: tuple[JournalEvent, ...]) -> tuple[ReportSource, ...]:
        queries = {
            item.payload.query_id: item
            for item in events
            if isinstance(item.payload, ResearchQueryProposedEventPayload)
        }
        consulted = {
            item.event_id: item
            for item in events
            if isinstance(item.payload, ResearchSourceConsultedEventPayload)
        }
        results: list[ReportSource] = []
        for item in events:
            payload = item.payload
            if not isinstance(payload, ResearchSourceAssessedEventPayload):
                continue
            consultation = consulted.get(payload.consulted_event_id)
            query = queries.get(payload.query_id)
            if consultation is None or not isinstance(
                consultation.payload, ResearchSourceConsultedEventPayload
            ):
                raise ValueError("assessed report source lacks its consultation")
            event_ids = tuple(
                dict.fromkeys(
                    (
                        item.event_id,
                        consultation.event_id,
                        *((query.event_id,) if query is not None else ()),
                        *payload.related_event_ids,
                    )
                )
            )
            results.append(
                ReportSource(
                    locator=consultation.payload.normalized_locator,
                    query=(
                        query.payload.normalized_query
                        if query is not None
                        and isinstance(query.payload, ResearchQueryProposedEventPayload)
                        else None
                    ),
                    assessment=f"{payload.assessment}: {payload.summary}",
                    event_ids=event_ids,
                )
            )
        return tuple(results)

    @staticmethod
    def _secrets(
        engagement_id,
        events: tuple[JournalEvent, ...],
        evidence_reader: EvidenceReader,
    ) -> tuple[ReportSecret, ...]:
        results: list[ReportSecret] = []
        evidence_references = {
            item.payload.evidence.evidence_id: item.payload.evidence
            for item in events
            if isinstance(item.payload, EvidenceAttachedPayload)
        }
        for item in events:
            payload = item.payload
            if not isinstance(payload, ObjectiveProofObservedEventPayload):
                continue
            reference = payload.candidate_value.evidence_slice
            sliced = evidence_reader(
                engagement_id,
                reference.evidence_id,
                offset=reference.start,
                limit=reference.end - reference.start,
            )
            expected_size = reference.end - reference.start
            evidence_reference = evidence_references.get(reference.evidence_id)
            if (
                evidence_reference is None
                or reference.end > evidence_reference.size
                or reference.media_type != evidence_reference.media_type
                or sliced.evidence_id != reference.evidence_id
                or sliced.offset != reference.start
                or sliced.complete != (reference.end >= evidence_reference.size)
                or len(sliced.data) != expected_size
                or sha256(sliced.data).hexdigest() != reference.sha256
            ):
                raise ValueError(
                    "objective proof evidence slice does not match its journal reference"
                )
            try:
                value = sliced.data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError("private proof evidence slice is not UTF-8") from error
            results.append(
                ReportSecret(
                    kind="flag",
                    label=payload.proof_requirement_id,
                    value=value,
                    event_ids=(item.event_id, *payload.source_event_ids),
                )
            )
        return tuple(results)

    @staticmethod
    def _capture(
        engagement_id, descriptor: EvidenceDescriptor, reader: EvidenceReader
    ) -> ReportCapturedOutput:
        reference = descriptor.reference
        evidence_ref = ReportEvidenceRef(
            attachment_event_id=descriptor.attachment_event_id,
            event_sequence=descriptor.event_sequence,
            evidence_id=reference.evidence_id,
            relative_path=reference.relative_path,
            sha256=reference.sha256,
            media_type=reference.media_type,
            representation=reference.representation,
            capture_limitations=reference.capture_limitations,
            size_bytes=reference.size,
            host_truncated=bool(reference.capture_limitations),
        )
        textual = reference.media_type.startswith("text/") or reference.media_type in {
            "application/json",
            "application/yaml",
        }
        if (
            not textual
            or reference.size > MAX_REPORT_INLINE_TEXT_BYTES
            or reference.capture_limitations
        ):
            return ReportCapturedOutput(disposition="evidence", evidence=evidence_ref)
        sliced = reader(engagement_id, reference.evidence_id, offset=0, limit=reference.size)
        if (
            sliced.evidence_id != reference.evidence_id
            or sliced.offset != 0
            or not sliced.complete
            or len(sliced.data) != reference.size
            or sha256(sliced.data).hexdigest() != reference.sha256
        ):
            raise ValueError("report evidence read is incomplete or corrupt")
        try:
            text = sliced.data.decode("utf-8")
        except UnicodeDecodeError:
            return ReportCapturedOutput(disposition="evidence", evidence=evidence_ref)
        if not text:
            return ReportCapturedOutput(
                disposition="absent", absence_reason="host_returned_no_result"
            )
        return ReportCapturedOutput(disposition="inline", inline_text=text)


__all__ = [
    "EvidenceReader",
    "OperationalReportProjector",
    "REPORT_IGNORED_EVENT_TYPES",
    "REPORT_PROJECTED_EVENT_TYPES",
]
