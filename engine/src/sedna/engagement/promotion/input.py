"""Trusted projection from a verified journal to symbolized promotion input."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from sedna.engagement.events import (
    EngagementSnapshot,
    EngagementVerifiedPayload,
    EventType,
    EvidenceAttachedPayload,
    ObjectiveChangedPayload,
    ObjectiveProofObservedEventPayload,
    ObservationExtractedEventPayload,
    PrivateValueEventRecord,
    ScopeChangedPayload,
    SecretReferenceEventRecord,
)
from sedna.engagement.models import EvidenceReference, EvidenceSlice
from sedna.engagement.promotion.models import (
    MAX_PROMOTION_PRIVATE_BYTES,
    MAX_PROMOTION_PRIVATE_VALUE_BYTES,
    MAX_PROMOTION_PRIVATE_VALUES,
    PromotionEvidenceItem,
    PromotionInput,
    PromotionSecretInventory,
)
from sedna.engagement.promotion.sanitize import assert_promotion_safe, symbolize_text
from sedna.knowledge.retrieval import AuthorizationScope

PROMOTION_PROJECTED_EVENT_TYPES = frozenset(
    {
        EventType.DECISION_RECORDED,
        EventType.OBSERVATION_EXTRACTED,
        EventType.HYPOTHESIS_FORMED,
        EventType.MISSING_INFORMATION_IDENTIFIED,
        EventType.OUTCOME_ASSESSED,
        EventType.OBJECTIVE_PROOF_OBSERVED,
        EventType.FRONTIER_PROPOSED,
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
PROMOTION_IGNORED_EVENT_TYPES = frozenset(
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
        EventType.FLAG_REJECTED,
        EventType.ENGAGEMENT_REOPENED,
        EventType.ENGAGEMENT_ABANDONED,
        EventType.SOURCE_SUGGESTED,
        EventType.RECOVERY_WARNING,
        EventType.UNCERTAIN_CORRELATION,
        EventType.USER_NOTE,
        EventType.JOURNAL_CORRECTION_RECORDED,
        EventType.INTERPRETATION_SUCCEEDED,
        EventType.INTERPRETATION_FAILED,
        EventType.PLAN_REQUESTED,
        EventType.FRONTIER_CRITICIZED,
        EventType.REPORT_GENERATED,
        EventType.ENGAGEMENT_CLOSED,
        EventType.REPORT_COMMIT_ABANDONED,
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
_PROMOTION_CLASSIFIED_EVENT_TYPES = PROMOTION_PROJECTED_EVENT_TYPES | PROMOTION_IGNORED_EVENT_TYPES
PROMOTION_PRIVATE_TEXT_MEDIA_TYPES = frozenset(
    {"application/json", "application/yaml", "text/plain"}
)
PROMOTION_PRIVATE_TEXT_REPRESENTATIONS = frozenset(
    {
        "canonical_host_json",
        "host_text",
        "private_proof_utf8",
        "sanitized_host_json",
        "utf-8",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class PrivatePromotionProjection:
    safe_input: PromotionInput
    inventory: PromotionSecretInventory = field(repr=False)


@dataclass(frozen=True, slots=True)
class _PendingItem:
    section: str
    summary: str
    event_id: UUID
    event_ids: tuple[UUID, ...]
    evidence_ids: tuple[str, ...]


def _status_value(snapshot: Any) -> str:
    status = snapshot.state.status
    return status.value if hasattr(status, "value") else str(status)


def _sorted_ids(values: tuple[Any, ...] | list[Any]) -> tuple[Any, ...]:
    return tuple(sorted(set(values), key=str))


def _evidence_ids(payload: Any) -> tuple[str, ...]:
    direct = getattr(payload, "evidence_ids", ())
    slices = getattr(payload, "evidence_slices", ())
    return _sorted_ids(tuple(direct) + tuple(item.evidence_id for item in slices))


def _event_ids(payload: Any, event_id: UUID) -> tuple[UUID, ...]:
    values = [event_id]

    def visit(candidate: object, field_name: str | None = None) -> None:
        if field_name is not None and (
            field_name.endswith("_event_id")
            or field_name.endswith("_event_ids")
            or field_name == "event_refs"
        ):
            if isinstance(candidate, UUID):
                values.append(candidate)
            elif isinstance(candidate, tuple):
                values.extend(item for item in candidate if isinstance(item, UUID))
        if isinstance(candidate, BaseModel):
            for name in type(candidate).model_fields:
                if hasattr(candidate, name):
                    visit(getattr(candidate, name), name)
        elif isinstance(candidate, tuple):
            for item in candidate:
                visit(item)

    visit(payload)
    return _sorted_ids(values)


def _summary_for(event: Any) -> _PendingItem:
    payload = event.payload
    kind = event.type
    section = "context"
    if kind is EventType.DECISION_RECORDED:
        section = "decisions"
        summary = ". ".join(part for part in (payload.strategy, payload.rationale) if part)
    elif kind is EventType.OBSERVATION_EXTRACTED:
        summary = payload.summary
    elif kind is EventType.HYPOTHESIS_FORMED:
        summary = payload.statement
    elif kind is EventType.MISSING_INFORMATION_IDENTIFIED:
        section = "alternatives"
        summary = f"{payload.question}. {payload.reason}"
    elif kind is EventType.OUTCOME_ASSESSED:
        section = "outcomes"
        summary = f"{payload.summary}. Strategic impact: {payload.strategic_impact}"
    elif kind is EventType.OBJECTIVE_PROOF_OBSERVED:
        section = "outcomes"
        summary = (
            f"Objective proof {payload.proof_requirement_id} was assessed "
            f"{payload.assessment} with confidence {payload.confidence}"
        )
    elif kind in {EventType.FRONTIER_PROPOSED, EventType.FRONTIER_REPAIRED}:
        section = "alternatives"
        proposal = payload.proposal
        command_templates = tuple(command.command_template for command in proposal.commands)
        summary = ". ".join(
            part
            for part in (
                getattr(proposal, "title", None),
                proposal.rationale,
                *command_templates,
            )
            if part
        )
    elif kind is EventType.FRONTIER_REJECTED:
        section = "alternatives"
        summary = "Frontier proposal rejected: " + ", ".join(payload.reason_codes)
    elif kind is EventType.PLANNING_GAP_RECORDED:
        section = "alternatives"
        summary = getattr(payload, "summary", None) or getattr(payload, "gap", None)
    elif kind in {
        EventType.STRATEGY_RECONCILED,
        EventType.STRATEGY_ARCHIVED,
        EventType.STRATEGY_REACTIVATED,
    }:
        section = "alternatives"
        summary = (
            getattr(payload, "reason", None)
            or getattr(payload, "summary", None)
            or "Strategy lifecycle changed"
        )
    elif kind in {
        EventType.RESEARCH_QUERY_PROPOSED,
        EventType.RESEARCH_SOURCE_CONSULTED,
        EventType.RESEARCH_SOURCE_ASSESSED,
    }:
        summary = (
            getattr(payload, "normalized_query", None)
            or getattr(payload, "normalized_locator", None)
            or getattr(payload, "assessment", None)
            or getattr(payload, "summary", None)
            or "Research evidence considered"
        )
    else:  # The projected set is closed; reaching this branch is a security boundary failure.
        raise ValueError("unknown strategic event kind")
    if not isinstance(summary, str) or not summary:
        raise ValueError("strategic event has no promotable summary")
    return _PendingItem(
        section=section,
        summary=summary,
        event_id=event.event_id,
        event_ids=_event_ids(payload, event.event_id),
        evidence_ids=_evidence_ids(payload),
    )


def _private_records(
    snapshot: EngagementSnapshot,
) -> tuple[tuple[UUID, str, PrivateValueEventRecord], ...]:
    records: list[tuple[UUID, str, PrivateValueEventRecord]] = []
    proof_kinds = {proof.proof_id: proof.kind for proof in snapshot.manifest.required_proofs}
    for event in snapshot.events:
        payload = event.payload
        if isinstance(payload, ObjectiveProofObservedEventPayload):
            if payload.assessment == "supported" and payload.candidate_value is not None:
                category = (
                    "flag"
                    if proof_kinds.get(payload.proof_requirement_id) == "flag"
                    else "credential"
                )
                records.append((event.event_id, category, payload.candidate_value))
        elif isinstance(payload, ObservationExtractedEventPayload) and isinstance(
            payload.observation, SecretReferenceEventRecord
        ):
            records.append((event.event_id, "credential", payload.observation.value))
    if len(records) > MAX_PROMOTION_PRIVATE_VALUES:
        raise ValueError("private value inventory exceeds its count bound")
    return tuple(records)


def _validate_private_descriptor(
    record: PrivateValueEventRecord, reference: EvidenceReference
) -> int:
    descriptor = record.evidence_slice
    size = descriptor.end - descriptor.start
    if size < 1 or size > MAX_PROMOTION_PRIVATE_VALUE_BYTES:
        raise ValueError("private evidence slice exceeds its bound")
    valid_descriptor = (
        reference.evidence_id == descriptor.evidence_id
        and descriptor.end <= reference.size
        and reference.media_type == descriptor.media_type
        and descriptor.media_type in PROMOTION_PRIVATE_TEXT_MEDIA_TYPES
        and reference.representation in PROMOTION_PRIVATE_TEXT_REPRESENTATIONS
        and not reference.capture_limitations
        and descriptor.sha256 == record.value_sha256
    )
    if not valid_descriptor:
        raise ValueError("private evidence slice descriptor is unsupported")
    return size


def _resolve_private_value(
    engagement_id: UUID,
    record: PrivateValueEventRecord,
    reference: EvidenceReference,
    evidence_reader: Callable[..., EvidenceSlice],
) -> str:
    descriptor = record.evidence_slice
    size = _validate_private_descriptor(record, reference)
    result: EvidenceSlice | None = None
    with suppress(Exception):
        result = evidence_reader(
            engagement_id,
            descriptor.evidence_id,
            offset=descriptor.start,
            limit=size,
        )
    if result is None:
        raise ValueError("private evidence slice is unavailable")
    valid = (
        isinstance(result, EvidenceSlice)
        and result.evidence_id == descriptor.evidence_id
        and result.offset == descriptor.start
        and result.complete
        and len(result.data) == size
        and sha256(result.data).hexdigest() == descriptor.sha256
        and descriptor.sha256 == record.value_sha256
    )
    if not valid:
        raise ValueError("private evidence slice failed integrity validation")
    decoded: str | None = None
    with suppress(UnicodeDecodeError):
        decoded = result.data.decode("utf-8", errors="strict")
    if decoded is None:
        raise ValueError("private evidence slice is not strict UTF-8")
    return decoded


def _effective_objective_and_scope(
    snapshot: EngagementSnapshot,
) -> tuple[str, AuthorizationScope]:
    objective = snapshot.manifest.initial_objective
    scope = snapshot.manifest.initial_scope
    for event in snapshot.events:
        if isinstance(event.payload, ObjectiveChangedPayload):
            objective = event.payload.objective
        elif isinstance(event.payload, ScopeChangedPayload):
            scope = event.payload.scope
    return objective, scope


def _manifest_identity(
    snapshot: EngagementSnapshot, scope: AuthorizationScope
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    targets = {
        target.normalized or target.value for target in scope.exact_targets if target.is_valid
    }
    targets.update(scope.hostnames)
    targets.update(scope.url_origins)
    targets.update(scope.generic_ids)
    display = snapshot.manifest.display_name
    challenges = {display}
    for separator in ("-", ":", "/"):
        if separator in display:
            alias = display.split(separator, 1)[1].strip()
            if alias:
                challenges.add(alias)
    challenges.update(
        target for target in targets if any(character.isalpha() for character in target)
    )
    return (
        tuple(sorted(targets, key=lambda item: (item.casefold(), item))),
        tuple(sorted(challenges, key=lambda item: (item.casefold(), item))),
    )


class PromotionInputProjector:
    """Reduce the exact verified journal into a bounded symbolized input."""

    def project(
        self,
        snapshot: EngagementSnapshot,
        *,
        verification_event_id: UUID,
        evidence_reader: Callable[..., EvidenceSlice],
    ) -> PrivatePromotionProjection:
        if _status_value(snapshot) != "closed_verified":
            raise ValueError("promotion requires a closed_verified snapshot")
        if not snapshot.events:
            raise ValueError("promotion requires an exact verification event")
        verification = snapshot.events[-1]
        if (
            verification.event_id != verification_event_id
            or verification.type is not EventType.ENGAGEMENT_VERIFIED
            or verification.sequence != snapshot.revision.sequence
            or verification.event_hash != snapshot.revision.event_hash
        ):
            raise ValueError("promotion verification event does not match the snapshot watermark")
        payload = verification.payload
        active_report = snapshot.state.active_report
        if (
            not isinstance(payload, EngagementVerifiedPayload)
            or active_report is None
            or payload.report_id != active_report.report_id
            or payload.report_revision != active_report.report_revision
        ):
            raise ValueError("promotion verification event does not bind the active report")

        if any(event.type not in _PROMOTION_CLASSIFIED_EVENT_TYPES for event in snapshot.events):
            raise ValueError("unclassified journal event at promotion boundary")

        attached_references: dict[str, EvidenceReference] = {}
        for event in snapshot.events:
            payload = event.payload
            if not isinstance(payload, EvidenceAttachedPayload):
                continue
            reference = payload.evidence
            previous = attached_references.get(reference.evidence_id)
            if previous is not None and previous != reference:
                raise ValueError("private evidence slice descriptor identity is ambiguous")
            attached_references[reference.evidence_id] = reference
        records = _private_records(snapshot)
        validated_records: list[tuple[UUID, str, PrivateValueEventRecord, EvidenceReference]] = []
        for event_id, category, record in records:
            reference = attached_references.get(record.evidence_slice.evidence_id)
            if reference is None:
                raise ValueError("private evidence slice descriptor is unavailable")
            _validate_private_descriptor(record, reference)
            validated_records.append((event_id, category, record, reference))
        resolved: list[tuple[str, str]] = []
        resolved_by_event: dict[UUID, str] = {}
        total = 0
        for event_id, category, record, reference in validated_records:
            value = _resolve_private_value(
                snapshot.engagement_id, record, reference, evidence_reader
            )
            total += len(value.encode("utf-8"))
            if total > MAX_PROMOTION_PRIVATE_BYTES:
                raise ValueError("private value inventory exceeds its byte bound")
            resolved.append((category, value))
            resolved_by_event[event_id] = value

        objective, scope = _effective_objective_and_scope(snapshot)
        targets, challenges = _manifest_identity(snapshot, scope)
        inventory = PromotionSecretInventory(
            flags=tuple(value for category, value in resolved if category == "flag"),
            credentials=tuple(value for category, value in resolved if category == "credential"),
            target_identifiers=targets,
            challenge_identifiers=challenges,
        )

        pending = tuple(
            _summary_for(event)
            for event in snapshot.events
            if event.type in PROMOTION_PROJECTED_EVENT_TYPES
        )
        sections: dict[str, list[PromotionEvidenceItem]] = {
            "context": [],
            "decisions": [],
            "outcomes": [],
            "alternatives": [],
        }
        for item in pending:
            summary = item.summary
            if item.event_id in resolved_by_event:
                summary = f"{summary}. Private value: {resolved_by_event[item.event_id]}"
            sections[item.section].append(
                PromotionEvidenceItem(
                    summary=symbolize_text(summary, inventory),
                    event_ids=item.event_ids,
                    evidence_ids=_sorted_ids(list(item.evidence_ids)),
                )
            )
        safe_input = PromotionInput(
            engagement_id=snapshot.engagement_id,
            verified_revision=snapshot.revision,
            verification_event_id=verification_event_id,
            display_name=symbolize_text(snapshot.manifest.display_name, inventory),
            objective=symbolize_text(objective, inventory),
            context=tuple(sections["context"]),
            decisions=tuple(sections["decisions"]),
            outcomes=tuple(sections["outcomes"]),
            alternatives=tuple(sections["alternatives"]),
        )
        assert_promotion_safe(safe_input, inventory)
        return PrivatePromotionProjection(safe_input=safe_input, inventory=inventory)
