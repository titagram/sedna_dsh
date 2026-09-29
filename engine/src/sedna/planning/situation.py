"""Deterministic reconstruction of the current planning situation."""

from __future__ import annotations

import json
from collections.abc import Sequence
from hashlib import sha256
from typing import Any, Literal
from uuid import UUID

from sedna.engagement import EngagementSnapshot, EventType, scope_references
from sedna.engagement.events import (
    AccessStateDeltaEventRecord,
    EngagementReopenedPayload,
    EvidenceAttachedPayload,
    FacetObservationEventRecord,
    FlagRejectedPayload,
    HypothesisFormedEventPayload,
    IncompatibilityObservationEventRecord,
    InterpretationFailedEventPayload,
    InterpretationSucceededEventPayload,
    MissingInformationIdentifiedEventPayload,
    ObjectiveProofObservedEventPayload,
    ObservationExtractedEventPayload,
    OutcomeAssessedEventPayload,
    ResearchSourceAssessedEventPayload,
    SecretReferenceEventRecord,
    TextFactEventRecord,
)
from sedna.planning.belief import project_hypothesis_beliefs
from sedna.planning.models import (
    MAX_SITUATION_ITEMS,
    AccessState,
    AttemptSummary,
    AvailableCredential,
    EvidenceInterpretationState,
    Incompatibility,
    InterpretationSubject,
    ObjectiveProgress,
    ObservedFacet,
    ObservedFact,
    ProofProgress,
    ProofRejectionRecord,
    ProofRequirementId,
    ProofValueReference,
    ResearchSourceAssessment,
    SecretReference,
    Sha256Hex,
    SituationHypothesis,
    SituationProjection,
    UnresolvedInformation,
)

_EMPTY_DIGEST = sha256(b"[]").hexdigest()

SITUATION_EFFECT_EVENT_TYPES = frozenset(
    {
        EventType.EVIDENCE_ATTACHED,
        EventType.INTERPRETATION_SUCCEEDED,
        EventType.INTERPRETATION_FAILED,
        EventType.FLAG_REJECTED,
        EventType.ENGAGEMENT_REOPENED,
        EventType.RESEARCH_SOURCE_ASSESSED,
        EventType.OUTCOME_ASSESSED,
        EventType.HYPOTHESIS_FORMED,
        EventType.MISSING_INFORMATION_IDENTIFIED,
        EventType.OBJECTIVE_PROOF_OBSERVED,
        EventType.OBSERVATION_EXTRACTED,
    }
)
SITUATION_NO_OP_EVENT_TYPES = frozenset(
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
        EventType.EVIDENCE_CAPTURE_FAILED,
        EventType.UNMATCHED_TOOL_COMPLETION,
        EventType.UNPLANNED_ACTION,
        EventType.CONTROL_TOOL_INVOKED,
        EventType.CLOSURE_REQUESTED,
        EventType.CLOSURE_CANCELLED,
        EventType.ENGAGEMENT_VERIFIED,
        EventType.ENGAGEMENT_ABANDONED,
        EventType.SOURCE_SUGGESTED,
        EventType.RECOVERY_WARNING,
        EventType.UNCERTAIN_CORRELATION,
        EventType.USER_NOTE,
        EventType.JOURNAL_CORRECTION_RECORDED,
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


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def transition_proof_generation(
    progress: ObjectiveProgress,
    *,
    policy: Literal["retain_rejections", "invalidate_all"],
    transition_event_id: UUID,
    rejected_requirement_id: ProofRequirementId | None = None,
    rejection_event_id: UUID | None = None,
    rejected_value_sha256: Sha256Hex | None = None,
) -> ObjectiveProgress:
    """Advance proof generations without importing M6C event types."""

    rejection_fields = (
        rejected_requirement_id,
        rejection_event_id,
        rejected_value_sha256,
    )
    if policy == "invalidate_all":
        if any(value is not None for value in rejection_fields):
            raise ValueError("invalidate_all_rejects_rejection_fields")
        selected_ids = {item.proof_requirement_id for item in progress.requirements}
    else:
        if any(value is None for value in rejection_fields):
            raise ValueError("retain_rejections_requires_rejection_fields")
        assert rejected_requirement_id is not None
        assert rejected_value_sha256 is not None
        selected_ids = {rejected_requirement_id}
        matching = [
            item
            for item in progress.requirements
            if item.proof_requirement_id == rejected_requirement_id
        ]
        if len(matching) != 1:
            raise ValueError("rejected_proof_requirement_not_found")
        cited_digests = {
            reference.value_sha256
            for reference in matching[0].value_references
            if reference.proof_event_id in matching[0].supporting_event_ids
        }
        if rejected_value_sha256 not in cited_digests:
            raise ValueError("rejected_value_not_grounded_in_current_proof")

    transitioned = []
    for item in progress.requirements:
        if item.proof_requirement_id not in selected_ids:
            transitioned.append(item)
            continue
        historical_rows = [
            (
                reference.assessment_generation,
                reference.assessment,
                str(reference.proof_event_id),
                reference.value_sha256,
            )
            for reference in item.value_references
        ]
        update: dict[str, Any] = {
            "assessment_generation": item.assessment_generation + 1,
            "generation_started_event_id": transition_event_id,
            "supporting_event_ids": (),
            "value_references": (),
            "historical_assessment_count": (
                item.historical_assessment_count + len(historical_rows)
            ),
            "historical_assessment_digest": (
                sha256(_canonical_bytes(historical_rows)).hexdigest()
                if historical_rows
                else item.historical_assessment_digest
            ),
        }
        if policy == "retain_rejections":
            assert rejection_event_id is not None
            assert rejected_value_sha256 is not None
            update.update(
                status="contradicted",
                contradicting_event_ids=(rejection_event_id,),
                rejected_value_sha256s=tuple(
                    dict.fromkeys((*item.rejected_value_sha256s, rejected_value_sha256))
                )[-32:],
            )
        else:
            update.update(status="pending", contradicting_event_ids=())
        transitioned.append(
            ProofProgress.model_validate(item.model_copy(update=update).model_dump(mode="python"))
        )
    return ObjectiveProgress(requirements=tuple(transitioned))


def proof_value_was_rejected(
    progress: ProofProgress,
    *,
    candidate_value_sha256: Sha256Hex,
    authoritative_rejections: Sequence[ProofRejectionRecord],
) -> bool:
    """Validate the rejection inventory before checking candidate membership."""

    records = tuple(authoritative_rejections)
    if any(record.proof_requirement_id != progress.proof_requirement_id for record in records):
        raise ValueError("proof_rejection_requirement_mismatch")
    event_ids = tuple(str(record.rejection_event_id) for record in records)
    if event_ids != tuple(sorted(event_ids)) or len(event_ids) != len(set(event_ids)):
        raise ValueError("proof_rejections_not_strictly_ordered")
    ordered_digests = tuple(dict.fromkeys(record.rejected_value_sha256 for record in records))
    expected_hot = ordered_digests[-32:]
    if progress.rejected_value_sha256s != expected_hot:
        raise ValueError("proof_rejection_hot_inventory_mismatch")
    expected_overflow_count = max(0, len(ordered_digests) - 32)
    if progress.rejected_value_overflow_count != expected_overflow_count:
        raise ValueError("proof_rejection_overflow_count_mismatch")
    overflow_records = records[:expected_overflow_count]
    expected_overflow_digest = sha256(
        _canonical_bytes([record.model_dump(mode="json") for record in overflow_records])
    ).hexdigest()
    if (
        expected_overflow_count
        and progress.rejected_value_overflow_digest != expected_overflow_digest
    ):
        raise ValueError("proof_rejection_overflow_digest_mismatch")
    if candidate_value_sha256 in progress.rejected_value_sha256s:
        return True
    if progress.rejected_value_overflow_count:
        return candidate_value_sha256 in ordered_digests[:-32]
    return False


class SituationReducer:
    """Pure event replay into a bounded, immutable situation projection."""

    @classmethod
    def rebuild(cls, snapshot: EngagementSnapshot) -> SituationProjection:
        validated = EngagementSnapshot.model_validate(snapshot.model_dump(mode="python"))
        requirements = tuple(
            ProofProgress(
                proof_requirement_id=requirement.proof_id,
                status="pending",
                historical_assessment_digest=_EMPTY_DIGEST,
                rejected_value_overflow_digest=_EMPTY_DIGEST,
            )
            for requirement in sorted(
                validated.manifest.required_proofs,
                key=lambda item: item.proof_id,
            )
        )
        proof_by_id = {item.proof_requirement_id: item for item in requirements}
        rejection_records: dict[str, list[ProofRejectionRecord]] = {
            item.proof_requirement_id: [] for item in requirements
        }
        pending_rejection: tuple[UUID, FlagRejectedPayload, str] | None = None
        attached_evidence: dict[str, EvidenceAttachedPayload] = {}
        attachments_by_event_id: dict[object, EvidenceAttachedPayload] = {}
        interpretation_events: dict[tuple[UUID, UUID | None, str], list[UUID]] = {}
        interpretation_coverage: dict[tuple[UUID, UUID | None, str], list[tuple[int, int]]] = {}
        interpretation_failure: dict[tuple[UUID, UUID | None, str], bool] = {}
        facts: list[ObservedFact] = []
        facets: list[ObservedFacet] = []
        access_states: list[AccessState] = []
        secret_references: list[SecretReference] = []
        incompatibilities: list[Incompatibility] = []
        hypotheses: list[SituationHypothesis] = []
        unresolved_information: list[UnresolvedInformation] = []
        research_sources: list[ResearchSourceAssessment] = []
        attempts: list[AttemptSummary] = []
        valid_scope_ids = {
            item.reference_id for item in scope_references(validated.manifest.initial_scope)
        }
        material_event_revision = 0
        for event in validated.events:
            if isinstance(event.payload, EvidenceAttachedPayload):
                attached_evidence[event.payload.evidence.evidence_id] = event.payload
                attachments_by_event_id[event.event_id] = event.payload
                continue
            if isinstance(event.payload, InterpretationSucceededEventPayload):
                attachment = attachments_by_event_id.get(event.payload.attachment_event_id)
                if (
                    attachment is None
                    or attachment.evidence.evidence_id != event.payload.evidence_id
                ):
                    raise ValueError("interpretation_subject_not_authoritative")
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                if not set(event.payload.emitted_event_ids).issubset(prior_event_ids):
                    raise ValueError("interpretation_emitted_events_not_authoritative")
                for covered_slice in event.payload.covered_slices:
                    if (
                        covered_slice.start < 0
                        or covered_slice.end <= covered_slice.start
                        or covered_slice.end > attachment.evidence.size
                        or covered_slice.media_type != attachment.evidence.media_type
                    ):
                        raise ValueError("interpretation_coverage_mismatch")
                subject_key = (
                    event.payload.attachment_event_id,
                    event.payload.terminal_tool_event_id,
                    event.payload.evidence_id,
                )
                interpretation_events.setdefault(subject_key, []).append(event.event_id)
                interpretation_coverage.setdefault(subject_key, []).extend(
                    (item.start, item.end) for item in event.payload.covered_slices
                )
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, InterpretationFailedEventPayload):
                attachment = attachments_by_event_id.get(event.payload.attachment_event_id)
                if (
                    attachment is None
                    or attachment.evidence.evidence_id != event.payload.evidence_id
                ):
                    raise ValueError("interpretation_subject_not_authoritative")
                for attempted_slice in event.payload.attempted_slices:
                    if (
                        attempted_slice.start < 0
                        or attempted_slice.end <= attempted_slice.start
                        or attempted_slice.end > attachment.evidence.size
                        or attempted_slice.media_type != attachment.evidence.media_type
                    ):
                        raise ValueError("interpretation_coverage_mismatch")
                subject_key = (
                    event.payload.attachment_event_id,
                    event.payload.terminal_tool_event_id,
                    event.payload.evidence_id,
                )
                interpretation_events.setdefault(subject_key, []).append(event.event_id)
                interpretation_failure[subject_key] = True
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, FlagRejectedPayload):
                if pending_rejection is not None:
                    raise ValueError("proof_rejection_pair_incomplete")
                matches = [
                    proof
                    for proof in proof_by_id.values()
                    if any(
                        reference.proof_event_id == event.payload.flag_event_id
                        and reference.value_sha256 == event.payload.rejected_value_sha256
                        and reference.assessment == "supported"
                        for reference in proof.value_references
                    )
                ]
                if len(matches) != 1:
                    raise ValueError("rejected_value_not_grounded_in_current_proof")
                pending_rejection = (
                    event.event_id,
                    event.payload,
                    matches[0].proof_requirement_id,
                )
                continue
            if isinstance(event.payload, EngagementReopenedPayload):
                current = ObjectiveProgress(
                    requirements=tuple(proof_by_id[key] for key in sorted(proof_by_id))
                )
                if event.payload.proof_revalidation == "retain_rejections":
                    if pending_rejection is None:
                        raise ValueError("proof_rejection_pair_incomplete")
                    rejection_event_id, rejection, requirement_id = pending_rejection
                    progress = proof_by_id[requirement_id]
                    record = ProofRejectionRecord(
                        proof_requirement_id=requirement_id,
                        assessment_generation=progress.assessment_generation,
                        rejection_event_id=rejection_event_id,
                        rejected_proof_event_id=rejection.flag_event_id,
                        rejected_value_sha256=rejection.rejected_value_sha256,
                    )
                    rejection_records[requirement_id].append(record)
                    objective = transition_proof_generation(
                        current,
                        policy="retain_rejections",
                        transition_event_id=event.event_id,
                        rejected_requirement_id=requirement_id,
                        rejection_event_id=rejection_event_id,
                        rejected_value_sha256=rejection.rejected_value_sha256,
                    )
                    records = rejection_records[requirement_id]
                    ordered_digests = tuple(
                        dict.fromkeys(item.rejected_value_sha256 for item in records)
                    )
                    overflow_count = max(0, len(ordered_digests) - 32)
                    overflow_digest = (
                        sha256(
                            _canonical_bytes(
                                [item.model_dump(mode="json") for item in records[:overflow_count]]
                            )
                        ).hexdigest()
                        if overflow_count
                        else _EMPTY_DIGEST
                    )
                    selected = next(
                        item
                        for item in objective.requirements
                        if item.proof_requirement_id == requirement_id
                    )
                    selected = ProofProgress.model_validate(
                        selected.model_copy(
                            update={
                                "rejected_value_sha256s": ordered_digests[-32:],
                                "rejected_value_overflow_count": overflow_count,
                                "rejected_value_overflow_digest": overflow_digest,
                            }
                        ).model_dump(mode="python")
                    )
                    objective = ObjectiveProgress(
                        requirements=tuple(
                            selected if item.proof_requirement_id == requirement_id else item
                            for item in objective.requirements
                        )
                    )
                    pending_rejection = None
                else:
                    if pending_rejection is not None:
                        raise ValueError("proof_rejection_pair_incomplete")
                    objective = transition_proof_generation(
                        current,
                        policy="invalidate_all",
                        transition_event_id=event.event_id,
                    )
                proof_by_id = {item.proof_requirement_id: item for item in objective.requirements}
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, ResearchSourceAssessedEventPayload):
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                if event.payload.consulted_event_id not in prior_event_ids or not set(
                    event.payload.related_event_ids
                ).issubset(prior_event_ids):
                    raise ValueError("research_assessment_grounding_not_authoritative")
                research_sources.append(
                    ResearchSourceAssessment(
                        event_ids=(event.event_id,),
                        source_id=event.payload.source_id,
                        assessment={
                            "useful": "useful",
                            "ambiguous": "inconclusive",
                            "contradicted": "not_useful",
                            "stale": "not_useful",
                            "irrelevant": "not_useful",
                        }[event.payload.assessment],
                    )
                )
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, OutcomeAssessedEventPayload):
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                required_ids = set(event.payload.source_event_ids) | {
                    event.payload.attachment_event_id,
                    event.payload.terminal_tool_event_id,
                }
                if not required_ids.issubset(prior_event_ids):
                    raise ValueError("outcome_grounding_not_authoritative")
                attempts.append(
                    AttemptSummary(
                        event_ids=(event.event_id,),
                        attempt_event_id=event.payload.terminal_tool_event_id,
                        outcome=event.payload.category,
                        summary=event.payload.summary,
                    )
                )
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, HypothesisFormedEventPayload):
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                cited_ids = set(event.payload.supporting_event_ids) | set(
                    event.payload.contradicting_event_ids
                )
                if not cited_ids.issubset(prior_event_ids):
                    raise ValueError("hypothesis_grounding_not_authoritative")
                hypotheses.append(
                    SituationHypothesis(
                        event_ids=(event.event_id,),
                        text=event.payload.statement,
                        confidence=event.payload.confidence,
                    )
                )
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, MissingInformationIdentifiedEventPayload):
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                if not set(event.payload.related_event_ids).issubset(prior_event_ids):
                    raise ValueError("missing_information_grounding_not_authoritative")
                unresolved_information.append(
                    UnresolvedInformation(
                        event_ids=(event.event_id,),
                        question=event.payload.question,
                    )
                )
                material_event_revision = event.sequence
                continue
            if isinstance(event.payload, ObjectiveProofObservedEventPayload):
                proof = proof_by_id.get(event.payload.proof_requirement_id)
                if proof is None:
                    raise ValueError("proof_requirement_not_in_manifest")
                if event.payload.assessment_generation != proof.assessment_generation:
                    raise ValueError("proof_assessment_generation_mismatch")
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                if not set(event.payload.source_event_ids).issubset(prior_event_ids):
                    raise ValueError("proof_grounding_not_authoritative")
                candidate = event.payload.candidate_value
                if proof_value_was_rejected(
                    proof,
                    candidate_value_sha256=candidate.value_sha256,
                    authoritative_rejections=rejection_records[event.payload.proof_requirement_id],
                ):
                    raise ValueError("proof_value_previously_rejected")
                attachment = attached_evidence.get(candidate.evidence_slice.evidence_id)
                if attachment is None:
                    raise ValueError("proof_evidence_not_attached")
                reference = attachment.evidence
                if (
                    candidate.evidence_slice.end > reference.size
                    or candidate.evidence_slice.media_type != reference.media_type
                    or candidate.evidence_slice.end <= candidate.evidence_slice.start
                    or candidate.value_sha256 != candidate.evidence_slice.sha256
                ):
                    raise ValueError("proof_evidence_slice_mismatch")
                value_reference = ProofValueReference(
                    proof_event_id=event.event_id,
                    proof_requirement_id=event.payload.proof_requirement_id,
                    assessment_generation=event.payload.assessment_generation,
                    assessment=event.payload.assessment,
                    evidence_id=candidate.evidence_slice.evidence_id,
                    candidate_start=candidate.evidence_slice.start,
                    candidate_end=candidate.evidence_slice.end,
                    value_sha256=candidate.value_sha256,
                )
                supporting = (
                    tuple(sorted((*proof.supporting_event_ids, event.event_id), key=str))
                    if event.payload.assessment == "supported"
                    else proof.supporting_event_ids
                )
                contradicting = (
                    tuple(sorted((*proof.contradicting_event_ids, event.event_id), key=str))
                    if event.payload.assessment == "contradicted"
                    else proof.contradicting_event_ids
                )
                proof_by_id[event.payload.proof_requirement_id] = proof.model_copy(
                    update={
                        "status": event.payload.assessment,
                        "supporting_event_ids": supporting,
                        "contradicting_event_ids": contradicting,
                        "value_references": (*proof.value_references, value_reference),
                    }
                )
                proof_by_id[event.payload.proof_requirement_id] = ProofProgress.model_validate(
                    proof_by_id[event.payload.proof_requirement_id].model_dump(mode="python")
                )
                material_event_revision = event.sequence
                continue
            if not isinstance(event.payload, ObservationExtractedEventPayload):
                continue
            for evidence_slice in event.payload.evidence_slices:
                attachment = attached_evidence.get(evidence_slice.evidence_id)
                if attachment is None:
                    raise ValueError("observation_evidence_not_attached")
                reference = attachment.evidence
                if (
                    evidence_slice.end > reference.size
                    or evidence_slice.media_type != reference.media_type
                    or evidence_slice.end <= evidence_slice.start
                ):
                    raise ValueError("observation_evidence_slice_mismatch")
            observation = event.payload.observation
            if isinstance(observation, TextFactEventRecord):
                facts.append(
                    ObservedFact(
                        event_ids=(event.event_id,),
                        text=observation.value,
                    )
                )
            elif isinstance(observation, FacetObservationEventRecord):
                facets.append(
                    ObservedFacet(
                        event_ids=(event.event_id,),
                        key=observation.key,
                        value=observation.value,
                    )
                )
            elif isinstance(observation, AccessStateDeltaEventRecord):
                if observation.scope_reference_id not in valid_scope_ids:
                    raise ValueError("observation_scope_not_in_manifest")
                access_states.append(
                    AccessState(
                        event_ids=(event.event_id,),
                        subject=f"{observation.scope_reference_id}/{observation.access_kind}",
                        state=observation.transition,
                    )
                )
            elif isinstance(observation, SecretReferenceEventRecord):
                if not set(observation.scope_reference_ids).issubset(valid_scope_ids):
                    raise ValueError("observation_scope_not_in_manifest")
                secret_references.append(
                    SecretReference(
                        event_ids=(event.event_id,),
                        label=observation.label,
                        evidence_id=observation.value.evidence_slice.evidence_id,
                        candidate_start=observation.value.evidence_slice.start,
                        candidate_end=observation.value.evidence_slice.end,
                        value_sha256=observation.value.value_sha256,
                    )
                )
            elif isinstance(observation, IncompatibilityObservationEventRecord):
                prior_event_ids = {item.event_id for item in validated.events[: event.sequence - 1]}
                if not set(observation.scope_reference_ids).issubset(valid_scope_ids) or not set(
                    observation.event_refs
                ).issubset(prior_event_ids):
                    raise ValueError("incompatibility_grounding_not_authoritative")
                incompatibilities.append(
                    Incompatibility(
                        event_ids=(event.event_id,),
                        subject=observation.subject_ref,
                        explanation=observation.reason,
                    )
                )
            else:
                continue
            material_event_revision = event.sequence
        if pending_rejection is not None:
            raise ValueError("proof_rejection_pair_incomplete")
        interpretations: list[EvidenceInterpretationState] = []
        for subject_key in sorted(
            interpretation_events, key=lambda item: (str(item[0]), str(item[1]), item[2])
        ):
            attachment_id, terminal_tool_id, evidence_id = subject_key
            attachment = attachments_by_event_id.get(attachment_id)
            if attachment is None:
                raise ValueError("interpretation_subject_not_authoritative")
            cursor = 0
            for start, end in sorted(interpretation_coverage.get(subject_key, ())):
                if start > cursor:
                    break
                cursor = max(cursor, end)
            complete = cursor >= attachment.evidence.size and not interpretation_failure.get(
                subject_key
            )
            # Unsupported media is the only terminal failure; a retryable failure stays nonterminal.
            if interpretation_failure.get(subject_key) and not interpretation_coverage.get(
                subject_key
            ):
                status = "failed"
            else:
                status = "completed" if complete else "pending"
            interpretations.append(
                EvidenceInterpretationState(
                    event_ids=tuple(sorted(interpretation_events[subject_key], key=str)),
                    subject=InterpretationSubject(
                        attachment_event_id=attachment_id,
                        terminal_tool_event_id=terminal_tool_id,
                        evidence_id=evidence_id,
                    ),
                    status=status,
                )
            )
        objective_progress = ObjectiveProgress(
            requirements=tuple(proof_by_id[key] for key in sorted(proof_by_id))
        )
        hypothesis_beliefs = project_hypothesis_beliefs(tuple(hypotheses), validated.events)
        material_state = {
            "objective_progress": objective_progress.model_dump(mode="json"),
            "facts": [fact.model_dump(mode="json") for fact in facts[-MAX_SITUATION_ITEMS:]],
            "facets": [facet.model_dump(mode="json") for facet in facets[-MAX_SITUATION_ITEMS:]],
            "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
            "hypothesis_beliefs": [item.model_dump(mode="json") for item in hypothesis_beliefs],
            "unresolved_information": [
                item.model_dump(mode="json") for item in unresolved_information
            ],
            "research_sources": [item.model_dump(mode="json") for item in research_sources],
            "access_states": [item.model_dump(mode="json") for item in access_states],
            "interpretations": [item.model_dump(mode="json") for item in interpretations],
            "secret_references": [item.model_dump(mode="json") for item in secret_references],
            "available_credentials": [
                {
                    "label": item.label,
                    "secret_kind": getattr(item, "secret_kind", "other"),
                }
                for item in secret_references
            ],
            "attempts": [item.model_dump(mode="json") for item in attempts],
            "incompatibilities": [item.model_dump(mode="json") for item in incompatibilities],
        }
        return SituationProjection(
            engagement_id=validated.engagement_id,
            authoritative_journal_revision=validated.revision,
            material_event_revision=material_event_revision,
            state_digest=sha256(_canonical_bytes(material_state)).hexdigest(),
            objective_progress=objective_progress,
            # Retention is bounded by the projection schema; the journal remains
            # the complete record. Keep the MOST RECENT items so the planner still
            # sees current knowledge instead of failing on tuple overflow.
            facts=tuple(facts[-MAX_SITUATION_ITEMS:]),
            facets=tuple(facets[-MAX_SITUATION_ITEMS:]),
            hypotheses=tuple(hypotheses),
            hypothesis_beliefs=hypothesis_beliefs,
            unresolved_information=tuple(unresolved_information),
            research_sources=tuple(research_sources),
            access_states=tuple(access_states),
            interpretations=tuple(interpretations),
            secret_references=tuple(secret_references),
            available_credentials=tuple(
                AvailableCredential(
                    event_ids=item.event_ids,
                    label=item.label,
                    secret_kind=getattr(item, "secret_kind", "other"),
                )
                for item in secret_references
            ),
            attempts=tuple(attempts),
            incompatibilities=tuple(incompatibilities),
        )
