"""Pure closed conversion of planning source records into journal payloads."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from hashlib import sha256
from typing import cast
from uuid import UUID

from pydantic import BaseModel, TypeAdapter

from sedna.engagement import (
    EventPayload,
    FrontierCriticizedEventPayload,
    FrontierProposedEventPayload,
    FrontierRejectedEventPayload,
    FrontierRepairedEventPayload,
    HypothesisFormedEventPayload,
    InterpretationFailedEventPayload,
    InterpretationSucceededEventPayload,
    MissingInformationIdentifiedEventPayload,
    ObjectiveProofObservedEventPayload,
    ObservationExtractedEventPayload,
    OutcomeAssessedEventPayload,
    PlanningGapRecordedEventPayload,
    PlanRequestedEventPayload,
    ResearchQueryProposedEventPayload,
    ResearchSourceAssessedEventPayload,
    ResearchSourceConsultedEventPayload,
    StrategyArchivedEventPayload,
    StrategyReactivatedEventPayload,
    StrategyReconciledEventPayload,
)
from sedna.engagement.events import (
    FrontierProposalEventRecord,
    PlanningCallMetadataEventRecord,
)
from sedna.planning.models import (
    MAX_PLANNING_EVENT_BATCH,
    MAX_PLANNING_PAYLOAD_BYTES,
    FrontierCriticizedSource,
    FrontierProposedSource,
    FrontierRejectedSource,
    FrontierRepairedSource,
    HypothesisFormedSource,
    InterpretationFailedSource,
    InterpretationSucceededSource,
    MissingInformationIdentifiedSource,
    ObjectiveProofObservedSource,
    ObservationEventConversion,
    ObservationExtractedSource,
    OutcomeAssessedSource,
    PlanningAttemptEventConversion,
    PlanningEventSource,
    PlanningGapRecordedSource,
    PlanRequestedSource,
    ResearchEventConversion,
    ResearchQueryProposedSource,
    ResearchSourceAssessedSource,
    ResearchSourceConsultedSource,
    StrategyArchivedSource,
    StrategyReactivatedSource,
    StrategyReconciledSource,
    StrategyReconciliationEventConversion,
    _ConversionEnvelope,
)

_EVENT_PAYLOAD_ADAPTER = TypeAdapter(EventPayload)


def _canonical_bytes(value: BaseModel | object, *, exclude: set[str] | None = None) -> bytes:
    if isinstance(value, BaseModel):
        data = value.model_dump(mode="json", exclude=exclude or set(), warnings="error")
    else:
        data = value
    return json.dumps(
        data,
        allow_nan=False,
        default=str,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: BaseModel | object, *, exclude: set[str] | None = None) -> str:
    return sha256(_canonical_bytes(value, exclude=exclude)).hexdigest()


def _call_metadata(conversion: _ConversionEnvelope) -> PlanningCallMetadataEventRecord:
    metadata = cast(object, conversion.call_metadata)
    if not isinstance(metadata, BaseModel):
        raise TypeError("conversion call metadata must be a typed model")
    return PlanningCallMetadataEventRecord.model_validate(
        metadata.model_dump(mode="json", warnings="error")
    )


def _source_digest(source: PlanningEventSource) -> str:
    return _digest(source, exclude={"local_id"})


def _archive_digest(source: StrategyArchivedSource) -> str:
    return _digest(source.archive_record, exclude={"archive_entry_digest"})


def _planner_draft_contains_proposal(
    conversion: PlanningAttemptEventConversion,
    source_proposal: FrontierProposalEventRecord,
) -> bool:
    if conversion.planner_draft is None:
        return False
    return any(
        draft.title == source_proposal.title
        and draft.score == source_proposal.score
        and draft.confidence == round(source_proposal.confidence * 100)
        and draft.rationale == source_proposal.rationale
        for draft in conversion.planner_draft.proposals
    )


def _reconciliation_digest(conversion: _ConversionEnvelope) -> str:
    items = tuple(
        {
            "operation": source.operation.model_dump(mode="json", warnings="error"),
            "resulting_snapshot": source.resulting_snapshot.model_dump(
                mode="json", warnings="error"
            ),
        }
        for source in conversion.sources
        if isinstance(source, StrategyReconciledSource)
    )
    return _digest(items)


def _payload_from_observation(
    source: PlanningEventSource, conversion: _ConversionEnvelope
) -> EventPayload:
    input_digest = _call_metadata(conversion).input_digest
    if isinstance(source, ObservationExtractedSource):
        return ObservationExtractedEventPayload(
            summary=source.summary,
            observation=source.observation,
            confidence=source.confidence,
            evidence_slices=source.evidence_slices,
            scope_reference_ids=source.scope_reference_ids,
            interpretation_input_digest=input_digest,
        )
    if isinstance(source, HypothesisFormedSource):
        return HypothesisFormedEventPayload(
            statement=source.statement,
            confidence=source.confidence,
            supporting_event_ids=source.supporting_event_ids,
            contradicting_event_ids=source.contradicting_event_ids,
            scope_reference_ids=source.scope_reference_ids,
            interpretation_input_digest=input_digest,
        )
    if isinstance(source, MissingInformationIdentifiedSource):
        return MissingInformationIdentifiedEventPayload(
            question=source.question,
            reason=source.reason,
            importance=source.importance,
            related_event_ids=source.related_event_ids,
            scope_reference_ids=source.scope_reference_ids,
            interpretation_input_digest=input_digest,
        )
    if isinstance(source, OutcomeAssessedSource):
        return OutcomeAssessedEventPayload(
            attachment_event_id=source.attachment_event_id,
            terminal_tool_event_id=source.terminal_tool_event_id,
            decision_id=source.decision_id,
            tool_call_ids=source.tool_call_ids,
            category=source.category,
            summary=source.summary,
            strategic_impact=source.strategic_impact,
            evidence_ids=source.evidence_ids,
            source_event_ids=source.source_event_ids,
            interpretation_input_digest=input_digest,
        )
    if isinstance(source, ObjectiveProofObservedSource):
        return ObjectiveProofObservedEventPayload(
            proof_requirement_id=source.proof_requirement_id,
            assessment_generation=source.assessment_generation,
            assessment=source.assessment,
            candidate_value=source.candidate_value,
            confidence=source.confidence,
            evidence_ids=source.evidence_ids,
            source_event_ids=source.source_event_ids,
            interpretation_input_digest=input_digest,
        )
    if isinstance(source, InterpretationSucceededSource):
        return InterpretationSucceededEventPayload(
            interpretation_id=source.interpretation_id,
            attachment_event_id=source.attachment_event_id,
            terminal_tool_event_id=source.terminal_tool_event_id,
            evidence_id=source.evidence_id,
            covered_slices=source.covered_slices,
            emitted_event_ids=source.emitted_event_ids,
            call_metadata=_call_metadata(conversion),
            call_input_digest=input_digest,
            call_output_digest=_source_digest(source),
        )
    if isinstance(source, InterpretationFailedSource):
        return InterpretationFailedEventPayload(
            interpretation_id=source.interpretation_id,
            attachment_event_id=source.attachment_event_id,
            terminal_tool_event_id=source.terminal_tool_event_id,
            evidence_id=source.evidence_id,
            attempted_slices=source.attempted_slices,
            failure_code=source.failure_code,
            retryable=source.retryable,
            safe_summary=source.safe_summary,
            call_metadata=(
                None if source.failure_code == "unsupported_media" else _call_metadata(conversion)
            ),
            call_input_digest=input_digest,
        )
    raise TypeError(f"unsupported observation source: {source.kind}")


def _payload_from_planning(
    source: PlanningEventSource, conversion: _ConversionEnvelope
) -> EventPayload:
    metadata = _call_metadata(conversion)
    if isinstance(source, PlanRequestedSource):
        fields = {
            "request_id": source.request_id,
            "lane_key": source.lane_key,
            "situation_digest": source.situation_digest,
            "material_event_revision": source.material_event_revision,
            "input_ledger_digest": source.input_ledger_digest,
            "canonical_revision": source.canonical_revision,
            "source_registry_digest": source.source_registry_digest,
            "max_proposals": source.max_proposals,
            "hindsight_candidate_ids": source.hindsight_candidate_ids,
            "hindsight_query_digests": source.hindsight_query_digests,
        }
        return PlanRequestedEventPayload(
            **fields,
            request_digest=_digest(
                {
                    "request_id": str(source.request_id),
                    "lane_key": source.lane_key,
                    "situation_digest": source.situation_digest,
                    "material_event_revision": source.material_event_revision.model_dump(
                        mode="json", warnings="error"
                    ),
                    "input_ledger_digest": source.input_ledger_digest,
                    "canonical_revision": source.canonical_revision,
                    "source_registry_digest": source.source_registry_digest,
                    "max_proposals": source.max_proposals,
                    "hindsight_candidate_ids": list(source.hindsight_candidate_ids),
                    "hindsight_query_digests": list(source.hindsight_query_digests),
                }
            ),
        )
    if isinstance(source, FrontierProposedSource):
        assert isinstance(conversion, PlanningAttemptEventConversion)
        return FrontierProposedEventPayload(
            request_id=source.request_id,
            frontier_id=source.frontier_id,
            proposal_ordinal=source.proposal_ordinal,
            proposal_count=source.proposal_count,
            proposal=source.proposal,
            situation_digest=source.situation_digest,
            input_ledger_digest=source.input_ledger_digest,
            knowledge_context_digest=source.knowledge_context_digest,
            draft_digest=_digest(conversion.planner_draft),
            call_metadata=metadata,
            planner_call_digest=_digest(metadata),
        )
    if isinstance(source, FrontierCriticizedSource):
        return FrontierCriticizedEventPayload(
            request_id=source.request_id,
            frontier_id=source.frontier_id,
            critic_pass=source.critic_pass,
            accepted=source.accepted,
            finding_codes=source.finding_codes,
            cited_event_ids=source.cited_event_ids,
            call_metadata=metadata,
            call_input_digest=metadata.input_digest,
            call_output_digest=_source_digest(source),
        )
    if isinstance(source, FrontierRepairedSource):
        assert isinstance(conversion, PlanningAttemptEventConversion)
        return FrontierRepairedEventPayload(
            request_id=source.request_id,
            frontier_id=source.frontier_id,
            critic_event_id=source.critic_event_id,
            proposal_ordinal=source.proposal_ordinal,
            proposal_count=source.proposal_count,
            proposal=source.proposal,
            repaired_draft_digest=_digest(conversion.planner_draft),
            call_metadata=metadata,
            call_input_digest=metadata.input_digest,
            call_output_digest=_source_digest(source),
        )
    if isinstance(source, FrontierRejectedSource):
        return FrontierRejectedEventPayload(
            request_id=source.request_id,
            frontier_id=source.frontier_id,
            critic_event_ids=source.critic_event_ids,
            reason_codes=source.reason_codes,
            rejected_draft_digest=_source_digest(source),
        )
    if isinstance(source, PlanningGapRecordedSource):
        return PlanningGapRecordedEventPayload(
            request_id=source.request_id,
            code=source.code,
            summary=source.summary,
            retryable=source.retryable,
            situation_digest=source.situation_digest,
            ledger_digest=source.ledger_digest,
            related_event_ids=source.related_event_ids,
        )
    raise TypeError(f"unsupported planning source: {source.kind}")


def _payload_from_reconciliation(
    source: PlanningEventSource, conversion: _ConversionEnvelope
) -> EventPayload:
    if isinstance(source, StrategyReconciledSource):
        return StrategyReconciledEventPayload(
            request_id=source.request_id,
            frontier_id=source.frontier_id,
            reconciliation_id=source.reconciliation_id,
            item_ordinal=source.item_ordinal,
            item_count=source.item_count,
            input_ledger_digest=source.input_ledger_digest,
            resulting_ledger_digest=source.resulting_ledger_digest,
            operation=source.operation,
            resulting_snapshot=source.resulting_snapshot,
            reconciliation_digest=_reconciliation_digest(conversion),
        )
    if isinstance(source, StrategyArchivedSource):
        expected_digest = _archive_digest(source)
        if source.archive_record.archive_entry_digest != expected_digest:
            raise ValueError("archive_entry_digest_mismatch")
        return StrategyArchivedEventPayload(
            request_id=source.request_id,
            archive_batch_id=source.archive_batch_id,
            entry_ordinal=source.entry_ordinal,
            entry_count=source.entry_count,
            archive_record=source.archive_record,
            resulting_archive_digest=source.resulting_archive_digest,
        )
    if isinstance(source, StrategyReactivatedSource):
        return StrategyReactivatedEventPayload(
            request_id=source.request_id,
            reactivation_batch_id=source.reactivation_batch_id,
            entry_ordinal=source.entry_ordinal,
            entry_count=source.entry_count,
            source_archive_event_id=source.source_archive_event_id,
            triggering_event_ids=source.triggering_event_ids,
            matched_predicate_ids=source.matched_predicate_ids,
            prior_archive_entry_digest=source.prior_archive_entry_digest,
            resulting_archive_digest=source.resulting_archive_digest,
            restored_snapshot=source.restored_snapshot,
        )
    raise TypeError(f"unsupported reconciliation source: {source.kind}")


def _payload_from_research(
    source: PlanningEventSource, conversion: _ConversionEnvelope
) -> EventPayload:
    if isinstance(source, ResearchQueryProposedSource):
        return ResearchQueryProposedEventPayload(
            query_id=source.query_id,
            normalized_query=source.normalized_query,
            query_digest=sha256(source.normalized_query.encode("utf-8")).hexdigest(),
            policy_decision=source.policy_decision,
            policy_version=source.policy_version,
            reason_codes=source.reason_codes,
            related_event_ids=source.related_event_ids,
            candidate_source_ids=source.candidate_source_ids,
        )
    if isinstance(source, ResearchSourceConsultedSource):
        return ResearchSourceConsultedEventPayload(
            query_id=source.query_id,
            source_id=source.source_id,
            normalized_locator=source.normalized_locator,
            locator_digest=sha256(source.normalized_locator.encode("utf-8")).hexdigest(),
            content_digest=sha256(source.content).hexdigest(),
            media_type=source.media_type,
            evidence_ids=source.evidence_ids,
            tool_event_ids=source.tool_event_ids,
        )
    if isinstance(source, ResearchSourceAssessedSource):
        fields = {
            "query_id": source.query_id,
            "source_id": source.source_id,
            "consulted_event_id": source.consulted_event_id,
            "assessment": source.assessment,
            "confidence": source.confidence,
            "summary": source.summary,
            "related_event_ids": source.related_event_ids,
            "suggested_registry_status": source.suggested_registry_status,
        }
        return ResearchSourceAssessedEventPayload(
            **fields,
            assessment_digest=_digest(fields),
        )
    raise TypeError(f"unsupported research source: {source.kind}")


_DISPATCH: dict[str, Callable[[PlanningEventSource, _ConversionEnvelope], EventPayload]] = {
    "observation_extracted": _payload_from_observation,
    "hypothesis_formed": _payload_from_observation,
    "missing_information_identified": _payload_from_observation,
    "outcome_assessed": _payload_from_observation,
    "objective_proof_observed": _payload_from_observation,
    "interpretation_succeeded": _payload_from_observation,
    "interpretation_failed": _payload_from_observation,
    "plan_requested": _payload_from_planning,
    "frontier_proposed": _payload_from_planning,
    "frontier_criticized": _payload_from_planning,
    "frontier_repaired": _payload_from_planning,
    "frontier_rejected": _payload_from_planning,
    "planning_gap_recorded": _payload_from_planning,
    "strategy_reconciled": _payload_from_reconciliation,
    "strategy_archived": _payload_from_reconciliation,
    "strategy_reactivated": _payload_from_reconciliation,
    "research_query_proposed": _payload_from_research,
    "research_source_consulted": _payload_from_research,
    "research_source_assessed": _payload_from_research,
}


def _walk(value: object) -> Iterable[tuple[str, object]]:
    if isinstance(value, BaseModel):
        yield from _walk(value.model_dump(mode="python", warnings="error"))
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _walk(item)
    elif isinstance(value, tuple | list):
        for item in value:
            yield from _walk(item)


def _evidence_slice_dicts(value: object) -> Iterable[dict[str, object]]:
    if isinstance(value, BaseModel):
        yield from _evidence_slice_dicts(value.model_dump(mode="python", warnings="error"))
    elif isinstance(value, dict):
        if {"evidence_id", "start", "end", "sha256", "media_type"}.issubset(value):
            yield value
        for item in value.values():
            yield from _evidence_slice_dicts(item)
    elif isinstance(value, tuple | list):
        for item in value:
            yield from _evidence_slice_dicts(item)


_EVENT_REF_FIELDS = frozenset(
    {
        "attachment_event_id",
        "terminal_tool_event_id",
        "source_event_ids",
        "supporting_event_ids",
        "contradicting_event_ids",
        "related_event_ids",
        "emitted_event_ids",
        "critic_event_id",
        "critic_event_ids",
        "cited_event_ids",
        "evidence_event_ids",
        "tool_event_ids",
        "source_reconciliation_event_id",
        "source_archive_event_id",
        "triggering_event_ids",
        "consulted_event_id",
        "event_refs",
    }
)
_EVIDENCE_REF_FIELDS = frozenset({"evidence_id", "evidence_ids"})


def _referenced_event_ids(value: object) -> set[UUID]:
    """Collect UUIDs the model places in event-reference fields.

    Event-reference fields are the closed vocabulary the converters use for
    journal provenance. This walks one conversion's sources and payloads the
    same way the reference validator does, so scoping an index and validating
    it can never disagree about what counts as a reference.
    """
    referenced: set[UUID] = set()
    for name, item in _walk(value):
        if name not in _EVENT_REF_FIELDS:
            continue
        values = item if isinstance(item, tuple | list) else (item,)
        for candidate in values:
            if isinstance(candidate, UUID):
                referenced.add(candidate)
            elif isinstance(candidate, str):
                try:
                    referenced.add(UUID(candidate))
                except ValueError:
                    continue
    return referenced


def _validate_references(payload: EventPayload, conversion: _ConversionEnvelope) -> None:
    valid_events = set(conversion.valid_event_ids)
    valid_evidence = set(conversion.valid_evidence_ids)
    valid_scopes = set(conversion.valid_scope_reference_ids)
    valid_sources = set(conversion.valid_source_ids)
    valid_knowledge = set(conversion.valid_knowledge_ids)
    for name, value in _walk(payload):
        values = tuple(
            item
            for item in (value if isinstance(value, tuple | list) else (value,))
            if item is not None
        )
        if name in _EVENT_REF_FIELDS and not set(values).issubset(valid_events):
            raise ValueError("event_reference_not_in_index")
        if name in _EVIDENCE_REF_FIELDS and not set(values).issubset(valid_evidence):
            raise ValueError("evidence_reference_not_in_index")
        if name == "scope_reference_ids" and not set(values).issubset(valid_scopes):
            raise ValueError("scope_reference_not_in_index")
        if name in {"source_id", "candidate_source_ids"} and not set(values).issubset(
            valid_sources
        ):
            raise ValueError("source_reference_not_in_index")
        if name == "knowledge_refs" and not set(values).issubset(valid_knowledge):
            raise ValueError("knowledge_reference_not_in_index")

    for value in _evidence_slice_dicts(payload):
        matching = [
            evidence_slice
            for evidence_slice in conversion.evidence_slices
            if evidence_slice.evidence_id == value["evidence_id"]
            and evidence_slice.start <= value["start"]
            and value["end"] <= evidence_slice.end
        ]
        if len(matching) != 1:
            raise ValueError("reference_validation_failed")
        slice_input = matching[0]
        start = value["start"] - slice_input.start
        end = value["end"] - slice_input.start
        candidate = slice_input.content[start:end]
        if sha256(candidate).hexdigest() != value["sha256"]:
            raise ValueError("reference_validation_failed")


def _validate_source_indexes(source: PlanningEventSource, conversion: _ConversionEnvelope) -> None:
    """Validate source-only identities before they can become journal facts."""
    if isinstance(source, ObjectiveProofObservedSource):
        proof_key = (source.proof_requirement_id, source.assessment_generation)
        indexed = {
            (item.proof_requirement_id, item.assessment_generation)
            for item in conversion.valid_proof_indexes
        }
        if proof_key not in indexed:
            raise ValueError("proof_requirement_not_in_index")
        admissions = tuple(
            item
            for item in conversion.proof_candidate_admissions
            if (item.proof_requirement_id, item.assessment_generation) == proof_key
            and item.candidate_sha256 == source.candidate_value.value_sha256
        )
        if len(admissions) != 1:
            raise ValueError("proof_candidate_admission_not_in_index")
        if admissions[0].decision != "allowed":
            raise ValueError("previously_rejected_proof_value")

    if isinstance(source, (FrontierProposedSource, FrontierRepairedSource)):
        if source.proposal.proposal_id not in conversion.valid_proposal_ids:
            raise ValueError("proposal_reference_not_in_index")
        if source.proposal.family_id not in conversion.valid_family_ids:
            raise ValueError("family_reference_not_in_index")
        if (
            source.proposal.variant_id is not None
            and source.proposal.variant_id not in conversion.valid_variant_ids
        ):
            raise ValueError("variant_reference_not_in_index")

    if (
        isinstance(source, StrategyReconciledSource)
        and source.operation.family_id not in conversion.valid_family_ids
    ):
        raise ValueError("family_reference_not_in_index")
    if isinstance(source, (StrategyArchivedSource, StrategyReactivatedSource)):
        snapshot = (
            source.archive_record.snapshot
            if isinstance(source, StrategyArchivedSource)
            else source.restored_snapshot
        )
        if (
            snapshot.record_kind == "strategy_family"
            and snapshot.family_id not in conversion.valid_family_ids
        ):
            raise ValueError("family_reference_not_in_index")
        if (
            snapshot.record_kind == "execution_variant"
            and snapshot.variant_id not in conversion.valid_variant_ids
        ):
            raise ValueError("variant_reference_not_in_index")


def _validated_payloads(
    conversion: _ConversionEnvelope,
    payloads: tuple[EventPayload, ...],
) -> tuple[EventPayload, ...]:
    if len(payloads) > MAX_PLANNING_EVENT_BATCH:
        raise ValueError("planning event batch exceeds its bound")
    result: list[EventPayload] = []
    for payload in payloads:
        _validate_references(payload, conversion)
        encoded = _canonical_bytes(payload)
        if len(encoded) > MAX_PLANNING_PAYLOAD_BYTES:
            raise ValueError("journal_payload_too_large")
        result.append(_EVENT_PAYLOAD_ADAPTER.validate_json(encoded))
    return tuple(result)


def _source_is_represented_by_authoritative_model(
    source: PlanningEventSource, conversion: _ConversionEnvelope
) -> bool:
    """Keep allocation records non-authoritative.

    The source record only carries pre-allocation and host binding information.  Its
    semantic claim must already be present in the family input before it is allowed
    to become a journal payload.
    """
    if isinstance(conversion, ObservationEventConversion):
        batch = conversion.batch
        if isinstance(source, ObservationExtractedSource):
            redacted_label = source.summary
            for draft in batch.observations:
                if (
                    draft.kind
                    != {
                        "text_fact": "text",
                        "facet": "facet",
                        "access_state_delta": "access",
                        "secret_reference": "secret",
                        "incompatibility": "incompatibility",
                    }[source.observation.record_kind]
                ):
                    continue
                if source.observation.record_kind == "secret_reference":
                    # A secret observation deliberately replaces the model's text
                    # with a redacted summary, so text cannot be compared. Bind it
                    # by EXACT evidence: this conversion is scoped to a single
                    # attached evidence, so the record's evidence must be that very
                    # evidence. An unrelated secret draft (grounded in any other
                    # evidence) cannot represent this source.
                    secret_evidence_id = source.observation.value.evidence_slice.evidence_id
                    if (
                        len(conversion.valid_evidence_ids) == 1
                        and secret_evidence_id == conversion.valid_evidence_ids[0]
                    ):
                        return True
                elif draft.text == redacted_label:
                    return True
            return False
        if isinstance(source, HypothesisFormedSource):
            return any(
                draft.text == source.statement
                and draft.confidence == source.confidence
                and draft.event_ids == source.supporting_event_ids
                for draft in batch.hypotheses
            )
        if isinstance(source, MissingInformationIdentifiedSource):
            return any(
                draft.question == source.question and draft.event_ids == source.related_event_ids
                for draft in batch.missing_information
            )
        if isinstance(source, OutcomeAssessedSource):
            return (
                batch.subject is not None
                and batch.subject.attachment_event_id == source.attachment_event_id
                and batch.subject.terminal_tool_event_id == source.terminal_tool_event_id
                and any(
                    draft.category == source.category
                    and draft.summary == source.summary
                    and draft.event_ids == source.source_event_ids
                    for draft in batch.outcomes
                )
            )
        if isinstance(source, ObjectiveProofObservedSource):
            return any(
                draft.proof_requirement_id == source.proof_requirement_id
                and draft.assessment == source.assessment
                and draft.event_ids == source.source_event_ids
                for draft in batch.objective_proofs
            )
        if isinstance(source, (InterpretationSucceededSource, InterpretationFailedSource)):
            expected_status = (
                "succeeded" if isinstance(source, InterpretationSucceededSource) else "failed"
            )
            return any(
                audit.status == expected_status
                and audit.subject.attachment_event_id == source.attachment_event_id
                and audit.subject.terminal_tool_event_id == source.terminal_tool_event_id
                and audit.subject.evidence_id == source.evidence_id
                for audit in conversion.interpretation_audits
            )
        return False
    if isinstance(conversion, PlanningAttemptEventConversion):
        if isinstance(source, PlanRequestedSource):
            audit = conversion.plan_request_audit
            return (
                audit is not None
                and audit.call_metadata == conversion.call_metadata
                and audit.request_id == source.request_id
                and audit.lane_key == source.lane_key
                and audit.state_digest == source.situation_digest
                and audit.material_event_revision == source.material_event_revision
                and audit.ledger_digest == source.input_ledger_digest
                and audit.canonical_revision == source.canonical_revision
                and audit.source_registry_digest == source.source_registry_digest
                and audit.max_proposals == source.max_proposals
            )
        if isinstance(source, FrontierProposedSource):
            return _planner_draft_contains_proposal(conversion, source.proposal) and any(
                proposal.request_id == source.request_id
                and proposal.frontier_id == source.frontier_id
                and proposal.proposal_ordinal == source.proposal_ordinal
                and proposal.proposal_count == source.proposal_count
                and proposal.proposal == source.proposal
                and proposal.situation_digest == source.situation_digest
                and proposal.input_ledger_digest == source.input_ledger_digest
                and proposal.knowledge_context_digest == source.knowledge_context_digest
                for proposal in conversion.planner_proposals
            )
        if isinstance(source, FrontierCriticizedSource):
            return any(
                verdict.request_id == source.request_id
                and verdict.frontier_id == source.frontier_id
                and verdict.critic_pass == source.critic_pass
                and verdict.accepted == source.accepted
                and tuple(finding.code for finding in verdict.findings) == source.finding_codes
                and verdict.cited_event_ids == source.cited_event_ids
                for verdict in conversion.critic_verdicts
            )
        if isinstance(source, FrontierRepairedSource):
            return _planner_draft_contains_proposal(conversion, source.proposal) and any(
                audit.request_id == source.request_id
                and audit.frontier_id == source.frontier_id
                and audit.critic_event_id == source.critic_event_id
                and audit.proposal_ordinal == source.proposal_ordinal
                and audit.proposal_count == source.proposal_count
                and audit.proposal == source.proposal
                for audit in conversion.repair_audits
            )
        if isinstance(source, FrontierRejectedSource):
            return any(
                audit.call_metadata == conversion.call_metadata
                and audit.request_id == source.request_id
                and audit.frontier_id == source.frontier_id
                and audit.critic_event_ids == source.critic_event_ids
                and audit.reason_codes == source.reason_codes
                for audit in conversion.rejection_audits
            )
        if isinstance(source, PlanningGapRecordedSource):
            return any(
                gap.request_id == source.request_id
                and gap.code == source.code
                and gap.summary == source.summary
                and gap.retryable == source.retryable
                and gap.situation_digest == source.situation_digest
                and gap.ledger_digest == source.ledger_digest
                and gap.related_event_ids == source.related_event_ids
                for gap in conversion.planning_gaps
            )
        return False
    if isinstance(conversion, StrategyReconciliationEventConversion):
        if isinstance(source, StrategyReconciledSource):
            return source.operation.family_id in conversion.reconciliation.input_family_ids and any(
                item.request_id == source.request_id
                and item.frontier_id == source.frontier_id
                and item.reconciliation_id == source.reconciliation_id
                and item.item_ordinal == source.item_ordinal
                and item.item_count == source.item_count
                and item.input_ledger_digest == source.input_ledger_digest
                and item.resulting_ledger_digest == source.resulting_ledger_digest
                and item.operation == source.operation
                and item.resulting_snapshot == source.resulting_snapshot
                for item in conversion.reconciliation.items
            )
        if isinstance(source, StrategyArchivedSource):
            return (
                source.archive_record.snapshot.family_id
                in conversion.reconciliation.input_family_ids
                and any(
                    transition.event_id
                    == next(
                        binding.event_id
                        for binding in conversion.local_event_bindings
                        if binding.local_id == source.local_id
                    )
                    and transition.family_id == source.archive_record.snapshot.family_id
                    and transition.rationale == source.archive_record.archive_reason
                    and transition.request_id == source.request_id
                    and transition.archive_batch_id == source.archive_batch_id
                    and transition.entry_ordinal == source.entry_ordinal
                    and transition.entry_count == source.entry_count
                    and transition.archive_record == source.archive_record
                    and transition.resulting_archive_digest == source.resulting_archive_digest
                    for transition in conversion.archive_transitions
                )
            )
        if isinstance(source, StrategyReactivatedSource):
            return (
                source.restored_snapshot.family_id in conversion.reconciliation.input_family_ids
                and any(
                    transition.event_id
                    == next(
                        binding.event_id
                        for binding in conversion.local_event_bindings
                        if binding.local_id == source.local_id
                    )
                    and transition.family_id == source.restored_snapshot.family_id
                    and transition.request_id == source.request_id
                    and transition.reactivation_batch_id == source.reactivation_batch_id
                    and transition.entry_ordinal == source.entry_ordinal
                    and transition.entry_count == source.entry_count
                    and transition.source_archive_event_id == source.source_archive_event_id
                    and transition.triggering_event_ids == source.triggering_event_ids
                    and transition.matched_predicate_ids == source.matched_predicate_ids
                    and transition.prior_archive_entry_digest == source.prior_archive_entry_digest
                    and transition.resulting_archive_digest == source.resulting_archive_digest
                    and transition.restored_snapshot == source.restored_snapshot
                    for transition in conversion.reactivation_transitions
                )
            )
        return False
    if isinstance(conversion, ResearchEventConversion):
        if isinstance(source, ResearchQueryProposedSource):
            return any(
                decision.query_id == source.query_id
                and decision.normalized_query == source.normalized_query
                and decision.allowed == (source.policy_decision == "allowed")
                and decision.policy_version == source.policy_version
                and decision.reason_codes == source.reason_codes
                and decision.related_event_ids == source.related_event_ids
                and decision.candidate_source_ids == source.candidate_source_ids
                for decision in conversion.policy_decisions
            )
        if isinstance(source, ResearchSourceAssessedSource):
            draft_assessment = {
                "useful": "useful",
                "contradicted": "not_useful",
                "stale": "not_useful",
                "irrelevant": "not_useful",
                "ambiguous": "inconclusive",
            }[source.assessment]
            return any(
                draft.source_id == source.source_id and draft.assessment == draft_assessment
                for draft in conversion.research_sources
            ) and any(
                assessment.query_id == source.query_id
                and assessment.source_id == source.source_id
                and assessment.consulted_event_id == source.consulted_event_id
                and assessment.assessment == source.assessment
                and assessment.confidence == source.confidence
                and assessment.summary == source.summary
                and assessment.related_event_ids == source.related_event_ids
                and assessment.suggested_registry_status == source.suggested_registry_status
                for assessment in conversion.research_assessments
            )
        if isinstance(source, ResearchSourceConsultedSource):
            return any(
                draft.source_id == source.source_id for draft in conversion.research_sources
            ) and any(
                consultation.query_id == source.query_id
                and consultation.source_id == source.source_id
                and consultation.normalized_locator == source.normalized_locator
                and consultation.content == source.content
                and consultation.media_type == source.media_type
                and consultation.evidence_ids == source.evidence_ids
                and consultation.tool_event_ids == source.tool_event_ids
                for consultation in conversion.research_consultations
            )
        return False
    return False


def _convert(conversion: _ConversionEnvelope) -> tuple[EventPayload, ...]:
    if set(_DISPATCH) != {
        "observation_extracted",
        "hypothesis_formed",
        "missing_information_identified",
        "outcome_assessed",
        "objective_proof_observed",
        "interpretation_succeeded",
        "interpretation_failed",
        "plan_requested",
        "frontier_proposed",
        "frontier_criticized",
        "frontier_repaired",
        "frontier_rejected",
        "planning_gap_recorded",
        "strategy_reconciled",
        "strategy_archived",
        "strategy_reactivated",
        "research_query_proposed",
        "research_source_consulted",
        "research_source_assessed",
    }:
        raise RuntimeError("planning_source_dispatch_is_not_closed")
    bindings = {binding.local_id: binding.event_id for binding in conversion.local_event_bindings}
    for source in conversion.sources:
        if (
            source.local_id not in bindings
            or bindings[source.local_id] not in conversion.valid_event_ids
        ):
            raise ValueError("source_local_id_not_preallocated")
        _validate_source_indexes(source, conversion)
        if not _source_is_represented_by_authoritative_model(source, conversion):
            family = (
                "observation source not represented by batch"
                if isinstance(conversion, ObservationEventConversion)
                else "planning source not represented by plan request audit"
                if isinstance(conversion, PlanningAttemptEventConversion)
                else "reconciliation source not represented by reconciliation"
                if isinstance(conversion, StrategyReconciliationEventConversion)
                else "research source not represented by research sources"
            )
            raise ValueError(family)
    payloads = tuple(_DISPATCH[source.kind](source, conversion) for source in conversion.sources)
    return _validated_payloads(conversion, payloads)


def payloads_from_observation_batch(
    conversion: ObservationEventConversion,
) -> tuple[EventPayload, ...]:
    return _convert(conversion)


def payloads_from_planning_attempt(
    conversion: PlanningAttemptEventConversion,
) -> tuple[EventPayload, ...]:
    return _convert(conversion)


def payloads_from_reconciliation(
    conversion: StrategyReconciliationEventConversion,
) -> tuple[EventPayload, ...]:
    return _convert(conversion)


def payloads_from_research_observations(
    conversion: ResearchEventConversion,
) -> tuple[EventPayload, ...]:
    return _convert(conversion)


__all__ = [
    "payloads_from_observation_batch",
    "payloads_from_planning_attempt",
    "payloads_from_reconciliation",
    "payloads_from_research_observations",
]
