# ruff: noqa: E501
"""Deterministic replay and bounded views of the strategy ledger.

The journal is authoritative.  This module never infers a strategy transition from prose or
from situation changes: only complete planning reconciliation/archive/reactivation batches alter
identity or status, while an outcome can add one categorical attempt to its explicitly cited
variant snapshot.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from sedna.engagement import EngagementSnapshot, EventType
from sedna.engagement.events import (
    ArchivedStrategyEventRecord,
    ExecutionVariantEventRecord,
    OutcomeAssessedEventPayload,
    RetryPredicateEventRecord,
    StrategyArchivedEventPayload,
    StrategyFamilyEventRecord,
    StrategyReactivatedEventPayload,
    StrategyReconciledEventPayload,
    StrategyReconciliationEventOperation,
    StrategyResultSnapshot,
    StrategyTombstoneEventRecord,
)
from sedna.planning.models import (
    MAX_ATTEMPTS_PER_VARIANT,
    MAX_HOT_ATTEMPTS,
    ArchivedStrategyState,
    AttemptState,
    ExecutionVariantState,
    SituationProjection,
    StrategyFamilyState,
    StrategyLedger,
    StrategyStatus,
)

MAX_HOT_FAMILIES = 32
MAX_HOT_VARIANTS = 64
MAX_REACTIVATION_CANDIDATES = 16
MAX_ARCHIVE_SUMMARY_BYTES = 16 * 1024

LEDGER_EFFECT_EVENT_TYPES = frozenset(
    {
        EventType.STRATEGY_RECONCILED,
        EventType.STRATEGY_ARCHIVED,
        EventType.STRATEGY_REACTIVATED,
        EventType.OUTCOME_ASSESSED,
    }
)
LEDGER_NO_OP_EVENT_TYPES = frozenset(
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
        EventType.OBJECTIVE_PROOF_OBSERVED,
        EventType.INTERPRETATION_SUCCEEDED,
        EventType.INTERPRETATION_FAILED,
        EventType.PLAN_REQUESTED,
        EventType.FRONTIER_PROPOSED,
        EventType.FRONTIER_CRITICIZED,
        EventType.FRONTIER_REPAIRED,
        EventType.FRONTIER_REJECTED,
        EventType.PLANNING_GAP_RECORDED,
        EventType.RESEARCH_QUERY_PROPOSED,
        EventType.RESEARCH_SOURCE_CONSULTED,
        EventType.RESEARCH_SOURCE_ASSESSED,
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


class LedgerReplayError(ValueError):
    """A planning batch cannot safely reconstruct a complete ledger state."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def ledger_digest(ledger: StrategyLedger) -> str:
    return sha256(_canonical(ledger.model_dump(mode="json", warnings="error"))).hexdigest()


def archive_digest(records: Sequence[ArchivedStrategyEventRecord]) -> str:
    return sha256(
        _canonical([record.model_dump(mode="json", warnings="error") for record in records])
    ).hexdigest()


@dataclass(frozen=True)
class LedgerReplay:
    ledger: StrategyLedger
    archive_records: tuple[ArchivedStrategyEventRecord, ...]
    ledger_sha256: str
    archive_sha256: str


def _attempt_id(payload: OutcomeAssessedEventPayload) -> UUID:
    decision = "" if payload.decision_id is None else str(payload.decision_id)
    return uuid5(
        NAMESPACE_URL, f"sedna-strategy-attempt:{decision}:{','.join(payload.tool_call_ids)}"
    )


def _family_state(record: StrategyFamilyEventRecord) -> StrategyFamilyState:
    return StrategyFamilyState(
        family_id=record.family_id,
        runtime_key=record.stable_key,
        status=record.status,
        variant_ids=tuple(sorted(record.variant_ids, key=str)),
    )


def _variant_state(record: ExecutionVariantEventRecord) -> ExecutionVariantState:
    recent = tuple(
        AttemptState(
            attempt_event_id=attempt_id,
            outcome="ambiguous",
            summary="Authoritative attempt summary retained in journal.",
        )
        for attempt_id in record.attempts.recent_attempt_ids
    )
    return ExecutionVariantState(
        variant_id=record.variant_id,
        family_id=record.family_id,
        runtime_key=record.stable_key,
        status=record.status,
        recent_attempts=recent,
        historical_attempt_count=max(0, record.attempts.total_count - len(recent)),
        outcome_category_totals={
            item.category: item.count for item in record.attempts.outcome_counts
        },
        historical_oldest_revision=(
            record.attempts.first_material_revision
            if record.attempts.total_count > len(recent)
            else None
        ),
        historical_newest_revision=(
            record.attempts.last_material_revision
            if record.attempts.total_count > len(recent)
            else None
        ),
        historical_attempt_digest=record.attempts.history_digest,
    )


def _append_historical_attempt(
    variant: ExecutionVariantState, attempt: AttemptState, revision: dict[str, object]
) -> ExecutionVariantState:
    """Fold one evicted hot attempt into a cumulative, replayable summary."""
    return variant.model_copy(
        update={
            "historical_attempt_count": variant.historical_attempt_count + 1,
            "historical_oldest_revision": variant.historical_oldest_revision or revision,
            "historical_newest_revision": revision,
            "historical_attempt_digest": sha256(
                _canonical(
                    {
                        "prior_digest": variant.historical_attempt_digest,
                        "attempt": attempt.model_dump(mode="json"),
                    }
                )
            ).hexdigest(),
        }
    )


def _ledger(
    families: dict[UUID, StrategyFamilyState],
    variants: dict[UUID, ExecutionVariantState],
    archives: Sequence[tuple[ArchivedStrategyEventRecord, UUID]],
) -> StrategyLedger:
    ordered_families = tuple(
        sorted(families.values(), key=lambda item: (item.runtime_key, str(item.family_id)))
    )
    ordered_variants = tuple(
        sorted(variants.values(), key=lambda item: (item.runtime_key, str(item.variant_id)))
    )
    # The hot ledger keeps summaries for planner candidate selection only; full cold state remains
    # in ``archive_records`` and the M6A paginated archive projection.
    selected: list[ArchivedStrategyState] = []
    used_summary_bytes = 0
    for item, event_id in reversed(archives):
        summary_bytes = len(item.archive_summary.encode("utf-8"))
        if summary_bytes > MAX_ARCHIVE_SUMMARY_BYTES:
            raise LedgerReplayError("strategy archive summary exceeds its aggregate bound")
        if (
            len(selected) >= MAX_REACTIVATION_CANDIDATES
            or used_summary_bytes + summary_bytes > MAX_ARCHIVE_SUMMARY_BYTES
        ):
            continue
        selected.append(
            ArchivedStrategyState(
                family_id=item.snapshot.family_id,
                summary=item.archive_summary,
                archived_event_id=event_id,
            )
        )
        used_summary_bytes += summary_bytes
    summaries = tuple(reversed(selected))
    return StrategyLedger(families=ordered_families, variants=ordered_variants, archive=summaries)


def _validate_hot_identity(
    families: dict[UUID, StrategyFamilyState], variants: dict[UUID, ExecutionVariantState]
) -> None:
    if len(families) > MAX_HOT_FAMILIES or len(variants) > MAX_HOT_VARIANTS:
        raise LedgerReplayError("strategy reconciliation exceeds hot ledger bounds")
    family_keys = [item.runtime_key for item in families.values()]
    variant_keys = [item.runtime_key for item in variants.values()]
    if len(family_keys) != len(set(family_keys)) or len(variant_keys) != len(set(variant_keys)):
        raise LedgerReplayError("strategy reconciliation has duplicate runtime keys")
    for variant in variants.values():
        family = families.get(variant.family_id)
        if family is None or variant.variant_id not in family.variant_ids:
            raise LedgerReplayError("strategy reconciliation has invalid variant ancestry")


def _apply_snapshot(
    snapshot: StrategyResultSnapshot,
    families: dict[UUID, StrategyFamilyState],
    variants: dict[UUID, ExecutionVariantState],
) -> None:
    if isinstance(snapshot, StrategyFamilyEventRecord):
        families[snapshot.family_id] = _family_state(snapshot)
    elif isinstance(snapshot, ExecutionVariantEventRecord):
        variants[snapshot.variant_id] = _variant_state(snapshot)
        family = families.get(snapshot.family_id)
        if family is not None and snapshot.variant_id not in family.variant_ids:
            families[snapshot.family_id] = family.model_copy(
                update={
                    "variant_ids": tuple(
                        sorted((*family.variant_ids, snapshot.variant_id), key=str)
                    )
                }
            )
    elif isinstance(snapshot, StrategyTombstoneEventRecord):
        if snapshot.entity_kind == "family":
            families.pop(snapshot.entity_id, None)
            for variant_id, variant in tuple(variants.items()):
                if variant.family_id == snapshot.entity_id:
                    variants.pop(variant_id)
        else:
            variants.pop(snapshot.entity_id, None)
            for family_id, family in tuple(families.items()):
                if snapshot.entity_id in family.variant_ids:
                    families[family_id] = family.model_copy(
                        update={
                            "variant_ids": tuple(
                                item for item in family.variant_ids if item != snapshot.entity_id
                            )
                        }
                    )
    else:  # pragma: no cover - the discriminated event union is closed
        raise LedgerReplayError("unknown strategy result snapshot")


def _remove_archived_snapshot(
    snapshot: StrategyFamilyEventRecord | ExecutionVariantEventRecord,
    families: dict[UUID, StrategyFamilyState],
    variants: dict[UUID, ExecutionVariantState],
) -> None:
    if isinstance(snapshot, StrategyFamilyEventRecord):
        families.pop(snapshot.family_id, None)
        for variant_id, variant in tuple(variants.items()):
            if variant.family_id == snapshot.family_id:
                variants.pop(variant_id)
        return
    variants.pop(snapshot.variant_id, None)
    family = families.get(snapshot.family_id)
    if family is not None:
        families[snapshot.family_id] = family.model_copy(
            update={
                "variant_ids": tuple(
                    item for item in family.variant_ids if item != snapshot.variant_id
                )
            }
        )


def _complete_batch(
    events: Sequence[Any],
    start: int,
    payload_type: type[Any],
    batch_id: str,
    ordinal: str,
    count: str,
) -> tuple[tuple[Any, ...], int]:
    first = events[start].payload
    identity = getattr(first, batch_id)
    batch: list[Any] = []
    index = start
    while index < len(events):
        event = events[index]
        payload = event.payload
        if not isinstance(payload, payload_type) or getattr(payload, batch_id) != identity:
            break
        batch.append(event)
        index += 1
    expected_count = getattr(first, count)
    if len(batch) != expected_count or tuple(
        getattr(item.payload, ordinal) for item in batch
    ) != tuple(range(1, expected_count + 1)):
        raise LedgerReplayError("strategy batch is incomplete or has invalid ordinals")
    return tuple(batch), index


def _reconciliation_snapshot_matches_operation(
    operation: StrategyReconciliationEventOperation,
    snapshot: StrategyResultSnapshot,
    known_families: dict[UUID, StrategyFamilyState],
    known_variants: dict[UUID, ExecutionVariantState],
    existing_by_key: dict[tuple[str, str], UUID],
) -> None:
    """Validate the typed state transition represented by one reconciliation item.

    A reconciliation digest is an audit value, not a transition language.  The concrete snapshot
    and operation must therefore agree before the reducer may use the snapshot to construct state.
    """
    if isinstance(snapshot, StrategyFamilyEventRecord):
        if operation.variant_id is not None or snapshot.family_id != operation.family_id:
            raise LedgerReplayError("strategy reconciliation family operation mismatches snapshot")
        prior_id = existing_by_key.get(("family", snapshot.stable_key))
        if prior_id is not None and prior_id != snapshot.family_id:
            raise LedgerReplayError("strategy reconciliation changes a family runtime ID")
        related = operation.related_family_ids
        supersedes = snapshot.supersedes_family_ids
    elif isinstance(snapshot, ExecutionVariantEventRecord):
        if snapshot.family_id != operation.family_id or snapshot.variant_id != operation.variant_id:
            raise LedgerReplayError("strategy reconciliation variant operation mismatches snapshot")
        prior_id = existing_by_key.get(("variant", snapshot.stable_key))
        if prior_id is not None and prior_id != snapshot.variant_id:
            raise LedgerReplayError("strategy reconciliation changes a variant runtime ID")
        prior = known_variants.get(snapshot.variant_id)
        if (
            prior is not None
            and prior.family_id != snapshot.family_id
            and prior.family_id not in operation.related_family_ids
        ):
            raise LedgerReplayError("strategy reconciliation reparents a variant")
        related = operation.related_variant_ids
        supersedes = snapshot.supersedes_variant_ids
    else:
        expected_id = (
            operation.family_id if snapshot.entity_kind == "family" else operation.variant_id
        )
        if snapshot.entity_id != expected_id:
            raise LedgerReplayError("strategy reconciliation tombstone mismatches operation")
        related = (
            operation.related_family_ids
            if snapshot.entity_kind == "family"
            else operation.related_variant_ids
        )
        supersedes = snapshot.replacement_ids

    if len(related) != len(set(related)) or len(supersedes) != len(set(supersedes)):
        raise LedgerReplayError("strategy reconciliation has duplicate related identities")
    if operation.operation in {"merge", "split", "supersede"}:
        if not related:
            raise LedgerReplayError(
                "strategy reconciliation relationship operation lacks companions"
            )
        if not set(related).issubset(set(supersedes) | {operation.family_id, operation.variant_id}):
            raise LedgerReplayError(
                "strategy reconciliation relationship is not represented by snapshot"
            )
    elif related or supersedes:
        raise LedgerReplayError("strategy reconciliation unrelated operation carries relationships")

    if isinstance(snapshot, StrategyTombstoneEventRecord):
        if operation.operation not in {"merge", "split", "supersede", "archive"}:
            raise LedgerReplayError(
                "strategy reconciliation operation requires a full state snapshot"
            )
        return
    expected_statuses = {
        "complete": {StrategyStatus.COMPLETED},
        "block": {StrategyStatus.BLOCKED},
        "archive": {StrategyStatus.ARCHIVED},
        "reactivate": {StrategyStatus.AVAILABLE, StrategyStatus.DEFERRED},
    }
    if (
        operation.operation in expected_statuses
        and snapshot.status not in expected_statuses[operation.operation]
    ):
        raise LedgerReplayError("strategy reconciliation operation does not match snapshot status")


def _reconciled_ledger(
    ledger: StrategyLedger, payloads: Sequence[StrategyReconciledEventPayload]
) -> StrategyLedger:
    """Build the exact post-reconciliation state after structural validation."""
    families = {item.family_id: item for item in ledger.families}
    variants = {item.variant_id: item for item in ledger.variants}
    for item in payloads:
        _apply_snapshot(item.resulting_snapshot, families, variants)
    _validate_hot_identity(families, variants)
    return _ledger(families, variants, ()).model_copy(update={"archive": ledger.archive})


def validate_reconciliation(
    ledger: StrategyLedger, payloads: Sequence[StrategyReconciledEventPayload]
) -> None:
    """Require a complete, identity-preserving reconciliation before replay applies it."""
    if not payloads:
        raise LedgerReplayError("strategy reconciliation is empty")
    first = payloads[0]
    stable = (
        first.request_id,
        first.frontier_id,
        first.reconciliation_id,
        first.item_count,
        first.input_ledger_digest,
        first.resulting_ledger_digest,
        first.reconciliation_digest,
    )
    if any(
        (
            item.request_id,
            item.frontier_id,
            item.reconciliation_id,
            item.item_count,
            item.input_ledger_digest,
            item.resulting_ledger_digest,
            item.reconciliation_digest,
        )
        != stable
        for item in payloads
    ):
        raise LedgerReplayError("strategy reconciliation mixes requests or digests")
    if tuple(item.item_ordinal for item in payloads) != tuple(range(1, first.item_count + 1)):
        raise LedgerReplayError("strategy reconciliation has invalid ordinals")
    if ledger_digest(ledger) != first.input_ledger_digest:
        raise LedgerReplayError("strategy reconciliation input digest is invalid")
    known_families = {item.family_id: item for item in ledger.families}
    known_variants = {item.variant_id: item for item in ledger.variants}
    existing_by_key = {
        **{("family", item.runtime_key): item.family_id for item in ledger.families},
        **{("variant", item.runtime_key): item.variant_id for item in ledger.variants},
    }
    covered_families: set[UUID] = set()
    covered_variants: set[UUID] = set()
    for item in payloads:
        operation = item.operation
        snapshot = item.resulting_snapshot
        covered_families.add(operation.family_id)
        if operation.variant_id is not None:
            covered_variants.add(operation.variant_id)
        _reconciliation_snapshot_matches_operation(
            operation, snapshot, known_families, known_variants, existing_by_key
        )
    if set(known_families) - covered_families or set(known_variants) - covered_variants:
        raise LedgerReplayError("strategy reconciliation omits a hot entry")
    resulting = _reconciled_ledger(ledger, payloads)
    if ledger_digest(resulting) != first.resulting_ledger_digest:
        raise LedgerReplayError("strategy reconciliation resulting digest is invalid")


def _predicate_matches(
    predicate: RetryPredicateEventRecord, situation: SituationProjection
) -> bool:
    facts = tuple(item.text for item in situation.facts)
    facets = {item.key: item.value for item in situation.facets}
    if predicate.kind == "fact_present":
        return predicate.subject_ref in facts or predicate.subject_ref in facets
    if predicate.kind == "fact_changed":
        value = facets.get(predicate.subject_ref)
        if value is None or predicate.expected_value_digest is None:
            return False
        return sha256(value.encode("utf-8")).hexdigest() != predicate.expected_value_digest
    if predicate.kind == "prerequisite_satisfied":
        return (
            predicate.subject_ref in facts
            or predicate.subject_ref in facets
            or any(item.subject == predicate.subject_ref for item in situation.access_states)
        )
    if predicate.kind == "evidence_category_present":
        return any(
            item.outcome.value == predicate.expected_symbolic_value for item in situation.attempts
        )
    if predicate.kind == "credential_available":
        return any(item.label == predicate.subject_ref for item in situation.secret_references)
    if predicate.kind == "state_revision_after":
        revision = predicate.minimum_material_revision
        return revision is not None and situation.material_event_revision > revision.sequence
    raise LedgerReplayError("unknown retry predicate kind")


def select_reactivation_candidates(
    archive: Iterable[ArchivedStrategyEventRecord], situation: SituationProjection
) -> tuple[ArchivedStrategyEventRecord, ...]:
    """Return at most sixteen cold records whose *typed* retry condition is now true."""
    selected = [
        record
        for record in archive
        if any(_predicate_matches(predicate, situation) for predicate in record.retry_predicates)
    ]
    return tuple(
        sorted(selected, key=lambda item: str(item.archive_entry_id))[:MAX_REACTIVATION_CANDIDATES]
    )


def matching_retry_predicate_ids(
    record: ArchivedStrategyEventRecord, situation: SituationProjection
) -> tuple[str, ...]:
    """Identify the typed retry predicates satisfied by this authoritative situation."""
    return tuple(
        predicate.predicate_id
        for predicate in record.retry_predicates
        if _predicate_matches(predicate, situation)
    )


def partition_ledger(ledger: StrategyLedger) -> tuple[StrategyLedger, tuple[UUID, ...]]:
    """Deterministically retain hot entries or reject a partition that would lose active state."""
    hot_statuses = {StrategyStatus.AVAILABLE, StrategyStatus.DEFERRED}
    protected_families = [item for item in ledger.families if item.status in hot_statuses]
    protected_variants = [item for item in ledger.variants if item.status in hot_statuses]
    if len(protected_families) > MAX_HOT_FAMILIES or len(protected_variants) > MAX_HOT_VARIANTS:
        raise LedgerReplayError(
            "hot strategy partition cannot retain all available or deferred entries"
        )
    families = tuple(
        sorted(
            ledger.families,
            key=lambda item: (
                item.status not in hot_statuses,
                item.runtime_key,
                str(item.family_id),
            ),
        )[:MAX_HOT_FAMILIES]
    )
    selected_family_ids = {item.family_id for item in families}
    variants = tuple(
        item
        for item in sorted(
            ledger.variants,
            key=lambda item: (
                item.status not in hot_statuses,
                item.runtime_key,
                str(item.variant_id),
            ),
        )
        if item.family_id in selected_family_ids
    )[:MAX_HOT_VARIANTS]
    retained_variant_ids = {item.variant_id for item in variants}
    missing = tuple(
        item.variant_id
        for item in sorted(
            ledger.variants, key=lambda item: (item.runtime_key, str(item.variant_id))
        )
        if item.variant_id not in retained_variant_ids
    )
    if any(item.status in hot_statuses for item in ledger.variants if item.variant_id in missing):
        raise LedgerReplayError("hot strategy partition would silently lose an active variant")
    revised_families = tuple(
        family.model_copy(
            update={
                "variant_ids": tuple(
                    item for item in family.variant_ids if item in retained_variant_ids
                )
            }
        )
        for family in families
    )
    return StrategyLedger(
        families=revised_families, variants=variants, archive=ledger.archive
    ), missing


class StrategyLedgerReducer:
    """Replay only complete strategy transactions from the authoritative journal."""

    @classmethod
    def rebuild_state(cls, snapshot: EngagementSnapshot) -> LedgerReplay:
        families: dict[UUID, StrategyFamilyState] = {}
        variants: dict[UUID, ExecutionVariantState] = {}
        attempt_revisions: dict[UUID, dict[str, object]] = {}
        hot_attempt_order: list[tuple[UUID, UUID]] = []
        archives: list[tuple[ArchivedStrategyEventRecord, UUID]] = []
        snapshot_variants_by_event: dict[UUID, UUID] = {}
        reconciled_snapshots: dict[UUID, StrategyResultSnapshot] = {}
        seen_reconciliations: set[UUID] = set()
        seen_archive_batches: set[UUID] = set()
        seen_reactivation_batches: set[UUID] = set()
        index = 0
        events = snapshot.events
        while index < len(events):
            event = events[index]
            payload = event.payload
            if isinstance(payload, StrategyReconciledEventPayload):
                batch, index = _complete_batch(
                    events,
                    index,
                    StrategyReconciledEventPayload,
                    "reconciliation_id",
                    "item_ordinal",
                    "item_count",
                )
                payloads = tuple(item.payload for item in batch)
                if payloads[0].reconciliation_id in seen_reconciliations:
                    raise LedgerReplayError("strategy reconciliation batch is duplicated")
                seen_reconciliations.add(payloads[0].reconciliation_id)
                validate_reconciliation(_ledger(families, variants, archives), payloads)
                for item in batch:
                    _apply_snapshot(item.payload.resulting_snapshot, families, variants)
                    reconciled_snapshots[item.event_id] = item.payload.resulting_snapshot
                    if isinstance(item.payload.resulting_snapshot, ExecutionVariantEventRecord):
                        snapshot_variants_by_event[item.event_id] = (
                            item.payload.resulting_snapshot.variant_id
                        )
                _validate_hot_identity(families, variants)
                resulting = _ledger(families, variants, archives)
                if ledger_digest(resulting) != payloads[0].resulting_ledger_digest:
                    raise LedgerReplayError("strategy reconciliation resulting digest is invalid")
                continue
            if isinstance(payload, StrategyArchivedEventPayload):
                batch, index = _complete_batch(
                    events,
                    index,
                    StrategyArchivedEventPayload,
                    "archive_batch_id",
                    "entry_ordinal",
                    "entry_count",
                )
                first = batch[0].payload
                if first.archive_batch_id in seen_archive_batches:
                    raise LedgerReplayError("strategy archive batch is duplicated")
                seen_archive_batches.add(first.archive_batch_id)
                if any(
                    item.payload.request_id != first.request_id
                    or item.payload.entry_count != first.entry_count
                    or item.payload.resulting_archive_digest != first.resulting_archive_digest
                    for item in batch
                ):
                    raise LedgerReplayError("strategy archive batch mixes requests")
                for item in batch:
                    archived = item.payload.archive_record
                    if archived.snapshot.status in {"available", "deferred"}:
                        raise LedgerReplayError("strategy archive cannot hide an active strategy")
                    if (
                        reconciled_snapshots.get(archived.source_reconciliation_event_id)
                        != archived.snapshot
                    ):
                        raise LedgerReplayError("strategy archive companion snapshot is invalid")
                    if any(
                        existing.archive_entry_id == archived.archive_entry_id
                        for existing, _ in archives
                    ):
                        raise LedgerReplayError("strategy archive entry is duplicated")
                    if (
                        archived.archive_entry_digest
                        != sha256(
                            _canonical(
                                archived.model_dump(mode="json", exclude={"archive_entry_digest"})
                            )
                        ).hexdigest()
                    ):
                        raise LedgerReplayError("strategy archive entry digest is invalid")
                    archives.append((archived, item.event_id))
                    _remove_archived_snapshot(archived.snapshot, families, variants)
                _validate_hot_identity(families, variants)
                actual_archive = archive_digest(tuple(item[0] for item in archives))
                if actual_archive != first.resulting_archive_digest:
                    raise LedgerReplayError("strategy archive resulting digest is invalid")
                continue
            if isinstance(payload, StrategyReactivatedEventPayload):
                batch, index = _complete_batch(
                    events,
                    index,
                    StrategyReactivatedEventPayload,
                    "reactivation_batch_id",
                    "entry_ordinal",
                    "entry_count",
                )
                first = batch[0].payload
                if first.reactivation_batch_id in seen_reactivation_batches:
                    raise LedgerReplayError("strategy reactivation batch is duplicated")
                seen_reactivation_batches.add(first.reactivation_batch_id)
                if any(
                    item.payload.request_id != first.request_id
                    or item.payload.entry_count != first.entry_count
                    or item.payload.resulting_archive_digest != first.resulting_archive_digest
                    for item in batch
                ):
                    raise LedgerReplayError("strategy reactivation batch mixes requests")
                for item in batch:
                    restored = item.payload.restored_snapshot
                    candidates = [
                        pair for pair in archives if pair[1] == item.payload.source_archive_event_id
                    ]
                    if (
                        len(candidates) != 1
                        or candidates[0][0].archive_entry_digest
                        != item.payload.prior_archive_entry_digest
                    ):
                        raise LedgerReplayError(
                            "strategy reactivation archive companion is invalid"
                        )
                    expected_restored = candidates[0][0].snapshot.model_copy(
                        update={"status": StrategyStatus.AVAILABLE.value}
                    )
                    if expected_restored != restored:
                        raise LedgerReplayError("strategy reactivation snapshot is invalid")
                    predicate_ids = {
                        predicate.predicate_id for predicate in candidates[0][0].retry_predicates
                    }
                    if not set(item.payload.matched_predicate_ids).issubset(predicate_ids):
                        raise LedgerReplayError(
                            "strategy reactivation predicate companion is invalid"
                        )
                    archives.remove(candidates[0])
                    _apply_snapshot(restored, families, variants)
                    if isinstance(restored, ExecutionVariantEventRecord):
                        snapshot_variants_by_event[item.event_id] = restored.variant_id
                _validate_hot_identity(families, variants)
                actual_archive = archive_digest(tuple(item[0] for item in archives))
                if actual_archive != first.resulting_archive_digest:
                    raise LedgerReplayError(
                        "strategy reactivation resulting archive digest is invalid"
                    )
                continue
            if isinstance(payload, OutcomeAssessedEventPayload):
                targets = {
                    snapshot_variants_by_event[event_id]
                    for event_id in payload.source_event_ids
                    if event_id in snapshot_variants_by_event
                }
                if len(targets) == 1:
                    variant_id = next(iter(targets))
                    variant = variants.get(variant_id)
                    if variant is not None:
                        attempt = AttemptState(
                            attempt_event_id=_attempt_id(payload),
                            outcome_event_id=event.event_id,
                            outcome=payload.category,
                            summary=payload.summary,
                        )
                        attempt_revisions[attempt.attempt_event_id] = {
                            "sequence": event.sequence,
                            "event_hash": event.event_hash,
                        }
                        totals = dict(variant.outcome_category_totals)
                        if attempt.attempt_event_id not in {
                            item.attempt_event_id for item in variant.recent_attempts
                        }:
                            totals[attempt.outcome] = totals.get(attempt.outcome, 0) + 1
                        recent = tuple(
                            item
                            for item in variant.recent_attempts
                            if item.attempt_event_id != attempt.attempt_event_id
                        ) + (attempt,)
                        if len(recent) > MAX_ATTEMPTS_PER_VARIANT:
                            hot_attempt_order = [
                                item
                                for item in hot_attempt_order
                                if item[1] != recent[0].attempt_event_id
                            ]
                            variant = _append_historical_attempt(
                                variant,
                                recent[0],
                                attempt_revisions.pop(
                                    recent[0].attempt_event_id,
                                    {"sequence": event.sequence, "event_hash": event.event_hash},
                                ),
                            )
                            recent = recent[1:]
                        variants[variant_id] = variant.model_copy(
                            update={
                                "recent_attempts": recent,
                                "outcome_category_totals": dict(
                                    sorted(totals.items(), key=lambda item: item[0])
                                ),
                            }
                        )
                        hot_attempt_order.append((variant_id, attempt.attempt_event_id))
                        while (
                            sum(len(item.recent_attempts) for item in variants.values())
                            > MAX_HOT_ATTEMPTS
                        ):
                            while hot_attempt_order:
                                oldest_variant_id, oldest_attempt_id = hot_attempt_order.pop(0)
                                oldest_variant = variants.get(oldest_variant_id)
                                if oldest_variant is None:
                                    continue
                                matching = next(
                                    (
                                        item
                                        for item in oldest_variant.recent_attempts
                                        if item.attempt_event_id == oldest_attempt_id
                                    ),
                                    None,
                                )
                                if matching is None:
                                    continue
                                variants[oldest_variant_id] = _append_historical_attempt(
                                    oldest_variant,
                                    matching,
                                    attempt_revisions.pop(
                                        oldest_attempt_id,
                                        {
                                            "sequence": event.sequence,
                                            "event_hash": event.event_hash,
                                        },
                                    ),
                                ).model_copy(
                                    update={
                                        "recent_attempts": tuple(
                                            item
                                            for item in oldest_variant.recent_attempts
                                            if item.attempt_event_id != oldest_attempt_id
                                        )
                                    }
                                )
                                break
                            else:
                                raise LedgerReplayError(
                                    "strategy hot attempt order is not reconstructible"
                                )
                index += 1
                continue
            index += 1
        ledger = _ledger(families, variants, archives)
        archive_records = tuple(item[0] for item in archives)
        return LedgerReplay(
            ledger=ledger,
            archive_records=archive_records,
            ledger_sha256=ledger_digest(ledger),
            archive_sha256=archive_digest(archive_records),
        )

    @classmethod
    def rebuild(cls, snapshot: EngagementSnapshot) -> StrategyLedger:
        return cls.rebuild_state(snapshot).ledger
