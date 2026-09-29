"""Deterministic semantic-loop guards for strategy retries."""

from __future__ import annotations

from uuid import UUID

from sedna.planning.models import OutcomeCategory

_ADVERSE_TECHNICAL_OUTCOMES = frozenset(
    {
        OutcomeCategory.NO_EFFECT,
        OutcomeCategory.NEGATIVE_EVIDENCE,
        OutcomeCategory.INCOMPATIBLE,
    }
)
_MATERIAL_EVIDENCE_EVENT_TYPES = frozenset(
    {
        "evidence_attached",
        "interpretation_succeeded",
        "observation_extracted",
        "objective_proof_observed",
        "outcome_assessed",
    }
)


def has_newer_material_reference(
    event_refs: tuple[UUID, ...],
    outcome_event_id: UUID | None,
    event_order: dict[UUID, int],
    event_types: dict[UUID, str],
) -> bool:
    """Return true only for newer cited material evidence after outcome assessment."""

    if outcome_event_id is None or outcome_event_id not in event_order:
        return False
    outcome_order = event_order[outcome_event_id]
    return any(
        event_order.get(event_id, -1) > outcome_order
        and event_types.get(event_id) in _MATERIAL_EVIDENCE_EVENT_TYPES
        for event_id in event_refs
    )


def validate_semantic_retry(
    *,
    latest_outcome: OutcomeCategory,
    has_new_material_evidence: bool,
) -> None:
    """Reject adverse retries unless a newer cited event can change the decision."""

    if latest_outcome in _ADVERSE_TECHNICAL_OUTCOMES and not has_new_material_evidence:
        raise ValueError("semantic_strategy_loop")


__all__ = ["has_newer_material_reference", "validate_semantic_retry"]
