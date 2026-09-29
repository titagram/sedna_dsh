"""Deterministic Bayesian-inspired belief updates over journal outcomes."""

from __future__ import annotations

from hashlib import sha256
from math import isfinite
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sedna.planning.models import (
    HypothesisBelief,
    OutcomeCategory,
    SituationHypothesis,
)


class BeliefEvidenceUpdate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    event_id: UUID
    outcome: OutcomeCategory
    independence_group: str | None = Field(default=None, min_length=1, max_length=256)
    correlation_refs: tuple[str, ...] = ()

    @field_validator("correlation_refs")
    @classmethod
    def _validate_refs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("correlation refs must be sorted and unique")
        return value


class BeliefUpdateResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    prior: float = Field(ge=0, le=1, allow_inf_nan=False)
    posterior: float = Field(ge=0, le=1, allow_inf_nan=False)
    applied_updates: tuple[BeliefEvidenceUpdate, ...]


_LIKELIHOOD_RATIO: dict[OutcomeCategory, float] = {
    OutcomeCategory.PROGRESS: 3.0,
    OutcomeCategory.PARTIAL_PROGRESS: 1.6,
    OutcomeCategory.NO_EFFECT: 0.8,
    OutcomeCategory.NEGATIVE_EVIDENCE: 0.25,
    OutcomeCategory.INCOMPATIBLE: 0.01,
    OutcomeCategory.EXECUTION_ERROR: 1.0,
    OutcomeCategory.AMBIGUOUS: 1.0,
}


def update_belief(
    prior: float,
    updates: tuple[BeliefEvidenceUpdate, ...],
) -> BeliefUpdateResult:
    """Apply bounded likelihood ratios once per event/independence group."""

    if not isfinite(prior) or not 0 <= prior <= 1:
        raise ValueError("belief prior must be finite and between zero and one")
    parent = list(range(len(updates)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    ref_owner: dict[str, int] = {}
    graph_refs_by_index: list[set[str]] = []
    for index, update in enumerate(updates):
        refs = set(update.correlation_refs)
        refs.add(f"event:{update.event_id}")
        if update.independence_group is not None:
            refs.add(f"legacy-group:{update.independence_group}")
        graph_refs_by_index.append(refs)
        for ref in refs:
            if ref in ref_owner:
                union(index, ref_owner[ref])
            else:
                ref_owner[ref] = index

    members_by_root: dict[int, list[BeliefEvidenceUpdate]] = {}
    graph_refs_by_root: dict[int, set[str]] = {}
    for index, update in enumerate(updates):
        root = find(index)
        members_by_root.setdefault(root, []).append(update)
        graph_refs_by_root.setdefault(root, set()).update(graph_refs_by_index[index])

    selected: list[BeliefEvidenceUpdate] = []
    components = sorted(
        members_by_root.items(),
        key=lambda item: min(update.event_id for update in item[1]),
    )
    for root, members in components:
        event_id = min(update.event_id for update in members)
        outcomes = {update.outcome for update in members}
        outcome = next(iter(outcomes)) if len(outcomes) == 1 else OutcomeCategory.AMBIGUOUS
        correlation_refs = tuple(
            sorted({value for update in members for value in update.correlation_refs})
        )
        graph_refs = graph_refs_by_root[root]
        independence_group = None
        if (
            len({update.event_id for update in members}) > 1
            or correlation_refs
            or any(update.independence_group is not None for update in members)
        ):
            digest = sha256("\n".join(sorted(graph_refs)).encode("utf-8")).hexdigest()
            independence_group = f"component:{digest}"
        selected.append(
            BeliefEvidenceUpdate(
                event_id=event_id,
                outcome=outcome,
                independence_group=independence_group,
                correlation_refs=correlation_refs,
            )
        )

    if prior in {0.0, 1.0}:
        posterior = prior
    else:
        odds = prior / (1.0 - prior)
        for update in selected:
            odds *= _LIKELIHOOD_RATIO[update.outcome]
        posterior = odds / (1.0 + odds)
    return BeliefUpdateResult(
        prior=prior,
        posterior=posterior,
        applied_updates=tuple(selected),
    )


def validate_outcome_score_transition(
    *,
    previous_score: int,
    new_score: int,
    outcomes: tuple[OutcomeCategory, ...],
) -> None:
    """Enforce score direction from outcomes that are the cited reason for a change."""

    if not 0 <= previous_score <= 100 or not 0 <= new_score <= 100:
        raise ValueError("strategy scores must be between zero and one hundred")
    adverse = {
        OutcomeCategory.NO_EFFECT,
        OutcomeCategory.NEGATIVE_EVIDENCE,
        OutcomeCategory.INCOMPATIBLE,
    }
    non_evidence = {OutcomeCategory.EXECUTION_ERROR, OutcomeCategory.AMBIGUOUS}
    if outcomes and set(outcomes) <= adverse and new_score >= previous_score:
        raise ValueError("adverse_outcome_requires_lower_score")
    if outcomes and set(outcomes) <= non_evidence and new_score < previous_score:
        raise ValueError("non_evidence_outcome_cannot_lower_score")


def project_hypothesis_beliefs(
    hypotheses: tuple[SituationHypothesis, ...],
    events: tuple[object, ...] | list[object],
) -> tuple[HypothesisBelief, ...]:
    """Replay proposal/decision/outcome links into deterministic hypothesis beliefs."""

    hypothesis_ids = {item.event_ids[0] for item in hypotheses}
    proposal_refs: dict[UUID, tuple[UUID, ...]] = {}
    decision_proposals: dict[UUID, UUID] = {}
    updates: dict[UUID, list[BeliefEvidenceUpdate]] = {
        hypothesis_id: [] for hypothesis_id in hypothesis_ids
    }
    for event in events:
        payload = getattr(event, "payload", None)
        kind = getattr(payload, "kind", None)
        if kind in {"frontier_proposed", "frontier_repaired"}:
            proposal = getattr(payload, "proposal", None)
            proposal_id = getattr(proposal, "proposal_id", None)
            if isinstance(proposal_id, UUID):
                proposal_refs[proposal_id] = tuple(
                    event_id
                    for event_id in getattr(proposal, "event_refs", ())
                    if event_id in hypothesis_ids
                )
            continue
        if kind == "decision_recorded":
            proposal_id = getattr(payload, "proposal_id", None)
            if not isinstance(proposal_id, UUID):
                continue
            try:
                decision_id = UUID(str(getattr(payload, "decision_id", "")))
            except ValueError:
                continue
            decision_proposals[decision_id] = proposal_id
            continue
        if kind != "outcome_assessed":
            continue
        if payload is None:
            continue
        decision_id = getattr(payload, "decision_id", None)
        if not isinstance(decision_id, UUID):
            continue
        proposal_id = decision_proposals.get(decision_id)
        if proposal_id is None:
            continue
        category = OutcomeCategory(payload.category)
        event_id = getattr(event, "event_id", None)
        if not isinstance(event_id, UUID):
            continue
        correlation_refs = []
        attachment_event_id = getattr(payload, "attachment_event_id", None)
        if isinstance(attachment_event_id, UUID):
            correlation_refs.append(f"attachment:{attachment_event_id}")
        correlation_refs.extend(f"evidence:{item}" for item in getattr(payload, "evidence_ids", ()))
        correlation_refs.extend(
            f"source-event:{item}" for item in getattr(payload, "source_event_ids", ())
        )
        for hypothesis_id in proposal_refs.get(proposal_id, ()):
            updates[hypothesis_id].append(
                BeliefEvidenceUpdate(
                    event_id=event_id,
                    outcome=category,
                    correlation_refs=tuple(sorted(set(correlation_refs))),
                )
            )

    beliefs = []
    for hypothesis in hypotheses:
        hypothesis_id = hypothesis.event_ids[0]
        result = update_belief(hypothesis.confidence, tuple(updates[hypothesis_id]))
        beliefs.append(
            HypothesisBelief(
                hypothesis_event_id=hypothesis_id,
                prior=result.prior,
                posterior=result.posterior,
                update_event_ids=tuple(
                    sorted((item.event_id for item in result.applied_updates), key=str)
                ),
            )
        )
    return tuple(sorted(beliefs, key=lambda item: str(item.hypothesis_event_id)))


__all__ = [
    "BeliefEvidenceUpdate",
    "BeliefUpdateResult",
    "project_hypothesis_beliefs",
    "update_belief",
    "validate_outcome_score_transition",
]
