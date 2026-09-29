"""Event-only reconstruction of the last accepted adaptive frontier."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sedna.engagement.events import (
    FrontierCriticizedEventPayload,
    FrontierProposedEventPayload,
    FrontierRepairedEventPayload,
    PlanRequestedEventPayload,
    StrategyReconciledEventPayload,
)
from sedna.planning.ledger import StrategyLedgerReducer
from sedna.planning.models import FrontierProjection, FrontierProposal


class FrontierReplayError(ValueError):
    """Journal events do not describe one complete accepted frontier."""


class FrontierReducer:
    """Rebuild a frontier from complete, accepted ordinal batches only."""

    @classmethod
    def rebuild(cls, snapshot: Any) -> FrontierProjection | None:
        operation_by_key: dict[tuple[object, object], object] = {}
        operation_by_request: dict[object, object] = {}
        request_by_id: dict[object, PlanRequestedEventPayload] = {}
        requested: dict[object, int] = defaultdict(int)
        proposed: dict[tuple[object, object], list[FrontierProposedEventPayload]] = defaultdict(
            list
        )
        repaired: dict[tuple[object, object], list[FrontierRepairedEventPayload]] = defaultdict(
            list
        )
        critics: list[Any] = []
        reconciled: dict[tuple[object, object], list[StrategyReconciledEventPayload]] = defaultdict(
            list
        )
        for event in snapshot.events:
            payload = event.payload
            if isinstance(payload, PlanRequestedEventPayload):
                requested[payload.request_id] += 1
                request_by_id[payload.request_id] = payload
                correlation = getattr(event, "system_correlation", None)
                operation_id = getattr(correlation, "operation_id", None)
                if operation_id is None:
                    raise FrontierReplayError("plan request lacks atomic operation identity")
                prior_operation = operation_by_request.setdefault(payload.request_id, operation_id)
                if prior_operation != operation_id:
                    raise FrontierReplayError("plan request is not atomic")
            if isinstance(
                payload,
                (
                    FrontierProposedEventPayload,
                    FrontierRepairedEventPayload,
                    FrontierCriticizedEventPayload,
                    StrategyReconciledEventPayload,
                ),
            ):
                key = (payload.request_id, payload.frontier_id)
                correlation = getattr(event, "system_correlation", None)
                operation_id = getattr(correlation, "operation_id", None)
                if operation_id is None:
                    raise FrontierReplayError("frontier attempt lacks atomic operation identity")
                prior_operation = operation_by_key.setdefault(key, operation_id)
                if prior_operation != operation_id:
                    raise FrontierReplayError("frontier attempt is not atomic")
                request_operation = operation_by_request.get(payload.request_id)
                if request_operation is not None and request_operation != operation_id:
                    raise FrontierReplayError("plan request and frontier attempt are not atomic")
            if isinstance(payload, FrontierProposedEventPayload):
                proposed[(payload.request_id, payload.frontier_id)].append(payload)
            elif isinstance(payload, FrontierRepairedEventPayload):
                repaired[(payload.request_id, payload.frontier_id)].append(payload)
            elif isinstance(payload, FrontierCriticizedEventPayload):
                critics.append(event)
            elif isinstance(payload, StrategyReconciledEventPayload):
                reconciled[(payload.request_id, payload.frontier_id)].append(payload)

        accepted = [event for event in critics if event.payload.accepted]
        if not accepted:
            return None
        critic = accepted[-1].payload
        key = (critic.request_id, critic.frontier_id)
        batch: list[FrontierProposedEventPayload | FrontierRepairedEventPayload]
        batch = repaired[key] if critic.critic_pass == 2 else proposed[key]
        ordered = cls._complete_batch(batch)
        if critic.critic_pass == 2:
            rejected_first = [
                event
                for event in critics
                if event.payload.request_id == critic.request_id
                and event.payload.frontier_id == critic.frontier_id
                and event.payload.critic_pass == 1
                and not event.payload.accepted
            ]
            if len(rejected_first) != 1:
                raise FrontierReplayError("repair requires exactly one rejected first critic")
            rejected_event_id = getattr(rejected_first[0], "event_id", None)
            if rejected_event_id is None or any(
                item.critic_event_id != rejected_event_id for item in ordered
            ):
                raise FrontierReplayError("repair does not link its rejected first critic")
        ledger_batch = reconciled[key]
        initial = cls._complete_batch(proposed[key])
        request = request_by_id.get(critic.request_id)
        if request is None:
            raise FrontierReplayError("accepted frontier lacks its plan request")
        if len(initial) > request.max_proposals:
            raise FrontierReplayError("proposal batch exceeds requested maximum")
        if any(
            item.situation_digest != request.situation_digest
            or item.input_ledger_digest != request.input_ledger_digest
            for item in initial
        ):
            raise FrontierReplayError("proposal batch does not match its plan request")
        if not ledger_batch:
            raise FrontierReplayError("accepted frontier lacks complete reconciliation")
        complete_ledger = cls._complete_batch(ledger_batch)
        if any(
            item.input_ledger_digest != request.input_ledger_digest
            or item.resulting_ledger_digest != complete_ledger[0].resulting_ledger_digest
            for item in complete_ledger
        ):
            raise FrontierReplayError("reconciliation digest chain is inconsistent")
        if requested[critic.request_id] != 1:
            raise FrontierReplayError("accepted frontier requires exactly one plan request")
        attempt_events = [
            event
            for event in snapshot.events
            if getattr(event.payload, "request_id", None) == critic.request_id
            and (
                isinstance(event.payload, PlanRequestedEventPayload)
                or getattr(event.payload, "frontier_id", None) == critic.frontier_id
            )
        ]
        accepted_index = next(
            index for index, event in enumerate(attempt_events) if event.payload is critic
        )
        relevant = [event.payload for event in attempt_events]
        if not isinstance(relevant[0], PlanRequestedEventPayload):
            raise FrontierReplayError("plan request must begin the frontier transaction")
        critic_sequence = tuple(
            payload.critic_pass
            for payload in relevant
            if isinstance(payload, FrontierCriticizedEventPayload)
        )
        expected_critics = (1, 2) if critic.critic_pass == 2 else (1,)
        if critic_sequence != expected_critics:
            raise FrontierReplayError("frontier transaction has an invalid critic sequence")
        proposal_indexes = [
            index
            for index, payload in enumerate(relevant)
            if isinstance(payload, FrontierProposedEventPayload)
        ]
        first_critic_index = next(
            index
            for index, payload in enumerate(relevant)
            if isinstance(payload, FrontierCriticizedEventPayload)
        )
        if proposal_indexes != list(range(1, first_critic_index)):
            raise FrontierReplayError("initial proposal sequence is not contiguous")
        if critic.critic_pass == 2:
            repaired_indexes = [
                index
                for index, payload in enumerate(relevant)
                if isinstance(payload, FrontierRepairedEventPayload)
            ]
            if repaired_indexes != list(range(first_critic_index + 1, accepted_index)):
                raise FrontierReplayError("repair proposal sequence is not contiguous")
        reconciliation_indexes = [
            index
            for index, payload in enumerate(relevant)
            if isinstance(payload, StrategyReconciledEventPayload)
        ]
        if reconciliation_indexes != list(range(accepted_index + 1, len(relevant))):
            raise FrontierReplayError("reconciliation must complete the frontier transaction")
        if any(
            isinstance(event.payload, StrategyReconciledEventPayload)
            for event in attempt_events[:accepted_index]
        ):
            raise FrontierReplayError("frontier reconciliation precedes accepted critic sequence")
        if any(
            isinstance(event.payload, (FrontierProposedEventPayload, FrontierRepairedEventPayload))
            for event in attempt_events[accepted_index + 1 :]
        ):
            raise FrontierReplayError("frontier proposal sequence continues after acceptance")
        resulting_digest = StrategyLedgerReducer.rebuild_state(snapshot).ledger_sha256
        proposals = tuple(cls._proposal(item.proposal) for item in ordered)
        return FrontierProjection(
            frontier_id=critic.frontier_id,
            engagement_id=snapshot.engagement_id,
            state_digest=initial[0].situation_digest,
            input_ledger_digest=initial[0].input_ledger_digest,
            resulting_ledger_digest=resulting_digest,
            proposals=proposals,
            constrained_rationale=(
                "The accepted frontier contains fewer than three applicable proposals."
                if len(proposals) < 3
                else None
            ),
        )

    @staticmethod
    def _complete_batch(batch: list[Any]) -> list[Any]:
        if not batch:
            raise FrontierReplayError("accepted frontier has no ordinal batch")
        counts = {
            getattr(item, "proposal_count", getattr(item, "item_count", None)) for item in batch
        }
        if len(counts) != 1:
            raise FrontierReplayError("mixed ordinal counts")
        count = counts.pop()
        identities = {
            (getattr(item, "request_id", None), getattr(item, "frontier_id", None))
            for item in batch
        }
        if len(identities) != 1:
            raise FrontierReplayError("mixed request or frontier ordinal batch")
        proposal_counts = [getattr(item, "proposal_count", None) for item in batch]
        if proposal_counts[0] is not None:
            common_digest_fields = (
                "situation_digest",
                "input_ledger_digest",
                "knowledge_context_digest",
                "draft_digest",
                "planner_call_digest",
                "repaired_draft_digest",
                "call_input_digest",
            )
            has_mixed_digest = any(
                len({getattr(item, name) for item in batch if hasattr(item, name)}) > 1
                for name in common_digest_fields
            )
            if has_mixed_digest:
                raise FrontierReplayError("mixed proposal batch digests")
        ordinal_name = (
            "proposal_ordinal" if hasattr(batch[0], "proposal_ordinal") else "item_ordinal"
        )
        ordinals = [getattr(item, ordinal_name) for item in batch]
        if count is None or sorted(ordinals) != list(range(1, count + 1)):
            raise FrontierReplayError("incomplete or duplicate ordinal batch")
        return sorted(batch, key=lambda item: getattr(item, ordinal_name))

    @staticmethod
    def _proposal(record: Any) -> FrontierProposal:
        if record.family_id is None or record.variant_id is None:
            raise FrontierReplayError("accepted proposal lacks allocated strategy ancestry")
        return FrontierProposal(
            proposal_id=record.proposal_id,
            family_id=record.family_id,
            variant_id=record.variant_id,
            title=record.title,
            score=record.score,
            confidence=round(record.confidence * 100),
            rationale=record.rationale,
        )


__all__ = ["FrontierReducer", "FrontierReplayError"]
