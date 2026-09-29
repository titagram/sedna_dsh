"""Private, deterministic telemetry from already validated journal events.

This is a projection, not a journal parser or an integrity verifier. Publication
contains numeric aggregates only; no command, rationale or evidence is copied.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from sedna.engagement.events import (
    DecisionRecordedPayload,
    FrontierProposedEventPayload,
    JournalEvent,
    OutcomeAssessedEventPayload,
    ToolCallCompletedPayload,
    ToolCallStartedPayload,
)


@dataclass(frozen=True)
class ControlLoopMetrics:
    started_calls: int
    completed_calls: int
    assessed_completed_calls: int
    decision_linked_calls: int
    frontier_linked_calls: int

    @property
    def outcome_coverage(self) -> float | None:
        if not self.completed_calls:
            return None
        return self.assessed_completed_calls / self.completed_calls

    @property
    def decision_link_coverage(self) -> float | None:
        if not self.started_calls:
            return None
        return self.decision_linked_calls / self.started_calls


def project_control_loop_metrics(events: Iterable[JournalEvent]) -> ControlLoopMetrics:
    """Count distinct calls, never repeated outcome events as extra coverage."""
    started: set[str] = set()
    completed: set[str] = set()
    assessed: set[str] = set()
    linked: set[str] = set()
    decisions: set[str] = set()
    proposals: set[object] = set()
    frontier_decisions: set[str] = set()
    frontier_calls: set[str] = set()
    for event in events:
        if event.type == "frontier_proposed":
            proposals.add(cast(FrontierProposedEventPayload, event.payload).proposal.proposal_id)
        elif event.type == "decision_recorded":
            decision = cast(DecisionRecordedPayload, event.payload)
            decisions.add(decision.decision_id)
            if decision.proposal_id in proposals:
                frontier_decisions.add(decision.decision_id)
        elif event.type == "tool_call_started":
            start = cast(ToolCallStartedPayload, event.payload)
            started.add(start.call_id)
            if start.decision_id in decisions:
                linked.add(start.call_id)
            if start.decision_id in frontier_decisions:
                frontier_calls.add(start.call_id)
        elif event.type == "tool_call_completed":
            completed.add(cast(ToolCallCompletedPayload, event.payload).call_id)
        elif event.type == "outcome_assessed":
            assessed.update(cast(OutcomeAssessedEventPayload, event.payload).tool_call_ids)
    completed &= started
    return ControlLoopMetrics(
        started_calls=len(started),
        completed_calls=len(completed),
        assessed_completed_calls=len(assessed & completed),
        decision_linked_calls=len(linked),
        frontier_linked_calls=len(frontier_calls),
    )
