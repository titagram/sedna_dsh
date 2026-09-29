"""Deterministic expected-utility scoring for frontier selection."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from sedna.planning.models import FrontierProposalDraft, StrategyStatus


class UtilityInput(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    objective_value: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    plausibility: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    information_gain: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    cost: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    risk: Annotated[float, Field(ge=0, le=1, allow_inf_nan=False)]
    prerequisites_satisfied: bool


def expected_utility(value: UtilityInput) -> float:
    """Return bounded utility; prerequisites are a hard gate rather than a soft penalty."""

    if not value.prerequisites_satisfied:
        return 0.0
    utility = (
        0.35 * value.objective_value
        + 0.30 * value.plausibility
        + 0.25 * value.information_gain
        - 0.05 * value.cost
        - 0.05 * value.risk
    )
    return round(max(0.0, min(1.0, utility)), 6)


def utility_input_for_proposal(proposal: FrontierProposalDraft) -> UtilityInput:
    """Project a validated proposal into the deterministic utility contract."""

    return UtilityInput(
        objective_value=proposal.score / 100,
        plausibility=proposal.confidence / 100,
        information_gain=min(
            1.0,
            0.35
            + 0.20 * min(2, len(proposal.expected_evidence))
            + 0.10 * min(1, len(proposal.stop_conditions)),
        ),
        cost=min(1.0, 0.10 * len(proposal.prerequisites) + 0.25 * len(proposal.commands)),
        risk=min(
            1.0,
            0.25 * len(proposal.commands)
            + (0.15 if proposal.commands and not proposal.stop_conditions else 0.0),
        ),
        prerequisites_satisfied=(
            proposal.status is StrategyStatus.AVAILABLE
            and len(proposal.prerequisite_proofs) == len(proposal.prerequisites)
        ),
    )


def select_best_utility(candidates: tuple[tuple[str, UtilityInput], ...]) -> str | None:
    """Select maximum utility with a stable identity tie-break."""

    eligible = tuple(item for item in candidates if item[1].prerequisites_satisfied)
    if not eligible:
        return None
    return min(
        eligible,
        key=lambda item: (-expected_utility(item[1]), item[0]),
    )[0]


def rank_utilities(candidates: tuple[tuple[str, UtilityInput], ...]) -> tuple[str, ...]:
    """Rank eligible candidates first, then terminal/ineligible records deterministically."""

    return tuple(
        item[0]
        for item in sorted(
            candidates,
            key=lambda item: (
                not item[1].prerequisites_satisfied,
                -expected_utility(item[1]),
                item[0],
            ),
        )
    )


__all__ = [
    "UtilityInput",
    "expected_utility",
    "rank_utilities",
    "select_best_utility",
    "utility_input_for_proposal",
]
