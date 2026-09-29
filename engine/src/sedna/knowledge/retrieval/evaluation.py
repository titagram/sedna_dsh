"""Typed, deterministic summaries for versioned retrieval evaluation suites."""

from __future__ import annotations

import math
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

EvaluationIdentifier = Annotated[str, Field(min_length=1, max_length=512)]
_MAX_EVALUATION_ITEMS = 256
_MAX_K = 100
_MAX_LATENCY_SECONDS = 7 * 24 * 60 * 60
_MAX_INDEX_SIZE_BYTES = 10 * 1024 * 1024 * 1024


class RetrievalScenarioEvaluation(BaseModel):
    """One bounded top-K observation with metrics derived from stable artifact identities."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    scenario_id: EvaluationIdentifier
    k: int = Field(ge=1, le=_MAX_K)
    relevant_artifact_ids: tuple[EvaluationIdentifier, ...] = Field(
        min_length=1, max_length=_MAX_EVALUATION_ITEMS
    )
    returned_artifact_ids: tuple[EvaluationIdentifier, ...] = Field(default=(), max_length=_MAX_K)
    incompatible_artifact_ids: tuple[EvaluationIdentifier, ...] = Field(
        default=(), max_length=_MAX_EVALUATION_ITEMS
    )
    reproducible: bool
    latency_seconds: float = Field(ge=0.0, le=_MAX_LATENCY_SECONDS)

    @field_validator("latency_seconds", mode="before")
    @classmethod
    def require_finite_latency(cls, value: object) -> object:
        if type(value) in {int, float} and not math.isfinite(value):
            raise ValueError("evaluation latency must be finite")
        return value

    @model_validator(mode="after")
    def validate_id_sets(self) -> RetrievalScenarioEvaluation:
        for field_name in (
            "relevant_artifact_ids",
            "returned_artifact_ids",
            "incompatible_artifact_ids",
        ):
            values = getattr(self, field_name)
            if len(set(values)) != len(values):
                raise ValueError(f"{field_name} must contain unique artifact IDs")
        if len(self.returned_artifact_ids) > self.k:
            raise ValueError("returned artifact IDs cannot exceed K")
        object.__setattr__(
            self,
            "relevant_artifact_ids",
            tuple(sorted(self.relevant_artifact_ids)),
        )
        object.__setattr__(
            self,
            "incompatible_artifact_ids",
            tuple(sorted(self.incompatible_artifact_ids)),
        )
        return self

    @computed_field(return_type=float)
    @property
    def recall_at_k(self) -> float:
        """Relevant identities returned in the bounded observation divided by all relevant IDs."""
        relevant = set(self.relevant_artifact_ids)
        return len(relevant.intersection(self.returned_artifact_ids)) / len(relevant)

    @computed_field(return_type=float)
    @property
    def precision_at_k(self) -> float:
        """Relevant identities divided by returned identities; empty results have zero precision."""
        if not self.returned_artifact_ids:
            return 0.0
        relevant = set(self.relevant_artifact_ids)
        return len(relevant.intersection(self.returned_artifact_ids)) / len(
            self.returned_artifact_ids
        )

    @computed_field(return_type=tuple[EvaluationIdentifier, ...])
    @property
    def incompatibility_violations(self) -> tuple[str, ...]:
        """Known-incompatible identities that escaped into the qualifying top-K output."""
        incompatible = set(self.incompatible_artifact_ids)
        return tuple(sorted(incompatible.intersection(self.returned_artifact_ids)))

    @classmethod
    def from_ranked_ids(
        cls,
        *,
        scenario_id: str,
        k: int,
        relevant_artifact_ids: tuple[str, ...],
        returned_artifact_ids: tuple[str, ...],
        incompatible_artifact_ids: tuple[str, ...] = (),
        reproducible: bool,
        latency_seconds: float,
    ) -> RetrievalScenarioEvaluation:
        """Build an observation without accepting caller-supplied derived metric values."""
        return cls(
            scenario_id=scenario_id,
            k=k,
            relevant_artifact_ids=relevant_artifact_ids,
            returned_artifact_ids=returned_artifact_ids,
            incompatible_artifact_ids=incompatible_artifact_ids,
            reproducible=reproducible,
            latency_seconds=latency_seconds,
        )


class RetrievalEvaluationReport(BaseModel):
    """Macro metrics and resource observations for one immutable versioned suite run."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    suite_version: Annotated[
        str,
        Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$"),
    ]
    k: int = Field(ge=1, le=_MAX_K)
    scenarios: tuple[RetrievalScenarioEvaluation, ...] = Field(
        min_length=1, max_length=_MAX_EVALUATION_ITEMS
    )
    index_size_bytes: int = Field(ge=0, le=_MAX_INDEX_SIZE_BYTES)

    @model_validator(mode="after")
    def validate_scenarios(self) -> RetrievalEvaluationReport:
        scenario_ids = tuple(scenario.scenario_id for scenario in self.scenarios)
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("evaluation scenario IDs must be unique")
        if any(scenario.k != self.k for scenario in self.scenarios):
            raise ValueError("every evaluation scenario must use the report K")
        object.__setattr__(
            self,
            "scenarios",
            tuple(sorted(self.scenarios, key=lambda scenario: scenario.scenario_id)),
        )
        return self

    @computed_field(return_type=float)
    @property
    def recall_at_k(self) -> float:
        return sum(scenario.recall_at_k for scenario in self.scenarios) / len(self.scenarios)

    @computed_field(return_type=float)
    @property
    def precision_at_k(self) -> float:
        return sum(scenario.precision_at_k for scenario in self.scenarios) / len(self.scenarios)

    @computed_field(return_type=int)
    @property
    def incompatibility_violations(self) -> int:
        return sum(len(scenario.incompatibility_violations) for scenario in self.scenarios)

    @computed_field(return_type=bool)
    @property
    def deterministic_reproducibility(self) -> bool:
        return all(scenario.reproducible for scenario in self.scenarios)

    @computed_field(return_type=float)
    @property
    def latency_seconds(self) -> float:
        return sum(scenario.latency_seconds for scenario in self.scenarios)

    @computed_field(return_type=float)
    @property
    def maximum_scenario_latency_seconds(self) -> float:
        return max(scenario.latency_seconds for scenario in self.scenarios)

    @classmethod
    def from_scenarios(
        cls,
        *,
        suite_version: str,
        k: int,
        scenarios: tuple[RetrievalScenarioEvaluation, ...],
        index_size_bytes: int,
    ) -> RetrievalEvaluationReport:
        """Build a report whose aggregate metrics cannot be supplied or forged by callers."""
        return cls(
            suite_version=suite_version,
            k=k,
            scenarios=scenarios,
            index_size_bytes=index_size_bytes,
        )


__all__ = ["RetrievalEvaluationReport", "RetrievalScenarioEvaluation"]
