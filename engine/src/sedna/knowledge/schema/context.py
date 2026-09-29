"""Immutable applicability and epistemic contracts for knowledge artifacts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sedna.knowledge.schema.common import (
    Generalizability,
    Origin,
    SearchableNonEmptyString,
    SearchableString,
    SourceRef,
    VerificationStatus,
)


class ContextRelation(StrEnum):
    """How a context assertion affects applicability."""

    OBSERVED = "observed"
    REQUIRED = "required"
    COMPATIBLE = "compatible"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


class ObservedOutcome(StrEnum):
    """The outcome observed when a context was assessed."""

    SUCCESS = "success"
    FAILURE = "failure"
    MIXED = "mixed"
    INFORMATIONAL = "informational"
    NOT_APPLICABLE = "not_applicable"


class ContextAssertion(BaseModel):
    """A source-backed statement about one aspect of an environment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: SearchableString
    relation: ContextRelation
    origin: Origin
    confidence: float = Field(ge=0.0, le=1.0)
    source_refs: tuple[SourceRef, ...] = Field(min_length=1)


class ServiceContext(BaseModel):
    """A typed, source-backed service identity in an environment."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_type: SearchableNonEmptyString
    identity: ContextAssertion


class TypedContext(BaseModel):
    """Known applicability dimensions expressed with a stable shared vocabulary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    os_family: ContextAssertion | None = None
    os_version: ContextAssertion | None = None
    cpu_architecture: ContextAssertion | None = None
    execution_environment: ContextAssertion | None = None
    system_role: ContextAssertion | None = None
    identity_context: ContextAssertion | None = None
    initial_access: ContextAssertion | None = None
    network_position: ContextAssertion | None = None
    observation_date: ContextAssertion | None = None
    services: tuple[ServiceContext, ...] = ()
    privileges: tuple[ContextAssertion, ...] = ()
    security_controls: tuple[ContextAssertion, ...] = ()


class ContextFacet(BaseModel):
    """An extensible, namespaced applicability dimension."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: SearchableNonEmptyString
    key: SearchableNonEmptyString
    assertion: ContextAssertion


class ApplicabilityContext(BaseModel):
    """Typed and extensible facts that scope an artifact's applicability."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    typed_context: TypedContext = Field(default_factory=TypedContext)
    facets: tuple[ContextFacet, ...] = ()

    @model_validator(mode="after")
    def validate_unique_context_entries(self) -> ApplicabilityContext:
        """Prevent duplicate typed service identities and equivalent facets."""
        service_identities = {
            (service.service_type, service.identity.value, service.identity.relation)
            for service in self.typed_context.services
        }
        if len(service_identities) != len(self.typed_context.services):
            raise ValueError("typed service identities must be unique")

        facet_entries = {
            (facet.namespace, facet.key, facet.assertion.value, facet.assertion.relation)
            for facet in self.facets
        }
        if len(facet_entries) != len(self.facets):
            raise ValueError("context facets must be unique")
        return self


class EpistemicAssessment(BaseModel):
    """Evidence quality and outcome information for a knowledge assertion."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_reliability: float = Field(ge=0.0, le=1.0)
    extraction_confidence: float = Field(ge=0.0, le=1.0)
    generalizability: Generalizability
    context_specificity: float = Field(ge=0.0, le=1.0)
    verification_status: VerificationStatus
    support_count: int = Field(default=1, ge=0)
    contradiction_count: int = Field(default=0, ge=0)
    observed_outcome: ObservedOutcome
    freshness_observed_at: SearchableString | None = None
    independence_group: SearchableNonEmptyString
