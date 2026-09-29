"""Strict shared contracts for provenance and knowledge classification."""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from sedna.knowledge.schema.context import ApplicabilityContext, EpistemicAssessment


def _reject_final_flag_material(value: str) -> str:
    from sedna.knowledge.parsing.sanitize import sanitize_searchable_text

    if sanitize_searchable_text(value, (value,)) != value:
        raise ValueError("searchable text contains raw or encoded final flag material")
    return value


SearchableString = Annotated[str, AfterValidator(_reject_final_flag_material)]
SearchableNonEmptyString = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(_reject_final_flag_material),
]


class DocumentType(StrEnum):
    """The structural category of a source document."""

    LESSON = "lesson"
    MACHINE_WALKTHROUGH = "machine_walkthrough"
    CHALLENGE_WALKTHROUGH = "challenge_walkthrough"
    CHEATSHEET_REFERENCE = "cheatsheet_reference"
    EXTERNAL_STUB = "external_stub"
    EXCLUDED = "excluded"


class KnowledgeRole(StrEnum):
    """The epistemic lane occupied by an extracted record."""

    REFERENCE = "reference"
    CASE_STUDY = "case_study"
    NEGATIVE_CASE = "negative_case"


class ArtifactType(StrEnum):
    """The type of a canonical knowledge artifact."""

    CONCEPT = "concept"
    METHODOLOGY = "methodology"
    DECISION_RULE = "decision_rule"
    CASE = "case"
    CASE_STEP = "case_step"
    NEGATIVE_EVIDENCE = "negative_evidence"
    ANTI_PATTERN = "anti_pattern"
    CONSTRAINT = "constraint"
    EVIDENCE_INTERPRETATION = "evidence_interpretation"
    EXCEPTION = "exception"


class Origin(StrEnum):
    """How a record or field was obtained."""

    EXPLICIT = "explicit"
    INFERRED = "inferred"
    DERIVED = "derived"


class ReviewStatus(StrEnum):
    """The legacy human-review state retained for existing artifact callers."""

    AUTO_EXTRACTED = "auto_extracted"
    DRAFT = "draft"
    APPROVED = "approved"
    REJECTED = "rejected"


class VerificationStatus(StrEnum):
    """The current verification state of source-backed knowledge."""

    EXTRACTED = "extracted"
    VERIFIED = "verified"
    CORROBORATED = "corroborated"
    CONTESTED = "contested"
    DEPRECATED = "deprecated"
    REJECTED = "rejected"


def verification_from_legacy_review(status: ReviewStatus) -> VerificationStatus:
    """Translate a legacy review state without making it canonical metadata."""
    return {
        ReviewStatus.AUTO_EXTRACTED: VerificationStatus.EXTRACTED,
        ReviewStatus.DRAFT: VerificationStatus.EXTRACTED,
        ReviewStatus.APPROVED: VerificationStatus.VERIFIED,
        ReviewStatus.REJECTED: VerificationStatus.REJECTED,
    }[status]


class Generalizability(StrEnum):
    """The intended degree of transfer beyond a source environment."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceQuality(StrEnum):
    """The amount and reliability of usable source material."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    MINIMAL = "minimal"
    UNUSABLE = "unusable"


class IngestionStatus(StrEnum):
    """The disposition of a source in an ingestion run."""

    ACCEPTED = "accepted"
    EXCLUDED = "excluded"
    QUARANTINED = "quarantined"


class SourceLocation(BaseModel):
    """A precise, immutable source span or asset reference."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    page: int | None = Field(default=None, ge=1)
    section: SearchableNonEmptyString | None = None
    asset_path: SearchableNonEmptyString | None = None

    @model_validator(mode="after")
    def validate_location(self) -> SourceLocation:
        """Require one addressable location and a non-reversed line span."""
        if not any((self.start_line, self.page, self.section, self.asset_path)):
            raise ValueError("at least one source location must be provided")
        if self.start_line and self.end_line and self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class SourceRef(BaseModel):
    """An immutable reference to an exact location in a source file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str = Field(min_length=1)
    path: SearchableNonEmptyString
    location: SourceLocation


class ExtractionMetadata(BaseModel):
    """Version identifiers needed to reproduce a deterministic extraction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = Field(min_length=1)
    parser_id: str = Field(min_length=1)
    parser_version: str = Field(min_length=1)
    extractor_id: str = Field(min_length=1)
    extractor_version: str = Field(min_length=1)
    prompt_id: str | None = Field(default=None, min_length=1)
    prompt_version: str | None = Field(default=None, min_length=1)
    model_id: str | None = Field(default=None, min_length=1)
    model_version: str | None = Field(default=None, min_length=1)


class CanonicalArtifactMetadata(BaseModel):
    """Epistemic identity and provenance required on every canonical artifact."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_type: ArtifactType
    knowledge_role: KnowledgeRole
    origin: Origin
    applicability: ApplicabilityContext
    assessment: EpistemicAssessment
    source_refs: tuple[SourceRef, ...] = Field(min_length=1)
    extraction: ExtractionMetadata

    @model_validator(mode="before")
    @classmethod
    def migrate_legacy_epistemic_metadata(cls, value: Any) -> Any:
        """Map legacy review fields only when the canonical assessment is absent."""
        if not isinstance(value, dict):
            return value

        payload = value.copy()
        legacy_review_status = payload.pop("review_status", None)
        legacy_generalizability = payload.pop("generalizability", None)
        explicit_assessment = payload.get("assessment")

        if explicit_assessment is not None:
            cls._reject_legacy_metadata_disagreement(
                explicit_assessment,
                legacy_review_status,
                legacy_generalizability,
            )
            return payload

        if legacy_review_status is None and legacy_generalizability is None:
            return payload
        if legacy_review_status is None or legacy_generalizability is None:
            raise ValueError("legacy review_status and generalizability must be supplied together")
        legacy_review_status = ReviewStatus(legacy_review_status)
        legacy_generalizability = Generalizability(legacy_generalizability)

        source_refs = payload.get("source_refs", ())
        if not source_refs:
            return payload
        first_source_ref = source_refs[0]
        source_id = first_source_ref.source_id if isinstance(first_source_ref, SourceRef) else None
        if isinstance(first_source_ref, dict):
            source_id = first_source_ref.get("source_id")
        if not source_id:
            return payload

        from sedna.knowledge.schema.context import (
            ApplicabilityContext,
            EpistemicAssessment,
            ObservedOutcome,
        )

        payload.setdefault("applicability", ApplicabilityContext())
        payload["assessment"] = EpistemicAssessment(
            source_reliability=0.5,
            extraction_confidence=0.5,
            generalizability=legacy_generalizability,
            context_specificity=0.5,
            verification_status=verification_from_legacy_review(legacy_review_status),
            support_count=1,
            contradiction_count=0,
            observed_outcome=ObservedOutcome.INFORMATIONAL,
            independence_group=source_id,
        )
        return payload

    @staticmethod
    def _reject_legacy_metadata_disagreement(
        assessment: Any,
        legacy_review_status: Any,
        legacy_generalizability: Any,
    ) -> None:
        """Reject legacy values that conflict with explicit canonical assessment data."""
        if isinstance(assessment, BaseModel):
            verification_status = assessment.verification_status
            generalizability = assessment.generalizability
        elif isinstance(assessment, dict):
            verification_status = assessment.get("verification_status")
            generalizability = assessment.get("generalizability")
        else:
            return

        if (
            legacy_review_status is not None
            and verification_from_legacy_review(ReviewStatus(legacy_review_status))
            != verification_status
        ):
            raise ValueError("review_status conflicts with assessment.verification_status")
        if (
            legacy_generalizability is not None
            and Generalizability(legacy_generalizability) != generalizability
        ):
            raise ValueError("generalizability conflicts with assessment.generalizability")

    @property
    def review_status(self) -> ReviewStatus:
        """Expose the closest legacy review state for read-only compatibility."""
        return {
            VerificationStatus.EXTRACTED: ReviewStatus.DRAFT,
            VerificationStatus.VERIFIED: ReviewStatus.APPROVED,
            VerificationStatus.CORROBORATED: ReviewStatus.APPROVED,
            VerificationStatus.CONTESTED: ReviewStatus.DRAFT,
            VerificationStatus.DEPRECATED: ReviewStatus.DRAFT,
            VerificationStatus.REJECTED: ReviewStatus.REJECTED,
        }[self.assessment.verification_status]

    @property
    def generalizability(self) -> Generalizability:
        """Expose the canonical assessment value at its former metadata location."""
        return self.assessment.generalizability
