"""Bounded orchestration for learning one local file or directory."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sedna.knowledge.inventory import SourceCandidate, discover_sources
from sedna.knowledge.pipeline import IngestionPipeline
from sedna.knowledge.repository import CanonicalKnowledgeRepository
from sedna.knowledge.retrieval.maintenance import (
    MaintenanceIssue,
    MaintenanceIssueCode,
    RetrievalMaintenanceReport,
    RetrievalMaintenanceService,
)
from sedna.knowledge.semantic import (
    CANONICAL_COMPILATION_FAILURE_MESSAGES,
    SemanticIngestionService,
)

_MAX_OUTCOMES = 100_000
_MAX_REASON_CODES = 32
_MAX_MESSAGES = 32
_MAX_FAILURE_CODES = 16
_MAX_SOURCE_ID_LENGTH = 512
_MAX_SOURCE_PATH_LENGTH = 4096
_MAX_SOURCES = 100_000
_SAFE_REASON_CODES = frozenset(CANONICAL_COMPILATION_FAILURE_MESSAGES)

BoundedSourceId = Annotated[str, Field(min_length=1, max_length=_MAX_SOURCE_ID_LENGTH)]
BoundedSourcePath = Annotated[str, Field(min_length=1, max_length=_MAX_SOURCE_PATH_LENGTH)]
BoundedReasonCode = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$"),
]
BoundedMessage = Annotated[str, Field(min_length=1, max_length=2048)]


class LearningDisposition(StrEnum):
    """The one terminal source disposition emitted by a learning run."""

    VERIFIED = "verified"
    SEMANTIC_QUARANTINED = "semantic_quarantined"
    EXCLUDED = "excluded"
    FOUNDATION_QUARANTINED = "foundation_quarantined"
    UNCHANGED = "unchanged"
    FAILED = "failed"


class LearningSourceOutcome(BaseModel):
    """Safe, source-scoped result of deterministic and semantic processing."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_id: BoundedSourceId
    disposition: LearningDisposition
    reason_codes: tuple[BoundedReasonCode, ...] = Field(default=(), max_length=_MAX_REASON_CODES)
    messages: tuple[BoundedMessage, ...] = Field(default=(), max_length=_MAX_MESSAGES)

    @field_validator("reason_codes", "messages")
    @classmethod
    def require_stable_unique_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if len(normalized) != len(values):
            raise ValueError("learning outcome values must be unique")
        return normalized

    @model_validator(mode="after")
    def require_safe_shape(self) -> Self:
        if self.disposition is LearningDisposition.FAILED and not self.reason_codes:
            raise ValueError("failed learning outcomes require a safe reason code")
        if self.disposition is not LearningDisposition.FAILED and self.messages:
            raise ValueError("only failed learning outcomes may carry canonical messages")
        return self


class LearningRunReport(BaseModel):
    """A frozen report with derived source counters and no source content."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    source_path: BoundedSourcePath
    outcomes: tuple[LearningSourceOutcome, ...] = Field(default=(), max_length=_MAX_OUTCOMES)
    index_report: RetrievalMaintenanceReport | None = None
    failure_codes: tuple[BoundedReasonCode, ...] = Field(default=(), max_length=_MAX_FAILURE_CODES)
    verified_source_count: int = Field(default=0, ge=0, le=_MAX_OUTCOMES)
    semantic_quarantined_source_count: int = Field(default=0, ge=0, le=_MAX_OUTCOMES)
    excluded_source_count: int = Field(default=0, ge=0, le=_MAX_OUTCOMES)
    foundation_quarantined_source_count: int = Field(default=0, ge=0, le=_MAX_OUTCOMES)
    unchanged_source_count: int = Field(default=0, ge=0, le=_MAX_OUTCOMES)
    failed_source_count: int = Field(default=0, ge=0, le=_MAX_OUTCOMES)
    failed: bool = False

    @model_validator(mode="before")
    @classmethod
    def populate_missing_derived_values(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = value.copy()
        outcomes = payload.get("outcomes", ())
        counts = _counts_for(outcomes)
        for field, count in counts.items():
            payload.setdefault(field, count)
        index_report = payload.get("index_report")
        index_failed = isinstance(index_report, dict) and index_report.get("succeeded") is False
        if isinstance(index_report, RetrievalMaintenanceReport):
            index_failed = not index_report.succeeded
        payload.setdefault(
            "failed",
            bool(payload.get("failure_codes")) or counts["failed_source_count"] > 0 or index_failed,
        )
        return payload

    @field_validator("outcomes")
    @classmethod
    def sort_unique_outcomes(
        cls, values: tuple[LearningSourceOutcome, ...]
    ) -> tuple[LearningSourceOutcome, ...]:
        ordered = tuple(sorted(values, key=lambda item: item.source_id))
        if len({item.source_id for item in ordered}) != len(ordered):
            raise ValueError("learning outcomes must have unique source IDs")
        return ordered

    @field_validator("failure_codes")
    @classmethod
    def sort_unique_failure_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if len(normalized) != len(values):
            raise ValueError("learning report failure codes must be unique")
        return normalized

    @model_validator(mode="after")
    def require_exact_derived_values(self) -> Self:
        expected = _counts_for(self.outcomes)
        for field, count in expected.items():
            if getattr(self, field) != count:
                raise ValueError(f"{field} must equal the outcomes-derived count")
        expected_failed = (
            bool(self.failure_codes)
            or self.failed_source_count > 0
            or bool(self.index_report is not None and not self.index_report.succeeded)
        )
        if self.failed != expected_failed:
            raise ValueError("failed must equal the derived learning run status")
        return self

    def model_copy(
        self,
        *,
        update: dict[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Keep Pydantic's copy API from bypassing frozen derived report invariants."""
        del deep
        payload = self.model_dump(mode="python")
        if update:
            payload.update(update)
        return type(self).model_validate(payload)


class DocumentLearningService:
    """Compose deterministic preparation, semantic compilation, and index rebuilds."""

    def __init__(
        self,
        *,
        knowledge_root: Path,
        semantic_service: SemanticIngestionService,
        maintenance: RetrievalMaintenanceService,
        repository: CanonicalKnowledgeRepository | None = None,
    ) -> None:
        self.knowledge_root = Path(knowledge_root)
        self.semantic_service = semantic_service
        self._maintenance = maintenance
        self._repository = repository

    def learn(self, source_path: Path) -> LearningRunReport:
        """Learn a confined local source selection without exposing exceptions or source text."""
        requested = Path(source_path)
        try:
            report_path = str(requested.resolve(strict=False))
        except (OSError, ValueError):
            return LearningRunReport(
                source_path="<invalid-source-path>",
                failure_codes=("invalid_source_path",),
            )
        if len(report_path) > _MAX_SOURCE_PATH_LENGTH:
            report_path = "<source-path-too-long>"
        try:
            root, only_relative_path = _resolve_learning_root(requested)
        except (OSError, ValueError):
            return LearningRunReport(
                source_path=report_path,
                failure_codes=("invalid_source_path",),
            )

        outcomes: list[LearningSourceOutcome] = []
        failure_codes: list[str] = []
        transition_barrier = getattr(self._maintenance, "barrier_source_revision", None)
        if not callable(transition_barrier):
            transition_barrier = getattr(
                self._maintenance,
                "invalidate_source_projection",
                None,
            )
        try:
            with IngestionPipeline(
                root,
                self.knowledge_root,
                repository=self._repository,
                before_foundation_revision_change=(
                    transition_barrier if callable(transition_barrier) else None
                ),
            ) as pipeline:
                try:
                    candidates = _select_candidates(discover_sources(root), only_relative_path)
                except (OSError, ValueError):
                    failure_codes.append("source_inventory_failed")
                else:
                    if len(candidates) > _MAX_SOURCES:
                        return LearningRunReport(
                            source_path=report_path,
                            failure_codes=("source_count_exceeded",),
                        )
                    if not candidates:
                        try:
                            root_status = os.stat(root, follow_symlinks=False)
                        except OSError:
                            failure_codes.append("source_inventory_failed")
                        else:
                            failure_codes.append(
                                "no_sources"
                                if stat.S_ISDIR(root_status.st_mode)
                                else "source_inventory_failed"
                            )
                    for candidate in candidates:
                        self._learn_candidate(pipeline, candidate, outcomes)
        except Exception:
            failure_codes.append("source_root_unavailable")

        return LearningRunReport(
            source_path=report_path,
            outcomes=tuple(outcomes),
            failure_codes=tuple(failure_codes),
            index_report=self._rebuild_safely(),
        )

    def _learn_candidate(
        self,
        pipeline: IngestionPipeline,
        candidate: SourceCandidate,
        outcomes: list[LearningSourceOutcome],
    ) -> None:
        prepared: object | None = None
        try:
            prepared = pipeline.prepare(candidate)
            if prepared is None:
                if pipeline.last_outcome == "unchanged":
                    prepared = self._reprepare_if_semantic_stale(pipeline, candidate)
                    if prepared is not None:
                        semantic = self.semantic_service.compile_and_store(prepared)
                        self._invalidate_failed_source_projection(candidate, semantic)
                        outcomes.append(_semantic_outcome(candidate, semantic))
                        return
                    if pipeline.last_outcome == "accepted":
                        outcomes.append(
                            LearningSourceOutcome(
                                source_id=candidate.source_id,
                                disposition=LearningDisposition.UNCHANGED,
                            )
                        )
                        return
                outcomes.append(_foundation_outcome(candidate, pipeline.last_outcome))
                return
            semantic = self.semantic_service.compile_and_store(prepared)
            self._invalidate_failed_source_projection(candidate, semantic)
            outcomes.append(_semantic_outcome(candidate, semantic))
        except Exception:
            if prepared is not None:
                invalidate = getattr(self.semantic_service, "invalidate_failed_result", None)
                if callable(invalidate):
                    with suppress(Exception):
                        invalidate(prepared)
                self._invalidate_source_projection(candidate)
            outcomes.append(_failed_outcome(candidate, "source_processing_failed"))

    def _reprepare_if_semantic_stale(
        self,
        pipeline: IngestionPipeline,
        candidate: SourceCandidate,
    ) -> object | None:
        """Return one refreshed source only when its semantic state is stale."""
        is_current = getattr(self.semantic_service, "is_current", None)
        if not callable(is_current):
            return None
        prepared = pipeline.prepare(candidate, force_reprepare=True)
        if prepared is None:
            return None
        if is_current(prepared):
            return None
        return prepared

    def _rebuild_safely(self) -> RetrievalMaintenanceReport:
        try:
            return self._maintenance.rebuild()
        except Exception:
            return RetrievalMaintenanceReport(
                operation="rebuild",
                succeeded=False,
                elapsed_seconds=0.0,
                issues=(
                    MaintenanceIssue(
                        code=MaintenanceIssueCode.INDEX_REBUILD_FAILED,
                        message="retrieval index rebuild failed",
                    ),
                ),
            )

    def _invalidate_failed_source_projection(
        self,
        candidate: SourceCandidate,
        semantic: object,
    ) -> None:
        """Remove a failed source from the live disposable projection before rebuilding."""
        if getattr(semantic, "disposition", None) != "failed":
            return
        self._invalidate_source_projection(candidate)

    def _invalidate_source_projection(self, candidate: SourceCandidate) -> None:
        """Fail closed the source's disposable projection after semantic uncertainty."""
        invalidate = getattr(self._maintenance, "invalidate_source_projection", None)
        if not callable(invalidate):
            return
        try:
            invalidate(candidate.source_id)
        except Exception:
            # A maintenance implementation outside this package may not fail closed itself.
            # The semantic outcome remains safely failed and the normal rebuild is still attempted.
            return


def _resolve_learning_root(source_path: Path) -> tuple[Path, str | None]:
    """Resolve one physical directory or regular source file before inventory starts."""
    try:
        status = os.lstat(source_path)
    except OSError as error:
        raise ValueError("source path is unavailable") from error
    if stat.S_ISLNK(status.st_mode):
        raise ValueError("source path must not be a symlink")
    resolved = source_path.resolve(strict=True)
    if stat.S_ISDIR(status.st_mode):
        return resolved, None
    if not stat.S_ISREG(status.st_mode) or resolved.suffix.casefold() not in {".md", ".pdf"}:
        raise ValueError("source path must be a supported regular file or directory")
    return resolved.parent, resolved.relative_to(resolved.parent).as_posix()


def _select_candidates(
    candidates: tuple[SourceCandidate, ...],
    only_relative_path: str | None,
) -> tuple[SourceCandidate, ...]:
    if only_relative_path is None:
        return candidates
    return tuple(
        candidate for candidate in candidates if candidate.relative_path == only_relative_path
    )


def _foundation_outcome(
    candidate: SourceCandidate,
    pipeline_outcome: str | None,
) -> LearningSourceOutcome:
    disposition = {
        "excluded": LearningDisposition.EXCLUDED,
        "quarantined": LearningDisposition.FOUNDATION_QUARANTINED,
        "unchanged": LearningDisposition.UNCHANGED,
    }.get(pipeline_outcome)
    if disposition is None:
        return _failed_outcome(candidate, "source_processing_failed")
    return LearningSourceOutcome(source_id=candidate.source_id, disposition=disposition)


def _semantic_outcome(candidate: SourceCandidate, semantic: object) -> LearningSourceOutcome:
    disposition = getattr(semantic, "disposition", None)
    if disposition == "verified":
        target = LearningDisposition.VERIFIED
    elif disposition == "unchanged":
        target = LearningDisposition.UNCHANGED
    elif disposition == "quarantined":
        target = LearningDisposition.SEMANTIC_QUARANTINED
    elif disposition == "failed":
        failure_code = getattr(semantic, "failure_code", None)
        code = failure_code if failure_code in _SAFE_REASON_CODES else "semantic_compilation_failed"
        message = CANONICAL_COMPILATION_FAILURE_MESSAGES.get(failure_code)
        return LearningSourceOutcome(
            source_id=candidate.source_id,
            disposition=LearningDisposition.FAILED,
            reason_codes=(code,),
            messages=(message,) if message is not None else (),
        )
    else:
        return _failed_outcome(candidate, "semantic_compilation_failed")
    reason_codes = ()
    if target is LearningDisposition.SEMANTIC_QUARANTINED:
        quarantine = getattr(semantic, "quarantine", None)
        codes = getattr(quarantine, "reason_codes", ())
        if isinstance(codes, tuple) and all(
            code in _SAFE_REASON_CODES or _is_safe_reason(code) for code in codes
        ):
            reason_codes = codes
    return LearningSourceOutcome(
        source_id=candidate.source_id,
        disposition=target,
        reason_codes=reason_codes,
    )


def _failed_outcome(candidate: SourceCandidate, reason_code: str) -> LearningSourceOutcome:
    return LearningSourceOutcome(
        source_id=candidate.source_id,
        disposition=LearningDisposition.FAILED,
        reason_codes=(reason_code,),
        messages=("The source could not be processed safely.",),
    )


def _is_safe_reason(value: object) -> bool:
    return isinstance(value, str) and value.replace("_", "").isalnum() and value == value.casefold()


def _counts_for(outcomes: Any) -> dict[str, int]:
    counts = dict.fromkeys(_COUNTER_FIELDS.values(), 0)
    if not isinstance(outcomes, (list, tuple)):
        return counts
    for outcome in outcomes:
        disposition = (
            outcome.disposition
            if isinstance(outcome, LearningSourceOutcome)
            else outcome.get("disposition")
            if isinstance(outcome, dict)
            else None
        )
        try:
            parsed = LearningDisposition(disposition)
        except (TypeError, ValueError):
            continue
        counts[_COUNTER_FIELDS[parsed]] += 1
    return counts


_COUNTER_FIELDS = {
    LearningDisposition.VERIFIED: "verified_source_count",
    LearningDisposition.SEMANTIC_QUARANTINED: "semantic_quarantined_source_count",
    LearningDisposition.EXCLUDED: "excluded_source_count",
    LearningDisposition.FOUNDATION_QUARANTINED: "foundation_quarantined_source_count",
    LearningDisposition.UNCHANGED: "unchanged_source_count",
    LearningDisposition.FAILED: "failed_source_count",
}


__all__ = [
    "DocumentLearningService",
    "LearningDisposition",
    "LearningRunReport",
    "LearningSourceOutcome",
]
