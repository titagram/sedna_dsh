"""Fail-closed rebuild and parity audit of disposable retrieval projections."""

from __future__ import annotations

import json
import math
import time
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sedna.knowledge.repository import (
    CanonicalKnowledgeRepository,
    SemanticBundleEnumerationError,
    SemanticSnapshotChangedError,
)
from sedna.knowledge.retrieval.models import (
    IndexAudit,
    IndexedSourceState,
    IndexStateSnapshot,
    RetrievalIndex,
)
from sedna.knowledge.retrieval.projection import project_source_state
from sedna.knowledge.schema import SemanticKnowledgeBundle

_MAX_ISSUES = 32
_MAX_IDENTIFIERS_PER_ISSUE = 16
_MAX_SOURCES = 100_000
_MAX_ARTIFACTS = 10_000_000
_MAX_ELAPSED_SECONDS = 7 * 24 * 60 * 60

BoundedCount = Annotated[int, Field(ge=0, le=_MAX_ARTIFACTS)]
BoundedMessage = Annotated[str, Field(min_length=1, max_length=2048)]
BoundedIdentifier = Annotated[str, Field(min_length=1, max_length=512)]


class MaintenanceIssueCode(StrEnum):
    """Closed, actionable reasons a retrieval projection needs attention."""

    CANONICAL_REPOSITORY_INVALID = "canonical_repository_invalid"
    CANONICAL_REPOSITORY_CHANGED = "canonical_repository_changed"
    INDEX_REBUILD_FAILED = "index_rebuild_failed"
    INDEX_UNAVAILABLE = "index_unavailable"
    INDEX_INTEGRITY_FAILURE = "index_integrity_failure"
    MISSING_SOURCE_PROJECTION = "missing_source_projection"
    STALE_SOURCE_PROJECTION = "stale_source_projection"
    ORPHAN_SOURCE_PROJECTION = "orphan_source_projection"


class MaintenanceIssue(BaseModel):
    """One bounded maintenance finding with sampled stable identities."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    code: MaintenanceIssueCode
    message: BoundedMessage
    source_ids: tuple[BoundedIdentifier, ...] = Field(
        default=(), max_length=_MAX_IDENTIFIERS_PER_ISSUE
    )

    @field_validator("source_ids")
    @classmethod
    def normalize_source_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(values)))
        if len(normalized) != len(values):
            raise ValueError("maintenance issue source IDs must be unique")
        return normalized


class RetrievalMaintenanceReport(BaseModel):
    """Typed bounded outcome for one rebuild or parity audit operation."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    operation: Literal["rebuild", "audit"]
    succeeded: bool
    canonical_source_count: BoundedCount = 0
    canonical_artifact_count: BoundedCount = 0
    indexed_source_count: BoundedCount = 0
    indexed_artifact_count: BoundedCount = 0
    missing_source_count: BoundedCount = 0
    stale_source_count: BoundedCount = 0
    orphan_source_count: BoundedCount = 0
    missing_artifact_count: BoundedCount = 0
    stale_artifact_count: BoundedCount = 0
    orphan_artifact_count: BoundedCount = 0
    elapsed_seconds: float = Field(ge=0.0, le=_MAX_ELAPSED_SECONDS)
    index_audit: IndexAudit | None = None
    issues: tuple[MaintenanceIssue, ...] = Field(default=(), max_length=_MAX_ISSUES)
    rebuild_required: bool = False

    @field_validator("elapsed_seconds")
    @classmethod
    def require_finite_elapsed(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("maintenance elapsed time must be finite")
        return value

    @field_validator("issues")
    @classmethod
    def normalize_issues(
        cls,
        values: tuple[MaintenanceIssue, ...],
    ) -> tuple[MaintenanceIssue, ...]:
        ordered = tuple(
            sorted(values, key=lambda issue: (issue.code.value, issue.source_ids, issue.message))
        )
        if len(set(ordered)) != len(ordered):
            raise ValueError("maintenance issues must be unique")
        return ordered

    @model_validator(mode="after")
    def derive_rebuild_requirement(self) -> RetrievalMaintenanceReport:
        required = bool(
            not self.succeeded
            or self.issues
            or (self.index_audit is not None and self.index_audit.rebuild_required)
            or self.canonical_source_count != self.indexed_source_count
            or self.canonical_artifact_count != self.indexed_artifact_count
            or any(
                (
                    self.missing_source_count,
                    self.stale_source_count,
                    self.orphan_source_count,
                    self.missing_artifact_count,
                    self.stale_artifact_count,
                    self.orphan_artifact_count,
                )
            )
        )
        object.__setattr__(self, "rebuild_required", required)
        return self


@dataclass(frozen=True, slots=True)
class RetrievalMaintenanceService:
    """Rebuild and compare a disposable index against canonical verified bundles."""

    repository: CanonicalKnowledgeRepository
    index: RetrievalIndex

    def rebuild(self) -> RetrievalMaintenanceReport:
        """Replace the index only after the full canonical corpus validates."""
        started = time.perf_counter()
        try:
            bundles, canonical_states, revision = self._canonical_snapshot()
        except SemanticBundleEnumerationError as error:
            return self._poison_failed_rebuild(self._canonical_failure("rebuild", started, error))
        except Exception:
            return self._poison_failed_rebuild(
                self._failure(
                    "rebuild",
                    started,
                    MaintenanceIssueCode.CANONICAL_REPOSITORY_INVALID,
                    "canonical semantic repository enumeration failed",
                )
            )

        try:
            self.index.rebuild(
                bundles,
                precommit_guard=lambda: self.repository.semantic_snapshot_guard(revision),
            )
        except SemanticSnapshotChangedError:
            return self._poison_failed_rebuild(
                self._failure(
                    "rebuild",
                    started,
                    MaintenanceIssueCode.CANONICAL_REPOSITORY_CHANGED,
                    "canonical semantic sources changed before index commit; prior index retained",
                    canonical_source_count=len(canonical_states),
                    canonical_artifact_count=sum(
                        state.artifact_count for state in canonical_states.values()
                    ),
                )
            )
        except Exception:
            return self._poison_failed_rebuild(
                self._failure(
                    "rebuild",
                    started,
                    MaintenanceIssueCode.INDEX_REBUILD_FAILED,
                    "retrieval index rebuild failed and the previous projection was retained",
                    canonical_source_count=len(canonical_states),
                    canonical_artifact_count=sum(
                        state.artifact_count for state in canonical_states.values()
                    ),
                )
            )
        report = self._audit(operation="rebuild", started=started)
        if not report.succeeded or report.rebuild_required:
            return self._poison_failed_rebuild(report)
        return report

    def audit(self) -> RetrievalMaintenanceReport:
        """Cross-check canonical source identity and projection parity without mutation."""
        return self._audit(operation="audit", started=time.perf_counter())

    def invalidate_source_projection(self, source_id: str) -> bool:
        """Delete and verify one stale projection, closing an unprovable index fail-closed."""
        try:
            self.index.delete_source(source_id)
            snapshot = _strict_index_snapshot(self.index.snapshot_state())
            if any(state.source_id == source_id for state in snapshot.source_states):
                raise ValueError("source projection remained after invalidation")
            return True
        except Exception:
            self.index.mark_unavailable()
            with suppress(Exception):
                self.index.close()
            return False

    def barrier_source_revision(self, source_id: str) -> bool:
        """Prove absence or persist a rebuildable global read barrier."""
        try:
            self.index.delete_source(source_id)
            snapshot = _strict_index_snapshot(self.index.snapshot_state())
            if any(state.source_id == source_id for state in snapshot.source_states):
                raise ValueError("source projection remained after revision barrier")
            return True
        except Exception:
            try:
                self.index.mark_rebuild_required()
                return True
            except Exception:
                with suppress(Exception):
                    self.index.mark_unavailable()
                with suppress(Exception):
                    self.index.close()
            return False

    def _poison_failed_rebuild(
        self,
        report: RetrievalMaintenanceReport,
    ) -> RetrievalMaintenanceReport:
        with suppress(Exception):
            self.index.mark_unavailable()
        return report

    def _audit(
        self,
        *,
        operation: Literal["rebuild", "audit"],
        started: float,
    ) -> RetrievalMaintenanceReport:
        try:
            _, canonical_states, _ = self._canonical_snapshot()
        except SemanticBundleEnumerationError as error:
            return self._canonical_failure(operation, started, error)
        except Exception:
            return self._failure(
                operation,
                started,
                MaintenanceIssueCode.CANONICAL_REPOSITORY_INVALID,
                "canonical semantic repository enumeration failed",
            )

        try:
            index_snapshot = _strict_index_snapshot(self.index.snapshot_state())
        except Exception:
            return self._failure(
                operation,
                started,
                MaintenanceIssueCode.INDEX_UNAVAILABLE,
                "retrieval index audit or source-state enumeration failed",
                canonical_source_count=len(canonical_states),
                canonical_artifact_count=sum(
                    state.artifact_count for state in canonical_states.values()
                ),
            )

        try:
            _, latest_canonical_states, _ = self._canonical_snapshot()
        except SemanticBundleEnumerationError as error:
            return self._canonical_failure(operation, started, error)
        except Exception:
            return self._failure(
                operation,
                started,
                MaintenanceIssueCode.CANONICAL_REPOSITORY_INVALID,
                "canonical semantic repository enumeration failed",
            )
        canonical_changed = canonical_states != latest_canonical_states
        canonical_states = latest_canonical_states
        index_audit = index_snapshot.audit
        indexed_states = {state.source_id: state for state in index_snapshot.source_states}

        missing_ids = tuple(sorted(canonical_states.keys() - indexed_states.keys()))
        orphan_ids = tuple(sorted(indexed_states.keys() - canonical_states.keys()))
        stale_ids = tuple(
            source_id
            for source_id in sorted(canonical_states.keys() & indexed_states.keys())
            if canonical_states[source_id] != indexed_states[source_id]
        )
        missing_artifact_ids: set[str] = set()
        stale_artifact_ids: set[str] = set()
        orphan_artifact_ids: set[str] = set(index_snapshot.unowned_artifact_ids)
        for source_id in missing_ids:
            missing_artifact_ids.update(
                artifact.artifact_id for artifact in canonical_states[source_id].artifacts
            )
        for source_id in orphan_ids:
            orphan_artifact_ids.update(
                artifact.artifact_id for artifact in indexed_states[source_id].artifacts
            )
        for source_id in canonical_states.keys() & indexed_states.keys():
            canonical_artifacts = {
                artifact.artifact_id: artifact for artifact in canonical_states[source_id].artifacts
            }
            indexed_artifacts = {
                artifact.artifact_id: artifact for artifact in indexed_states[source_id].artifacts
            }
            missing_artifact_ids.update(canonical_artifacts.keys() - indexed_artifacts.keys())
            orphan_artifact_ids.update(indexed_artifacts.keys() - canonical_artifacts.keys())
            stale_artifact_ids.update(
                artifact_id
                for artifact_id in canonical_artifacts.keys() & indexed_artifacts.keys()
                if canonical_artifacts[artifact_id] != indexed_artifacts[artifact_id]
            )
        issues: list[MaintenanceIssue] = []
        if canonical_changed:
            issues.append(
                MaintenanceIssue(
                    code=MaintenanceIssueCode.CANONICAL_REPOSITORY_CHANGED,
                    message=(
                        "canonical semantic sources changed during the audit; rebuild from the "
                        "latest complete snapshot"
                    ),
                )
            )
        if index_audit.rebuild_required:
            issues.append(
                MaintenanceIssue(
                    code=MaintenanceIssueCode.INDEX_INTEGRITY_FAILURE,
                    message="the disposable retrieval index failed its internal integrity audit",
                )
            )
        issues.extend(
            issue
            for issue in (
                _parity_issue(
                    MaintenanceIssueCode.MISSING_SOURCE_PROJECTION,
                    "canonical sources are missing from the retrieval projection",
                    missing_ids,
                ),
                _parity_issue(
                    MaintenanceIssueCode.STALE_SOURCE_PROJECTION,
                    "retrieval source hashes, artifact counts, or projection digests are stale",
                    stale_ids,
                ),
                _parity_issue(
                    MaintenanceIssueCode.ORPHAN_SOURCE_PROJECTION,
                    "retrieval projections exist without a canonical verified source",
                    orphan_ids,
                ),
            )
            if issue is not None
        )

        return RetrievalMaintenanceReport(
            operation=operation,
            succeeded=True,
            canonical_source_count=len(canonical_states),
            canonical_artifact_count=sum(
                state.artifact_count for state in canonical_states.values()
            ),
            indexed_source_count=len(indexed_states),
            indexed_artifact_count=index_audit.artifact_count,
            missing_source_count=len(missing_ids),
            stale_source_count=len(stale_ids),
            orphan_source_count=len(orphan_ids),
            missing_artifact_count=len(missing_artifact_ids),
            stale_artifact_count=len(stale_artifact_ids),
            orphan_artifact_count=len(orphan_artifact_ids),
            elapsed_seconds=_elapsed(started),
            index_audit=index_audit,
            issues=tuple(issues),
        )

    def _canonical_snapshot(
        self,
    ) -> tuple[
        tuple[SemanticKnowledgeBundle, ...],
        dict[str, IndexedSourceState],
        str,
    ]:
        snapshot = self.repository.semantic_bundle_snapshot()
        bundles = snapshot.bundles
        if len(bundles) > _MAX_SOURCES:
            raise ValueError("canonical semantic source count exceeds the maintenance bound")
        states: dict[str, IndexedSourceState] = {}
        artifact_count = 0
        for bundle in bundles:
            state = project_source_state(bundle)
            if state.source_id in states:
                raise ValueError("canonical semantic source IDs must be unique")
            states[state.source_id] = state
            artifact_count += state.artifact_count
            if artifact_count > _MAX_ARTIFACTS:
                raise ValueError("canonical artifact count exceeds the maintenance bound")
        return bundles, states, snapshot.revision

    @staticmethod
    def _canonical_failure(
        operation: Literal["rebuild", "audit"],
        started: float,
        error: SemanticBundleEnumerationError,
    ) -> RetrievalMaintenanceReport:
        return RetrievalMaintenanceService._failure(
            operation,
            started,
            MaintenanceIssueCode.CANONICAL_REPOSITORY_INVALID,
            "a canonical semantic source is corrupt, incomplete, unsafe, or stale",
            source_ids=(error.source_id,),
        )

    @staticmethod
    def _failure(
        operation: Literal["rebuild", "audit"],
        started: float,
        code: MaintenanceIssueCode,
        message: str,
        *,
        source_ids: tuple[str, ...] = (),
        canonical_source_count: int = 0,
        canonical_artifact_count: int = 0,
    ) -> RetrievalMaintenanceReport:
        return RetrievalMaintenanceReport(
            operation=operation,
            succeeded=False,
            canonical_source_count=canonical_source_count,
            canonical_artifact_count=canonical_artifact_count,
            elapsed_seconds=_elapsed(started),
            issues=(
                MaintenanceIssue(
                    code=code,
                    message=message,
                    source_ids=source_ids,
                ),
            ),
        )


def _parity_issue(
    code: MaintenanceIssueCode,
    message: str,
    source_ids: tuple[str, ...],
) -> MaintenanceIssue | None:
    if not source_ids:
        return None
    return MaintenanceIssue(
        code=code,
        message=message,
        source_ids=source_ids[:_MAX_IDENTIFIERS_PER_ISSUE],
    )


def _elapsed(started: float) -> float:
    return min(_MAX_ELAPSED_SECONDS, max(0.0, time.perf_counter() - started))


def _strict_index_snapshot(value: object) -> IndexStateSnapshot:
    if type(value) is not IndexStateSnapshot:
        raise ValueError("retrieval index must return an exact IndexStateSnapshot")
    budget = {"nodes": 0, "text": 0}
    _preflight_protocol_value(value, depth=0, budget=budget, active=set())
    try:
        primitive = json.loads(
            json.dumps(
                value.model_dump(mode="json", warnings="error"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        return IndexStateSnapshot.model_validate(primitive)
    except (TypeError, ValueError) as error:
        raise ValueError("retrieval index snapshot failed deep canonical validation") from error


def _preflight_protocol_value(
    value: object,
    *,
    depth: int,
    budget: dict[str, int],
    active: set[int],
) -> None:
    if depth > 32:
        raise ValueError("retrieval index snapshot exceeds the nesting bound")
    budget["nodes"] += 1
    if budget["nodes"] > 20_000_000:
        raise ValueError("retrieval index snapshot exceeds the cumulative node bound")
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("retrieval index snapshot contains a non-finite number")
        if isinstance(value, str):
            budget["text"] += len(value)
            if budget["text"] > 128 * 1024 * 1024:
                raise ValueError("retrieval index snapshot exceeds the cumulative text bound")
        return
    identity = id(value)
    if identity in active:
        raise ValueError("retrieval index snapshot contains a recursive value")
    active.add(identity)
    try:
        if isinstance(value, BaseModel):
            field_names = set(type(value).model_fields)
            hidden_names = set(value.__dict__) - field_names
            if hidden_names or getattr(value, "__pydantic_extra__", None):
                raise ValueError("retrieval index snapshot contains hidden model state")
            for field_name in field_names:
                _preflight_protocol_value(
                    getattr(value, field_name),
                    depth=depth + 1,
                    budget=budget,
                    active=active,
                )
            return
        if type(value) in {tuple, list}:
            for item in value:
                _preflight_protocol_value(
                    item,
                    depth=depth + 1,
                    budget=budget,
                    active=active,
                )
            return
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ValueError("retrieval index snapshot mappings require string keys")
                _preflight_protocol_value(
                    key,
                    depth=depth + 1,
                    budget=budget,
                    active=active,
                )
                _preflight_protocol_value(
                    item,
                    depth=depth + 1,
                    budget=budget,
                    active=active,
                )
            return
        raise ValueError("retrieval index snapshot contains an unsupported runtime value")
    finally:
        active.remove(identity)


__all__ = [
    "MaintenanceIssue",
    "MaintenanceIssueCode",
    "RetrievalMaintenanceReport",
    "RetrievalMaintenanceService",
]
