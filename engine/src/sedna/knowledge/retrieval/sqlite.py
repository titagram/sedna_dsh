"""Descriptor-confined, disposable SQLite FTS5 projection of canonical knowledge."""

from __future__ import annotations

import fcntl
import json
import math
import os
import secrets
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager, nullcontext, suppress
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from types import TracebackType

from pydantic import TypeAdapter, ValidationError

from sedna.knowledge.retrieval.models import (
    EpistemicLane,
    ExecutionExampleLocator,
    IndexAudit,
    IndexCandidate,
    IndexedArtifact,
    IndexedArtifactState,
    IndexedExecutionExampleState,
    IndexedSourceState,
    IndexStateSnapshot,
    RetrievalQuery,
)
from sedna.knowledge.retrieval.projection import (
    SOURCE_PROJECTION_VERSION,
    ProjectedArtifact,
    project_semantic_bundle,
    project_source_state,
    projected_artifact_digest,
)
from sedna.knowledge.schema import (
    CaseStep,
    KnowledgeCase,
    ReferenceArtifact,
    SemanticKnowledgeBundle,
)
from sedna.knowledge.semantic.compiler import SEMANTIC_SCHEMA_VERSION

_SCHEMA_VERSION = 5
_MAX_LIMIT = 100
_FTS_FIELDS = (
    "statement",
    "rationale",
    "observations",
    "action_intent",
    "expected_evidence",
    "exceptions",
)
_ARTIFACT_ADAPTER = TypeAdapter(IndexedArtifact)

_SCHEMA = """
CREATE TABLE indexed_sources (
    source_id TEXT PRIMARY KEY,
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
    artifact_count INTEGER NOT NULL CHECK(artifact_count >= 0),
    projection_version TEXT NOT NULL,
    projection_digest TEXT NOT NULL CHECK(length(projection_digest) = 64),
    semantic_schema_version TEXT NOT NULL,
    execution_example_schema_version TEXT
);

CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY,
    owner_source_id TEXT NOT NULL REFERENCES indexed_sources(source_id) ON DELETE CASCADE,
    canonical_path TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    knowledge_role TEXT NOT NULL,
    verification_status TEXT NOT NULL,
    source_reliability REAL NOT NULL CHECK(source_reliability BETWEEN 0.0 AND 1.0),
    extraction_confidence REAL NOT NULL CHECK(extraction_confidence BETWEEN 0.0 AND 1.0),
    generalizability TEXT NOT NULL,
    context_specificity REAL NOT NULL CHECK(context_specificity BETWEEN 0.0 AND 1.0),
    support_count INTEGER NOT NULL CHECK(support_count >= 0),
    contradiction_count INTEGER NOT NULL CHECK(contradiction_count >= 0),
    observed_outcome TEXT NOT NULL,
    observed_at TEXT,
    freshness_observed_at TEXT,
    independence_group TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    projection_digest TEXT NOT NULL
);

CREATE TABLE facet_values (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    facet_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    relation TEXT NOT NULL,
    origin TEXT NOT NULL,
    confidence REAL NOT NULL CHECK(confidence BETWEEN 0.0 AND 1.0),
    PRIMARY KEY (artifact_id, facet_id)
);

CREATE TABLE artifact_links (
    from_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    to_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    PRIMARY KEY (from_artifact_id, relation, to_artifact_id)
);

CREATE TABLE artifact_sources (
    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    path TEXT NOT NULL,
    location_json TEXT NOT NULL,
    independence_group TEXT NOT NULL,
    relation TEXT NOT NULL,
    PRIMARY KEY (
        artifact_id, source_id, path, location_json, independence_group, relation
    )
);

CREATE TABLE execution_example_lookup (
    example_id TEXT PRIMARY KEY,
    parent_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
    owner_source_id TEXT NOT NULL REFERENCES indexed_sources(source_id) ON DELETE CASCADE
);

CREATE INDEX execution_example_parent_idx
ON execution_example_lookup(parent_artifact_id, example_id);

CREATE TABLE index_metadata (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    generation INTEGER NOT NULL CHECK(generation >= 0)
);

INSERT INTO index_metadata(singleton, generation) VALUES (1, 0);

CREATE VIRTUAL TABLE artifact_fts USING fts5(
    artifact_id UNINDEXED,
    statement,
    rationale,
    observations,
    action_intent,
    expected_evidence,
    exceptions,
    tokenize = 'unicode61'
);

CREATE INDEX artifacts_owner_source_idx ON artifacts(owner_source_id);
CREATE INDEX artifacts_lane_idx
    ON artifacts(artifact_type, knowledge_role, observed_outcome, artifact_id);
CREATE INDEX facet_values_lookup_idx
    ON facet_values(namespace, key, value, artifact_id);
CREATE INDEX artifact_links_target_idx
    ON artifact_links(to_artifact_id, relation, from_artifact_id);
CREATE INDEX artifact_sources_source_idx
    ON artifact_sources(source_id, artifact_id);
"""

_REQUIRED_SCHEMA_COLUMNS = {
    "indexed_sources": frozenset(
        {
            "source_id",
            "source_sha256",
            "artifact_count",
            "projection_version",
            "projection_digest",
            "semantic_schema_version",
            "execution_example_schema_version",
        }
    ),
    "execution_example_lookup": frozenset(
        {
            "example_id",
            "parent_artifact_id",
            "owner_source_id",
        }
    ),
    "artifacts": frozenset(
        {
            "artifact_id",
            "owner_source_id",
            "canonical_path",
            "artifact_type",
            "knowledge_role",
            "verification_status",
            "source_reliability",
            "extraction_confidence",
            "generalizability",
            "context_specificity",
            "support_count",
            "contradiction_count",
            "observed_outcome",
            "observed_at",
            "freshness_observed_at",
            "independence_group",
            "canonical_json",
            "projection_digest",
        }
    ),
    "facet_values": frozenset(
        {
            "artifact_id",
            "facet_id",
            "channel",
            "namespace",
            "key",
            "value",
            "relation",
            "origin",
            "confidence",
        }
    ),
    "artifact_links": frozenset({"from_artifact_id", "relation", "to_artifact_id"}),
    "artifact_sources": frozenset(
        {
            "artifact_id",
            "source_id",
            "path",
            "location_json",
            "independence_group",
            "relation",
        }
    ),
    "index_metadata": frozenset({"singleton", "generation"}),
    "artifact_fts": frozenset({"artifact_id", *_FTS_FIELDS}),
}


class _MemoryConnection(sqlite3.Connection):
    """Patchable connection type used only for private in-memory snapshots."""


class SQLiteRetrievalIndex:
    """A fixed-path retrieval index that never asks SQLite to open that path."""

    def __init__(self, path: str | Path, *, parent_fd: int | None = None) -> None:
        self._mutex = threading.RLock()
        self._poisoned = False
        self._durable_unavailable = False
        self._connection: _MemoryConnection | None = None
        self._parent_fd: int | None = None
        self._lock_fd: int | None = None
        self._lock_identity: tuple[int, int] | None = None
        self._db_identity: tuple[int, int] | None = None
        self._generation = 0
        self.path, self._filename = self._prepare_target(path)
        self._lock_filename = f".{self._filename}.lock"
        self._unavailable_filename = f".{self._filename}.unavailable"
        try:
            if parent_fd is None:
                self._open_parent()
            else:
                self._open_parent_descriptor(parent_fd)
            self._open_lock()
            with self._file_lock(exclusive=True):
                self._durable_unavailable = self._unavailable_marker_exists()
                database_bytes, identity = self._read_database_bytes()
                if database_bytes:
                    connection = self._connection_from_bytes(database_bytes)
                    generation = _database_generation(connection)
                    if generation is None:
                        generation = self._read_generation() or 0
                    self._repair_generation(generation)
                else:
                    connection = self._new_schema_connection()
                    generation = 0
                    try:
                        identity, generation = self._persist_database(
                            self._serialize_candidate(connection, generation),
                            previous_bytes=database_bytes or b"",
                            expected_identity=identity,
                            generation=generation,
                        )
                    except BaseException:
                        connection.close()
                        raise
                self._connection = connection
                self._db_identity = identity
                self._generation = generation
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> SQLiteRetrievalIndex:
        with self._mutex:
            self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        """Close resources in dependency order without losing handles on failure."""
        with self._mutex:
            connection = self._connection
            if connection is not None:
                connection.close()
                self._connection = None
            lock_fd = self._lock_fd
            if lock_fd is not None:
                os.close(lock_fd)
                self._lock_fd = None
                self._lock_identity = None
            parent_fd = self._parent_fd
            if parent_fd is not None:
                os.close(parent_fd)
                self._parent_fd = None

    def mark_unavailable(self) -> None:
        """Irreversibly poison this object and persist a rebuild requirement for reopen."""
        with self._mutex:
            self._poisoned = True
            self._durable_unavailable = True
            with self._file_lock(exclusive=True):
                self._persist_unavailable_marker()

    def mark_rebuild_required(self) -> None:
        """Persist a soft read barrier that a fresh successful rebuild may clear."""
        with self._mutex:
            self._durable_unavailable = True
            with self._file_lock(exclusive=True):
                self._persist_unavailable_marker()

    def upsert_bundle(self, bundle: SemanticKnowledgeBundle) -> None:
        """Atomically replace one source projection after canonical validation."""
        self._require_available()
        projection = project_semantic_bundle(bundle)
        source_id = _validated_source_id(bundle.source_id)
        source_sha256 = _validated_source_hash(bundle.source_sha256)
        source_state = project_source_state(bundle)
        with self._mutex:
            self._ensure_open()
            with self._file_lock(exclusive=True):
                self._require_no_durable_unavailable_marker()
                candidate, previous_bytes, identity, generation = self._load_live_connection()
                try:
                    self._require_current_schema(candidate)
                    with self._transaction(candidate):
                        self._delete_source_rows(candidate, source_id)
                        self._insert_projection_rows(
                            candidate,
                            source_id,
                            source_sha256,
                            source_state,
                            projection,
                        )
                    new_identity, new_generation = self._persist_database(
                        self._serialize_candidate(candidate, generation),
                        previous_bytes=previous_bytes,
                        expected_identity=identity,
                        generation=generation,
                    )
                except BaseException:
                    candidate.close()
                    raise
                self._adopt_connection(candidate, new_identity, new_generation)

    def delete_source(self, source_id: str) -> None:
        """Atomically remove every row owned by one canonical source."""
        self._require_available()
        source_id = _validated_source_id(source_id)
        with self._mutex:
            self._ensure_open()
            with self._file_lock(exclusive=True):
                self._require_no_durable_unavailable_marker()
                candidate, previous_bytes, identity, generation = self._load_live_connection()
                try:
                    self._require_current_schema(candidate)
                    with self._transaction(candidate):
                        self._delete_source_rows(candidate, source_id)
                    new_identity, new_generation = self._persist_database(
                        self._serialize_candidate(candidate, generation),
                        previous_bytes=previous_bytes,
                        expected_identity=identity,
                        generation=generation,
                    )
                except BaseException:
                    candidate.close()
                    raise
                self._adopt_connection(candidate, new_identity, new_generation)

    def rebuild(
        self,
        bundles: Iterable[SemanticKnowledgeBundle],
        *,
        precommit_guard: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> IndexAudit:
        """Serialize a checked fresh database and atomically install its synced bytes."""
        self._require_rebuildable()
        if precommit_guard is not None and not callable(precommit_guard):
            raise TypeError("precommit_guard must be callable")
        projected: list[tuple[str, str, IndexedSourceState, tuple[ProjectedArtifact, ...]]] = []
        source_ids: set[str] = set()
        for bundle in bundles:
            rows = project_semantic_bundle(bundle)
            source_id = _validated_source_id(bundle.source_id)
            source_sha256 = _validated_source_hash(bundle.source_sha256)
            source_state = project_source_state(bundle)
            if source_id in source_ids:
                raise ValueError("rebuild source IDs must be unique")
            source_ids.add(source_id)
            projected.append((source_id, source_sha256, source_state, rows))

        with self._mutex:
            self._ensure_rebuildable_open()
            with self._file_lock(exclusive=True):
                _, previous_bytes, identity, generation = self._load_live_connection(close=True)
                candidate = self._new_schema_connection()
                try:
                    with self._transaction(candidate):
                        for source_id, source_sha256, source_state, rows in projected:
                            self._insert_projection_rows(
                                candidate,
                                source_id,
                                source_sha256,
                                source_state,
                                rows,
                            )
                    audit = self._audit_snapshot(candidate)
                    if audit.rebuild_required:
                        raise ValueError(f"rebuilt index failed audit: {', '.join(audit.issues)}")
                    new_identity, new_generation = self._persist_database(
                        self._serialize_candidate(candidate, generation),
                        previous_bytes=previous_bytes,
                        expected_identity=identity,
                        generation=generation,
                        precommit_guard=precommit_guard,
                    )
                except BaseException:
                    candidate.close()
                    raise
                self._adopt_connection(candidate, new_identity, new_generation)
                self._clear_unavailable_marker()
                self._durable_unavailable = False
                return audit

    def get_execution_example_locators(
        self, parent_artifact_id: str
    ) -> tuple[ExecutionExampleLocator, ...]:
        """Return ID-only lookup rows for one exact parent; command text is never stored."""
        self._require_available()
        parent_artifact_id = _validated_identifier(parent_artifact_id, "artifact_id")
        with self._read_snapshot() as connection:
            rows = connection.execute(
                "SELECT example_id, parent_artifact_id, owner_source_id "
                "FROM execution_example_lookup WHERE parent_artifact_id = ? "
                "ORDER BY example_id",
                (parent_artifact_id,),
            ).fetchall()
        return tuple(
            ExecutionExampleLocator(
                example_id=row[0],
                parent_artifact_id=row[1],
                source_id=row[2],
            )
            for row in rows
        )

    def get_source_capability(self, source_id: str) -> str | None:
        """Return the indexed source's semantic schema version, or None when absent."""
        self._require_available()
        source_id = _validated_source_id(source_id)
        with self._read_snapshot() as connection:
            row = connection.execute(
                "SELECT semantic_schema_version FROM indexed_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        return row[0]

    def get_artifact(self, artifact_id: str) -> IndexedArtifact | None:
        """Return one deeply reconstructed canonical artifact by exact identity."""
        self._require_available()
        artifact_id = _validated_identifier(artifact_id, "artifact_id")
        with self._read_snapshot() as connection:
            row = connection.execute(
                "SELECT artifact_id, canonical_json FROM artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                return None
            return self._reconstruct_artifact(row["artifact_id"], row["canonical_json"])

    def list_source_states(
        self,
        *,
        after_source_id: str | None,
        limit: int,
    ) -> tuple[IndexedSourceState, ...]:
        """Return one bounded, source-ID ordered page of projection identities."""
        self._require_available()
        if after_source_id is not None:
            after_source_id = _validated_source_id(after_source_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIMIT}")
        with self._read_snapshot() as connection:
            connection.execute("BEGIN")
            try:
                self._require_current_schema(connection)
                if _database_generation(connection) is None:
                    raise ValueError("index generation metadata is invalid")
                rows = connection.execute(
                    "SELECT source_id, source_sha256, artifact_count, projection_version, "
                    "projection_digest FROM indexed_sources WHERE source_id > ? "
                    "ORDER BY source_id LIMIT ?",
                    (after_source_id or "", limit),
                ).fetchall()
                return tuple(
                    self._actual_source_state(
                        connection,
                        source_id=_validated_source_id(row["source_id"]),
                        source_sha256=_validated_source_hash(row["source_sha256"]),
                        asserted_artifact_count=row["artifact_count"],
                        asserted_projection_version=row["projection_version"],
                        asserted_projection_digest=row["projection_digest"],
                    )
                    for row in rows
                )
            finally:
                connection.rollback()

    def snapshot_state(self) -> IndexStateSnapshot:
        """Return audit and exact source/artifact states from one locked generation."""
        self._require_available()
        with self._read_snapshot() as connection:
            connection.execute("BEGIN")
            try:
                self._require_current_schema(connection)
                audit = self._audit_connection(connection)
                generation = _database_generation(connection)
                if generation is None:
                    raise ValueError("index generation metadata is invalid")
                source_states = self._actual_source_states(connection)
                unowned_artifact_ids = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT artifact_id FROM artifacts WHERE owner_source_id NOT IN "
                        "(SELECT source_id FROM indexed_sources) ORDER BY artifact_id"
                    )
                )
                return IndexStateSnapshot(
                    generation=generation,
                    audit=audit,
                    source_states=source_states,
                    unowned_artifact_ids=unowned_artifact_ids,
                )
            finally:
                connection.rollback()

    def search_candidates(
        self,
        query: RetrievalQuery,
        *,
        lane: EpistemicLane,
        limit: int,
    ) -> tuple[IndexCandidate, ...]:
        """Return bounded candidates and FTS5-native phrase explanations."""
        self._require_available()
        query = RetrievalQuery.model_validate(query.model_dump(mode="json"))
        try:
            lane = EpistemicLane(lane)
        except ValueError as error:
            raise ValueError("lane must be a supported epistemic lane") from error
        if type(limit) is not int or not 1 <= limit <= _MAX_LIMIT:
            raise ValueError(f"limit must be between 1 and {_MAX_LIMIT}")
        effective_limit = min(limit, query.max_candidates)
        terms = tuple(sorted({*query.situation.terms, *query.terms, *query.synonyms}))
        fts_terms = tuple((term, _fts_phrase(term)) for term in terms)
        if not fts_terms and not query.facets:
            return ()

        clauses = [_lane_clause(lane)]
        parameters: list[object] = []
        for facet in query.facets:
            clauses.append(
                "EXISTS (SELECT 1 FROM facet_values AS fv "
                "WHERE fv.artifact_id = a.artifact_id "
                "AND fv.namespace = ? AND fv.key = ? AND fv.value = ?)"
            )
            parameters.extend((facet.namespace, facet.key, facet.value))

        if fts_terms:
            clauses.insert(0, "artifact_fts MATCH ?")
            parameters.insert(0, " OR ".join(phrase for _, phrase in fts_terms))
            rank = "bm25(artifact_fts)"
            table = "artifact_fts JOIN artifacts AS a USING (artifact_id)"
        else:
            rank = "0.0"
            table = "artifacts AS a JOIN artifact_fts USING (artifact_id)"
        parameters.append(effective_limit)

        with self._read_snapshot() as connection:
            rows = connection.execute(
                f"""
                SELECT a.artifact_id, a.canonical_json, {rank} AS lexical_rank
                FROM {table}
                WHERE {" AND ".join(clauses)}
                ORDER BY lexical_rank ASC, a.artifact_id ASC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            max_quality = max((_rank_quality(row["lexical_rank"]) for row in rows), default=0.0)
            candidates: list[IndexCandidate] = []
            for row in rows:
                artifact = self._reconstruct_artifact(row["artifact_id"], row["canonical_json"])
                matched_terms, matched_fields, evidence = _fts_match_evidence(
                    connection, row["artifact_id"], fts_terms
                )
                candidates.append(
                    IndexCandidate(
                        artifact_id=row["artifact_id"],
                        artifact=artifact,
                        lexical_relevance=_normalise_rank(row["lexical_rank"], max_quality),
                        matched_terms=matched_terms,
                        matched_fields=matched_fields,
                        matched_evidence=evidence,
                    )
                )
            return tuple(candidates)

    def audit(self) -> IndexAudit:
        """Audit one explicit, lock-protected database snapshot."""
        self._require_available()
        with self._read_snapshot() as connection:
            return self._audit_snapshot(connection)

    def _audit_snapshot(self, connection: sqlite3.Connection) -> IndexAudit:
        connection.execute("BEGIN")
        try:
            return self._audit_connection(connection)
        finally:
            connection.rollback()

    def _audit_connection(self, connection: sqlite3.Connection) -> IndexAudit:
        issues: set[str] = set()
        corruption_count = 0
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != _SCHEMA_VERSION:
            issues.add("schema_version_mismatch")
        integrity = tuple(row[0] for row in connection.execute("PRAGMA integrity_check"))
        bad_integrity = tuple(message for message in integrity if message != "ok")
        if bad_integrity:
            issues.add("integrity_check_failed")
            corruption_count += len(bad_integrity)

        schema_issues = _required_schema_issues(connection)
        issues.update(schema_issues)
        if schema_issues:
            return IndexAudit(
                artifact_count=_safe_table_count(connection, "artifacts"),
                source_count=_safe_table_count(connection, "indexed_sources"),
                facet_count=_safe_table_count(connection, "facet_values"),
                fts_count=_safe_table_count(connection, "artifact_fts"),
                corruption_count=corruption_count,
                issues=tuple(sorted(issues)),
            )
        if _database_generation(connection) is None:
            issues.add("generation_metadata_invalid")

        artifact_count = connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        source_count = connection.execute("SELECT COUNT(*) FROM indexed_sources").fetchone()[0]
        facet_count = connection.execute("SELECT COUNT(*) FROM facet_values").fetchone()[0]
        fts_count = connection.execute("SELECT COUNT(*) FROM artifact_fts").fetchone()[0]
        foreign_key_rows = tuple(connection.execute("PRAGMA foreign_key_check"))
        explicit_orphans = sum(
            connection.execute(statement).fetchone()[0]
            for statement in (
                "SELECT COUNT(*) FROM artifacts AS child "
                "LEFT JOIN indexed_sources AS parent "
                "ON parent.source_id = child.owner_source_id "
                "WHERE parent.source_id IS NULL",
                "SELECT COUNT(*) FROM facet_values AS child "
                "LEFT JOIN artifacts AS parent USING (artifact_id) "
                "WHERE parent.artifact_id IS NULL",
                "SELECT COUNT(*) FROM artifact_sources AS child "
                "LEFT JOIN artifacts AS parent USING (artifact_id) "
                "WHERE parent.artifact_id IS NULL",
                "SELECT COUNT(*) FROM artifact_links AS child "
                "LEFT JOIN artifacts AS parent ON parent.artifact_id = child.from_artifact_id "
                "WHERE parent.artifact_id IS NULL",
                "SELECT COUNT(*) FROM artifact_links AS child "
                "LEFT JOIN artifacts AS parent ON parent.artifact_id = child.to_artifact_id "
                "WHERE parent.artifact_id IS NULL",
                "SELECT COUNT(*) FROM artifact_fts AS child "
                "LEFT JOIN artifacts AS parent USING (artifact_id) "
                "WHERE parent.artifact_id IS NULL",
            )
        )
        orphan_count = max(len(foreign_key_rows), explicit_orphans)
        duplicate_id_count = connection.execute(
            "SELECT COALESCE(SUM(count - 1), 0) FROM "
            "(SELECT COUNT(*) AS count FROM artifacts GROUP BY artifact_id HAVING count > 1)"
        ).fetchone()[0]
        duplicate_id_count += connection.execute(
            "SELECT COALESCE(SUM(count - 1), 0) FROM "
            "(SELECT COUNT(*) AS count FROM artifact_fts GROUP BY artifact_id HAVING count > 1)"
        ).fetchone()[0]

        artifact_ids = {row[0] for row in connection.execute("SELECT artifact_id FROM artifacts")}
        fts_ids = {row[0] for row in connection.execute("SELECT artifact_id FROM artifact_fts")}
        if artifact_ids != fts_ids:
            issues.add("fts_artifact_mismatch")

        for row in connection.execute(
            "SELECT source_id, source_sha256, artifact_count, projection_version, "
            "projection_digest FROM indexed_sources ORDER BY source_id"
        ):
            try:
                source_id = _validated_source_id(row["source_id"])
                source_sha256 = _validated_source_hash(row["source_sha256"])
                actual_state = self._actual_source_state(
                    connection,
                    source_id=source_id,
                    source_sha256=source_sha256,
                    asserted_artifact_count=row["artifact_count"],
                    asserted_projection_version=row["projection_version"],
                    asserted_projection_digest=row["projection_digest"],
                )
                if (
                    row["projection_version"] != actual_state.projection_version
                    or row["artifact_count"] != actual_state.artifact_count
                    or row["projection_digest"] != actual_state.projection_digest
                ):
                    raise ValueError("source projection metadata mismatch")
            except (TypeError, ValueError, ValidationError):
                issues.add("source_projection_mismatch")
                corruption_count += 1

        has_digest = version == _SCHEMA_VERSION and _column_exists(
            connection, "artifacts", "projection_digest"
        )
        for row in connection.execute("SELECT * FROM artifacts ORDER BY artifact_id"):
            try:
                artifact = self._reconstruct_artifact(row["artifact_id"], row["canonical_json"])
                if not _stored_metadata_matches(row, artifact):
                    raise ValueError("stored projection metadata does not match canonical artifact")
                if row["canonical_json"] != _canonical_json(artifact):
                    raise ValueError("canonical artifact JSON is not canonical")
            except (TypeError, ValueError, ValidationError):
                corruption_count += 1
            if has_digest and row["projection_digest"] != _live_projection_digest(connection, row):
                issues.add("projection_digest_mismatch")
                corruption_count += 1

        uncovered = 0
        for row in connection.execute(
            "SELECT artifact_id, owner_source_id, canonical_json "
            "FROM artifacts ORDER BY artifact_id"
        ):
            try:
                artifact = self._reconstruct_artifact(row["artifact_id"], row["canonical_json"])
            except ValueError:
                continue
            expected_sources = {
                (
                    source.source_id,
                    source.path,
                    _location_json(source.location.model_dump(mode="json")),
                    artifact.assessment.independence_group,
                )
                for source in artifact.source_refs
            }
            stored_sources = {
                tuple(source_row)
                for source_row in connection.execute(
                    """
                    SELECT source_id, path, location_json, independence_group
                    FROM artifact_sources
                    WHERE artifact_id = ? AND relation = 'artifact'
                    """,
                    (row["artifact_id"],),
                )
            }
            if stored_sources != expected_sources or row["owner_source_id"] not in {
                source[0] for source in expected_sources
            }:
                uncovered += 1
        if uncovered:
            issues.add("source_coverage_mismatch")
            corruption_count += uncovered

        return IndexAudit(
            artifact_count=artifact_count,
            source_count=source_count,
            facet_count=facet_count,
            fts_count=fts_count,
            orphan_count=orphan_count,
            duplicate_id_count=duplicate_id_count,
            corruption_count=corruption_count,
            issues=tuple(sorted(issues)),
        )

    def _actual_source_states(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[IndexedSourceState, ...]:
        return tuple(
            self._actual_source_state(
                connection,
                source_id=_validated_source_id(row["source_id"]),
                source_sha256=_validated_source_hash(row["source_sha256"]),
                asserted_artifact_count=row["artifact_count"],
                asserted_projection_version=row["projection_version"],
                asserted_projection_digest=row["projection_digest"],
            )
            for row in connection.execute(
                "SELECT source_id, source_sha256, artifact_count, projection_version, "
                "projection_digest FROM indexed_sources ORDER BY source_id"
            )
        )

    def _actual_source_state(
        self,
        connection: sqlite3.Connection,
        *,
        source_id: str,
        source_sha256: str,
        asserted_artifact_count: int,
        asserted_projection_version: str,
        asserted_projection_digest: str,
    ) -> IndexedSourceState:
        capability = connection.execute(
            "SELECT semantic_schema_version, execution_example_schema_version "
            "FROM indexed_sources WHERE source_id = ?",
            (source_id,),
        ).fetchone()
        example_rows = connection.execute(
            "SELECT example_id, parent_artifact_id FROM execution_example_lookup "
            "WHERE owner_source_id = ? ORDER BY example_id",
            (source_id,),
        ).fetchall()
        artifacts = tuple(
            IndexedArtifactState(
                artifact_id=row["artifact_id"],
                projection_digest=_live_projection_digest(connection, row),
                asserted_projection_digest=row["projection_digest"],
            )
            for row in connection.execute(
                "SELECT * FROM artifacts WHERE owner_source_id = ? ORDER BY artifact_id",
                (source_id,),
            )
        )
        return IndexedSourceState.from_artifacts(
            source_id=source_id,
            source_sha256=source_sha256,
            projection_version=SOURCE_PROJECTION_VERSION,
            artifacts=artifacts,
            asserted_artifact_count=asserted_artifact_count,
            asserted_projection_version=asserted_projection_version,
            asserted_projection_digest=asserted_projection_digest,
            execution_examples=tuple(
                IndexedExecutionExampleState(
                    example_id=row["example_id"],
                    parent_artifact_id=row["parent_artifact_id"],
                )
                for row in example_rows
            ),
            semantic_schema_version=(
                capability["semantic_schema_version"]
                if capability is not None
                else SEMANTIC_SCHEMA_VERSION
            ),
            execution_example_schema_version=(
                capability["execution_example_schema_version"] if capability is not None else None
            ),
        )

    @contextmanager
    def _read_snapshot(self) -> Iterator[_MemoryConnection]:
        with self._mutex:
            self._ensure_open()
            with self._file_lock(exclusive=False):
                self._require_no_durable_unavailable_marker()
                connection, _, _, _ = self._load_live_connection(close=False)
                try:
                    yield connection
                finally:
                    connection.close()

    @contextmanager
    def _transaction(self, connection: sqlite3.Connection) -> Iterator[None]:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()

    def _delete_source_rows(self, connection: sqlite3.Connection, source_id: str) -> None:
        connection.execute(
            "DELETE FROM artifact_fts WHERE artifact_id IN "
            "(SELECT artifact_id FROM artifacts WHERE owner_source_id = ?)",
            (source_id,),
        )
        connection.execute(
            "DELETE FROM execution_example_lookup WHERE owner_source_id = ?",
            (source_id,),
        )
        connection.execute("DELETE FROM artifacts WHERE owner_source_id = ?", (source_id,))
        connection.execute("DELETE FROM indexed_sources WHERE source_id = ?", (source_id,))

    def _insert_projection_rows(
        self,
        connection: sqlite3.Connection,
        source_id: str,
        source_sha256: str,
        source_state: IndexedSourceState,
        projection: tuple[ProjectedArtifact, ...],
    ) -> None:
        if (
            source_state.source_id != source_id
            or source_state.source_sha256 != source_sha256
            or source_state.artifact_count != len(projection)
            or source_state.projection_version != SOURCE_PROJECTION_VERSION
        ):
            raise ValueError("source state does not match its projected bundle")
        artifact_states = tuple(
            IndexedArtifactState(
                artifact_id=artifact.artifact_id,
                projection_digest=projected_artifact_digest(source_id, artifact),
                asserted_projection_digest=projected_artifact_digest(source_id, artifact),
            )
            for artifact in projection
        )
        if source_state.artifacts != artifact_states:
            raise ValueError("source state artifact identities do not match the projection")
        connection.execute(
            """
            INSERT INTO indexed_sources(
                source_id, source_sha256, artifact_count,
                projection_version, projection_digest,
                semantic_schema_version, execution_example_schema_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                source_sha256,
                len(projection),
                source_state.projection_version,
                source_state.projection_digest,
                source_state.semantic_schema_version,
                source_state.execution_example_schema_version,
            ),
        )
        digest_by_artifact = {
            artifact.artifact_id: artifact.projection_digest for artifact in artifact_states
        }
        for artifact in projection:
            connection.execute(
                """
                INSERT INTO artifacts(
                    artifact_id, owner_source_id, canonical_path, artifact_type, knowledge_role,
                    verification_status, source_reliability, extraction_confidence,
                    generalizability, context_specificity, support_count,
                    contradiction_count, observed_outcome, observed_at,
                    freshness_observed_at, independence_group, canonical_json, projection_digest
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.artifact_id,
                    source_id,
                    _canonical_path(source_id),
                    artifact.artifact_type,
                    artifact.knowledge_role,
                    artifact.verification_status,
                    artifact.source_reliability,
                    artifact.extraction_confidence,
                    artifact.generalizability,
                    artifact.context_specificity,
                    artifact.support_count,
                    artifact.contradiction_count,
                    artifact.observed_outcome,
                    artifact.observed_at,
                    artifact.freshness_observed_at,
                    artifact.independence_group,
                    artifact.canonical_json,
                    digest_by_artifact[artifact.artifact_id],
                ),
            )
        for artifact in projection:
            connection.executemany(
                """
                INSERT INTO facet_values(
                    artifact_id, facet_id, channel, namespace, key, value,
                    relation, origin, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        facet.artifact_id,
                        facet.facet_id,
                        facet.channel,
                        facet.namespace,
                        facet.key,
                        facet.value,
                        facet.relation,
                        facet.origin,
                        facet.confidence,
                    )
                    for facet in artifact.facets
                ),
            )
            connection.executemany(
                """
                INSERT INTO artifact_sources(
                    artifact_id, source_id, path, location_json,
                    independence_group, relation
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        source.artifact_id,
                        source.source_id,
                        source.path,
                        _location_json(source.location.model_dump(mode="json")),
                        source.independence_group,
                        source.relation,
                    )
                    for source in artifact.sources
                ),
            )
            connection.execute(
                """
                INSERT INTO artifact_fts(
                    artifact_id, statement, rationale, observations,
                    action_intent, expected_evidence, exceptions
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.artifact_id,
                    artifact.statement,
                    artifact.rationale,
                    artifact.observations,
                    artifact.action_intent,
                    artifact.expected_evidence,
                    artifact.exceptions,
                ),
            )
        for artifact in projection:
            connection.executemany(
                """
                INSERT INTO artifact_links(from_artifact_id, relation, to_artifact_id)
                VALUES (?, ?, ?)
                """,
                (
                    (link.from_artifact_id, link.relation, link.to_artifact_id)
                    for link in artifact.links
                ),
            )

        for example in source_state.execution_examples:
            connection.execute(
                """
                INSERT INTO execution_example_lookup(
                    example_id, parent_artifact_id, owner_source_id
                ) VALUES (?, ?, ?)
                """,
                (example.example_id, example.parent_artifact_id, source_id),
            )

    def _reconstruct_artifact(self, artifact_id: str, canonical_json: str) -> IndexedArtifact:
        try:
            payload = json.loads(canonical_json)
            artifact = _ARTIFACT_ADAPTER.validate_python(payload)
        except (TypeError, json.JSONDecodeError, ValidationError) as error:
            raise ValueError(f"invalid canonical artifact for {artifact_id!r}") from error
        if _artifact_id(artifact) != artifact_id:
            raise ValueError(f"invalid canonical artifact identity for {artifact_id!r}")
        return artifact

    def _load_live_connection(
        self, *, close: bool = False
    ) -> tuple[_MemoryConnection, bytes, tuple[int, int], int]:
        database_bytes, identity = self._read_database_bytes()
        if not database_bytes or identity is None:
            raise RuntimeError("database target changed after index open")
        connection = self._connection_from_bytes(database_bytes)
        generation = _database_generation(connection)
        if generation is None:
            generation = self._read_generation() or 0
        if (
            self._db_identity is not None
            and identity != self._db_identity
            and generation == self._generation
        ):
            connection.close()
            raise RuntimeError("database target changed after index open")
        if close:
            connection.close()
        return connection, database_bytes, identity, generation

    @staticmethod
    def _serialize_candidate(connection: sqlite3.Connection, generation: int) -> bytes:
        next_generation = generation + 1
        cursor = connection.execute(
            "UPDATE index_metadata SET generation = ? WHERE singleton = 1",
            (next_generation,),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("database generation metadata requires a full rebuild")
        return connection.serialize()

    def _adopt_connection(
        self,
        connection: _MemoryConnection,
        identity: tuple[int, int],
        generation: int,
    ) -> None:
        old_connection = self._connection
        self._connection = connection
        self._db_identity = identity
        self._generation = generation
        if old_connection is not None:
            # Persistence has already succeeded at this point.  A best-effort
            # disposal of the superseded private snapshot must not turn that
            # success into a raised mutation with committed state.
            with suppress(Exception):
                old_connection.close()

    def _new_schema_connection(self) -> _MemoryConnection:
        connection = self._new_memory_connection()
        try:
            connection.executescript(_SCHEMA)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        except BaseException:
            connection.close()
            raise
        return connection

    def _connection_from_bytes(self, database_bytes: bytes) -> _MemoryConnection:
        connection = self._new_memory_connection()
        try:
            connection.deserialize(database_bytes)
            connection.execute("PRAGMA foreign_keys = ON")
        except BaseException:
            connection.close()
            raise
        return connection

    @staticmethod
    def _new_memory_connection() -> _MemoryConnection:
        connection = sqlite3.connect(
            ":memory:",
            isolation_level=None,
            check_same_thread=False,
            factory=_MemoryConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _require_current_schema(connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if (
            version != _SCHEMA_VERSION
            or _required_schema_issues(connection)
            or _database_generation(connection) is None
        ):
            raise RuntimeError("database schema version requires a full rebuild")

    def _prepare_target(self, path: str | Path) -> tuple[Path, str]:
        if not isinstance(path, (str, os.PathLike)):
            raise TypeError("database path must be a filesystem path")
        raw = os.fspath(path)
        if not raw or "\x00" in raw:
            raise ValueError("database path must be a fixed filesystem target")
        requested = Path(path).expanduser()
        if requested.name in {"", ".", ".."}:
            raise ValueError("database path must name a fixed file target")
        absolute = requested if requested.is_absolute() else Path.cwd() / requested
        if any(part in {"", ".", ".."} for part in absolute.parts[1:]):
            raise ValueError("database parent must not contain symlink or traversal components")
        return absolute, absolute.name

    def _open_parent(self) -> None:
        required = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
        if any(not hasattr(os, name) for name in required) or any(
            function not in os.supports_dir_fd for function in (os.open, os.mkdir, os.unlink)
        ):
            raise RuntimeError("platform lacks safe local database path primitives")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        directory_fd = os.open(Path(self.path.anchor), flags)
        try:
            for component in self.path.parent.parts[1:]:
                with suppress(FileExistsError):
                    os.mkdir(component, mode=0o755, dir_fd=directory_fd)
                try:
                    child_fd = os.open(component, flags, dir_fd=directory_fd)
                except OSError as error:
                    raise ValueError("database parent must not contain symlinks") from error
                if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                    os.close(child_fd)
                    raise ValueError("database parent must contain only directories")
                os.close(directory_fd)
                directory_fd = child_fd
            self._parent_fd = directory_fd
            directory_fd = -1
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def _open_parent_descriptor(self, parent_fd: int) -> None:
        """Retain a duplicate of an already-confined database parent descriptor."""
        try:
            directory_fd = os.dup(parent_fd)
        except OSError as error:
            raise ValueError("database parent descriptor is unavailable") from error
        try:
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise ValueError("database parent descriptor is not a directory")
            self._parent_fd = directory_fd
            directory_fd = -1
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def _open_lock(self) -> None:
        parent_fd = self._ensure_parent_open()
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            lock_fd = os.open(self._lock_filename, flags, 0o600, dir_fd=parent_fd)
        except OSError as error:
            raise ValueError("database lock target must be a regular file") from error
        lock_status = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_status.st_mode):
            os.close(lock_fd)
            raise ValueError("database lock target must be a regular file")
        self._lock_fd = lock_fd
        self._lock_identity = (lock_status.st_dev, lock_status.st_ino)

    @contextmanager
    def _file_lock(self, *, exclusive: bool) -> Iterator[None]:
        self._ensure_parent_identity()
        self._ensure_lock_identity()
        # The stable parent-directory inode is the writer domain.  The
        # generation sidecar remains independently replaceable/recoverable,
        # but renaming it cannot create a second cooperative lock domain.
        lock_fd = self._ensure_parent_open()
        fcntl.flock(lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            self._ensure_parent_identity()
            self._ensure_lock_identity()
            yield
        finally:
            # A mutation can already be durably installed when this context
            # unwinds.  An unlock error must not turn that success into a
            # raised call; closing the retained descriptor remains a fallback
            # lock release.
            with suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)

    def _read_database_bytes(self) -> tuple[bytes | None, tuple[int, int] | None]:
        self._ensure_parent_identity()
        parent_fd = self._ensure_parent_open()
        before = self._target_status()
        if before is None:
            return None, None
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("database target must be a regular file")
        descriptor = os.open(
            self._filename,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        try:
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
            if not stat.S_ISREG(opened.st_mode) or identity != (before.st_dev, before.st_ino):
                raise ValueError("database target changed while being read")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 1024 * 1024):
                chunks.append(chunk)
            after = self._target_status()
            if after is None or identity != (after.st_dev, after.st_ino):
                raise ValueError("database target changed while being read")
            return b"".join(chunks), identity
        finally:
            os.close(descriptor)

    def _persist_database(
        self,
        database_bytes: bytes,
        *,
        previous_bytes: bytes,
        expected_identity: tuple[int, int] | None,
        generation: int,
        precommit_guard: Callable[[], AbstractContextManager[None]] | None = None,
    ) -> tuple[tuple[int, int], int]:
        parent_fd = self._ensure_parent_open()
        temporary_name = f".{self._filename}.{secrets.token_hex(16)}.tmp"
        backup_name = f".{self._filename}.{secrets.token_hex(16)}.backup"
        temporary_identity: tuple[int, int] | None = None
        backup_identity: tuple[int, int] | None = None
        backup_created = False
        installed = False
        generation_written = False
        validated_descriptor: int | None = None
        backup_descriptor: int | None = None
        backup_digest: str | None = None
        preserve_backup = False
        next_generation = generation + 1
        try:
            temporary_identity = self._write_named_bytes(temporary_name, database_bytes)
            validated_descriptor, validated_digest = self._validate_serialized_sibling(
                temporary_name,
                temporary_identity,
                expected_generation=next_generation,
            )
            if expected_identity is not None:
                backup_identity = self._write_named_bytes(backup_name, previous_bytes)
                backup_created = True
                backup_descriptor, backup_digest = self._retain_exact_named_bytes(
                    backup_name,
                    backup_identity,
                    previous_bytes,
                )
            self._ensure_lock_identity()
            self._verify_expected_target(expected_identity)
            try:
                guard_context = nullcontext() if precommit_guard is None else precommit_guard()
                with guard_context:
                    self._verify_retained_sibling(
                        validated_descriptor,
                        temporary_name,
                        temporary_identity,
                        validated_digest,
                        expected_generation=next_generation,
                    )
                    os.replace(
                        temporary_name,
                        self._filename,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    installed = True
                    os.fsync(parent_fd)
                    current = self._target_status()
                    if current is None or temporary_identity != (current.st_dev, current.st_ino):
                        raise OSError("database target changed during atomic persistence")
                    self._verify_retained_sibling(
                        validated_descriptor,
                        self._filename,
                        temporary_identity,
                        validated_digest,
                        expected_generation=next_generation,
                    )
                    # The atomically installed database is authoritative.  The
                    # sidecar copy is recoverable and must never make a durable
                    # mutation report failure after installation.
                    with suppress(OSError):
                        self._write_generation(next_generation)
                    generation_written = True
                    if backup_created:
                        if backup_identity is None:
                            raise RuntimeError("database backup identity was not retained")
                        self._unlink_named_identity(backup_name, backup_identity)
                        backup_created = False
                    os.fsync(parent_fd)
                    # Backup deletion and its directory sync are part of the
                    # commit boundary. This finite stable-byte check is the
                    # cooperative commit linearization point; no fallible or
                    # expensive work follows before the committed identity is
                    # returned. A same-UID process can still mutate the file
                    # after this method returns, which no pathname protocol can
                    # prevent.
                    self._verify_retained_bytes(
                        validated_descriptor,
                        self._filename,
                        temporary_identity,
                        validated_digest,
                    )
            except BaseException as original_error:
                rollback_errors, restored_identity = self._rollback_persistence(
                    backup_name=backup_name,
                    backup_descriptor=backup_descriptor,
                    backup_identity=backup_identity,
                    backup_digest=backup_digest,
                    had_previous=expected_identity is not None,
                    backup_is_database=bool(previous_bytes),
                    installed_identity=temporary_identity,
                    generation=generation,
                    # A generation write can fail after a short/partial write,
                    # so restore it whenever the database was installed.
                    restore_generation=installed or generation_written,
                )
                if restored_identity is not None:
                    self._db_identity = restored_identity
                    self._generation = generation
                    installed = False
                if not rollback_errors:
                    backup_created = False
                else:
                    preserve_backup = True
                    preservation_error = self._preserve_retained_backup(
                        backup_name,
                        backup_descriptor,
                        backup_identity,
                        backup_digest,
                    )
                    if preservation_error is not None:
                        rollback_errors.append(preservation_error)
                for rollback_error in rollback_errors:
                    original_error.add_note(
                        "database persistence rollback failed: "
                        f"{type(rollback_error).__name__}: {rollback_error}"
                    )
                raise
            return temporary_identity, next_generation
        finally:
            if validated_descriptor is not None:
                # Persistence may already be durable. Descriptor disposal
                # cannot turn that success into a raised mutation.
                with suppress(OSError):
                    os.close(validated_descriptor)
            if backup_descriptor is not None:
                with suppress(OSError):
                    os.close(backup_descriptor)
            if not installed and temporary_identity is not None:
                self._unlink_named_identity_if_present(temporary_name, temporary_identity)
            if backup_created and not installed and not preserve_backup and backup_identity:
                self._unlink_named_identity_if_present(backup_name, backup_identity)

    def _validate_serialized_sibling(
        self,
        filename: str,
        expected_identity: tuple[int, int],
        *,
        expected_generation: int,
    ) -> tuple[int, str]:
        """Validate and retain a reader for the exact inode eligible for install."""
        descriptor = self._open_named_reader(filename, expected_identity)
        try:
            database_bytes = self._read_descriptor_bytes(descriptor)
            self._validate_database_bytes(database_bytes, expected_generation)
        except sqlite3.Error as error:
            os.close(descriptor)
            raise sqlite3.DatabaseError("serialized database validation failed") from error
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, sha256(database_bytes).hexdigest()

    def _validate_database_bytes(self, database_bytes: bytes, expected_generation: int) -> None:
        connection = self._connection_from_bytes(database_bytes)
        try:
            self._require_current_schema(connection)
            if _database_generation(connection) != expected_generation:
                raise ValueError("serialized database generation does not match candidate")
            quick_check = tuple(row[0] for row in connection.execute("PRAGMA quick_check"))
            integrity_check = tuple(row[0] for row in connection.execute("PRAGMA integrity_check"))
            if quick_check != ("ok",) or integrity_check != ("ok",):
                raise ValueError("serialized database integrity check failed")
            audit = self._audit_snapshot(connection)
            if audit.rebuild_required:
                raise ValueError(
                    f"serialized database projection audit failed: {', '.join(audit.issues)}"
                )
        finally:
            connection.close()

    def _verify_retained_sibling(
        self,
        descriptor: int,
        filename: str,
        expected_identity: tuple[int, int],
        expected_digest: str,
        *,
        expected_generation: int,
    ) -> None:
        database_bytes = self._verify_retained_bytes(
            descriptor,
            filename,
            expected_identity,
            expected_digest,
        )
        try:
            self._validate_database_bytes(database_bytes, expected_generation)
        except sqlite3.Error as error:
            raise sqlite3.DatabaseError("serialized database validation failed") from error
        # The semantic audit above can be expensive. Bind its decision back
        # to the live pathname and retained inode after it returns, so a path
        # swap or in-place write during the audit cannot be committed.
        self._verify_retained_bytes(
            descriptor,
            filename,
            expected_identity,
            expected_digest,
        )

    def _verify_retained_bytes(
        self,
        descriptor: int,
        filename: str,
        expected_identity: tuple[int, int],
        expected_digest: str,
    ) -> bytes:
        parent_fd = self._ensure_parent_open()
        retained_before = os.fstat(descriptor)
        current_before = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        retained_before_metadata = _stable_file_metadata(retained_before)
        current_before_metadata = _stable_file_metadata(current_before)
        database_bytes = self._read_descriptor_bytes(descriptor)
        observed_digest = sha256(database_bytes).hexdigest()
        retained_after = os.fstat(descriptor)
        retained_after_metadata = _stable_file_metadata(retained_after)
        current_after = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        current_after_metadata = _stable_file_metadata(current_after)
        for status in (retained_before, current_before, retained_after, current_after):
            if not stat.S_ISREG(status.st_mode) or expected_identity != (
                status.st_dev,
                status.st_ino,
            ):
                raise ValueError("serialized database sibling identity changed after validation")
        if not (
            retained_before_metadata
            == current_before_metadata
            == retained_after_metadata
            == current_after_metadata
        ):
            raise ValueError("serialized database sibling metadata changed after validation")
        if observed_digest != expected_digest:
            raise ValueError("serialized database sibling bytes changed after validation")
        return database_bytes

    def _retain_exact_named_bytes(
        self,
        filename: str,
        expected_identity: tuple[int, int],
        expected_bytes: bytes,
    ) -> tuple[int, str]:
        descriptor = self._open_named_reader(filename, expected_identity)
        digest = sha256(expected_bytes).hexdigest()
        try:
            retained_bytes = self._verify_retained_bytes(
                descriptor,
                filename,
                expected_identity,
                digest,
            )
            if retained_bytes != expected_bytes:
                raise ValueError("retained database backup differs from prior bytes")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, digest

    def _open_named_reader(
        self,
        filename: str,
        expected_identity: tuple[int, int],
    ) -> int:
        parent_fd = self._ensure_parent_open()
        before = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or expected_identity != (before.st_dev, before.st_ino):
            raise ValueError("serialized database sibling changed before validation")
        descriptor = os.open(
            filename,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or expected_identity != (
            opened.st_dev,
            opened.st_ino,
        ):
            os.close(descriptor)
            raise ValueError("serialized database sibling changed during validation")
        return descriptor

    @staticmethod
    def _read_descriptor_bytes(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)

    def _read_named_bytes(
        self,
        filename: str,
        expected_identity: tuple[int, int],
    ) -> bytes:
        descriptor = self._open_named_reader(filename, expected_identity)
        try:
            database_bytes = self._read_descriptor_bytes(descriptor)
            after = os.stat(
                filename,
                dir_fd=self._ensure_parent_open(),
                follow_symlinks=False,
            )
            if expected_identity != (after.st_dev, after.st_ino):
                raise ValueError("serialized database sibling changed during validation")
            return database_bytes
        finally:
            os.close(descriptor)

    def _rollback_persistence(
        self,
        *,
        backup_name: str,
        backup_descriptor: int | None,
        backup_identity: tuple[int, int] | None,
        backup_digest: str | None,
        had_previous: bool,
        backup_is_database: bool,
        installed_identity: tuple[int, int],
        generation: int,
        restore_generation: bool,
    ) -> tuple[list[BaseException], tuple[int, int] | None]:
        errors: list[BaseException] = []
        parent_fd = self._ensure_parent_open()
        restored_identity: tuple[int, int] | None = None
        rollback_ready = False
        rollback_name: str | None = None
        rollback_identity: tuple[int, int] | None = None
        rollback_descriptor: int | None = None
        rollback_digest: str | None = None
        if had_previous:
            rollback_name = f".{self._filename}.{secrets.token_hex(16)}.rollback"
            try:
                if backup_descriptor is None or backup_identity is None or backup_digest is None:
                    raise RuntimeError("database rollback backup was not retained")
                previous_bytes = self._read_verified_descriptor_bytes(
                    backup_descriptor,
                    backup_identity,
                    backup_digest,
                )
                rollback_identity = self._write_named_bytes(rollback_name, previous_bytes)
                if backup_is_database:
                    rollback_descriptor, rollback_digest = self._validate_serialized_sibling(
                        rollback_name,
                        rollback_identity,
                        expected_generation=generation,
                    )
                else:
                    rollback_descriptor, rollback_digest = self._retain_exact_named_bytes(
                        rollback_name,
                        rollback_identity,
                        previous_bytes,
                    )
                if rollback_digest != backup_digest:
                    raise ValueError("database rollback candidate differs from retained backup")
                if backup_is_database:
                    self._verify_retained_sibling(
                        rollback_descriptor,
                        rollback_name,
                        rollback_identity,
                        rollback_digest,
                        expected_generation=generation,
                    )
                else:
                    self._verify_retained_bytes(
                        rollback_descriptor,
                        rollback_name,
                        rollback_identity,
                        rollback_digest,
                    )
                os.replace(
                    rollback_name,
                    self._filename,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
                if backup_is_database:
                    self._verify_retained_sibling(
                        rollback_descriptor,
                        self._filename,
                        rollback_identity,
                        rollback_digest,
                        expected_generation=generation,
                    )
                else:
                    self._verify_retained_bytes(
                        rollback_descriptor,
                        self._filename,
                        rollback_identity,
                        rollback_digest,
                    )
                rollback_ready = True
            except BaseException as error:
                errors.append(error)
        else:
            try:
                current = self._target_status()
                if current is None:
                    rollback_ready = True
                elif installed_identity != (current.st_dev, current.st_ino):
                    raise RuntimeError("database target changed before empty-index rollback")
                else:
                    if not stat.S_ISREG(current.st_mode):
                        raise RuntimeError("database target is not regular during rollback")
                    os.unlink(self._filename, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    if self._target_status() is not None:
                        raise RuntimeError("database target remained after empty-index rollback")
                    rollback_ready = True
            except BaseException as error:
                errors.append(error)
        if restore_generation and rollback_ready:
            try:
                self._write_generation(generation)
                if had_previous:
                    if (
                        rollback_descriptor is None
                        or rollback_identity is None
                        or rollback_digest is None
                    ):
                        raise RuntimeError("restored database identity was not retained")
                    if backup_is_database:
                        self._verify_retained_sibling(
                            rollback_descriptor,
                            self._filename,
                            rollback_identity,
                            rollback_digest,
                            expected_generation=generation,
                        )
                    else:
                        database_bytes = self._verify_retained_bytes(
                            rollback_descriptor,
                            self._filename,
                            rollback_identity,
                            rollback_digest,
                        )
                        if database_bytes:
                            raise RuntimeError("restored empty database target gained content")
            except BaseException as error:
                errors.append(error)
                rollback_ready = False
        if rollback_ready and had_previous:
            try:
                if (
                    backup_identity is None
                    or rollback_descriptor is None
                    or rollback_identity is None
                    or rollback_digest is None
                ):
                    raise RuntimeError("restored database identity was not retained")
                self._unlink_named_identity_if_present(backup_name, backup_identity)
                os.fsync(parent_fd)
                self._verify_retained_bytes(
                    rollback_descriptor,
                    self._filename,
                    rollback_identity,
                    rollback_digest,
                )
                # Cooperative writers remain excluded by the retained parent
                # lock. This finite reread is the rollback linearization point:
                # all fallible cleanup is complete, so publish success now.
                # Arbitrary same-UID mutation after this method returns is
                # outside the enforceable pathname boundary.
                restored_identity = rollback_identity
            except BaseException as error:
                errors.append(error)
                rollback_ready = False
        if rollback_descriptor is not None:
            with suppress(OSError):
                os.close(rollback_descriptor)
        if rollback_name is not None and rollback_identity is not None and not rollback_ready:
            self._unlink_named_identity_if_present(rollback_name, rollback_identity)
        return errors, restored_identity

    def _read_verified_descriptor_bytes(
        self,
        descriptor: int,
        expected_identity: tuple[int, int],
        expected_digest: str,
    ) -> bytes:
        before = os.fstat(descriptor)
        database_bytes = self._read_descriptor_bytes(descriptor)
        after = os.fstat(descriptor)
        for status in (before, after):
            if not stat.S_ISREG(status.st_mode) or expected_identity != (
                status.st_dev,
                status.st_ino,
            ):
                raise ValueError("retained database backup identity changed")
        if sha256(database_bytes).hexdigest() != expected_digest:
            raise ValueError("retained database backup bytes changed")
        return database_bytes

    def _preserve_retained_backup(
        self,
        backup_name: str,
        backup_descriptor: int | None,
        backup_identity: tuple[int, int] | None,
        backup_digest: str | None,
    ) -> BaseException | None:
        try:
            if backup_descriptor is None or backup_identity is None or backup_digest is None:
                raise RuntimeError("no retained database backup is available for recovery")
            previous_bytes = self._read_verified_descriptor_bytes(
                backup_descriptor,
                backup_identity,
                backup_digest,
            )
            current = self._named_status(backup_name)
            if current is not None and backup_identity == (current.st_dev, current.st_ino):
                os.fsync(self._ensure_parent_open())
                return None
            recovery_name = f"{backup_name}.{secrets.token_hex(8)}.recovery"
            recovery_identity = self._write_named_bytes(recovery_name, previous_bytes)
            recovery_bytes = self._read_named_bytes(recovery_name, recovery_identity)
            if sha256(recovery_bytes).hexdigest() != backup_digest:
                raise ValueError("preserved database backup content changed")
            os.fsync(self._ensure_parent_open())
        except BaseException as error:
            return error
        return None

    def _unlink_named_identity(self, filename: str, identity: tuple[int, int]) -> None:
        current = self._named_status(filename)
        if current is None or identity != (current.st_dev, current.st_ino):
            raise RuntimeError("database sibling path changed before cleanup")
        os.unlink(filename, dir_fd=self._ensure_parent_open())

    def _unlink_named_identity_if_present(
        self,
        filename: str,
        identity: tuple[int, int],
    ) -> None:
        try:
            current = self._named_status(filename)
            if current is not None and identity == (current.st_dev, current.st_ino):
                with suppress(FileNotFoundError):
                    os.unlink(filename, dir_fd=self._ensure_parent_open())
        except OSError:
            pass

    def _named_status(self, filename: str) -> os.stat_result | None:
        try:
            return os.stat(
                filename,
                dir_fd=self._ensure_parent_open(),
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return None

    def _write_named_bytes(self, filename: str, payload: bytes) -> tuple[int, int]:
        parent_fd = self._ensure_parent_open()
        descriptor = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        try:
            try:
                if not stat.S_ISREG(opened.st_mode):
                    raise ValueError("database temporary target must be a regular file")
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError("database temporary write made no progress")
                    view = view[written:]
                os.fsync(descriptor)
                status = os.fstat(descriptor)
                if not stat.S_ISREG(status.st_mode) or identity != (
                    status.st_dev,
                    status.st_ino,
                ):
                    raise ValueError("database temporary target changed while being written")
            finally:
                os.close(descriptor)
        except BaseException:
            self._unlink_named_identity_if_present(filename, identity)
            raise
        return identity

    def _verify_expected_target(self, expected_identity: tuple[int, int] | None) -> None:
        current = self._target_status()
        if expected_identity is None:
            if current is not None:
                raise RuntimeError("database target changed before atomic persistence")
            return
        if (
            current is None
            or not stat.S_ISREG(current.st_mode)
            or expected_identity != (current.st_dev, current.st_ino)
        ):
            raise RuntimeError("database target changed before atomic persistence")

    def _read_generation(self) -> int | None:
        lock_fd = self._ensure_lock_open()
        os.lseek(lock_fd, 0, os.SEEK_SET)
        raw = os.read(lock_fd, 64)
        if not raw:
            return None
        try:
            text = raw.decode("ascii")
            if not text.endswith("\n") or not text[:-1].isdigit():
                raise ValueError
            return int(text[:-1])
        except (UnicodeError, ValueError):
            return None

    def _repair_generation(self, generation: int) -> None:
        if self._read_generation() != generation:
            self._write_generation(generation)

    def _write_generation(self, generation: int) -> None:
        lock_fd = self._ensure_lock_open()
        payload = f"{generation}\n".encode("ascii")
        os.lseek(lock_fd, 0, os.SEEK_SET)
        written = os.write(lock_fd, payload)
        if written != len(payload):
            raise OSError("database generation write was incomplete")
        os.ftruncate(lock_fd, len(payload))
        os.fsync(lock_fd)

    def _unavailable_marker_exists(self) -> bool:
        try:
            status = os.stat(
                self._unavailable_filename,
                dir_fd=self._ensure_parent_open(),
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(status.st_mode):
            raise ValueError("retrieval unavailable marker is not a regular file")
        return True

    def _persist_unavailable_marker(self) -> None:
        parent_fd = self._ensure_parent_open()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            marker_fd = os.open(
                self._unavailable_filename,
                flags,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            if not self._unavailable_marker_exists():
                raise RuntimeError("retrieval unavailable marker changed") from None
            return
        try:
            if not stat.S_ISREG(os.fstat(marker_fd).st_mode):
                raise ValueError("retrieval unavailable marker is not a regular file")
            payload = b"sedna-retrieval-rebuild-required-v1\n"
            if os.write(marker_fd, payload) != len(payload):
                raise OSError("retrieval unavailable marker write was incomplete")
            os.fsync(marker_fd)
        finally:
            os.close(marker_fd)
        os.fsync(parent_fd)

    def _clear_unavailable_marker(self) -> None:
        parent_fd = self._ensure_parent_open()
        if not self._unavailable_marker_exists():
            return
        os.unlink(self._unavailable_filename, dir_fd=parent_fd)
        os.fsync(parent_fd)

    def _require_no_durable_unavailable_marker(self) -> None:
        """Observe barriers written by already-open cooperative peer processes."""
        if self._unavailable_marker_exists():
            self._durable_unavailable = True
            raise RuntimeError("retrieval index is unavailable")

    def _ensure_open(self) -> _MemoryConnection:
        if self._poisoned or self._durable_unavailable:
            raise RuntimeError("retrieval index is unavailable")
        connection = self._connection
        if connection is None:
            raise RuntimeError("retrieval index is closed")
        return connection

    def _require_available(self) -> None:
        with self._mutex:
            self._ensure_open()

    def _require_rebuildable(self) -> None:
        with self._mutex:
            self._ensure_rebuildable_open()

    def _ensure_rebuildable_open(self) -> _MemoryConnection:
        if self._poisoned:
            raise RuntimeError("retrieval index is unavailable")
        connection = self._connection
        if connection is None:
            raise RuntimeError("retrieval index is closed")
        return connection

    def _ensure_parent_open(self) -> int:
        parent_fd = self._parent_fd
        if parent_fd is None:
            raise RuntimeError("retrieval index is closed")
        return parent_fd

    def _ensure_lock_open(self) -> int:
        lock_fd = self._lock_fd
        if lock_fd is None:
            raise RuntimeError("retrieval index is closed")
        return lock_fd

    def _ensure_lock_identity(self) -> None:
        lock_fd = self._ensure_lock_open()
        expected = self._lock_identity
        retained = os.fstat(lock_fd)
        try:
            current = os.stat(
                self._lock_filename,
                dir_fd=self._ensure_parent_open(),
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise RuntimeError("database lock target changed after index open") from error
        identity = (retained.st_dev, retained.st_ino)
        if (
            expected is None
            or identity != expected
            or identity != (current.st_dev, current.st_ino)
            or not stat.S_ISREG(retained.st_mode)
            or not stat.S_ISREG(current.st_mode)
        ):
            raise RuntimeError("database lock target changed after index open")

    def _ensure_parent_identity(self) -> None:
        parent_fd = self._ensure_parent_open()
        expected = os.fstat(parent_fd)
        try:
            actual = os.stat(self.path.parent, follow_symlinks=False)
        except FileNotFoundError as error:
            raise RuntimeError("database parent changed after index open") from error
        if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise RuntimeError("database parent changed after index open")

    def _target_status(self) -> os.stat_result | None:
        parent_fd = self._ensure_parent_open()
        try:
            return os.stat(self._filename, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None


def _validated_identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 2048 or "\x00" in value:
        raise ValueError(f"{field} must be bounded non-empty text")
    return value


def _stable_file_metadata(status: os.stat_result) -> tuple[object, ...]:
    """Return mutation-sensitive metadata, excluding read-affected access time."""
    return (
        status.st_mode,
        status.st_dev,
        status.st_ino,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        getattr(status, "st_mtime_ns", status.st_mtime),
        getattr(status, "st_ctime_ns", status.st_ctime),
        getattr(status, "st_birthtime", None),
        getattr(status, "st_flags", None),
        getattr(status, "st_gen", None),
        getattr(status, "st_blocks", None),
    )


def _validated_source_id(value: str) -> str:
    value = _validated_identifier(value, "source_id")
    if value in {".", ".."} or "/" in value or "\\" in value or Path(value).is_absolute():
        raise ValueError("source_id must be a safe path segment")
    return value


def _validated_source_hash(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("source_sha256 must be a lowercase SHA-256 digest")
    return value


def _canonical_path(source_id: str) -> str:
    return f"semantic_bundles/{source_id}.json"


def _artifact_id(artifact: IndexedArtifact) -> str:
    if isinstance(artifact, ReferenceArtifact):
        return artifact.artifact_id
    if isinstance(artifact, KnowledgeCase):
        return artifact.case_id
    if isinstance(artifact, CaseStep):
        return artifact.step_id
    return artifact.rule_id


def _canonical_json(artifact: IndexedArtifact) -> str:
    return json.dumps(
        artifact.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _location_json(location: object) -> str:
    return json.dumps(
        location,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _live_projection_digest(connection: sqlite3.Connection, row: sqlite3.Row) -> str:
    artifact_row = {
        key: row[key]
        for key in (
            "artifact_id",
            "owner_source_id",
            "canonical_path",
            "artifact_type",
            "knowledge_role",
            "verification_status",
            "source_reliability",
            "extraction_confidence",
            "generalizability",
            "context_specificity",
            "support_count",
            "contradiction_count",
            "observed_outcome",
            "observed_at",
            "freshness_observed_at",
            "independence_group",
            "canonical_json",
        )
    }
    facets = _rows_as_dicts(
        connection.execute(
            "SELECT artifact_id, facet_id, channel, namespace, key, value, relation, origin, "
            "confidence FROM facet_values WHERE artifact_id = ? ORDER BY facet_id",
            (row["artifact_id"],),
        )
    )
    links = _rows_as_dicts(
        connection.execute(
            "SELECT from_artifact_id, relation, to_artifact_id FROM artifact_links "
            "WHERE from_artifact_id = ? ORDER BY relation, to_artifact_id",
            (row["artifact_id"],),
        )
    )
    sources = _rows_as_dicts(
        connection.execute(
            "SELECT artifact_id, source_id, path, location_json, independence_group, relation "
            "FROM artifact_sources WHERE artifact_id = ? "
            "ORDER BY relation, independence_group, source_id, path, location_json",
            (row["artifact_id"],),
        )
    )
    fts = _rows_as_dicts(
        connection.execute(
            "SELECT artifact_id, statement, rationale, observations, action_intent, "
            "expected_evidence, exceptions FROM artifact_fts WHERE artifact_id = ? "
            "ORDER BY statement, rationale, observations, action_intent, "
            "expected_evidence, exceptions",
            (row["artifact_id"],),
        )
    )
    return _digest_payload(artifact_row, facets, links, sources, fts)


def _rows_as_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, object]]:
    return [dict(row) for row in rows]


def _digest_payload(
    artifact: dict[str, object],
    facets: Sequence[dict[str, object]],
    links: Sequence[dict[str, object]],
    sources: Sequence[dict[str, object]],
    fts: Sequence[dict[str, object]],
) -> str:
    payload = json.dumps(
        {
            "artifact": artifact,
            "facets": _sorted_digest_rows(facets),
            "links": _sorted_digest_rows(links),
            "sources": _sorted_digest_rows(sources),
            "fts": _sorted_digest_rows(fts),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return sha256(payload.encode("utf-8")).hexdigest()


def _sorted_digest_rows(
    rows: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    """Canonicalize normalized row order independently of query/insertion order."""
    return sorted(
        rows,
        key=lambda row: json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ),
    )


def _stored_metadata_matches(row: sqlite3.Row, artifact: IndexedArtifact) -> bool:
    try:
        owner_source_id = _validated_source_id(row["owner_source_id"])
    except (TypeError, ValueError):
        return False
    assessment = artifact.assessment
    observed_at = artifact.observed_at if isinstance(artifact, ReferenceArtifact) else None
    return (
        row["canonical_path"] == _canonical_path(owner_source_id)
        and row["artifact_type"] == artifact.artifact_type
        and row["knowledge_role"] == artifact.knowledge_role
        and row["verification_status"] == assessment.verification_status
        and row["source_reliability"] == assessment.source_reliability
        and row["extraction_confidence"] == assessment.extraction_confidence
        and row["generalizability"] == assessment.generalizability
        and row["context_specificity"] == assessment.context_specificity
        and row["support_count"] == assessment.support_count
        and row["contradiction_count"] == assessment.contradiction_count
        and row["observed_outcome"] == assessment.observed_outcome
        and row["observed_at"] == observed_at
        and row["freshness_observed_at"] == assessment.freshness_observed_at
        and row["independence_group"] == assessment.independence_group
    )


def _column_exists(connection: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in connection.execute(f"PRAGMA table_info({table})"))


def _required_schema_issues(connection: sqlite3.Connection) -> set[str]:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')"
        )
    }
    issues: set[str] = set()
    for table, required_columns in _REQUIRED_SCHEMA_COLUMNS.items():
        if table not in tables:
            issues.add("schema_table_missing")
            continue
        columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if not required_columns <= columns:
            issues.add("schema_column_missing")
    expected_objects = dict(_expected_schema_objects())
    actual_objects = dict(_schema_objects(connection))
    if actual_objects.keys() - expected_objects.keys():
        issues.add("schema_object_unexpected")
    for name, expected in expected_objects.items():
        actual = actual_objects.get(name)
        if actual is None:
            issues.add("schema_object_missing")
        elif actual != expected:
            issues.add("schema_object_mismatch")
    return issues


@lru_cache(maxsize=1)
def _expected_schema_objects() -> tuple[tuple[str, tuple[str, str, str]], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        return _schema_objects(connection)
    finally:
        connection.close()


def _schema_objects(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, tuple[str, str, str]], ...]:
    objects: list[tuple[str, tuple[str, str, str]]] = []
    for object_type, name, table_name, sql in connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL"
    ):
        if name.startswith("sqlite_"):
            continue
        objects.append(
            (
                name,
                (object_type, table_name, " ".join(sql.split()).casefold()),
            )
        )
    return tuple(sorted(objects))


def _safe_table_count(connection: sqlite3.Connection, table: str) -> int:
    try:
        return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except sqlite3.Error:
        return 0


def _safe_distinct_count(connection: sqlite3.Connection, table: str, column: str) -> int:
    if not _column_exists(connection, table, column):
        return 0
    return connection.execute(f"SELECT COUNT(DISTINCT {column}) FROM {table}").fetchone()[0]


def _database_generation(connection: sqlite3.Connection) -> int | None:
    try:
        rows = connection.execute("SELECT singleton, generation FROM index_metadata").fetchall()
    except sqlite3.Error:
        return None
    if len(rows) != 1 or rows[0][0] != 1:
        return None
    generation = rows[0][1]
    if type(generation) is not int or generation < 0:
        return None
    return generation


def _lane_clause(lane: EpistemicLane) -> str:
    if lane is EpistemicLane.GUIDANCE:
        return "a.artifact_type = 'decision_rule'"
    if lane is EpistemicLane.CASE_STEP:
        return (
            "a.artifact_type = 'case_step' AND a.knowledge_role != 'negative_case' "
            "AND a.observed_outcome != 'failure'"
        )
    if lane is EpistemicLane.NEGATIVE_EVIDENCE:
        return (
            "((a.artifact_type = 'case_step' AND "
            "(a.knowledge_role = 'negative_case' OR a.observed_outcome = 'failure')) "
            "OR a.artifact_type IN ('negative_evidence', 'anti_pattern', 'exception'))"
        )
    return (
        "a.artifact_type NOT IN "
        "('case', 'case_step', 'decision_rule', 'negative_evidence', 'anti_pattern', 'exception')"
    )


def _fts_phrase(term: str) -> str:
    return f'"{term.replace(chr(34), chr(34) * 2)}"'


def _fts_match_evidence(
    connection: sqlite3.Connection,
    artifact_id: str,
    terms: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    matched_terms: set[str] = set()
    matched_fields: set[str] = set()
    evidence: set[str] = set()
    for term, phrase in terms:
        term_match = connection.execute(
            "SELECT 1 FROM artifact_fts WHERE artifact_id = ? AND artifact_fts MATCH ?",
            (artifact_id, phrase),
        ).fetchone()
        if term_match is None:
            continue
        matched_terms.add(term)
        for field_index, field in enumerate(_FTS_FIELDS, start=1):
            field_query = f"{field} : {phrase}"
            snippet = connection.execute(
                "SELECT snippet(artifact_fts, ?, '[', ']', ' … ', 12) "
                "FROM artifact_fts WHERE artifact_id = ? AND artifact_fts MATCH ?",
                (field_index, artifact_id, field_query),
            ).fetchone()
            if snippet is not None:
                matched_fields.add(field)
                evidence.add(f"{field}: {snippet[0]}"[:2048])
    return tuple(sorted(matched_terms)), tuple(sorted(matched_fields)), tuple(sorted(evidence))


def _rank_quality(value: object) -> float:
    try:
        rank = -float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(rank) or rank <= 0.0:
        return 0.0
    return rank


def _normalise_rank(value: object, max_quality: float) -> float:
    quality = _rank_quality(value)
    if max_quality <= 0.0:
        return 0.0
    return min(1.0, quality / max_quality)


__all__ = ["SQLiteRetrievalIndex"]
