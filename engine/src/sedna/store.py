"""Small SQLite store for Sedna state and local full-text search."""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import TypeVar
from uuid import UUID

from pydantic import BaseModel

from sedna.models import (
    Credential,
    Engagement,
    Finding,
    KnowledgeChunk,
    Loot,
    Machine,
    SearchHit,
    Technique,
    ToolRef,
)

SednaRecord = (
    Machine | Finding | Credential | Loot | Engagement | KnowledgeChunk | Technique | ToolRef
)
RecordT = TypeVar("RecordT", bound=BaseModel)
_SUPPORTED_TYPES = {
    model.__name__: model
    for model in (
        Machine,
        Finding,
        Credential,
        Loot,
        Engagement,
        KnowledgeChunk,
        Technique,
        ToolRef,
    )
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    machine_id TEXT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS records_kind_idx ON records(kind);
CREATE INDEX IF NOT EXISTS records_machine_idx ON records(machine_id);

CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
    record_id UNINDEXED,
    title,
    content,
    tokenize = 'unicode61'
);
"""


class SednaStore:
    """Persist typed Sedna records and expose a single FTS5 search surface."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection: sqlite3.Connection | None = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(_SCHEMA)

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("store is closed")
        return self._connection

    def save(self, record: SednaRecord) -> None:
        """Insert or replace a record and keep its FTS row in sync."""
        if record.__class__.__name__ not in _SUPPORTED_TYPES:
            raise TypeError(f"unsupported record type: {record.__class__.__name__}")

        title, content = _search_document(record)
        record_id = str(record.id)
        machine_id = _machine_id(record)
        now = datetime.now(UTC).isoformat()
        created_at = getattr(record, "created_at", None)
        created = created_at.isoformat() if created_at is not None else now

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO records(
                    id, kind, machine_id, title, content, payload, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    kind = excluded.kind,
                    machine_id = excluded.machine_id,
                    title = excluded.title,
                    content = excluded.content,
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (
                    record_id,
                    record.__class__.__name__,
                    machine_id,
                    title,
                    content,
                    record.model_dump_json(),
                    created,
                    now,
                ),
            )
            self.connection.execute("DELETE FROM records_fts WHERE record_id = ?", (record_id,))
            self.connection.execute(
                "INSERT INTO records_fts(record_id, title, content) VALUES (?, ?, ?)",
                (record_id, title, content),
            )

    def get(self, model_type: type[RecordT], record_id: UUID | str) -> RecordT | None:
        """Load one record when both its id and expected model type match."""
        row = self.connection.execute(
            "SELECT kind, payload FROM records WHERE id = ?", (str(record_id),)
        ).fetchone()
        if row is None or row["kind"] != model_type.__name__:
            return None
        return model_type.model_validate_json(row["payload"])

    def search(
        self,
        query: str,
        *,
        kinds: tuple[str, ...] | None = None,
        machine_id: UUID | str | None = None,
        limit: int = 20,
    ) -> list[SearchHit]:
        """Search indexed text. Terms are combined with AND for predictable results."""
        match_query = _fts_query(query)
        if limit < 1:
            raise ValueError("limit must be positive")

        clauses = ["records_fts MATCH ?"]
        parameters: list[object] = [match_query]
        if kinds:
            unknown = set(kinds) - _SUPPORTED_TYPES.keys()
            if unknown:
                raise ValueError(f"unknown record kinds: {', '.join(sorted(unknown))}")
            placeholders = ", ".join("?" for _ in kinds)
            clauses.append(f"records.kind IN ({placeholders})")
            parameters.extend(kinds)
        if machine_id is not None:
            clauses.append("records.machine_id = ?")
            parameters.append(str(machine_id))
        parameters.append(limit)

        rows = self.connection.execute(
            f"""
            SELECT
                records.id,
                records.kind,
                records.title,
                snippet(records_fts, 2, '[', ']', ' … ', 12) AS snippet,
                bm25(records_fts) AS rank
            FROM records_fts
            JOIN records ON records.id = records_fts.record_id
            WHERE {" AND ".join(clauses)}
            ORDER BY rank
            LIMIT ?
            """,
            parameters,
        ).fetchall()
        return [
            SearchHit(
                id=row["id"],
                kind=row["kind"],
                title=row["title"],
                snippet=row["snippet"],
                rank=row["rank"],
            )
            for row in rows
        ]

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> SednaStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _machine_id(record: SednaRecord) -> str | None:
    if isinstance(record, Machine):
        return str(record.id)
    value = getattr(record, "machine_id", None)
    return str(value) if value is not None else None


def _search_document(record: SednaRecord) -> tuple[str, str]:
    """Build searchable text while deliberately excluding credential/loot secrets."""
    if isinstance(record, Machine):
        return record.name, " ".join(
            value for value in (record.ip, record.platform, record.os, *record.tags) if value
        )
    if isinstance(record, Finding):
        return record.title, " ".join(
            value
            for value in (
                record.description,
                record.tool,
                record.raw_output,
                record.cve,
                *record.tags,
            )
            if value
        )
    if isinstance(record, Credential):
        return f"{record.username}@{record.service}", " ".join(
            value for value in (record.source, record.hash_type) if value
        )
    if isinstance(record, Loot):
        return record.kind, " ".join(value for value in (record.description, record.path) if value)
    if isinstance(record, Engagement):
        return f"engagement:{record.id}", " ".join(
            (record.notes, *record.objectives, *record.completed_objectives)
        )
    if isinstance(record, KnowledgeChunk):
        return record.title, " ".join(
            value
            for value in (
                record.content,
                record.summary,
                *record.tags,
                *record.tool_refs,
                *record.technique_refs,
            )
            if value
        )
    if isinstance(record, Technique):
        return record.name, " ".join(
            value
            for value in (
                record.description,
                record.mitre_id,
                record.tactic,
                *record.platforms,
                *record.prerequisites,
                *record.tools,
            )
            if value
        )
    if isinstance(record, ToolRef):
        return record.name, " ".join(
            value
            for value in (
                record.category,
                record.description,
                *record.common_flags,
                *record.examples,
            )
            if value
        )
    raise TypeError(f"unsupported record type: {record.__class__.__name__}")


def _fts_query(query: str) -> str:
    terms = re.findall(r"\w+", query, flags=re.UNICODE)
    if not terms:
        raise ValueError("query must contain searchable text")
    return " AND ".join(f'"{term}"' for term in terms)
