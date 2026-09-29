"""Descriptor-confined durable storage for append-only engagement journals."""

from __future__ import annotations

import base64
import errno
import fcntl
import json
import os
import re
import stat
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from sedna.engagement.events import (
    CasePromotedPayload,
    CasePromotionRevokedPayload,
    CasePromotionSupersededPayload,
    EngagementReopenedPayload,
    EventType,
    EvidenceAttachedPayload,
    FlagRejectedPayload,
    JournalEvent,
    JournalEventDraft,
    LaneBoundPayload,
    LaneUnboundPayload,
    PromotionAttemptCancellationRequestedPayload,
    PromotionAttemptTerminatedPayload,
    PromotionCandidateReadyPayload,
    PromotionIndexPendingPayload,
    PromotionIndexRetryFailedPayload,
    PromotionRequestedPayload,
    PromotionRevocationRequestedPayload,
    PromotionSemanticCommittedPayload,
    PromotionSourceCommittedPayload,
    RecoveryWarningPayload,
    RevocationLifecycleIntent,
    SystemCorrelation,
    canonical_event_hash,
    canonical_event_json_bytes,
)
from sedna.engagement.models import (
    MAX_CREATE_INTENT_BYTES,
    MAX_DERIVED_PROJECTION_BYTES,
    MAX_ENGAGEMENT_DIRECTORY_ENTRIES,
    MAX_ENGAGEMENTS,
    MAX_EVIDENCE_DIRECTORY_ENTRIES,
    MAX_EVIDENCE_ENGAGEMENT_BYTES,
    MAX_EVIDENCE_ITEM_BYTES,
    MAX_EVIDENCE_OBJECTS,
    MAX_JOURNAL_BATCH_EVENTS,
    MAX_JOURNAL_BYTES,
    MAX_JOURNAL_EVENT_BYTES,
    MAX_JOURNAL_EVENTS,
    MAX_JOURNAL_HEAD_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_PENDING_APPEND_BYTES,
    MAX_RECOVERABLE_TAIL_BYTES,
    MAX_STRATEGY_ARCHIVE_BYTES,
    MAX_STRATEGY_ARCHIVE_RECORD_BYTES,
    MAX_STRATEGY_ARCHIVE_RECORDS,
    MAX_TAIL_RECOVERY_INTENT_BYTES,
    EngagementManifest,
    EvidenceId,
    EvidenceReference,
    EvidenceSlice,
    ExecutionLaneKey,
    JournalRevision,
    OrphanEvidencePage,
    PromotionSagaInProgressError,
    StrategyArchiveCommitResult,
    StrategyArchivePage,
    StrategyArchiveProjectionEnvelope,
    StrategyArchiveRecordDraft,
)
from sedna.engagement.reducer import reduce_engagement

JOURNAL_HEAD_SCHEMA_VERSION = "sedna.journal-head.v1"

PROJECTION_OWNERS = {
    "engagement-state": "engagement",
    "state": "planning",
    "frontier": "planning",
    "strategy-ledger": "planning",
}

STRATEGY_ARCHIVE_NAME = "strategy-archive.jsonl"
MAX_PROMOTION_SOURCE_FILE_BYTES = 96 * 1024
MAX_PROMOTION_PROVENANCE_FILE_BYTES = 64 * 1024
MAX_PROMOTION_SOURCE_INTENT_BYTES = 256 * 1024
MAX_PROMOTION_CANDIDATE_FILE_BYTES = 512 * 1024
MAX_PROMOTION_CANDIDATE_INTENT_BYTES = 8 * 1024


class RevisionConflictError(ValueError):
    """A compare-and-swap revision did not match the authoritative journal head."""


class ProjectionOwnershipError(ValueError):
    """A projection writer attempted to cross a sealed ownership boundary."""


class EngagementAppendAuthorityError(ValueError):
    """A generic append attempted to emit a repository-owned event."""


class JournalUnavailableError(ValueError):
    """The journal cannot be served without weakening its durability contract."""


class JournalHead(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_version: Literal[JOURNAL_HEAD_SCHEMA_VERSION] = JOURNAL_HEAD_SCHEMA_VERSION
    engagement_id: UUID
    revision: JournalRevision
    event_count: StrictInt = Field(ge=0, le=MAX_JOURNAL_EVENTS)
    journal_bytes: StrictInt = Field(ge=0, le=MAX_JOURNAL_BYTES)
    journal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AppendResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event: JournalEvent
    revision: JournalRevision
    created: bool


class BatchAppendResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    events: tuple[JournalEvent, ...]
    revision: JournalRevision
    created_event_ids: tuple[UUID, ...] = ()
    existing_event_ids: tuple[UUID, ...] = ()


class _RecoverableTailError(Exception):
    def __init__(self, tail: bytes, head: JournalHead, recovery_lane: ExecutionLaneKey) -> None:
        self.tail = tail
        self.head = head
        self.recovery_lane = recovery_lane


class _RegistryTailRecoveryRequiredError(Exception):
    def __init__(self, engagement_id: UUID) -> None:
        self.engagement_id = engagement_id


@dataclass(frozen=True)
class _CreateRecovery:
    engagement_id: UUID
    manifest: EngagementManifest
    manifest_bytes: bytes
    events: tuple[JournalEvent, ...]
    journal_bytes: bytes
    head: JournalHead
    head_bytes: bytes
    projection_bytes: bytes


def _require_posix_primitives() -> None:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required) or not hasattr(fcntl, "flock"):
        raise JournalUnavailableError("required POSIX descriptor primitives are unavailable")
    if os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd:
        raise JournalUnavailableError("required POSIX descriptor primitives are unavailable")


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _read_flags() -> int:
    return os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _create_flags(*, append: bool = False) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if append:
        flags |= os.O_APPEND
    return flags | getattr(os, "O_CLOEXEC", 0)


def _canonical_json(value: Any) -> bytes:
    """Canonical JSON bytes.

    Delegates to ``events.canonical_event_json_bytes`` so that the repository,
    the reducer and the event module share ONE serialization. Divergence here
    was a real defect: event hashes written by creation could not be reproduced
    by validation for non-ASCII payloads.
    """
    return canonical_event_json_bytes(value)


def _model_bytes(model: BaseModel) -> bytes:
    return _canonical_json(model.model_dump(mode="json", warnings="error"))


def _canonical_projection_envelope(value: Mapping[str, Any]) -> bytes:
    material = dict(value)
    material.pop("projection_digest", None)
    digest = sha256(_canonical_json(material)).hexdigest()
    material["projection_digest"] = digest
    return _canonical_json(material)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short descriptor write")
        view = view[written:]


def _validate_regular(fd: int, *, label: str, expected_mode: int | None = None) -> os.stat_result:
    result = os.fstat(fd)
    if not stat.S_ISREG(result.st_mode):
        raise JournalUnavailableError(f"{label} must be a regular file")
    if expected_mode is not None and stat.S_IMODE(result.st_mode) != expected_mode:
        raise JournalUnavailableError(f"{label} has an unsafe mode")
    return result


def _validate_directory(fd: int, *, label: str, expected_mode: int) -> os.stat_result:
    result = os.fstat(fd)
    if not stat.S_ISDIR(result.st_mode):
        raise JournalUnavailableError(f"{label} must be a directory")
    if stat.S_IMODE(result.st_mode) != expected_mode:
        raise JournalUnavailableError(f"{label} has an unsafe mode")
    return result


def _revision(events: Sequence[JournalEvent]) -> JournalRevision:
    if not events:
        return JournalRevision(sequence=0, event_hash="0" * 64)
    event = events[-1]
    return JournalRevision(sequence=event.sequence, event_hash=event.event_hash)


def _head(engagement_id: UUID, events: Sequence[JournalEvent], data: bytes) -> JournalHead:
    return JournalHead(
        engagement_id=engagement_id,
        revision=_revision(events),
        event_count=len(events),
        journal_bytes=len(data),
        journal_sha256=sha256(data).hexdigest(),
    )


def _event_line(event: JournalEvent) -> bytes:
    return _model_bytes(event)


def _draft_material(event: JournalEvent) -> dict[str, Any]:
    return event.model_dump(
        mode="json",
        exclude={
            "schema_version",
            "event_id",
            "sequence",
            "occurred_at",
            "engagement_id",
            "previous_hash",
            "event_hash",
        },
    )


def _complete_staged_create_value(name: str, data: bytes, engagement_id: UUID) -> bool:
    try:
        if name == "engagement.json":
            return EngagementManifest.model_validate_json(data).engagement_id == engagement_id
        if name == "journal-head.json":
            return JournalHead.model_validate_json(data).engagement_id == engagement_id
        if name == "events.jsonl":
            if not data or not data.endswith(b"\n"):
                return False
            events = tuple(
                JournalEvent.model_validate_json(line) for line in _iter_journal_lines(data)
            )
            return bool(events) and all(event.engagement_id == engagement_id for event in events)
    except Exception:
        return False
    return False


class _EvidenceObjectStore:
    """Private normalized-byte object primitive shared with the future public store."""

    def __init__(
        self,
        engagement_fd: int,
        *,
        fault: Callable[[str], None] | None = None,
        max_item_bytes: int | None = None,
        max_objects: int | None = None,
        max_engagement_bytes: int | None = None,
    ) -> None:
        self._engagement_fd = engagement_fd
        self._fault = fault or (lambda _point: None)
        self._max_item_bytes = MAX_EVIDENCE_ITEM_BYTES if max_item_bytes is None else max_item_bytes
        self._max_objects = MAX_EVIDENCE_OBJECTS if max_objects is None else max_objects
        self._max_engagement_bytes = (
            MAX_EVIDENCE_ENGAGEMENT_BYTES if max_engagement_bytes is None else max_engagement_bytes
        )

    def capture(self, data: bytes) -> EvidenceReference:
        if not isinstance(data, bytes):
            raise TypeError("evidence object store accepts normalized bytes only")
        if len(data) > self._max_item_bytes:
            raise ValueError("evidence item quota exceeded")
        digest = sha256(data).hexdigest()
        name = f"blob-{digest}.bin"
        pending_name = f".pending-blob-{digest}.bin"
        with _locked_file(self._engagement_fd, ".evidence.lock"):
            evidence_fd = _open_or_create_directory(self._engagement_fd, "evidence", 0o700)
            try:
                entries = _scan_directory_bounded(
                    evidence_fd,
                    MAX_EVIDENCE_DIRECTORY_ENTRIES,
                    "evidence directory",
                )
                objects: list[tuple[str, int, tuple[int, int]]] = []
                for entry in entries:
                    if entry.startswith("blob-") and entry.endswith(".bin"):
                        expected_digest = entry[len("blob-") : -len(".bin")]
                    elif entry.startswith(".pending-blob-") and entry.endswith(".bin"):
                        expected_digest = entry[len(".pending-blob-") : -len(".bin")]
                    elif _is_quarantine_payload_name(entry):
                        fd = _open_regular(
                            evidence_fd,
                            entry,
                            self._max_item_bytes,
                            "quarantined evidence",
                        )
                        try:
                            quarantine_stat = os.fstat(fd)
                            objects.append(
                                (
                                    entry,
                                    quarantine_stat.st_size,
                                    (quarantine_stat.st_dev, quarantine_stat.st_ino),
                                )
                            )
                        finally:
                            os.close(fd)
                        continue
                    elif (
                        _is_capture_intent_name(entry)
                        or _is_logbook_temp_name(entry)
                        or _is_logbook_canonical_name(entry)
                    ):
                        # Recognized non-payload Task 4 metadata: bounded pre-stat only.
                        metadata_fd = _open_regular(
                            evidence_fd,
                            entry,
                            MAX_DERIVED_PROJECTION_BYTES,
                            "evidence metadata",
                        )
                        try:
                            os.fstat(metadata_fd)
                        finally:
                            os.close(metadata_fd)
                        continue
                    else:
                        raise JournalUnavailableError("invalid evidence directory entry")
                    if len(expected_digest) != 64 or any(
                        char not in "0123456789abcdef" for char in expected_digest
                    ):
                        raise JournalUnavailableError("invalid evidence object digest name")
                    fd = _open_regular(
                        evidence_fd,
                        entry,
                        self._max_item_bytes,
                        "evidence object",
                    )
                    try:
                        object_stat = os.fstat(fd)
                        content_digest = sha256()
                        while True:
                            chunk = os.read(fd, 65_536)
                            if not chunk:
                                break
                            content_digest.update(chunk)
                        if content_digest.hexdigest() != expected_digest and entry != pending_name:
                            raise JournalUnavailableError(
                                "evidence object filename digest mismatch"
                            )
                        objects.append(
                            (
                                entry,
                                object_stat.st_size,
                                (object_stat.st_dev, object_stat.st_ino),
                            )
                        )
                    finally:
                        os.close(fd)
                canonical_count = sum(item.startswith("blob-") for item, _, _ in objects)
                quarantine_count = sum(item.startswith(".quarantine-") for item, _, _ in objects)
                object_count = canonical_count + quarantine_count
                payload_by_identity = {identity: size for _, size, identity in objects}
                payload_bytes = sum(payload_by_identity.values())
                existing = next((size for item, size, _ in objects if item == name), None)
                if object_count > self._max_objects:
                    raise ValueError("evidence object quota exceeded")
                if payload_bytes > self._max_engagement_bytes:
                    raise ValueError("evidence engagement quota exceeded")
                if existing is not None:
                    found = _read_bounded(
                        evidence_fd,
                        name,
                        MAX_EVIDENCE_ITEM_BYTES,
                        "evidence object",
                    )
                    if found != data:
                        raise JournalUnavailableError("evidence digest collision")
                    if pending_name in entries:
                        pending = _read_bounded(
                            evidence_fd,
                            pending_name,
                            MAX_EVIDENCE_ITEM_BYTES,
                            "pending evidence object",
                        )
                        if pending != data:
                            raise JournalUnavailableError(
                                "pending evidence object does not match canonical object"
                            )
                        os.unlink(pending_name, dir_fd=evidence_fd)
                        os.fsync(evidence_fd)
                else:
                    if object_count + 1 > self._max_objects:
                        raise ValueError("evidence object quota exceeded")
                    pending = next(
                        (size for item, size, _ in objects if item == pending_name),
                        None,
                    )
                    if pending is not None:
                        pending_data = _read_bounded(
                            evidence_fd,
                            pending_name,
                            self._max_item_bytes,
                            "pending evidence object",
                        )
                        if pending_data != data:
                            os.unlink(pending_name, dir_fd=evidence_fd)
                            os.fsync(evidence_fd)
                            objects = [item for item in objects if item[0] != pending_name]
                            pending = None
                            payload_bytes = sum(
                                {identity: size for _, size, identity in objects}.values()
                            )
                    additional = 0 if pending is not None else len(data)
                    if payload_bytes + additional > self._max_engagement_bytes:
                        raise ValueError("evidence engagement quota exceeded")
                    if pending is None:
                        self._fault("evidence_before_temp_write")
                        fd = os.open(
                            pending_name,
                            _create_flags(),
                            0o600,
                            dir_fd=evidence_fd,
                        )
                        try:
                            os.fchmod(fd, 0o600)
                            split = max(1, len(data) // 2) if data else 0
                            _write_all(fd, data[:split])
                            self._fault("evidence_after_partial_temp_write")
                            _write_all(fd, data[split:])
                            self._fault("evidence_after_complete_temp_write")
                            os.fsync(fd)
                            self._fault("evidence_after_file_fsync")
                        finally:
                            os.close(fd)
                    try:
                        os.link(
                            pending_name,
                            name,
                            src_dir_fd=evidence_fd,
                            dst_dir_fd=evidence_fd,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        found = _read_bounded(
                            evidence_fd,
                            name,
                            self._max_item_bytes,
                            "evidence object",
                        )
                        if found != data:
                            raise JournalUnavailableError("evidence digest collision") from None
                    self._fault("evidence_after_publication")
                    os.fsync(evidence_fd)
                    self._fault("evidence_after_directory_fsync")
                    with suppress(FileNotFoundError):
                        os.unlink(pending_name, dir_fd=evidence_fd)
                    os.fsync(evidence_fd)
            finally:
                os.close(evidence_fd)
        return EvidenceReference(
            evidence_id=f"evidence-sha256-{digest}",
            sha256=digest,
            size=len(data),
            media_type="application/octet-stream",
            representation="recovery_tail",
            relative_path=f"evidence/{name}",
        )

    def load(self, digest: str, size: int) -> bytes:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise JournalUnavailableError("tail recovery evidence digest is invalid")
        if not 0 <= size <= self._max_item_bytes:
            raise JournalUnavailableError("tail recovery evidence size is invalid")
        with _locked_file(self._engagement_fd, ".evidence.lock"):
            evidence_fd = _open_or_create_directory(self._engagement_fd, "evidence", 0o700)
            try:
                data = _read_bounded(
                    evidence_fd,
                    f"blob-{digest}.bin",
                    self._max_item_bytes,
                    "tail recovery evidence",
                )
            finally:
                os.close(evidence_fd)
        if len(data) != size or sha256(data).hexdigest() != digest:
            raise JournalUnavailableError("tail recovery evidence does not match its intent")
        return data


def _tail_recovery_drafts(
    engagement_id: UUID,
    lane: ExecutionLaneKey,
    digest: str,
    size: int,
) -> tuple[JournalEventDraft, JournalEventDraft]:
    reference = EvidenceReference(
        evidence_id=f"evidence-sha256-{digest}",
        sha256=digest,
        size=size,
        media_type="application/octet-stream",
        representation="recovery_tail",
        relative_path=f"evidence/blob-{digest}.bin",
    )
    correlation = SystemCorrelation(
        source="recovery",
        operation_id=uuid5(NAMESPACE_URL, f"sedna-tail-operation:{engagement_id}:{digest}"),
    )
    return (
        JournalEventDraft(
            event_id=uuid5(NAMESPACE_URL, f"sedna-tail-evidence:{engagement_id}:{digest}"),
            lane=lane,
            actor="host_agent",
            type="evidence_attached",
            payload=EvidenceAttachedPayload(evidence=reference),
            idempotency_key=f"tail-evidence:{digest}",
        ),
        JournalEventDraft(
            event_id=uuid5(NAMESPACE_URL, f"sedna-tail-warning:{engagement_id}:{digest}"),
            actor="system",
            type="recovery_warning",
            payload=RecoveryWarningPayload(
                reason_code="partial_final_jsonl_record",
                evidence_id=reference.evidence_id,
            ),
            system_correlation=correlation,
            idempotency_key=f"tail-warning:{digest}",
        ),
    )


def _open_or_create_directory(parent_fd: int, name: str, mode: int) -> int:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise JournalUnavailableError(f"unsafe directory: {name}") from exc
    try:
        _validate_directory(fd, label=name, expected_mode=mode)
    except Exception:
        os.close(fd)
        raise
    return fd


def _open_regular(parent_fd: int, name: str, bound: int, label: str) -> int:
    try:
        fd = os.open(name, _read_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise JournalUnavailableError(f"unable to open {label}") from exc
    try:
        result = _validate_regular(fd, label=label, expected_mode=0o600)
        if result.st_size > bound:
            raise JournalUnavailableError(f"{label} exceeds its byte bound")
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_bounded(parent_fd: int, name: str, bound: int, label: str) -> bytes:
    fd = _open_regular(parent_fd, name, bound, label)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, bound + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > bound:
                raise JournalUnavailableError(f"{label} exceeds its byte bound")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _scan_directory_bounded(parent_fd: int, bound: int, label: str) -> list[str]:
    entries: list[str] = []
    with os.scandir(parent_fd) as iterator:
        for entry in iterator:
            if len(entries) >= bound:
                raise JournalUnavailableError(f"{label} entry bound exceeded")
            entries.append(entry.name)
    return entries


def _iter_journal_lines(data: bytes) -> Iterator[bytes]:
    start = 0
    count = 0
    while start < len(data):
        end = data.find(b"\n", start)
        if end < 0:
            end = len(data)
            next_start = len(data)
        else:
            next_start = end + 1
        line = data[start:end]
        count += 1
        if count > MAX_JOURNAL_EVENTS:
            raise ValueError("journal event count exceeds its bound")
        if len(line) > MAX_JOURNAL_EVENT_BYTES:
            raise ValueError("journal event exceeds its byte bound")
        yield line
        start = next_start


def _atomic_write(parent_fd: int, name: str, data: bytes) -> None:
    try:
        existing_fd = os.open(name, _read_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise JournalUnavailableError(f"unsafe atomic target: {name}") from exc
    else:
        try:
            _validate_regular(existing_fd, label=name, expected_mode=0o600)
        finally:
            os.close(existing_fd)
    temporary = f".{name}.tmp-{uuid4()}"
    try:
        fd = os.open(temporary, _create_flags(), 0o600, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o600)
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent_fd)
        with suppress(OSError):
            os.fsync(parent_fd)
        raise
    try:
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=parent_fd)
        raise


def _archive_header_bytes(envelope: StrategyArchiveProjectionEnvelope) -> bytes:
    return _model_bytes(envelope) + b"\n"


def _archive_record_bytes(record: StrategyArchiveRecordDraft, archive_revision: int) -> bytes:
    return (
        _canonical_json(
            {
                "archive_revision": archive_revision,
                "entry_id": str(record.entry_id),
                "payload": record.payload,
            }
        )
        + b"\n"
    )


def _archive_envelope(
    *,
    schema_id: str,
    archive_revision: int,
    journal_revision: JournalRevision,
    entry_count: int,
    entries_sha256: str,
    entry_bytes: int,
) -> StrategyArchiveProjectionEnvelope:
    """Resolve the small self-referential total-byte header deterministically."""
    byte_size = entry_bytes + 1
    for _ in range(8):
        envelope = StrategyArchiveProjectionEnvelope(
            schema_id=schema_id,
            archive_revision=archive_revision,
            authoritative_journal_revision=journal_revision,
            entry_count=entry_count,
            entries_sha256=entries_sha256,
            byte_size=byte_size,
        )
        resolved = entry_bytes + len(_archive_header_bytes(envelope))
        if resolved == byte_size:
            return envelope
        byte_size = resolved
    raise JournalUnavailableError("strategy archive header byte size did not converge")


def _archive_read_lines(fd: int) -> Iterator[bytes]:
    """Yield newline-terminated archive lines without retaining the complete archive."""
    buffered = b""
    while True:
        chunk = os.read(fd, 65_536)
        if not chunk:
            break
        buffered += chunk
        while b"\n" in buffered:
            line, buffered = buffered.split(b"\n", 1)
            if len(line) > MAX_STRATEGY_ARCHIVE_RECORD_BYTES + 1024:
                raise JournalUnavailableError("strategy archive line exceeds its byte bound")
            yield line
        if len(buffered) > MAX_STRATEGY_ARCHIVE_RECORD_BYTES + 1024:
            raise JournalUnavailableError("strategy archive line exceeds its byte bound")
    if buffered:
        raise JournalUnavailableError("strategy archive is missing its final newline")


@contextmanager
def _locked_file(parent_fd: int, name: str):
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd: int | None = None
    for _ in range(3):
        try:
            fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
            break
        except FileNotFoundError:
            # A concurrently created descriptor-relative lock can transiently race
            # with another opener on Darwin. The retained parent remains authoritative.
            continue
        except OSError as exc:
            raise JournalUnavailableError(f"unable to open lock {name}") from exc
    if fd is None:
        raise JournalUnavailableError(f"unable to open lock {name}")
    try:
        _validate_regular(fd, label=name, expected_mode=0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


class _ReportCommitCapability:
    """Repository-issued authority for immutable report transactions only."""

    def __init__(self, repository: Any, token: object) -> None:
        if token is not repository._report_capability_token:
            raise ValueError("invalid report capability token")
        self._repository = repository
        self._token = token

    def _require_holder(self) -> None:
        if self._token is not self._repository._report_capability_token:
            raise ValueError("invalid report capability holder")

    def commit_report_snapshot(self, engagement_id, report, markdown, *, expected_revision):
        self._require_holder()
        return self._repository._commit_report_snapshot(
            engagement_id,
            report,
            markdown,
            expected_revision=expected_revision,
        )

    def commit_report_revision(
        self,
        engagement_id,
        report,
        markdown,
        *,
        generation_reason,
        expected_revision,
    ):
        self._require_holder()
        return self._repository._commit_report_revision(
            engagement_id,
            report,
            markdown,
            generation_reason=generation_reason,
            expected_revision=expected_revision,
        )

    def repair_markdown(self, engagement_id, report_revision, *, expected_revision):
        self._require_holder()
        return self._repository._repair_markdown(
            engagement_id,
            report_revision,
            expected_revision=expected_revision,
        )


@dataclass(frozen=True)
class _PromotionSourceWriteResult:
    event: JournalEvent
    revision: JournalRevision
    created: bool


@dataclass(frozen=True)
class _PromotionClaimWriteResult:
    event: JournalEvent | None
    attempt: Any | None
    revision: JournalRevision
    disposition: Literal["created", "resumed", "existing", "retry_exhausted"]


@dataclass(frozen=True)
class _PromotionMutationWriteResult:
    event_id: UUID
    revision: JournalRevision


class _PromotionJournalWriter:
    """Repository-issued, data-only authority for promotion journal transactions."""

    def __init__(self, repository: Any, token: object) -> None:
        if token is not repository._promotion_capability_token:
            raise ValueError("invalid promotion capability token")
        self._repository = repository
        self._token = token
        self._holder_token = object()

    def _require_holder(self) -> None:
        if self._token is not self._repository._promotion_capability_token:
            raise ValueError("invalid promotion capability holder")

    def commit_source(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_source(engagement_id, **values)

    def claim(self, engagement_id, **values):
        self._require_holder()
        return self._repository._claim_promotion(
            engagement_id,
            holder_token=self._holder_token,
            **values,
        )

    def commit_candidate(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_candidate(engagement_id, **values)

    def load_candidate(self, engagement_id, **values):
        self._require_holder()
        return self._repository._load_promotion_candidate(engagement_id, **values)

    def terminate(self, engagement_id, **values):
        self._require_holder()
        return self._repository._terminate_promotion(
            engagement_id,
            holder_token=self._holder_token,
            **values,
        )

    def commit_semantic(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_semantic(engagement_id, **values)

    def commit_index_pending(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_index_pending(engagement_id, **values)

    def commit_index_retry(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_index_retry(engagement_id, **values)

    def commit_promoted(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promoted_case(engagement_id, **values)

    def commit_superseded_and_promoted(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_superseded_and_promoted(engagement_id, **values)

    def request_cancellation(self, engagement_id, **values):
        self._require_holder()
        return self._repository._request_promotion_cancellation(engagement_id, **values)

    def request_revocation(self, engagement_id, **values):
        self._require_holder()
        return self._repository._request_promotion_revocation(engagement_id, **values)

    def commit_cleanup_and_reopen(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_cleanup_and_reopen(engagement_id, **values)

    def commit_cleanup_reject_and_reopen(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_promotion_cleanup_and_reopen(engagement_id, **values)

    def commit_empty_reject_and_reopen(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_empty_revocation(
            engagement_id,
            operation="reject",
            **values,
        )

    def commit_empty_and_reopen(self, engagement_id, **values):
        self._require_holder()
        return self._repository._commit_empty_revocation(
            engagement_id,
            operation="reopen",
            proof_rejection=None,
            **values,
        )

    def load_snapshot(self, engagement_id):
        self._require_holder()
        return self._repository.load_snapshot(engagement_id)

    def authenticate_claim(self, engagement_id, **values):
        self._require_holder()
        return self._repository._authenticate_promotion_claim_holder(
            engagement_id,
            holder_token=self._holder_token,
            **values,
        )


class EngagementJournalRepository:
    """Append-only engagement repository rooted in retained POSIX descriptors."""

    def __init__(
        self,
        knowledge_root: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
        uuid_factory: Callable[[], UUID] | None = None,
        evidence_quota: Any | None = None,
    ) -> None:
        _require_posix_primitives()
        if evidence_quota is None:
            from sedna.engagement.evidence import DEFAULT_EVIDENCE_QUOTA

            evidence_quota = DEFAULT_EVIDENCE_QUOTA
        self._evidence_quota = evidence_quota
        raw = os.fspath(knowledge_root)
        if not isinstance(raw, str) or "\0" in raw or not os.path.isabs(raw):
            raise ValueError("knowledge root must be an absolute NUL-free path")
        self._knowledge_root = Path(raw)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._uuid_factory = uuid_factory or uuid4
        self._closed = False
        self._report_capability_token = object()
        self._promotion_capability_token = object()
        self._lifecycle_capability_token = object()
        self._owned_promotion_attempt_ids: set[UUID] = set()
        self._promotion_claim_holders: dict[UUID, tuple[UUID, object, int]] = {}
        self._root_fd = self._open_absolute_root(raw)
        try:
            _validate_directory(self._root_fd, label="knowledge root", expected_mode=0o700)
            pathname = os.stat(raw, follow_symlinks=False)
            retained = os.fstat(self._root_fd)
            if not stat.S_ISDIR(pathname.st_mode) or (
                pathname.st_dev,
                pathname.st_ino,
            ) != (retained.st_dev, retained.st_ino):
                raise JournalUnavailableError("knowledge root descriptor identity mismatch")
            self._engagements_fd = _open_or_create_directory(self._root_fd, "engagements", 0o700)
            entries = self._bounded_engagement_entries()
            if ".registry.lock" not in entries and len(entries) >= MAX_ENGAGEMENT_DIRECTORY_ENTRIES:
                raise JournalUnavailableError("engagement directory entry bound exceeded")
            self._retry_registry_tail_recovery(self._recover_registry_once)
        except Exception:
            with suppress(AttributeError):
                os.close(self._engagements_fd)
            os.close(self._root_fd)
            raise

    @staticmethod
    def _open_absolute_root(path: str) -> int:
        current = os.open("/", _directory_flags())
        try:
            for component in Path(path).parts[1:]:
                if component in {"", ".", ".."}:
                    raise ValueError("knowledge root contains an unsafe component")
                try:
                    next_fd = os.open(component, _directory_flags(), dir_fd=current)
                except FileNotFoundError:
                    try:
                        os.mkdir(component, 0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                    else:
                        os.fsync(current)
                    next_fd = os.open(component, _directory_flags(), dir_fd=current)
                os.close(current)
                current = next_fd
            return current
        except Exception:
            os.close(current)
            raise

    def __enter__(self) -> EngagementJournalRepository:
        self._require_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for _, _, lock_fd in self._promotion_claim_holders.values():
            with suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(lock_fd)
        self._promotion_claim_holders.clear()
        os.close(self._engagements_fd)
        os.close(self._root_fd)

    def _require_open(self) -> None:
        if self._closed:
            raise JournalUnavailableError("repository is closed")

    def _retry_registry_tail_recovery(self, operation: Callable[[], Any]) -> Any:
        for _ in range(MAX_ENGAGEMENTS + 1):
            try:
                return operation()
            except _RegistryTailRecoveryRequiredError as recovery:
                self._complete_tail_recovery(recovery.engagement_id)
        raise JournalUnavailableError("registry tail-recovery retry bound exceeded")

    def _recover_registry_once(self) -> None:
        with _locked_file(self._engagements_fd, ".registry.lock"):
            entries = self._bounded_engagement_entries()
            self._recover_pending_creates(entries)
            entries = self._bounded_engagement_entries()
            for name in entries:
                entry_stat = os.stat(
                    name,
                    dir_fd=self._engagements_fd,
                    follow_symlinks=False,
                )
                if (
                    _is_uuid_name(name)
                    and stat.S_ISDIR(entry_stat.st_mode)
                    and stat.S_IMODE(entry_stat.st_mode) == 0o700
                ):
                    self._recover_published_create_intent(UUID(name))
            self._bounded_engagement_entries()

    def _fault(self, point: str) -> None:
        del point

    def _bounded_engagement_entries(self) -> list[str]:
        return _scan_directory_bounded(
            self._engagements_fd,
            MAX_ENGAGEMENT_DIRECTORY_ENTRIES,
            "engagement directory",
        )

    def list_snapshot_ids(self) -> tuple[UUID, ...]:
        """Return published engagement UUIDs under the registry lock (bounded)."""
        self._require_open()
        with _locked_file(self._engagements_fd, ".registry.lock"):
            entries = self._bounded_engagement_entries()
            return tuple(UUID(name) for name in entries if _is_uuid_name(name))

    def _recover_pending_creates(self, entries: Sequence[str]) -> None:
        pending: list[tuple[str, UUID]] = []
        published = {name for name in entries if _is_uuid_name(name)}
        for name in entries:
            engagement_id = _pending_create_id(name)
            if engagement_id is not None:
                pending.append((name, engagement_id))
        prospective = len(published) + sum(
            str(engagement_id) not in published for _, engagement_id in pending
        )
        if prospective > MAX_ENGAGEMENTS:
            raise JournalUnavailableError("engagement count exceeds its bound")
        for name, engagement_id in pending:
            self._recover_pending_create(name, engagement_id)

    def _decode_create_intent(self, raw: bytes, expected_engagement_id: UUID) -> _CreateRecovery:
        try:
            value = json.loads(raw)
            if _canonical_json(value) != raw:
                raise ValueError("intent is not canonical")
            if set(value) != {
                "engagement_id",
                "manifest",
                "journal",
                "head",
                "manifest_sha256",
                "journal_sha256",
                "head_sha256",
            }:
                raise ValueError("intent fields differ")
            manifest_bytes = base64.b64decode(value["manifest"], validate=True)
            journal_bytes = base64.b64decode(value["journal"], validate=True)
            head_bytes = base64.b64decode(value["head"], validate=True)
            if (
                value["engagement_id"] != str(expected_engagement_id)
                or sha256(manifest_bytes).hexdigest() != value["manifest_sha256"]
                or sha256(journal_bytes).hexdigest() != value["journal_sha256"]
                or sha256(head_bytes).hexdigest() != value["head_sha256"]
            ):
                raise ValueError("intent digest mismatch")
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise ValueError("manifest exceeds limits")
            manifest = EngagementManifest.model_validate_json(manifest_bytes)
            if manifest_bytes != _model_bytes(manifest):
                raise ValueError("manifest is not canonical")
            if not journal_bytes.endswith(b"\n"):
                raise ValueError("initial journal is incomplete")
            raw_lines = tuple(_iter_journal_lines(journal_bytes))
            events = tuple(JournalEvent.model_validate_json(line) for line in raw_lines)
            if journal_bytes != b"".join(_event_line(item) + b"\n" for item in events):
                raise ValueError("initial journal is not canonical")
            if (
                len(events) != 2
                or events[0].type != "engagement_opened"
                or events[1].type != "lane_bound"
                or not isinstance(events[1].payload, LaneBoundPayload)
                or events[1].lane != events[1].payload.lane
            ):
                raise ValueError("initial event pair is invalid")
            self._validate_journal_limits(events, journal_bytes)
            head = JournalHead.model_validate_json(head_bytes)
            if (
                manifest.engagement_id != expected_engagement_id
                or head.engagement_id != expected_engagement_id
                or head_bytes != _model_bytes(head)
                or head != _head(expected_engagement_id, events, journal_bytes)
            ):
                raise ValueError("create identity or head mismatch")
            state = reduce_engagement(manifest, events)
            projection = self._projection_bytes(head.revision, state)
        except Exception as exc:
            raise JournalUnavailableError("conflicting pending create transaction") from exc
        return _CreateRecovery(
            engagement_id=expected_engagement_id,
            manifest=manifest,
            manifest_bytes=manifest_bytes,
            events=events,
            journal_bytes=journal_bytes,
            head=head,
            head_bytes=head_bytes,
            projection_bytes=projection,
        )

    @staticmethod
    def _verify_create_files(
        directory_fd: int, recovery: _CreateRecovery, *, allow_missing: bool
    ) -> tuple[str, ...]:
        missing: list[str] = []
        for name, expected in (
            ("engagement.json", recovery.manifest_bytes),
            ("events.jsonl", recovery.journal_bytes),
            ("journal-head.json", recovery.head_bytes),
        ):
            try:
                actual = _read_bounded(
                    directory_fd,
                    name,
                    max(len(expected), 1),
                    f"staged {name}",
                )
            except JournalUnavailableError as exc:
                if allow_missing and _missing_file(exc):
                    missing.append(name)
                    continue
                raise JournalUnavailableError("conflicting pending create transaction") from exc
            if actual != expected:
                raise JournalUnavailableError("conflicting pending create transaction")
        return tuple(missing)

    def _finalize_published_create(self, engagement_fd: int, recovery: _CreateRecovery) -> None:
        self._verify_create_files(engagement_fd, recovery, allow_missing=False)
        _atomic_write(engagement_fd, "engagement-state.json", recovery.projection_bytes)
        with suppress(FileNotFoundError):
            os.unlink(".create-intent.json", dir_fd=engagement_fd)
        os.fsync(engagement_fd)

    def _recover_pending_create(self, name: str, engagement_id: UUID) -> None:
        try:
            pending_fd = os.open(name, _directory_flags(), dir_fd=self._engagements_fd)
        except OSError as exc:
            raise JournalUnavailableError("unsafe pending create directory") from exc
        try:
            _validate_directory(pending_fd, label="pending create directory", expected_mode=0o700)
            entries = _scan_directory_bounded(pending_fd, 8, "pending create directory")
            intent_temp_prefix = "..create-intent.json.tmp-"
            intent_temps = [entry for entry in entries if entry.startswith(intent_temp_prefix)]
            if (
                any(not _is_uuid_name(entry[len(intent_temp_prefix) :]) for entry in intent_temps)
                or len(intent_temps) > 1
            ):
                raise JournalUnavailableError("conflicting pending create transaction")
            if intent_temps:
                temp_name = intent_temps[0]
                try:
                    temp_bytes = _read_bounded(
                        pending_fd,
                        temp_name,
                        MAX_CREATE_INTENT_BYTES,
                        "create intent temporary",
                    )
                    self._decode_create_intent(temp_bytes, engagement_id)
                except Exception:
                    os.unlink(temp_name, dir_fd=pending_fd)
                    os.fsync(pending_fd)
                else:
                    try:
                        canonical_intent = _read_bounded(
                            pending_fd,
                            ".create-intent.json",
                            MAX_CREATE_INTENT_BYTES,
                            "create intent",
                        )
                    except JournalUnavailableError as exc:
                        if not _missing_file(exc):
                            raise
                        os.replace(
                            temp_name,
                            ".create-intent.json",
                            src_dir_fd=pending_fd,
                            dst_dir_fd=pending_fd,
                        )
                        os.fsync(pending_fd)
                    else:
                        if canonical_intent != temp_bytes:
                            raise JournalUnavailableError("conflicting pending create transaction")
                        os.unlink(temp_name, dir_fd=pending_fd)
                        os.fsync(pending_fd)
                entries = _scan_directory_bounded(pending_fd, 8, "pending create directory")
            if not entries:
                os.close(pending_fd)
                pending_fd = -1
                os.rmdir(name, dir_fd=self._engagements_fd)
                os.fsync(self._engagements_fd)
                return
            staged_temp_prefixes = {
                staged_name: f".{staged_name}.tmp-"
                for staged_name in (
                    "engagement.json",
                    "events.jsonl",
                    "journal-head.json",
                )
            }
            staged_temps: dict[str, list[str]] = {
                staged_name: [] for staged_name in staged_temp_prefixes
            }
            for entry in entries:
                for staged_name, prefix in staged_temp_prefixes.items():
                    if entry.startswith(prefix):
                        if not _is_uuid_name(entry[len(prefix) :]):
                            raise JournalUnavailableError("conflicting pending create transaction")
                        staged_temps[staged_name].append(entry)
                        break
            if sum(len(temps) for temps in staged_temps.values()) > 1:
                raise JournalUnavailableError("conflicting pending create transaction")
            allowed = {
                ".create-intent.json",
                "engagement.json",
                "events.jsonl",
                "journal-head.json",
                *(temp for temps in staged_temps.values() for temp in temps),
            }
            if any(entry not in allowed for entry in entries):
                raise JournalUnavailableError("conflicting pending create transaction")
            raw = _read_bounded(
                pending_fd,
                ".create-intent.json",
                MAX_CREATE_INTENT_BYTES,
                "create intent",
            )
            recovery = self._decode_create_intent(raw, engagement_id)
            expected_by_name = {
                "engagement.json": recovery.manifest_bytes,
                "events.jsonl": recovery.journal_bytes,
                "journal-head.json": recovery.head_bytes,
            }
            staged_bounds = {
                "engagement.json": MAX_MANIFEST_BYTES,
                "events.jsonl": MAX_JOURNAL_BYTES,
                "journal-head.json": MAX_JOURNAL_HEAD_BYTES,
            }
            for staged_name, temps in staged_temps.items():
                if not temps:
                    continue
                temp_name = temps[0]
                expected = expected_by_name[staged_name]
                try:
                    temp_bytes = _read_bounded(
                        pending_fd,
                        temp_name,
                        staged_bounds[staged_name],
                        f"staged {staged_name} temporary",
                    )
                except JournalUnavailableError as exc:
                    if "exceeds its byte bound" not in str(exc):
                        raise
                    temp_bytes = b""
                if temp_bytes != expected:
                    if _complete_staged_create_value(staged_name, temp_bytes, engagement_id):
                        raise JournalUnavailableError("conflicting pending create transaction")
                    os.unlink(temp_name, dir_fd=pending_fd)
                    os.fsync(pending_fd)
                    continue
                try:
                    canonical = _read_bounded(
                        pending_fd,
                        staged_name,
                        max(len(expected), 1),
                        f"staged {staged_name}",
                    )
                except JournalUnavailableError as exc:
                    if not _missing_file(exc):
                        raise
                    os.replace(
                        temp_name,
                        staged_name,
                        src_dir_fd=pending_fd,
                        dst_dir_fd=pending_fd,
                    )
                    os.fsync(pending_fd)
                else:
                    if canonical != expected:
                        raise JournalUnavailableError("conflicting pending create transaction")
                    os.unlink(temp_name, dir_fd=pending_fd)
                    os.fsync(pending_fd)
            missing = self._verify_create_files(pending_fd, recovery, allow_missing=True)
            self._assert_lane_available(recovery.events[1].lane, exclude=engagement_id)
            for missing_name in missing:
                _atomic_write(pending_fd, missing_name, expected_by_name[missing_name])
            os.fsync(pending_fd)
            try:
                published_fd = self._engagement_fd(engagement_id)
            except JournalUnavailableError as exc:
                if not _missing_file(exc):
                    raise
                os.close(pending_fd)
                pending_fd = -1
                os.rename(
                    name,
                    str(engagement_id),
                    src_dir_fd=self._engagements_fd,
                    dst_dir_fd=self._engagements_fd,
                )
                os.fsync(self._engagements_fd)
                published_fd = self._engagement_fd(engagement_id)
            else:
                self._verify_create_files(published_fd, recovery, allow_missing=False)
                for entry in _scan_directory_bounded(pending_fd, 8, "pending create directory"):
                    os.unlink(entry, dir_fd=pending_fd)
                os.close(pending_fd)
                pending_fd = -1
                os.rmdir(name, dir_fd=self._engagements_fd)
                os.fsync(self._engagements_fd)
            try:
                self._finalize_published_create(published_fd, recovery)
            finally:
                os.close(published_fd)
        except JournalUnavailableError:
            raise
        except Exception as exc:
            raise JournalUnavailableError("conflicting pending create transaction") from exc
        finally:
            if pending_fd >= 0:
                os.close(pending_fd)

    def _recover_published_create_intent(self, engagement_id: UUID) -> None:
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            try:
                raw = _read_bounded(
                    engagement_fd,
                    ".create-intent.json",
                    MAX_CREATE_INTENT_BYTES,
                    "create intent",
                )
            except JournalUnavailableError as exc:
                if _missing_file(exc):
                    return
                raise
            recovery = self._decode_create_intent(raw, engagement_id)
            self._finalize_published_create(engagement_fd, recovery)
        finally:
            os.close(engagement_fd)

    def _engagement_fd(self, engagement_id: UUID) -> int:
        self._require_open()
        if type(engagement_id) is not UUID:
            raise ValueError("engagement_id must be a UUID")
        try:
            fd = os.open(str(engagement_id), _directory_flags(), dir_fd=self._engagements_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ValueError("unsafe engagement directory") from exc
            raise JournalUnavailableError("engagement does not exist") from exc
        try:
            _validate_directory(fd, label="engagement directory", expected_mode=0o700)
        except Exception:
            os.close(fd)
            raise
        return fd

    def create(
        self,
        manifest: EngagementManifest,
        initial_drafts: Sequence[JournalEventDraft],
    ):
        return self._retry_registry_tail_recovery(
            lambda: self._create_once(manifest, initial_drafts)
        )

    def _create_once(
        self,
        manifest: EngagementManifest,
        initial_drafts: Sequence[JournalEventDraft],
    ):
        self._require_open()
        manifest = EngagementManifest.model_validate(manifest.model_dump(mode="python"))
        if not isinstance(initial_drafts, tuple) or len(initial_drafts) != 2:
            raise ValueError("initial journal requires an immutable pair of drafts")
        drafts = tuple(
            JournalEventDraft.model_validate(item.model_dump(mode="python"))
            for item in initial_drafts
        )
        if drafts[0].type != "engagement_opened" or drafts[1].type != "lane_bound":
            raise ValueError("initial journal must be engagement_opened then lane_bound")
        if (
            not isinstance(drafts[1].payload, LaneBoundPayload)
            or drafts[1].lane != drafts[1].payload.lane
        ):
            raise ValueError("initial lane binding must be exact")
        manifest_bytes = _model_bytes(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ValueError("manifest exceeds its byte bound")

        with _locked_file(self._engagements_fd, ".registry.lock"):
            entries = self._bounded_engagement_entries()
            published = [name for name in entries if _is_uuid_name(name)]
            pending_name = f".pending-create-{manifest.engagement_id}"
            if str(manifest.engagement_id) in published:
                snapshot = self._load_snapshot_registry_locked(manifest.engagement_id)
                if snapshot.manifest == manifest and self._drafts_match(
                    snapshot.events[:2], drafts
                ):
                    return snapshot
                raise ValueError("engagement UUID already exists with different content")
            pending_reservation = 0 if pending_name in entries else 1
            if len(entries) + pending_reservation > MAX_ENGAGEMENT_DIRECTORY_ENTRIES:
                raise ValueError("engagement directory entry bound exceeded")
            if len(published) + 1 > MAX_ENGAGEMENTS:
                raise ValueError("engagement count exceeds its bound")
            self._assert_lane_available(drafts[1].lane, exclude=None)
            events = self._materialize(manifest.engagement_id, (), drafts)
            state = reduce_engagement(manifest, events)
            journal_bytes = b"".join(_event_line(item) + b"\n" for item in events)
            self._validate_journal_limits(events, journal_bytes)
            head = _head(manifest.engagement_id, events, journal_bytes)
            head_bytes = _model_bytes(head)
            projection = self._projection_bytes(head.revision, state)
            intent = _canonical_json(
                {
                    "engagement_id": str(manifest.engagement_id),
                    "manifest": base64.b64encode(manifest_bytes).decode(),
                    "journal": base64.b64encode(journal_bytes).decode(),
                    "head": base64.b64encode(head_bytes).decode(),
                    "manifest_sha256": sha256(manifest_bytes).hexdigest(),
                    "journal_sha256": sha256(journal_bytes).hexdigest(),
                    "head_sha256": sha256(head_bytes).hexdigest(),
                }
            )
            if len(intent) > MAX_CREATE_INTENT_BYTES:
                raise ValueError("create intent exceeds its byte bound")
            try:
                os.mkdir(pending_name, 0o700, dir_fd=self._engagements_fd)
            except FileExistsError:
                pending_fd = os.open(pending_name, _directory_flags(), dir_fd=self._engagements_fd)
                try:
                    _validate_directory(
                        pending_fd,
                        label="pending create directory",
                        expected_mode=0o700,
                    )
                    entries = _scan_directory_bounded(pending_fd, 8, "pending create directory")
                    if any(
                        entry
                        not in {
                            ".create-intent.json",
                            "engagement.json",
                            "events.jsonl",
                            "journal-head.json",
                        }
                        for entry in entries
                    ):
                        raise JournalUnavailableError("conflicting pending create transaction")
                    try:
                        existing_intent = _read_bounded(
                            pending_fd,
                            ".create-intent.json",
                            MAX_CREATE_INTENT_BYTES,
                            "create intent",
                        )
                    except JournalUnavailableError as exc:
                        if _missing_file(exc) and not entries:
                            os.close(pending_fd)
                            pending_fd = -1
                            os.rmdir(pending_name, dir_fd=self._engagements_fd)
                            os.fsync(self._engagements_fd)
                            os.mkdir(pending_name, 0o700, dir_fd=self._engagements_fd)
                            pending_fd = os.open(
                                pending_name,
                                _directory_flags(),
                                dir_fd=self._engagements_fd,
                            )
                            _validate_directory(
                                pending_fd,
                                label="pending create directory",
                                expected_mode=0o700,
                            )
                            existing_intent = None
                        else:
                            raise JournalUnavailableError(
                                "conflicting pending create transaction"
                            ) from exc
                    if existing_intent is not None:
                        try:
                            stored = json.loads(existing_intent)
                            stored_manifest_bytes = base64.b64decode(
                                stored["manifest"], validate=True
                            )
                            stored_journal_bytes = base64.b64decode(
                                stored["journal"], validate=True
                            )
                            stored_head_bytes = base64.b64decode(stored["head"], validate=True)
                            if (
                                stored["engagement_id"] != str(manifest.engagement_id)
                                or sha256(stored_manifest_bytes).hexdigest()
                                != stored["manifest_sha256"]
                                or sha256(stored_journal_bytes).hexdigest()
                                != stored["journal_sha256"]
                                or sha256(stored_head_bytes).hexdigest() != stored["head_sha256"]
                            ):
                                raise ValueError("intent digest mismatch")
                            stored_manifest = EngagementManifest.model_validate_json(
                                stored_manifest_bytes
                            )
                            stored_events = tuple(
                                JournalEvent.model_validate_json(line)
                                for line in _iter_journal_lines(stored_journal_bytes)
                            )
                            stored_head = JournalHead.model_validate_json(stored_head_bytes)
                            if (
                                stored_manifest != manifest
                                or not self._drafts_match(stored_events, drafts)
                                or stored_head
                                != _head(
                                    manifest.engagement_id,
                                    stored_events,
                                    stored_journal_bytes,
                                )
                            ):
                                raise ValueError("intent content mismatch")
                            stored_state = reduce_engagement(stored_manifest, stored_events)
                        except Exception as exc:
                            raise JournalUnavailableError(
                                "conflicting pending create transaction"
                            ) from exc
                        manifest_bytes = stored_manifest_bytes
                        journal_bytes = stored_journal_bytes
                        head_bytes = stored_head_bytes
                        events = stored_events
                        head = stored_head
                        state = stored_state
                        projection = self._projection_bytes(head.revision, state)
                        for name, expected in (
                            ("engagement.json", manifest_bytes),
                            ("events.jsonl", journal_bytes),
                            ("journal-head.json", head_bytes),
                        ):
                            try:
                                actual = _read_bounded(
                                    pending_fd,
                                    name,
                                    max(len(expected), 1),
                                    f"staged {name}",
                                )
                            except JournalUnavailableError as exc:
                                if not _missing_file(exc):
                                    raise
                                _atomic_write(pending_fd, name, expected)
                            else:
                                if actual != expected:
                                    raise JournalUnavailableError(
                                        "conflicting pending create transaction"
                                    )
                        os.fsync(pending_fd)
                        os.close(pending_fd)
                        pending_fd = -1
                        os.rename(
                            pending_name,
                            str(manifest.engagement_id),
                            src_dir_fd=self._engagements_fd,
                            dst_dir_fd=self._engagements_fd,
                        )
                        os.fsync(self._engagements_fd)
                        engagement_fd = self._engagement_fd(manifest.engagement_id)
                        try:
                            _atomic_write(engagement_fd, "engagement-state.json", projection)
                            os.unlink(".create-intent.json", dir_fd=engagement_fd)
                            os.fsync(engagement_fd)
                        finally:
                            os.close(engagement_fd)
                        return self._snapshot(manifest, events, state)
                finally:
                    if pending_fd >= 0:
                        os.close(pending_fd)
            self._fault("create_after_directory")
            pending_fd = os.open(pending_name, _directory_flags(), dir_fd=self._engagements_fd)
            try:
                _validate_directory(
                    pending_fd,
                    label="pending create directory",
                    expected_mode=0o700,
                )
                _atomic_write(pending_fd, ".create-intent.json", intent)
                self._fault("create_after_intent")
                _atomic_write(pending_fd, "engagement.json", manifest_bytes)
                self._fault("create_after_manifest")
                _atomic_write(pending_fd, "events.jsonl", journal_bytes)
                self._fault("create_after_journal")
                _atomic_write(pending_fd, "journal-head.json", head_bytes)
                self._fault("create_after_head")
                os.fsync(pending_fd)
                self._fault("create_after_directory_fsync")
            finally:
                os.close(pending_fd)
            os.rename(
                pending_name,
                str(manifest.engagement_id),
                src_dir_fd=self._engagements_fd,
                dst_dir_fd=self._engagements_fd,
            )
            self._fault("create_after_rename_before_parent_fsync")
            os.fsync(self._engagements_fd)
            self._fault("create_after_parent_fsync")
            self._fault("create_after_rename")
            engagement_fd = self._engagement_fd(manifest.engagement_id)
            try:
                _atomic_write(engagement_fd, "engagement-state.json", projection)
                self._fault("create_after_projection")
                with suppress(FileNotFoundError):
                    os.unlink(".create-intent.json", dir_fd=engagement_fd)
                os.fsync(engagement_fd)
            finally:
                os.close(engagement_fd)
            self._fault("create_before_response")
            return self._snapshot(manifest, events, state)

    def append(
        self,
        engagement_id: UUID,
        draft: JournalEventDraft,
        *,
        expected_revision: JournalRevision | None = None,
    ) -> AppendResult:
        result = self.append_batch(
            engagement_id,
            (draft,),
            expected_revision=expected_revision,
        )
        return AppendResult(
            event=result.events[0],
            revision=result.revision,
            created=bool(result.created_event_ids),
        )

    def append_batch(
        self,
        engagement_id: UUID,
        drafts: Sequence[JournalEventDraft],
        *,
        expected_revision: JournalRevision | None = None,
    ) -> BatchAppendResult:
        repository_owned = {
            "report_generated",
            "engagement_closed",
            "report_commit_abandoned",
            "promotion_requested",
            "promotion_candidate_ready",
            "promotion_source_committed",
            "promotion_semantic_committed",
            "promotion_index_pending",
            "promotion_index_retry_failed",
            "case_promoted",
            "promotion_attempt_terminated",
            "promotion_attempt_cancellation_requested",
            "promotion_revocation_requested",
            "case_promotion_revoked",
            "case_promotion_superseded",
        }
        if any(draft.type in repository_owned for draft in drafts):
            raise EngagementAppendAuthorityError(
                "generic append cannot emit repository-owned report events"
            )
        return self._append_batch(
            engagement_id,
            drafts,
            expected_revision=expected_revision,
            defer_tail_recovery=False,
        )

    def _issue_report_commit_capability(self) -> _ReportCommitCapability:
        return _ReportCommitCapability(self, self._report_capability_token)

    def _issue_promotion_journal_writer(self) -> _PromotionJournalWriter:
        return _PromotionJournalWriter(self, self._promotion_capability_token)

    def _require_active_promotion_claim(
        self,
        state: Any,
        *,
        attempt_id: UUID,
        promotion_revision: int,
        claim_event_id: UUID | None = None,
    ) -> Any:
        active = state.promotion.active_attempt
        if (
            active is None
            or active.attempt_id != attempt_id
            or active.promotion_revision != promotion_revision
            or (claim_event_id is not None and active.claim_event_id != claim_event_id)
        ):
            raise ValueError("promotion transition does not match the active claim")
        if active.claim_expires_at is None or self._clock() >= active.claim_expires_at:
            raise ValueError("promotion claim has expired")
        return active

    @staticmethod
    def _require_no_active_promotion(state: Any) -> None:
        if state.promotion.active_attempt is not None:
            raise PromotionSagaInProgressError()

    def _commit_promotion_candidate(
        self,
        engagement_id: UUID,
        *,
        attempt_id: UUID,
        promotion_revision: int,
        candidate_bytes: bytes,
        candidate_sha256: str,
        repair_count: int,
        expected_revision: JournalRevision,
    ) -> _PromotionSourceWriteResult:
        """Bind one canonical candidate artifact and journal event under the journal lock."""

        if (
            type(promotion_revision) is not int
            or promotion_revision < 1
            or type(repair_count) is not int
            or repair_count not in {0, 1}
        ):
            raise ValueError("invalid promotion candidate identity")
        if (
            not isinstance(candidate_bytes, bytes)
            or not candidate_bytes
            or len(candidate_bytes) > MAX_PROMOTION_CANDIDATE_FILE_BYTES
            or sha256(candidate_bytes).hexdigest() != candidate_sha256
        ):
            raise ValueError("invalid promotion candidate artifact")
        name = f"{attempt_id}.json"
        relative_path = f"engagements/{engagement_id}/promotion/candidates/{name}"
        intent = _canonical_json(
            {
                "attempt_id": str(attempt_id),
                "candidate_sha256": candidate_sha256,
                "expected_revision": expected_revision.model_dump(mode="json"),
                "promotion_revision": promotion_revision,
                "repair_count": repair_count,
            }
        )
        if len(intent) > MAX_PROMOTION_CANDIDATE_INTENT_BYTES:
            raise ValueError("promotion candidate intent exceeds its byte bound")

        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, existing, head, journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                state = reduce_engagement(manifest, existing)
                active = self._require_active_promotion_claim(
                    state,
                    attempt_id=attempt_id,
                    promotion_revision=promotion_revision,
                )
                matching = tuple(
                    item
                    for item in existing
                    if isinstance(item.payload, PromotionCandidateReadyPayload)
                    and item.payload.attempt_id == attempt_id
                )
                if len(matching) > 1:
                    raise JournalUnavailableError("duplicate promotion candidate events")
                with suppress(FileExistsError):
                    os.mkdir("promotion", 0o700, dir_fd=engagement_fd)
                promotion_fd = os.open("promotion", _directory_flags(), dir_fd=engagement_fd)
                try:
                    _validate_directory(
                        promotion_fd, label="promotion directory", expected_mode=0o700
                    )
                    with suppress(FileExistsError):
                        os.mkdir("candidates", 0o700, dir_fd=promotion_fd)
                    candidates_fd = os.open("candidates", _directory_flags(), dir_fd=promotion_fd)
                    try:
                        _validate_directory(
                            candidates_fd,
                            label="promotion candidates directory",
                            expected_mode=0o700,
                        )
                        if matching:
                            payload = matching[0].payload
                            assert isinstance(payload, PromotionCandidateReadyPayload)
                            if (
                                payload.promotion_revision != promotion_revision
                                or payload.candidate_relative_path != relative_path
                                or payload.candidate_sha256 != candidate_sha256
                                or payload.repair_count != repair_count
                                or _read_bounded(
                                    candidates_fd,
                                    name,
                                    MAX_PROMOTION_CANDIDATE_FILE_BYTES,
                                    "promotion candidate",
                                )
                                != candidate_bytes
                            ):
                                raise JournalUnavailableError("conflicting promotion candidate")
                            with suppress(FileNotFoundError):
                                os.unlink(".candidate-transaction.json", dir_fd=candidates_fd)
                                os.fsync(candidates_fd)
                            return _PromotionSourceWriteResult(
                                event=matching[0], revision=head.revision, created=False
                            )
                        if head.revision != expected_revision:
                            raise RevisionConflictError("expected revision is stale")
                        if active.stage != "requested":
                            raise ValueError("promotion candidate does not match the active claim")
                        try:
                            retained = _read_bounded(
                                candidates_fd,
                                ".candidate-transaction.json",
                                MAX_PROMOTION_CANDIDATE_INTENT_BYTES,
                                "promotion candidate transaction",
                            )
                        except JournalUnavailableError as exc:
                            if not _missing_file(exc):
                                raise
                            _atomic_write(candidates_fd, ".candidate-transaction.json", intent)
                        else:
                            if retained != intent:
                                raise JournalUnavailableError(
                                    "conflicting promotion candidate transaction"
                                )
                        self._fault("promotion_candidate_after_intent")
                        try:
                            current = _read_bounded(
                                candidates_fd,
                                name,
                                MAX_PROMOTION_CANDIDATE_FILE_BYTES,
                                "promotion candidate",
                            )
                        except JournalUnavailableError as exc:
                            if not _missing_file(exc):
                                raise
                            _atomic_write(candidates_fd, name, candidate_bytes)
                        else:
                            if current != candidate_bytes:
                                raise JournalUnavailableError(
                                    "immutable promotion candidate conflicts"
                                )
                        self._fault("promotion_candidate_after_artifact")
                        draft = JournalEventDraft(
                            actor="system",
                            type=EventType.PROMOTION_CANDIDATE_READY,
                            payload=PromotionCandidateReadyPayload(
                                attempt_id=attempt_id,
                                promotion_revision=promotion_revision,
                                candidate_relative_path=relative_path,
                                candidate_sha256=candidate_sha256,
                                repair_count=repair_count,
                            ),
                            system_correlation=SystemCorrelation(
                                source="promotion",
                                operation_id=uuid5(
                                    NAMESPACE_URL,
                                    f"sedna:promotion-candidate:{engagement_id}:{attempt_id}",
                                ),
                            ),
                        )
                        self._fault("promotion_candidate_before_event_append")
                        appended = self._append_locked(
                            engagement_fd,
                            manifest,
                            existing,
                            head,
                            journal_bytes,
                            (draft,),
                        )
                        self._fault("promotion_candidate_after_event_append")
                        os.unlink(".candidate-transaction.json", dir_fd=candidates_fd)
                        os.fsync(candidates_fd)
                        return _PromotionSourceWriteResult(
                            event=appended.events[0],
                            revision=appended.revision,
                            created=True,
                        )
                    finally:
                        os.close(candidates_fd)
                finally:
                    os.close(promotion_fd)
        finally:
            os.close(engagement_fd)

    def _load_promotion_candidate(
        self,
        engagement_id: UUID,
        *,
        attempt_id: UUID,
        claim_event_id: UUID,
    ) -> bytes:
        """Descriptor-confined recovery of the candidate bound to the active claim."""

        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, existing, _head, _journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                state = reduce_engagement(manifest, existing)
                active = state.promotion.active_attempt
                if (
                    active is None
                    or active.attempt_id != attempt_id
                    or active.claim_event_id != claim_event_id
                    or active.stage == "requested"
                    or active.candidate_relative_path is None
                    or active.candidate_sha256 is None
                ):
                    raise ValueError("promotion candidate is not bound to the active claim")
                expected_path = (
                    f"engagements/{engagement_id}/promotion/candidates/{attempt_id}.json"
                )
                if active.candidate_relative_path != expected_path:
                    raise JournalUnavailableError("promotion candidate path is not canonical")
                promotion_fd = os.open("promotion", _directory_flags(), dir_fd=engagement_fd)
                try:
                    candidates_fd = os.open("candidates", _directory_flags(), dir_fd=promotion_fd)
                    try:
                        candidate = _read_bounded(
                            candidates_fd,
                            f"{attempt_id}.json",
                            MAX_PROMOTION_CANDIDATE_FILE_BYTES,
                            "promotion candidate",
                        )
                    finally:
                        os.close(candidates_fd)
                finally:
                    os.close(promotion_fd)
                if sha256(candidate).hexdigest() != active.candidate_sha256:
                    raise JournalUnavailableError("promotion candidate digest does not match")
                return candidate
        finally:
            os.close(engagement_fd)

    def _acquire_promotion_claim_holder(
        self,
        engagement_fd: int,
        engagement_id: UUID,
        attempt_id: UUID,
        holder_token: object,
    ) -> bool:
        retained = self._promotion_claim_holders.get(engagement_id)
        if retained is not None:
            retained_attempt, retained_token, _ = retained
            return retained_attempt == attempt_id and retained_token is holder_token
        lock_fd = os.open(
            ".promotion-claim.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=engagement_fd,
        )
        try:
            _validate_regular(lock_fd, label="promotion claim lock", expected_mode=0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            return False
        except Exception:
            os.close(lock_fd)
            raise
        self._promotion_claim_holders[engagement_id] = (attempt_id, holder_token, lock_fd)
        return True

    def _release_promotion_claim_holder(
        self,
        engagement_id: UUID,
        attempt_id: UUID,
        holder_token: object,
    ) -> None:
        retained = self._promotion_claim_holders.get(engagement_id)
        if retained is None or retained[0] != attempt_id or retained[1] is not holder_token:
            return
        _, _, lock_fd = self._promotion_claim_holders.pop(engagement_id)
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

    def _authenticate_promotion_claim_holder(
        self,
        engagement_id: UUID,
        *,
        attempt_id: UUID,
        claim_event_id: UUID,
        expected_stages: set[str],
        holder_token: object,
    ) -> tuple[Any, JournalRevision]:
        retained = self._promotion_claim_holders.get(engagement_id)
        if retained is None or retained[0] != attempt_id or retained[1] is not holder_token:
            raise ValueError("promotion claim holder no longer owns the persisted lease")
        snapshot = self.load_snapshot(engagement_id)
        active = snapshot.state.promotion.active_attempt
        if (
            active is None
            or active.attempt_id != attempt_id
            or active.claim_event_id != claim_event_id
            or active.stage not in expected_stages
        ):
            raise ValueError("promotion publication fence no longer matches the owned attempt")
        if active.claim_expires_at is None or self._clock() >= active.claim_expires_at:
            raise ValueError("promotion claim has expired")
        return active, snapshot.revision

    def _claim_promotion(
        self,
        engagement_id: UUID,
        *,
        holder_token: object,
        request: Mapping[str, Any],
        expected_revision: JournalRevision,
    ) -> _PromotionClaimWriteResult:
        """Atomically coalesce or create one repository-authored promotion claim."""

        required = {
            "verified_revision",
            "verification_event_id",
            "compiler_version",
            "extractor_prompt_version",
            "critic_prompt_version",
            "repair_prompt_version",
            "renderer_version",
            "semantic_compiler_version",
            "semantic_prompt_versions",
        }
        if set(request) != required:
            raise ValueError("promotion claim request has an invalid shape")
        canonical_request = _canonical_json(dict(request))
        verified_revision = JournalRevision.model_validate(request["verified_revision"])
        verification_event_id = UUID(str(request["verification_event_id"]))

        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, existing, head, journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                state = reduce_engagement(manifest, existing)
                active = state.promotion.active_attempt
                if active is not None:
                    event = next(
                        item
                        for item in existing
                        if isinstance(item.payload, PromotionRequestedPayload)
                        and item.payload.attempt_id == active.attempt_id
                    )
                    payload = event.payload
                    bound_request = {
                        key: value
                        for key, value in payload.model_dump(mode="json", warnings="error").items()
                        if key in required
                    }
                    # A matching retry is an idempotent observation, never a lease transfer.
                    if _canonical_json(bound_request) == canonical_request:
                        if (
                            active.claim_expires_at is None
                            or self._clock() >= active.claim_expires_at
                        ):
                            raise ValueError("promotion claim has expired")
                        disposition = "existing"
                        if self._acquire_promotion_claim_holder(
                            engagement_fd,
                            engagement_id,
                            active.attempt_id,
                            holder_token,
                        ):
                            self._owned_promotion_attempt_ids.add(active.attempt_id)
                            disposition = "resumed"
                        return _PromotionClaimWriteResult(
                            event=event,
                            attempt=active,
                            revision=head.revision,
                            disposition=disposition,
                        )
                    return _PromotionClaimWriteResult(
                        event=event,
                        attempt=active,
                        revision=head.revision,
                        disposition="existing",
                    )

                if head.revision != expected_revision:
                    raise RevisionConflictError("expected revision is stale")
                if state.status.value != "closed_verified":
                    raise ValueError("promotion claim requires a closed verified engagement")
                verified_event = next(
                    (item for item in existing if item.event_id == verification_event_id), None
                )
                if (
                    verified_event is None
                    or verified_event.type != "engagement_verified"
                    or JournalRevision(
                        sequence=verified_event.sequence,
                        event_hash=verified_event.event_hash,
                    )
                    != verified_revision
                ):
                    raise ValueError("promotion claim does not match the verified revision")

                requested = tuple(
                    item for item in existing if isinstance(item.payload, PromotionRequestedPayload)
                )
                claims = {
                    item.payload.attempt_id: item.payload
                    for item in requested
                    if isinstance(item.payload, PromotionRequestedPayload)
                }
                terminal_count = sum(
                    1
                    for item in existing
                    if isinstance(item.payload, PromotionAttemptTerminatedPayload)
                    and item.payload.attempt_id in claims
                    and claims[item.payload.attempt_id].verification_event_id
                    == verification_event_id
                )
                if terminal_count >= 3:
                    return _PromotionClaimWriteResult(
                        event=None,
                        attempt=None,
                        revision=head.revision,
                        disposition="retry_exhausted",
                    )

                attempt_id = self._uuid_factory()
                attempt_ordinal = terminal_count + 1
                idempotency_identity = {
                    "engagement_id": str(engagement_id),
                    "attempt_ordinal": attempt_ordinal,
                    "verified_revision": verified_revision.model_dump(
                        mode="json", warnings="error"
                    ),
                    "verification_event_id": str(verification_event_id),
                    "compiler_version": request["compiler_version"],
                    "extractor_prompt_version": request["extractor_prompt_version"],
                    "critic_prompt_version": request["critic_prompt_version"],
                    "repair_prompt_version": request["repair_prompt_version"],
                    "renderer_version": request["renderer_version"],
                    "semantic_compiler_version": request["semantic_compiler_version"],
                    "semantic_prompt_versions": request["semantic_prompt_versions"],
                }
                payload = PromotionRequestedPayload(
                    attempt_id=attempt_id,
                    attempt_ordinal=attempt_ordinal,
                    promotion_revision=len(requested) + 1,
                    idempotency_key=sha256(_canonical_json(idempotency_identity)).hexdigest(),
                    verified_revision=verified_revision,
                    verification_event_id=verification_event_id,
                    compiler_version=request["compiler_version"],
                    extractor_prompt_version=request["extractor_prompt_version"],
                    critic_prompt_version=request["critic_prompt_version"],
                    repair_prompt_version=request["repair_prompt_version"],
                    renderer_version=request["renderer_version"],
                    semantic_compiler_version=request["semantic_compiler_version"],
                    semantic_prompt_versions=tuple(request["semantic_prompt_versions"]),
                    claim_expires_at=self._clock() + timedelta(minutes=5),
                )
                draft = JournalEventDraft(
                    actor="system",
                    type=EventType.PROMOTION_REQUESTED,
                    payload=payload,
                    system_correlation=SystemCorrelation(
                        source="promotion",
                        operation_id=uuid5(
                            NAMESPACE_URL,
                            f"sedna:promotion-claim:{engagement_id}:{attempt_id}",
                        ),
                    ),
                )
                appended = self._append_locked(
                    engagement_fd,
                    manifest,
                    existing,
                    head,
                    journal_bytes,
                    (draft,),
                )
                next_state = reduce_engagement(manifest, (*existing, *appended.events))
                if not self._acquire_promotion_claim_holder(
                    engagement_fd,
                    engagement_id,
                    attempt_id,
                    holder_token,
                ):
                    raise JournalUnavailableError("new promotion claim holder lock is unavailable")
                self._owned_promotion_attempt_ids.add(attempt_id)
                return _PromotionClaimWriteResult(
                    event=appended.events[0],
                    attempt=next_state.promotion.active_attempt,
                    revision=appended.revision,
                    disposition="created",
                )
        finally:
            os.close(engagement_fd)

    def _commit_promotion_semantic(
        self, engagement_id: UUID, *, expected_revision: JournalRevision, **values: Any
    ) -> BatchAppendResult:
        return self._append_promotion_event(
            engagement_id,
            PromotionSemanticCommittedPayload(**values),
            expected_revision=expected_revision,
        )

    def _commit_promotion_index_pending(
        self, engagement_id: UUID, *, expected_revision: JournalRevision, **values: Any
    ) -> BatchAppendResult:
        return self._append_promotion_event(
            engagement_id,
            PromotionIndexPendingPayload(**values),
            expected_revision=expected_revision,
        )

    def _commit_promotion_index_retry(
        self, engagement_id: UUID, *, expected_revision: JournalRevision, **values: Any
    ) -> BatchAppendResult:
        return self._append_promotion_event(
            engagement_id,
            PromotionIndexRetryFailedPayload(**values),
            expected_revision=expected_revision,
        )

    def _commit_promoted_case(
        self, engagement_id: UUID, *, expected_revision: JournalRevision, **values: Any
    ) -> BatchAppendResult:
        return self._append_promotion_event(
            engagement_id,
            CasePromotedPayload(**values),
            expected_revision=expected_revision,
        )

    def _commit_superseded_and_promoted(
        self,
        engagement_id: UUID,
        *,
        replacement: object,
        expected_revision: JournalRevision,
    ) -> _PromotionMutationWriteResult:
        snapshot = self.load_snapshot(engagement_id)
        active = snapshot.state.promotion.active_attempt
        prior = snapshot.state.promotion.latest_successful_publication
        receipt = cast(Any, replacement)
        if (
            snapshot.revision != expected_revision
            or active is None
            or active.stage not in {"index_pending", "retry_failed"}
            or active.source_id is None
            or prior is None
            or prior.attempt_id == active.attempt_id
            or prior.source_id != active.source_id
            or getattr(receipt, "attempt_id", None) != active.attempt_id
            or getattr(receipt, "promotion_revision", None) != active.promotion_revision
            or getattr(receipt, "source_id", None) != active.source_id
            or not getattr(receipt, "case_ids", ())
        ):
            raise ValueError("promotion supersession fence does not match")
        correlation = SystemCorrelation(
            source="promotion",
            operation_id=uuid5(
                NAMESPACE_URL,
                f"sedna:promotion:{engagement_id}:{active.attempt_id}:supersession",
            ),
        )
        result = self._append_batch(
            engagement_id,
            (
                JournalEventDraft(
                    actor="system",
                    type=EventType.CASE_PROMOTION_SUPERSEDED,
                    payload=CasePromotionSupersededPayload(
                        prior_attempt_id=prior.attempt_id,
                        replacement_attempt_id=active.attempt_id,
                        source_id=prior.source_id,
                        removed_case_ids=prior.case_ids,
                    ),
                    system_correlation=correlation,
                ),
                JournalEventDraft(
                    actor="system",
                    type=EventType.CASE_PROMOTED,
                    payload=CasePromotedPayload(
                        attempt_id=active.attempt_id,
                        source_id=active.source_id,
                        promotion_revision=active.promotion_revision,
                        case_ids=receipt.case_ids,
                    ),
                    system_correlation=correlation,
                ),
            ),
            expected_revision=expected_revision,
            defer_tail_recovery=False,
            allow_active_promotion=True,
        )
        return _PromotionMutationWriteResult(
            event_id=result.events[-1].event_id,
            revision=result.revision,
        )

    def _resolve_exact_promotion_request_replay(
        self,
        snapshot: Any,
        *,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        attempt_id: UUID,
        operation: Literal["reject", "reopen"],
        reopen_reason: str,
        proof_rejection: object | None,
        expected_revision: JournalRevision,
        request_type: EventType,
    ) -> _PromotionMutationWriteResult | None:
        request = next(
            (
                event
                for event in reversed(snapshot.events)
                if event.type == request_type
                and getattr(event.payload, "attempt_id", None) == attempt_id
            ),
            None,
        )
        if request is None:
            return None
        preceding = snapshot.events[request.sequence - 2] if request.sequence > 1 else None
        reserved_in_batch = (
            preceding is not None
            and preceding.type == EventType.LANE_BOUND
            and preceding.payload.lane == lane
            and preceding.idempotency_key == f"lane-bind:{lane.stable_key}:{engagement_id}"
        )
        base_sequence = request.sequence - (2 if reserved_in_batch else 1)
        base_revision = (
            JournalRevision(sequence=0, event_hash="0" * 64)
            if base_sequence == 0
            else JournalRevision(
                sequence=base_sequence,
                event_hash=snapshot.events[base_sequence - 1].event_hash,
            )
        )
        if base_revision != expected_revision:
            return None
        if operation == "reopen":
            if proof_rejection is not None:
                return None
            expected_intent = RevocationLifecycleIntent.build(
                operation="reopen",
                lane=lane,
                reopen_reason=reopen_reason,
                proof_revalidation="invalidate_all",
            )
        else:
            self._authenticate_settled_proof_rejection(
                snapshot,
                engagement_id=engagement_id,
                receipt=proof_rejection,
            )
            receipt = cast(Any, proof_rejection)
            expected_intent = RevocationLifecycleIntent.build(
                operation="reject",
                lane=lane,
                reopen_reason=reopen_reason,
                proof_revalidation="retain_rejections",
                receipt_authoritative_revision=receipt.authoritative_revision,
                situation_sha256=receipt.situation_sha256,
                proof_requirement_id=receipt.proof_requirement_id,
                assessment_generation=receipt.assessment_generation,
                flag_event_id=receipt.proof_event_id,
                rejected_value_sha256=receipt.rejected_value_sha256,
            )
        if request.payload.lifecycle_intent != expected_intent:
            return None
        return _PromotionMutationWriteResult(
            event_id=request.event_id,
            revision=snapshot.revision,
        )

    def _request_promotion_revocation(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        attempt_id: UUID,
        operation: Literal["reject", "reopen"],
        reopen_reason: str,
        proof_rejection: object | None,
        expected_revision: JournalRevision,
    ) -> _PromotionMutationWriteResult:
        snapshot = self.load_snapshot(engagement_id)
        active = snapshot.state.promotion.active_attempt
        if (
            active is not None
            and active.attempt_id == attempt_id
            and active.stage == "revocation_requested"
        ):
            replay = self._resolve_exact_promotion_request_replay(
                snapshot,
                engagement_id=engagement_id,
                lane=lane,
                attempt_id=attempt_id,
                operation=operation,
                reopen_reason=reopen_reason,
                proof_rejection=proof_rejection,
                expected_revision=expected_revision,
                request_type=EventType.PROMOTION_REVOCATION_REQUESTED,
            )
            if replay is not None:
                return replay
            raise ValueError("promotion revocation replay intent does not match")
        lineage = snapshot.state.promotion.latest_successful_publication
        published = next(
            (
                attempt
                for attempt in reversed(snapshot.state.promotion.recent_terminal_attempts)
                if lineage is not None and attempt.attempt_id == lineage.attempt_id
            ),
            None,
        )
        if (
            snapshot.revision != expected_revision
            or snapshot.state.status.value != "closed_verified"
            or lineage is None
            or published is None
            or published.attempt_id != attempt_id
            or published.stage != "promoted"
            or published.disposition != "promoted"
        ):
            raise ValueError("promotion revocation does not match an active publication")
        if operation == "reopen":
            if proof_rejection is not None:
                raise ValueError("reopen revocation forbids a proof rejection receipt")
            intent = RevocationLifecycleIntent.build(
                operation="reopen",
                lane=lane,
                reopen_reason=reopen_reason,
                proof_revalidation="invalidate_all",
            )
        else:
            receipt = cast(Any, proof_rejection)
            if (
                proof_rejection is None
                or getattr(receipt, "_issuer_token", None) is not self._lifecycle_capability_token
                or getattr(receipt, "engagement_id", None) != engagement_id
                or getattr(receipt, "authoritative_revision", None) != expected_revision
            ):
                raise ValueError("reject revocation requires an authentic current receipt")
            intent = RevocationLifecycleIntent.build(
                operation="reject",
                lane=lane,
                reopen_reason=reopen_reason,
                proof_revalidation="retain_rejections",
                receipt_authoritative_revision=receipt.authoritative_revision,
                situation_sha256=receipt.situation_sha256,
                proof_requirement_id=receipt.proof_requirement_id,
                assessment_generation=receipt.assessment_generation,
                flag_event_id=receipt.proof_event_id,
                rejected_value_sha256=receipt.rejected_value_sha256,
            )
        result = self._append_promotion_request_with_lane(
            engagement_id,
            lane,
            PromotionRevocationRequestedPayload(
                attempt_id=attempt_id,
                source_id=lineage.source_id,
                promoted_case_ids=lineage.case_ids,
                reason="flag_rejected" if operation == "reject" else "reopened",
                lifecycle_intent=intent,
            ),
            expected_revision=expected_revision,
            claim_event_id=published.claim_event_id,
            proof_rejection=proof_rejection,
        )
        return _PromotionMutationWriteResult(
            event_id=result.events[-1].event_id,
            revision=result.revision,
        )

    def _request_promotion_cancellation(
        self,
        engagement_id: UUID,
        *,
        lane: ExecutionLaneKey,
        attempt_id: UUID,
        operation: Literal["reject", "reopen"],
        reopen_reason: str,
        proof_rejection: object | None,
        expected_revision: JournalRevision,
    ) -> _PromotionMutationWriteResult:
        snapshot = self.load_snapshot(engagement_id)
        active = snapshot.state.promotion.active_attempt
        if (
            active is not None
            and active.attempt_id == attempt_id
            and active.stage == "cancellation_requested"
        ):
            replay = self._resolve_exact_promotion_request_replay(
                snapshot,
                engagement_id=engagement_id,
                lane=lane,
                attempt_id=attempt_id,
                operation=operation,
                reopen_reason=reopen_reason,
                proof_rejection=proof_rejection,
                expected_revision=expected_revision,
                request_type=EventType.PROMOTION_ATTEMPT_CANCELLATION_REQUESTED,
            )
            if replay is not None:
                return replay
            raise ValueError("promotion cancellation replay intent does not match")
        if (
            snapshot.revision != expected_revision
            or snapshot.state.status.value != "closed_verified"
            or active is None
            or active.attempt_id != attempt_id
            or active.stage
            not in {
                "requested",
                "candidate_ready",
                "source_committed",
                "semantic_committed",
                "index_pending",
            }
        ):
            raise ValueError("promotion cancellation does not match an active recoverable claim")
        if operation == "reopen":
            if proof_rejection is not None:
                raise ValueError("reopen cancellation forbids a proof rejection receipt")
            intent = RevocationLifecycleIntent.build(
                operation="reopen",
                lane=lane,
                reopen_reason=reopen_reason,
                proof_revalidation="invalidate_all",
            )
        else:
            required = (
                "authoritative_revision",
                "situation_sha256",
                "proof_requirement_id",
                "assessment_generation",
                "proof_event_id",
                "rejected_value_sha256",
            )
            if proof_rejection is None or any(
                not hasattr(proof_rejection, field) for field in required
            ):
                raise ValueError("reject cancellation requires a settled proof receipt")
            receipt = cast(Any, proof_rejection)
            if (
                getattr(receipt, "_issuer_token", None) is not self._lifecycle_capability_token
                or getattr(receipt, "engagement_id", None) != engagement_id
                or receipt.authoritative_revision != expected_revision
            ):
                raise ValueError("reject cancellation requires an authentic current receipt")
            intent = RevocationLifecycleIntent.build(
                operation="reject",
                lane=lane,
                reopen_reason=reopen_reason,
                proof_revalidation="retain_rejections",
                receipt_authoritative_revision=receipt.authoritative_revision,
                situation_sha256=receipt.situation_sha256,
                proof_requirement_id=receipt.proof_requirement_id,
                assessment_generation=receipt.assessment_generation,
                flag_event_id=receipt.proof_event_id,
                rejected_value_sha256=receipt.rejected_value_sha256,
            )
        result = self._append_promotion_request_with_lane(
            engagement_id,
            lane,
            PromotionAttemptCancellationRequestedPayload(
                attempt_id=attempt_id,
                promotion_revision=active.promotion_revision,
                verification_event_id=active.verification_event_id,
                stage=cast(
                    Literal[
                        "requested",
                        "candidate_ready",
                        "source_committed",
                        "semantic_committed",
                        "index_pending",
                    ],
                    active.stage,
                ),
                reason="flag_rejected" if operation == "reject" else "reopened",
                lifecycle_intent=intent,
            ),
            expected_revision=expected_revision,
            claim_event_id=active.claim_event_id,
            proof_rejection=proof_rejection,
        )
        return _PromotionMutationWriteResult(
            event_id=result.events[-1].event_id,
            revision=result.revision,
        )

    def _commit_empty_revocation(
        self,
        engagement_id: UUID,
        *,
        operation: Literal["reject", "reopen"],
        lane: ExecutionLaneKey,
        reason: str,
        proof_rejection: object | None,
        absence_proof: object,
        expected_revision: JournalRevision,
    ) -> BatchAppendResult:
        snapshot = self.load_snapshot(engagement_id)
        verified = next(
            (event for event in reversed(snapshot.events) if event.type == "engagement_verified"),
            None,
        )
        proof = cast(Any, absence_proof)
        promotion = snapshot.state.promotion
        current_terminal = (
            None
            if verified is None
            else next(
                (
                    attempt
                    for attempt in reversed(promotion.recent_terminal_attempts)
                    if attempt.verification_event_id == verified.event_id
                ),
                None,
            )
        )
        lineage = promotion.latest_successful_publication
        lineage_attempt = (
            None
            if lineage is None
            else next(
                (
                    attempt
                    for attempt in reversed(promotion.recent_terminal_attempts)
                    if attempt.attempt_id == lineage.attempt_id
                ),
                None,
            )
        )
        historical_lineage_is_inactive = lineage is None or (
            (current_terminal is None or current_terminal.attempt_id != lineage.attempt_id)
            and (lineage_attempt is None or lineage_attempt.stage in {"revoked", "superseded"})
        )
        current_terminal_is_empty = current_terminal is None or (
            current_terminal.stage == "terminated"
            and current_terminal.cleanup_canonical_revision is None
        )
        expected_attempt_id = None if current_terminal is None else current_terminal.attempt_id
        if (
            promotion.active_attempt is not None
            or not historical_lineage_is_inactive
            or not current_terminal_is_empty
            or verified is None
            or getattr(proof, "engagement_id", None) != engagement_id
            or getattr(proof, "verification_event_id", None) != verified.event_id
            or getattr(proof, "attempt_id", None) != expected_attempt_id
            or getattr(proof, "purpose", None) != "direct_empty"
            or getattr(proof, "request_event_id", None) is not None
            or getattr(proof, "canonical_state", None) != "absent"
            or getattr(proof, "canonical_revision", None) is not None
            or getattr(proof, "source_id", None) is not None
            or getattr(proof, "removed_case_ids", None) != ()
        ):
            raise ValueError("direct-empty revocation absence fence does not match")
        drafts: list[JournalEventDraft] = []
        if operation == "reject":
            receipt = cast(Any, proof_rejection)
            if (
                proof_rejection is None
                or getattr(receipt, "_issuer_token", None) is not self._lifecycle_capability_token
                or getattr(receipt, "engagement_id", None) != engagement_id
                or getattr(receipt, "authoritative_revision", None) != expected_revision
            ):
                raise ValueError("direct rejection requires an authentic current receipt")
            self._authenticate_settled_proof_rejection(
                snapshot,
                engagement_id=engagement_id,
                receipt=proof_rejection,
            )
            drafts.append(
                JournalEventDraft(
                    actor="system",
                    type=EventType.FLAG_REJECTED,
                    payload=FlagRejectedPayload(
                        flag_event_id=receipt.proof_event_id,
                        rejected_value_sha256=receipt.rejected_value_sha256,
                        reason=reason,
                    ),
                    system_correlation=SystemCorrelation(
                        source="lifecycle",
                        operation_id=receipt.proof_event_id,
                    ),
                    idempotency_key=(
                        f"direct-empty:{operation}:{proof.guard_nonce}:proof-rejection"
                    ),
                )
            )
        elif proof_rejection is not None:
            raise ValueError("direct reopen forbids a proof rejection receipt")
        drafts.append(
            JournalEventDraft(
                actor="system",
                type=EventType.ENGAGEMENT_REOPENED,
                payload=EngagementReopenedPayload(
                    reason=reason,
                    prior_status="closed_verified",
                    proof_revalidation=(
                        "retain_rejections" if operation == "reject" else "invalidate_all"
                    ),
                ),
                system_correlation=SystemCorrelation(
                    source="lifecycle",
                    operation_id=verified.event_id,
                ),
                idempotency_key=f"direct-empty:{operation}:{proof.guard_nonce}:reopen",
            )
        )
        if (
            snapshot.revision != expected_revision
            or snapshot.state.status.value != "closed_verified"
        ) and snapshot.state.status.value != "active":
            raise ValueError("direct-empty revocation absence fence does not match")
        return self.append_lifecycle_batch(
            engagement_id,
            lane,
            tuple(drafts),
            binding_reason=operation,
            expected_revision=expected_revision,
        )

    def _commit_promotion_cleanup_and_reopen(
        self,
        engagement_id: UUID,
        *,
        request_event_id: UUID,
        absence_proof: object,
        expected_revision: JournalRevision,
    ) -> BatchAppendResult:
        snapshot = self.load_snapshot(engagement_id)
        active = snapshot.state.promotion.active_attempt
        request = next(
            (event for event in snapshot.events if event.event_id == request_event_id),
            None,
        )
        request_payload = None if request is None else request.payload
        is_cancellation = isinstance(
            request_payload,
            PromotionAttemptCancellationRequestedPayload,
        )
        is_revocation = isinstance(request_payload, PromotionRevocationRequestedPayload)
        if (
            snapshot.revision != expected_revision
            or snapshot.state.status.value != "closed_verified"
            or active is None
            or (
                is_cancellation
                and (
                    active.stage != "cancellation_requested"
                    or active.cancellation_request_event_id != request_event_id
                )
            )
            or (
                is_revocation
                and (
                    active.stage != "revocation_requested"
                    or active.revocation_request_event_id != request_event_id
                )
            )
            or not (is_cancellation or is_revocation)
        ):
            raise ValueError("promotion cleanup request fence no longer matches")
        proof = cast(Any, absence_proof)
        if (
            getattr(proof, "engagement_id", None) != engagement_id
            or getattr(proof, "verification_event_id", None) != active.verification_event_id
            or getattr(proof, "attempt_id", None) != active.attempt_id
            or getattr(proof, "purpose", None) != "request_cleanup"
            or getattr(proof, "request_event_id", None) != request_event_id
            or getattr(proof, "canonical_state", None) not in {"absent", "excluded"}
        ):
            raise ValueError("promotion cleanup absence proof does not match the request")
        intent = request_payload.lifecycle_intent
        correlation = SystemCorrelation(source="lifecycle", operation_id=request_event_id)
        if is_revocation:
            if (
                proof.canonical_state != "excluded"
                or active.source_id is None
                or proof.source_id != active.source_id
                or proof.removed_case_ids != active.case_ids
                or proof.canonical_revision is None
            ):
                raise ValueError("published cleanup requires excluded canonical lineage")
            cleanup_payload = CasePromotionRevokedPayload(
                attempt_id=active.attempt_id,
                source_id=active.source_id,
                removed_case_ids=active.case_ids,
                canonical_revision=proof.canonical_revision,
            )
            cleanup_type = EventType.CASE_PROMOTION_REVOKED
        else:
            cleanup_payload = PromotionAttemptTerminatedPayload(
                attempt_id=active.attempt_id,
                promotion_revision=active.promotion_revision,
                disposition="cancelled",
                reason_code=(
                    "verification_revoked"
                    if intent.operation == "reject"
                    else "engagement_reopened"
                ),
                cleanup_source_id=(
                    proof.source_id if proof.canonical_state == "excluded" else None
                ),
                cleanup_canonical_revision=(
                    proof.canonical_revision if proof.canonical_state == "excluded" else None
                ),
            )
            cleanup_type = EventType.PROMOTION_ATTEMPT_TERMINATED
        drafts: list[JournalEventDraft] = [
            JournalEventDraft(
                actor="system",
                type=cleanup_type,
                payload=cleanup_payload,
                system_correlation=SystemCorrelation(
                    source="promotion",
                    operation_id=request_event_id,
                ),
            )
        ]
        if intent.operation == "reject":
            if intent.flag_event_id is None or intent.rejected_value_sha256 is None:
                raise ValueError("reject lifecycle intent is incomplete")
            drafts.append(
                JournalEventDraft(
                    actor="system",
                    type=EventType.FLAG_REJECTED,
                    payload=FlagRejectedPayload(
                        flag_event_id=intent.flag_event_id,
                        rejected_value_sha256=intent.rejected_value_sha256,
                        reason=intent.reopen_reason,
                    ),
                    system_correlation=correlation,
                )
            )
        drafts.append(
            JournalEventDraft(
                actor="system",
                type=EventType.ENGAGEMENT_REOPENED,
                payload=EngagementReopenedPayload(
                    reason=intent.reopen_reason,
                    prior_status="closed_verified",
                    proof_revalidation=intent.proof_revalidation,
                ),
                system_correlation=correlation,
            )
        )
        return self.append_lifecycle_batch(
            engagement_id,
            intent.lane,
            tuple(drafts),
            binding_reason=intent.operation,
            expected_revision=expected_revision,
            allow_active_promotion=True,
        )

    def _terminate_promotion(
        self,
        engagement_id: UUID,
        *,
        holder_token: object,
        attempt_id: UUID,
        promotion_revision: int,
        disposition: Any,
        reason_code: Any,
        cleanup_source_id: str | None,
        cleanup_canonical_revision: str | None,
        claim_event_id: UUID,
        expected_revision: JournalRevision,
    ) -> BatchAppendResult:
        payload = PromotionAttemptTerminatedPayload(
            attempt_id=attempt_id,
            promotion_revision=promotion_revision,
            disposition=disposition,
            reason_code=reason_code,
            cleanup_source_id=cleanup_source_id,
            cleanup_canonical_revision=cleanup_canonical_revision,
        )
        result = self._append_promotion_event(
            engagement_id,
            payload,
            expected_revision=expected_revision,
            claim_event_id=claim_event_id,
        )
        self._release_promotion_claim_holder(engagement_id, attempt_id, holder_token)
        return result

    def _commit_promotion_source(
        self,
        engagement_id: UUID,
        *,
        attempt_id: UUID,
        source_id: str,
        promotion_revision: int,
        source_bytes: bytes,
        source_sha256: str,
        provenance_bytes: bytes,
        provenance_sha256: str,
        verified_revision: JournalRevision,
        verification_event_id: UUID,
        expected_revision: JournalRevision,
    ) -> _PromotionSourceWriteResult:
        """Atomically bind immutable promotion source bytes to one journal event."""

        if type(promotion_revision) is not int or promotion_revision < 1:
            raise ValueError("promotion revision must be a positive integer")
        if not isinstance(source_bytes, bytes) or not isinstance(provenance_bytes, bytes):
            raise TypeError("promotion source artifacts must be canonical bytes")
        if (
            not source_bytes
            or len(source_bytes) > MAX_PROMOTION_SOURCE_FILE_BYTES
            or not provenance_bytes
            or len(provenance_bytes) > MAX_PROMOTION_PROVENANCE_FILE_BYTES
        ):
            raise ValueError("promotion source artifact exceeds its byte bound")
        if (
            sha256(source_bytes).hexdigest() != source_sha256
            or sha256(provenance_bytes).hexdigest() != provenance_sha256
        ):
            raise ValueError("promotion source artifact digest mismatch")
        source_name = f"promotion-v{promotion_revision}.md"
        provenance_name = f"promotion-v{promotion_revision}.provenance.json"
        prefix = f"engagements/{engagement_id}/promotion/sources"
        source_relative_path = f"{prefix}/{source_name}"
        provenance_relative_path = f"{prefix}/{provenance_name}"
        intent = _canonical_json(
            {
                "attempt_id": str(attempt_id),
                "engagement_id": str(engagement_id),
                "expected_revision": expected_revision.model_dump(mode="json"),
                "promotion_revision": promotion_revision,
                "provenance_sha256": provenance_sha256,
                "source_id": source_id,
                "source_sha256": source_sha256,
                "verification_event_id": str(verification_event_id),
                "verified_revision": verified_revision.model_dump(mode="json"),
            }
        )
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, existing, head, journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                self._require_active_promotion_claim(
                    reduce_engagement(manifest, existing),
                    attempt_id=attempt_id,
                    promotion_revision=promotion_revision,
                )
                matching = tuple(
                    event
                    for event in existing
                    if isinstance(event.payload, PromotionSourceCommittedPayload)
                    and event.payload.attempt_id == attempt_id
                )
                if len(matching) > 1:
                    raise JournalUnavailableError("duplicate promotion source commit events")
                with suppress(FileExistsError):
                    os.mkdir("promotion", 0o700, dir_fd=engagement_fd)
                promotion_fd = os.open("promotion", _directory_flags(), dir_fd=engagement_fd)
                try:
                    _validate_directory(
                        promotion_fd, label="promotion directory", expected_mode=0o700
                    )
                    with suppress(FileExistsError):
                        os.mkdir("sources", 0o700, dir_fd=promotion_fd)
                    sources_fd = os.open("sources", _directory_flags(), dir_fd=promotion_fd)
                    try:
                        _validate_directory(
                            sources_fd,
                            label="promotion sources directory",
                            expected_mode=0o700,
                        )

                        def require_artifacts() -> None:
                            for name, expected, limit in (
                                (source_name, source_bytes, MAX_PROMOTION_SOURCE_FILE_BYTES),
                                (
                                    provenance_name,
                                    provenance_bytes,
                                    MAX_PROMOTION_PROVENANCE_FILE_BYTES,
                                ),
                            ):
                                actual = _read_bounded(sources_fd, name, limit, name)
                                if actual != expected:
                                    raise JournalUnavailableError(
                                        "immutable promotion source artifact conflicts"
                                    )

                        if matching:
                            payload = matching[0].payload
                            assert isinstance(payload, PromotionSourceCommittedPayload)
                            if (
                                payload.source_id != source_id
                                or payload.promotion_revision != promotion_revision
                                or payload.source_relative_path != source_relative_path
                                or payload.source_sha256 != source_sha256
                                or payload.provenance_relative_path != provenance_relative_path
                                or payload.provenance_sha256 != provenance_sha256
                                or payload.verified_revision != verified_revision
                                or payload.verification_event_id != verification_event_id
                            ):
                                raise JournalUnavailableError("conflicting promotion source commit")
                            require_artifacts()
                            with suppress(FileNotFoundError):
                                os.unlink(".source-transaction.json", dir_fd=sources_fd)
                                os.fsync(sources_fd)
                            return _PromotionSourceWriteResult(
                                event=matching[0], revision=head.revision, created=False
                            )
                        if head.revision != expected_revision:
                            raise RevisionConflictError("expected revision is stale")
                        try:
                            retained = _read_bounded(
                                sources_fd,
                                ".source-transaction.json",
                                MAX_PROMOTION_SOURCE_INTENT_BYTES,
                                "promotion source transaction",
                            )
                        except JournalUnavailableError as exc:
                            if not _missing_file(exc):
                                raise
                            _atomic_write(sources_fd, ".source-transaction.json", intent)
                        else:
                            if retained != intent:
                                raise JournalUnavailableError(
                                    "conflicting promotion source transaction"
                                )
                        self._fault("promotion_source_after_intent")
                        for index, (name, data, limit) in enumerate(
                            (
                                (source_name, source_bytes, MAX_PROMOTION_SOURCE_FILE_BYTES),
                                (
                                    provenance_name,
                                    provenance_bytes,
                                    MAX_PROMOTION_PROVENANCE_FILE_BYTES,
                                ),
                            )
                        ):
                            try:
                                current = _read_bounded(sources_fd, name, limit, name)
                            except JournalUnavailableError as exc:
                                if not _missing_file(exc):
                                    raise
                                _atomic_write(sources_fd, name, data)
                            else:
                                if current != data:
                                    raise JournalUnavailableError(
                                        "immutable promotion source artifact conflicts"
                                    )
                            self._fault(
                                "promotion_source_after_source"
                                if index == 0
                                else "promotion_source_after_provenance"
                            )
                        os.fsync(sources_fd)
                        self._fault("promotion_source_before_event_append")
                        draft = JournalEventDraft(
                            actor="system",
                            type="promotion_source_committed",
                            payload=PromotionSourceCommittedPayload(
                                attempt_id=attempt_id,
                                source_id=source_id,
                                promotion_revision=promotion_revision,
                                source_relative_path=source_relative_path,
                                source_sha256=source_sha256,
                                provenance_relative_path=provenance_relative_path,
                                provenance_sha256=provenance_sha256,
                                verified_revision=verified_revision,
                                verification_event_id=verification_event_id,
                            ),
                            system_correlation=SystemCorrelation(
                                source="promotion",
                                operation_id=uuid5(
                                    engagement_id,
                                    f"promotion-source:{attempt_id}:{promotion_revision}",
                                ),
                            ),
                        )
                        appended = self._append_locked(
                            engagement_fd,
                            manifest,
                            existing,
                            head,
                            journal_bytes,
                            (draft,),
                        )
                        self._fault("promotion_source_after_event_append")
                        os.unlink(".source-transaction.json", dir_fd=sources_fd)
                        os.fsync(sources_fd)
                        return _PromotionSourceWriteResult(
                            event=appended.events[0],
                            revision=appended.revision,
                            created=True,
                        )
                    finally:
                        os.close(sources_fd)
                finally:
                    os.close(promotion_fd)
        finally:
            os.close(engagement_fd)

    def _authenticate_settled_proof_rejection(
        self,
        snapshot: Any,
        *,
        engagement_id: UUID,
        receipt: object | None,
    ) -> None:
        """Authenticate every settled receipt field against its authoritative replay."""

        from sedna.planning.situation import SituationReducer

        value = cast(Any, receipt)
        if (
            receipt is None
            or getattr(value, "_issuer_token", None) is not self._lifecycle_capability_token
            or getattr(value, "engagement_id", None) != engagement_id
        ):
            raise ValueError("reject promotion request requires an authentic current receipt")
        try:
            authoritative_revision = value.authoritative_revision
            if authoritative_revision.sequence > len(snapshot.events):
                raise ValueError("receipt revision is ahead of the journal")
            if authoritative_revision.sequence == 0:
                if authoritative_revision.event_hash != "0" * 64:
                    raise ValueError("receipt revision hash does not match")
                authoritative_events = ()
            else:
                authoritative_events = snapshot.events[: authoritative_revision.sequence]
                if authoritative_events[-1].event_hash != authoritative_revision.event_hash:
                    raise ValueError("receipt revision hash does not match")
            authoritative = self._snapshot(
                snapshot.manifest,
                authoritative_events,
                reduce_engagement(snapshot.manifest, authoritative_events),
            )
            if authoritative.state.status.value != "closed_verified":
                raise ValueError("receipt revision is not verified")
            situation = SituationReducer.rebuild(authoritative)
            proof = next(
                item
                for item in situation.objective_progress.requirements
                if item.proof_requirement_id == value.proof_requirement_id
            )
            reference = next(
                item
                for item in proof.value_references
                if item.proof_event_id == value.proof_event_id
            )
            proof_event = next(
                item for item in authoritative.events if item.event_id == value.proof_event_id
            )
            verification = next(
                item
                for item in reversed(authoritative.events)
                if item.type == EventType.ENGAGEMENT_VERIFIED
            )
        except (AttributeError, StopIteration, TypeError, ValueError) as exc:
            raise ValueError(
                "reject promotion request requires an authentic current receipt"
            ) from exc
        proof_payload = proof_event.payload
        if (
            situation.state_digest != value.situation_sha256
            or proof.assessment_generation != value.assessment_generation
            or reference.proof_requirement_id != value.proof_requirement_id
            or reference.assessment_generation != value.assessment_generation
            or reference.assessment != "supported"
            or reference.value_sha256 != value.rejected_value_sha256
            or proof_event.type != EventType.OBJECTIVE_PROOF_OBSERVED
            or getattr(proof_payload, "proof_requirement_id", None) != value.proof_requirement_id
            or getattr(proof_payload, "assessment_generation", None) != value.assessment_generation
            or getattr(proof_payload, "assessment", None) != "supported"
            or getattr(getattr(proof_payload, "candidate_value", None), "value_sha256", None)
            != value.rejected_value_sha256
            or proof_event.sequence > verification.sequence
            or verification.sequence > value.authoritative_revision.sequence
        ):
            raise ValueError("reject promotion request requires an authentic current receipt")

    def _append_promotion_request_with_lane(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        payload: PromotionAttemptCancellationRequestedPayload | PromotionRevocationRequestedPayload,
        *,
        expected_revision: JournalRevision,
        claim_event_id: UUID | None,
        proof_rejection: object | None,
    ) -> BatchAppendResult:
        """Reserve the lifecycle lane and append its request under one registry CAS."""

        request_draft = JournalEventDraft(
            type=EventType(payload.kind),
            payload=payload,
            actor="system",
            system_correlation=SystemCorrelation(
                source="promotion",
                operation_id=uuid5(
                    NAMESPACE_URL,
                    f"sedna:promotion:{engagement_id}:{payload.attempt_id}:{payload.kind}",
                ),
            ),
        )

        def attempt() -> BatchAppendResult:
            with _locked_file(self._engagements_fd, ".registry.lock"):
                self._assert_lane_available(lane, exclude=engagement_id)
                snapshot = self._load_snapshot_registry_locked(engagement_id)
                if snapshot.revision != expected_revision:
                    raise RevisionConflictError("expected revision is stale")
                if payload.lifecycle_intent.operation == "reject":
                    self._authenticate_settled_proof_rejection(
                        snapshot,
                        engagement_id=engagement_id,
                        receipt=proof_rejection,
                    )
                state = snapshot.state
                if isinstance(payload, PromotionAttemptCancellationRequestedPayload):
                    active = state.promotion.active_attempt
                    if (
                        active is None
                        or active.attempt_id != payload.attempt_id
                        or (claim_event_id is not None and active.claim_event_id != claim_event_id)
                        or active.stage != payload.stage
                        or active.promotion_revision != payload.promotion_revision
                        or active.verification_event_id != payload.verification_event_id
                    ):
                        raise ValueError("promotion revocation fence no longer matches")
                else:
                    lineage = state.promotion.latest_successful_publication
                    published = next(
                        (
                            item
                            for item in reversed(state.promotion.recent_terminal_attempts)
                            if lineage is not None and item.attempt_id == lineage.attempt_id
                        ),
                        None,
                    )
                    if (
                        lineage is None
                        or published is None
                        or published.attempt_id != payload.attempt_id
                        or published.stage != "promoted"
                        or published.disposition != "promoted"
                        or published.source_id != payload.source_id
                        or published.case_ids != payload.promoted_case_ids
                        or (
                            claim_event_id is not None
                            and published.claim_event_id != claim_event_id
                        )
                    ):
                        raise ValueError("promotion revocation fence no longer matches")
                batch: tuple[JournalEventDraft, ...] = (request_draft,)
                if not any(binding.lane == lane for binding in state.bound_lanes):
                    batch = (
                        JournalEventDraft(
                            lane=lane,
                            actor="host_agent",
                            type=EventType.LANE_BOUND,
                            payload=LaneBoundPayload(
                                lane=lane,
                                binding_reason="promotion lifecycle request",
                            ),
                            idempotency_key=f"lane-bind:{lane.stable_key}:{engagement_id}",
                        ),
                        request_draft,
                    )
                return self._append_batch(
                    engagement_id,
                    batch,
                    expected_revision=expected_revision,
                    defer_tail_recovery=True,
                    allow_active_promotion=True,
                )

        return self._retry_registry_tail_recovery(attempt)

    def _append_promotion_event(
        self,
        engagement_id,
        payload,
        *,
        expected_revision,
        claim_event_id: UUID | None = None,
    ):
        allowed = {
            "promotion_requested",
            "promotion_candidate_ready",
            "promotion_semantic_committed",
            "promotion_index_pending",
            "promotion_index_retry_failed",
            "case_promoted",
            "promotion_attempt_terminated",
            "promotion_attempt_cancellation_requested",
            "promotion_revocation_requested",
            "case_promotion_superseded",
        }
        if payload.kind not in allowed:
            raise EngagementAppendAuthorityError("invalid promotion stage event")
        draft = JournalEventDraft(
            type=payload.kind,
            payload=payload,
            actor="system",
            system_correlation=SystemCorrelation(
                source="promotion",
                operation_id=uuid5(
                    NAMESPACE_URL,
                    f"sedna:promotion:{engagement_id}:{payload.attempt_id}:{payload.kind}",
                ),
            ),
        )
        if isinstance(payload, PromotionRequestedPayload):
            return self._append_batch(
                engagement_id,
                (draft,),
                expected_revision=expected_revision,
                defer_tail_recovery=False,
                allow_active_promotion=True,
            )
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, existing, head, journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                if head.revision != expected_revision:
                    raise RevisionConflictError("expected revision is stale")
                state = reduce_engagement(manifest, existing)
                active = state.promotion.active_attempt
                if isinstance(payload, PromotionAttemptCancellationRequestedPayload):
                    if (
                        active is None
                        or active.attempt_id != payload.attempt_id
                        or (claim_event_id is not None and active.claim_event_id != claim_event_id)
                        or active.stage != payload.stage
                        or active.promotion_revision != payload.promotion_revision
                        or active.verification_event_id != payload.verification_event_id
                    ):
                        raise ValueError("promotion revocation fence no longer matches")
                elif isinstance(payload, PromotionRevocationRequestedPayload):
                    lineage = state.promotion.latest_successful_publication
                    published = next(
                        (
                            attempt
                            for attempt in reversed(state.promotion.recent_terminal_attempts)
                            if lineage is not None and attempt.attempt_id == lineage.attempt_id
                        ),
                        None,
                    )
                    if (
                        lineage is None
                        or published is None
                        or published.attempt_id != payload.attempt_id
                        or published.stage != "promoted"
                        or published.disposition != "promoted"
                        or published.source_id != payload.source_id
                        or published.case_ids != payload.promoted_case_ids
                        or (
                            claim_event_id is not None
                            and published.claim_event_id != claim_event_id
                        )
                    ):
                        raise ValueError("promotion revocation fence no longer matches")
                else:
                    self._require_active_promotion_claim(
                        state,
                        attempt_id=payload.attempt_id,
                        promotion_revision=payload.promotion_revision,
                        claim_event_id=claim_event_id,
                    )
                return self._append_locked(
                    engagement_fd,
                    manifest,
                    existing,
                    head,
                    journal_bytes,
                    (draft,),
                )
        finally:
            os.close(engagement_fd)

    def _commit_report_snapshot(
        self,
        engagement_id: UUID,
        report,
        markdown: str,
        *,
        expected_revision: JournalRevision,
    ):
        return self._commit_report(
            engagement_id,
            report,
            markdown,
            generation_reason="closure",
            expected_revision=expected_revision,
        )

    def _commit_report_revision(
        self,
        engagement_id: UUID,
        report,
        markdown: str,
        *,
        generation_reason: str,
        expected_revision: JournalRevision,
    ):
        return self._commit_report(
            engagement_id,
            report,
            markdown,
            generation_reason=generation_reason,
            expected_revision=expected_revision,
        )

    def report_artifact_status(self, engagement_id: UUID, ref) -> tuple[bool, bool]:
        """Validate current immutable report artifacts under the journal lock."""
        from sedna.engagement.reporting.markdown import render_operational_report
        from sedna.engagement.reporting.models import (
            MAX_REPORT_JSON_BYTES,
            MAX_REPORT_MARKDOWN_BYTES,
            OperationalReport,
        )

        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, _head, _journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                snapshot = self._snapshot(manifest, events, reduce_engagement(manifest, events))
                if ref not in snapshot.state.reports or snapshot.state.active_report != ref:
                    raise ValueError("report reference is not the active journal-bound report")
                reports_fd = os.open("reports", _directory_flags(), dir_fd=engagement_fd)
                try:
                    try:
                        raw = _read_bounded(
                            reports_fd,
                            f"report-v{ref.report_revision}.json",
                            MAX_REPORT_JSON_BYTES,
                            label="committed report JSON",
                        )
                        if sha256(raw).hexdigest() != ref.json_sha256:
                            return False, False
                        report = OperationalReport.model_validate_json(raw)
                    except (JournalUnavailableError, ValueError):
                        return False, False
                    expected_markdown = render_operational_report(report).encode("utf-8")
                    if sha256(expected_markdown).hexdigest() != ref.markdown_sha256:
                        raise JournalUnavailableError(
                            "journal-bound report renderer digest mismatch"
                        )
                    try:
                        markdown = _read_bounded(
                            reports_fd,
                            f"report-v{ref.report_revision}.md",
                            MAX_REPORT_MARKDOWN_BYTES,
                            label="committed report Markdown",
                        )
                    except JournalUnavailableError:
                        return True, False
                    return True, markdown == expected_markdown
                finally:
                    os.close(reports_fd)
        finally:
            os.close(engagement_fd)

    def _repair_markdown(
        self, engagement_id: UUID, report_revision: int, *, expected_revision: JournalRevision
    ):
        from sedna.engagement.reporting.markdown import render_operational_report
        from sedna.engagement.reporting.models import (
            MAX_REPORT_JSON_BYTES,
            OperationalReport,
        )

        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, _head, _journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                snapshot = self._snapshot(manifest, events, reduce_engagement(manifest, events))
                self._require_no_active_promotion(snapshot.state)
                if snapshot.revision != expected_revision:
                    raise RevisionConflictError("expected revision is stale")
                ref = next(
                    (
                        item
                        for item in snapshot.state.reports
                        if item.report_revision == report_revision
                    ),
                    None,
                )
                if ref is None:
                    raise ValueError("report revision does not exist")
                reports_fd = os.open("reports", _directory_flags(), dir_fd=engagement_fd)
                try:
                    json_name = f"report-v{report_revision}.json"
                    raw = _read_bounded(
                        reports_fd,
                        json_name,
                        MAX_REPORT_JSON_BYTES,
                        label="committed report JSON",
                    )
                    if sha256(raw).hexdigest() != ref.json_sha256:
                        raise JournalUnavailableError("committed report JSON digest mismatch")
                    report = OperationalReport.model_validate_json(raw)
                    markdown = render_operational_report(report).encode("utf-8")
                    if sha256(markdown).hexdigest() != ref.markdown_sha256:
                        raise JournalUnavailableError(
                            "renderer output does not match committed digest"
                        )
                    _atomic_write(reports_fd, f"report-v{report_revision}.md", markdown)
                    os.fsync(reports_fd)
                finally:
                    os.close(reports_fd)
                return ref
        finally:
            os.close(engagement_fd)

    def _commit_report(
        self,
        engagement_id: UUID,
        report,
        markdown: str,
        *,
        generation_reason: Literal["closure", "repair_json", "manual_report"],
        expected_revision: JournalRevision,
    ):
        from sedna.engagement.events import (
            EngagementClosedPayload,
            ReportGeneratedPayload,
            SystemCorrelation,
        )
        from sedna.engagement.reporting.markdown import render_operational_report
        from sedna.engagement.reporting.models import (
            MAX_REPORT_JSON_BYTES,
            MAX_REPORT_MARKDOWN_BYTES,
            MAX_REPORT_TRANSACTION_BYTES,
            REPORT_RENDERER_VERSION,
            OperationalReport,
            ReportCommitResult,
            ReportRef,
        )

        report = OperationalReport.model_validate(report.model_dump(mode="json", warnings="error"))
        expected_markdown = render_operational_report(report)
        if markdown != expected_markdown:
            raise ValueError("report Markdown does not match its immutable JSON snapshot")
        json_bytes = _canonical_json(report.model_dump(mode="json", warnings="error"))
        markdown_bytes = markdown.encode("utf-8")
        if (
            len(json_bytes) > MAX_REPORT_JSON_BYTES
            or len(markdown_bytes) > MAX_REPORT_MARKDOWN_BYTES
        ):
            raise ValueError("report exceeds immutable report budget")
        json_digest = sha256(json_bytes).hexdigest()
        markdown_digest = sha256(markdown_bytes).hexdigest()
        json_name = f"report-v{report.report_revision}.json"
        markdown_name = f"report-v{report.report_revision}.md"
        intent_id = uuid5(
            engagement_id,
            f"report-intent:{report.report_revision}:{generation_reason}:{json_digest}:{markdown_digest}",
        )
        intent = _canonical_json(
            {
                "intent_id": str(intent_id),
                "engagement_id": str(engagement_id),
                "report_id": str(report.report_id),
                "report_revision": report.report_revision,
                "generation_reason": generation_reason,
                "expected_revision": expected_revision.model_dump(mode="json"),
                "json_name": json_name,
                "json_sha256": json_digest,
                "markdown_name": markdown_name,
                "markdown_sha256": markdown_digest,
                "renderer_version": REPORT_RENDERER_VERSION,
            }
        )
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, existing, head, journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                snapshot = self._snapshot(manifest, existing, reduce_engagement(manifest, existing))
                self._require_no_active_promotion(snapshot.state)
                already_payload = next(
                    (
                        event.payload
                        for event in existing
                        if isinstance(event.payload, ReportGeneratedPayload)
                        and event.payload.report.report_id == report.report_id
                    ),
                    None,
                )
                if already_payload is not None:
                    already = already_payload.report
                    prefix = f"engagements/{engagement_id}/reports"
                    if (
                        already_payload.generation_reason != generation_reason
                        or already.report_revision != report.report_revision
                        or already.json_relative_path
                        != f"{prefix}/report-v{report.report_revision}.json"
                        or already.markdown_relative_path
                        != f"{prefix}/report-v{report.report_revision}.md"
                        or already.renderer_version != REPORT_RENDERER_VERSION
                        or (already.json_sha256, already.markdown_sha256, already.journal_revision)
                        != (
                            json_digest,
                            markdown_digest,
                            expected_revision,
                        )
                    ):
                        raise JournalUnavailableError("conflicting committed report")
                    try:
                        reports_fd = os.open("reports", _directory_flags(), dir_fd=engagement_fd)
                    except OSError as exc:
                        raise JournalUnavailableError(
                            "committed reports directory is unavailable"
                        ) from exc
                    try:
                        _validate_directory(
                            reports_fd, label="reports directory", expected_mode=0o700
                        )
                        for name, expected, limit, label in (
                            (
                                f"report-v{report.report_revision}.json",
                                json_bytes,
                                MAX_REPORT_JSON_BYTES,
                                "committed report JSON",
                            ),
                            (
                                f"report-v{report.report_revision}.md",
                                markdown_bytes,
                                MAX_REPORT_MARKDOWN_BYTES,
                                "committed report Markdown",
                            ),
                        ):
                            actual = _read_bounded(reports_fd, name, limit, label=label)
                            if actual != expected:
                                raise JournalUnavailableError(f"{label} digest mismatch")
                        try:
                            retained_intent = _read_bounded(
                                reports_fd,
                                ".report-transaction.json",
                                MAX_REPORT_TRANSACTION_BYTES,
                                "report transaction intent",
                            )
                        except JournalUnavailableError as exc:
                            if not _missing_file(exc):
                                raise
                        else:
                            if retained_intent != intent:
                                raise JournalUnavailableError(
                                    "conflicting report transaction intent"
                                )
                            os.unlink(".report-transaction.json", dir_fd=reports_fd)
                            os.fsync(reports_fd)
                    finally:
                        os.close(reports_fd)
                    return ReportCommitResult(report=already, snapshot=snapshot)
                if head.revision != expected_revision:
                    raise RevisionConflictError("expected revision is stale")
                if (
                    report.engagement_id != engagement_id
                    or report.journal_revision != expected_revision
                ):
                    raise ValueError("report does not match engagement journal revision")
                if generation_reason == "closure":
                    if snapshot.state.status.value != "closing" or not snapshot.state.closure_ready:
                        raise ValueError("closure barrier is not ready")
                elif snapshot.state.status.value not in {"closed_unverified", "closed_verified"}:
                    raise ValueError("report revision requires a closed engagement")
                with suppress(FileExistsError):
                    os.mkdir("reports", 0o700, dir_fd=engagement_fd)
                try:
                    reports_fd = os.open("reports", _directory_flags(), dir_fd=engagement_fd)
                except OSError as exc:
                    raise JournalUnavailableError("reports directory is unavailable") from exc
                try:
                    _validate_directory(reports_fd, label="reports directory", expected_mode=0o700)
                    try:
                        current_intent = _read_bounded(
                            reports_fd,
                            ".report-transaction.json",
                            MAX_REPORT_TRANSACTION_BYTES,
                            "report transaction intent",
                        )
                    except JournalUnavailableError as exc:
                        if not _missing_file(exc):
                            raise
                        _atomic_write(reports_fd, ".report-transaction.json", intent)
                    else:
                        if current_intent != intent:
                            raise JournalUnavailableError("conflicting report transaction intent")
                    self._fault("report_after_intent")
                    for index, (name, data, limit) in enumerate(
                        (
                            (json_name, json_bytes, MAX_REPORT_JSON_BYTES),
                            (markdown_name, markdown_bytes, MAX_REPORT_MARKDOWN_BYTES),
                        )
                    ):
                        try:
                            current = _read_bounded(reports_fd, name, limit, name)
                        except JournalUnavailableError as exc:
                            if not _missing_file(exc):
                                raise
                            _atomic_write(reports_fd, name, data)
                        else:
                            if current != data:
                                raise JournalUnavailableError("immutable report file conflicts")
                        self._fault("report_after_json" if index == 0 else "report_after_markdown")
                    os.fsync(reports_fd)
                    self._fault("report_after_directory_fsync")
                finally:
                    os.close(reports_fd)
                prefix = f"engagements/{engagement_id}/reports"
                ref = ReportRef(
                    report_id=report.report_id,
                    report_revision=report.report_revision,
                    json_relative_path=f"{prefix}/{json_name}",
                    json_sha256=json_digest,
                    markdown_relative_path=f"{prefix}/{markdown_name}",
                    markdown_sha256=markdown_digest,
                    renderer_version=REPORT_RENDERER_VERSION,
                    journal_revision=expected_revision,
                )
                operation_id = uuid5(
                    engagement_id, f"report-commit:{report.report_revision}:{generation_reason}"
                )
                correlation = SystemCorrelation(source="reporting", operation_id=operation_id)
                drafts = [
                    JournalEventDraft(
                        actor="system",
                        type="report_generated",
                        payload=ReportGeneratedPayload(
                            report=ref, generation_reason=generation_reason
                        ),
                        system_correlation=correlation,
                    )
                ]
                if generation_reason == "closure":
                    closure = snapshot.state.closure
                    assert closure is not None
                    drafts.append(
                        JournalEventDraft(
                            actor="system",
                            type="engagement_closed",
                            payload=EngagementClosedPayload(
                                report_id=ref.report_id,
                                report_revision=ref.report_revision,
                                closure_request_event_id=closure.event_id,
                                terminal_watermark=closure.terminal_watermark,
                            ),
                            system_correlation=correlation,
                        )
                    )
                self._fault("report_before_event_append")
                appended = self._append_locked(
                    engagement_fd, manifest, existing, head, journal_bytes, tuple(drafts)
                )
                self._fault("report_after_event_append")
                reports_fd = os.open("reports", _directory_flags(), dir_fd=engagement_fd)
                try:
                    os.unlink(".report-transaction.json", dir_fd=reports_fd)
                    os.fsync(reports_fd)
                finally:
                    os.close(reports_fd)
                self._fault("report_after_intent_clear")
                events = (*existing, *appended.events)
                closed = self._snapshot(manifest, events, reduce_engagement(manifest, events))
                return ReportCommitResult(report=ref, snapshot=closed)
        finally:
            os.close(engagement_fd)

    def _append_batch(
        self,
        engagement_id: UUID,
        drafts: Sequence[JournalEventDraft],
        *,
        expected_revision: JournalRevision | None,
        defer_tail_recovery: bool,
        allow_active_promotion: bool = False,
    ) -> BatchAppendResult:
        self._require_open()
        if not isinstance(drafts, Sequence) or isinstance(drafts, (str, bytes)):
            raise TypeError("drafts must be a sequence")
        if not 1 <= len(drafts) <= MAX_JOURNAL_BATCH_EVENTS:
            raise ValueError("journal batch exceeds its event bound")
        validated = tuple(
            JournalEventDraft.model_validate(item.model_dump(mode="python")) for item in drafts
        )
        if not defer_tail_recovery:
            self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                if defer_tail_recovery:
                    (
                        manifest,
                        existing,
                        current_head,
                        journal_bytes,
                    ) = self._load_authoritative_registry_locked(engagement_fd, engagement_id)
                else:
                    (
                        manifest,
                        existing,
                        current_head,
                        journal_bytes,
                    ) = self._load_authoritative_locked(
                        engagement_fd, engagement_id, allow_tail=False
                    )
                if not allow_active_promotion:
                    state = reduce_engagement(manifest, existing)
                    self._require_no_active_promotion(state)
                abandoned = self._abandon_report_transaction_locked(
                    engagement_fd,
                    manifest,
                    existing,
                    current_head,
                    journal_bytes,
                    validated,
                    expected_revision,
                )
                if abandoned is not None:
                    return abandoned
                prior = self._resolve_existing_batch(existing, validated)
                if prior is not None:
                    self._validate_journal_limits(existing, journal_bytes)
                    state = reduce_engagement(manifest, existing)
                    expected_projection = self._projection_bytes(current_head.revision, state)
                    try:
                        actual_projection = _read_bounded(
                            engagement_fd,
                            "engagement-state.json",
                            MAX_DERIVED_PROJECTION_BYTES,
                            "engagement state projection",
                        )
                    except JournalUnavailableError as exc:
                        if not _recoverable_projection_read(exc):
                            raise
                        actual_projection = b""
                    if actual_projection != expected_projection:
                        _atomic_write(
                            engagement_fd,
                            "engagement-state.json",
                            expected_projection,
                        )
                    return BatchAppendResult(
                        events=prior,
                        revision=current_head.revision,
                        existing_event_ids=tuple(item.event_id for item in prior),
                    )
                if expected_revision is not None and expected_revision != current_head.revision:
                    raise RevisionConflictError("expected revision is stale")
                return self._append_locked(
                    engagement_fd,
                    manifest,
                    existing,
                    current_head,
                    journal_bytes,
                    validated,
                )
        finally:
            os.close(engagement_fd)

    def _abandon_report_transaction_locked(
        self,
        engagement_fd: int,
        manifest: EngagementManifest,
        existing: tuple[JournalEvent, ...],
        current_head: JournalHead,
        journal_bytes: bytes,
        drafts: tuple[JournalEventDraft, ...],
        caller_expected_revision: JournalRevision | None,
    ) -> BatchAppendResult | None:
        from sedna.engagement.events import (
            EventType,
            ReportCommitAbandonedPayload,
            ReportGeneratedPayload,
        )
        from sedna.engagement.reporting.models import (
            MAX_REPORT_JSON_BYTES,
            MAX_REPORT_MARKDOWN_BYTES,
            MAX_REPORT_TRANSACTION_BYTES,
            REPORT_RENDERER_VERSION,
        )

        try:
            reports_fd = os.open("reports", _directory_flags(), dir_fd=engagement_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise JournalUnavailableError("committed reports directory is unavailable") from exc
        try:
            _validate_directory(reports_fd, label="reports directory", expected_mode=0o700)
            try:
                raw = _read_bounded(
                    reports_fd,
                    ".report-transaction.json",
                    MAX_REPORT_TRANSACTION_BYTES,
                    "report transaction intent",
                )
            except JournalUnavailableError as exc:
                if _missing_file(exc):
                    return None
                raise
            try:
                value = json.loads(raw)
                if _canonical_json(value) != raw:
                    raise ValueError("non-canonical intent")
                if set(value) != {
                    "intent_id",
                    "engagement_id",
                    "report_id",
                    "report_revision",
                    "generation_reason",
                    "expected_revision",
                    "json_name",
                    "json_sha256",
                    "markdown_name",
                    "markdown_sha256",
                    "renderer_version",
                }:
                    raise ValueError("unexpected intent fields")
                intent_id = UUID(value["intent_id"])
                report_id = UUID(value["report_id"])
                expected = JournalRevision.model_validate(value["expected_revision"])
                report_revision = value["report_revision"]
                if type(report_revision) is not int or report_revision < 1:
                    raise ValueError("invalid report revision")
                generation_reason = value["generation_reason"]
                json_digest = value["json_sha256"]
                markdown_digest = value["markdown_sha256"]
                json_name = f"report-v{report_revision}.json"
                markdown_name = f"report-v{report_revision}.md"
                expected_report_id = uuid5(manifest.engagement_id, f"report:{report_revision}")
                expected_intent_id = uuid5(
                    manifest.engagement_id,
                    f"report-intent:{report_revision}:{generation_reason}:"
                    f"{json_digest}:{markdown_digest}",
                )
                if (
                    value["engagement_id"] != str(manifest.engagement_id)
                    or value["json_name"] != json_name
                    or value["markdown_name"] != markdown_name
                    or not re.fullmatch(r"[0-9a-f]{64}", json_digest)
                    or not re.fullmatch(r"[0-9a-f]{64}", markdown_digest)
                    or generation_reason not in {"closure", "repair_json", "manual_report"}
                    or value["renderer_version"] != REPORT_RENDERER_VERSION
                    or report_id != expected_report_id
                    or intent_id != expected_intent_id
                ):
                    raise ValueError("intent identity mismatch")
            except Exception as exc:
                raise JournalUnavailableError("invalid report transaction intent") from exc

            bound = next(
                (
                    item.payload
                    for item in existing
                    if isinstance(item.payload, ReportGeneratedPayload)
                    and item.payload.report.report_id == report_id
                ),
                None,
            )
            if bound is not None:
                ref = bound.report
                prefix = f"engagements/{manifest.engagement_id}/reports"
                if (
                    bound.generation_reason != value["generation_reason"]
                    or ref.report_revision != report_revision
                    or ref.journal_revision != expected
                    or ref.json_relative_path != f"{prefix}/{json_name}"
                    or ref.markdown_relative_path != f"{prefix}/{markdown_name}"
                    or ref.json_sha256 != json_digest
                    or ref.markdown_sha256 != markdown_digest
                    or ref.renderer_version != value["renderer_version"]
                ):
                    raise JournalUnavailableError("conflicting event-bound report transaction")
                for name, digest, limit, label in (
                    (
                        json_name,
                        json_digest,
                        MAX_REPORT_JSON_BYTES,
                        "event-bound report JSON",
                    ),
                    (
                        markdown_name,
                        markdown_digest,
                        MAX_REPORT_MARKDOWN_BYTES,
                        "event-bound report Markdown",
                    ),
                ):
                    data = _read_bounded(reports_fd, name, limit, label)
                    if sha256(data).hexdigest() != digest:
                        raise JournalUnavailableError(f"{label} digest mismatch")
                os.unlink(".report-transaction.json", dir_fd=reports_fd)
                os.fsync(reports_fd)
                return None

            state = reduce_engagement(manifest, existing)
            closing_reason_is_valid = (
                report_revision == 1
                and generation_reason == "closure"
                and state.status.value == "closing"
                and state.closure_ready
                and not state.reports
            )
            later_reason_is_valid = (
                report_revision == len(state.reports) + 1
                and report_revision > 1
                and generation_reason in {"repair_json", "manual_report"}
                and state.status.value in {"closed_unverified", "closed_verified"}
            )
            if not (closing_reason_is_valid or later_reason_is_valid):
                raise JournalUnavailableError("invalid report transaction intent")

            draft_digest = sha256(
                _canonical_json([item.model_dump(mode="json", warnings="error") for item in drafts])
            ).hexdigest()
            orphan_name = f"{intent_id}-{json_digest}"
            orphan_directory = f"engagements/{manifest.engagement_id}/reports/orphans/{orphan_name}"

            def complete_abandonment() -> None:
                with suppress(FileExistsError):
                    os.mkdir("orphans", 0o700, dir_fd=reports_fd)
                orphans_fd = os.open("orphans", _directory_flags(), dir_fd=reports_fd)
                try:
                    _validate_directory(orphans_fd, label="report orphans", expected_mode=0o700)
                    with suppress(FileExistsError):
                        os.mkdir(orphan_name, 0o700, dir_fd=orphans_fd)
                    orphan_fd = os.open(orphan_name, _directory_flags(), dir_fd=orphans_fd)
                    try:
                        _validate_directory(
                            orphan_fd,
                            label="report orphan directory",
                            expected_mode=0o700,
                        )
                        for name, digest, limit, label, fault_point in (
                            (
                                json_name,
                                json_digest,
                                MAX_REPORT_JSON_BYTES,
                                "orphaned report JSON",
                                "report_abandon_after_json_move",
                            ),
                            (
                                markdown_name,
                                markdown_digest,
                                MAX_REPORT_MARKDOWN_BYTES,
                                "orphaned report Markdown",
                                "report_abandon_after_markdown_move",
                            ),
                        ):
                            try:
                                source = _read_bounded(reports_fd, name, limit, label)
                            except JournalUnavailableError as exc:
                                if not _missing_file(exc):
                                    raise
                                source = None
                            try:
                                destination = _read_bounded(orphan_fd, name, limit, label)
                            except JournalUnavailableError as exc:
                                if not _missing_file(exc):
                                    raise
                                destination = None
                            if source is not None and destination is not None:
                                raise JournalUnavailableError(
                                    "report transaction file exists in both canonical "
                                    "and orphan locations"
                                )
                            data = source if source is not None else destination
                            if data is None or sha256(data).hexdigest() != digest:
                                raise JournalUnavailableError(f"{label} digest mismatch")
                            if source is not None:
                                os.rename(
                                    name,
                                    name,
                                    src_dir_fd=reports_fd,
                                    dst_dir_fd=orphan_fd,
                                )
                                self._fault(fault_point)
                        os.fsync(orphan_fd)
                    finally:
                        os.close(orphan_fd)
                    os.fsync(orphans_fd)
                finally:
                    os.close(orphans_fd)
                os.fsync(reports_fd)
                os.unlink(".report-transaction.json", dir_fd=reports_fd)
                os.fsync(reports_fd)

            prior = next(
                (
                    (index, item.payload)
                    for index, item in enumerate(existing)
                    if isinstance(item.payload, ReportCommitAbandonedPayload)
                    and item.payload.intent_id == intent_id
                ),
                None,
            )
            if prior is not None:
                index, payload = prior
                replay = existing[index + 1 : index + 1 + payload.displaced_batch_count]
                if (
                    payload.displaced_batch_count != len(drafts)
                    or payload.displaced_batch_digest != draft_digest
                    or payload.report_id != report_id
                    or payload.report_revision != report_revision
                    or payload.expected_revision != expected
                    or payload.json_sha256 != json_digest
                    or payload.markdown_sha256 != markdown_digest
                    or payload.orphan_directory != orphan_directory
                    or len(replay) != len(drafts)
                    or not self._drafts_match(replay, drafts)
                ):
                    raise JournalUnavailableError("conflicting abandoned report retry")
                complete_abandonment()
                return BatchAppendResult(
                    events=replay,
                    revision=current_head.revision,
                    existing_event_ids=tuple(item.event_id for item in replay),
                )

            if len(drafts) > MAX_JOURNAL_BATCH_EVENTS - 1:
                raise ValueError("report abandonment leaves no room for caller batch")
            if (
                caller_expected_revision is not None
                and caller_expected_revision != current_head.revision
            ):
                raise RevisionConflictError("expected revision is stale")
            for name, digest, limit, label in (
                (json_name, json_digest, MAX_REPORT_JSON_BYTES, "report transaction JSON"),
                (
                    markdown_name,
                    markdown_digest,
                    MAX_REPORT_MARKDOWN_BYTES,
                    "report transaction Markdown",
                ),
            ):
                data = _read_bounded(reports_fd, name, limit, label)
                if sha256(data).hexdigest() != digest:
                    raise JournalUnavailableError(f"{label} digest mismatch")

            recovery = JournalEventDraft(
                actor="system",
                type=EventType.REPORT_COMMIT_ABANDONED,
                payload=ReportCommitAbandonedPayload(
                    intent_id=intent_id,
                    report_id=report_id,
                    report_revision=report_revision,
                    expected_revision=expected,
                    json_sha256=json_digest,
                    markdown_sha256=markdown_digest,
                    orphan_directory=orphan_directory,
                    displaced_batch_count=len(drafts),
                    displaced_batch_digest=draft_digest,
                ),
                system_correlation=SystemCorrelation(
                    source="recovery",
                    operation_id=uuid5(manifest.engagement_id, f"report-abandoned:{intent_id}"),
                ),
            )
            self._fault("report_abandon_before_event_append")
            appended = self._append_locked(
                engagement_fd,
                manifest,
                existing,
                current_head,
                journal_bytes,
                (recovery, *drafts),
            )
            self._fault("report_abandon_after_event_append")
            complete_abandonment()
            self._fault("report_abandon_after_intent_clear")
            caller_events = appended.events[1:]
            return BatchAppendResult(
                events=caller_events,
                revision=appended.revision,
                created_event_ids=tuple(item.event_id for item in caller_events),
            )
        finally:
            os.close(reports_fd)

    def _append_locked(
        self,
        engagement_fd: int,
        manifest: EngagementManifest,
        existing: tuple[JournalEvent, ...],
        base_head: JournalHead,
        journal_bytes: bytes,
        drafts: tuple[JournalEventDraft, ...],
    ) -> BatchAppendResult:
        new_events = self._materialize(manifest.engagement_id, existing, drafts)
        lines = tuple(_event_line(item) + b"\n" for item in new_events)
        for line in lines:
            if len(line) - 1 > MAX_JOURNAL_EVENT_BYTES:
                raise ValueError("journal event exceeds its byte bound")
        target_bytes = journal_bytes + b"".join(lines)
        all_events = (*existing, *new_events)
        self._validate_journal_limits(all_events, target_bytes)
        state = reduce_engagement(manifest, all_events)
        projection_bytes = self._projection_bytes(_revision(all_events), state)
        target_head = _head(manifest.engagement_id, all_events, target_bytes)
        intent = _canonical_json(
            {
                "base_head": base_head.model_dump(mode="json"),
                "target_head": target_head.model_dump(mode="json"),
                "lines": [base64.b64encode(line).decode() for line in lines],
            }
        )
        if len(intent) > MAX_PENDING_APPEND_BYTES:
            raise ValueError("pending append exceeds its byte bound")
        self._fault("append_before_intent")
        _atomic_write(engagement_fd, ".pending-append.json", intent)
        self._fault("append_after_intent")
        self._fault("append_before_journal_write")
        journal_fd = os.open(
            "events.jsonl",
            os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=engagement_fd,
        )
        try:
            result = _validate_regular(journal_fd, label="events.jsonl", expected_mode=0o600)
            if result.st_size != base_head.journal_bytes:
                raise JournalUnavailableError("journal_corrupt: append base size changed")
            for index, line in enumerate(lines):
                split = max(1, len(line) // 2)
                _write_all(journal_fd, line[:split])
                if index == 0:
                    self._fault("append_after_partial_journal_write")
                _write_all(journal_fd, line[split:])
            self._fault("append_after_complete_journal_write")
            os.fsync(journal_fd)
        finally:
            os.close(journal_fd)
        self._fault("append_after_journal_fsync")
        _atomic_write(engagement_fd, "journal-head.json", _model_bytes(target_head))
        self._fault("append_after_head_replace")
        os.unlink(".pending-append.json", dir_fd=engagement_fd)
        os.fsync(engagement_fd)
        self._fault("append_after_intent_clear")
        _atomic_write(engagement_fd, "engagement-state.json", projection_bytes)
        self._fault("append_after_projection")
        self._fault("append_before_response")
        return BatchAppendResult(
            events=new_events,
            revision=target_head.revision,
            created_event_ids=tuple(item.event_id for item in new_events),
        )

    def load_events(self, engagement_id: UUID) -> tuple[JournalEvent, ...]:
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                _, events, _, _ = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                return events
        finally:
            os.close(engagement_fd)

    def load_snapshot(self, engagement_id: UUID):
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, head, _ = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                state = reduce_engagement(manifest, events)
                expected = self._projection_bytes(head.revision, state)
                try:
                    actual = _read_bounded(
                        engagement_fd,
                        "engagement-state.json",
                        MAX_DERIVED_PROJECTION_BYTES,
                        "engagement state projection",
                    )
                except JournalUnavailableError as exc:
                    if not _recoverable_projection_read(exc):
                        raise
                    actual = b""
                if actual != expected:
                    _atomic_write(engagement_fd, "engagement-state.json", expected)
                return self._snapshot(manifest, events, state)
        finally:
            os.close(engagement_fd)

    def write_projection(
        self,
        engagement_id: UUID,
        *,
        name: str,
        owner: str,
        envelope: Mapping[str, Any],
        expected_revision: JournalRevision | None = None,
    ) -> None:
        expected_owner = PROJECTION_OWNERS.get(name)
        if expected_owner is None or expected_owner != owner or name == "engagement-state":
            raise ProjectionOwnershipError("projection name is not owned by this writer")
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, head, _ = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                state = reduce_engagement(manifest, events)
                self._require_no_active_promotion(state)
                engagement_projection = self._projection_bytes(head.revision, state)
                try:
                    current_projection = _read_bounded(
                        engagement_fd,
                        "engagement-state.json",
                        MAX_DERIVED_PROJECTION_BYTES,
                        "engagement state projection",
                    )
                except JournalUnavailableError as exc:
                    if not _recoverable_projection_read(exc):
                        raise
                    current_projection = b""
                if current_projection != engagement_projection:
                    _atomic_write(
                        engagement_fd,
                        "engagement-state.json",
                        engagement_projection,
                    )
                if expected_revision is not None and head.revision != expected_revision:
                    raise RevisionConflictError("projection revision is stale")
                supplied = envelope.get("authoritative_revision")
                if (
                    supplied is not None
                    and JournalRevision.model_validate(supplied) != head.revision
                ):
                    raise RevisionConflictError("projection envelope revision is stale")
                value = dict(envelope)
                value["name"] = name
                value["owner"] = owner
                value["authoritative_revision"] = head.revision.model_dump(mode="json")
                data = _canonical_projection_envelope(value)
                if len(data) > MAX_DERIVED_PROJECTION_BYTES:
                    raise ValueError("projection exceeds its byte bound")
                _atomic_write(engagement_fd, f"{name}.json", data)
        finally:
            os.close(engagement_fd)

    def load_projection(
        self, engagement_id: UUID, *, name: str, owner: str
    ) -> dict[str, Any] | None:
        expected_owner = PROJECTION_OWNERS.get(name)
        if expected_owner is None or expected_owner != owner:
            raise ProjectionOwnershipError("projection name is not owned by this reader")
        snapshot = self.load_snapshot(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            try:
                data = _read_bounded(
                    engagement_fd,
                    f"{name}.json",
                    MAX_DERIVED_PROJECTION_BYTES,
                    "projection",
                )
            except JournalUnavailableError as exc:
                if _missing_file(exc):
                    return None
                raise
            value = json.loads(data)
            if (
                not isinstance(value, dict)
                or value.get("owner") != owner
                or value.get("name") != name
            ):
                raise ProjectionOwnershipError("stored projection owner does not match")
            supplied_digest = value.get("projection_digest")
            material = dict(value)
            material.pop("projection_digest", None)
            if (
                not isinstance(supplied_digest, str)
                or supplied_digest != sha256(_canonical_json(material)).hexdigest()
            ):
                raise JournalUnavailableError("projection digest is invalid")
            try:
                revision = JournalRevision.model_validate(value["authoritative_revision"])
            except Exception as exc:
                raise JournalUnavailableError("projection revision is invalid") from exc
            if revision != snapshot.revision:
                raise RevisionConflictError("projection revision is stale")
            return value
        finally:
            os.close(engagement_fd)

    def _load_strategy_archive_locked(
        self,
        engagement_fd: int,
        *,
        after_entry_id: UUID | None = None,
        limit: int = 256,
    ) -> StrategyArchivePage | None:
        """Validate a complete archive while retaining at most one bounded page."""
        try:
            fd = _open_regular(
                engagement_fd,
                STRATEGY_ARCHIVE_NAME,
                MAX_STRATEGY_ARCHIVE_BYTES,
                "strategy archive",
            )
        except JournalUnavailableError as exc:
            if _missing_file(exc):
                return None
            raise
        try:
            size = os.fstat(fd).st_size
            lines = _archive_read_lines(fd)
            try:
                header_line = next(lines)
            except StopIteration as exc:
                raise JournalUnavailableError("strategy archive has no header") from exc
            try:
                envelope = StrategyArchiveProjectionEnvelope.model_validate_json(header_line)
            except Exception as exc:
                raise JournalUnavailableError("strategy archive header is invalid") from exc
            if _archive_header_bytes(envelope) != header_line + b"\n":
                raise JournalUnavailableError("strategy archive header is not canonical")
            if envelope.byte_size != size:
                raise JournalUnavailableError("strategy archive byte size is invalid")

            count = 0
            previous_id: UUID | None = None
            entries_digest = sha256()
            page: list[StrategyArchiveRecordDraft] = []
            omitted_digest = sha256()
            has_omitted = False
            cursor_found = after_entry_id is None
            for line in lines:
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("record must be an object")
                    revision = value.pop("archive_revision")
                    record = StrategyArchiveRecordDraft.model_validate(value)
                except Exception as exc:
                    raise JournalUnavailableError("strategy archive entry is invalid") from exc
                if revision != envelope.archive_revision:
                    raise JournalUnavailableError("strategy archive entry revision is invalid")
                canonical = _archive_record_bytes(record, envelope.archive_revision)
                if canonical != line + b"\n":
                    raise JournalUnavailableError("strategy archive entry is not canonical")
                if previous_id is not None and record.entry_id <= previous_id:
                    raise JournalUnavailableError(
                        "strategy archive entries are not strictly ordered"
                    )
                previous_id = record.entry_id
                if record.entry_id == after_entry_id:
                    cursor_found = True
                count += 1
                if count > MAX_STRATEGY_ARCHIVE_RECORDS:
                    raise JournalUnavailableError("strategy archive record count exceeds its bound")
                entries_digest.update(canonical)
                if after_entry_id is None or record.entry_id > after_entry_id:
                    if len(page) < limit:
                        page.append(record)
                    else:
                        has_omitted = True
                        omitted_digest.update(canonical)
            if count != envelope.entry_count:
                raise JournalUnavailableError("strategy archive record count is invalid")
            if entries_digest.hexdigest() != envelope.entries_sha256:
                raise JournalUnavailableError("strategy archive digest is invalid")
            if not cursor_found:
                raise JournalUnavailableError("strategy archive cursor is unknown")
            return StrategyArchivePage(
                envelope=envelope,
                records=tuple(page),
                next_after_entry_id=page[-1].entry_id if has_omitted else None,
                complete=not has_omitted,
                omitted_entries_sha256=omitted_digest.hexdigest() if has_omitted else None,
            )
        finally:
            os.close(fd)

    def load_strategy_archive(
        self,
        engagement_id: UUID,
        *,
        after_entry_id: UUID | None = None,
        limit: int = 256,
    ) -> StrategyArchivePage | None:
        if not 1 <= limit <= 256:
            raise ValueError("strategy archive page limit is out of bounds")
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".strategy-archive.lock"):
                return self._load_strategy_archive_locked(
                    engagement_fd, after_entry_id=after_entry_id, limit=limit
                )
        finally:
            os.close(engagement_fd)

    def commit_strategy_archive(
        self,
        engagement_id: UUID,
        *,
        schema_id: str,
        records: Iterable[StrategyArchiveRecordDraft],
        expected_archive_revision: int | None,
        expected_journal_revision: JournalRevision,
    ) -> StrategyArchiveCommitResult:
        """Stream a fixed-path cold projection with archive and journal CAS guards."""
        if not isinstance(schema_id, str) or not schema_id:
            raise ValueError("strategy archive schema ID is required")
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        stage_name: str | None = None
        temporary_name: str | None = None
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, head, _ = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                self._require_no_active_promotion(reduce_engagement(manifest, events))
                if head.revision != expected_journal_revision:
                    raise RevisionConflictError("strategy archive journal revision is stale")
                with _locked_file(engagement_fd, ".strategy-archive.lock"):
                    current = self._load_strategy_archive_locked(engagement_fd)
                    current_revision = (
                        None if current is None else current.envelope.archive_revision
                    )
                    if current_revision != expected_archive_revision:
                        raise RevisionConflictError("strategy archive revision is stale")
                    archive_revision = 1 if current_revision is None else current_revision + 1
                    stage_name = f".{STRATEGY_ARCHIVE_NAME}.stage-{uuid4()}"
                    stage_fd = os.open(stage_name, _create_flags(), 0o600, dir_fd=engagement_fd)
                    try:
                        os.fchmod(stage_fd, 0o600)
                        digest = sha256()
                        entry_bytes = 0
                        entry_count = 0
                        prior_id: UUID | None = None
                        iterator = iter(records)
                        while True:
                            try:
                                supplied = next(iterator)
                            except StopIteration:
                                break
                            entry_count += 1
                            if entry_count > MAX_STRATEGY_ARCHIVE_RECORDS:
                                raise ValueError("strategy archive record count exceeds its bound")
                            record = StrategyArchiveRecordDraft.model_validate(supplied)
                            if prior_id is not None and record.entry_id <= prior_id:
                                raise ValueError(
                                    "strategy archive records must be strictly ordered"
                                )
                            prior_id = record.entry_id
                            line = _archive_record_bytes(record, archive_revision)
                            entry_bytes += len(line)
                            if entry_bytes >= MAX_STRATEGY_ARCHIVE_BYTES:
                                raise ValueError("strategy archive exceeds its byte bound")
                            _write_all(stage_fd, line)
                            digest.update(line)
                        os.fsync(stage_fd)
                    finally:
                        os.close(stage_fd)
                    envelope = _archive_envelope(
                        schema_id=schema_id,
                        archive_revision=archive_revision,
                        journal_revision=head.revision,
                        entry_count=entry_count,
                        entries_sha256=digest.hexdigest(),
                        entry_bytes=entry_bytes,
                    )
                    header = _archive_header_bytes(envelope)
                    if len(header) + entry_bytes > MAX_STRATEGY_ARCHIVE_BYTES:
                        raise ValueError("strategy archive exceeds its byte bound")
                    temporary_name = f".{STRATEGY_ARCHIVE_NAME}.tmp-{uuid4()}"
                    temporary_fd = os.open(
                        temporary_name, _create_flags(), 0o600, dir_fd=engagement_fd
                    )
                    try:
                        os.fchmod(temporary_fd, 0o600)
                        _write_all(temporary_fd, header)
                        stage_fd = _open_regular(
                            engagement_fd,
                            stage_name,
                            MAX_STRATEGY_ARCHIVE_BYTES,
                            "strategy archive staging file",
                        )
                        try:
                            while chunk := os.read(stage_fd, 65_536):
                                _write_all(temporary_fd, chunk)
                        finally:
                            os.close(stage_fd)
                        os.fsync(temporary_fd)
                    finally:
                        os.close(temporary_fd)
                    self._fault("strategy_archive_after_temp_fsync")
                    os.replace(
                        temporary_name,
                        STRATEGY_ARCHIVE_NAME,
                        src_dir_fd=engagement_fd,
                        dst_dir_fd=engagement_fd,
                    )
                    temporary_name = None
                    os.fsync(engagement_fd)
                    self._fault("strategy_archive_after_replace")
                    return StrategyArchiveCommitResult(envelope=envelope)
        finally:
            for name in (stage_name, temporary_name):
                if name is not None:
                    with suppress(FileNotFoundError):
                        os.unlink(name, dir_fd=engagement_fd)
            os.close(engagement_fd)

    def rollback_strategy_archive(
        self,
        engagement_id: UUID,
        *,
        failed_archive_revision: int,
        expected_journal_revision: JournalRevision,
        previous: StrategyArchivePage | None,
    ) -> None:
        """Compensate an archive-first planner transaction while both CAS guards still match."""
        del expected_journal_revision
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, _head, _journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                self._require_no_active_promotion(reduce_engagement(manifest, events))
                with _locked_file(engagement_fd, ".strategy-archive.lock"):
                    current = self._load_strategy_archive_locked(engagement_fd)
                    if (
                        current is None
                        or current.envelope.archive_revision != failed_archive_revision
                    ):
                        raise RevisionConflictError("strategy archive rollback revision is stale")
                    if previous is None:
                        os.unlink(STRATEGY_ARCHIVE_NAME, dir_fd=engagement_fd)
                    else:
                        restored = _archive_header_bytes(previous.envelope) + b"".join(
                            _archive_record_bytes(record, previous.envelope.archive_revision)
                            for record in previous.records
                        )
                        _atomic_write(engagement_fd, STRATEGY_ARCHIVE_NAME, restored)
                    os.fsync(engagement_fd)
        finally:
            os.close(engagement_fd)

    def write_evidence(
        self,
        engagement_id: UUID,
        data: bytes,
        *,
        media_type: str,
        representation: str,
        capture_limitations: tuple[Any, ...] = (),
    ) -> EvidenceReference:
        """Capture one normalized byte payload with a durable crash intent."""
        from sedna.engagement.evidence import EvidenceStore

        self._require_open()
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, _head, _journal_bytes = self._load_authoritative_locked(
                    engagement_fd, engagement_id, allow_tail=False
                )
                self._require_no_active_promotion(reduce_engagement(manifest, events))
                store = EvidenceStore(
                    engagement_fd,
                    quota=self._evidence_quota,
                    fault=self._fault,
                )
                result = store.capture_with_intent(
                    data,
                    media_type=media_type,
                    representation=representation,
                    capture_limitations=capture_limitations,
                )
        finally:
            os.close(engagement_fd)
        return result.reference

    def read_evidence_slice(
        self,
        engagement_id: UUID,
        evidence_id: EvidenceId,
        *,
        offset: int,
        limit: int,
    ) -> EvidenceSlice:
        """Read one bounded verified slice from a referenced evidence sidecar."""
        from sedna.engagement.evidence import read_evidence_slice as _read_slice

        self._require_open()
        self._complete_tail_recovery(engagement_id)
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            return _read_slice(
                engagement_fd,
                evidence_id,
                offset=offset,
                limit=limit,
            )
        finally:
            os.close(engagement_fd)

    def inventory_orphan_evidence(
        self,
        engagement_id: UUID,
        *,
        after_name: str | None = None,
        limit: int = 256,
    ) -> OrphanEvidencePage:
        """Return a bounded page of sidecar objects unreferenced by the journal."""
        from sedna.engagement.evidence import EvidenceStore

        self._require_open()
        self._complete_tail_recovery(engagement_id)
        events = self.load_events(engagement_id)
        referenced: set[str] = set()
        for event in events:
            payload = event.payload
            kind = event.type.value
            if kind == "evidence_attached":
                referenced.add(payload.evidence.sha256)
            elif kind == "recovery_warning":
                evidence_id = payload.evidence_id
                if evidence_id and evidence_id.startswith("evidence-sha256-"):
                    referenced.add(evidence_id[len("evidence-sha256-") :])
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            store = EvidenceStore(engagement_fd, quota=self._evidence_quota)
            return store.inventory_orphans(
                referenced,
                after_name=after_name,
                limit=limit,
            )
        finally:
            os.close(engagement_fd)

    def bind_lane(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        *,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> BatchAppendResult:
        draft = JournalEventDraft(
            lane=lane,
            actor="host_agent",
            type="lane_bound",
            payload=LaneBoundPayload(lane=lane, binding_reason=reason),
            idempotency_key=f"lane-bind:{lane.stable_key}:{engagement_id}",
        )

        def attempt() -> BatchAppendResult:
            with _locked_file(self._engagements_fd, ".registry.lock"):
                self._assert_lane_available(lane, exclude=engagement_id)
                return self._append_batch(
                    engagement_id,
                    (draft,),
                    expected_revision=expected_revision,
                    defer_tail_recovery=True,
                )

        return self._retry_registry_tail_recovery(attempt)

    def append_lifecycle_batch(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        drafts: Sequence[JournalEventDraft],
        *,
        binding_reason: str,
        expected_revision: JournalRevision,
        allow_active_promotion: bool = False,
    ) -> BatchAppendResult:
        """Atomically derive an optional lane binding and append a lifecycle batch."""

        def attempt() -> BatchAppendResult:
            with _locked_file(self._engagements_fd, ".registry.lock"):
                self._assert_lane_available(lane, exclude=engagement_id)
                snapshot = self._load_snapshot_registry_locked(engagement_id)
                batch = tuple(drafts)
                if not any(binding.lane == lane for binding in snapshot.state.bound_lanes):
                    batch = (
                        JournalEventDraft(
                            lane=lane,
                            actor="host_agent",
                            type="lane_bound",
                            payload=LaneBoundPayload(lane=lane, binding_reason=binding_reason),
                            idempotency_key=f"lane-bind:{lane.stable_key}:{engagement_id}",
                        ),
                        *batch,
                    )
                return self._append_batch(
                    engagement_id,
                    batch,
                    expected_revision=expected_revision,
                    defer_tail_recovery=True,
                    allow_active_promotion=allow_active_promotion,
                )

        return self._retry_registry_tail_recovery(attempt)

    def unbind_lane(
        self,
        engagement_id: UUID,
        lane: ExecutionLaneKey,
        *,
        reason: str,
        expected_revision: JournalRevision | None = None,
    ) -> BatchAppendResult:
        draft = JournalEventDraft(
            lane=lane,
            actor="host_agent",
            type="lane_unbound",
            payload=LaneUnboundPayload(lane=lane, reason=reason),
            idempotency_key=f"lane-unbind:{lane.stable_key}:{engagement_id}",
        )

        def attempt() -> BatchAppendResult:
            with _locked_file(self._engagements_fd, ".registry.lock"):
                return self._append_batch(
                    engagement_id,
                    (draft,),
                    expected_revision=expected_revision,
                    defer_tail_recovery=True,
                )

        return self._retry_registry_tail_recovery(attempt)

    def _assert_lane_available(
        self, lane: ExecutionLaneKey | None, *, exclude: UUID | None
    ) -> None:
        if lane is None:
            raise ValueError("lane binding requires a lane")
        entries = self._bounded_engagement_entries()
        published = [name for name in entries if _is_uuid_name(name)]
        if len(published) > MAX_ENGAGEMENTS:
            raise JournalUnavailableError("engagement count exceeds its bound")
        for name in published:
            engagement_id = UUID(name)
            if engagement_id == exclude:
                continue
            snapshot = self._load_snapshot_registry_locked(engagement_id)
            if any(binding.lane == lane for binding in snapshot.state.bound_lanes):
                raise ValueError("execution lane is already bound to another engagement")

    def _load_authoritative_registry_locked(
        self,
        engagement_fd: int,
        engagement_id: UUID,
    ) -> tuple[EngagementManifest, tuple[JournalEvent, ...], JournalHead, bytes]:
        try:
            _read_bounded(
                engagement_fd,
                ".tail-recovery.json",
                MAX_TAIL_RECOVERY_INTENT_BYTES,
                "tail recovery intent",
            )
        except JournalUnavailableError as exc:
            if not _missing_file(exc):
                raise
        else:
            raise _RegistryTailRecoveryRequiredError(engagement_id)
        try:
            return self._load_authoritative_locked(engagement_fd, engagement_id, allow_tail=True)
        except _RecoverableTailError as recovery:
            raise _RegistryTailRecoveryRequiredError(engagement_id) from recovery

    def _load_snapshot_registry_locked(self, engagement_id: UUID):
        engagement_fd = self._engagement_fd(engagement_id)
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                manifest, events, head, _ = self._load_authoritative_registry_locked(
                    engagement_fd, engagement_id
                )
                state = reduce_engagement(manifest, events)
                expected = self._projection_bytes(head.revision, state)
                try:
                    actual = _read_bounded(
                        engagement_fd,
                        "engagement-state.json",
                        MAX_DERIVED_PROJECTION_BYTES,
                        "engagement state projection",
                    )
                except JournalUnavailableError as exc:
                    if not _recoverable_projection_read(exc):
                        raise
                    actual = b""
                if actual != expected:
                    _atomic_write(engagement_fd, "engagement-state.json", expected)
                return self._snapshot(manifest, events, state)
        finally:
            os.close(engagement_fd)

    @staticmethod
    def _drafts_match(events: Sequence[JournalEvent], drafts: Sequence[JournalEventDraft]) -> bool:
        if len(events) != len(drafts):
            return False
        for event, draft in zip(events, drafts, strict=True):
            if _draft_material(event) != draft.model_dump(mode="json", exclude={"event_id"}):
                return False
            if draft.event_id is not None and draft.event_id != event.event_id:
                return False
        return True

    def _resolve_existing_batch(
        self,
        events: tuple[JournalEvent, ...],
        drafts: tuple[JournalEventDraft, ...],
    ) -> tuple[JournalEvent, ...] | None:
        starts: set[int] = set()
        for draft in drafts:
            identifier = draft.idempotency_key
            matches = [
                index
                for index, event in enumerate(events)
                if (identifier is not None and event.idempotency_key == identifier)
                or (draft.event_id is not None and event.event_id == draft.event_id)
            ]
            for index in matches:
                event = events[index]
                expected = draft.model_dump(mode="json", exclude={"event_id"})
                if _draft_material(event) != expected or (
                    draft.event_id is not None and event.event_id != draft.event_id
                ):
                    if identifier is not None:
                        raise ValueError("idempotency key collision")
                    raise ValueError("event ID collision")
                starts.add(index)
        if not starts:
            return None
        for start in sorted(starts):
            candidate = events[start : start + len(drafts)]
            if len(candidate) == len(drafts) and self._drafts_match(candidate, drafts):
                return candidate
        raise ValueError("idempotent batch is not a consecutive exact match")

    def _materialize(
        self,
        engagement_id: UUID,
        existing: Sequence[JournalEvent],
        drafts: Sequence[JournalEventDraft],
    ) -> tuple[JournalEvent, ...]:
        created: list[JournalEvent] = []
        previous_hash = existing[-1].event_hash if existing else None
        for offset, draft in enumerate(drafts, start=1):
            event = JournalEvent(
                **draft.model_dump(exclude={"event_id"}),
                event_id=draft.event_id or self._uuid_factory(),
                sequence=len(existing) + offset,
                occurred_at=self._clock(),
                engagement_id=engagement_id,
                previous_hash=previous_hash,
                event_hash="0" * 64,
            )
            digest = canonical_event_hash(event)
            event = event.model_copy(update={"event_hash": digest})
            event = JournalEvent.model_validate(event.model_dump(mode="python"))
            created.append(event)
            previous_hash = digest
        return tuple(created)

    @staticmethod
    def _validate_journal_limits(events: Sequence[JournalEvent], data: bytes) -> None:
        if len(events) > MAX_JOURNAL_EVENTS:
            raise ValueError("journal event count exceeds its bound")
        if len(data) > MAX_JOURNAL_BYTES:
            raise ValueError("journal bytes exceed their bound")
        parsed_count = sum(1 for _ in _iter_journal_lines(data))
        if parsed_count != len(events):
            raise ValueError("journal event count does not match its lines")

    @staticmethod
    def _projection_bytes(revision: JournalRevision, state: BaseModel) -> bytes:
        data = _canonical_projection_envelope(
            {
                "authoritative_revision": revision.model_dump(mode="json"),
                "name": "engagement-state",
                "owner": "engagement",
                "state": state.model_dump(mode="json"),
            }
        )
        if len(data) > MAX_DERIVED_PROJECTION_BYTES:
            raise ValueError("engagement state projection exceeds its byte bound")
        return data

    @staticmethod
    def _snapshot(manifest, events, state):
        from sedna.engagement.events import EngagementSnapshot

        return EngagementSnapshot(
            engagement_id=manifest.engagement_id,
            revision=_revision(events),
            manifest=manifest,
            events=events,
            state=state,
        )

    def _load_authoritative_locked(
        self,
        engagement_fd: int,
        engagement_id: UUID,
        *,
        allow_tail: bool,
    ) -> tuple[EngagementManifest, tuple[JournalEvent, ...], JournalHead, bytes]:
        manifest_bytes = _read_bounded(
            engagement_fd, "engagement.json", MAX_MANIFEST_BYTES, "engagement manifest"
        )
        head_bytes = _read_bounded(
            engagement_fd, "journal-head.json", MAX_JOURNAL_HEAD_BYTES, "journal head"
        )
        journal_bytes = _read_bounded(
            engagement_fd,
            "events.jsonl",
            MAX_JOURNAL_BYTES + MAX_RECOVERABLE_TAIL_BYTES,
            "events.jsonl",
        )
        try:
            manifest = EngagementManifest.model_validate_json(manifest_bytes)
            head = JournalHead.model_validate_json(head_bytes)
        except Exception as exc:
            raise JournalUnavailableError("journal_corrupt: invalid manifest or head") from exc
        if head.engagement_id != engagement_id or manifest.engagement_id != engagement_id:
            raise JournalUnavailableError("journal_corrupt: engagement identity mismatch")
        prefix = journal_bytes[: head.journal_bytes]
        if len(prefix) != head.journal_bytes or sha256(prefix).hexdigest() != head.journal_sha256:
            raise JournalUnavailableError("journal_corrupt: journal disagrees with head")
        lines = tuple(_iter_journal_lines(prefix))
        try:
            events = tuple(JournalEvent.model_validate_json(line) for line in lines)
            state = reduce_engagement(manifest, events)
        except Exception as exc:
            raise JournalUnavailableError("journal_corrupt: invalid event chain") from exc
        if len(events) != head.event_count or _revision(events) != head.revision:
            raise JournalUnavailableError("journal_corrupt: head revision mismatch")
        tail = journal_bytes[head.journal_bytes :]
        if tail:
            if (
                allow_tail
                and len(tail) <= MAX_RECOVERABLE_TAIL_BYTES
                and not tail.endswith(b"\n")
                and b"\n" not in tail
            ):
                if not state.bound_lanes:
                    raise JournalUnavailableError(
                        "journal_corrupt: recovery evidence requires a retained lane"
                    )
                raise _RecoverableTailError(tail, head, state.bound_lanes[0].lane)
            raise JournalUnavailableError("journal_corrupt: journal is ahead of head")
        return manifest, events, head, prefix

    def _recover_pending_append(self, engagement_fd: int, engagement_id: UUID) -> None:
        try:
            raw = _read_bounded(
                engagement_fd,
                ".pending-append.json",
                MAX_PENDING_APPEND_BYTES,
                "pending append",
            )
        except JournalUnavailableError as exc:
            if _missing_file(exc):
                return
            raise
        try:
            value = json.loads(raw)
            base = JournalHead.model_validate(value["base_head"])
            target = JournalHead.model_validate(value["target_head"])
            lines = tuple(base64.b64decode(item, validate=True) for item in value["lines"])
        except Exception as exc:
            raise JournalUnavailableError("journal_corrupt: invalid pending append") from exc
        if base.engagement_id != engagement_id or target.engagement_id != engagement_id:
            raise JournalUnavailableError("journal_corrupt: pending append identity mismatch")
        journal = _read_bounded(engagement_fd, "events.jsonl", MAX_JOURNAL_BYTES, "events.jsonl")
        suffix = b"".join(lines)
        prefix = journal[: base.journal_bytes]
        if len(prefix) != base.journal_bytes or not prefix:
            raise JournalUnavailableError("journal_corrupt: pending append base missing")
        if sha256(prefix).hexdigest() != base.journal_sha256:
            raise JournalUnavailableError("journal_corrupt: pending append base mismatch")
        present = journal[base.journal_bytes :]
        if not suffix.startswith(present):
            raise JournalUnavailableError("journal_corrupt: pending append diverged")
        completed = prefix + suffix
        try:
            if any(not line.endswith(b"\n") for line in lines):
                raise ValueError("pending line is not complete")
            manifest = EngagementManifest.model_validate_json(
                _read_bounded(
                    engagement_fd,
                    "engagement.json",
                    MAX_MANIFEST_BYTES,
                    "engagement manifest",
                )
            )
            base_events = tuple(
                JournalEvent.model_validate_json(line) for line in _iter_journal_lines(prefix)
            )
            target_events = tuple(
                JournalEvent.model_validate_json(line) for line in _iter_journal_lines(completed)
            )
            if base != _head(engagement_id, base_events, prefix):
                raise ValueError("pending base head mismatch")
            if target != _head(engagement_id, target_events, completed):
                raise ValueError("pending target head mismatch")
            self._validate_journal_limits(target_events, completed)
            state = reduce_engagement(manifest, target_events)
            self._projection_bytes(target.revision, state)
        except Exception as exc:
            raise JournalUnavailableError(
                "journal_corrupt: pending append exceeds limits or is invalid"
            ) from exc
        try:
            current_head_bytes = _read_bounded(
                engagement_fd,
                "journal-head.json",
                MAX_JOURNAL_HEAD_BYTES,
                "journal head",
            )
        except JournalUnavailableError as exc:
            if not _missing_file(exc):
                raise
            # The exact sealed transaction is the sole authority for restoring a
            # missing/malformed commit anchor; no transaction means fail closed.
            current_head = target if present == suffix else base
        else:
            try:
                current_head = JournalHead.model_validate_json(current_head_bytes)
            except Exception:
                current_head = target if present == suffix else base
        if current_head not in {base, target}:
            raise JournalUnavailableError("journal_corrupt: pending append head mismatch")
        if current_head == target and present != suffix:
            raise JournalUnavailableError(
                "journal_corrupt: committed head is ahead of pending journal"
            )
        if present != suffix:
            fd = os.open(
                "events.jsonl",
                os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=engagement_fd,
            )
            try:
                _write_all(fd, suffix[len(present) :])
                os.fsync(fd)
            finally:
                os.close(fd)
        if (
            len(completed) != target.journal_bytes
            or sha256(completed).hexdigest() != target.journal_sha256
        ):
            raise JournalUnavailableError("journal_corrupt: pending target mismatch")
        _atomic_write(engagement_fd, "journal-head.json", _model_bytes(target))
        os.unlink(".pending-append.json", dir_fd=engagement_fd)
        os.fsync(engagement_fd)

    def _complete_tail_recovery(self, engagement_id: UUID) -> None:
        engagement_fd = self._engagement_fd(engagement_id)
        tail: bytes | None = None
        recorded_head: JournalHead | None = None
        recovery_lane: ExecutionLaneKey | None = None
        tail_digest: str | None = None
        tail_size: int | None = None
        journal_identity: tuple[int, int] | None = None
        full_file_size: int | None = None
        sealed_drafts: tuple[JournalEventDraft, JournalEventDraft] | None = None
        try:
            with _locked_file(engagement_fd, ".journal.lock"):
                self._recover_pending_append(engagement_fd, engagement_id)
                try:
                    raw_intent = _read_bounded(
                        engagement_fd,
                        ".tail-recovery.json",
                        MAX_TAIL_RECOVERY_INTENT_BYTES,
                        "tail recovery intent",
                    )
                except JournalUnavailableError as exc:
                    if not _missing_file(exc):
                        raise
                    raw_intent = None
                if raw_intent is not None:
                    try:
                        stored = json.loads(raw_intent)
                        if stored["engagement_id"] != str(engagement_id):
                            raise ValueError("identity mismatch")
                        recorded_head = JournalHead.model_validate(stored["head"])
                        tail_digest = str(stored["tail_sha256"])
                        tail_size = int(stored["tail_size"])
                        identity = stored["journal_identity"]
                        journal_identity = (int(identity[0]), int(identity[1]))
                        full_file_size = int(stored["full_file_size"])
                        if int(stored["last_valid_offset"]) != recorded_head.journal_bytes:
                            raise ValueError("valid offset mismatch")
                        if (
                            JournalRevision.model_validate(stored["valid_prefix_revision"])
                            != recorded_head.revision
                            or stored["valid_prefix_hash"] != recorded_head.revision.event_hash
                        ):
                            raise ValueError("valid prefix mismatch")
                        parsed_drafts = tuple(
                            JournalEventDraft.model_validate(item) for item in stored["drafts"]
                        )
                        if len(parsed_drafts) != 2:
                            raise ValueError("recovery pair mismatch")
                        sealed_drafts = (parsed_drafts[0], parsed_drafts[1])
                    except Exception as exc:
                        raise JournalUnavailableError(
                            "journal_corrupt: invalid tail recovery intent"
                        ) from exc
                try:
                    manifest, events, head, _ = self._load_authoritative_locked(
                        engagement_fd, engagement_id, allow_tail=True
                    )
                    state = reduce_engagement(manifest, events)
                    if raw_intent is None:
                        return
                    if not state.bound_lanes:
                        raise JournalUnavailableError(
                            "journal_corrupt: recovery evidence requires a retained lane"
                        )
                    recovery_lane = state.bound_lanes[0].lane
                except _RecoverableTailError as recovery:
                    tail = recovery.tail
                    head = recovery.head
                    recovery_lane = recovery.recovery_lane
                    digest = sha256(tail).hexdigest()
                    if raw_intent is None:
                        recorded_head = head
                        tail_digest = digest
                        tail_size = len(tail)
                        journal_fd = _open_regular(
                            engagement_fd,
                            "events.jsonl",
                            MAX_JOURNAL_BYTES + MAX_RECOVERABLE_TAIL_BYTES,
                            "events.jsonl",
                        )
                        try:
                            journal_stat = os.fstat(journal_fd)
                        finally:
                            os.close(journal_fd)
                        journal_identity = (journal_stat.st_dev, journal_stat.st_ino)
                        full_file_size = journal_stat.st_size
                        sealed_drafts = _tail_recovery_drafts(
                            engagement_id, recovery_lane, digest, len(tail)
                        )
                        intent = _canonical_json(
                            {
                                "engagement_id": str(engagement_id),
                                "head": head.model_dump(mode="json"),
                                "journal_identity": list(journal_identity),
                                "full_file_size": full_file_size,
                                "last_valid_offset": head.journal_bytes,
                                "valid_prefix_revision": head.revision.model_dump(mode="json"),
                                "valid_prefix_hash": head.revision.event_hash,
                                "tail_sha256": digest,
                                "tail_size": len(tail),
                                "drafts": [
                                    draft.model_dump(mode="json") for draft in sealed_drafts
                                ],
                            }
                        )
                        if len(intent) > MAX_TAIL_RECOVERY_INTENT_BYTES:
                            raise JournalUnavailableError(
                                "tail recovery intent exceeds its bound"
                            ) from recovery
                        self._fault("tail_before_intent")
                        _atomic_write(engagement_fd, ".tail-recovery.json", intent)
                        raw_intent = intent
                        self._fault("tail_after_intent")
                    elif (
                        recorded_head != head
                        or tail_digest != digest
                        or tail_size != len(tail)
                        or full_file_size != head.journal_bytes + len(tail)
                    ):
                        raise JournalUnavailableError(
                            "journal_corrupt: tail recovery intent mismatch"
                        ) from recovery
                if (
                    recovery_lane is not None
                    and tail_digest is not None
                    and tail_size is not None
                    and sealed_drafts
                    != _tail_recovery_drafts(engagement_id, recovery_lane, tail_digest, tail_size)
                ):
                    raise JournalUnavailableError(
                        "journal_corrupt: tail recovery drafts are not deterministic"
                    )
            if (
                recorded_head is None
                or tail_digest is None
                or tail_size is None
                or journal_identity is None
                or full_file_size is None
                or sealed_drafts is None
            ):
                raise JournalUnavailableError("journal_corrupt: incomplete tail recovery state")
            evidence_store = _EvidenceObjectStore(engagement_fd, fault=self._fault)
            if tail is None:
                tail = evidence_store.load(tail_digest, tail_size)
            reference = evidence_store.capture(tail)
            self._fault("tail_after_evidence")
            drafts = sealed_drafts
            expected_reference = drafts[0].payload.evidence
            if reference != expected_reference:
                raise JournalUnavailableError(
                    "journal_corrupt: tail evidence disagrees with sealed draft"
                )
            self._fault("tail_before_second_lock")
            with _locked_file(engagement_fd, ".journal.lock"):
                try:
                    current_intent = _read_bounded(
                        engagement_fd,
                        ".tail-recovery.json",
                        MAX_TAIL_RECOVERY_INTENT_BYTES,
                        "tail recovery intent",
                    )
                except JournalUnavailableError as exc:
                    if not _missing_file(exc):
                        raise
                    manifest, events, _, _ = self._load_authoritative_locked(
                        engagement_fd, engagement_id, allow_tail=False
                    )
                    reduce_engagement(manifest, events)
                    if self._resolve_existing_batch(events, drafts) is None:
                        raise JournalUnavailableError(
                            "journal_corrupt: cleared tail intent lacks committed pair"
                        ) from exc
                    return
                if raw_intent is None or current_intent != raw_intent:
                    raise JournalUnavailableError("journal_corrupt: tail recovery intent changed")
                journal_fd = _open_regular(
                    engagement_fd,
                    "events.jsonl",
                    MAX_JOURNAL_BYTES + MAX_RECOVERABLE_TAIL_BYTES,
                    "events.jsonl",
                )
                try:
                    journal_stat = os.fstat(journal_fd)
                finally:
                    os.close(journal_fd)
                if (journal_stat.st_dev, journal_stat.st_ino) != journal_identity:
                    raise JournalUnavailableError(
                        "journal_corrupt: tail recovery descriptor identity changed"
                    )
                journal = _read_bounded(
                    engagement_fd,
                    "events.jsonl",
                    MAX_JOURNAL_BYTES + MAX_RECOVERABLE_TAIL_BYTES,
                    "events.jsonl",
                )
                if journal[recorded_head.journal_bytes :] == tail:
                    if len(journal) != full_file_size:
                        raise JournalUnavailableError(
                            "journal_corrupt: tail recovery file size changed"
                        )
                    manifest, events, base_head, prefix = self._load_prefix_with_tail(
                        engagement_fd, engagement_id, tail
                    )
                    journal_fd = os.open(
                        "events.jsonl",
                        os.O_WRONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=engagement_fd,
                    )
                    try:
                        _validate_regular(
                            journal_fd,
                            label="events.jsonl",
                            expected_mode=0o600,
                        )
                        os.ftruncate(journal_fd, base_head.journal_bytes)
                        os.fsync(journal_fd)
                    finally:
                        os.close(journal_fd)
                    self._fault("tail_after_truncate")
                else:
                    manifest, events, base_head, prefix = self._load_authoritative_locked(
                        engagement_fd, engagement_id, allow_tail=False
                    )
                    committed = self._resolve_existing_batch(events, drafts)
                    if committed is not None:
                        os.unlink(".tail-recovery.json", dir_fd=engagement_fd)
                        os.fsync(engagement_fd)
                        return
                    if base_head != recorded_head:
                        raise JournalUnavailableError(
                            "journal_corrupt: tail recovery revision changed"
                        )
                self._append_locked(
                    engagement_fd,
                    manifest,
                    events,
                    base_head,
                    prefix,
                    drafts,
                )
                os.unlink(".tail-recovery.json", dir_fd=engagement_fd)
                os.fsync(engagement_fd)
                self._fault("tail_after_intent_clear")
        finally:
            os.close(engagement_fd)

    def _load_prefix_with_tail(
        self, engagement_fd: int, engagement_id: UUID, expected_tail: bytes
    ) -> tuple[EngagementManifest, tuple[JournalEvent, ...], JournalHead, bytes]:
        journal = _read_bounded(
            engagement_fd,
            "events.jsonl",
            MAX_JOURNAL_BYTES + MAX_RECOVERABLE_TAIL_BYTES,
            "events.jsonl",
        )
        head = JournalHead.model_validate_json(
            _read_bounded(
                engagement_fd, "journal-head.json", MAX_JOURNAL_HEAD_BYTES, "journal head"
            )
        )
        if journal[head.journal_bytes :] != expected_tail:
            raise JournalUnavailableError("journal_corrupt: tail changed during recovery")
        prefix = journal[: head.journal_bytes]
        manifest = EngagementManifest.model_validate_json(
            _read_bounded(
                engagement_fd, "engagement.json", MAX_MANIFEST_BYTES, "engagement manifest"
            )
        )
        events = tuple(
            JournalEvent.model_validate_json(line) for line in _iter_journal_lines(prefix)
        )
        reduce_engagement(manifest, events)
        if head != _head(engagement_id, events, prefix):
            raise JournalUnavailableError("journal_corrupt: tail recovery head mismatch")
        return manifest, events, head, prefix


def _is_uuid_name(value: str) -> bool:
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _is_capture_intent_name(value: str) -> bool:
    prefix = ".capture-"
    if not value.startswith(prefix) or not value.endswith(".json"):
        return False
    identifier = value[len(prefix) : -len(".json")]
    return _is_uuid_name(identifier)


def _is_quarantine_payload_name(value: str) -> bool:
    prefix = ".quarantine-"
    if not value.startswith(prefix) or not value.endswith(".bin"):
        return False
    identifier = value[len(prefix) : -len(".bin")]
    return _is_uuid_name(identifier)


def _is_logbook_temp_name(value: str) -> bool:
    prefix = ".logbook-"
    if not value.startswith(prefix) or not value.endswith(".tmp"):
        return False
    identifier = value[len(prefix) : -len(".tmp")]
    return _is_uuid_name(identifier)


def _is_logbook_canonical_name(value: str) -> bool:
    # YYYYMMDD-HHMMSSffffff-<slug>-<session-digest>.md
    match = re.fullmatch(
        r"[0-9]{8}-[0-9]{12}-[a-z0-9-]+-[0-9a-f]{64}\.md",
        value,
    )
    return match is not None


def _pending_create_id(value: str) -> UUID | None:
    prefix = ".pending-create-"
    if not value.startswith(prefix):
        return None
    identifier = value[len(prefix) :]
    if not _is_uuid_name(identifier):
        return None
    return UUID(identifier)


def _missing_file(exc: JournalUnavailableError) -> bool:
    cause = exc.__cause__
    return isinstance(cause, OSError) and cause.errno == errno.ENOENT


def _recoverable_projection_read(exc: JournalUnavailableError) -> bool:
    return _missing_file(exc) or "exceeds its byte bound" in str(exc)


__all__ = [
    "AppendResult",
    "BatchAppendResult",
    "EngagementJournalRepository",
    "JournalHead",
    "JournalUnavailableError",
    "ProjectionOwnershipError",
    "RevisionConflictError",
]
