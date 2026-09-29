"""Public content-addressed evidence persistence built on the repository primitive."""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import suppress
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from sedna.engagement.models import (
    MAX_CAPTURE_INTENT_BYTES,
    MAX_EVIDENCE_DIRECTORY_ENTRIES,
    MAX_EVIDENCE_ENGAGEMENT_BYTES,
    MAX_EVIDENCE_ITEM_BYTES,
    MAX_EVIDENCE_OBJECTS,
    EvidenceId,
    EvidenceReference,
    EvidenceSlice,
    OrphanEvidencePage,
)
from sedna.engagement.repository import (
    JournalUnavailableError,
    _canonical_json,
    _EvidenceObjectStore,
    _locked_file,
    _open_or_create_directory,
    _read_bounded,
    _scan_directory_bounded,
)

EVIDENCE_ID_PATTERN = re.compile(r"^evidence-sha256-[0-9a-f]{64}$")
CAPTURE_INTENT_PREFIX = ".capture-"
QUARANTINE_PREFIX = ".quarantine-"
MAX_EVIDENCE_READ_LIMIT = 65_536


class EvidenceQuota(BaseModel):
    """Injected bounded evidence quotas; production defaults match the M6A contract."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    max_item_bytes: StrictInt = Field(ge=1, le=MAX_EVIDENCE_ITEM_BYTES)
    max_engagement_bytes: StrictInt = Field(ge=1, le=MAX_EVIDENCE_ENGAGEMENT_BYTES)


DEFAULT_EVIDENCE_QUOTA = EvidenceQuota(
    max_item_bytes=MAX_EVIDENCE_ITEM_BYTES,
    max_engagement_bytes=MAX_EVIDENCE_ENGAGEMENT_BYTES,
)


class EvidenceCaptureError(ValueError):
    """A typed capture failure that retains only safe observed metadata."""

    def __init__(
        self,
        reason_code: str,
        *,
        observed_size: int | None = None,
        observed_sha256: str | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.observed_size = observed_size
        self.observed_sha256 = observed_sha256
        super().__init__(reason_code)


class EvidenceCapture(BaseModel):
    """One public capture result with the exact persisted bytes."""

    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    reference: EvidenceReference
    persisted_bytes: bytes


def _is_capture_intent_name(name: str) -> bool:
    if not name.startswith(CAPTURE_INTENT_PREFIX) or not name.endswith(".json"):
        return False
    identifier = name[len(CAPTURE_INTENT_PREFIX) : -len(".json")]
    try:
        return str(UUID(identifier)) == identifier
    except ValueError:
        return False


def _is_quarantine_payload_name(name: str) -> bool:
    if not name.startswith(QUARANTINE_PREFIX) or not name.endswith(".bin"):
        return False
    identifier = name[len(QUARANTINE_PREFIX) : -len(".bin")]
    try:
        return str(UUID(identifier)) == identifier
    except ValueError:
        return False


def _digest_name(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))


class EvidenceStore:
    """Content-addressed evidence store with bounded capture intents and quarantine.

    Storage and locking delegate to the private ``_EvidenceObjectStore`` primitive;
    this layer adds host-facing capture intents, quarantine, and orphan enumeration
    without duplicating descriptor/lock logic.
    """

    def __init__(
        self,
        engagement_fd: int,
        *,
        quota: EvidenceQuota = DEFAULT_EVIDENCE_QUOTA,
        fault: Any = None,
    ) -> None:
        self._engagement_fd = engagement_fd
        self._quota = quota
        self._fault = fault or (lambda _point: None)
        self._primitive = _EvidenceObjectStore(
            engagement_fd,
            fault=self._fault,
            max_item_bytes=quota.max_item_bytes,
            max_objects=MAX_EVIDENCE_OBJECTS,
            max_engagement_bytes=quota.max_engagement_bytes,
        )

    def _recover_capture_intents(self, evidence_fd: int) -> None:
        """Finish or quarantine every bounded capture intent under the evidence lock."""
        entries = _scan_directory_bounded(
            evidence_fd, MAX_EVIDENCE_DIRECTORY_ENTRIES, "evidence directory"
        )
        for entry in sorted(entries):
            if not _is_capture_intent_name(entry):
                continue
            try:
                raw = _read_bounded(evidence_fd, entry, MAX_CAPTURE_INTENT_BYTES, "capture intent")
                value = json.loads(raw)
                if _canonical_json(value) != raw:
                    raise ValueError("intent is not canonical")
                digest = value["digest"]
                size = int(value["size"])
                target = value["target"]
                temp = value["temp"]
                if not _digest_name(digest):
                    raise ValueError("invalid digest")
                if target != f"blob-{digest}.bin":
                    raise ValueError("invalid target")
                if temp != f".pending-blob-{digest}.bin":
                    raise ValueError("invalid temp")
            except Exception:
                quarantine = f"{QUARANTINE_PREFIX}{uuid4()}.json"
                os.rename(entry, quarantine, src_dir_fd=evidence_fd, dst_dir_fd=evidence_fd)
                os.fsync(evidence_fd)
                continue
            try:
                temp_stat = os.stat(temp, dir_fd=evidence_fd, follow_symlinks=False)
            except FileNotFoundError:
                os.unlink(entry, dir_fd=evidence_fd)
                os.fsync(evidence_fd)
                continue
            if not stat.S_ISREG(temp_stat.st_mode) or stat.S_IMODE(temp_stat.st_mode) != 0o600:
                raise JournalUnavailableError("unsafe capture temp")
            temp_bytes = _read_bounded(
                evidence_fd, temp, self._quota.max_item_bytes, "capture temp"
            )
            if sha256(temp_bytes).hexdigest() == digest and len(temp_bytes) == size:
                try:
                    os.link(
                        temp,
                        target,
                        src_dir_fd=evidence_fd,
                        dst_dir_fd=evidence_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    found = _read_bounded(
                        evidence_fd, target, self._quota.max_item_bytes, "evidence object"
                    )
                    if found != temp_bytes:
                        raise JournalUnavailableError("evidence digest collision") from None
                os.fsync(evidence_fd)
                os.unlink(temp, dir_fd=evidence_fd)
                os.fsync(evidence_fd)
            else:
                quarantine_id = uuid4()
                os.rename(
                    temp,
                    f"{QUARANTINE_PREFIX}{quarantine_id}.bin",
                    src_dir_fd=evidence_fd,
                    dst_dir_fd=evidence_fd,
                )
                os.rename(
                    entry,
                    f"{QUARANTINE_PREFIX}{quarantine_id}.json",
                    src_dir_fd=evidence_fd,
                    dst_dir_fd=evidence_fd,
                )
                os.fsync(evidence_fd)
                continue
            os.unlink(entry, dir_fd=evidence_fd)
            os.fsync(evidence_fd)

    def capture(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        representation: str = "host_bytes",
        capture_limitations: tuple[Any, ...] = (),
    ) -> EvidenceReference:
        """Persist one already-normalized byte payload and return its reference."""
        if not isinstance(data, bytes):
            raise TypeError("evidence store accepts normalized bytes only")
        digest = sha256(data).hexdigest()
        if len(data) > self._quota.max_item_bytes:
            raise EvidenceCaptureError(
                "item_quota_exceeded",
                observed_size=len(data),
                observed_sha256=digest,
            )
        try:
            self._primitive.capture(data)
        except ValueError as exc:
            raise _translate_primitive_quota_error(exc, len(data), digest) from None
        return EvidenceReference(
            evidence_id=f"evidence-sha256-{digest}",
            sha256=digest,
            size=len(data),
            media_type=media_type,
            representation=representation,
            relative_path=f"evidence/blob-{digest}.bin",
            capture_limitations=tuple(capture_limitations),
        )

    def capture_with_intent(
        self,
        data: bytes,
        *,
        media_type: str = "application/octet-stream",
        representation: str = "host_bytes",
        capture_limitations: tuple[Any, ...] = (),
    ) -> EvidenceCapture:
        """Capture with a durable intent so a crash can recover or quarantine."""
        if not isinstance(data, bytes):
            raise TypeError("evidence store accepts normalized bytes only")
        digest = sha256(data).hexdigest()
        if len(data) > self._quota.max_item_bytes:
            raise EvidenceCaptureError(
                "item_quota_exceeded",
                observed_size=len(data),
                observed_sha256=digest,
            )
        target = f"blob-{digest}.bin"
        temp = f".pending-blob-{digest}.bin"
        intent_name = self._seal_capture_intent(digest, len(data), target, temp)
        try:
            self._primitive.capture(data)
        except ValueError as exc:
            raise _translate_primitive_quota_error(exc, len(data), digest) from None
        self._clear_capture_intent(intent_name)
        return EvidenceCapture(
            reference=EvidenceReference(
                evidence_id=f"evidence-sha256-{digest}",
                sha256=digest,
                size=len(data),
                media_type=media_type,
                representation=representation,
                relative_path=f"evidence/{target}",
                capture_limitations=tuple(capture_limitations),
            ),
            persisted_bytes=data,
        )

    def _seal_capture_intent(self, digest: str, size: int, target: str, temp: str) -> str:
        """Write and fsync one bounded capture intent while holding the evidence lock."""
        intent = _canonical_json(
            {
                "digest": digest,
                "size": size,
                "target": target,
                "temp": temp,
            }
        )
        if len(intent) > MAX_CAPTURE_INTENT_BYTES:
            raise ValueError("capture intent exceeds its byte bound")
        intent_name = f"{CAPTURE_INTENT_PREFIX}{uuid4()}.json"
        with _locked_file(self._engagement_fd, ".evidence.lock"):
            evidence_fd = _open_or_create_directory(self._engagement_fd, "evidence", 0o700)
            try:
                self._recover_capture_intents(evidence_fd)
                _write_intent_file(evidence_fd, intent_name, intent)
            finally:
                os.close(evidence_fd)
        self._fault("evidence_after_intent")
        return intent_name

    def _clear_capture_intent(self, intent_name: str) -> None:
        """Remove a completed capture intent only after canonical publication is durable."""
        with _locked_file(self._engagement_fd, ".evidence.lock"):
            evidence_fd = _open_or_create_directory(self._engagement_fd, "evidence", 0o700)
            try:
                with suppress(FileNotFoundError):
                    os.unlink(intent_name, dir_fd=evidence_fd)
                os.fsync(evidence_fd)
            finally:
                os.close(evidence_fd)

    def load(self, digest: str, size: int) -> bytes:
        return self._primitive.load(digest, size)

    def inventory_orphans(
        self,
        referenced: set[str],
        *,
        after_name: str | None = None,
        limit: int = 256,
    ) -> OrphanEvidencePage:
        """Return a bounded page of canonical objects not referenced by the journal."""
        if not 1 <= limit <= 256:
            raise ValueError("orphan inventory limit must be within 1..256")
        with _locked_file(self._engagement_fd, ".evidence.lock"):
            evidence_fd = _open_or_create_directory(self._engagement_fd, "evidence", 0o700)
            try:
                entries = _scan_directory_bounded(
                    evidence_fd, MAX_EVIDENCE_DIRECTORY_ENTRIES, "evidence directory"
                )
                names = sorted(
                    entry
                    for entry in entries
                    if entry.startswith("blob-") and entry.endswith(".bin")
                )
            finally:
                os.close(evidence_fd)
        orphans = [name for name in names if name[len("blob-") : -len(".bin")] not in referenced]
        total = len(orphans)
        if after_name is not None:
            orphans = [name for name in orphans if name > after_name]
        page_names = tuple(orphans[:limit])
        next_after = page_names[-1] if len(orphans) > limit else None
        return OrphanEvidencePage(
            names=page_names,
            total_count=total,
            next_after_name=next_after,
            summary=_orphan_summary(orphans[limit:]),
        )


def _orphan_summary(undisplayed: list[str]) -> tuple[tuple[str, int], ...]:
    counts: dict[str, int] = {}
    for name in undisplayed:
        digest = name[len("blob-") : -len(".bin")]
        counts[digest] = counts.get(digest, 0) + 1
    return tuple(sorted(counts.items()))


def _translate_primitive_quota_error(
    exc: ValueError, size: int, digest: str
) -> EvidenceCaptureError:
    if isinstance(exc, JournalUnavailableError):
        raise exc
    message = str(exc)
    if "evidence item quota exceeded" in message:
        return EvidenceCaptureError(
            "item_quota_exceeded", observed_size=size, observed_sha256=digest
        )
    if "evidence object quota exceeded" in message:
        return EvidenceCaptureError(
            "evidence_object_limit_exceeded", observed_size=size, observed_sha256=digest
        )
    if "evidence engagement quota exceeded" in message:
        return EvidenceCaptureError(
            "engagement_quota_exceeded", observed_size=size, observed_sha256=digest
        )
    return EvidenceCaptureError(
        "external_artifact_unavailable", observed_size=size, observed_sha256=digest
    )


def _write_intent_file(evidence_fd: int, name: str, data: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=evidence_fd,
    )
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short descriptor write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(evidence_fd)


def read_evidence_slice(
    engagement_fd: int,
    evidence_id: EvidenceId,
    *,
    offset: int,
    limit: int,
) -> EvidenceSlice:
    """Read one bounded byte slice, verifying the content-addressed sidecar."""
    if offset < 0:
        raise ValueError("evidence slice offset must be non-negative")
    if not 1 <= limit <= MAX_EVIDENCE_READ_LIMIT:
        raise ValueError("evidence slice limit must be within 1..65536")
    if not EVIDENCE_ID_PATTERN.fullmatch(evidence_id):
        raise ValueError("invalid evidence id")
    digest = evidence_id[len("evidence-sha256-") :]
    with _locked_file(engagement_fd, ".evidence.lock"):
        evidence_fd = _open_or_create_directory(engagement_fd, "evidence", 0o700)
        try:
            data = _read_bounded(
                evidence_fd,
                f"blob-{digest}.bin",
                MAX_EVIDENCE_ITEM_BYTES,
                "evidence object",
            )
        finally:
            os.close(evidence_fd)
    if sha256(data).hexdigest() != digest:
        raise JournalUnavailableError("evidence object does not match its reference")
    return EvidenceSlice(
        evidence_id=evidence_id,
        offset=offset,
        data=data[offset : offset + limit],
        complete=offset + limit >= len(data),
    )
