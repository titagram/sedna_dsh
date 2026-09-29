"""Shared ``sources.md`` registry with preserved manual content."""

from __future__ import annotations

import html
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from errno import ELOOP, ENOTDIR
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator

from sedna.engagement.models import Sha256Hex
from sedna.engagement.normalization import SOURCE_SECRET_KEYS
from sedna.engagement.repository import (
    _canonical_json,
    _locked_file,
)

SOURCE_REGISTRY_SCHEMA_VERSION = "sedna.sources.v1"
MAX_SOURCE_REGISTRY_BYTES = 1024 * 1024
MAX_SOURCE_REGISTRY_ENTRIES = 4096

SOURCE_MARKER_PREFIX = "<!-- sedna-source:"
_BEGIN_RE = re.compile(r"^<!-- sedna-source:v1 begin (source-[0-9a-f]{64}) -->$")
_END_RE = re.compile(r"^<!-- sedna-source:v1 end (source-[0-9a-f]{64}) -->$")
_CONTROL_TEXT = re.compile(r"^[^\x00-\x1f\x7f]*$")


class SourceRegistryLimitError(ValueError):
    """A registry byte or entry limit was exceeded before any mutation."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class SourceRegistryConflict(ValueError):  # noqa: N818 - authoritative M6A plan name
    """An external edit was detected between registry read and replace."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SourceOrigin(StrEnum):
    USER_SUGGESTED = "user_suggested"
    BUILT_IN = "built_in"
    DISCOVERED = "discovered"


class SourceStatus(StrEnum):
    SUGGESTED = "suggested"
    CONSULTED = "consulted"
    USEFUL = "useful"
    CONTRADICTED = "contradicted"
    STALE = "stale"
    PREFERRED = "preferred"


def _normalize_locator(locator: str) -> str:
    normalized = " ".join(locator.split())
    if not normalized:
        raise ValueError("locator is required")
    parsed = urlsplit(normalized)
    if parsed.scheme.casefold() in {"http", "https"}:
        if parsed.username or parsed.password:
            raise ValueError("locator must not contain URL userinfo")
        netloc = parsed.netloc.casefold()
        normalized = parsed._replace(netloc=netloc).geturl()
        secret_keys = {key.casefold() for key in SOURCE_SECRET_KEYS}
        if _query_keys(parsed.query) & secret_keys:
            raise ValueError("locator contains a secret query or fragment key")
        if _query_keys(parsed.fragment) & secret_keys:
            raise ValueError("locator contains a secret query or fragment key")
    return normalized


def _query_keys(value: str) -> set[str]:
    keys: set[str] = set()
    for item in value.split("&"):
        if not item:
            continue
        keys.add(item.split("=", 1)[0].casefold())
    return keys


def _validate_user_field(value: str, *, field: str) -> str:
    if "\x00" in value or not _CONTROL_TEXT.fullmatch(value):
        raise ValueError(f"{field} contains unsafe control characters")
    if SOURCE_MARKER_PREFIX in value:
        raise ValueError(f"{field} contains a managed source marker")
    lowered = value.casefold()
    if "bearer " in lowered or "basic " in lowered:
        raise ValueError(f"{field} contains a credential prefix")
    return value


class SharedSourceEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    schema_version: str = SOURCE_REGISTRY_SCHEMA_VERSION
    source_id: str = Field(pattern=r"^source-[0-9a-f]{64}$")
    name: str = Field(min_length=1, max_length=256)
    locator: str = Field(min_length=1, max_length=4096)
    topics: tuple[str, ...] = Field(default=(), max_length=64)
    origin: SourceOrigin
    status: SourceStatus
    notes: str = Field(default="", max_length=8192)
    last_observed_on: date | None = None

    @classmethod
    def suggested(
        cls,
        *,
        name: str,
        locator: str,
        topics: tuple[str, ...] = (),
        notes: str = "",
    ) -> SharedSourceEntry:
        return cls(
            source_id=_source_id(locator),
            name=name,
            locator=locator,
            topics=topics,
            origin=SourceOrigin.USER_SUGGESTED,
            status=SourceStatus.SUGGESTED,
            notes=notes,
        )

    @field_validator("name", "locator", "notes")
    @classmethod
    def _safe_text(cls, value: str, info: Any) -> str:
        field = info.field_name or "field"
        return _validate_user_field(value, field=field)

    @field_validator("locator", mode="before")
    @classmethod
    def _normalize_locator_before(cls, value: Any) -> Any:
        if isinstance(value, str):
            return _normalize_locator(value)
        return value

    @field_validator("topics")
    @classmethod
    def _safe_topics(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        seen: set[str] = set()
        for topic in value:
            cleaned = _validate_user_field(topic, field="topic")
            folded = cleaned.casefold()
            if folded in seen:
                continue
            seen.add(folded)
            normalized.append(cleaned)
        return tuple(normalized)

    @model_validator(mode="after")
    def validate_entry(self) -> SharedSourceEntry:
        if self.source_id != _source_id(self.locator):
            raise ValueError("source_id does not match the normalized locator")
        if self.schema_version != SOURCE_REGISTRY_SCHEMA_VERSION:
            raise ValueError("source schema version is not supported")
        return self


def _source_id(locator: str) -> str:
    normalized = _normalize_locator(locator)
    digest = sha256(normalized.encode("utf-8")).hexdigest()
    return f"source-{digest}"


class SourceRegistrySnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    content_sha256: Sha256Hex
    byte_size: StrictInt = Field(ge=0, le=MAX_SOURCE_REGISTRY_BYTES)
    entries: tuple[SharedSourceEntry, ...] = Field(max_length=MAX_SOURCE_REGISTRY_ENTRIES)


class PlannerSourceSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    registry_sha256: Sha256Hex
    total_count: int = Field(ge=0, le=MAX_SOURCE_REGISTRY_ENTRIES)
    entries: tuple[SharedSourceEntry, ...] = Field(max_length=128)
    truncated: bool
    omitted_entries_sha256: Sha256Hex | None = None
    canonical_bytes: int = Field(ge=0, le=64 * 1024)


class PlannerSourceHintPage(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")

    registry_sha256: Sha256Hex
    total_count: int = Field(ge=0, le=MAX_SOURCE_REGISTRY_ENTRIES)
    entries: tuple[SharedSourceEntry, ...] = Field(max_length=16)
    truncated: bool
    omitted_entries_sha256: Sha256Hex | None = None
    canonical_bytes: int = Field(ge=0, le=16 * 1024)


@dataclass(frozen=True)
class SourceRegistryResult:
    entry: SharedSourceEntry
    changed: bool


class SharedSourceRegistry:
    """Bounded atomic registry of shared sources with preserved manual bytes."""

    def __init__(self, repository: Any) -> None:
        self._root_fd = repository._root_fd
        self._knowledge_root = repository._knowledge_root

    def _read_current(self) -> bytes:
        try:
            fd = os.open(
                "sources.md",
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._root_fd,
            )
        except FileNotFoundError:
            return b""
        except OSError as exc:
            if exc.errno in {ELOOP, ENOTDIR}:
                raise ValueError("source registry is an unsafe file") from exc
            raise SourceRegistryLimitError("byte_limit_exceeded") from exc
        try:
            result = os.fstat(fd)
            if not stat.S_ISREG(result.st_mode):
                raise SourceRegistryLimitError("byte_limit_exceeded")
            if result.st_size > MAX_SOURCE_REGISTRY_BYTES:
                raise SourceRegistryLimitError("byte_limit_exceeded")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, min(65_536, MAX_SOURCE_REGISTRY_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_SOURCE_REGISTRY_BYTES:
                    raise SourceRegistryLimitError("byte_limit_exceeded")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _parse(self, data: bytes) -> tuple[dict[str, SharedSourceEntry], list[bytes]]:
        if len(data) > MAX_SOURCE_REGISTRY_BYTES:
            raise SourceRegistryLimitError("byte_limit_exceeded")
        text = data.decode("utf-8", errors="strict")
        lines = text.splitlines(keepends=True)
        entries: dict[str, SharedSourceEntry] = {}
        preserved: list[bytes] = []
        index = 0
        while index < len(lines):
            line = lines[index]
            begin = _BEGIN_RE.fullmatch(line.strip("\n"))
            if begin is None:
                if SOURCE_MARKER_PREFIX in line:
                    raise ValueError("invalid managed source block")
                preserved.append(line.encode("utf-8"))
                index += 1
                continue
            source_id = begin.group(1)
            block: list[str] = []
            index += 1
            closed = False
            while index < len(lines):
                current = lines[index]
                end = _END_RE.fullmatch(current.strip("\n"))
                if end is not None:
                    if end.group(1) != source_id:
                        raise ValueError("invalid managed source block")
                    closed = True
                    index += 1
                    break
                block.append(current)
                index += 1
            if not closed:
                raise ValueError("invalid managed source block")
            entry = _decode_block(block, source_id)
            if entry.source_id in entries:
                raise ValueError("invalid managed source block")
            entries[entry.source_id] = entry
        if len(entries) > MAX_SOURCE_REGISTRY_ENTRIES:
            raise SourceRegistryLimitError("entry_limit_exceeded")
        return entries, preserved

    def snapshot(self) -> SourceRegistrySnapshot:
        with _locked_file(self._root_fd, ".sources.lock"):
            data = self._read_current()
            entries, _ = self._parse(data)
        digest = sha256(data).hexdigest()
        return SourceRegistrySnapshot(
            content_sha256=digest,
            byte_size=len(data),
            entries=tuple(sorted(entries.values(), key=lambda item: item.source_id)),
        )

    def list_entries(self) -> tuple[SharedSourceEntry, ...]:
        return self.snapshot().entries

    def planner_snapshot(self) -> PlannerSourceSnapshot:
        with _locked_file(self._root_fd, ".sources.lock"):
            data = self._read_current()
            entries, preserved = self._parse(data)
        ordered = tuple(sorted(entries.values(), key=lambda item: item.source_id))
        selected, canonical_bytes = _bounded_planner_entries(
            ordered, count_limit=128, byte_limit=64 * 1024
        )
        omitted = ordered[len(selected) :]
        return PlannerSourceSnapshot(
            registry_sha256=_planner_registry_digest(ordered, preserved),
            total_count=len(ordered),
            entries=selected,
            truncated=bool(omitted),
            omitted_entries_sha256=_entries_digest(omitted) if omitted else None,
            canonical_bytes=canonical_bytes,
        )

    def list_planner_hints(
        self,
        *,
        topic_tokens: tuple[str, ...] = (),
    ) -> PlannerSourceHintPage:
        tokens = tuple(
            sorted({" ".join(token.split()).casefold() for token in topic_tokens if token.split()})
        )
        if len(tokens) > 32 or sum(map(len, tokens)) > 4096:
            raise ValueError("planner topic tokens exceed the cumulative bound")
        with _locked_file(self._root_fd, ".sources.lock"):
            data = self._read_current()
            entries, preserved = self._parse(data)
        complete = tuple(sorted(entries.values(), key=lambda item: item.source_id))
        compatible = tuple(item for item in complete if _planner_topics_compatible(item, tokens))
        ranked = tuple(sorted(compatible, key=lambda item: _planner_hint_key(item, tokens)))
        selected, canonical_bytes = _bounded_planner_entries(
            ranked, count_limit=16, byte_limit=16 * 1024
        )
        selected_ids = {item.source_id for item in selected}
        omitted = tuple(item for item in complete if item.source_id not in selected_ids)
        return PlannerSourceHintPage(
            registry_sha256=_planner_registry_digest(complete, preserved),
            total_count=len(complete),
            entries=selected,
            truncated=bool(omitted),
            omitted_entries_sha256=_entries_digest(omitted) if omitted else None,
            canonical_bytes=canonical_bytes,
        )

    def add_or_update(self, entry: SharedSourceEntry) -> SourceRegistryResult:
        entry = SharedSourceEntry.model_validate(entry.model_dump(mode="python"))
        with _locked_file(self._root_fd, ".sources.lock"):
            data = self._read_current()
            entries, preserved = self._parse(data)
            if entry.source_id in entries and entries[entry.source_id] == entry:
                return SourceRegistryResult(entry=entry, changed=False)
            if len(entries) + 1 > MAX_SOURCE_REGISTRY_ENTRIES:
                raise SourceRegistryLimitError("entry_limit_exceeded")
            entries[entry.source_id] = entry
            content = self._render(entries, preserved)
            if len(content) > MAX_SOURCE_REGISTRY_BYTES:
                raise SourceRegistryLimitError("byte_limit_exceeded")
            self._replace_with_conflict_check(data, content, entry)
        return SourceRegistryResult(entry=entry, changed=True)

    def _replace_with_conflict_check(
        self,
        original: bytes,
        content: bytes,
        entry: SharedSourceEntry,
    ) -> None:
        current = self._read_current()
        if current != original:
            # An external edit landed between our read and replace: re-merge once
            # so the human bytes survive; never overwrite them blindly.
            entries, preserved = self._parse(current)
            if len(entries) + 1 > MAX_SOURCE_REGISTRY_ENTRIES:
                raise SourceRegistryConflict(code="source_registry_conflict")
            entries[entry.source_id] = entry
            content = self._render(entries, preserved)
            if len(content) > MAX_SOURCE_REGISTRY_BYTES:
                raise SourceRegistryLimitError("byte_limit_exceeded")
        _replace_registry(self._root_fd, content)

    def _render(
        self,
        entries: dict[str, SharedSourceEntry],
        preserved: list[bytes],
    ) -> bytes:
        chunks = list(preserved)
        for source_id in sorted(entries):
            chunks.append(_render_block(entries[source_id]).encode("utf-8"))
        return b"".join(chunks)


def _canonical_entry_bytes(entry: SharedSourceEntry) -> bytes:
    return _canonical_json(entry.model_dump(mode="json"))


def _entries_digest(entries: tuple[SharedSourceEntry, ...]) -> str:
    return sha256(b"\n".join(_canonical_entry_bytes(entry) for entry in entries)).hexdigest()


def _planner_registry_digest(entries: tuple[SharedSourceEntry, ...], preserved: list[bytes]) -> str:
    payload = {
        "entries_sha256": _entries_digest(entries),
        "manual_sha256": sha256(b"".join(preserved)).hexdigest(),
    }
    return sha256(_canonical_json(payload)).hexdigest()


def _bounded_planner_entries(
    entries: tuple[SharedSourceEntry, ...], *, count_limit: int, byte_limit: int
) -> tuple[tuple[SharedSourceEntry, ...], int]:
    selected: list[SharedSourceEntry] = []
    canonical_bytes = 2
    for entry in entries[:count_limit]:
        size = len(_canonical_entry_bytes(entry)) + (1 if selected else 0)
        if canonical_bytes + size > byte_limit:
            break
        selected.append(entry)
        canonical_bytes += size
    return tuple(selected), canonical_bytes


def _planner_hint_key(entry: SharedSourceEntry, tokens: tuple[str, ...]) -> tuple[int, int, str]:
    topics = {topic.casefold() for topic in entry.topics}
    matches = sum(token in topics for token in tokens)
    user_priority = entry.origin is SourceOrigin.USER_SUGGESTED
    return (-matches, -int(user_priority), entry.source_id)


def _planner_topics_compatible(entry: SharedSourceEntry, tokens: tuple[str, ...]) -> bool:
    topics = {topic.casefold() for topic in entry.topics}
    token_set = set(tokens)
    incompatible = {
        "linux": {"windows", "macos", "darwin", "freebsd"},
        "windows": {"linux", "macos", "darwin", "freebsd"},
        "x86_64": {"aarch64", "arm64", "i386", "armv7"},
        "aarch64": {"x86_64", "amd64", "i386", "armv7"},
    }
    return not any(topics & incompatible.get(token, set()) for token in token_set)


def _decode_block(block: list[str], source_id: str) -> SharedSourceEntry:
    json_lines = [
        line for line in block if line.strip().endswith("json") and line.lstrip().startswith("`")
    ]
    if len(json_lines) != 1:
        raise ValueError("invalid managed source block")
    opener = json_lines[0]
    tick_run = len(opener) - len(opener.lstrip("`"))
    if tick_run < 3:
        raise ValueError("invalid managed source block")
    closing = "`" * tick_run
    payload: list[str] = []
    after = block[block.index(opener) + 1 :]
    for line in after:
        stripped = line.rstrip("\n")
        if stripped == closing:
            break
        payload.append(line)
    raw = "".join(payload).strip()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid managed source block") from exc
    if _canonical_json(value) != raw.encode("utf-8"):
        raise ValueError("invalid managed source block")
    try:
        entry = SharedSourceEntry.model_validate(value)
    except Exception as exc:
        raise ValueError("invalid managed source block") from exc
    if entry.source_id != source_id:
        raise ValueError("invalid managed source block")
    return entry


def _render_block(entry: SharedSourceEntry) -> str:
    machine = json.dumps(
        entry.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    sections = [
        f"<!-- sedna-source:v1 begin {entry.source_id} -->",
        "### Source",
        "",
        "````text",
        f"Name: {html.escape(entry.name)}",
        f"Locator: {html.escape(entry.locator)}",
        f"Topics: {html.escape(', '.join(entry.topics))}",
        f"Origin: {entry.origin.value}",
        f"Status: {entry.status.value}",
        "````",
        "",
        "`````json",
        machine,
        "`````",
        f"<!-- sedna-source:v1 end {entry.source_id} -->",
        "",
    ]
    return "\n".join(sections)


def _replace_registry(root_fd: int, content: bytes) -> None:
    temporary = f".sources.md.tmp-{os.urandom(8).hex()}"
    fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        0o600,
        dir_fd=root_fd,
    )
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short descriptor write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(temporary, "sources.md", src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary, dir_fd=root_fd)
        raise


__all__ = [
    "MAX_SOURCE_REGISTRY_BYTES",
    "MAX_SOURCE_REGISTRY_ENTRIES",
    "SOURCE_REGISTRY_SCHEMA_VERSION",
    "SharedSourceEntry",
    "SharedSourceRegistry",
    "SourceOrigin",
    "SourceRegistryConflict",
    "SourceRegistryLimitError",
    "SourceRegistryResult",
    "SourceRegistrySnapshot",
    "SourceStatus",
]
