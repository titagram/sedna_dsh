"""Reproducible session logbook rendering and crash-safe projection publication."""

from __future__ import annotations

import html
import os
import re
from collections.abc import Sequence
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote
from uuid import UUID, uuid4

from sedna.engagement.events import JournalEvent
from sedna.engagement.models import (
    EngagementManifest,
    EngagementState,
    EvidenceReference,
)
from sedna.engagement.repository import (
    JournalUnavailableError,
    _locked_file,
    _open_or_create_directory,
)

MAX_LOGBOOK_INLINE_ITEM_BYTES = 64 * 1024
MAX_LOGBOOK_INLINE_TOTAL_BYTES = 1 * 1024 * 1024
MAX_LOGBOOK_BYTES = 2 * 1024 * 1024
MAX_LOGBOOK_DESCRIPTOR_ENTRIES = 2048
MAX_LOGBOOK_TIMELINE_ENTRIES = 4096
MAX_LOGBOOK_REBUILD_RETRIES = 3
MAX_LOGBOOK_READ_LIMIT = 65_536

_LOGBOOK_NAME = re.compile(r"^[0-9]{8}-[0-9]{12}-[a-z0-9-]+-[0-9a-f]{64}\.md$")


class LogbookProjectionConflict(Exception):  # noqa: N818 - authoritative M6A plan name
    """Typed failure when logbook rebuilds keep losing the revision race."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EvidenceReader(Protocol):
    """Reads a complete evidence sidecar when it fits the inline budget."""

    def read(self, reference: EvidenceReference) -> bytes | None: ...


class RepositoryEvidenceReader:
    """Bounded evidence reader backed by the retained repository descriptor."""

    def __init__(self, repository: Any, engagement_id: UUID | None) -> None:
        self._repository = repository
        self._engagement_id = engagement_id

    def __call__(self, reference: EvidenceReference) -> bytes | None:
        return self.read(reference)

    def read(self, reference: EvidenceReference) -> bytes | None:
        if self._engagement_id is None:
            return None
        if reference.size > MAX_LOGBOOK_INLINE_ITEM_BYTES:
            return None
        try:
            slice_result = self._repository.read_evidence_slice(
                self._engagement_id,
                reference.evidence_id,
                offset=0,
                limit=min(MAX_LOGBOOK_READ_LIMIT, reference.size),
            )
        except JournalUnavailableError:
            return None
        if not slice_result.complete:
            return None
        return slice_result.data


def repository_evidence_reader(
    repository: Any, engagement_id: UUID | None = None
) -> RepositoryEvidenceReader:
    """Return an evidence reader bound to one engagement for render tests."""
    return RepositoryEvidenceReader(repository, engagement_id)


def _fence(text: str) -> str:
    """Return a backtick fence one character longer than the longest run (min 3)."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(longest + 1, 3)


def _inline(value: str) -> str:
    """Render one multiline untrusted fragment inside an adaptive inert fence."""
    fence = _fence(value)
    return f"{fence}\n{value}\n{fence}"


def _code_span(value: str) -> str:
    """Render one single-line untrusted fragment as an adaptive escaped span."""
    escaped = html.escape(value)
    fence = _fence(value)
    return f"{fence}{escaped}{fence}"


def _scalar(value: Any) -> str:
    return html.escape(str(value))


def _session_digest(session_id: str) -> str:
    return sha256(session_id.encode("utf-8")).hexdigest()


def _slug(display_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", display_name.casefold()).strip("-")
    return slug[:64] or "engagement"


def _logbook_timestamp(events: Sequence[JournalEvent]) -> str:
    for event in events:
        stamp = event.occurred_at
        return stamp.strftime("%Y%m%d-%H%M%S%f")
    return "19700101-000000000000"


def _sidecar_href(reference: EvidenceReference) -> str:
    """Derive a validated URL-encoded href relative to the logbook in evidence/."""
    relative = reference.relative_path
    if not relative.startswith("evidence/"):
        raise ValueError("evidence reference is not engagement-root relative")
    basename = relative[len("evidence/") :]
    if (
        not basename
        or ".." in basename
        or "/" in basename
        or not re.fullmatch(r"blob-[0-9a-f]{64}\.bin", basename)
    ):
        raise ValueError("evidence reference basename is not confined")
    return quote(basename)


def render_session_logbook(
    manifest: EngagementManifest,
    state: EngagementState,
    events: Sequence[JournalEvent],
    evidence_reader: EvidenceReader,
    *,
    session_id: str,
) -> str:
    """Render one immutable session logbook with inert untrusted content only."""
    sections: list[str] = []
    sections.append("# Sedna session logbook")
    sections.append("")
    sections.append(f"- Session: {_scalar(session_id)}")
    sections.append(f"- Engagement: {_scalar(manifest.display_name)}")
    sections.append(f"- Objective: {_scalar(manifest.initial_objective)}")
    scope_values = " ".join(
        f"{reference.kind}={_scalar(reference.value)}" for reference in state.scope_references
    )
    sections.append(f"- Scope: {_scalar(scope_values)}")
    sections.append(
        f"- Revision: {_scalar(state.revision.sequence)}/{_scalar(state.revision.event_hash[:12])}"
    )
    if state.bound_lanes:
        bound = ", ".join(_scalar(binding.lane.stable_key) for binding in state.bound_lanes)
        sections.append(f"- Bound lanes: {bound}")
    if state.in_flight_call_ids:
        inflight = ", ".join(_scalar(item) for item in state.in_flight_call_ids)
        sections.append(f"- In-flight calls: {inflight}")
    sections.append("")

    timeline: list[str] = []
    descriptor_entries = 0
    inline_total = 0
    overflow: list[Any] = []
    for event in events:
        if len(timeline) >= MAX_LOGBOOK_TIMELINE_ENTRIES:
            overflow.append(event)
            continue
        payload = event.payload
        kind = event.type.value
        if kind == "decision_recorded":
            timeline.append(
                f"- Decision {_code_span(payload.decision_id)}: {_inline(payload.strategy)}"
            )
            timeline.append(f"  - Rationale: {_inline(payload.rationale)}")
            continue
        if kind == "tool_call_started":
            summary = payload.safe_arguments
            encoded = (
                ",".join(f"{key}={value}" for key, value in sorted(summary.items()))
                if isinstance(summary, dict)
                else ""
            )
            timeline.append(
                f"- Tool {_code_span(payload.tool_name)} "
                f"{_code_span(payload.call_id)}: {_code_span(encoded)}"
            )
            continue
        if kind == "tool_call_completed":
            timeline.append(
                f"- Completed {_code_span(payload.call_id)}: "
                f"{_scalar(payload.technical_status)} in {_scalar(payload.duration_ms)}ms"
            )
            continue
        if kind == "evidence_attached":
            reference = payload.evidence
            href = _sidecar_href(reference)
            if (
                reference.size <= MAX_LOGBOOK_INLINE_ITEM_BYTES
                and inline_total + reference.size <= MAX_LOGBOOK_INLINE_TOTAL_BYTES
            ):
                data = evidence_reader.read(reference)
                if data is not None:
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        text = None
                    if text is not None and "\x00" not in text:
                        timeline.append(
                            f"- Evidence {_code_span(reference.evidence_id[:16])}: {_inline(text)}"
                        )
                        inline_total += reference.size
                        continue
            if descriptor_entries >= MAX_LOGBOOK_DESCRIPTOR_ENTRIES:
                overflow.append(event)
                continue
            descriptor_entries += 1
            limitations = (
                ",".join(item.value for item in reference.capture_limitations)
                if reference.capture_limitations
                else ""
            )
            timeline.append(
                f"- Evidence {_code_span(reference.evidence_id[:16])}: "
                f"[{_scalar(href)}]({_scalar(href)}) "
                f"({_scalar(reference.media_type)}, {_scalar(reference.size)} bytes, "
                f"sha256:{_scalar(reference.sha256[:16])}"
                + (f", {_scalar(limitations)}" if limitations else "")
                + ")"
            )
            continue
        if kind == "recovery_warning":
            timeline.append(f"- Recovery warning: {_code_span(payload.reason_code)}")
            continue
        if kind in {
            "engagement_opened",
            "lane_bound",
            "lane_unbound",
            "closure_requested",
            "closure_cancelled",
        }:
            timeline.append(f"- {_scalar(kind.replace('_', ' ').title())}")
            continue
    if overflow:
        total = len(overflow)
        first_sequence = overflow[0].sequence
        last_sequence = overflow[-1].sequence
        digest = sha256(
            ",".join(str(event.event_id) for event in overflow).encode("utf-8")
        ).hexdigest()
        timeline.append(
            f"- Overflow summary: {_scalar(total)} entries "
            f"(sequences {_scalar(first_sequence)}..{_scalar(last_sequence)}), "
            f"sha256:{_scalar(digest[:32])}"
        )
    sections.append("## Timeline")
    sections.append("")
    sections.extend(timeline)
    rendered = "\n".join(sections) + "\n"
    encoded = rendered.encode("utf-8")
    if len(encoded) > MAX_LOGBOOK_BYTES:
        raise ValueError("logbook exceeds its byte bound")
    return rendered


def logbook_filename(events: Sequence[JournalEvent], display_name: str, session_id: str) -> str:
    """Deterministic YYYYMMDD-HHMMSSffffff-<slug>-<session-digest>.md name."""
    return f"{_logbook_timestamp(events)}-{_slug(display_name)}-{_session_digest(session_id)}.md"


def rebuild_session_logbooks(repository: Any, engagement_id: UUID) -> tuple[Path, ...]:
    """Render and atomically publish one logbook per session at the journal head."""
    engagement_fd = repository._engagement_fd(engagement_id)
    engagement_path = repository._knowledge_root / "engagements" / str(engagement_id)
    try:
        for _ in range(MAX_LOGBOOK_REBUILD_RETRIES):
            snapshot = repository.load_snapshot(engagement_id)
            session_ids = sorted(
                {event.lane.session_id for event in snapshot.events if event.lane is not None}
            )
            reader = RepositoryEvidenceReader(repository, engagement_id)
            rendered_by_session = {
                session_id: render_session_logbook(
                    snapshot.manifest,
                    snapshot.state,
                    snapshot.events,
                    reader,
                    session_id=session_id,
                )
                for session_id in session_ids
            }
            if not rendered_by_session:
                raise JournalUnavailableError("logbook rebuild requires a session")
            with _locked_file(engagement_fd, ".logbook.lock"):
                current = repository.load_snapshot(engagement_id)
                if current.revision != snapshot.revision:
                    continue
                return tuple(
                    _publish_logbook(
                        engagement_fd,
                        engagement_path,
                        logbook_filename(
                            snapshot.events, snapshot.manifest.display_name, session_id
                        ),
                        rendered,
                    )
                    for session_id, rendered in rendered_by_session.items()
                )
    finally:
        os.close(engagement_fd)
    raise LogbookProjectionConflict(code="logbook_rebuild_conflict")


def _publish_logbook(engagement_fd: int, engagement_path: Path, name: str, rendered: str) -> Path:
    if not _LOGBOOK_NAME.fullmatch(name):
        raise JournalUnavailableError("logbook name is not confined")
    data = rendered.encode("utf-8")
    if len(data) > MAX_LOGBOOK_BYTES:
        raise ValueError("logbook exceeds its byte bound")
    with _locked_file(engagement_fd, ".evidence.lock"):
        evidence_fd = _open_or_create_directory(engagement_fd, "evidence", 0o700)
        try:
            temporary = f".logbook-{uuid4()}.tmp"
            fd = os.open(
                temporary,
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
            os.replace(temporary, name, src_dir_fd=evidence_fd, dst_dir_fd=evidence_fd)
            os.fsync(evidence_fd)
        finally:
            os.close(evidence_fd)
    return engagement_path / "evidence" / name
