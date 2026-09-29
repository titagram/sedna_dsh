#!/usr/bin/env python3
"""Sync Sedna engagement journal events into rolling pt-report format."""

import argparse
import fcntl
import json
import os
import stat
import subprocess
import sys
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_FILE_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
_CHECKPOINT_MAX_BYTES = 1_048_576
_CHECKPOINT_MAX_IDS = 8192


def _safe_event_reference(event: object) -> str | None:
    if not isinstance(event, dict):
        return None
    try:
        return str(UUID(str(event.get("event_id", ""))))
    except ValueError:
        return None


def _validate_name(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name:
        raise ValueError("unsafe synchronization state name")


def _verify_owned(fd: int, *, directory: bool) -> None:
    metadata = os.fstat(fd)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise PermissionError("synchronization state must be owned by the current user")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PermissionError("synchronization path has unsafe permissions")
    if not directory and metadata.st_nlink != 1:
        raise PermissionError("synchronization state file must not be hard-linked")


def _open_directory(parent_fd: int, name: str, *, create: bool) -> int:
    _validate_name(name)
    if create:
        with suppress(FileExistsError):
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    try:
        _verify_owned(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_root(path: Path) -> int:
    absolute = path if path.is_absolute() else Path.cwd() / path
    parts = absolute.parts
    if not parts or parts[0] != absolute.anchor:
        raise ValueError("sedna_root must resolve from an absolute filesystem anchor")

    fd = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for component in parts[1:]:
            if component in {"", "."}:
                continue
            if component == "..":
                raise ValueError("sedna_root must not contain parent traversal")
            next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        _verify_owned(fd, directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_trusted_script(path: Path) -> int:
    if path.name in {"", ".", ".."}:
        raise ValueError("pt_report_script must name a file")
    parent_fd = _open_root(path.parent)
    try:
        script_fd = os.open(path.name, _FILE_READ_FLAGS, dir_fd=parent_fd)
        try:
            _verify_owned(script_fd, directory=False)
            return script_fd
        except BaseException:
            os.close(script_fd)
            raise
    finally:
        os.close(parent_fd)


def _open_journal(root_fd: int, engagement_id: str) -> int:
    engagements_fd = _open_directory(root_fd, "engagements", create=False)
    try:
        engagement_fd = _open_directory(engagements_fd, engagement_id, create=False)
        try:
            journal_fd = os.open("events.jsonl", _FILE_READ_FLAGS, dir_fd=engagement_fd)
            try:
                _verify_owned(journal_fd, directory=False)
                return journal_fd
            except BaseException:
                os.close(journal_fd)
                raise
        finally:
            os.close(engagement_fd)
    finally:
        os.close(engagements_fd)


def _open_state_directory(root_fd: int, engagement_id: str) -> int:
    state_root_fd = _open_directory(root_fd, ".pt-report-sync", create=True)
    try:
        return _open_directory(state_root_fd, engagement_id, create=True)
    finally:
        os.close(state_root_fd)


def _open_owned_file(
    directory_fd: int,
    name: str,
    flags: int,
    *,
    mode: int = 0o600,
) -> int:
    _validate_name(name)
    fd = os.open(name, flags | os.O_CLOEXEC | os.O_NOFOLLOW, mode, dir_fd=directory_fd)
    try:
        _verify_owned(fd, directory=False)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _canonical_event_ids(raw_ids: object) -> list[str]:
    if not isinstance(raw_ids, list) or len(raw_ids) > _CHECKPOINT_MAX_IDS:
        raise ValueError("invalid pt-report sync checkpoint")
    event_ids: list[str] = []
    for value in raw_ids:
        try:
            canonical = str(UUID(str(value)))
        except ValueError as exc:
            raise ValueError("invalid pt-report sync checkpoint") from exc
        if value != canonical:
            raise ValueError("invalid pt-report sync checkpoint")
        event_ids.append(canonical)
    if event_ids != sorted(set(event_ids)):
        raise ValueError("invalid pt-report sync checkpoint")
    return event_ids


def _load_checkpoint(directory_fd: int, name: str) -> tuple[set[str], str | None]:
    try:
        fd = _open_owned_file(directory_fd, name, os.O_RDONLY)
    except FileNotFoundError:
        return set(), None
    with os.fdopen(fd, "rb") as handle:
        raw_payload = handle.read(_CHECKPOINT_MAX_BYTES + 1)
    if len(raw_payload) > _CHECKPOINT_MAX_BYTES:
        raise ValueError("invalid pt-report sync checkpoint")
    try:
        payload = json.loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid pt-report sync checkpoint") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid pt-report sync checkpoint")

    if payload.get("version") != 2 or set(payload) != {
        "completed_event_ids",
        "pending_event_id",
        "version",
    }:
        raise ValueError("invalid pt-report sync checkpoint")

    completed = _canonical_event_ids(payload.get("completed_event_ids"))
    pending_value = payload.get("pending_event_id")
    if pending_value is None:
        pending = None
    else:
        try:
            pending = str(UUID(str(pending_value)))
        except ValueError as exc:
            raise ValueError("invalid pt-report sync checkpoint") from exc
        if pending_value != pending or pending in completed:
            raise ValueError("invalid pt-report sync checkpoint")
    return set(completed), pending


def _store_checkpoint(
    directory_fd: int,
    name: str,
    event_ids: set[str],
    *,
    pending_event_id: str | None,
) -> None:
    _validate_name(name)
    if pending_event_id is not None:
        try:
            canonical_pending = str(UUID(pending_event_id))
        except ValueError as exc:
            raise ValueError("invalid pending event UUID") from exc
        if canonical_pending != pending_event_id or pending_event_id in event_ids:
            raise ValueError("invalid pending event UUID")
    completed_event_ids = _canonical_event_ids(sorted(event_ids))
    payload = {
        "completed_event_ids": completed_event_ids,
        "pending_event_id": pending_event_id,
        "version": 2,
    }
    payload_bytes = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    if len(payload_bytes) > _CHECKPOINT_MAX_BYTES:
        raise ValueError("pt-report sync checkpoint exceeds bounded size")

    temp_name = f".checkpoint-{uuid4().hex}"
    temp_fd: int | None = None
    try:
        temp_fd = _open_owned_file(
            directory_fd,
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        )
        with os.fdopen(temp_fd, "wb") as handle:
            temp_fd = None
            handle.write(payload_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        if pending_event_id is None:
            # Destination success is already authoritative. If this fsync fails,
            # the visible state is either completed (skip) or the prior pending
            # barrier (stop); neither state permits duplicate automatic replay.
            with suppress(OSError):
                os.fsync(directory_fd)
        else:
            os.fsync(directory_fd)
    finally:
        if temp_fd is not None:
            os.close(temp_fd)
        with suppress(FileNotFoundError):
            os.unlink(temp_name, dir_fd=directory_fd)


def sync_events(
    sedna_root: Path,
    engagement_id: str,
    pt_engagement: str,
    pt_report_script: Path,
) -> None:
    try:
        canonical_engagement_id = str(UUID(engagement_id))
    except ValueError as exc:
        raise ValueError("engagement_id must be a UUID") from exc
    if engagement_id != canonical_engagement_id:
        raise ValueError("engagement_id must be a UUID")

    root_fd = _open_root(sedna_root)
    try:
        try:
            journal_fd = _open_journal(root_fd, canonical_engagement_id)
        except FileNotFoundError:
            print(
                f"[!] Journal not found for engagement {canonical_engagement_id}",
                file=sys.stderr,
            )
            raise SystemExit(1) from None
        try:
            state_fd = _open_state_directory(root_fd, canonical_engagement_id)
        except BaseException:
            os.close(journal_fd)
            raise
    finally:
        os.close(root_fd)

    report_key = sha256(pt_engagement.encode("utf-8")).hexdigest()
    checkpoint_name = f"{report_key}.json"
    try:
        pt_report_fd = _open_trusted_script(pt_report_script)
    except BaseException:
        os.close(journal_fd)
        os.close(state_fd)
        raise
    pt_report_command = [sys.executable, f"/proc/self/fd/{pt_report_fd}"]

    print(f"[*] Syncing Sedna engagement {engagement_id} -> pt-report {pt_engagement}")
    try:
        fcntl.flock(state_fd, fcntl.LOCK_EX)
        processed, pending_event_id = _load_checkpoint(state_fd, checkpoint_name)
        if pending_event_id is not None:
            raise RuntimeError(
                "pt-report sync has ambiguous pending event "
                f"{pending_event_id}; manual reconciliation required"
            )
        with os.fdopen(journal_fd, encoding="utf-8") as journal:
            journal_fd = -1
            for line in journal:
                if not line.strip():
                    continue
                event = json.loads(line)
                event_type = event.get("type")
                event_reference = _safe_event_reference(event)
                if event_reference is None or event_reference in processed:
                    continue

                if event_type == "decision_recorded":
                    command = [
                        *pt_report_command,
                        "add-note",
                        "--engagement",
                        pt_engagement,
                        "--title",
                        "Strategy decision recorded",
                        "--body",
                        f"Private Sedna journal event: {event_reference}",
                        "--idempotency-key",
                        event_reference,
                    ]
                elif event_type == "observation_extracted":
                    command = [
                        *pt_report_command,
                        "add-observation",
                        "--engagement",
                        pt_engagement,
                        "--title",
                        "Observation recorded",
                        "--severity",
                        "info",
                        "--description",
                        f"Private Sedna journal event: {event_reference}",
                        "--idempotency-key",
                        event_reference,
                    ]
                else:
                    continue

                if len(processed) >= _CHECKPOINT_MAX_IDS:
                    raise ValueError("pt-report sync completed event limit reached")
                _store_checkpoint(
                    state_fd,
                    checkpoint_name,
                    processed,
                    pending_event_id=event_reference,
                )
                subprocess.run(command, check=True, pass_fds=(pt_report_fd,))
                processed.add(event_reference)
                _store_checkpoint(
                    state_fd,
                    checkpoint_name,
                    processed,
                    pending_event_id=None,
                )

        print(f"[+] Sync completed for {pt_engagement}")
    finally:
        with suppress(OSError):
            fcntl.flock(state_fd, fcntl.LOCK_UN)
        if journal_fd >= 0:
            os.close(journal_fd)
        os.close(state_fd)
        os.close(pt_report_fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync Sedna journal to pt-report")
    parser.add_argument(
        "--sedna-root",
        default=str(Path.home() / ".hermes" / "knowledge" / "sedna"),
    )
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--pt-engagement", required=True)
    parser.add_argument("--pt-report-script", type=Path, required=True)
    args = parser.parse_args()
    sync_events(
        Path(args.sedna_root),
        args.engagement_id,
        args.pt_engagement,
        args.pt_report_script,
    )
