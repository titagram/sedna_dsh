"""Deterministic discovery of source documents and their local assets."""

from __future__ import annotations

import errno
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import NAMESPACE_URL, uuid5

_SOURCE_SUFFIXES = {".md", ".pdf"}


@dataclass(frozen=True, slots=True)
class AssetCandidate:
    """A non-document file associated with a source document."""

    path: Path
    relative_path: str
    suffix: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class SourceCandidate:
    """A source document and the assets stored beneath its directory."""

    source_id: str
    path: Path
    relative_path: str
    suffix: str
    sha256: str
    size_bytes: int
    assets: tuple[AssetCandidate, ...]
    source_namespace: str | None = None


@dataclass(frozen=True, slots=True)
class _DiscoveredFile:
    relative_path: str
    suffix: str
    sha256: str
    size_bytes: int


def stable_source_id(relative_path: str) -> str:
    """Build a content-independent source identifier from a POSIX path."""
    return f"source-{uuid5(NAMESPACE_URL, f'sedna:{relative_path}')}"


def stable_source_namespace(source_root: Path) -> str:
    """Return an opaque stable namespace for one resolved source-root origin."""
    resolved = Path(source_root).resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("source namespace root must be a directory")
    return f"source-root-{uuid5(NAMESPACE_URL, f'sedna-root:{resolved.as_posix()}')}"


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a regular, non-symlink file."""
    file_fd = os.open(
        path,
        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise ValueError(f"not a regular file: {path}")
        return _sha256_descriptor(file_fd)
    finally:
        os.close(file_fd)


def discover_sources(source_root: Path) -> tuple[SourceCandidate, ...]:
    """Discover regular documents from a retained root descriptor in stable order.

    A symlink supplied as the root itself remains a supported alias.  After that
    one explicit resolution boundary, traversal and file reads are descriptor-relative
    with ``O_NOFOLLOW``; symlinked entries within the source tree are ignored.
    """
    requested_root = Path(source_root)
    try:
        resolved_root = requested_root.resolve(strict=True)
    except FileNotFoundError:
        return ()
    expected = os.stat(resolved_root, follow_symlinks=False)
    if not stat.S_ISDIR(expected.st_mode):
        return ()
    root_fd = os.open(resolved_root, _directory_open_flags())
    try:
        actual = os.fstat(root_fd)
        if not stat.S_ISDIR(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
            expected.st_dev,
            expected.st_ino,
        ):
            raise ValueError("source root changed while it was being opened")
        files = tuple(sorted(_walk_files(root_fd), key=lambda item: item.relative_path))
    finally:
        os.close(root_fd)

    source_files = tuple(item for item in files if item.suffix in _SOURCE_SUFFIXES)
    source_paths = frozenset(item.relative_path for item in source_files)
    source_namespace = stable_source_namespace(resolved_root)
    return tuple(
        SourceCandidate(
            source_id=stable_source_id(item.relative_path),
            path=requested_root.joinpath(*PurePosixPath(item.relative_path).parts),
            relative_path=item.relative_path,
            suffix=item.suffix,
            sha256=item.sha256,
            size_bytes=item.size_bytes,
            assets=_assets_for(item, files, source_paths, requested_root),
            source_namespace=source_namespace,
        )
        for item in source_files
    )


def _walk_files(directory_fd: int, prefix: str = "") -> tuple[_DiscoveredFile, ...]:
    discovered: list[_DiscoveredFile] = []
    for name in sorted(os.listdir(directory_fd)):
        relative_path = f"{prefix}/{name}" if prefix else name
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(before.st_mode):
            try:
                child_fd = os.open(name, _directory_open_flags(), dir_fd=directory_fd)
            except OSError as exc:
                if _entry_became_unsafe(exc):
                    continue
                raise
            try:
                opened = os.fstat(child_fd)
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    continue
                discovered.extend(_walk_files(child_fd, relative_path))
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(before.st_mode):
            continue
        try:
            file_fd = os.open(name, _file_read_flags(), dir_fd=directory_fd)
        except OSError as exc:
            if _entry_became_unsafe(exc):
                continue
            raise
        try:
            opened = os.fstat(file_fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                continue
            discovered.append(
                _DiscoveredFile(
                    relative_path=relative_path,
                    suffix=PurePosixPath(name).suffix.casefold(),
                    sha256=_sha256_descriptor(file_fd),
                    size_bytes=opened.st_size,
                )
            )
        finally:
            os.close(file_fd)
    return tuple(discovered)


def _sha256_descriptor(file_fd: int) -> str:
    digest = hashlib.sha256()
    while block := os.read(file_fd, 1024 * 1024):
        digest.update(block)
    return digest.hexdigest()


def _assets_for(
    source: _DiscoveredFile,
    all_files: tuple[_DiscoveredFile, ...],
    source_paths: frozenset[str],
    source_root: Path,
) -> tuple[AssetCandidate, ...]:
    source_directory = PurePosixPath(source.relative_path).parent
    assets: list[AssetCandidate] = []
    for item in all_files:
        item_path = PurePosixPath(item.relative_path)
        if (
            item.relative_path == source.relative_path
            or item.relative_path in source_paths
            or item_path.name == ".DS_Store"
            or source_directory not in item_path.parents
        ):
            continue
        assets.append(
            AssetCandidate(
                path=source_root.joinpath(*item_path.parts),
                relative_path=item.relative_path,
                suffix=item.suffix,
                sha256=item.sha256,
                size_bytes=item.size_bytes,
            )
        )
    return tuple(assets)


def _directory_open_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_read_flags() -> int:
    return os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _entry_became_unsafe(exc: OSError) -> bool:
    return exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ELOOP}
