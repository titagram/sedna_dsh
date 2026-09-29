#!/usr/bin/env python3
"""Fail-closed secret/flag scanner for seed artifacts.

Purpose
-------
This repository ships *data* (a Hindsight bank export and a Sedna knowledge-base
seed) next to code.  Data that leaves a pentest machine can carry things that must
never be published: captured flags, credentials, private keys, session tokens.

The scanner is the single gate in front of that.  It is deliberately boring:

  * stdlib only (no pip install on a fresh machine),
  * deterministic output (sorted, no timestamps),
  * fail-closed: any BLOCK finding makes the process exit 1,
  * it NEVER prints a secret it found -- only a masked form -- because CI logs and
    terminal scrollback of a public repository are themselves an exposure.

Classes
-------
BLOCK  must not ship: flags, private keys, cloud/API tokens, JWTs, credentials in
       URLs, and assignments whose value looks like a real secret.
WARN   should not ship without a look: IP literals, e-mail addresses, absolute
       home paths.  Warnings do not fail the run unless --strict-warn.

Usage
-----
    scan_secrets.py PATH [PATH ...] [--json] [--summary] [--strict-warn]
                    [--max-findings N] [--exclude GLOB ...]

PATH may be a file, a directory, a .zip or a .tar.gz/.tgz; archives are scanned
recursively (depth-capped).
"""

from __future__ import annotations

import argparse
import fnmatch
import io
import json
import math
import os
import re
import sys
import tarfile
import zipfile

# --------------------------------------------------------------------------- #
# Tunables
# --------------------------------------------------------------------------- #

MAX_ARCHIVE_DEPTH = 3
MAX_MEMBER_BYTES = 64 * 1024 * 1024  # do not read absurd members
SNIFF_BYTES = 8192
CONTEXT_RADIUS = 24  # characters of context kept around a finding (masked)

PLACEHOLDER_VALUES = re.compile(
    r"""^(?:
        <.*> | \{.*\} | \[.*\] | \$\(.*\) | \$\{.*\} | %.*% |
        x{3,} | \*{2,} | -{2,} | \.{3,} | \?{3,} | _{2,} |
        redacted | removed | omitted | suppressed | none | null | nil | n/a |
        true | false | yes | no | on | off | unset | empty | placeholder |
        example | sample | dummy | changeme | changeme123 | secret | password |
        passwd | token | apikey | api[_-]?key | your[_-]?\w* | my[_-]?\w* |
        some[_-]?\w* | test | testing | foo | bar | baz | abc | abc123 |
        <redacted> | <none>
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

BLOCK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Captured flags.  The strict body class is what keeps "<FLAG>" placeholders
    # and "HTB{...}" format examples out: they contain characters not allowed here
    # or are shorter than four characters.
    ("flag_htb", re.compile(r"\bHTB\{[A-Za-z0-9_!@#$%^&*+=?-]{4,}\}")),
    ("flag_ctf", re.compile(r"\b(?:CTF|flag)\{[A-Za-z0-9_!@#$%^&*+=?-]{4,}\}", re.IGNORECASE)),
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("putty_key", re.compile(r"PuTTY-User-Key-File-\d")),
    # Split so this file does not contain the literal it looks for: the gate scans
    # the tools directory too, and a secret scanner that trips itself would push
    # its own maintainers to add exactly the kind of exception it exists to deny.
    ("ssh_private_openssh", re.compile("BEGIN OPENSSH" + " PRIVATE KEY")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(r"\baws.{0,20}(?:secret|key).{0,4}[:=]\s*[\"']?([A-Za-z0-9/+=]{40})", re.IGNORECASE)),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("basic_auth_url", re.compile(r"://[^/\s:@'\"]{1,64}:[^/\s:@'\"]{4,}@")),
    ("openssl_passphrase", re.compile(r"\bDEK-Info:\s*[A-F0-9]{16}")),
]

# keyword[:=]value, then filtered below by value shape
SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key
      |secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)
    \b\s*[:=]\s*["']?([^\s"',;\)\]\}]{8,})
    """
)

# `\b` was the obvious choice and it was wrong: a boundary does not exist between a letter
# and a digit, so an address written the way documents actually write it -- escaped newline,
# then the address (`...\n95.245.249.208`) -- did not match, and four occurrences of a real
# address survived redaction *and* were invisible to this scanner.  Lookarounds instead:
# they still refuse to match inside a longer dotted number, without needing a boundary.
IPV4_PATTERN = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])")
EMAIL_PATTERN = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

WARN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ipv4", IPV4_PATTERN),
    ("email", EMAIL_PATTERN),
    ("home_path", re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+")),
]

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".tgz",
    ".xz", ".bz2", ".7z", ".rar", ".bin", ".so", ".dylib", ".dll", ".exe",
    ".woff", ".woff2", ".ttf", ".otf", ".ico", ".sqlite", ".db", ".dump",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    if PLACEHOLDER_VALUES.match(value):
        return True
    if any(ch in value for ch in "<>{}$%"):
        return True
    if value.lower() in {"password", "passwd", "secret", "token", "apikey", "api_key"}:
        return True
    # a run of the same character (xxxx, ----, ....)
    if len(set(value)) <= 2:
        return True
    return False


def looks_like_secret(value: str) -> bool:
    """Conservative: only clearly secret-shaped assignments are BLOCKed."""
    if looks_like_placeholder(value):
        return False
    has_digit = any(ch.isdigit() for ch in value)
    has_upper = any(ch.isupper() for ch in value)
    has_symbol = any(not ch.isalnum() for ch in value)
    if len(value) >= 24 and entropy(value) >= 3.0:
        return True
    if len(value) >= 12 and has_digit and (has_upper or has_symbol) and entropy(value) >= 3.2:
        return True
    if len(value) >= 16 and has_digit and entropy(value) >= 3.5:
        return True
    return False


def mask(text: str) -> str:
    """Never reveal a matched secret. Keep shape only."""
    text = text.strip()
    if not text:
        return "(empty)"
    if len(text) <= 8:
        return f"{text[0]}{'*' * (len(text) - 1)} (len {len(text)})" if len(text) > 2 else f"*** (len {len(text)})"
    return f"{text[:4]}...{'*' * 4} (len {len(text)})"


def is_probably_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:SNIFF_BYTES]
    if b"\x00" in sample:
        return True
    # non-decodable sample -> binary
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def decode(data: bytes) -> str | None:
    if is_probably_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


class Findings:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, severity: str, cls: str, location: str, evidence: str) -> None:
        self.items.append(
            {
                "severity": severity,
                "class": cls,
                "location": location,
                "evidence": mask(evidence),
            }
        )

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in self.items:
            key = f"{item['severity']}:{item['class']}"
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items()))


def scan_text(text: str, location: str, findings: Findings) -> None:
    for cls, pattern in BLOCK_PATTERNS:
        for match in pattern.finditer(text):
            literal = match.group(1) if match.lastindex else match.group(0)
            if cls == "aws_secret" and not literal:
                continue
            findings.add("BLOCK", cls, location, literal)

    for match in SECRET_ASSIGNMENT.finditer(text):
        value = match.group(2)
        if looks_like_secret(value):
            findings.add("BLOCK", f"secret_assignment[{match.group(1).lower()}]", location, value)

    for cls, pattern in WARN_PATTERNS:
        hits = pattern.findall(text)
        if not hits:
            continue
        # report the class once per location, masked, with a count
        sample = hits[0] if isinstance(hits[0], str) else hits[0][0]
        findings.add("WARN", cls, location, f"{sample} (and {len(hits) - 1} more)" if len(hits) > 1 else sample)


def scan_bytes(data: bytes, location: str, findings: Findings) -> None:
    text = decode(data)
    if text is None:
        return
    scan_text(text, location, findings)


def scan_zip(path: str, location: str, findings: Findings, depth: int, excludes: list[str]) -> None:
    try:
        with zipfile.ZipFile(path) as zf:
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                if info.is_dir():
                    continue
                member_location = f"{location}::{info.filename}"
                if excluded(info.filename, excludes):
                    continue
                if info.file_size > MAX_MEMBER_BYTES:
                    findings.add("WARN", "skipped_large_member", member_location, f"{info.file_size} bytes")
                    continue
                try:
                    data = zf.read(info)
                except Exception as exc:  # pragma: no cover - corrupt archive
                    findings.add("WARN", "unreadable_member", member_location, type(exc).__name__)
                    continue
                if depth < MAX_ARCHIVE_DEPTH and info.filename.lower().endswith((".zip",)):
                    with io.BytesIO(data) as buf:
                        nested = os.path.join(os.path.dirname(path), os.path.basename(info.filename))
                        scan_zip_stream(buf, nested, member_location, findings, depth + 1, excludes)
                    continue
                scan_bytes(data, member_location, findings)
    except zipfile.BadZipFile:
        findings.add("WARN", "bad_zip", location, "not a zip archive")


def scan_zip_stream(buf: io.BytesIO, name: str, location: str, findings: Findings, depth: int, excludes: list[str]) -> None:
    try:
        with zipfile.ZipFile(buf) as zf:
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                if info.is_dir():
                    continue
                if excluded(info.filename, excludes):
                    continue
                member_location = f"{location}::{info.filename}"
                if info.file_size > MAX_MEMBER_BYTES:
                    continue
                scan_bytes(zf.read(info), member_location, findings)
    except zipfile.BadZipFile:
        findings.add("WARN", "bad_nested_zip", location, name)


def scan_tar(path: str, location: str, findings: Findings, depth: int, excludes: list[str]) -> None:
    try:
        with tarfile.open(path, "r:*") as tf:
            for member in sorted(tf.getmembers(), key=lambda m: m.name):
                if not member.isfile():
                    continue
                if excluded(member.name, excludes):
                    continue
                member_location = f"{location}::{member.name}"
                if member.size > MAX_MEMBER_BYTES:
                    findings.add("WARN", "skipped_large_member", member_location, f"{member.size} bytes")
                    continue
                handle = tf.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                if depth < MAX_ARCHIVE_DEPTH and member.name.lower().endswith(".zip"):
                    scan_zip_stream(io.BytesIO(data), member.name, member_location, findings, depth + 1, excludes)
                    continue
                scan_bytes(data, member_location, findings)
    except tarfile.TarError:
        findings.add("WARN", "bad_tar", location, "not a tar archive")


def excluded(rel_path: str, excludes: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pat) or fnmatch.fnmatch(os.path.basename(rel_path), pat) for pat in excludes)


def scan_path(path: str, findings: Findings, excludes: list[str], depth: int = 0) -> None:
    if excluded(path, excludes):
        return
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not excluded(os.path.join(root, d), excludes) and d != ".git")
            for name in sorted(files):
                full = os.path.join(root, name)
                if excluded(full, excludes):
                    continue
                scan_path(full, findings, excludes, depth)
        return

    if not os.path.exists(path):
        findings.add("WARN", "missing_path", path, "path does not exist")
        return

    lower = path.lower()
    if lower.endswith(".zip"):
        scan_zip(path, path, findings, depth, excludes)
        return
    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        scan_tar(path, path, findings, depth, excludes)
        return
    if os.path.splitext(lower)[1] in BINARY_EXT:
        findings.add("WARN", "skipped_binary", path, os.path.splitext(lower)[1])
        return
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_MEMBER_BYTES)
    except OSError as exc:
        findings.add("WARN", "unreadable_file", path, type(exc).__name__)
        return
    scan_bytes(data, path, findings)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed secret/flag scanner for seed artifacts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="+", help="files, directories, .zip or .tar.gz to scan")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--summary", action="store_true", help="print counts only")
    parser.add_argument("--strict-warn", action="store_true", help="treat WARN as a failure too")
    parser.add_argument("--max-findings", type=int, default=200, help="cap printed findings (default 200)")
    parser.add_argument("--exclude", action="append", default=[], help="glob to skip (repeatable)")
    args = parser.parse_args(argv)

    findings = Findings()
    for path in args.paths:
        scan_path(path, findings, args.exclude)

    blocks = [f for f in findings.items if f["severity"] == "BLOCK"]
    warns = [f for f in findings.items if f["severity"] == "WARN"]
    counts = findings.counts()

    if args.json:
        print(
            json.dumps(
                {
                    "blocked": len(blocks),
                    "warned": len(warns),
                    "counts": counts,
                    "findings": findings.items[: args.max_findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif args.summary:
        for key, value in counts.items():
            print(f"{value:6d}  {key}")
        print(f"{len(blocks):6d}  BLOCK total")
        print(f"{len(warns):6d}  WARN total")
    else:
        for item in findings.items[: args.max_findings]:
            print(f"{item['severity']:5s} {item['class']:28s} {item['location']} :: {item['evidence']}")
        if len(findings.items) > args.max_findings:
            print(f"... {len(findings.items) - args.max_findings} more findings suppressed")
        print(f"\n{len(blocks)} BLOCK, {len(warns)} WARN")

    if blocks:
        return 1
    if args.strict_warn and warns:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
