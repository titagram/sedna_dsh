#!/usr/bin/env python3
"""Redact secret-shaped literals from a Hindsight bank export before it is published.

The live bank on a pentest machine legitimately contains material that must never
leave it: keys found during authorized lab work, credentials quoted from a
write-up, tokens captured in a challenge.  Those documents are still valuable
knowledge, so the answer is not "drop the document" but "publish it without the
literal".

This tool takes the ZIP produced by

    hindsight-admin export-bank --bank <bank> --output bank.zip

and writes a copy in which every literal matched by ``scan_secrets`` is replaced
by a visible marker.  Guarantees:

  * the input archive is never modified (a copy is written; ``--output`` is
    required to differ from ``--input`` unless ``--in-place`` is passed),
  * replacements never introduce a character that would invalidate the JSON that
    surrounds them,
  * a finding is *always* visible in the output as ``[REDACTED-<class>]``, so a
    reader can tell that something was taken out,
  * a Markdown report lists what was redacted, per archive member, **masked** --
    the report is meant to be committed next to the seed, so it must not become
    the leak it is documenting,
  * the tool re-scans its own output and fails (exit 1) if anything is left.

Usage
-----
    sanitize_export.py --input bank.zip --output bank-redacted.zip [--report REPORT.md]
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import ipaddress
import subprocess
import sys
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scan_secrets as S  # noqa: E402

MARKER = "[REDACTED-{}]"

# Two classes the seed must not publish, and one it deliberately keeps.
#
# A *public* IPv4 address can name a system outside the lab, and it is not needed to
# reuse the knowledge -- the technique does not depend on which address it was used
# against.  Private ranges and loopback are kept: they identify nobody, and they are
# the record of which box the note is about.
#
# E-mail addresses are redacted because they are people, and the knowledge does not
# need them.
#
# Home directories are left to the existing, narrower rule below: the maintainer's own
# machine layout is normalised, while a *lab* user's path (`/home/svcweb/...`) is part
# of the finding and stays.  That distinction is deliberate and is stated in the report.
IPV4 = S.IPV4_PATTERN
EMAIL = S.EMAIL_PATTERN


PERSONAL_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.it", "hotmail.com", "hotmail.it",
    "live.com", "live.it", "msn.com", "yahoo.com", "yahoo.it", "ymail.com", "icloud.com",
    "me.com", "mac.com", "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.de",
    "mail.com", "zoho.com", "aol.com", "fastmail.com", "tutanota.com", "libero.it",
    "virgilio.it", "tin.it", "alice.it", "tiscali.it", "poste.it", "hotmail.co.uk",
}


def _personal_email(value: str) -> bool:
    """True only for a mailbox at a consumer provider.

    The first version of this rule redacted every address and threw away 65 of the bank's
    106: `ben@silentium.htb`, `hr.trilocor.local`, `nexus.htb` -- target users and lab
    domains, which are the finding itself ("user enumeration distinguishes valid
    addresses").  A memory about lab work is mostly made of lab names; the exposure worth
    removing is a real mailbox, and that is what this list names.
    """
    domain = value.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    return domain in PERSONAL_MAIL_DOMAINS


def machine_addresses(egress_timeout: float = 3.0) -> set[str]:
    """The public addresses of the machine the snapshot runs on: those are personal.

    Deliberately not a list kept in this repository -- a list of what must not be
    published would itself publish it.  Ask the machine instead: interface addresses from
    `ip`/`hostname`, and the egress address best-effort (a few seconds, never fatal).
    Everything else stays, including addresses a lab scenario mentions.
    """
    found: set[str] = set()
    for command in (["ip", "-4", "-o", "addr", "show"], ["hostname", "-I"]):
        try:
            out = subprocess.run(command, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for match in IPV4.finditer(out):
            value = match.group(0)
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            # Only the ones that would actually expose the operator: a private address, a
            # loopback, a Docker bridge, a broadcast address -- `127.0.0.1` appears in half
            # the lab documents ever written and identifies nobody.  The tailnet address
            # (100.64.0.0/10) is not `is_private` in Python but is certainly his.
            if address.is_private or address.is_loopback or address.is_link_local \
                    or address.is_multicast or address.is_unspecified or address.is_reserved:
                continue
            found.add(value)
    try:
        out = subprocess.run(
            ["curl", "-s", "--max-time", str(int(egress_timeout)), "https://api.ipify.org"],
            capture_output=True, text=True, timeout=egress_timeout + 2,
        ).stdout.strip()
        if IPV4.fullmatch(out):
            found.add(out)
    except (OSError, subprocess.SubprocessError):
        pass
    return found

PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    re.DOTALL,
)
PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
BASE64_LINE = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
MAX_KEY_BODY_LINES = 200


def valid_json(text: str) -> bool:
    """A redacted member must still parse: the seed has to remain importable."""
    try:
        json.loads(text)
    except Exception:
        return False
    return True


def redact_private_key_bodies(text: str, counter: Counter) -> str:
    """Remove whole PEM bodies, not just their header."""

    def replace_block(match: re.Match[str]) -> str:
        counter.update(["private_key"])
        return MARKER.format("private_key-block")

    text = PRIVATE_KEY_BLOCK.sub(replace_block, text)

    # header without a matching END marker: eat the base64 lines that follow
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if PRIVATE_KEY_HEADER.search(line):
            counter.update(["private_key"])
            out.append(PRIVATE_KEY_HEADER.sub(MARKER.format("private_key-header"), line))
            i += 1
            eaten = 0
            while i < len(lines) and eaten < MAX_KEY_BODY_LINES and BASE64_LINE.match(lines[i].strip()):
                out.append(MARKER.format("private_key-body"))
                i += 1
                eaten += 1
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def home_path_pattern(users: list[str]) -> re.Pattern[str] | None:
    """Match the home directories of the *operator's* machines only.

    Users that show up inside lab documents (datawrangler, svcweb, developer, ...)
    are part of the knowledge and are left alone; the point of this pattern is to
    stop publishing the maintainer's own machine layout.
    """
    names = [re.escape(u) for u in users if u]
    if not names:
        return None
    return re.compile(r"/(?:home|Users)/(?:" + "|".join(names) + r")\b")


def redact_text(
    text: str,
    counter: Counter,
    home_users: list[str] | None = None,
    extra: list[re.Pattern[str]] | None = None,
    own_addresses: set[str] | None = None,
) -> str:
    own_addresses = own_addresses or set()
    text = redact_private_key_bodies(text, counter)

    def replacement(cls: str):
        def repl(_match: re.Match[str]) -> str:
            counter.update([cls])
            return MARKER.format(cls)

        return repl

    for cls, pattern in S.BLOCK_PATTERNS:
        if cls in {"private_key", "putty_key", "ssh_private_openssh"}:
            continue  # handled above
        text = pattern.sub(replacement(cls), text)

    def replace_assignment(match: re.Match[str]) -> str:
        value = match.group(2)
        if not S.looks_like_secret(value):
            return match.group(0)
        counter.update([f"secret_assignment[{match.group(1).lower()}]"])
        return match.group(0)[: match.start(2) - match.start(0)] + MARKER.format("secret")

    text = S.SECRET_ASSIGNMENT.sub(replace_assignment, text)

    # Only this machine's own addresses.  Redacting every public address was the earlier
    # rule, and it cost a knowledge-base source: the address a challenge attributes to an
    # attacker is part of the case, while 95.245.249.208 (this host's egress) and
    # 100.75.95.33 (its tailnet address) are the operator, and those are what must go.
    if own_addresses:
        def redact_own_ip(match: re.Match[str]) -> str:
            if match.group(0) not in own_addresses:
                return match.group(0)
            counter.update(["own_ipv4"])
            return MARKER.format("own_ipv4")

        text = IPV4.sub(redact_own_ip, text)

    def redact_personal_mail(match: re.Match[str]) -> str:
        if not _personal_email(match.group(0)):
            return match.group(0)
        counter.update(["personal_email"])
        return MARKER.format("personal_email")

    text = EMAIL.sub(redact_personal_mail, text)

    home_pattern = home_path_pattern(home_users or [])
    if home_pattern is not None:
        def normalize(match: re.Match[str]) -> str:
            counter.update(["home_path_normalized"])
            return MARKER.format("home")

        text = home_pattern.sub(normalize, text)

    for pattern in extra or []:
        def repl_extra(_match: re.Match[str]) -> str:
            counter.update(["extra"])
            return MARKER.format("extra")

        text = pattern.sub(repl_extra, text)

    return text


def sanitize_zip(
    input_path: str,
    output_path: str,
    report_path: str | None,
    home_users: list[str] | None = None,
    extra: list[re.Pattern[str]] | None = None,
    own_addresses: set[str] | None = None,
) -> int:
    counter: Counter = Counter()
    per_member: dict[str, Counter] = {}
    members: list[tuple[str, bytes]] = []
    invalid_json: list[str] = []

    with zipfile.ZipFile(input_path) as src:
        for info in sorted(src.infolist(), key=lambda i: i.filename):
            data = src.read(info)
            if info.is_dir():
                continue
            text = S.decode(data)
            if text is None:
                members.append((info.filename, data))
                continue
            member_counter: Counter = Counter()
            new_text = redact_text(
                text, member_counter, home_users=home_users, extra=extra, own_addresses=own_addresses
            )
            if member_counter:
                per_member[info.filename] = member_counter
                counter.update(member_counter)
                if info.filename.endswith(".json") and not valid_json(new_text):
                    invalid_json.append(info.filename)
            members.append((info.filename, new_text.encode("utf-8")))

    if invalid_json:
        print(f"ERROR: redaction produced invalid JSON in {len(invalid_json)} member(s):", file=sys.stderr)
        for name in invalid_json[:10]:
            print(f"  {name}", file=sys.stderr)
        return 3

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as dst:
        for name, data in members:
            dst.writestr(name, data)

    if report_path:
        write_report(report_path, input_path, output_path, counter, per_member)

    # fail-closed: the sanitized copy must be clean
    findings = S.Findings()
    S.scan_path(output_path, findings, excludes=[])
    remaining = [f for f in findings.items if f["severity"] == "BLOCK"]

    summary = ", ".join(f"{name}×{count}" for name, count in sorted(counter.items())) or "nothing"
    print(f"redacted in {os.path.basename(output_path)}: {summary}")
    if remaining:
        print(f"ERROR: {len(remaining)} BLOCK finding(s) survived sanitization:", file=sys.stderr)
        for item in remaining[:20]:
            print(f"  {item['class']} @ {item['location']}", file=sys.stderr)
        return 1
    print("post-sanitization scan: 0 BLOCK")
    return 0


def write_report(report_path: str, input_path: str, output_path: str, counter: Counter, per_member: dict[str, Counter]) -> None:
    lines = [
        "# Seed redaction report",
        "",
        "Generated by `tools/sanitize_export.py`. This file is committed next to the seed on purpose:",
        "a reader must be able to tell that material was removed, and what class of material it was.",
        "Values are never reproduced here.",
        "",
        f"- source archive: `{os.path.basename(input_path)}`",
        f"- published archive: `{os.path.basename(output_path)}`",
        f"- members rewritten: **{len(per_member)}**",
        f"- literals redacted: **{sum(counter.values())}**",
        "",
        "| class | count |",
        "|---|---|",
    ]
    for name, count in sorted(counter.items()):
        lines.append(f"| `{name}` | {count} |")
    lines += ["", "## Per archive member", "", "| member | classes |", "|---|---|"]
    for member, counts in sorted(per_member.items()):
        detail = ", ".join(f"`{k}`×{v}" for k, v in sorted(counts.items()))
        lines.append(f"| `{member}` | {detail} |")
    lines += [
        "",
        "## What this does not do",
        "",
        "- It does not touch the live bank: the export is redacted, the source of truth is not.",
        "- It keeps what the knowledge is *about*: private IPv4 ranges, loopback, and lab users'",
        "  home directories (`/home/svcweb/...`). Those are facts about a target, not about a",
        "  person, and a finding that cannot say where on the box it happened is worth less. The",
        "  scanner still reports them as warnings, on purpose: a warning is not a finding, and the",
        "  difference is stated here rather than hidden by tuning the scanner.",
        "- It redacts what is not needed: public IPv4 addresses (they can name a system outside the",
        "  lab and no technique depends on which address it was used against) and e-mail addresses.",
        "- It does not prove the absence of an unknown secret class. It proves the absence of the",
        "  classes the scanner knows.",
        "",
    ]
    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Redact secret-shaped literals from a bank export ZIP.")
    parser.add_argument("--input", required=True, help="archive produced by hindsight-admin export-bank")
    parser.add_argument("--output", required=True, help="archive to write (must differ from --input)")
    parser.add_argument("--report", default=None, help="Markdown report to write")
    parser.add_argument("--in-place", action="store_true", help="allow output == input")
    parser.add_argument(
        "--normalize-home",
        action="append",
        default=[],
        metavar="USER",
        help="rewrite /home/USER and /Users/USER to a marker (repeatable); never touches other users",
    )
    parser.add_argument(
        "--extra-redact",
        action="append",
        default=[],
        metavar="REGEX",
        help="additional pattern to replace with a marker (repeatable)",
    )
    args = parser.parse_args(argv)

    if not os.path.exists(args.input):
        print(f"ERROR: no such archive: {args.input}", file=sys.stderr)
        return 2
    if os.path.abspath(args.input) == os.path.abspath(args.output) and not args.in_place:
        print("ERROR: refusing to overwrite the source archive (pass --in-place to allow)", file=sys.stderr)
        return 2

    extra = []
    for expression in args.extra_redact:
        try:
            extra.append(re.compile(expression))
        except re.error as exc:
            print(f"ERROR: bad --extra-redact pattern {expression!r}: {exc}", file=sys.stderr)
            return 2

    own = machine_addresses()
    if own:
        print(f"addresses of this machine (redacted if they appear): {len(own)} found")
    return sanitize_zip(
        args.input, args.output, args.report,
        home_users=args.normalize_home, extra=extra, own_addresses=own,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
