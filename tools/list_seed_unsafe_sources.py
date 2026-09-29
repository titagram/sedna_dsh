#!/usr/bin/env python3
"""Print the ids of knowledge-base sources the seed must not publish.

The knowledge base cannot be redacted after the fact: an artifact's id is
content-addressed (`stable_artifact_id` = a digest of its own content) and the repository is
fail-closed, so editing a bundle's text without recomputing its ids makes the whole
canonical corpus invalid -- measured by mutating one bundle and watching the audit drop to
zero sources. A source carrying material we will not publish therefore has to be *left out*,
the same way a journal-promoted source is.

"Will not publish" is deliberately the same predicate the bank sanitizer uses, imported from
it rather than reimplemented, so the memory and the knowledge base cannot drift apart:

  * a mailbox at a consumer provider -- a real person's address;
  * an address of the machine doing the rebuild (its egress address, its tailnet address).

Everything else stays, including lab users and lab domains (`ben@silentium.htb`,
`hr.trilocor.local` -- which are the finding itself) and addresses a lab scenario names.

Usage:  list_seed_unsafe_sources.py <knowledge-base-root>
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sanitize_export as S  # noqa: E402

IPV4 = S.IPV4
EMAIL = S.EMAIL


def unsafe_classes(text: str, own_addresses: set[str]) -> set[str]:
    found: set[str] = set()
    if any(S._personal_email(match.group(0)) for match in EMAIL.finditer(text)):
        found.add("personal_email")
    if own_addresses and any(match.group(0) in own_addresses for match in IPV4.finditer(text)):
        found.add("own_ipv4")
    return found


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0] if argv else ".")
    own_addresses = S.machine_addresses()
    bundles = root / "semantic_bundles"
    for bundle in sorted(bundles.glob("source-*.json")):
        try:
            text = bundle.read_text(encoding="utf-8")
        except OSError:
            continue
        if unsafe_classes(text, own_addresses):
            print(bundle.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
