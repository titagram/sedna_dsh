#!/usr/bin/env python3
"""Print the ids of canonical sources that depend on an engagement journal artifact.

A source whose manifest was written by the journal-promotion renderer references a
file under `engagements/`, which the seed does not publish.  The repository treats
such a source as invalid when that file is absent, and a single invalid source makes
the whole canonical corpus fail closed.  See docs/maintenance.md.
"""

from __future__ import annotations

import json
import pathlib
import sys

PROFILES = {"journal_promotion"}
NAMESPACES = {"journal-promotion"}


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0] if argv else ".")
    manifests = root / "manifests"
    for manifest in sorted(manifests.glob("source-*.json")):
        try:
            data = json.loads(manifest.read_text())
        except Exception:
            continue
        if data.get("parser_profile") in PROFILES or data.get("source_namespace") in NAMESPACES:
            print(manifest.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
