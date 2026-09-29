#!/usr/bin/env python3
"""Check that seed/SEED-MANIFEST.json still describes the files that are in seed/.

The manifest is what turns "the repository carries an up-to-date backup" from a
claim into a check: it records the size and sha256 of every artifact at the moment
it was generated.  If someone edits a seed archive by hand, or commits one artifact
without the other, this fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

REQUIRED_FIELDS = ("schema", "generated_at", "bank", "counts", "artifacts")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str]) -> int:
    seed_dir = argv[0] if argv else "seed"
    manifest_path = os.path.join(seed_dir, "SEED-MANIFEST.json")

    if not os.path.exists(manifest_path):
        print(f"verify-manifest: no manifest at {manifest_path}", file=sys.stderr)
        return 2

    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)

    problems = []
    for field in REQUIRED_FIELDS:
        if field not in manifest:
            problems.append(f"manifest is missing the '{field}' field")

    for artifact in manifest.get("artifacts", []):
        path = os.path.join(seed_dir, artifact.get("name", ""))
        if not os.path.exists(path):
            problems.append(f"missing artifact: {artifact.get('name')}")
            continue
        actual_size = os.path.getsize(path)
        if actual_size != artifact.get("bytes"):
            problems.append(f"{artifact['name']}: size {actual_size} != manifest {artifact['bytes']}")
        actual_hash = sha256(path)
        if actual_hash != artifact.get("sha256"):
            problems.append(f"{artifact['name']}: sha256 {actual_hash[:12]}... != manifest {str(artifact.get('sha256'))[:12]}...")

    counts = manifest.get("counts", {})
    if not counts.get("documents"):
        problems.append("manifest counts report no documents: the seed would restore an empty memory")

    for problem in problems:
        print(f"verify-manifest: {problem}", file=sys.stderr)

    if problems:
        print(f"verify-manifest: {len(problems)} problem(s)", file=sys.stderr)
        return 1

    print(
        f"verify-manifest: ok ({len(manifest.get('artifacts', []))} artifacts, "
        f"bank '{manifest.get('bank')}', {counts.get('documents')} documents, "
        f"generated {manifest.get('generated_at')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
