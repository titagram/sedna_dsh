#!/usr/bin/env bash
# Structural checks on the seed: the two archives must contain what the manifest
# claims, in a shape the importers will accept.  Hash equality is checked by
# tools/verify-manifest.py; this checks the *inside*.
#
# Kept dependency-free (python3 stdlib only) so it runs anywhere CI does.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
seed="$repo/seed"

passed=0
failed=0

check() { # check <description> <command...>
    local description="$1"; shift
    if output="$("$@" 2>&1)"; then
        printf '  ok   %s %s\n' "$description" "${output:+($output)}"
        passed=$((passed + 1))
    else
        printf '  FAIL %s\n' "$description"
        [[ -n "${output:-}" ]] && printf '       %s\n' "$(printf '%s' "$output" | head -3)"
        failed=$((failed + 1))
    fi
}

echo "seed structure: $seed"

check "bank archive exists" test -f "$seed/hindsight-bank.zip"
check "knowledge base archive exists" test -f "$seed/sedna-kb.tar.gz"
check "manifest exists" test -f "$seed/SEED-MANIFEST.json"
check "redaction report exists" test -f "$seed/REDACTION-REPORT.md"

# The bank export must be a zip whose every JSON member parses, and whose manifest
# reports a non-zero document count.  A truncated or hand-edited export would fail
# here rather than at import time on a stranger's machine.
check "bank archive members parse and agree with the manifest" python3 - "$seed" <<'PY'
import json, os, sys, zipfile

seed = sys.argv[1]
archive_path = os.path.join(seed, "hindsight-bank.zip")
with zipfile.ZipFile(archive_path) as archive:
    bad = archive.testzip()
    if bad:
        raise SystemExit(f"corrupt member: {bad}")
    names = archive.namelist()
    if not names:
        raise SystemExit("the archive is empty")
    if "manifest.json" not in names:
        raise SystemExit("no manifest.json inside the export")

    broken = []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            json.loads(archive.read(name))
        except Exception as exc:
            broken.append(f"{name}: {exc}")
    if broken:
        raise SystemExit("unparseable members: " + "; ".join(broken[:3]))

    inside = json.loads(archive.read("manifest.json"))
    documents = inside.get("document_count") or inside.get("documents") or 0
    if not documents:
        raise SystemExit("the export reports no documents")

    with open(os.path.join(seed, "SEED-MANIFEST.json"), encoding="utf-8") as handle:
        outside = json.load(handle)
    if outside.get("counts", {}).get("documents") != documents:
        raise SystemExit(
            f"document count disagrees: export {documents}, manifest {outside.get('counts', {}).get('documents')}"
        )

print(f"{len(names)} members, {documents} documents")
PY

# The knowledge base seed must carry the canonical trees, and must NOT carry the
# engagement journals or the disposable index: those are the parts that quote what
# was found on target, and they are not publishable.
check "knowledge base carries the canonical trees only" python3 - "$seed" <<'PY'
import sys, tarfile

seed = sys.argv[1]
with tarfile.open(f"{seed}/sedna-kb.tar.gz") as archive:
    names = archive.getnames()

top = {name.split("/")[0] for name in names}
required = {"semantic_bundles", "manifests", "semantic_verification"}
missing = required - top
if missing:
    raise SystemExit(f"missing from the seed: {sorted(missing)}")

forbidden = {"engagements", "indexes", "raw_src"}
present = forbidden & top
if present:
    raise SystemExit(f"must never be published: {sorted(present)}")

bundles = [n for n in names if n.startswith("semantic_bundles/") and not n.endswith("/")]
if not bundles:
    raise SystemExit("no bundles in the seed")
print(f"{len(top)} top-level entries, {len(bundles)} bundle files")
PY

check "the redaction report names what was removed, without quoting it" python3 - "$seed" <<'PY'
import re, sys

path = f"{sys.argv[1]}/REDACTION-REPORT.md"
with open(path, encoding="utf-8") as handle:
    text = handle.read()

if len(text.strip()) < 200:
    raise SystemExit("the report is too short to be a report")

classes = sorted(set(re.findall(r"\b(?:flag_htb|flag_ctf|private_key|aws_access_key|github_token|openai_key|anthropic_key|jwt|secret_assignment)\b", text)))
if not classes:
    raise SystemExit("no redaction classes named")

# A report that names a class and then shows the value defeats its own purpose: the
# values must appear only as the [REDACTED-...] marker.
leaked = [line for line in text.splitlines()
          if re.search(r"(?:HTB|CTF|flag)\{[A-Za-z0-9_!@#$%^&*+=?-]{4,}\}", line)]
if leaked:
    raise SystemExit(f"{len(leaked)} line(s) quote a flag-like literal")

print(f"{len(classes)} classes documented")
PY

echo
if (( failed > 0 )); then
    printf 'seed structure: %d passed, %d failed\n' "$passed" "$failed"
    exit 1
fi
printf 'seed structure: %d passed, 0 failed\n' "$passed"
