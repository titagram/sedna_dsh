#!/usr/bin/env bash
# Report whether the engine vendored in this repository still matches an upstream
# checkout -- the "keep the latest Sedna tuning in the repository" half of the point.
#
# Vendoring is deliberate: someone decides, in a reviewable commit, that a new revision
# is what this stack ships. What must not happen is that nobody *knows* when the copy
# has fallen behind, so this prints the difference and exits non-zero when there is one.
#
#   tools/check-engine-drift.sh ~/path/to/upstream-checkout
#   tools/check-engine-drift.sh /path/to/tree-with/src/sedna
#
# Exit codes: 0 no drift, 1 drift, 2 the comparison could not be made.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

upstream="${1:-}"
if [[ -z "$upstream" ]]; then
    printf 'usage: check-engine-drift.sh <upstream-checkout>\n' >&2
    exit 2
fi

# Accept either the repository root or a tree that already contains src/sedna.
for candidate in "$upstream/src/sedna" "$upstream/sedna" "$upstream"; do
    if [[ -d "$candidate" ]] && [[ -f "$candidate/__init__.py" ]]; then
        upstream_src="$candidate"
        break
    fi
done

if [[ -z "${upstream_src:-}" ]]; then
    printf 'check-engine-drift: cannot find the engine sources under %s\n' "$upstream" >&2
    printf '  looked for src/sedna, sedna, and the argument itself\n' >&2
    exit 2
fi

local_src="$repo/engine/src/sedna"
[[ -d "$local_src" ]] || { printf 'check-engine-drift: %s is missing\n' "$local_src" >&2; exit 2; }

printf 'vendored : %s\n' "$local_src"
printf 'upstream : %s\n' "$upstream_src"

upstream_rev="$(git -C "$(dirname "$(dirname "$upstream_src")")" log -1 --format='%h %cs %s' 2>/dev/null || true)"
[[ -n "$upstream_rev" ]] && printf 'revision : %s\n' "$upstream_rev"

# -q prints only the files that differ; --exclude keeps byte-compiled noise out of it.
difference="$(diff -rq --exclude='__pycache__' --exclude='*.pyc' "$local_src" "$upstream_src" 2>&1)"
status=$?

if (( status == 0 )); then
    files="$(find "$local_src" -name '*.py' | wc -l)"
    printf '\nno drift: the vendored engine is identical to the upstream checkout (%s python modules)\n' "$files"
    exit 0
fi

if (( status == 1 )); then
    count="$(printf '%s\n' "$difference" | wc -l)"
    printf '\ndrift: %s difference(s) between the vendored engine and upstream\n\n' "$count"
    printf '%s\n' "$difference" | head -40 | sed 's/^/  /'
    (( count > 40 )) && printf '  ... and %s more\n' "$((count - 40))"
    printf '\nTo take the upstream revision, see engine/VENDORED.md (and update it in the same commit).\n'
    exit 1
fi

printf 'check-engine-drift: the comparison failed:\n%s\n' "$difference" >&2
exit 2
