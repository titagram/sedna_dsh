#!/usr/bin/env bash
# Fail-closed gate in front of every seed artifact.
#
# The repository ships data next to code. This script is what stands between a
# pentest machine's memory and a public repository, so it is deliberately dumb
# and easy to audit: it scans the seed, the code and the documentation with
# tools/scan_secrets.py and fails on any BLOCK finding.
#
# It is run by CI (.github/workflows/verify-seed.yml) and by hand before a
# commit. It never prints a secret it finds -- see tools/scan_secrets.py.
#
# Usage:
#   tools/verify-seed.sh [--strict-warn] [--quiet]
#
# Exit: 0 clean, 1 findings, 2 usage/setup error.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
scanner="$repo/tools/scan_secrets.py"

strict=()
quiet="false"
for arg in "$@"; do
    case "$arg" in
        --strict-warn) strict+=(--strict-warn) ;;
        --quiet) quiet="true" ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "verify-seed: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ ! -f "$scanner" ]]; then
    echo "verify-seed: scanner not found at $scanner" >&2
    exit 2
fi

command -v python3 >/dev/null || { echo "verify-seed: python3 is required" >&2; exit 2; }

# The seed plus everything a reader is expected to trust. tests/ is excluded on
# purpose: its fixtures are assembled at run time precisely so that the suite can
# exercise the scanner without containing a flag-shaped literal itself.
targets=()
for candidate in seed plugin preset engine lib tools docs README.md install.sh; do
    [[ -e "$repo/$candidate" ]] && targets+=("$repo/$candidate")
done

if [[ "${#targets[@]}" == "0" ]]; then
    echo "verify-seed: nothing to scan" >&2
    exit 2
fi

# An empty seed/ directory is a configuration accident, not a clean bill of health.
if [[ -d "$repo/seed" ]] && [[ -z "$(ls -A "$repo/seed" 2>/dev/null)" ]]; then
    echo "verify-seed: seed/ exists but is empty -- the repository would install an empty memory" >&2
    exit 2
fi

if [[ "$quiet" != "true" ]]; then
    echo "verify-seed: scanning ${#targets[@]} path(s)"
    for target in "${targets[@]}"; do
        printf '  - %s\n' "${target#"$repo"/}"
    done
fi

out="$(python3 "$scanner" --summary "${strict[@]}" "${targets[@]}" 2>&1)"
rc=$?
printf '%s\n' "$out"

if [[ "$rc" != "0" ]]; then
    echo
    echo "verify-seed: REFUSED -- secret-shaped material would be published." >&2
    echo "verify-seed: run the scanner without --summary for masked locations:" >&2
    echo "  python3 tools/scan_secrets.py ${targets[*]}" >&2
    echo "verify-seed: fix at the source, or regenerate the seed with:" >&2
    echo "  tools/snapshot-seed.sh --redact" >&2
    exit 1
fi

[[ "$quiet" == "true" ]] || echo "verify-seed: OK"
exit 0
