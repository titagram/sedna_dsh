#!/usr/bin/env bash
# Run every check this repository has, in the order a change should be judged:
# the gate's own tests first (a broken gate is worse than no gate), then the
# artifacts, then the entry point's structure.
#
# CI runs exactly this, so "it passes locally" means something.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

failed=0
run() { # run <description> <command...>
    printf '\n\033[1m== %s\033[0m\n' "$1"
    shift
    if "$@"; then
        return 0
    fi
    printf '\033[31mFAILED: %s\033[0m\n' "$1"
    failed=$((failed + 1))
    return 1
}

run "the gate's own tests"          bash tests/test_scan_secrets.sh
run "the seed's structure"          bash tests/test_seed_structure.sh
run "the seed manifest"             python3 tools/verify-manifest.py seed
run "the seed's knowledge base works" bash tests/test_seed_kb_audit.sh
# The host is not Linux: this catches what only a hand audit found twice.
run "host-script portability"      bash tests/test_portability.sh
run "provider modes" bash tests/test_provider_modes.sh
# The tree is gated by verify-seed; the history is what gets published.
run "the published history"        bash tests/test_history_clean.sh
# Everything else runs in the development tree; this one runs where the user starts.
run "the first run from a clone"   bash tests/test_first_run.sh
# The stack's own scripts are checked here too: they run inside containers on every start, so a
# syntax error in them is a restart loop for the user, and nothing else in this suite would see it.
run "shell and python syntax"       bash -c 'bash -n install.sh && for f in tools/*.sh tests/*.sh compose/*.sh compose/dsh/*.sh; do bash -n "$f"; done && python3 -m py_compile tools/*.py compose/backup/*.py && echo "syntax ok"'
run "the installer plans a full run" ./install.sh --dry-run
run "no secret-shaped material"     tools/verify-seed.sh

printf '\n'
if (( failed > 0 )); then
    printf '\033[31m%s check(s) failed\033[0m\n' "$failed"
    exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
