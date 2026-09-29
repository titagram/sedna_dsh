#!/usr/bin/env bash
# Bootstrap the Sedna knowledge base inside a container.
#
# The seed in this repository is a *starting point*, not the knowledge base.  The rule that
# makes both true at once is: unpack only into an empty directory.  After that the volume is
# the operator's -- they add sources to it, and `git pull` on the repository can never
# collide with what they added, because the repository no longer describes the contents.
#
# The retrieval index is disposable and is deliberately not shipped with the seed: it is
# rebuilt from the canonical bundles.  Rebuilding it is not optional, because until it exists
# every retrieval lane answers "no_applicable_knowledge" -- a silent, convincing nothing.
#
# Container contract:
#   /data/kb   the knowledge base volume (persisted)
#   /seed      the seed artifacts copied into the image, read-only
#   SEDNA_SRC  the engine sources
#
# Idempotent: run it on every start.
set -euo pipefail

KB_ROOT="${SEDNA_KB_ROOT:-/data/kb}"
SEED_DIR="${SEDNA_SEED_DIR:-/seed}"
SEDNA_SRC="${SEDNA_SRC:-/opt/sedna/src}"
DRIVER="${SEDNA_DRIVER:-/opt/sedna/driver.py}"
PYTHON="${SEDNA_PYTHON:-python3}"

log() { printf '[kb] %s\n' "$*" >&2; }
fail() { printf '[kb] error: %s\n' "$*" >&2; exit 1; }

# The engine's engagement repository validates the knowledge root's mode by *equality*:
# `_validate_directory(self._root_fd, label="knowledge root", expected_mode=0o700)`. A fresh
# volume inherits the image directory's 0755, so every journal-backed operation -- including
# ingest -- fails with "knowledge root has an unsafe mode" while retrieval keeps working,
# which makes it look like a plugin problem rather than a permissions one. Enforced here as
# well as in the image, because a volume created by an older image keeps its mode.
if [[ -d "$KB_ROOT" ]]; then
    current="$(stat -c '%a' "$KB_ROOT" 2>/dev/null || echo unknown)"
    if [[ "$current" != "700" ]]; then
        if chmod 700 "$KB_ROOT" 2>/dev/null; then
            log "knowledge root mode $current -> 700 (the engine requires exactly this)"
        else
            # Measured, not imagined: chmod fails exactly this way on a read-only mount, and on
            # Docker Desktop for macOS and Windows the same happens for a bind-mounted host
            # folder, because Unix modes are not expressible there. Without this branch the
            # failure was silent and the run continued with a 0755 knowledge base: journal-backed
            # operations then failed with "unsafe mode" while retrieval kept answering, which is
            # the plugin-shaped confusion the comment above this block exists to prevent.
            fail "the knowledge root $KB_ROOT is mode $current and its mode cannot be changed. The engine validates that directory by equality and refuses every journal-backed operation -- ingest included -- while retrieval keeps working, so it looks like a plugin fault. A bind-mounted host folder does this on Docker Desktop for macOS and Windows, where Unix modes are not expressible; use the Docker-managed 'kb' volume instead."
        fi
    fi
fi
[[ -f "$DRIVER" ]] || fail "engine driver not found at $DRIVER"
[[ -d "$SEDNA_SRC" ]] || fail "engine sources not found at $SEDNA_SRC"

mkdir -p "$KB_ROOT"

# 1. Seed, only into an empty base.  A non-empty base is somebody's knowledge: leave it alone.
if [[ -z "$(ls -A "$KB_ROOT" 2>/dev/null)" ]]; then
    seed="$SEED_DIR/sedna-kb.tar.gz"
    [[ -f "$seed" ]] || fail "the knowledge base is empty and no seed is present at $seed"
    log "empty knowledge base: unpacking the seed"
    tar xzf "$seed" -C "$KB_ROOT" || fail "cannot unpack $seed"
    log "seeded $(find "$KB_ROOT/semantic_bundles" -maxdepth 1 -name 'source-*.json' 2>/dev/null | wc -l) source(s)"
else
    log "knowledge base present: leaving it as it is ($(find "$KB_ROOT/semantic_bundles" -maxdepth 1 -name 'source-*.json' 2>/dev/null | wc -l) source(s))"
fi

# 2. Index, only when missing -- or when it is poisoned.  A failed audit or rebuild leaves
#    `indexes/.retrieval.sqlite.unavailable` behind, and while that marker exists every lane
#    is blocked: the knowledge base looks empty and nothing says why.  Treat it as a
#    missing index, which it is.
poison="$KB_ROOT/indexes/.retrieval.sqlite.unavailable"
if [[ -f "$poison" ]]; then
    log "the retrieval index is marked unavailable (a previous rebuild failed): rebuilding"
    rm -f "$poison"
fi
if [[ -z "$(ls -A "$KB_ROOT/indexes" 2>/dev/null)" ]]; then
    log "no retrieval index: building it from the canonical bundles (this is not optional)"
    outcome="$(printf '%s' '{"op":"maintenance","args":{"operation":"rebuild"}}' \
        | SEDNA_SRC="$SEDNA_SRC" SEDNA_KB_ROOT="$KB_ROOT" "$PYTHON" "$DRIVER" 2>/dev/null \
        | "$PYTHON" -c 'import json,sys
try:
    report = json.load(sys.stdin)["data"]["report"]
except Exception:
    print("unreadable"); raise SystemExit(0)
print(f"{report.get(\"indexed_source_count\")} sources, {report.get(\"indexed_artifact_count\")} artifacts, succeeded={report.get(\"succeeded\")}")' 2>/dev/null || true)"
    case "$outcome" in
        *succeeded=True*) log "retrieval index built: $outcome" ;;
        *) fail "the retrieval index could not be built ($outcome); retrieval would answer nothing" ;;
    esac
else
    log "retrieval index present: leaving it as it is"
fi

log "ready"
