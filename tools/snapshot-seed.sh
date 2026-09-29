#!/usr/bin/env bash
# Regenerate the memory seed that ships inside this repository.
#
# Two artifacts, two sources:
#
#   seed/hindsight-bank.zip    <- a live Hindsight bank, exported with
#                                 `hindsight-admin export-bank` and then redacted
#   seed/sedna-kb.tar.gz       <- the canonical Sedna knowledge base (bundles,
#                                 manifests, guards, verification records)
#
# Design rules:
#   * the live systems are only ever READ. The export is redacted as a copy; the
#     bank and the KB on disk are never rewritten;
#   * nothing is published unless tools/verify-seed.sh accepts it afterwards, so
#     artifacts are staged and moved into place only at the end;
#   * every artifact is checksummed into seed/SEED-MANIFEST.json, which is what
#     makes "the backup in the repo is up to date" a checkable claim rather than
#     a hope.
#
# Usage:
#   tools/snapshot-seed.sh [--bank hermes] [--kb-root DIR] [--out DIR] [--dry-run]
#
# Environment:
#   HINDSIGHT_ADMIN   path to the hindsight-admin CLI (auto-detected otherwise)
#   SEDNA_KB_ROOT     Sedna knowledge base root (auto-detected otherwise)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"

bank="${HINDSIGHT_BANK:-hermes}"
kb_root="${SEDNA_KB_ROOT:-}"
out="$repo/seed"
dry_run="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bank) bank="$2"; shift 2 ;;
        --kb-root) kb_root="$2"; shift 2 ;;
        --out) out="$2"; shift 2 ;;
        --dry-run) dry_run="true"; shift ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "snapshot-seed: unknown argument: $1" >&2; exit 2 ;;
    esac
done

log() { printf '[snapshot] %s\n' "$*"; }
die() { printf '[snapshot] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- discovery ----

find_admin() {
    if [[ -n "${HINDSIGHT_ADMIN:-}" ]]; then
        [[ -x "$HINDSIGHT_ADMIN" ]] || die "HINDSIGHT_ADMIN is set but not executable: $HINDSIGHT_ADMIN"
        printf '%s\n' "$HINDSIGHT_ADMIN"; return
    fi
    if command -v hindsight-admin >/dev/null 2>&1; then
        command -v hindsight-admin; return
    fi
    local candidate
    for candidate in \
        "$HOME/.hermes/hermes-agent/venv/bin/hindsight-admin" \
        "$HOME/.local/bin/hindsight-admin" \
        "$HOME/.venv/bin/hindsight-admin"; do
        [[ -x "$candidate" ]] && { printf '%s\n' "$candidate"; return; }
    done
    printf '\n'
}

find_kb_root() {
    if [[ -n "$kb_root" ]]; then
        [[ -d "$kb_root" ]] || die "kb root does not exist: $kb_root"
        printf '%s\n' "$kb_root"; return
    fi
    local candidate
    for candidate in \
        "$HOME/.sedna/knowledge" \
        "$HOME/.dsh/knowledge/sedna" \
        "$HOME/.hermes/knowledge/sedna"; do
        [[ -d "$candidate/semantic_bundles" ]] && { printf '%s\n' "$candidate"; return; }
    done
    printf '\n'
}

# The admin CLI must talk to the same embedded database the running server uses.
# Without HINDSIGHT_API_DATABASE_URL it silently connects to an empty default
# instance and fails with "relation public.documents does not exist", so the
# value is read from the live process -- one variable only, never the whole
# environ (which also carries the model provider key).
find_db_url() {
    if [[ -n "${HINDSIGHT_API_DATABASE_URL:-}" ]]; then
        printf '%s\n' "$HINDSIGHT_API_DATABASE_URL"; return
    fi
    local unit="${HINDSIGHT_UNIT:-}"
    if [[ -z "$unit" ]] && command -v systemctl >/dev/null 2>&1; then
        unit="$(systemctl --user list-units --type=service --all --no-legend 2>/dev/null \
            | awk '{print $1}' | grep -m1 '^hindsight' || true)"
    fi
    local pid="" value=""
    if [[ -n "$unit" ]]; then
        pid="$(systemctl --user show -p MainPID --value "$unit" 2>/dev/null || true)"
    fi
    if [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/environ" ]]; then
        value="$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | grep -m1 '^HINDSIGHT_API_DATABASE_URL=' || true)"
    fi
    if [[ -z "$value" && -n "$unit" ]] && command -v systemctl >/dev/null 2>&1; then
        # the service may be stopped; the unit file still names the instance
        value="$(systemctl --user cat "$unit" 2>/dev/null | grep -m1 -oE 'HINDSIGHT_API_DATABASE_URL=[^ "]+' || true)"
    fi
    printf '%s\n' "${value#HINDSIGHT_API_DATABASE_URL=}"
}

admin="$(find_admin)"
kb="$(find_kb_root)"
db_url="$(find_db_url)"

log "repository:  $repo"
log "hindsight:   ${admin:-<not found>}"
log "kb root:     ${kb:-<not found>}"
log "bank:        $bank"
log "db url:      ${db_url:-<not found>}"
log "output:      $out"
[[ "$dry_run" == "true" ]] && { log "dry run: nothing will be written"; exit 0; }

[[ -n "$admin" ]] || die "hindsight-admin not found; set HINDSIGHT_ADMIN"
[[ -n "$kb" ]] || die "Sedna knowledge base not found; set SEDNA_KB_ROOT"
command -v python3 >/dev/null || die "python3 is required"

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
mkdir -p "$out"

# ------------------------------------------------------- 1. hindsight export ----

log "exporting bank '$bank'"
raw="$staging/bank-raw.zip"
if [[ -n "$db_url" ]]; then
    HINDSIGHT_API_DATABASE_URL="$db_url" "$admin" export-bank --bank "$bank" --output "$raw" >"$staging/export.log" 2>&1 \
        || { sed 's/^/[snapshot]   /' "$staging/export.log" >&2; die "export-bank failed"; }
else
    log "warning: no HINDSIGHT_API_DATABASE_URL found; relying on the CLI default"
    "$admin" export-bank --bank "$bank" --output "$raw" >"$staging/export.log" 2>&1 \
        || { sed 's/^/[snapshot]   /' "$staging/export.log" >&2; die "export-bank failed"; }
fi
grep -E '^\[transfer\]' "$staging/export.log" | sed 's/^/[snapshot] /' || true
log "exported $(du -h "$raw" | cut -f1)"

log "redacting secret-shaped literals (the live bank is not modified)"
redacted="$staging/hindsight-bank.zip"
report="$staging/REDACTION-REPORT.md"

# The operator's own home directories are machine layout, not knowledge: they are
# meaningless on the machine that imports the seed and they identify this one.
# Home directories that appear *inside* lab documents (target-machine users) are
# left alone -- only the names listed here are rewritten.
redact_args=()
redact_args+=(--normalize-home "$(basename "${HOME:-/home/unknown}")")
if [[ -n "${SNAPSHOT_EXTRA_HOME_USERS:-}" ]]; then
    for user in ${SNAPSHOT_EXTRA_HOME_USERS}; do
        redact_args+=(--normalize-home "$user")
    done
fi
if [[ -n "${SNAPSHOT_EXTRA_REDACT:-}" ]]; then
    for expression in ${SNAPSHOT_EXTRA_REDACT}; do
        redact_args+=(--extra-redact "$expression")
    done
fi

python3 "$repo/tools/sanitize_export.py" --input "$raw" --output "$redacted" --report "$report" \
    "${redact_args[@]}" || die "redaction failed or left findings behind"

# ----------------------------------------------------------- 2. sedna kb seed --

log "packing the canonical knowledge base"
kb_seed="$staging/sedna-kb.tar.gz"
# Every directory the repository needs to *interpret* a source's state, not just
# the ones that hold readable knowledge.  `quarantine` and `semantic_quarantine`
# are load-bearing: a source whose bundle is absent is only valid if its quarantine
# record says so, and shipping the manifest without the record makes the whole
# repository fail closed -- the audit reports one invalid source and then zero
# canonical artifacts, so a restored install answers every retrieval with
# "no_applicable_knowledge".  Found by running the engine against the seed, not by
# looking at it; tests/test_seed_kb_audit.sh now runs it after every refresh.
kb_members=(
    semantic_bundles manifests semantic_verification
    semantic_compilation_guards promotion_publication_guards report-registry.json
    quarantine semantic_quarantine
)
present=()
for member in "${kb_members[@]}"; do
    [[ -e "$kb/$member" ]] && present+=("$member")
done
[[ "${#present[@]}" -gt 0 ]] || die "none of the expected KB members exist under $kb"

# Sources promoted from an engagement journal stay valid only while the physical
# artifact they were rendered from is present -- and that artifact lives under
# engagements/, which this seed must never publish: it quotes what was found on
# target.  The repository is fail-closed about it: a single such source makes the
# whole canonical view invalid, and every retrieval then answers
# "no_applicable_knowledge" -- silently, which is the worst way to be wrong.  So they
# are left out by name, and the reason is written into the manifest.
excluded_ids=()
while IFS= read -r sid; do
    [[ -n "$sid" ]] && excluded_ids+=("$sid")
done < <(
    python3 "$repo/tools/list_journal_promoted.py" "$kb"
    # Sources carrying material this seed does not publish: e-mail addresses, and public
    # IPv4 addresses.  They cannot be redacted in place -- a bundle's source_sha256 stops
    # validating, and the repository is fail-closed -- so they are excluded by name.
    python3 "$repo/tools/list_seed_unsafe_sources.py" "$kb"
)

exclude_args=()
for sid in "${excluded_ids[@]:-}"; do
    [[ -n "$sid" ]] || continue
    exclude_args+=(--exclude "*/$sid.json" --exclude "*/$sid.lock")
done
[[ "${#excluded_ids[@]}" -gt 0 ]] && log "leaving out ${#excluded_ids[@]} source(s) that cannot be published as they stand: an engagement artifact we do not publish, or a personal address"

tar czf "$kb_seed" ${exclude_args[@]+"${exclude_args[@]}"} -C "$kb" "${present[@]}" || die "tar failed"
printf '%s\n' ${excluded_ids[@]+"${excluded_ids[@]}"} >"$staging/kb-excluded.txt"
log "packed $(du -h "$kb_seed" | cut -f1) from ${#present[@]} members"

# -------------------------------------------------------------- 3. manifest ----

log "writing the manifest"
python3 - "$staging" "$out" "$bank" "$kb" "$admin" "${present[*]}" <<'PY'
import hashlib, json, os, subprocess, sys, zipfile
from datetime import datetime, timezone

staging, out, bank, kb_root, admin, kb_members = sys.argv[1:7]


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def version_of(cmd, *args):
    try:
        result = subprocess.run([cmd, *args], capture_output=True, text=True, timeout=60)
        first = (result.stdout or "").strip().splitlines()
        return first[0] if first else None
    except Exception:
        return None


def hindsight_version(admin_path):
    """The CLI has no --version; ask the venv that owns it."""
    venv_python = os.path.join(os.path.dirname(admin_path), "python3")
    if not os.path.exists(venv_python):
        venv_python = os.path.join(os.path.dirname(admin_path), "python")
    if not os.path.exists(venv_python):
        return None
    code = "import importlib.metadata as m;print(m.version('hindsight-all'))"
    return version_of(venv_python, "-c", code)


def home_relative(path):
    home = os.path.expanduser("~")
    if home and path.startswith(home):
        return "$HOME" + path[len(home):]
    return path


counts = {}
try:
    with zipfile.ZipFile(os.path.join(staging, "hindsight-bank.zip")) as zf:
        inner = json.loads(zf.read("manifest.json"))
    counts = {
        "documents": inner.get("document_count"),
        "facts": inner.get("fact_count"),
        "observations": inner.get("observation_count"),
        "mental_models": inner.get("mental_model_count"),
        "knowledge_pages": inner.get("knowledge_page_count"),
    }
except Exception as exc:  # a manifest we cannot read is a seed we cannot trust
    print(f"seed manifest: cannot read the export manifest: {exc}", file=sys.stderr)
    sys.exit(1)

artifacts = []
for name in ("hindsight-bank.zip", "sedna-kb.tar.gz", "REDACTION-REPORT.md"):
    path = os.path.join(staging, name)
    artifacts.append({
        "name": name,
        "bytes": os.path.getsize(path),
        "sha256": sha256(path),
    })

manifest = {
    "schema": 1,
    "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "bank": bank,
    "hindsight": {
        "admin": os.path.basename(admin),
        "version": hindsight_version(admin),
    },
    "sedna": {
        "kb_root": home_relative(kb_root),
        "members": kb_members.split(),
    },
    "counts": counts,
    "artifacts": artifacts,
    "how_to_restore": [
        "hindsight-admin import-bank --archive seed/hindsight-bank.zip --target-bank <name>",
        "tar xzf seed/sedna-kb.tar.gz -C \"$SEDNA_KB_ROOT\"",
    ],
}
with open(os.path.join(out, "SEED-MANIFEST.json"), "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("seed counts:", json.dumps(counts, sort_keys=True))
PY
[[ $? == 0 ]] || die "manifest generation failed"

# ------------------------------------------------------------- 4. publish ------

cp "$redacted" "$out/hindsight-bank.zip"
cp "$report" "$out/REDACTION-REPORT.md"
cp "$kb_seed" "$out/sedna-kb.tar.gz"
log "staged artifacts published into $out"

# ------------------------------------------------------------- 5. verify ------

if ! "$repo/tools/verify-seed.sh"; then
    die "verify-seed refused the freshly generated seed -- nothing is safe to commit"
fi
log "done: $(ls -1 "$out" | tr '\n' ' ')"
