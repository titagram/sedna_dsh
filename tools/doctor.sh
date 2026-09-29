#!/usr/bin/env bash
# Report whether this machine has what the stack in DEPENDENCIES.md needs.
#
# Read-only: nothing is installed, started, stopped or written.  Every check is the
# same one the installer or a user would make by hand -- a binary on PATH, a version,
# a file, an HTTP status code -- and each line says which component it is about and
# what was actually observed.  A component that is missing is a failure; a component
# that is optional (HexStrike, ollama, pt-report.py) is reported and never fails the run.
#
#   tools/doctor.sh
#
# Exit codes: 0 every mandatory component is present, 1 at least one is missing,
#             2 the script could not run (bad invocation).
#
# It reads no credential file: settings.yaml, hindsight.env and the plugin's
# config.json are never opened, and nothing secret is ever printed.  Every network
# probe has a short timeout, so the script cannot hang on a machine with nothing.
#
# Paths follow the installer's defaults and can be overridden the same way the
# installer allows: DSH_HOME, STACK_HOME, KB_ROOT (lib/00-common.sh).
set -uo pipefail

DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
STACK_HOME="${STACK_HOME:-$DSH_HOME/sedna}"
KB_ROOT="${KB_ROOT:-$DSH_HOME/knowledge/sedna}"

# The installer's own state file names the paths it actually used (--prefix, a
# moved venv); prefer it when it is readable, so the doctor describes the machine
# as installed rather than as assumed.
state_get() { # state_get <key> <default>
    local key="$1" default="$2" file="$DSH_HOME/sedna-stack.json"
    [[ -f "$file" ]] || { printf '%s' "$default"; return 0; }
    command -v python3 >/dev/null 2>&1 || { printf '%s' "$default"; return 0; }
    python3 - "$file" "$key" "$default" <<'PY' 2>/dev/null || printf '%s' "$default"
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle).get(sys.argv[2], sys.argv[3])
except Exception:
    value = sys.argv[3]
print(value if isinstance(value, str) else json.dumps(value))
PY
}

ENGINE_PYTHON="$(state_get engine_python "$STACK_HOME/.venv/bin/python")"
KB_DIR="$(state_get kb_root "$KB_ROOT")"
PLUGIN_DIR="$(state_get plugin_dir "$DSH_HOME/plugins/sedna")"

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BOLD=""
fi

missing=0
present=0
optional_found=0
optional_total=0

ok() { # ok <component> <detail>
    present=$((present + 1))
    printf '  %s[ok]%s       %-22s %s\n' "$C_GREEN" "$C_RESET" "$1" "$2"
}

absent() { # absent <component> <detail>
    missing=$((missing + 1))
    printf '  %s[missing]%s  %-22s %s\n' "$C_RED" "$C_RESET" "$1" "$2"
}

optional() { # optional <component> <detail> -- absent, but never a failure
    optional_total=$((optional_total + 1))
    printf '  %s[optional]%s %-22s %s\n' "$C_YELLOW" "$C_RESET" "$1" "$2"
}

optional_ok() { # optional_ok <component> <detail> -- present, never a failure
    optional_total=$((optional_total + 1))
    optional_found=$((optional_found + 1))
    printf '  %s[optional]%s %-22s %s\n' "$C_GREEN" "$C_RESET" "$1" "$2"
}

have() { command -v "$1" >/dev/null 2>&1; }

# http_code <url> -- status code, or 000 when nothing answers.  Bounded: connect 2s,
# total 3s, and no output beyond the code, so a stray page can never be printed.
http_code() {
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 "$1" 2>/dev/null)" || code="000"
    [[ -n "$code" ]] || code="000"
    printf '%s' "$code"
}

# version_at_least <version> <major> <minor>
version_at_least() {
    local version="$1" want_major="$2" want_minor="$3" major minor
    major="${version%%.*}"
    minor="${version#*.}"; minor="${minor%%.*}"
    [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || return 1
    (( major > want_major )) && return 0
    (( major == want_major && minor >= want_minor )) && return 0
    return 1
}

printf '%sdoctor: what this machine has for the Sedna + Hindsight DSH stack%s\n' "$C_BOLD" "$C_RESET"
printf '  dsh home : %s\n' "$DSH_HOME"
printf '  engine   : %s\n' "$STACK_HOME"
printf '  knowledge: %s\n' "$KB_DIR"

# ---------------------------------------------------------------- mandatory ----

# node >= 24.2 -- on PATH, then an nvm install the way lib/10-prereqs.sh looks for it.
node_bin=""
node_version=""
if have node; then
    node_bin="$(command -v node)"
    node_version="$(node -v 2>/dev/null)"
fi
node_version="${node_version#v}"
if [[ -z "$node_version" ]] || ! version_at_least "$node_version" 24 2; then
    for candidate in "$HOME"/.nvm/versions/node/*/bin/node; do
        [[ -x "$candidate" ]] || continue
        candidate_version="$("$candidate" -v 2>/dev/null)"; candidate_version="${candidate_version#v}"
        version_at_least "$candidate_version" 24 2 || continue
        node_bin="$candidate"; node_version="$candidate_version"
        break
    done
fi
if [[ -n "$node_bin" ]] && version_at_least "$node_version" 24 2; then
    if have node && [[ "$(command -v node)" == "$node_bin" ]]; then
        ok "node >= 24.2" "$node_bin ($node_version)"
    else
        ok "node >= 24.2" "$node_bin ($node_version; not the node on PATH)"
    fi
else
    have node && node_version="$(node -v 2>/dev/null; :)"
    absent "node >= 24.2" "found '${node_version:-none}' -- dsh needs >= 24.2 (import.meta.main, node:util parseEnv)"
fi

# npm -- beside the resolved node, as lib/20-dsh.sh looks for it.
npm_bin=""
if [[ -n "$node_bin" ]] && [[ -x "$(dirname "$node_bin")/npm" ]]; then
    npm_bin="$(dirname "$node_bin")/npm"
elif have npm; then
    npm_bin="$(command -v npm)"
fi
if [[ -n "$npm_bin" ]]; then
    ok "npm" "$npm_bin ($("$npm_bin" --version 2>/dev/null || echo 'version unknown'))"
else
    absent "npm" "not beside $node_bin and not on PATH -- it is what installs @deepseek-ai/dsh"
fi

# python >= 3.11 -- one of the interpreters lib/10-prereqs.sh probes.
python_bin=""
python_version=""
for candidate in python3.13 python3.12 python3.11 python3; do
    have "$candidate" || continue
    candidate_version="$("$candidate" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
    version_at_least "$candidate_version" 3 11 || continue
    python_bin="$(command -v "$candidate")"; python_version="$candidate_version"
    break
done
if [[ -n "$python_bin" ]]; then
    ok "python >= 3.11" "$python_bin ($python_version)"
else
    have python3 && python_version="$(python3 -V 2>&1)"
    absent "python >= 3.11" "found '${python_version:-none}' -- the engine needs >=3.11,<3.14, Hindsight >= 3.11"
fi

# git, curl, tar -- the loop in lib/10-prereqs.sh, one line each.
for tool in git curl tar; do
    if have "$tool"; then
        case "$tool" in
            git)  ok "git"  "$(command -v git) ($(git --version 2>/dev/null))" ;;
            curl) ok "curl" "$(command -v curl) ($(curl --version 2>/dev/null | head -1 | awk '{print $1, $2}'))" ;;
            tar)  ok "tar"  "$(command -v tar) ($(tar --version 2>/dev/null | head -1))" ;;
        esac
    else
        absent "$tool" "not on PATH -- the prerequisites step stops without it"
    fi
done

# systemd --user -- the two units in lib/80-services.sh.  A degraded user manager
# still runs units, so any state word other than empty counts as available.
systemd_state="$(systemctl --user is-system-running 2>/dev/null | head -1)"
if [[ -n "$systemd_state" ]]; then
    ok "systemd --user" "user manager reachable (state: $systemd_state)"
else
    absent "systemd --user" "systemctl --user does not answer -- no user units, no memory daemon, no web UI"
fi

# dsh -- on PATH (what lib/20-dsh.sh and lib/90-verify.sh want), or the wrapper the
# installer creates in ~/.local/bin when the global npm prefix is unwritable.
dsh_bin=""
if have dsh; then
    dsh_bin="$(command -v dsh)"
elif [[ -x "$HOME/.local/bin/dsh" ]]; then
    dsh_bin="$HOME/.local/bin/dsh"
fi
if [[ -n "$dsh_bin" ]]; then
    dsh_version="$(timeout 10 "$dsh_bin" --version 2>/dev/null | head -1)"
    if have dsh; then
        ok "dsh" "$dsh_bin (${dsh_version:-version unknown})"
    else
        ok "dsh" "$dsh_bin (${dsh_version:-version unknown}; not on PATH -- open a new shell)"
    fi
else
    absent "dsh" "neither 'dsh' on PATH nor ~/.local/bin/dsh -- run ./install.sh"
fi

# The Sedna plugin row: the installer's managed block in the host patch, or any row
# whose id is sedna.  Both are the same mount; the entry file is checked beside it.
patch_file="$DSH_HOME/cordis.patch.yml"
patch_note=""
if [[ -f "$patch_file" ]] && grep -qE '^[[:space:]]*-?[[:space:]]*id:[[:space:]]*sedna[[:space:]]*$' "$patch_file"; then
    patch_note="row found in $patch_file"
elif [[ -f "$patch_file" ]] && grep -qF 'sedna-stack managed block' "$patch_file"; then
    patch_note="managed block found in $patch_file"
else
    patch_note=""
fi
if [[ -n "$patch_note" ]]; then
    if [[ -f "$PLUGIN_DIR/index.mjs" ]] && [[ -f "$PLUGIN_DIR/driver.py" ]]; then
        ok "sedna plugin row" "$patch_note; entry files in $PLUGIN_DIR"
    else
        absent "sedna plugin row" "$patch_note, but $PLUGIN_DIR/index.mjs or driver.py is missing"
    fi
else
    absent "sedna plugin row" "no sedna row and no managed block in $patch_file -- the sedna_* tools stay invisible"
fi

# The engine virtualenv: an interpreter that can actually import sedna.
if [[ -x "$ENGINE_PYTHON" ]]; then
    engine_version="$("$ENGINE_PYTHON" -c 'import sedna;print(getattr(sedna, "__version__", "unknown"))' 2>&1 | tail -1)"
    if [[ "$engine_version" != *"Traceback"* ]] && [[ "$engine_version" != *"Error"* ]] && [[ -n "$engine_version" ]]; then
        ok "engine virtualenv" "$ENGINE_PYTHON (sedna $engine_version)"
    else
        absent "engine virtualenv" "$ENGINE_PYTHON exists but does not import sedna: $(printf '%s' "$engine_version" | head -c 120)"
    fi
else
    absent "engine virtualenv" "no executable interpreter at $ENGINE_PYTHON"
fi

# The knowledge base root: the canonical bundles are what retrieval reads.
bundle_count=0
[[ -d "$KB_DIR/semantic_bundles" ]] && bundle_count="$(find "$KB_DIR/semantic_bundles" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
if (( bundle_count > 0 )); then
    ok "knowledge base root" "$KB_DIR ($bundle_count bundles)"
else
    absent "knowledge base root" "no semantic_bundles under $KB_DIR -- retrieval would answer nothing"
fi

# Hindsight on 127.0.0.1:9177 -- the memory daemon the installer creates as
# sedna-hindsight.service.  It is part of the stack; only --llm skip omits it.
hindsight_code="$(http_code http://127.0.0.1:9177/health)"
if [[ "$hindsight_code" == "200" ]]; then
    ok "hindsight 127.0.0.1:9177" "/health returned 200"
else
    absent "hindsight 127.0.0.1:9177" "/health returned $hindsight_code -- memory is not being served (--llm skip omits it on purpose)"
fi

# ------------------------------------------------------------- the optional ----
# Never failures: the skills document these, the installer never installs them.

printf '\n  %soptional -- not installed by this repository%s\n' "$C_DIM" "$C_RESET"

hexstrike_code="$(http_code http://127.0.0.1:8888/health)"
if [[ "$hexstrike_code" == "200" ]]; then
    optional_ok "HexStrike :8888" "/health returned 200 (no installer support; see DEPENDENCIES.md)"
else
    optional "HexStrike :8888" "/health returned $hexstrike_code -- the offensive skills' scanning half needs it"
fi

ollama_code="$(http_code http://127.0.0.1:11434/api/tags)"
if [[ "$ollama_code" == "200" ]]; then
    optional_ok "ollama" "$(command -v ollama 2>/dev/null || echo 'binary not on PATH') and 127.0.0.1:11434 answers"
elif have ollama; then
    optional "ollama" "binary at $(command -v ollama) but nothing on 127.0.0.1:11434"
else
    optional "ollama" "no binary and nothing on 127.0.0.1:11434 -- needed only for --llm ollama"
fi

pt_report=""
if [[ -n "${PT_REPORT:-}" ]] && [[ -f "${PT_REPORT:-}" ]]; then
    pt_report="$PT_REPORT"
elif [[ -f ./pt-report.py ]]; then
    pt_report="$PWD/pt-report.py"
elif have pt-report.py; then
    pt_report="$(command -v pt-report.py)"
elif [[ -f "$HOME/hexstrike-kali-hermes/pt-report.py" ]]; then
    pt_report="$HOME/hexstrike-kali-hermes/pt-report.py"
fi
if [[ -n "$pt_report" ]]; then
    optional_ok "pt-report.py" "$pt_report"
else
    optional "pt-report.py" "not in the current directory, on PATH, or at ~/hexstrike-kali-hermes -- no rolling reports"
fi

# ----------------------------------------------------------------- summary -----

printf '\n'
if (( missing == 0 )); then
    printf '%sdoctor: %d mandatory ok, 0 missing, %d/%d optional present -- this machine can run the stack%s\n' \
        "$C_GREEN" "$present" "$optional_found" "$optional_total" "$C_RESET"
    exit 0
fi
printf '%sdoctor: %d mandatory ok, %d missing, %d/%d optional present -- the stack is not complete%s\n' \
    "$C_RED" "$present" "$missing" "$optional_found" "$optional_total" "$C_RESET"
printf '  the missing components and what they cost are in DEPENDENCIES.md\n'
exit 1
