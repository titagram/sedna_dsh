#!/usr/bin/env bash
# Shared helpers for the installer steps.
#
# Every step is a function named step_<order>_<name>; install.sh sources the
# library files in order and runs the functions.  A step must:
#   * use `run` for anything that changes the system, so --dry-run is honest;
#   * end with a real check that the thing it installed actually works
#     (`verify_*`), because an installer that reports success while leaving an
#     inert stack is the failure mode this repository exists to avoid.
set -uo pipefail

# ------------------------------------------------------------------- basics ----

: "${DSH_HOME:=$HOME/.dsh}"
: "${STACK_HOME:=$DSH_HOME/sedna}"
: "${KB_ROOT:=$DSH_HOME/knowledge/sedna}"
: "${PLUGIN_DIR:=$DSH_HOME/plugins/sedna}"
: "${DSH_VERSION:=0.1.5-rc.2}"
: "${HINDSIGHT_VERSION:=0.9.1}"
: "${BANK_NAME:=hermes}"
: "${ASSUME_YES:=false}"
: "${DRY_RUN:=false}"
: "${LOG_PREFIX:=sedna-stack}"

export DSH_HOME STACK_HOME KB_ROOT PLUGIN_DIR

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BOLD=""
fi

log()  { printf '%s[%s]%s %s\n' "$C_DIM" "$LOG_PREFIX" "$C_RESET" "$*"; }
info() { printf '%s[%s]%s %s\n' "$C_BOLD" "$LOG_PREFIX" "$C_RESET" "$*"; }
ok()   { printf '%s[%s] ok%s %s\n' "$C_GREEN" "$LOG_PREFIX" "$C_RESET" "$*"; }
warn() { printf '%s[%s] warning:%s %s\n' "$C_YELLOW" "$LOG_PREFIX" "$C_RESET" "$*" >&2; }
die()  { printf '%s[%s] ERROR:%s %s\n' "$C_RED" "$LOG_PREFIX" "$C_RESET" "$*" >&2; exit 1; }

heading() {
    printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"
}

# ------------------------------------------------------------------- running ---

# run <command...>   -- print, then execute unless --dry-run
run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        printf '    %s(dry-run)%s %s\n' "$C_DIM" "$C_RESET" "$*"
        return 0
    fi
    printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RESET"
    "$@"
}

run_sh() { # run_sh '<shell code>' -- same contract, for pipelines
    if [[ "$DRY_RUN" == "true" ]]; then
        printf '    %s(dry-run)%s %s\n' "$C_DIM" "$C_RESET" "$1"
        return 0
    fi
    printf '    %s%s%s\n' "$C_DIM" "$1" "$C_RESET"
    bash -c "$1"
}

have() { command -v "$1" >/dev/null 2>&1; }

confirm() { # confirm <question>; honours --yes
    [[ "$ASSUME_YES" == "true" ]] && return 0
    [[ "$DRY_RUN" == "true" ]] && return 0
    local answer
    read -r -p "$1 [y/N] " answer </dev/tty || return 1
    [[ "$answer" =~ ^[Yy]$ ]]
}

# --------------------------------------------------------------- versioning ----

# ensure_path_entry <directory>
#
# An install that puts a binary in ~/.local/bin and leaves the PATH alone produces
# a user who cannot run the thing they just installed.  Add it to the login and
# interactive profiles, once, inside a marked block, after backing the files up.
ensure_path_entry() {
    local dir="$1" file marker_begin="# >>> sedna-stack PATH" marker_end="# <<< sedna-stack PATH"
    case ":$PATH:" in
        *":$dir:"*) : ;;
    esac

    local added="false" file
    for file in "$HOME/.profile" "$HOME/.bashrc"; do
        if [[ -f "$file" ]] && grep -qF "$marker_begin" "$file" 2>/dev/null; then
            continue
        fi
        if [[ ! -e "$file" ]]; then
            # no profile at all: creating ~/.profile is how a login shell finds it
            [[ "$file" == *".profile" ]] || continue
            printf '%s\n' "# ~/.profile: created by the sedna-stack installer" >"$file"
        fi
        backup_file "$file" >/dev/null || true
        {
            printf '\n%s\n' "$marker_begin"
            printf 'case ":$PATH:" in *":%s:"*) ;; *) PATH="%s:$PATH" ;; esac\n' "$dir" "$dir"
            printf 'export PATH\n'
            printf '%s\n' "$marker_end"
        } >>"$file"
        added="true"
    done

    if [[ "$added" == "true" ]]; then
        log "added $dir to PATH in your shell profiles (open a new shell, or: export PATH=\"$dir:\$PATH\")"
    fi
    return 0
}


# make_venv <directory> <python>: create a virtualenv that actually has pip.
#
# On a stock Debian/Ubuntu, `python3 -m venv` fails because ensurepip lives in a
# separate package (python3.x-venv) that a clean machine does not have.  The
# installer must not require root and must not tell the user to go and fix their
# system: it retries with --without-pip and bootstraps pip inside the environment,
# which needs nothing but curl.  Found the hard way, in a clean container.
make_venv() {
    local dir="$1" python="${2:-python3}" venv_log
    venv_log="$(mktemp)"

    if "$python" -m venv "$dir" >"$venv_log" 2>&1; then
        rm -f "$venv_log"
        return 0
    fi

    warn "python -m venv failed: $(grep -m1 -E 'ensurepip|not available|No module' "$venv_log" || head -1 "$venv_log")"
    log "retrying without ensurepip and bootstrapping pip inside the environment"

    rm -rf "$dir"
    if ! "$python" -m venv --without-pip "$dir" >>"$venv_log" 2>&1; then
        warn "python -m venv --without-pip failed too:"
        head -3 "$venv_log" | sed 's/^/    /'
        rm -f "$venv_log"
        warn "install the venv support for your python and re-run:"
        warn "  Debian/Ubuntu: sudo apt install python3-venv python3-pip"
        warn "  Fedora:        sudo dnf install python3-pip"
        warn "  macOS:         brew install python@3.12"
        return 1
    fi

    local get_pip="$dir/get-pip.py"
    if ! curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$get_pip" >>"$venv_log" 2>&1; then
        warn "cannot download get-pip.py (no network?)"
        rm -f "$venv_log"
        return 1
    fi
    if ! "$dir/bin/python" "$get_pip" >>"$venv_log" 2>&1; then
        warn "bootstrapping pip failed:"
        tail -3 "$venv_log" | sed 's/^/    /'
        rm -f "$venv_log"
        return 1
    fi
    rm -f "$get_pip" "$venv_log"

    if ! "$dir/bin/python" -m pip --version >/dev/null 2>&1; then
        warn "the virtualenv exists but pip does not work in it"
        return 1
    fi
    ok "virtualenv created with a bootstrapped pip: $dir"
    return 0
}


node_major() { # node_major [binary] -> major version or empty
    local binary="${1:-node}"
    have "$binary" || return 1
    "$binary" -p 'process.versions.node.split(".")[0]' 2>/dev/null
}

node_minor() {
    local binary="${1:-node}"
    "$binary" -p 'process.versions.node.split(".")[1]' 2>/dev/null
}

# node_ok <binary>: DSH needs Node >= 24.2 (import.meta.main, node:util parseEnv)
node_ok() {
    local binary="${1:-node}" major minor
    major="$(node_major "$binary")" || return 1
    minor="$(node_minor "$binary")" || return 1
    [[ -z "$major" ]] && return 1
    (( major > 24 )) && return 0
    (( major == 24 && minor >= 2 )) && return 0
    return 1
}

python_ok() { # python_ok <binary>: Hindsight and Sedna both want >= 3.11
    local binary="${1:-python3}" version
    have "$binary" || return 1
    version="$("$binary" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" || return 1
    local major="${version%%.*}" minor="${version#*.}"
    (( major > 3 )) && return 0
    (( major == 3 && minor >= 11 )) && return 0
    return 1
}

# ---------------------------------------------------------------- state file ---

state_file() { printf '%s/sedna-stack.json\n' "$DSH_HOME"; }

state_forget() { # state_forget <key>
    local key="$1" file
    file="$(state_file)"
    [[ "$DRY_RUN" == "true" ]] && return 0
    [[ -f "$file" ]] || return 0
    python3 - "$file" "$key" <<'PYEOF'
import json, os, sys
path, key = sys.argv[1:3]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except Exception:
    raise SystemExit(0)
data.pop(key, None)
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp, path)
PYEOF
}

state_set() { # state_set <key> <value>
    local key="$1" value="$2" file
    file="$(state_file)"
    [[ "$DRY_RUN" == "true" ]] && return 0
    mkdir -p "$(dirname "$file")"
    python3 - "$file" "$key" "$value" <<'PY'
import json, os, sys
path, key, value = sys.argv[1:4]
data = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        data = {}
data[key] = value
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp, path)
PY
}

state_get() { # state_get <key> [default]
    local key="$1" default="${2:-}" file
    file="$(state_file)"
    [[ -f "$file" ]] || { printf '%s\n' "$default"; return 0; }
    python3 - "$file" "$key" "$default" <<'PY'
import json, sys
path, key, default = sys.argv[1:4]
try:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
except Exception:
    data = {}
value = data.get(key, default)
print(value if isinstance(value, str) else json.dumps(value))
PY
}

# ---------------------------------------------------------------- utilities ----

backup_file() { # backup_file <path> -> prints the backup path
    local path="$1"
    [[ -f "$path" ]] || return 0
    [[ "$DRY_RUN" == "true" ]] && { printf '%s\n' "${path}.bak.dry-run"; return 0; }
    local backup="${path}.bak.sedna-stack.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$path" "$backup"
    printf '%s\n' "$backup"
}

install_systemd_unit() { # install_systemd_unit <name> (unit content on stdin)
    local name="$1" dir="$HOME/.config/systemd/user"
    mkdir -p "$dir"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "would write $dir/$name"
        cat >/dev/null
        return 0
    fi
    cat >"$dir/$name"
    chmod 644 "$dir/$name"
    systemctl --user daemon-reload || warn "systemctl --user daemon-reload failed"
}

service_active() { systemctl --user is-active --quiet "$1" 2>/dev/null; }

service_enable_start() { # service_enable_start <unit>
    run systemctl --user enable --now "$1" || return 1
    [[ "$DRY_RUN" == "true" ]] && return 0
    sleep 1
    service_active "$1"
}

http_ok() { # http_ok <url> [expected-code]
    local url="$1" expected="${2:-200}" code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)" || return 1
    [[ "$code" == "$expected" ]]
}
