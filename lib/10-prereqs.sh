# Step: prereqs -- what the rest of the install needs, checked before anything changes.
#
# The interesting one is Node.  DSH uses `import.meta.main` and `node:util.parseEnv`
# and therefore needs Node >= 24.2: on an older runtime it either crashes or, on
# 22/23, exits successfully doing nothing -- the worst possible failure mode for an
# installer, so the version is checked explicitly rather than assumed.

step_prereqs() {
    local os
    os="$(uname -s)"
    log "platform: $os $(uname -m)"

    local missing=()

    # ---- python -------------------------------------------------------------
    local python_bin=""
    for candidate in python3.13 python3.12 python3.11 python3; do
        if python_ok "$candidate"; then python_bin="$(command -v "$candidate")"; break; fi
    done
    if [[ -z "$python_bin" ]]; then
        missing+=("python>=3.11")
        warn "no python >= 3.11 on PATH"
        warn "  Debian/Ubuntu: sudo apt install python3.12 python3.12-venv python3-pip"
        warn "  macOS:         brew install python@3.12"
    else
        ok "python: $python_bin ($("$python_bin" -V 2>&1))"
        export PYTHON_BIN="$python_bin"
        state_set python_bin "$python_bin"
    fi

    # ---- node ---------------------------------------------------------------
    local node_bin=""
    if have node && node_ok node; then
        node_bin="$(command -v node)"
    else
        # nvm installs into $NVM_DIR/versions/node/*/bin and is often not on the
        # PATH of a non-interactive shell, so look for it explicitly.
        local candidate
        for candidate in "$HOME"/.nvm/versions/node/*/bin/node; do
            [[ -x "$candidate" ]] || continue
            if node_ok "$candidate"; then node_bin="$candidate"; break; fi
        done
    fi

    if [[ -z "$node_bin" ]]; then
        missing+=("node>=24.2")
        local current="none"
        have node && current="$(node -v 2>/dev/null)"
        warn "node is $current but DSH needs >= 24.2 (import.meta.main, node:util parseEnv)"
        if have nvm || [[ -s "$HOME/.nvm/nvm.sh" ]]; then
            warn "  nvm found: installing with 'nvm install 24'"
            if confirm "Install Node 24 with nvm now?"; then
                run_sh '. "$HOME/.nvm/nvm.sh" && nvm install 24 --no-progress'
                for candidate in "$HOME"/.nvm/versions/node/*/bin/node; do
                    node_ok "$candidate" && node_bin="$candidate"
                done
            fi
        else
            warn "  install Node 24 first: https://nodejs.org/en/download (or nvm, or nodesource)"
        fi
    fi

    if [[ -n "$node_bin" ]]; then
        ok "node: $node_bin ($("$node_bin" -v))"
        export NODE_BIN="$node_bin"
        export PATH="$(dirname "$node_bin"):$PATH"
        state_set node_bin "$node_bin"
    fi

    # ---- the rest -----------------------------------------------------------
    local tool
    for tool in git curl tar; do
        have "$tool" || missing+=("$tool")
    done
    have unzip || warn "unzip not found (only needed if you inspect the seed archives)"
    have pnpm || log "pnpm not found -- not needed: the plugin is installed as a file:// row, not from the registry"

    if (( ${#missing[@]} > 0 )); then
        die "missing prerequisites: ${missing[*]}
  Install them and re-run. Nothing has been changed on this system yet."
    fi

    ok "prerequisites satisfied"
    return 0
}
