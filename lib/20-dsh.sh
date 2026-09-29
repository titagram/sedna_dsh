# Step: dsh -- install DeepSeek Harness itself, pinned, and make sure it runs.
#
# DSH is a small public npm package (~27 KB, bin `dsh`) with no bootstrap step: the
# profile and settings.yaml materialise on first boot.  Two install shapes are
# supported because the global prefix is often not writable:
#
#   * `npm i -g @deepseek-ai/dsh@<pinned>`        when the prefix is writable
#   * `npm i -g --prefix ~/.dsh/sedna/npm ...`    otherwise, plus a ~/.local/bin/dsh
#     wrapper -- which also keeps the machine-wide Node install untouched.

step_dsh() {
    [[ -n "${NODE_BIN:-}" ]] || NODE_BIN="$(state_get node_bin "")"
    [[ -n "$NODE_BIN" ]] || die "node was not resolved by the prereqs step"
    export PATH="$(dirname "$NODE_BIN"):$PATH"

    local npm_bin
    npm_bin="$(dirname "$NODE_BIN")/npm"
    have "$npm_bin" || npm_bin="$(command -v npm || true)"
    [[ -n "$npm_bin" ]] || die "npm not found next to $NODE_BIN"

    mkdir -p "$DSH_HOME"

    local installed="" global_root=""
    if have dsh; then
        installed="$(dsh --version 2>/dev/null || true)"
    fi

    if [[ "$installed" == "$DSH_VERSION" ]]; then
        ok "dsh already installed: $installed"
    else
        global_root="$("$npm_bin" root -g 2>/dev/null || true)"
        local prefix_flags=(-g)
        if [[ -n "$global_root" ]] && [[ ! -w "$global_root" ]]; then
            warn "global npm prefix is not writable ($global_root); installing into $STACK_HOME/npm"
            mkdir -p "$STACK_HOME/npm"
            prefix_flags=(--prefix "$STACK_HOME/npm")
        fi
        run "$npm_bin" install "${prefix_flags[@]}" --no-fund --no-audit \
            "@deepseek-ai/dsh@${DSH_VERSION}" || die "npm install of dsh failed"

        if [[ "${prefix_flags[0]}" == "--prefix" ]]; then
            mkdir -p "$HOME/.local/bin"
            local bin="$STACK_HOME/npm/bin/dsh"
            [[ -x "$bin" ]] || bin="$STACK_HOME/npm/node_modules/.bin/dsh"
            [[ -x "$bin" ]] || die "dsh binary not found after a --prefix install"
            run ln -sf "$bin" "$HOME/.local/bin/dsh"
            export PATH="$HOME/.local/bin:$PATH"
            ensure_path_entry "$HOME/.local/bin"
        fi
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        ok "dry run: skipping the dsh version check"
        return 0
    fi

    have dsh || die "dsh is still not on PATH after installation (check ~/.local/bin)"
    installed="$(dsh --version 2>/dev/null || true)"
    [[ "$installed" == "$DSH_VERSION" ]] \
        || warn "dsh reports '$installed', expected '$DSH_VERSION' (continuing)"
    ok "dsh: $installed"
    state_set dsh_version "$installed"

    # The profile is created on first boot; doing it now keeps later steps simple.
    if [[ ! -f "$DSH_HOME/profiles/web/package.json" ]]; then
        log "creating the web profile (first boot materialises it)"
        run dsh --profile web --dump-config >/dev/null 2>&1 || true
    fi
    [[ -d "$DSH_HOME/profiles" ]] && ok "profile directory present: $DSH_HOME/profiles"
    return 0
}
