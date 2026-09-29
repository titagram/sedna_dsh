# Step: engine -- the Sedna Python engine and its virtualenv.
#
# The engine is vendored in this repository under engine/ so the install needs no
# second clone.  It is installed as an editable source tree with its own venv: the
# plugin invokes its driver with that interpreter, which keeps the stack independent
# of whatever python the user happens to have on PATH.

step_engine() {
    [[ -n "${PYTHON_BIN:-}" ]] || PYTHON_BIN="$(state_get python_bin python3)"
    have "$PYTHON_BIN" || die "python interpreter not found: $PYTHON_BIN"

    local source="$REPO_ROOT/engine"
    if [[ ! -d "$source" ]] || [[ -z "$(ls -A "$source" 2>/dev/null)" ]]; then
        die "engine/ is empty in this checkout -- the repository is not installable as-is"
    fi

    mkdir -p "$STACK_HOME"
    if [[ -d "$STACK_HOME/src" ]]; then
        log "updating the existing engine tree"
        run rsync -a --delete --exclude '.venv' "$source/" "$STACK_HOME/src/" 2>/dev/null \
            || run cp -a "$source/." "$STACK_HOME/src/"
    else
        run mkdir -p "$STACK_HOME/src"
        run cp -a "$source/." "$STACK_HOME/src/"
    fi
    ok "engine sources in $STACK_HOME/src"

    if [[ ! -x "$STACK_HOME/.venv/bin/python" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log "would create a virtualenv at $STACK_HOME/.venv (with a pip bootstrap fallback)"
        else
            make_venv "$STACK_HOME/.venv" "$PYTHON_BIN" || die "cannot create the virtualenv for the engine"
        fi
    fi
    local venv_python="$STACK_HOME/.venv/bin/python"

    if [[ -f "$STACK_HOME/src/requirements.txt" ]]; then
        run "$venv_python" -m pip install --quiet --upgrade pip
        run "$venv_python" -m pip install --quiet -r "$STACK_HOME/src/requirements.txt" \
            || die "installing the engine requirements failed"
    elif [[ -f "$STACK_HOME/src/pyproject.toml" ]]; then
        run "$venv_python" -m pip install --quiet --upgrade pip
        run "$venv_python" -m pip install --quiet -e "$STACK_HOME/src" \
            || die "installing the engine failed"
    else
        warn "no requirements.txt or pyproject.toml in the engine tree"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        ok "dry run: skipping the engine import check"
        return 0
    fi

    # Import check: the plugin will do exactly this on first tool call, so doing it
    # now turns a silent runtime failure into an install failure.
    local version
    version="$(cd "$STACK_HOME/src" && "$venv_python" -c '
import sys
try:
    import sedna
except Exception as exc:
    print(f"import failed: {exc!r}", file=sys.stderr)
    sys.exit(1)
print(getattr(sedna, "__version__", "unknown"))
' 2>&1)" || die "the engine does not import with $venv_python: $version"
    ok "engine imports (version: $version)"
    state_set engine_version "$version"
    state_set engine_python "$venv_python"
    return 0
}
