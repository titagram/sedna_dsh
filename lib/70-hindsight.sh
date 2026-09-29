# Step: hindsight -- install the memory daemon and load the seed bank into it.
#
# Hindsight is open source (vectorize-io/hindsight) and completely independent of
# the Hermes install this stack was first wired into: `hindsight-all` from PyPI
# brings the API, the admin CLI and `hindsight-embed`, which downloads and manages
# its own embedded PostgreSQL under ~/.pg0.  Nothing is installed system-wide.
#
# The seed is the portable `export-bank` archive: documents, facts, observations,
# bank config, mental models and knowledge pages, WITHOUT embeddings -- the import
# re-embeds with the local model, which is why a 8.9 MB archive can restore a
# 553 MB bank.

HINDSIGHT_VENV_NAME="hindsight-venv"

hindsight_python() { printf '%s/%s/bin/python\n' "$STACK_HOME" "$HINDSIGHT_VENV_NAME"; }
hindsight_admin()  { printf '%s/%s/bin/hindsight-admin\n' "$STACK_HOME" "$HINDSIGHT_VENV_NAME"; }
hindsight_api()    { printf '%s/%s/bin/hindsight-api\n' "$STACK_HOME" "$HINDSIGHT_VENV_NAME"; }

hindsight_env() { # print `env KEY=VAL ...` for the daemon
    local file
    file="$(state_get hindsight_env "$STACK_HOME/hindsight.env")"
    [[ -f "$file" ]] || return 1
    printf '%s\n' "$file"
}

step_hindsight() {
    # Measured, not guessed: Hindsight keeps its memory in an embedded PostgreSQL, and
    # its initdb refuses to run as root -- "initdb: error: cannot be run as root".  The
    # install would spend four minutes downloading torch before failing there with a
    # message from inside somebody else's tool, so say it now, while the reason is ours.
    # ...but never in a dry run: a plan is not an action, and a plan that refuses to
    # describe what it would do is not a plan.  Found by running the suite as root in a
    # container, where the dry-run check died on this guard.
    if [[ "$(id -u)" == "0" ]]; then
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            warn "running as root: the real install would stop here -- Hindsight's embedded"
            warn "  PostgreSQL refuses to run as root; run it as your own user instead"
        else
            die "Hindsight cannot be installed as root: its embedded PostgreSQL refuses to run as root.
       Run this installer as your own user (it installs into your home, and the service
       is a user service).  In a container, create a user and run it as that user, and
       give that user a writable HOME."
        fi
    fi

    if [[ "${SKIP_LLM:-false}" == "true" ]]; then
        warn "skipping Hindsight: it needs a model to extract memory with (--llm skip was requested)"
        warn "when you have one: ./install.sh --only settings --llm api|ollama && ./install.sh --only hindsight,services"
        state_set hindsight_skipped true
        return 0
    fi

    [[ -n "${PYTHON_BIN:-}" ]] || PYTHON_BIN="$(state_get python_bin python3)"
    local venv="$STACK_HOME/$HINDSIGHT_VENV_NAME"
    local env_file
    env_file="$(state_get hindsight_env "$STACK_HOME/hindsight.env")"

    if [[ ! -x "$venv/bin/python" ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log "would create a virtualenv at $venv (with a pip bootstrap fallback)"
        else
            make_venv "$venv" "$PYTHON_BIN" || die "cannot create the Hindsight virtualenv"
        fi
    fi
    local python_bin="$venv/bin/python"

    run "$python_bin" -m pip install --quiet --upgrade pip

    # Be honest about the size before downloading it: hindsight-all pulls the local
    # embedding stack (torch and friends), which is measured in gigabytes, and a
    # "one click" install that silently downloads 6 GB is not one click.
    if ! "$python_bin" -c 'import hindsight_api' >/dev/null 2>&1; then
        log "installing hindsight-all ${HINDSIGHT_VERSION}: this pulls the local embedding"
        log "  stack (torch) and typically several hundred megabytes to a few gigabytes;"
        log "  it is the price of embedding your memory locally instead of sending it out."
    fi
    run "$python_bin" -m pip install --quiet "hindsight-all==${HINDSIGHT_VERSION}" \
        || die "installing hindsight-all failed"
    ok "hindsight-all ${HINDSIGHT_VERSION} installed in $venv"

    if [[ ! -f "$env_file" ]]; then
        warn "no model environment file at $env_file (the settings step was skipped)"
        warn "run: $0 --only settings --llm ollama   (or --llm api)"
        return 1
    fi
    chmod 600 "$env_file" 2>/dev/null || true

    if [[ "$DRY_RUN" == "true" ]]; then
        ok "dry run: skipping the bank import"
        return 0
    fi

    local -a env_args=()
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        env_args+=("$line")
    done <"$env_file"

    local admin="$venv/bin/hindsight-admin"
    [[ -x "$admin" ]] || die "hindsight-admin is missing from $venv"

    if [[ "$(state_get bank_imported false)" == "true" ]]; then
        ok "bank '$BANK_NAME' was already imported by a previous run"
    else
        log "importing the seed bank as '$BANK_NAME' (this starts the embedded PostgreSQL)"
        env "${env_args[@]}" "$admin" import-bank \
            --archive "$REPO_ROOT/seed/hindsight-bank.zip" \
            --target-bank "$BANK_NAME" >"$STACK_HOME/import.log" 2>&1 \
            || { sed 's/^/    /' "$STACK_HOME/import.log" >&2; die "import-bank failed (see $STACK_HOME/import.log)"; }
        grep -Ei 'import|document|fact' "$STACK_HOME/import.log" | tail -3 | sed 's/^/    /'
        state_set bank_imported true
    fi

    local documents
    documents="$(python3 - "$REPO_ROOT/seed/hindsight-bank.zip" <<'PY'
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as archive:
    print(json.loads(archive.read("manifest.json")).get("document_count", "unknown"))
PY
)"
    state_set bank_documents "$documents"
    ok "bank '$BANK_NAME': $documents documents"
    return 0
}
