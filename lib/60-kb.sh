# Step: kb -- unpack the Sedna knowledge base seed.
#
# The seed is the canonical, verified material only: semantic bundles, manifests,
# guards and verification records.  Engagement journals and evidence are *not* in
# it (they are the operator's raw working data and they contain captured flags),
# and neither is the full-text index, which is rebuilt on demand.

step_kb() {
    local seed="$REPO_ROOT/seed/sedna-kb.tar.gz"
    [[ -f "$seed" ]] || die "missing seed: $seed"

    run mkdir -p "$KB_ROOT"
    run tar xzf "$seed" -C "$KB_ROOT" || die "cannot unpack the knowledge base seed"
    ok "knowledge base unpacked into $KB_ROOT"

    if [[ "$DRY_RUN" == "true" ]]; then
        ok "dry run: skipping the knowledge base check"
        return 0
    fi

    local bundles=0
    [[ -d "$KB_ROOT/semantic_bundles" ]] && bundles="$(find "$KB_ROOT/semantic_bundles" -mindepth 1 -maxdepth 1 | wc -l)"
    (( bundles > 0 )) || die "the knowledge base is empty after unpacking -- the seed is wrong"
    ok "knowledge base: $bundles bundles"
    state_set kb_bundles "$bundles"
    state_set kb_root "$KB_ROOT"

    # The retrieval index is disposable, and the seed deliberately does not carry it
    # (it is rebuilt from the canonical bundles).  It must be built here: until it
    # exists the retrieval lanes answer "no_applicable_knowledge" for every query --
    # a silent, convincing nothing, which is the worst possible first impression of a
    # knowledge base.  Measured: before the rebuild the four lanes are empty, after it
    # they return 5 references, 5 case steps, 5 negative cases and 1 piece of guidance
    # for a test query.
    local venv_python driver
    venv_python="$(state_get engine_python "$STACK_HOME/.venv/bin/python")"
    driver="$(state_get plugin_dir "$DSH_HOME/plugins/sedna")/driver.py"
    if [[ -x "$venv_python" ]] && [[ -f "$driver" ]]; then
        log "building the retrieval index from the canonical bundles"
        local outcome
        outcome="$(printf '%s' '{"op":"maintenance","args":{"operation":"rebuild"}}' \
            | SEDNA_SRC="$STACK_HOME/src" SEDNA_KB_ROOT="$KB_ROOT" "$venv_python" "$driver" 2>/dev/null \
            | python3 -c 'import json,sys
try:
    report = json.load(sys.stdin)["data"]["report"]
except Exception:
    print("unreadable"); raise SystemExit(0)
print(f"{report.get(\"indexed_source_count\")} sources, {report.get(\"indexed_artifact_count\")} artifacts, succeeded={report.get(\"succeeded\")}")' 2>/dev/null || true)"
        if [[ "$outcome" == *"succeeded=True"* ]]; then
            ok "retrieval index built: $outcome"
            state_set kb_indexed "$outcome"
        else
            warn "could not build the retrieval index ($outcome); the sedna_knowledge_maintenance tool"
            warn "  with operation=rebuild does the same thing once the stack is running"
        fi
    else
        warn "no engine virtualenv yet: the retrieval index will be built on first use"
    fi
        return 0
}
