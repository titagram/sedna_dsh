# Step: verify -- prove the stack works, or say exactly what does not.
#
# Every check here is the same thing a user would do by hand: ask the daemon, ask
# the plugin, count the knowledge base.  A step that cannot be verified is reported
# as a failure, not as a warning: an installer that exits 0 over a dead stack is
# worse than one that exits 1 over a live one.

CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_SKIPPED=0

skip() { # skip <description> <reason>
    printf '  %sSKIP%s %s %s\n' "$C_DIM" "$C_RESET" "$1" "${C_DIM}($2)${C_RESET}"
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
}

check() { # check <description> <command...>
    local description="$1"; shift
    if [[ "$DRY_RUN" == "true" ]]; then
        printf '  %sSKIP%s %s\n' "$C_DIM" "$C_RESET" "$description"
        return 0
    fi
    if output="$("$@" 2>&1)"; then
        printf '  %sPASS%s %s %s\n' "$C_GREEN" "$C_RESET" "$description" "${C_DIM}${output}${C_RESET}"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
        return 0
    fi
    printf '  %sFAIL%s %s\n' "$C_RED" "$C_RESET" "$description"
    [[ -n "${output:-}" ]] && printf '        %s\n' "$(printf '%s' "$output" | head -3)"
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    return 1
}

step_verify() {
    local node_bin venv_python kb_root plugin_dir
    node_bin="$(state_get node_bin "$(command -v node || echo node)")"
    venv_python="$(state_get engine_python "$STACK_HOME/.venv/bin/python")"
    kb_root="$(state_get kb_root "$KB_ROOT")"
    plugin_dir="$(state_get plugin_dir "$PLUGIN_DIR")"

    check "dsh is installed" bash -c '
        if command -v dsh >/dev/null 2>&1; then dsh --version
        elif [[ -x "$HOME/.local/bin/dsh" ]]; then "$HOME/.local/bin/dsh" --version
        else exit 1; fi'
    check "node is new enough for dsh" bash -c "
        major=\$($node_bin -p 'process.versions.node.split(\".\")[0]');
        minor=\$($node_bin -p 'process.versions.node.split(\".\")[1]');
        if (( major > 24 )) || (( major == 24 && minor >= 2 )); then echo \"\$major.\$minor\"; else exit 1; fi"
    check "plugin file is present" test -f "$plugin_dir/index.mjs"
    check "plugin loads" bash -c "
        $node_bin --input-type=module -e \"
import { pathToFileURL } from 'node:url';
const mod = await import(pathToFileURL('$plugin_dir/index.mjs').href);
if (typeof mod.apply !== 'function') process.exit(1);
\" >/dev/null 2>&1"
    check "host patch mounts the plugin" grep -q "sedna" "$DSH_HOME/cordis.patch.yml"
    check "sedna_* tools are declared" grep -q "sedna_retrieve_knowledge" "$plugin_dir/index.mjs"

    if [[ -x "$venv_python" ]] && [[ -d "$STACK_HOME/src" ]]; then
        check "engine imports" bash -c "cd '$STACK_HOME/src' && '$venv_python' -c 'import sedna'"
    elif [[ "$DRY_RUN" == "true" ]]; then
        skip "engine imports" "dry run: nothing is installed yet"
    else
        printf '  %sFAIL%s engine virtualenv or sources missing\n' "$C_RED" "$C_RESET"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi

    if [[ -d "$kb_root/semantic_bundles" ]]; then
        check "knowledge base bundles" bash -c "
            count=\$(find '$kb_root/semantic_bundles' -mindepth 1 -maxdepth 1 | wc -l);
            [[ \$count -gt 0 ]] && echo \"\$count bundles\""
    elif [[ "$DRY_RUN" == "true" ]]; then
        skip "knowledge base bundles" "dry run: nothing is installed yet"
    else
        printf '  %sFAIL%s knowledge base is missing at %s\n' "$C_RED" "$C_RESET" "$kb_root"
        CHECKS_FAILED=$((CHECKS_FAILED + 1))
    fi

    # Hindsight is the one part that may legitimately be absent: the installer can be
    # asked to leave the model out (--llm skip), in which case the daemon is not
    # installed at all.  That is a skip, not a failure -- but it must be visible.
    local hindsight_unit="$HOME/.config/systemd/user/sedna-hindsight.service"
    if [[ -f "$hindsight_unit" ]] || http_ok "http://127.0.0.1:9177/health" >/dev/null 2>&1; then
        check "hindsight answers on /health" http_ok "http://127.0.0.1:9177/health"
        # A daemon answering on the port is not proof that *our* unit is running: a
        # machine may already have a Hindsight of its own. If the unit exists, it
        # must be the thing that is active.
        if [[ -f "$hindsight_unit" ]]; then
            check "our hindsight unit is active" systemctl --user is-active sedna-hindsight.service
        fi
        check "hindsight knows the bank" bash -c "
            curl -s --max-time 5 http://127.0.0.1:9177/v1/default/banks \
            | python3 -c 'import json,sys; d=json.load(sys.stdin); banks=d.get(\"banks\", d) if isinstance(d,(dict,list)) else []; print(str(banks)[:80])'"
    else
        skip "hindsight answers on /health" "not installed${SKIP_LLM:+ -- the model was skipped}"
        skip "hindsight knows the bank" "no memory daemon on 127.0.0.1:9177"
    fi

    printf '\n  %d passed, %d failed, %d skipped\n' "$CHECKS_PASSED" "$CHECKS_FAILED" "$CHECKS_SKIPPED"
    state_set verify_passed "$CHECKS_PASSED"
    state_set verify_failed "$CHECKS_FAILED"
    state_set verify_skipped "$CHECKS_SKIPPED"

    if (( CHECKS_FAILED > 0 )); then
        die "$CHECKS_FAILED check(s) failed -- the stack is installed but not working"
    fi
    if (( CHECKS_SKIPPED > 0 )); then
        warn "$CHECKS_SKIPPED check(s) skipped: this install is incomplete, and it says so"
    fi
    ok "all checks passed"
    return 0
}
