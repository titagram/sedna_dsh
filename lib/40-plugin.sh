# Step: plugin -- put the Cordis plugin in place and mount it for every session.
#
# The mount is the cheap path verified on ai_server: copy a directory and add an
# absolute `file://` row.  No pnpm, no registry, no node_modules -- the plugin has
# no bare imports by design, which is exactly why this works.
#
# The row lives on the *host* plane ($DSH_HOME/cordis.patch.yml), so the sedna_*
# tools exist in every session and not only inside one preset.  The block is fenced
# with markers and rewritten wholesale on every install, which makes the step
# idempotent without parsing YAML we do not own.

MANAGED_BEGIN="# >>> sedna-stack managed block (rewritten by install.sh; do not edit inside)"
MANAGED_END="# <<< sedna-stack managed block"

plugin_row_block() {
    cat <<EOF
$MANAGED_BEGIN
- insert:
    - id: sedna
      name: file://$PLUGIN_DIR/index.mjs
      config:
        python: "$STACK_HOME/.venv/bin/python"
        driver: "$PLUGIN_DIR/driver.py"
        sednaSrc: "$STACK_HOME/src"
        knowledgeRoot: "$KB_ROOT"
        timeoutMs: 120000
$MANAGED_END
EOF
}

write_managed_block() { # write_managed_block <file>
    local file="$1" block
    block="$(plugin_row_block)"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "would write the plugin row into $file"
        printf '%s\n' "$block"
        return 0
    fi
    mkdir -p "$(dirname "$file")"
    [[ -f "$file" ]] || printf '[]\n' >"$file"

    SEDNA_ROW_BLOCK="$block" python3 - "$file" "$MANAGED_BEGIN" "$MANAGED_END" <<'PY' || return 1
import os
import sys

path, begin, end = sys.argv[1:4]
with open(path, encoding="utf-8") as handle:
    lines = handle.read().splitlines()

out, skipping = [], False
for line in lines:
    if line.strip() == begin:
        skipping = True
        continue
    if line.strip() == end:
        skipping = False
        continue
    if not skipping:
        out.append(line)

# the block itself is passed in through the environment to keep it out of argv
block = os.environ["SEDNA_ROW_BLOCK"]
text = "\n".join(out).strip()
if text in ("", "[]"):
    text = ""
new = (text + "\n" if text else "") + block.strip() + "\n"
with open(path, "w", encoding="utf-8") as handle:
    handle.write(new)
print(f"plugin row written to {path}")
PY
}

step_plugin() {
    [[ -d "$REPO_ROOT/plugin/sedna" ]] || die "plugin directory missing from the repository"

    mkdir -p "$PLUGIN_DIR"
    local file
    for file in index.mjs driver.py plugin.json; do
        run install -m 0644 "$REPO_ROOT/plugin/sedna/$file" "$PLUGIN_DIR/$file" \
            || die "cannot install plugin file: $file"
    done
    ok "plugin files installed in $PLUGIN_DIR"

    write_managed_block "$DSH_HOME/cordis.patch.yml"

    # The skills that make the tools usable are plain directories; DSH picks them
    # up from ~/.agents/skills for every session.
    if [[ -d "$REPO_ROOT/preset/pentest/skills" ]] && [[ -n "$(ls -A "$REPO_ROOT/preset/pentest/skills" 2>/dev/null)" ]]; then
        mkdir -p "$HOME/.agents/skills"
        local skill
        for skill in "$REPO_ROOT"/preset/pentest/skills/*/; do
            [[ -d "$skill" ]] || continue
            run cp -r "$skill" "$HOME/.agents/skills/" || warn "could not install skill $(basename "$skill")"
        done
        ok "skills installed in $HOME/.agents/skills"
    else
        log "no skills bundled in this checkout yet"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        ok "dry run: skipping the plugin import check"
        return 0
    fi

    [[ -f "$DSH_HOME/cordis.patch.yml" ]] || die "the host patch file was not written"
    grep -q "sedna-stack managed block" "$DSH_HOME/cordis.patch.yml" \
        || die "the managed block is missing from $DSH_HOME/cordis.patch.yml"

    # Import the plugin the same way DSH will: a syntax error here is a broken
    # install that would otherwise only show up as "the tools are missing".
    local node_bin="${NODE_BIN:-node}"
    if ! "$node_bin" --input-type=module -e "
import { pathToFileURL } from 'node:url';
const mod = await import(pathToFileURL('$PLUGIN_DIR/index.mjs').href);
if (typeof mod.apply !== 'function') { console.error('plugin has no apply()'); process.exit(1); }
console.log('plugin exports: ' + mod.name);
" 2>&1 | tail -2; then
        die "the plugin does not load -- check $PLUGIN_DIR/index.mjs"
    fi
    ok "plugin loads and exports apply()"
    state_set plugin_dir "$PLUGIN_DIR"
    return 0
}
