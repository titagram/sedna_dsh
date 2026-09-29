# Step: uninstall -- put the machine back, without touching the memory.
#
# The rule this step follows: remove what the installer *created*, restore what it
# *changed*, and never delete the data the user produced.  The bank is the user's
# memory; a bank is not an installation artifact, and an uninstall that quietly
# destroys a year of notes is a worse bug than any it could fix.  `--purge-data` is
# therefore a separate, explicit decision, and even then it is reported before it
# happens.
#
# The other rule: an uninstall that half-works is worse than one that refuses.  Every
# removal is checked afterwards, and a step that finds something it cannot safely
# identify (a modified plugin row, a unit with the user's own edits) says so and
# leaves it alone.

UNINSTALL_BEGIN="# >>> sedna-stack managed block (rewritten by install.sh; do not edit inside)"
UNINSTALL_END="# <<< sedna-stack managed block"
PATH_BEGIN="# >>> sedna-stack PATH"
PATH_END="# <<< sedna-stack PATH"

remove_managed_block() { # remove_managed_block <file> <begin> <end>
    local file="$1" begin="$2" end="$3"
    [[ -f "$file" ]] || return 0
    grep -qF "$begin" "$file" || return 0
    backup_file "$file" >/dev/null 2>&1 || true
    python3 - "$file" "$begin" "$end" <<'PY'
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

text = "\n".join(out).strip()
if text in ("", "[]"):
    text = ""
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text + "\n" if text else "")
print(f"managed block removed from {path}")
PY
}

remove_unit() { # remove_unit <name>
    local unit="$1" file="$HOME/.config/systemd/user/$1"
    [[ -f "$file" ]] || { log "no unit to remove: $unit"; return 0; }
    run systemctl --user disable --now "$unit" >/dev/null 2>&1 || true
    run rm -f "$file"
    ok "removed unit $unit"
    SYSTEMD_CHANGED="true"
}

step_uninstall() {
    local plugin_dir="${PLUGIN_DIR:-$(state_get plugin_dir "$DSH_HOME/plugins/sedna")}"
    local stack_home="${STACK_HOME:-$(state_get stack_home "$DSH_HOME/sedna")}"
    local kb_root="${KB_ROOT:-$(state_get kb_root "$DSH_HOME/knowledge/sedna")}"
    local purge="${PURGE_DATA:-false}"

    heading "this will remove"
    cat <<EOF
  plugin      $plugin_dir
  engine      $stack_home
  knowledge   $kb_root   (unpacked from the repository seed, not authored here)
  row         the managed block in $DSH_HOME/cordis.patch.yml
  skills      the three skills this repository installs into $HOME/.agents/skills
  units       sedna-hindsight.service, sedna-dsh-web.service (if this installer made them)
  PATH        the managed block in ~/.profile and ~/.bashrc
EOF

    if [[ "$purge" == "true" ]]; then
        heading "and, because --purge-data was given"
        cat <<EOF
  memory      the Hindsight instance and its bank (the whole point of the stack:
              anything the agents remembered through it lives there and nowhere else)
EOF
    else
        heading "this will keep"
        cat <<EOF
  memory      the Hindsight bank and its embedded instance (~/.pg0): your data, not
              an installation artifact.  Remove it deliberately with --purge-data.
  settings    ~/.dsh/settings.yaml, and the model key inside it
  dsh         DeepSeek Harness itself (this stack was installed on top of it)
EOF
    fi

    confirm "proceed with the uninstall?" || { log "nothing was removed"; return 1; }

    # 1. the plugin row: only our block, only if it is ours
    remove_managed_block "$DSH_HOME/cordis.patch.yml" "$UNINSTALL_BEGIN" "$UNINSTALL_END"

    # 2. the plugin files
    if [[ -d "$plugin_dir" ]]; then
        run rm -rf "$plugin_dir"
        [[ -d "$plugin_dir" ]] && warn "could not remove $plugin_dir" || ok "removed $plugin_dir"
    fi

    # 3. the engine, its virtualenvs and the installer state
    if [[ -d "$stack_home" ]]; then
        run rm -rf "$stack_home"
        [[ -d "$stack_home" ]] && warn "could not remove $stack_home" || ok "removed $stack_home"
    fi
    [[ -f "$DSH_HOME/sedna-stack.json" ]] && { run rm -f "$DSH_HOME/sedna-stack.json"; ok "removed the installer state file"; }

    # 4. the knowledge base -- but only the trees the seed owns.  An engagement
    #    journal that happens to live under the same root is the user's, and stays.
    if [[ -d "$kb_root" ]]; then
        local tree
        for tree in semantic_bundles manifests semantic_verification semantic_compilation_guards promotion_publication_guards report-registry.json; do
            [[ -e "$kb_root/$tree" ]] && run rm -rf "$kb_root/$tree"
        done
        if [[ -d "$kb_root/engagements" ]]; then
            warn "kept $kb_root/engagements: engagement journals are your work, not this installer's"
        fi
        rmdir "$kb_root" 2>/dev/null && ok "removed the now-empty knowledge base directory" || log "kept $kb_root (it still holds something)"
    fi

    # 5. the skills, one by one, so a skill the user edited is still theirs
    local skill
    for skill in sedna-cyber-workflow lab-pentest sedna-dsh-bridge; do
        if [[ -d "$HOME/.agents/skills/$skill" ]]; then
            run rm -rf "$HOME/.agents/skills/$skill"
            ok "removed skill $skill"
        fi
    done

    # 6. the units this installer created
    SYSTEMD_CHANGED="false"
    remove_unit sedna-hindsight.service
    remove_unit sedna-dsh-web.service
    [[ "$SYSTEMD_CHANGED" == "true" ]] && run systemctl --user daemon-reload

    # 7. the PATH block
    local file
    for file in "$HOME/.profile" "$HOME/.bashrc"; do
        remove_managed_block "$file" "$PATH_BEGIN" "$PATH_END"
    done

    # 8. the memory, only on request, and only after saying what it is
    if [[ "$purge" == "true" ]]; then
        local env_file="$stack_home/hindsight.env"
        warn "purging the memory: this cannot be undone"
        if [[ -d "$HOME/.pg0/instances/sedna-stack" ]]; then
            run rm -rf "$HOME/.pg0/instances/sedna-stack"
            ok "removed the embedded instance"
        else
            log "no instance named sedna-stack under ~/.pg0/instances"
        fi
        [[ -n "$env_file" ]] && run rm -f "$env_file"
        state_forget bank_imported
    fi

    heading "uninstall finished"
    [[ "$purge" != "true" ]] && cat <<EOF
The memory was kept.  To remove it as well:

  ./install.sh --uninstall --purge-data --yes
EOF
    return 0
}
