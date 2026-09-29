# Step: settings -- give the stack a model to talk to.
#
# Nothing in this stack works without an LLM: Hindsight extracts facts with one and
# Sedna plans and ingests with one.  DSH holds its routes in settings.yaml, so this
# step merges one provider block into that file:
#
#   * `api`     -- any OpenAI-compatible endpoint (a key the user supplies)
#   * `ollama`  -- a local ollama, whose models are discovered over HTTP
#
# The merge is done with DSH's own js-yaml (already on the machine, no extra
# dependency) and the file is backed up first.  If the merge cannot be performed
# safely the step refuses and prints the block to paste, rather than writing a
# settings file it cannot verify.

settings_path() { printf '%s/settings.yaml\n' "$DSH_HOME"; }

# Hindsight is a separate service with its own model configuration, and it is the
# only place besides settings.yaml where a key must be written.  The file is 0600
# and is the single source of truth for the daemon's environment.
write_llm_env() { # write_llm_env <provider> <model> <base-url> <api-key>
    local provider="$1" model="$2" base="$3" key="$4"
    local file="$STACK_HOME/hindsight.env"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "would write $file (provider=$provider model=$model)"
        return 0
    fi
    mkdir -p "$STACK_HOME"
    umask 077
    cat >"$file" <<EOF
# Written by install.sh.  Mode 0600: it carries the model credential.
HINDSIGHT_API_HOST=127.0.0.1
HINDSIGHT_API_PORT=9177
HINDSIGHT_API_DATABASE_URL=pg0://sedna-stack
HINDSIGHT_API_LLM_PROVIDER=$provider
HINDSIGHT_API_LLM_MODEL=$model
HINDSIGHT_API_LLM_TIMEOUT=300
HINDSIGHT_API_LLM_MAX_CONCURRENT=2
HINDSIGHT_API_LOG_LEVEL=info
HINDSIGHT_EMBED_DAEMON_IDLE_TIMEOUT=0
EOF
    [[ -n "$base" ]] && printf 'HINDSIGHT_API_LLM_BASE_URL=%s\n' "$base" >>"$file"
    [[ -n "$key" ]] && printf 'HINDSIGHT_API_LLM_API_KEY=%s\n' "$key" >>"$file"
    chmod 600 "$file"
    state_set hindsight_env "$file"
    state_set llm_provider "$provider"
    state_set llm_model "$model"
}

# settings_merge <provider-id> <json-object>  -- json is merged under llm-pi-ai.providers.<id>
settings_merge() {
    local provider_id="$1" config_json="$2" settings node_dir require_from
    settings="$(settings_path)"

    node_dir="$(dirname "$(command -v dsh)" 2>/dev/null || true)"
    local dsh_module=""
    for candidate in \
        "$(npm root -g 2>/dev/null)/@deepseek-ai/dsh" \
        "$STACK_HOME/npm/lib/node_modules/@deepseek-ai/dsh" \
        "$STACK_HOME/npm/node_modules/@deepseek-ai/dsh"; do
        [[ -f "$candidate/package.json" ]] && { dsh_module="$candidate"; break; }
    done

    if [[ -z "$dsh_module" ]]; then
        warn "cannot locate the dsh package to borrow js-yaml from"
        warn "add this block to $settings by hand:"
        printf '\nllm-pi-ai:\n  providers:\n    %s:\n%s\n' "$provider_id" "$config_json"
        return 1
    fi

    [[ "$DRY_RUN" == "true" ]] && { log "would merge provider '$provider_id' into $settings"; return 0; }

    [[ -f "$settings" ]] || printf '{}\n' >"$settings"
    local backup
    backup="$(backup_file "$settings")"
    [[ -n "$backup" ]] && log "backed up settings to $backup"

    # The provider config may contain an API key, so it is handed over in a 0600
    # temporary file rather than as an argument: argv is visible to `ps`.
    local config_file
    config_file="$(mktemp)"
    chmod 600 "$config_file"
    printf '%s\n' "$config_json" >"$config_file"

    python3 - "$settings" "$provider_id" "$config_file" "$dsh_module" <<'PY' || { rm -f "$config_file"; return 1; }
import subprocess, sys

settings_path, provider_id, config_file, dsh_module = sys.argv[1:5]
script = r"""
const fs = require('node:fs');
const { createRequire } = require('node:module');
const path = require('node:path');
const [settingsPath, providerId, configFile, dshModule] = process.argv.slice(2);
const require2 = createRequire(path.join(dshModule, 'package.json'));
const yaml = require2('js-yaml');
const provider = JSON.parse(fs.readFileSync(configFile, 'utf8'));
const doc = yaml.load(fs.readFileSync(settingsPath, 'utf8')) || {};
doc['llm-pi-ai'] = doc['llm-pi-ai'] || {};
doc['llm-pi-ai'].providers = doc['llm-pi-ai'].providers || {};
doc['llm-pi-ai'].providers[providerId] = provider;
doc['agent-default-model'] = { provider: providerId, model: provider.models[0].id };
fs.writeFileSync(settingsPath + '.tmp', yaml.dump(doc, { lineWidth: 120 }));
fs.renameSync(settingsPath + '.tmp', settingsPath);
console.log('merged provider ' + providerId);
"""
result = subprocess.run(
    ["node", "-e", script, settings_path, provider_id, config_file, dsh_module],
    capture_output=True, text=True,
)
if result.returncode != 0:
    print(result.stderr.strip() or "js-yaml merge failed", file=sys.stderr)
    sys.exit(1)
print(result.stdout.strip())
PY
    local rc=$?
    rm -f "$config_file"
    return $rc
}

ollama_models() { # prints "id<TAB>name" for each model on a local ollama
    curl -s --max-time 5 http://127.0.0.1:11434/api/tags 2>/dev/null \
        | python3 -c '
import json,sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for model in data.get("models", []):
    name = model.get("name") or model.get("model")
    if name:
        print(f"{name}\t{name}")
' 2>/dev/null
}

step_settings() {
    local settings
    settings="$(settings_path)"
    local mode="${LLM_MODE:-}"

    if [[ -z "$mode" ]]; then
        if [[ -r /dev/tty && "$ASSUME_YES" != "true" && "$DRY_RUN" != "true" ]]; then
            printf 'How should this stack reach a language model?\n'
            printf '  1) OpenAI-compatible endpoint (you supply a base URL and key) [default]\n'
            printf '  2) local ollama\n'
            printf '  3) skip for now (the stack installs but does nothing useful)\n'
            local choice
            read -r -p 'Choice [1]: ' choice </dev/tty || choice=1
            case "${choice:-1}" in
                2) mode=ollama ;;
                3) mode=skip ;;
                *) mode=api ;;
            esac
        else
            mode="skip"
        fi
    fi
    state_set llm_mode "$mode"

    case "$mode" in
        skip)
            warn "no model configured: retrieval works, planning and ingestion will not"
            return 0
            ;;
        ollama)
            local base="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
            if ! http_ok "$base/api/tags"; then
                warn "no ollama answering on $base"
                warn "install ollama (https://ollama.com) and pull a model, then re-run:"
                warn "  $0 --only settings --llm ollama"
                return 1
            fi
            local models model_id
            models="$(ollama_models)"
            [[ -n "$models" ]] || { warn "ollama is running but has no models"; return 1; }
            model_id="$(printf '%s\n' "$models" | awk -F'\t' '{print $1}' | head -1)"
            if [[ -r /dev/tty && "$ASSUME_YES" != "true" ]]; then
                printf '%s\n' "$models" | awk -F'\t' '{printf "  - %s\n", $1}' >/dev/tty
                read -r -p "Model [$model_id]: " answer </dev/tty || answer=""
                [[ -n "${answer:-}" ]] && model_id="$answer"
            fi
            local config
            config="$(python3 - "$model_id" "$base" <<'PY'
import json, sys
model, base = sys.argv[1:3]
print(json.dumps({
    "displayName": f"ollama ({base})",
    "api": "openai-completions",
    "baseURL": f"{base}/v1",
    "models": [{"id": model, "name": model}],
}))
PY
)"
            settings_merge "ollama-local" "$config" || return 1
            write_llm_env ollama "$model_id" "" "ollama"
            ok "ollama provider configured with model $model_id"
            ;;
        api)
            local base="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
            local key="${OPENAI_API_KEY:-}"
            local model="${OPENAI_MODEL:-gpt-4o-mini}"
            if [[ -r /dev/tty && "$ASSUME_YES" != "true" ]]; then
                read -r -p "Base URL [$base]: " answer </dev/tty || answer=""
                [[ -n "${answer:-}" ]] && base="$answer"
                read -r -s -p "API key (input hidden): " key </dev/tty || true
                printf '\n' >/dev/tty
                read -r -p "Model [$model]: " answer </dev/tty || answer=""
                [[ -n "${answer:-}" ]] && model="$answer"
            fi
            [[ -n "$key" ]] || die "an API key is required for --llm api"
            if [[ "$DRY_RUN" != "true" ]]; then
                # never echo the key, and never pass it as an argument: argv is
                # world-readable through /proc, the environment of this process is not.
                local config
                export SEDNA_LLM_MODEL="$model" SEDNA_LLM_BASE="$base" SEDNA_LLM_KEY="$key"
                config="$(python3 - <<'PY'
import json, os
model = os.environ["SEDNA_LLM_MODEL"]
base = os.environ["SEDNA_LLM_BASE"]
key = os.environ["SEDNA_LLM_KEY"]
print(json.dumps({
    "displayName": f"openai-compatible ({base})",
    "api": "openai-completions",
    "baseURL": base,
    "headers": {"Authorization": f"Bearer {key}"},
    "models": [{"id": model, "name": model}],
}))
PY
)"
                unset SEDNA_LLM_KEY
                settings_merge "sedna-endpoint" "$config" || return 1
                write_llm_env openai "$model" "$base" "$key"
                unset config
                chmod 600 "$settings" 2>/dev/null || true
                ok "endpoint configured (key not echoed)"
            else
                log "would configure endpoint $base with model $model"
            fi
            ;;
        *) die "unknown --llm value: $mode (use api, ollama or skip)" ;;
    esac
    return 0
}
