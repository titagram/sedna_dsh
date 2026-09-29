# Step: services -- keep both halves running under systemd --user.
#
# Two units, both user-scoped so nothing needs root:
#
#   sedna-hindsight.service   the memory daemon (127.0.0.1:9177)
#   sedna-dsh-web.service     the DSH web UI (127.0.0.1:3080)
#
# If a unit that already runs `dsh web` exists, this step leaves it alone and says
# so: replacing a working service that the user configured (ports, --trusted-host,
# a tunnel in front of it) would be a rude install.

hindsight_env_file() { state_get hindsight_env "$STACK_HOME/hindsight.env"; }

existing_dsh_web_unit() {
    local unit
    for unit in $(systemctl --user list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}'); do
        systemctl --user cat "$unit" 2>/dev/null | grep -q 'dsh.* web' && { printf '%s\n' "$unit"; return 0; }
    done
    return 1
}

step_services() {
    local api_bin env_file
    api_bin="$(hindsight_api)"
    env_file="$(hindsight_env_file)"

    if [[ "$DRY_RUN" != "true" && ! -x "$api_bin" ]]; then
        warn "hindsight-api not found at $api_bin -- skipping the daemon unit"
    else
        install_systemd_unit sedna-hindsight.service <<EOF
[Unit]
Description=Hindsight memory daemon (Sedna stack)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$HOME
EnvironmentFile=$env_file
ExecStart=$api_bin --host 127.0.0.1 --port 9177
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
        if service_enable_start sedna-hindsight.service; then
            ok "hindsight service active"
        else
            warn "hindsight service did not become active: journalctl --user -u sedna-hindsight.service -n 20"
        fi
    fi

    if existing_dsh_web_unit >/dev/null; then
        ok "a DSH web service is already running ($(existing_dsh_web_unit)); left untouched"
    else
        local dsh_bin
        dsh_bin="$(command -v dsh || true)"
        [[ -n "$dsh_bin" ]] || { warn "dsh not on PATH: not creating a web unit"; return 0; }
        install_systemd_unit sedna-dsh-web.service <<EOF
[Unit]
Description=DeepSeek Harness web UI (Sedna stack)
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$HOME
Environment=HOME=$HOME
ExecStart=$dsh_bin web --no-open --port 3080
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
        if service_enable_start sedna-dsh-web.service; then
            ok "dsh web service active on 127.0.0.1:3080 (the URL with its token is in the journal)"
        else
            warn "dsh web did not start: journalctl --user -u sedna-dsh-web.service -n 20"
        fi
    fi
    return 0
}
