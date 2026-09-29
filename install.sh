#!/usr/bin/env bash
# Install and start Sedna + Hindsight with Docker Compose.
#
#   ./install.sh                 install and start
#   ./install.sh --dry-run       say what would happen, change nothing
#   ./install.sh --port 3080     use another port for the web interface
#
# Everything runs in containers. This script installs nothing on the host and writes exactly
# one file, compose/.env, the first time -- and never again, because that file holds your
# provider choice and your bucket credentials.
#
# What it needs: Docker with the Compose v2 plugin (Docker Desktop covers macOS, Windows and
# Linux; on Linux, "docker compose" must exist, not only "docker-compose").
#
# What to expect: the first start loads the seed (866 documents) into an empty volume and
# re-embeds it, which takes roughly half an hour on a laptop. Later starts are immediate.
set -euo pipefail

DRY_RUN=false
PORT_OVERRIDE=""

usage() { sed -n '2,18p' "$0"; }
say()   { printf '%s\n' "$*"; }
warn()  { printf 'warning: %s\n' "$*" >&2; }
fail()  { printf 'error: %s\n' "$*" >&2; printf '\n' >&2; usage >&2; exit 1; }
step()  { printf '\n== %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)    usage; exit 0 ;;
        -n|--dry-run) DRY_RUN=true; shift ;;
        --port)       [ $# -ge 2 ] || fail "--port needs a number"
                      PORT_OVERRIDE="$2"; shift 2 ;;
        *)            fail "unknown option: $1" ;;
    esac
done

if [ -n "$PORT_OVERRIDE" ]; then
    case "$PORT_OVERRIDE" in
        *[!0-9]*) fail "--port needs a number, got '$PORT_OVERRIDE'" ;;
    esac
fi

HERE=$(cd "$(dirname "$0")" && pwd)
COMPOSE_DIR="$HERE/compose"
ENV_FILE="$COMPOSE_DIR/.env"
[ -f "$COMPOSE_DIR/docker-compose.yml" ] || fail "compose/docker-compose.yml is missing next to this script"

# A secret is generated locally, so that the first thing a new user does is not inventing a
# password for a database, and so that every machine does not share the one from the example.
generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    elif [ -r /dev/urandom ]; then
        od -An -tx1 -N24 /dev/urandom | tr -d ' \n'
    else
        printf 'sedna-local-%s-%s' "$$" "$RANDOM"
    fi
}

# bash's /dev/tcp works on Linux, macOS and Git Bash alike, which is why it is used instead of
# lsof, ss or netstat: those differ on every platform and none of them is reliably installed.
port_in_use() {
    # The descriptor is opened and closed inside the subshell on purpose. Closing it in the
    # parent (`exec 3<&-`) looks harmless and is not: when fd 3 was never opened, that is a
    # redirection error on `exec` with no command, and a non-interactive shell exits *there* --
    # bypassing `|| true` and printing nothing. It made this check fail silently, but only when
    # the port was in use, which is exactly when the message mattered.
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
        return 0
    fi
    return 1
}

env_value() {
    [ -f "$ENV_FILE" ] || return 1
    sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

step "this machine"
say "   host:  $(uname -s) $(uname -m)"
say "   docker is the only requirement; nothing is installed on the host"

step "checking docker"
command -v docker >/dev/null 2>&1 || fail "docker is not installed (Docker Desktop on macOS and Windows, Docker Engine on Linux)"
if ! docker compose version >/dev/null 2>&1; then
    fail "'docker compose' (the v2 plugin) is not available; this stack does not use docker-compose v1"
fi
say "   ok: $(docker compose version | head -1)"

step "configuration"
if [ -f "$ENV_FILE" ]; then
    say "   keeping your existing $ENV_FILE"
elif $DRY_RUN; then
    say "   would create $ENV_FILE from .env.example, with a generated database password"
else
    umask 077
    sed "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(generate_secret)|" \
        "$COMPOSE_DIR/.env.example" > "$ENV_FILE"
    say "   created $ENV_FILE with a generated database password"
    say "   edit it to choose your LLM provider (the LLM_* block); the defaults need no key"
fi

PORT="${PORT_OVERRIDE:-$(env_value DSH_PORT 2>/dev/null || true)}"
PORT="${PORT:-3080}"
if port_in_use "$PORT"; then
    fail "port $PORT on 127.0.0.1 is already taken -- something else is serving there. Use --port <other>, or stop it"
fi
say "   web interface will listen on 127.0.0.1:$PORT"

step "starting the stack"
if $DRY_RUN; then
    printf '   would run: cd %s && docker compose up -d\n' "$COMPOSE_DIR"
else
    cd "$COMPOSE_DIR"
    # The shell environment wins over .env during interpolation, so --port has to reach
    # compose this way: otherwise the check tests one port and the stack binds another.
    export DSH_PORT="$PORT"
    DOCKER_BUILDKIT=1 docker compose up -d
fi

step "done"
if $DRY_RUN; then
    say "   dry run finished: nothing was changed"
    exit 0
fi
say "   On a first run the stack is loading the seed; watch it with:"
say "     docker compose -f $COMPOSE_DIR/docker-compose.yml logs -f dsh"
say
say "   Your authenticated URL (the token is generated at every start and is the only way in):"
count=0
url=""
while [ "$count" -lt 30 ]; do
    url=$(docker compose -f "$COMPOSE_DIR/docker-compose.yml" logs dsh 2>/dev/null \
          | grep -o 'http://127.0.0.1:[0-9][0-9]*/?token=[A-Za-z0-9_-]*' | tail -1 || true)
    if [ -n "$url" ]; then break; fi
    count=$((count + 1))
    sleep 4
done
if [ -n "$url" ]; then
    say "     $url"
    say
    say "   When that page answers, verify the whole stack with: cd $COMPOSE_DIR && ./verify.sh"
else
    warn "the interface has not announced itself yet; read it with: docker compose -f $COMPOSE_DIR/docker-compose.yml logs dsh | grep token="
fi
