#!/usr/bin/env bash
# The host is not Linux.
#
# This stack claims to install and run on any machine, and the scripts a user runs on that
# machine are the part this claim actually tests. Two bugs of this class were found by hand in
# consecutive rounds and neither would have been caught by any other test in this suite:
#
#   * verify.sh parsed the engine's JSON with the HOST's python3. Fine on Linux; macOS has
#     python3 only with the Xcode command line tools, and Git Bash on Windows usually has none.
#     The tool a user runs to check their installation failed on exactly the platforms the
#     README claims, and passed on the one platform it was written on.
#   * docker-compose.yml published "127.0.0.1:${DSH_PORT:-3080}:3080" while the entrypoint ran
#     `dsh web --port "${DSH_PORT}"`: DSH_PORT is the host side, 3080 the container's, and
#     anywhere but the default the GUI was unreachable while the stack still looked healthy.
#
# The rule is mechanical, so it can be checked mechanically. A script COPIED INTO AN IMAGE runs
# on the image's Debian and may use everything Linux has. A script that runs ON THE HOST may
# not: it gets whatever the operator's machine happens to provide. This test classifies each
# script by asking the Dockerfiles which files they copy, rather than by a list maintained by
# hand, so a new container-side script is exempt automatically and a new host-side one is not.
#
# Comments are stripped before matching, so a script is free to *talk* about python3 -- as
# verify.sh does, to explain why it no longer uses it.

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

container_side() {
    local base f
    base="$(basename "$1")"
    for f in compose/Dockerfile compose/*/Dockerfile; do
        [ -f "$f" ] || continue
        grep -qE "^[[:space:]]*COPY[^#]*[[:space:]/]${base}([[:space:]]|$)" "$f" && return 0
    done
    return 1
}

# Patterns that mean "this assumes a GNU userland or a Linux-only tool on the host". Each one is
# absent or different on macOS, and absent on Windows outside WSL.
patterns=(
    '(^|[|;&]|\$\()[[:space:]]*python3?[[:space:]]|command -v python3'
    'sha256sum|md5sum'
    'stat -c'
    'readlink -f'
    'grep -P|grep -oP'
    'sed -i[[:space:]]'
    'date -d|date --date'
    'find[^|]*--?printf'
    'realpath'
    'sort -V'
    'mktemp -p'
    'getopt '
)

checked=0 skipped=0
# Scope: what a USER runs on their own machine. tools/ is excluded deliberately -- those are
# maintainer scripts (snapshot the seed, verify its redaction) that run on the publisher's Linux
# host and are allowed to need python3. Saying so out loud beats an unexplained exemption.
for f in install.sh compose/*.sh; do
    [ -f "$f" ] || continue
    if container_side "$f"; then
        skipped=$((skipped + 1))
        echo "  ok   $f runs inside an image, exempt"
        continue
    fi
    checked=$((checked + 1))
    body="$(sed 's/#.*$//' "$f")"
    for pat in "${patterns[@]}"; do
        hits="$(printf '%s\n' "$body" | grep -nE "$pat" | head -2)"
        if [ -n "$hits" ]; then
            echo "  FAIL $f assumes the host has: $pat"
            printf '%s\n' "$hits" | sed 's/^/       | /'
            fail=1
        fi
    done
done

if [ "$checked" -eq 0 ]; then
    echo "  FAIL no host-side script was checked -- the loop is not matching anything"
    fail=1
fi

# A host script that needs bash has to say so, because /bin/sh on macOS is bash in POSIX mode
# and on Debian is dash: `[[ ]]`, arrays and /dev/tcp are bash-only and silently wrong in dash.
for f in install.sh compose/verify.sh; do
    [ -f "$f" ] || continue
    head -1 "$f" | grep -qE '^#!.*bash' || { echo "  FAIL $f does not declare bash"; fail=1; }
done

if [ "$fail" -eq 0 ]; then
    echo "  ok   $checked host script(s) portable, $skipped container script(s) exempt"
    echo "portability ok"
else
    exit 1
fi
