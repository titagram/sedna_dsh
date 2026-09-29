#!/usr/bin/env bash
# Boot DSH once, inside the image, with the real composition patch applied.
#
# Every earlier check in this Dockerfile answers "are the packages there". This one answers
# "does it run", and the difference is not academic: a patch row pointing at a file the image
# does not contain passes every dependency check, then exits -- and because the container has
# a restart policy, what an operator sees is a clean exit with no logs, restarting forever.
# That is the least debuggable failure this stack can produce, so it is caught here instead.
#
# What is asserted: the tree loads (no unresolved plugin, no missing module) and the web
# server comes up far enough to publish an authenticated URL. What is deliberately *not*
# asserted: anything needing the knowledge base, which does not exist at build time -- the
# seed is bind-mounted at runtime and the entrypoint bootstraps the base before starting DSH.
set -uo pipefail

export DSH_HOME=/tmp/bootcheck
rm -rf "$DSH_HOME"
mkdir -p "$DSH_HOME"
cp /opt/sedna/cordis.patch.yml "$DSH_HOME/cordis.patch.yml"

cd /tmp || exit 1
timeout 240 dsh web --no-open --port 3999 >/tmp/bootcheck.log 2>&1 &
pid=$!

ok=0
for _ in $(seq 1 60); do
    sleep 2
    if grep -qE 'token=' /tmp/bootcheck.log; then ok=1; break; fi
    if grep -qE 'ERR_MODULE_NOT_FOUND|failed to load|could not be resolved|Cannot find' /tmp/bootcheck.log; then break; fi
    kill -0 "$pid" 2>/dev/null || break
done

kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

if [ "$ok" = 1 ]; then
    echo "  DSH boots with the sedna-bridge row mounted"
    rm -rf "$DSH_HOME" /tmp/bootcheck.log
    exit 0
fi

echo "  DSH did not boot; refusing to ship this image. The log:"
sed 's/^/    | /' /tmp/bootcheck.log | tail -30
exit 1
