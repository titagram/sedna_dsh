#!/usr/bin/env bash
# Restore the seeded Hindsight bank into a running stack.
#
# Run this once after the first `docker compose up`. The import refuses a bank that already
# exists, and that refusal is the right way to enforce "never overwrite the operator's
# memory" -- the tool decides, not a script guessing at state.
#
# But a refusal is *not* automatically good news. The import re-embeds every memory, so on a
# slow machine it takes minutes; if it is interrupted (Ctrl-C, a sleeping laptop, a container
# restart) the bank exists and is incomplete, and a second run would refuse and look like
# success. So this script reports what is actually in the bank, and says plainly when that
# looks like a partial import rather than a restored one.
#
# `hindsight-admin` talks straight to PostgreSQL, not to the HTTP API, which is why this runs
# inside the Hindsight container with the seed mounted read-only at /seed.
set -euo pipefail
cd "$(dirname "$0")"

bank="${BANK:-hermes}"
archive="${ARCHIVE:-/seed/hindsight-bank.zip}"

psql() { docker compose exec -T postgres psql -U "${POSTGRES_USER:-hindsight}" -d "${POSTGRES_DB:-hindsight}" -tAc "$1" 2>/dev/null | tr -d '\r'; }

documents() { psql "select count(*) from documents"; }

echo "restoring bank '$bank' from the seed at $archive"
echo "(this re-embeds every memory: it takes minutes, and it is not hung)"
echo

out="$(docker compose exec -T hindsight /app/api/.venv/bin/hindsight-admin \
        import-bank --archive "$archive" --target-bank "$bank" 2>&1)" && status=0 || status=$?
printf '%s\n' "$out"

docs="$(documents || echo '?')"

if [[ "$status" == "0" ]]; then
    echo
    echo "imported: the bank holds $docs document(s)."
    exit 0
fi

if grep -qi "already exist" <<<"$out"; then
    echo
    if [[ "${docs:-0}" == "0" ]]; then
        echo "The bank exists but holds no documents: a previous import registered the bank"
        echo "and did not finish. Drop it and run this again:"
        echo "    docker compose exec postgres psql -U ${POSTGRES_USER:-hindsight} \\"
        echo "        -d ${POSTGRES_DB:-hindsight} -c \"delete from banks where bank_id='$bank'\""
        exit 1
    fi
    echo "The bank already exists and holds $docs document(s); nothing was touched."
    echo "If that is fewer than the seed contains, that import was interrupted: drop the bank"
    echo "(see above) and run this again, rather than assuming the memories are there."
    exit 0
fi

echo "import failed; the bank was not restored." >&2
exit 1
