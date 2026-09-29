#!/usr/bin/env bash
# Restore the seeded Hindsight bank into a running stack.
#
# Run this once after the first `docker compose up`. It is safe to re-run: the import
# refuses a bank that already exists, and that refusal is the desired outcome here — it is
# how "do not overwrite the operator's memory" is enforced by the tool rather than by a
# script that has to guess.
#
# `hindsight-admin` talks straight to PostgreSQL, not to the HTTP API, which is why this
# runs inside the Hindsight container with the seed mounted read-only at /seed.
set -euo pipefail
cd "$(dirname "$0")"

bank="${BANK:-hermes}"
archive="${ARCHIVE:-/seed/hindsight-bank.zip}"

echo "restoring bank '$bank' from the seed at $archive"
echo "(a refusal meaning the bank already exists is a success, not a failure)"

out="$(docker compose exec -T hindsight /app/api/.venv/bin/hindsight-admin \
        import-bank --archive "$archive" --target-bank "$bank" 2>&1)" && status=0 || status=$?
printf '%s\n' "$out"

if [[ "$status" == "0" ]]; then
    echo "imported."
elif grep -qi "already exist" <<<"$out"; then
    echo "the bank already exists: nothing was touched."
else
    echo "import failed; the bank was not restored." >&2
    exit 1
fi
