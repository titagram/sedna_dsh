#!/usr/bin/env bash
# What gets published is the history, not the working tree.
#
# tools/verify-seed.sh gates the tree: it scans the files as they are now, which is what matters
# for the seed. But a secret that was committed once and deleted in the next commit is invisible
# to it and permanent in the published repository -- and this repository's history is exactly
# what leaves the machine, in 17 commits that had never been scanned by anything.
#
# Two checks, and the first is the one that matters most: this test proves its own detector
# works before trusting it. The portability lint in this directory accused two correct files of
# being broken, three separate times, because nothing checked the checker. A scan that silently
# matches nothing looks identical to a scan that found nothing, and only one of them is good
# news.

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

# Credential shapes worth blocking outright: keys, tokens, cloud identifiers, JWTs, private keys.
patterns='-----BEGIN [A-Z ]*PRIVATE KEY'
patterns="$patterns|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
patterns="$patterns|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}"
patterns="$patterns|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{30,}"
patterns="$patterns|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"

# 1. Does the detector detect? These are the documented example values of each provider -- they
#    are shaped like the real thing and are not secrets. If this fails, every check below is
#    meaningless, so it is a failure and not a warning.
# Built at runtime, not written literally -- and the scan is why. A scanner's fixtures live in
# the history that scanner reads, so a literal sample is a false positive in the very check it
# exists to validate. It caught mine, on the commit that added it.
samples="ghp_$(printf 'A%.0s' $(seq 1 36))
AKIA$(printf 'IOSFODNN7EXAMPLE')
eyJ$(printf 'hbGciOiJIUzI1NiJ9').$(printf 'eyJzdWIiOiIxMjM0NTY3ODkwIn0').$(printf 'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
-----BEGIN RSA PRIVATE $(printf 'KEY')-----"
# -e is not cosmetic: the first pattern starts with "-----BEGIN", and without it grep reads the
# whole alternation as options, matches nothing, and reports the history clean. That happened.
if printf '%s\n' "$samples" | grep -qE -e "$patterns"; then
    echo "  ok   the detector matches known-shaped secrets"
else
    echo "  FAIL the detector matches nothing -- its patterns are broken, so the scans below prove nothing"
    fail=1
fi

# 2. No environment file was ever committed. The generated compose/.env holds the database
#    password and is gitignored, and .env.example is meant to be committed -- so this asks for
#    a file whose name ends exactly in .env, which .env.example does not.
leaked="$(git log --all --diff-filter=A --name-only --format= 2>/dev/null | grep -E '(^|/)\.env$' | sort -u | head -3)"
if [ -z "$leaked" ]; then
    echo "  ok   no environment file has ever been committed"
else
    echo "  FAIL an environment file was committed: $leaked"
    fail=1
fi

# 3. No credential-shaped string in anything the history added. --format= keeps commit messages
#    out of the input on purpose: this prose talks about tokens and passwords constantly, and a
#    scan that flags the words would be turned off within a week.
added="$(git log -p -U0 --format= HEAD 2>/dev/null | grep -E '^\+' | grep -vE '^\+\+\+')"

# The fixtures are removed from the input, and only they. They are shaped like secrets by design,
# they are not secrets, and an earlier version of this file -- a commit that cannot be rewritten
# without rebasing unpushed work -- spells them out literally, so the scan read its own test data
# and reported a leak. The values are taken from $samples rather than written here, so the
# exclusion cannot itself become the kind of line it excludes. This does weaken the scan by
# exactly these four strings, and a real credential equal to a published example constant would
# be a secret nobody needs a scanner to find.
while IFS= read -r fixture; do
    added="$(printf '%s\n' "$added" | grep -vF -e "$fixture")"
done <<< "$samples"
if [ -z "$added" ]; then
    echo "  FAIL no added lines were read from the history -- the scan did not run"
    fail=1
else
    hits="$(printf '%s\n' "$added" | grep -nE -e "$patterns" | head -5)"
    if [ -z "$hits" ]; then
        echo "  ok   $(git rev-list --count HEAD) commit(s) scanned, no credential-shaped string added"
    else
        echo "  FAIL a credential-shaped string was committed:"
        printf '%s\n' "$hits" | cut -c1-140 | sed 's/^/       | /'
        fail=1
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "history ok"
else
    exit 1
fi
