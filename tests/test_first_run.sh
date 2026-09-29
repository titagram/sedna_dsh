#!/usr/bin/env bash
# The user's first minute, tested the way the user experiences it: a clone, and the installer.
#
# Everything else in this suite runs in the development tree, where a script can be executable
# because I chmod'ed it, a file can be present because I created it and not because it is
# tracked, and the line endings are whatever this filesystem writes. The executable bit is the
# sharpest example: it lives in the git index, not in the working tree, so a new script can work
# perfectly here and arrive as "permission denied" for everybody who clones. Nothing else could
# see that.

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone -q . "$work/clone" 2>/dev/null || { echo "  FAIL cannot clone the repository"; exit 1; }

# The bit a user relies on when they type ./install.sh. It is recorded in the index as 100755 or
# it is not, and no amount of local chmod changes what a clone delivers.
for f in install.sh compose/verify.sh; do
    if [ -x "$work/clone/$f" ]; then
        echo "  ok   $f arrives executable from a clone"
    else
        echo "  FAIL $f is committed without the executable bit -- ./$f is 'permission denied'"
        fail=1
    fi
done

# And the first run itself, in the mode that changes nothing. --dry-run must reach its own end:
# it is what an operator does before trusting anything here, and a path that assumes the
# development layout fails on the line where it uses a file it can see but did not get.
out="$(cd "$work/clone/compose" && bash ../install.sh --dry-run 2>&1)"
case "$out" in
    *"dry run finished"*)
        echo "  ok   a clean clone runs install.sh --dry-run to completion" ;;
    *)
        echo "  FAIL install.sh --dry-run did not finish from a clean clone:"
        printf '%s\n' "$out" | tail -6 | sed 's/^/       | /'
        fail=1 ;;
esac

# The clone must be unchanged afterwards: an installer that writes in dry-run mode is worse than
# one that writes, because it makes the check worthless.
if [ -e "$work/clone/compose/.env" ]; then
    echo "  FAIL --dry-run created compose/.env (it must change nothing)"
    fail=1
else
    echo "  ok   --dry-run left no .env behind"
fi

if [ "$fail" -eq 0 ]; then
    echo "first run ok"
else
    exit 1
fi
