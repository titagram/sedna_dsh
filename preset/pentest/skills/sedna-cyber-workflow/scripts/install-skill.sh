#!/usr/bin/env bash
# install-skill.sh — install the sedna-cyber-workflow skill from this repository into the
# locations that the hosts actually load, or verify that they are already in sync.
#
#   ./scripts/install-skill.sh          # install / refresh both destinations
#   ./scripts/install-skill.sh --check  # compare hashes, change nothing, exit 1 on drift
#
# Why this exists: the skill had been installed by hand, and it ended up in six places with
# three different contents — two of them not under version control, holding work that existed
# nowhere else. One source (this repository) and one installer removes the cause; --check makes
# the drift visible instead of silent (see gate G15 in SKILL.md).
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SRC
readonly DESTINATIONS=(
  "${HOME}/.agents/skills/sedna-cyber-workflow"          # loaded by DSH
  "${HOME}/.hermes/skills/security/sedna-cyber-workflow" # loaded by Hermes
)

CHECK=0
case "${1:-}" in
  --check|-c) CHECK=1 ;;
  ""|--install) CHECK=0 ;;
  *) echo "usage: $(basename "$0") [--check]" >&2; exit 2 ;;
esac

# Files that make up the distributable unit. Backups, caches and editor droppings never travel.
file_list() {
  find "$1" -type f \
    ! -name '*.bak.*' ! -name '*.orig' ! -name '*~' \
    ! -name '*.pyc' \
    ! -path '*/__pycache__/*' ! -path '*/.pytest_cache/*' \
    ! -path '*/.mypy_cache/*' ! -path '*/.ruff_cache/*' ! -path '*/.git/*' \
    | sed "s|^$1/||" | sort
}

hash_of() { # hash_of <root> <relative-path>
  md5sum "$1/$2" 2>/dev/null | cut -d' ' -f1
}

source_list="$(file_list "$SRC")"
source_files="$(printf '%s\n' "$source_list" | wc -l)"
echo "source: $SRC"
echo "        $source_files files, commit $(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo 'n/a')"
[ "$CHECK" = 0 ] && echo "        SKILL.md md5 $(hash_of "$SRC" SKILL.md)"

drift=0
for dest in "${DESTINATIONS[@]}"; do
  if [ "$CHECK" = 1 ]; then
    if [ ! -d "$dest" ]; then
      echo "  DRIFT  $dest — not installed"
      drift=1
      continue
    fi
    dest_list="$(file_list "$dest")"
    if [ "$source_list" != "$dest_list" ]; then
      echo "  DRIFT  $dest — file set differs"
      diff <(printf '%s\n' "$source_list") <(printf '%s\n' "$dest_list") | sed 's/^/           /' || true
      drift=1
      continue
    fi
    mismatch=0
    while IFS= read -r rel; do
      [ -z "$rel" ] && continue
      [ "$(hash_of "$SRC" "$rel")" = "$(hash_of "$dest" "$rel")" ] || { echo "           differs: $rel"; mismatch=1; }
    done <<< "$source_list"
    if [ "$mismatch" = 1 ]; then
      echo "  DRIFT  $dest — content differs from the source"
      drift=1
    else
      echo "  ok     $dest"
    fi
  else
    mkdir -p "$dest"
    while IFS= read -r rel; do
      [ -z "$rel" ] && continue
      mkdir -p "$dest/$(dirname "$rel")"
      cp -p "$SRC/$rel" "$dest/$rel"
    done <<< "$source_list"
    # scripts must stay executable: a copied skill with a non-executable verifier fails silently
    find "$dest" -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} +
    echo "  installed $dest (SKILL.md md5 $(hash_of "$dest" SKILL.md))"
  fi
done

if [ "$CHECK" = 1 ]; then
  [ "$drift" = 0 ] && echo "result: in sync" || echo "result: DRIFT — reinstall from the source"
  exit "$drift"
fi
