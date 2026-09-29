#!/usr/bin/env bash
# Sedna + Hindsight on DeepSeek Harness, installed from this repository.
#
# One command, no containers, no Hermes:
#
#     ./install.sh
#
# What it installs into $HOME (override with DSH_HOME / STACK_HOME / KB_ROOT):
#
#   ~/.dsh                      DSH itself, its profile, and the plugin row
#   ~/.dsh/sedna                the Sedna engine and its virtualenv
#   ~/.dsh/knowledge/sedna      the Sedna knowledge base, unpacked from seed/
#   ~/.dsh/plugins/sedna        the Cordis plugin that exposes the sedna_* tools
#   ~/.hindsight                the Hindsight daemon and the imported memory bank
#
# Design rules:
#   * idempotent: running it twice is safe and cheap;
#   * honest: every step ends with a check, and the installer fails if the thing
#     it installed does not actually answer;
#   * reversible: existing files are backed up before they are touched, and
#     nothing is deleted;
#   * --dry-run prints every command without running it.
#
# Usage:
#   ./install.sh [options]
#
#   --dry-run              print what would happen, change nothing
#   --yes                  do not ask for confirmation
#   --llm <api|ollama|skip>  how the stack reaches a model (asked interactively otherwise)
#   --only <step,...>      run only these steps
#   --skip <step,...>      run everything except these steps
#   --bank <name>          Hindsight bank to create/import (default: hermes)
#   --dsh-version <ver>    version of @deepseek-ai/dsh to install
#   --hindsight-version <ver>  version of hindsight-all to install
#   --uninstall            remove what this installer created (keeps your memory)
#   --purge-data           with --uninstall: also delete the memory (irreversible)
#   --help
#
# Steps: prereqs dsh settings plugin engine kb hindsight services verify
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO_ROOT

ONLY=""
SKIP=""
LLM_MODE=""
UNINSTALL="false"
PURGE_DATA="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=true; export DRY_RUN; shift ;;
        --yes|-y) ASSUME_YES=true; shift ;;
        --llm) LLM_MODE="$2"; shift 2 ;;
        --only) ONLY="$2"; shift 2 ;;
        --skip) SKIP="$2"; shift 2 ;;
        --bank) BANK_NAME="$2"; shift 2 ;;
        --dsh-version) DSH_VERSION="$2"; shift 2 ;;
        --hindsight-version) HINDSIGHT_VERSION="$2"; shift 2 ;;
        --uninstall) UNINSTALL="true"; shift ;;
        --purge-data) PURGE_DATA="true"; shift ;;
        --prefix) DSH_HOME="$2/.dsh"; STACK_HOME="$2/.dsh/sedna"; shift 2 ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
        *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done
export ASSUME_YES BANK_NAME DSH_VERSION HINDSIGHT_VERSION LLM_MODE UNINSTALL PURGE_DATA

# `--llm skip` is an explicit "the DSH half now, the memory daemon when I have a
# model" request.  Nothing downstream of the model can work without one, so
# pretending to install it and failing at the end would be worse than saying so.
SKIP_LLM="false"
[[ "$LLM_MODE" == "skip" ]] && SKIP_LLM="true"
export SKIP_LLM

for file in "$REPO_ROOT"/lib/*.sh; do
    # shellcheck disable=SC1090
    source "$file"
done

STEPS=(prereqs dsh settings plugin engine kb hindsight services verify)

# An uninstall is not a step in the install: it is the other direction, and running
# any installation step after it would rebuild what was just removed.
if [[ "$UNINSTALL" == "true" ]]; then
    STEPS=(uninstall)
    ONLY=""
    SKIP=""
fi

selected() {
    local step="$1"
    if [[ -n "$ONLY" ]]; then
        [[ ",$ONLY," == *",$step,"* ]] || return 1
    fi
    if [[ -n "$SKIP" ]]; then
        [[ ",$SKIP," == *",$step,"* ]] && return 1
    fi
    return 0
}

banner() {
    cat <<EOF
${C_BOLD}Sedna + Hindsight for DSH${C_RESET}
  repository : $REPO_ROOT
  dsh home   : $DSH_HOME
  engine     : $STACK_HOME
  knowledge  : $KB_ROOT
  bank       : $BANK_NAME
$( [[ "$DRY_RUN" == "true" ]] && echo "  mode       : DRY RUN -- nothing will be changed" )
EOF
}

banner

for step in "${STEPS[@]}"; do
    selected "$step" || { log "skipping step: $step"; continue; }
    function="step_${step}"
    if ! declare -F "$function" >/dev/null; then
        die "step '$step' has no implementation ($function) -- refusing to pretend"
    fi
    heading "$step"
    "$function" || die "step '$step' failed"
done

if [[ "$UNINSTALL" == "true" ]]; then
    printf '\nThe stack is gone.  Your memory and your DSH settings are not.\n'
else
    heading "summary"
    printf '  dsh        : %s\n' "$(state_get dsh_version 'not installed')"
    printf '  engine     : %s\n' "$(state_get engine_version 'not installed')"
    printf '  knowledge  : %s\n' "$(state_get kb_bundles 'not installed') bundles"
    printf '  bank       : %s (%s documents)\n' "$BANK_NAME" "$(state_get bank_documents unknown)"
    printf '  state file : %s\n' "$(state_file)"
    if [[ "${SKIP_LLM:-false}" == "true" ]]; then
        printf '\nNext: %s\n' "${C_BOLD}./install.sh --only settings --llm api|ollama${C_RESET}  then --only hindsight,services"
    else
        printf '\nNext: %s\n' "${C_BOLD}dsh web${C_RESET}  (it prints the URL and token to open)"
    fi
fi

if [[ "$DRY_RUN" == "true" ]]; then
    printf '\n%sDry run finished: nothing above actually happened.%s\n' "$C_YELLOW" "$C_RESET"
fi
