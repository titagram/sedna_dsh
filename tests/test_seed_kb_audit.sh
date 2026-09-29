#!/usr/bin/env bash
# Run the Sedna engine against the committed seed and demand that it works.
#
# This is the test that would have caught the worst bug this repository has had: the
# knowledge base seed packed the readable bundles but not the quarantine state, and
# shipped a source whose engagement artifact is (deliberately) not published. The
# repository is fail-closed, so ONE such source made the whole corpus invalid and
# every retrieval answered "no_applicable_knowledge" -- a knowledge base that
# confidently knows nothing, which no amount of listing files would reveal.
#
# So this test does not read the seed. It loads it, audits it, rebuilds the retrieval
# index from it, asks it a question, and asks it a question it must refuse.
#
# Cost: one virtualenv with the engine's dependencies. Set SEDNA_TEST_PYTHON to an
# interpreter that already has them (the installed stack's venv, for instance) to skip
# that. If the environment cannot provide one, the test says so and fails unless
# SEDNA_TEST_ALLOW_SKIP=1 -- a check that silently skips is the bug it is meant to
# catch.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

failures=0
ok() { printf '  ok   %s\n' "$*"; }
bad() { printf '  FAIL %s\n' "$*"; failures=$((failures + 1)); }

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

kb="$work/knowledge"
mkdir -p "$kb"
tar xzf "$repo/seed/sedna-kb.tar.gz" -C "$kb" || { bad "cannot unpack the seed"; exit 1; }

python_bin="${SEDNA_TEST_PYTHON:-}"
if [[ -z "$python_bin" ]]; then
    if python3 -m venv "$work/venv" >/dev/null 2>&1 && \
       "$work/venv/bin/python" -m pip install -q -e "$repo/engine" >/dev/null 2>&1; then
        python_bin="$work/venv/bin/python"
    else
        msg="cannot build a virtualenv with the engine's dependencies (network? python3-venv?)"
        if [[ "${SEDNA_TEST_ALLOW_SKIP:-0}" == "1" ]]; then
            printf '  SKIP %s\n' "$msg"
            exit 0
        fi
        bad "$msg"
        printf '        set SEDNA_TEST_PYTHON=/path/to/venv/bin/python, or SEDNA_TEST_ALLOW_SKIP=1 to accept the gap\n'
        exit 1
    fi
fi

driver="$repo/plugin/sedna/driver.py"
call() { # call <json> -> stdout
    printf '%s' "$1" | SEDNA_SRC="$repo/engine/src" SEDNA_KB_ROOT="$kb" "$python_bin" "$driver" 2>/dev/null
}

field() { # field <json> <python expression over `d`>
    python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
except Exception:
    print('unreadable'); raise SystemExit(0)
print($2)
"
}

echo "seed knowledge base audit (engine: $python_bin)"

# 1. the canonical corpus must validate as a whole -- this is the fail-closed contract
audit="$(call '{"op":"maintenance","args":{"operation":"audit"}}')"
succeeded="$(printf '%s' "$audit" | field x "d['data']['report']['succeeded']")"
sources="$(printf '%s' "$audit" | field x "d['data']['report']['canonical_source_count']")"
artifacts="$(printf '%s' "$audit" | field x "d['data']['report']['canonical_artifact_count']")"

if [[ "$succeeded" == "True" ]]; then
    ok "the canonical corpus validates ($sources sources, $artifacts artifacts)"
else
    bad "the canonical corpus does not validate -- this is the fail-closed trap: one invalid source means ZERO knowledge"
    printf '%s' "$audit" | field x "[i.get('code') for i in d['data']['report'].get('issues', [])][:3]" | sed 's/^/        issues: /'
fi
if [[ "$sources" =~ ^[0-9]+$ ]] && (( sources > 0 )); then
    ok "the seed carries canonical knowledge ($sources sources)"
else
    bad "the seed validates but carries no canonical sources"
fi

# 2. the disposable index is rebuilt from those bundles, and must cover them
rebuild="$(call '{"op":"maintenance","args":{"operation":"rebuild"}}')"
rebuilt="$(printf '%s' "$rebuild" | field x "d['data']['report']['succeeded']")"
indexed="$(printf '%s' "$rebuild" | field x "d['data']['report']['indexed_source_count']")"
if [[ "$rebuilt" == "True" ]] && [[ "$indexed" =~ ^[0-9]+$ ]] && (( indexed > 0 )); then
    ok "the retrieval index rebuilds from the seed ($indexed sources indexed)"
else
    bad "the retrieval index could not be built from the seed (succeeded=$rebuilt indexed=$indexed)"
fi

# 3. the four lanes must be able to return something. The exact query is not the
#    point -- the seed changes as the memory grows -- so several are tried and any
#    non-empty lane counts.
lanes_hit=""
for terms in '["enumeration"]' '["linux","privilege escalation"]' '["http","web"]' '["windows","smb"]' '["upload","php"]'; do
    answer="$(call "{\"op\":\"retrieve\",\"args\":{\"target\":\"10.10.10.1\",\"authorization_state\":\"authorized\",\"exact_targets\":[\"10.10.10.1\"],\"query_terms\":$terms,\"observed_services\":[\"http\"]}}")"
    total="$(printf '%s' "$answer" | field x "len(d['data']['references'])+len(d['data']['case_steps'])+len(d['data']['negative_cases'])+len(d['data']['decision_guidance'])")"
    if [[ "$total" =~ ^[0-9]+$ ]] && (( total > 0 )); then
        lanes_hit="$terms -> $total candidates"
        break
    fi
done
if [[ -n "$lanes_hit" ]]; then
    ok "the retrieval lanes return knowledge ($lanes_hit)"
else
    bad "every retrieval came back empty: the lanes cannot reach the seeded knowledge"
fi

# 4. fail closed: an unauthorized scope must return nothing at all
refusal="$(call '{"op":"retrieve","args":{"target":"10.10.10.1","authorization_state":"unknown","exact_targets":[],"query_terms":["enumeration"]}}')"
gap="$(printf '%s' "$refusal" | field x "d['data']['knowledge_gap']['code'] if d['data'].get('knowledge_gap') else None")"
leaked="$(printf '%s' "$refusal" | field x "len(d['data']['references'])+len(d['data']['case_steps'])+len(d['data']['negative_cases'])+len(d['data']['decision_guidance'])")"
if [[ "$gap" == "unauthorized_scope" ]] && [[ "$leaked" == "0" ]]; then
    ok "an unauthorized scope is refused with empty lanes (knowledge_gap=$gap)"
else
    bad "an unauthorized scope did not fail closed (gap=$gap, candidates=$leaked)"
fi

echo
if (( failures > 0 )); then
    printf 'seed kb audit: %d check(s) failed\n' "$failures"
    exit 1
fi
printf 'seed kb audit: all checks passed\n'
