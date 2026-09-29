#!/usr/bin/env bash
# Check that a running stack is actually working, not merely up.
#
# "Up" is not the claim this repository makes. The claims are: the knowledge base was seeded
# and indexed, the engine is importable inside the image, the retrieval lanes answer, and the
# bank is reachable. Each is checked here, and each fails loudly -- the silent failures in
# this stack are exactly the ones worth a script (an unindexed base answers everything with
# the same convincing nothing).
#
# Usage:  ./verify.sh          (from compose/, with the stack up)
set -uo pipefail
cd "$(dirname "$0")"

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$*"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n' "$*"; }
info() { printf '  ..   %s\n' "$*"; }

DC=(docker compose)
if [[ -f .env ]]; then DC+=(--env-file .env); fi

dsh_port="$(docker compose port dsh 3080 2>/dev/null | awk -F: '{print $NF}')"
his_port="$(docker compose port hindsight 8888 2>/dev/null | awk -F: '{print $NF}')"

echo "== services"
for svc in postgres hindsight dsh; do
    state="$("${DC[@]}" ps --format '{{.Service}} {{.State}} {{.Health}}' 2>/dev/null | awk -v s="$svc" '$1==s {print $2" "$3}')"
    case "$state" in
        running*|"running "*) ok "$svc: $state" ;;
        *) bad "$svc: ${state:-not running}" ;;
    esac
done

echo "== the memory API"
if [[ -n "$his_port" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$his_port/health" || true)"
    [[ "$code" == "200" ]] && ok "hindsight /health -> $code" || bad "hindsight /health -> ${code:-no answer}"
else
    info "hindsight port not published; skipping"
fi

echo "== the knowledge base inside the container"
out="$("${DC[@]}" exec -T dsh /opt/sedna/venv/bin/python /opt/sedna/driver.py <<<'{"op":"maintenance","args":{"operation":"audit"}}' 2>&1)"
# Parsed by the container's Python, never the host's. python3 is not a given on macOS (it needs
# the Xcode command line tools) and is usually absent from Git Bash on Windows -- the two
# platforms this stack claims to run on. This script is what a user runs to check that claim,
# so it must not fail there for a reason that has nothing to do with the stack. The image has
# Python by construction; the host is not asked for anything but Docker.
AUDIT_PARSE='import json,sys
raw=sys.argv[1] if len(sys.argv)>1 else ""
try:
    d=json.loads(raw)
except Exception:
    # the driver may print a log line before the JSON
    start=raw.find("{")
    try: d=json.loads(raw[start:]) if start>=0 else {}
    except Exception: d={}
r=(d.get("data") or {}).get("report") or {}
print("%s %s %s" % (r.get("succeeded"), r.get("canonical_source_count"), r.get("rebuild_required")))'
report="$("${DC[@]}" exec -T dsh /opt/sedna/venv/bin/python -c "$AUDIT_PARSE" "$out" 2>/dev/null)"
set -- $report
if [[ "${1:-}" == "True" ]]; then
    ok "audit: succeeded, ${2:-0} canonical source(s), rebuild_required=${3:-?}"
else
    bad "audit: ${report:-no answer from the engine}"
    printf '%s\n' "$out" | head -3 | sed 's/^/       | /'
fi

lane="$("${DC[@]}" exec -T dsh /opt/sedna/venv/bin/python /opt/sedna/driver.py <<<'{"op":"retrieve","args":{"target":"10.10.14.5","authorization_state":"authorized","exact_targets":["10.10.14.5"],"query_terms":["privilege escalation"]}}' 2>&1)"
# The four lanes sit directly on `data`, each a list; `knowledge_gap` is the engine saying out
# loud that the base has nothing on this subject, which is not the same as a bad query.
LANE_PARSE='import json,sys
raw=sys.argv[1] if len(sys.argv)>1 else ""
start=raw.find("{")
try: d=json.loads(raw[start:]) if start>=0 else {}
except Exception: d={}
data=d.get("data") or {}
lanes = {k: len(data.get(k) or []) for k in ("references", "case_steps", "negative_cases", "decision_guidance")}
total = sum(lanes.values())
gap = "no" if data.get("knowledge_gap") is None else "yes"
print("%d|%d|%d|%d|%d|%s" % (total, lanes["references"], lanes["case_steps"], lanes["negative_cases"], lanes["decision_guidance"], gap))'
summary="$("${DC[@]}" exec -T dsh /opt/sedna/venv/bin/python -c "$LANE_PARSE" "$lane" 2>/dev/null)"
IFS='|' read -r count r c n g gap <<<"$summary"
if [[ "${count:-0}" -gt 0 ]]; then
    ok "retrieval: $count candidate(s) -- $r references, $c case steps, $n negative, $g guidance (gap: ${gap:-?})"
else
    bad "retrieval returned nothing: this is what an unindexed base looks like"
fi

echo "== the web GUI"
if [[ -n "$dsh_port" ]]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:$dsh_port/" || true)"
    case "$code" in
        401|403) ok "GUI answers $code without a token (authentication is on, as it must be)" ;;
        200|303) ok "GUI answers $code" ;;
        *) bad "GUI -> ${code:-no answer}" ;;
    esac
    url="$(docker compose logs dsh 2>/dev/null | grep -oE 'http://[^ ]*token=[A-Za-z0-9_-]+' | tail -1)"
    if [[ -n "$url" ]]; then
        # The proof the whole chain works: the address the operator will actually open,
        # answered by a server bound on every interface *inside* the container. The token
        # itself is never printed here -- one in a log is still a token.
        token="${url##*token=}"
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
                 "http://127.0.0.1:$dsh_port/?token=$token" || true)"
        case "$code" in
            200|302|303) ok "GUI accepts the logged token -> $code: that URL is the way in" ;;
            *) bad "GUI with the token -> ${code:-no answer}" ;;
        esac
        info "find it with: docker compose logs dsh | grep token="
    else
        info "no token URL in the logs yet"
    fi
fi

echo "== off-machine backup"
bucket="${BUCKET_NAME:-$(grep -E '^BUCKET_NAME=' .env 2>/dev/null | cut -d= -f2-)}"
if [[ -z "${bucket:-}" ]]; then
    info "no bucket configured: the bank exists only on this machine"
else
    listing="$("${DC[@]}" --profile backup run --rm -T backup list 2>/dev/null | grep 'MiB' || true)"
    newest="$(printf '%s\n' "$listing" | tail -1)"
    if [[ -n "$newest" ]]; then
        ok "bucket '$bucket' has $(printf '%s\n' "$listing" | grep -c 'MiB') archive(s); newest: $newest"
    else
        bad "bucket '$bucket' is configured but no archive is readable in it"
    fi
fi

echo
printf 'passed %d, failed %d\n' "$pass" "$fail"
[[ "$fail" == 0 ]]
