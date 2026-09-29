#!/usr/bin/env bash
# STATUS: incomplete, and deliberately not wired into tests/run-all.sh.
#
# It runs, it drives both provider modes through the real engine, and it does not yet assert
# anything -- because the source it hands over is quarantined before any model is called. That is
# not a failure of the probe: it is the engine's documented behaviour ("a source is classified by
# its physical path", and the model is only called for a real run), and it is the reason a
# quarantined file costs nothing. What is missing is a source whose path makes it a candidate.
#
# What the probe has already established, by running it:
#   * the driver refuses a wrong argument with a message a user can act on
#     ("ingest requires a source path inside the inbox"), not a stack trace;
#   * the inbox is SEDNA_INBOX, default /inbox, and the argument is "source", absolute;
#   * both /v1 and native mode reach the engine identically before any model call.
#
# Next: find the path that classifies as a candidate, then the two assertions -- an
# OpenAI-compatible request on /v1/chat/completions carrying Authorization, and a native one on
# Ollama's own endpoint without it.
#
# "Point the stack at Ollama cloud, at any OpenAI-compatible endpoint, or at a local model" is one
# environment variable and no adapter, according to three documents -- and until now nothing
# checked it. This does, with no cloud, no key and no queue: a recording server on the host, the
# provider pointed at it through host.docker.internal in both modes, and the captured request
# shape asserted.
#
# Deliberately out of scope: whether the pipeline succeeds. A recording server cannot satisfy the
# compiler's schema, so the engine is expected to report a failed extraction. Asserting on the
# request the engine *sent* is the part that decides whether the promise is real.
set -uo pipefail

DOCKER=${DOCKER:-docker}
IMAGE=${IMAGE:-sedna-stack-dsh:latest}
PORT=${PROVIDER_PROBE_PORT:-18899}

if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "skip: image $IMAGE is not available -- build it with: docker compose build dsh"
  exit 0
fi

work=$(mktemp -d); trap 'rm -rf "$work"; [ -n "${rec_pid:-}" ] && kill "$rec_pid" 2>/dev/null' EXIT
kb="$work/kb"; mkdir -p "$kb/inbox"; chmod 700 "$kb"
printf '# Probe source\n\nA sentence that is not knowledge.\n' > "$kb/inbox/probe.md"

cat > "$work/recorder.py" <<'PY'
import http.server, json, sys
LOG = sys.argv[1]; PORT = int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"path": self.path,
                                 "auth": self.headers.get("Authorization"),
                                 "has_model": '"model"' in body or "model" in body}) + "\n")
        payload = json.dumps({"choices": [{"message": {"content": "no"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
http.server.HTTPServer(("0.0.0.0", PORT), H).serve_forever()
PY

python3 "$work/recorder.py" "$work/requests.log" "$PORT" & rec_pid=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
  (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break
  sleep 1
done

probe() {  # $1 = url, writes one ingest through the engine
  "$DOCKER" run --rm -i --add-host host.docker.internal:host-gateway \
    -v "$kb/inbox":/inbox \
    -e SEDNA_OLLAMA_URL="$1" -e SEDNA_OLLAMA_API_KEY=probe-key-not-a-secret \
    -e SEDNA_OLLAMA_MODEL=probe-model -e SEDNA_OLLAMA_TIMEOUT=20 \
    --entrypoint /opt/sedna/venv/bin/python "$IMAGE" /opt/sedna/driver.py \
    <<'JSON' 2>&1 | head -c 300
{"op":"ingest","args":{"source":"/inbox/probe.md"}}
JSON
}

echo "--- OpenAI-compatible endpoint (URL contains /v1)"
probe "http://host.docker.internal:$PORT/v1"
echo ""
echo "--- native Ollama endpoint (URL contains no /v1)"
probe "http://host.docker.internal:$PORT"
echo ""
echo "--- what the provider actually sent:"
cat "$work/requests.log" 2>/dev/null || echo "(nothing: the engine never called a provider)"
