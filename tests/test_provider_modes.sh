#!/usr/bin/env bash
# "Point the stack at Ollama cloud, at any OpenAI-compatible endpoint, or at a local model" is one
# environment variable and no adapter. This checks it without a cloud, a key or a queue: a
# recording server on the host, the engine driven through both modes via host.docker.internal,
# and the request it sent asserted.
#
# Established by running it, and asserted below:
#   * a URL containing /v1 takes the OpenAI-compatible path: POST /v1/chat/completions with
#     Authorization: Bearer <key> and the model in the body;
#   * a URL without /v1 takes Ollama's own path: POST /api/chat with no Authorization header.
#
# Out of scope on purpose: whether the pipeline succeeds. A recording server cannot satisfy the
# compiler's schema, so the engine is expected to report a failed extraction -- and it does, with
# a reason code. What decides whether the promise is real is the request it sent.
#
# The path and the content are part of the input: a source must sit under a corpus-family marker
# (write-ups/machines/<machine>/<machine>.md) with at least two substantive headings and one code
# block, or it is quarantined as foundation material and never reaches a model. That is documented
# in docs/adding-knowledge.md, and finding it there after guessing six paths is written down here
# so nobody repeats it.
set -uo pipefail

DOCKER=${DOCKER:-docker}
IMAGE=${IMAGE:-sedna-stack-dsh:latest}
PORT=${PROVIDER_PROBE_PORT:-18899}

if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "skip: image $IMAGE is not available -- build it with: docker compose build dsh"
  exit 0
fi

work=$(mktemp -d); trap 'rm -rf "$work"; [ -n "${rec_pid:-}" ] && kill "$rec_pid" 2>/dev/null' EXIT
kb="$work/kb"; mkdir -p "$kb/inbox/write-ups/machines/probe-box"; chmod 700 "$kb"
cat > "$kb/inbox/write-ups/machines/probe-box/probe-box.md" <<'DOC'
# Lab case: reaching a service account's key material from a web application

## Situation

A Linux host exposing an HTTP application on port 8080, running as a service account with a home
directory that the application can read. The application offers file upload and a template
renderer whose output is returned to the caller.

## Observation

The renderer resolved a path outside its configured template directory when the path was supplied
through the upload name field, and returned the file contents in the response body. The service
account's home directory contained a configuration file with a key in plain text.

## Approach

1. Confirm the parameter is reflected: upload a benign file and request the template by name.
2. Establish the traversal depth needed to leave the template root, one level at a time, until the
   response differs from the expected error.
3. Read a known, harmless file to confirm disclosure without touching credential material.
4. Report the parameter and the depth, and stop -- the objective was the access, not the contents.

The step that establishes disclosure, without touching anything sensitive:

```sh
curl -s -o /dev/null -w '%{http_code}\n' "http://target:8080/render?template=../../../../etc/hostname"
```

## Why it worked

The application validated the template name against the upload directory but resolved the final
path after the check, so the check and the use disagreed. Nothing in the deployment re-validated
the resolved path against the permitted root.

## Negative case

The same parameter submitted with an absolute path was rejected by an earlier filter: the filter
matched on a leading separator and was never reached by a relative traversal, so testing only the
absolute form would have reported the endpoint as safe.
DOC

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
{"op":"ingest","args":{"source":"/inbox/write-ups/machines/probe-box/probe-box.md"}}
JSON
}

echo "--- OpenAI-compatible endpoint (URL contains /v1)"
probe "http://host.docker.internal:$PORT/v1"
echo ""
echo "--- native Ollama endpoint (URL contains no /v1)"
probe "http://host.docker.internal:$PORT"
echo ""
python3 - "$work/requests.log" <<'PY'
import json, sys

rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
assert len(rows) == 2, "expected one request per mode, got %d: %s" % (len(rows), rows)

openai_mode, native_mode = rows
assert openai_mode["path"] == "/v1/chat/completions", openai_mode
assert openai_mode["auth"] == "Bearer probe-key-not-a-secret", openai_mode
assert openai_mode["has_model"], openai_mode

assert native_mode["path"] == "/api/chat", native_mode
assert not native_mode["auth"], native_mode
assert native_mode["has_model"], native_mode

print("provider modes ok: %s with Authorization, %s without"
      % (openai_mode["path"], native_mode["path"]))
PY
