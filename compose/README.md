# The stack, in containers

Docker Compose is the supported way to run this. Not because containers are fashionable, but
because the alternative was bash plus `systemd --user`, and macOS and Windows have neither
(`docs/decisions.md` D19). With Compose the requirement is one thing: Docker.

## Four commands

```sh
git clone https://github.com/titagram/sedna_dsh.git && cd sedna_dsh/compose
cp .env.example .env          # then set POSTGRES_PASSWORD and your provider
docker compose up -d
docker compose logs dsh | grep -i token    # the authenticated URL, with its one-time token
```

Then, once, to put the seeded memories into the bank:

```sh
./seed-bank.sh
```

That is the whole install. No Node, Python, bash version or service manager on the host: the
images carry their own, and `--no-open` means nothing tries to launch a browser.

`./seed-bank.sh` takes a while the first time — it re-embeds every memory with *your* embedding
model rather than copying vectors built elsewhere, which is also why changing that model later
is recoverable: export the bank, then import it again.

## Does it actually work

```sh
./verify.sh
```

Eight checks, and they are the difference between "the containers are up" and "the thing
works": each service's health, the memory API answering, the knowledge base's canonical sources
*and* whether its index needs rebuilding, a real retrieval through the four lanes the engine
returns, and the web GUI both refusing an unauthenticated request and accepting the token it
printed. The failures this catches are the silent ones: an unindexed base answers every question
with the same convincing nothing, and the retrieval check is the only one that notices.

## What runs, and what survives a restart

| service | what it is | port (host) |
|---|---|---|
| `dsh` | the agent, the Sedna tools, the knowledge base | `127.0.0.1:3080` |
| `hindsight` | the memory API | `127.0.0.1:9177` |
| `postgres` | the bank's database | not published |
| `tei` | optional embeddings service | not published |

| volume | what is in it | losing it means |
|---|---|---|
| `kb` | the Sedna knowledge base — seeded once, then yours | the base, not the seed: re-run the bootstrap |
| `dshhome` | sessions, settings, credentials, your edits to the composition | your sessions and settings |
| `pgdata` | the memory bank | the memories — restore from the seed or your bucket |
| `hfcache` | downloaded model weights | a slow first start |

## The provider

One choice, in `.env`, for the whole stack: the agent's route, Hindsight's extraction, and
Sedna's ingest all read it, so they cannot disagree.

```sh
# Ollama Cloud (the provider this stack was built against)
LLM_PROVIDER=ollama-cloud
LLM_API_KEY=...                       # from ollama.com
LLM_MODEL=gpt-oss:120b

# any OpenAI-compatible endpoint, including a daemon on the host
LLM_PROVIDER=openai
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=gpt-oss:120b-cloud          # no key needed when the daemon is already signed in
```

`LLM_PROVIDER=none` is legitimate: retrieval, the knowledge base and every `sedna_*` tool work
without a model. A model is needed only to *add* knowledge and to extract new memories.

### Embeddings: the one thing Ollama Cloud cannot serve

Measured, not assumed: `https://ollama.com/v1/embeddings` answers `404 path not found`, and
Hindsight's embedding providers are `local | onnx | openai | openai-codex | openrouter |
cohere | google | tei | zeroentropy | litellm` — there is no `ollama` among them. Three ways
out, in `.env`:

```sh
EMBEDDINGS_PROVIDER=onnx      # default: in-process, CPU, no extra service, no chat model
EMBEDDINGS_PROVIDER=tei       # a service: docker compose --profile tei up -d
EMBEDDINGS_PROVIDER=openai    # somebody else's cloud: openai | cohere | google | zeroentropy
```

**Keep the dimensions.** The seeded bank was embedded with `intfloat/multilingual-e5-small`
at 384 dimensions, and Hindsight fixes a bank's dimensions once memories exist. Choosing
another model with another size means re-embedding: export the bank, then import it into the
instance configured the way you want — import re-embeds.

### The reranker stays local

It is the difference between a good answer and a plausible one, and it is cheap on a machine
that has the memory. On one that does not:

```sh
RERANKER_PROVIDER=rrf          # no model at all, cheapest, quality drops
RERANKER_PROVIDER=flashrank    # small ONNX model, CPU
RERANKER_PROVIDER=cohere       # or litellm | tei | jina-mlx (Apple Silicon) | ...
```

## Adding knowledge to the base

The seed is a starting point, not the base. The `kb` volume is the base, and it is yours:
the bootstrap only fills an empty volume, so adding to it never collides with `git pull`.
What the pipeline actually is, and the two traps that make "point it at a file" the wrong
interface, are in `docs/adding-knowledge.md`.

## Adding knowledge

The knowledge base is a volume, not a frozen seed: the bootstrap only ever fills an empty one,
and never touches a base that already holds something. To add to it, drop a source in the
inbox and ingest it:

```sh
mkdir -p inbox/write-ups/machines/YourBox
$EDITOR inbox/write-ups/machines/YourBox/YourBox.md
docker compose exec dsh /opt/sedna/venv/bin/python /opt/sedna/driver.py <<'JSON'
{"op":"ingest","args":{"source":"/inbox/write-ups/machines/YourBox/YourBox.md"}}
JSON
```

Before spending a model call, ask whether the source will be accepted. The same operation
with `"check":true` runs the deterministic half of the pipeline -- inventory, family and
structure -- and calls no model at all:

```sh
docker compose exec dsh /opt/sedna/venv/bin/python /opt/sedna/driver.py <<'JSON'
{"op":"ingest","args":{"source":"/inbox/write-ups/machines/YourBox/YourBox.md","check":true}}
JSON
```

A file outside that layout comes back `quarantined` with the classifier's own reasons —
measured: `["ambiguous", "no_deterministic_rule_matched"]`. A source the engine already holds
comes back `unchanged`, which means it is knowledge, not that it was refused.

You get back the engine's own verdict per source — `verified`, `unchanged`, `quarantined` or
`failed`, with reason codes. **Read it.** A source is classified by its physical path, and the
failure that matters is not a refusal you can see: it is a file that is accepted into a
quarantine nobody looks at and never becomes knowledge, which looks exactly like success. The
layout above is the one this has been exercised with.

The model matters, and not in the way the provider list suggests. Ingest is the one stage that
sends a **JSON schema** to the model; a model that answers in prose instead fails semantic
validation and the source is reported as `invalid_structured_response`. Measured here, against
Ollama Cloud through a local daemon:

| model | result |
| --- | --- |
| `glm-5.3:cloud` | `verified` — the source became knowledge |
| `gpt-oss:120b-cloud` | `invalid_structured_response` — ignores the schema |
| `qwen3.5:397b-cloud` | `transport_failure` |

That is why `SEDNA_OLLAMA_URL` is deliberately **without** `/v1`: a URL containing `/v1` or
`ollama.com` selects the OpenAI-compatible path, where the schema is advisory; the native path
asks Ollama to constrain the output. The provider axis in `.env` is otherwise free.

## Backing up

The bank grows without bound and does not belong in git, so it is exported as a portable
archive and pushed to any S3-compatible bucket you supply. Configure it in `.env` and start
the service:

```sh
docker compose --profile backup up -d
docker compose --profile backup run --rm backup list      # what is in the bucket
docker compose --profile backup run --rm backup once      # one backup now, then exit
docker compose --profile backup run --rm backup restore   # import the newest archive back
```

The archive is produced by `hindsight-admin export-bank`, which carries the documents, facts,
bank config, mental models and directives but **no embeddings** — those are regenerated on
import. That is why the file is small, why it survives a change of embedding model or
Hindsight version, and why a restore re-embeds (expect it to take as long as the first seed).

Point it at your provider with the `BUCKET_*` block in `.env`: Cloudflare R2, Backblaze B2,
Wasabi and AWS S3 all speak this, with `BUCKET_PATH_STYLE=auto`; MinIO-style self-hosted
gateways want `path`.

### Testing the backup without a cloud account

```sh
docker compose --profile s3test up -d      # a throwaway S3 endpoint, served by rclone
```
and in `.env`:
```sh
BUCKET_ENDPOINT=http://s3test:8333
BUCKET_ACCESS_KEY=akid
BUCKET_SECRET_KEY=secretkey
BUCKET_PATH_STYLE=path
```
Its storage is memory, so nothing survives a restart. That is deliberate: it exists to prove
the path works before you hand it a bucket you care about. (MinIO would be the obvious choice
here and we tried it first; its Docker Hub repository is no longer pullable, and a service in
this file that cannot be pulled is worse than none.)

## Before you change the ports

Both published ports are bound to `127.0.0.1` on purpose, and DSH's web GUI is a full agent
with a shell: anyone who can reach the port can act as you. The GUI authenticates with a
per-process token in the URL, which is protection against a stray browser tab, not against a
network. Exposing it means a TLS terminator and real authentication in front — nothing here
provides either.

On Linux, the workspace bind mount (`WORKSPACE_DIR`) may be owned by a uid the container user
(1000) cannot write to; pass `user:` in the compose file or match the numbers.
