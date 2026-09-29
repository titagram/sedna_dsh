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

## Backing up

Not wired to a bucket yet — the design slot is in `.env.example` and the work is tracked in
`docs/ROADMAP.md`. What exists today:

```sh
docker compose exec hindsight /app/api/.venv/bin/hindsight-admin export-bank \
    --bank hermes --output /tmp/bank.zip     # then copy it somewhere that is not this machine
```

## Before you change the ports

Both published ports are bound to `127.0.0.1` on purpose, and DSH's web GUI is a full agent
with a shell: anyone who can reach the port can act as you. The GUI authenticates with a
per-process token in the URL, which is protection against a stray browser tab, not against a
network. Exposing it means a TLS terminator and real authentication in front — nothing here
provides either.

On Linux, the workspace bind mount (`WORKSPACE_DIR`) may be owned by a uid the container user
(1000) cannot write to; pass `user:` in the compose file or match the numbers.
