# Dependencies

What this repository expects to find on the machine, what it brings itself, and what is
optional. Every claim below names the file it was read from. Anything that could not be
established from a file here, or measured, is marked **unconfirmed** rather than guessed.

The principle, in one sentence: **the host needs Docker and nothing else** — the whole stack
(DSH, the Sedna engine and plugin, Hindsight, PostgreSQL) runs in containers, and the only
thing this repository writes outside them is `compose/.env`.

Related documents: [README.md](README.md) (what ends up where),
[compose/README.md](compose/README.md) (running it),
[docs/decisions.md](docs/decisions.md) (why it is shaped this way),
[THIRD-PARTY.md](THIRD-PARTY.md) (what is vendored and under what licence).

## On the host

| What | Why | How it is detected | Without it |
|---|---|---|---|
| **Docker**, with the **Compose v2 plugin** | The stack *is* Compose. `docker-compose` v1 is not supported: the file uses `env_file` with `required: false`, profiles, and YAML anchors. | `install.sh` runs `docker compose version` and refuses to continue if it fails. | `install.sh` stops before changing anything, with the reason. `docs/decisions.md` (D19) records why Compose replaced bash + `systemd --user`. |
| Access to the Docker daemon (member of `docker`, or Docker Desktop) | Compose talks to the daemon; nothing runs as root on the host. | Implied by `docker compose version` answering. | As root, Hindsight's PostgreSQL would refuse to start — one of the reasons the containers own that problem now instead of the installer (`compose/docker-compose.yml`). |
| **Ports** `3080` and `9177` on `127.0.0.1`, free | The web interface and the memory API. Both bind to loopback only, deliberately. | `install.sh` probes the chosen port through bash's `/dev/tcp` before starting, and says which process would need to move. | `install.sh` stops with `port N is already taken`; `--port` moves the web interface. A collision is otherwise reported by Docker as a container that stays in `created`. |
| **Disk** — about 8 GB for the images | Measured images: `ghcr.io/vectorize-io/hindsight:0.9.2` **6.4 GB**, the built `sedna-stack-dsh` **1.01 GB** (Node 24 base + the engine + the DSH package set), `pgvector/pgvector:pg17` a few hundred MB. | `docker image ls`, `docker compose config --images`. | The pull fails. The first start additionally downloads the embedding and reranker weights into the `hfcache` volume; that figure is **unconfirmed** here. |
| **Disk** — volumes, separate from the images | `pgdata` (the bank), `kb` (the knowledge base), `dshhome`, `hfcache`. `docker compose down` keeps them; `down -v` destroys them. | `compose/docker-compose.yml` (the `volumes:` block). | Nothing; the sizes grow with use. |
| **Nothing else** — no Node, Python, git, curl, tar, npm, pip, or systemd | Every one of those lives in an image: `compose/dsh/Dockerfile` installs `python3`, `python3-venv`, `curl` and `tini` from Debian and pins Node 24 as its base. | `compose/dsh/Dockerfile`. | — |
| **bash**, for the helper scripts | `install.sh` and `compose/verify.sh` are shell scripts that drive `docker compose`. On Windows they need Git Bash or WSL; Docker Desktop alone is not enough to run them. | The shebangs; both are checked by `tests/run-all.sh`. | Docker Compose can be driven by hand: `compose/README.md` lists the commands. |
| **A model endpoint** — only for planning and ingest | Hindsight extracts facts with one and Sedna plans and ingests with one. Retrieval, the knowledge-base audit and every container start need no model at all. | `compose/.env` (`LLM_*`); the stack reads it through `env_file`. | The stack still starts and retrieves. Planning and ingesting fail. |

Line endings are part of this: `.gitattributes` pins LF on scripts, Dockerfiles and YAML,
because a Windows clone with `core.autocrlf=true` otherwise ships CRLF into a Linux container,
where the entry point dies with `\r': command not found` and the container restart-loops.

## Brought by the images, pinned in this repository

| What | Version / source | Where it is pinned | Notes |
|---|---|---|---|
| Node | 24 (`node:24-bookworm-slim`) | `compose/dsh/Dockerfile` | **≥ 24.2 is mandatory**: on Node 22 the DSH CLI starts and silently does nothing. The image is built on 24 so the floor is satisfied by construction, not by a check at run time. |
| DSH | `@deepseek-ai/dsh` `^0.1.5-rc.2` | `compose/dsh/install/package.json` + `package-lock.json` (585 packages) | Installed with `npm ci` from the resolved lock, **not** globally: a global install produces 120 `@deepseek-ai` packages where the working tree has 241, and the missing ones are load-time failures. `compose/dsh/check-bundles.mjs` asserts that the profile's bundles (`@deepseek-ai/dsh-base`, `@deepseek-ai/dsh-web-app`) actually resolve, at build time. |
| Python | 3.12 (Debian bookworm) | `compose/dsh/Dockerfile` | The Sedna engine declares `>=3.11,<3.14` (`engine/pyproject.toml`) and is installed editable into a venv in the image. |
| Sedna engine | vendored in this repository | `engine/` | No network fetch at build time. `compose/dsh/boot-check.sh` boots DSH inside the image and fails the build if the plugin row does not load — so a broken composition cannot be published as a working one. |
| Hindsight | `ghcr.io/vectorize-io/hindsight:0.9.2`, multi-arch | `compose/docker-compose.yml` | Debian 13 base, venv at `/app/api/.venv`. It already carries **boto3**, which is why the bucket backup needs no extra dependency (`compose/backup/bank-backup.py`). |
| PostgreSQL | `pgvector/pgvector:pg17`, multi-arch | `compose/docker-compose.yml` | Hindsight's vector store. |
| The seed | `seed/hindsight-bank.zip` (**8.9 MB**, 866 documents, 13 785 facts) and `seed/sedna-kb.tar.gz` (94 canonical sources) | `seed/` | Loaded **only** into an empty volume; `compose/bootstrap-kb.sh` never writes to a knowledge base that already holds something. |

## Optional, per profile or per `.env`

| What | Enabled by | Notes |
|---|---|---|
| A cloud bucket for bank backups | `BUCKET_*` in `compose/.env`, profile `backup` | Any S3-compatible service. `compose/backup/bank-backup.py` exports, uploads, prunes, lists and restores; a full restore was measured at 866 documents and 13 785 facts, identical to the source. |
| A throwaway S3 endpoint | profile `s3test` | `rclone/rclone` serving S3 from memory, to prove the backup path without a cloud account. |
| A separate embedding server | profile `tei` | `teidata` volume. The default is local ONNX embeddings (`EMBEDDINGS_PROVIDER=onnx`, 384 dimensions); the alternative is any OpenAI-compatible embeddings endpoint. |
| A different reranker | `compose/.env` | Local by default, because the machine that runs this is powerful enough and no query leaves it; a lighter reranker is a one-line change. |

## What this does not install, and does not check

The offensive tooling the skills describe — HexStrike, nmap, the exploitation frameworks — is
out of scope here and is neither installed nor verified by anything in this repository. The
stack also makes no attempt to check whether a model endpoint is *good* at the job: ingest
needs a model that honours a JSON schema, which no provider advertises as a feature and which
had to be measured (`compose/README.md`, "Adding knowledge").
