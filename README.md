# Sedna + Hindsight, as a DSH stack

[![verify-seed](https://github.com/titagram/sedna_dsh/actions/workflows/verify-seed.yml/badge.svg)](https://github.com/titagram/sedna_dsh/actions/workflows/verify-seed.yml)

One repository that installs, on a machine that has nothing, a complete
offensive-security memory stack **for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) only**:

* **DSH** itself, in a container built from this repository;
* **Sedna**, the curated, fail-closed knowledge engine, mounted as a DSH plugin
  (five `sedna_*` tools, available in every session);
* **Hindsight**, the long-term memory daemon, with its bank **restored from the
  seed committed in this repository**;
* the operator's own **knowledge base** (canonical bundles, guards, verification
  records) unpacked into a volume that no later start ever writes to.

No Hermes. No Hades. No pnpm. Nothing installed on the host except Docker.

```bash
git clone https://github.com/titagram/sedna_dsh.git
cd sedna_dsh
./install.sh
```

The installer checks that Docker and the Compose v2 plugin are present, creates `compose/.env`
once with a generated database password, and brings the stack up — PostgreSQL with pgvector,
Hindsight, DSH. It never overwrites an `.env` that already exists, because that file holds your
provider choice and your bucket credentials. The first start loads the seed: 866 documents,
re-embedded locally, about half an hour on a laptop. Later starts are immediate. When the
interface answers, the installer prints its authenticated URL.

`./install.sh --dry-run` says what it would do without changing anything.
`./install.sh --port 3080` moves the web interface when something already serves that port;
it checks before starting, because a port collision is otherwise reported as a container that
silently stays in `created`.
The model is chosen in `compose/.env`, not on the command line (see [The model](#the-model)).

## Status

This repository is being built in the open; the table is the honest state of it.
Everything in *verified* was measured on the maintainer's machine (ai_server,
Ubuntu, user `titagram`) on 2026-09-29.

| Part | State | Evidence |
|---|---|---|
| Seed redaction + fail-closed gate | **verified** | `tests/test_scan_secrets.sh` (24 assertions, includes real-data scans) |
| Hindsight bank seed | **verified** | `hindsight-admin export-bank` → 8.9 MB, 864 documents, 13 766 facts, 8 961 observations, 7 mental models, 8 knowledge pages; 12 secret-shaped literals redacted, 0 left |
| Sedna KB seed | **verified** | 95 canonical bundles, 6.0 MB → 577 KB packed, 0 findings |
| Seed manifest | **verified** | `tools/verify-manifest.py` checks size + sha256 of every artifact |
| Plugin (vendored) | **verified to load** | exports `name`/`inject`/`apply`; same code that runs on ai_server |
| Engine (vendored) | **verified to import** | 90 modules, 53 961 lines |
| Installer steps | **verified by running them** | each step is exercised individually (`--only <step>`), and `--dry-run` walks the whole plan |
| Install on a clean machine | **verified for everything except Hindsight** | in a `node:24-bookworm` container, as a non-root user, with no `python3-venv` and an unwritable global npm prefix: install exits 0, 95 bundles, engine 0.2.0 importing, plugin row written, and `verify` reports 8 passed / 2 failed — the two failures being the Hindsight checks, which is the correct answer on a machine that has none |
| Hindsight install step | **verified on an empty host** | `hindsight-all==0.9.1` on a bare `node:24-bookworm`: installed in **3m30s** into **6.8 GB**, then imported the seed — `EXIT=0`, 865 documents, 13 772 facts, 8 965 observations, 7 mental models, 8 knowledge pages. It **cannot run as root**: Hindsight's embedded PostgreSQL refuses, so the installer now stops up front with that reason instead of after the download |
| Seed import into a fresh Hindsight | **verified, twice** | the committed `seed/hindsight-bank.zip` was imported into a brand-new embedded instance by the version that exported it (0.9.1) and again by **0.10.1**: 864 documents, 13 766 facts, 8 961 observations, 7 mental models, 8 knowledge pages, **0 skipped** both times, in 9m42s and 11m20s of local re-embedding |

The seed material is real: this repository carries the maintainer's own memory.
Read [SECURITY.md](SECURITY.md) before you decide to clone it in public.

## What ends up on the machine

Nothing on the host except Docker. Everything lives in named volumes, and `docker compose down`
keeps them — only `down -v` destroys them, which is also how you start over.

| Volume | What |
|---|---|
| `pgdata` | Hindsight's PostgreSQL: the memory bank |
| `hfcache` | Hindsight's model cache (local embedding and reranker weights) |
| `kb` | the Sedna knowledge base, unpacked from `seed/sedna-kb.tar.gz` on the first start only |
| `dshhome` | DSH's home inside the container: settings and the plugin row |
| `teidata` | the optional embedding server, only if you enable the `tei` profile |

The host directory `compose/inbox/` is the one place where a file you write on the host becomes
input: it is mounted at `/inbox`, and the ingest operation refuses any path outside it.

Prerequisites: **Docker with the Compose v2 plugin**. Node and Python are *not* prerequisites —
they live inside the images. (DSH needs Node ≥ 24.2, and the image pins Node 24, because on
Node 22 the CLI starts and silently does nothing: a version check that fails loudly is worth
more than one that works by accident.)

## The model

Nothing here works without a language model — Hindsight extracts facts with one and Sedna plans
and ingests with one. It is one axis in `compose/.env`, and it applies to the whole stack:

* `LLM_PROVIDER=ollama` with `LLM_BASE_URL` pointing at a daemon you run: no key and no account
  anywhere, which is why the stack can come up on a machine with no internet account at all;
* `LLM_PROVIDER=ollama-cloud` or `openai`: a hosted endpoint, with `LLM_API_KEY` and `LLM_MODEL`.
  Any OpenAI-compatible service works; that is the only interface this needs.

Embeddings and the reranker are chosen in the same file and default to running locally (`onnx`,
plus a local reranker), so nothing leaves the machine unless you decide it should. Retrieval and
the knowledge-base audit need no model at all; only planning and ingestion do.

Secrets live only in `compose/.env`, mode 0600 and gitignored. `.env.example` documents every
axis. **Ingest is the one stage that needs a model honouring a JSON schema**, which no provider
advertises as a feature and which had to be measured — see "Adding knowledge" in
`compose/README.md`.

## The seed, and the gate

This repository publishes **memory**, which on a pentest machine means captured
flags, credentials and keys are one careless commit away. So the seed is generated
by a pipeline and refused by a gate:

```
hindsight-admin export-bank          # read-only: the live bank is never touched
        │
        ▼
tools/sanitize_export.py             # rewrites secret-shaped literals as [REDACTED-<class>]
        │                            # normalises the operator's own home directories
        ▼
seed/hindsight-bank.zip  +  seed/REDACTION-REPORT.md
        │
        ▼
tools/verify-seed.sh                 # fail-closed: any BLOCK literal stops everything
```

* `tools/snapshot-seed.sh` regenerates both seeds and the manifest in one go, then
  runs the gate. The artifacts are staged and only moved into place if the gate
  passes, so a failed run cannot leave a half-published seed behind.
* `tools/scan_secrets.py` is the scanner: stdlib only, deterministic, and it never
  prints what it found — only a masked form, because a CI log of a public
  repository is itself an exposure. It splits its own patterns so that the tools
  directory it scans does not trip it.
* `.github/workflows/verify-seed.yml` runs the scanner's test suite, the manifest
  check and the gate on every push and pull request.
* `seed/REDACTION-REPORT.md` is committed on purpose: a reader must be able to see
  that material was removed, and what class of material it was.

Warnings (IP literals, e-mail addresses, home directories) do not fail the gate.
They are listed so that the decision to publish them is a decision, not an accident:
`tools/verify-seed.sh --strict-warn` turns them into failures for anyone who wants
that stricter line.

## What it needs

See `DEPENDENCIES.md` for what the installer provides, what it expects to find, and the
tools of the offensive workflow that are deliberately *not* installed (HexStrike among
them), and `install.sh` checks for it before doing anything else.

## Making an agent use it

Capabilities are not a personality. The installer mounts the `sedna_*` tools host-wide
and installs the three skills, and what an agent *does* with them comes from the preset
its session mounts. `docs/preset.md` shows the three small edits — the plugin row, the
skills row, a persona — and explains why a **complete** preset is deliberately not
bundled here: a preset replaces the shipped `standard`, so a copy of its rows in this
repository would age into a composition that silently withholds new tools from the
agent that mounts it.

## Keeping it up to date

Two pipelines, because there are two kinds of thing here:

* **Sedna itself** (engine, plugin, skills) is *source*: this repository is the
  pipeline. The engine under `engine/` is vendored from
  [`titagram/sedna`](https://github.com/titagram/sedna) and updated by copying a new
  revision in, on purpose and in a reviewable commit.
* **The seeds** are *live data*: a timer on the machine that owns the memory runs
  `tools/snapshot-seed.sh` and opens a pull request on a `seed` branch. The gate and
  CI run there, and a human merges. Memory is data; data gets a human before it
  becomes public.

## Layout

```
install.sh              one entry point; every step is verifiable and idempotent
install.sh              the entry point: checks Docker, creates .env once, starts the stack
compose/                the stack itself: docker-compose.yml, the DSH image, verify.sh, the backup
plugin/sedna/           the Cordis plugin that exposes the sedna_* tools
engine/                 the Sedna engine (vendored), imported by the plugin inside the container
seed/                   the Hindsight bank archive and the knowledge base, loaded on a first start
tools/                  seed tooling: the fail-closed gate, the manifest, the sanitizer
tests/                  what CI runs: the same suite you can run locally
plugin/sedna/           the Cordis plugin (index.mjs, driver.py) as it runs today
engine/                 vendored Sedna engine (upstream: titagram/sedna)
preset/pentest/skills/  the skills that make the tools usable
seed/                   the memory: bank export, knowledge base, manifest, redaction report
tools/                  scan / sanitize / snapshot / verify
tests/                  the gate's own tests
docs/                   design notes and the decision log
```

## Roadmap

* [x] fail-closed gate, with tests, running on real data
* [x] seed generation (`export-bank`, redaction, knowledge base packing, manifest)
* [x] installer structure with `--dry-run` and per-step verification
* [ ] first end-to-end install on a clean machine (the acceptance test)
* [x] import verification against a *fresh* Hindsight instance (see the table above)
* [x] migration across versions: the same archive imports under 0.10.1, so pinning an
      older release is a preference rather than a requirement
* [ ] seed-refresh timer with a pull request instead of a push
* [ ] `--uninstall`

## Credits

Sedna (`engine/`, `plugin/`) is [titagram/sedna](https://github.com/titagram/sedna).
Hindsight is [vectorize-io/hindsight](https://github.com/vectorize-io/hindsight).
DSH is [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness).
The stack in this repository was assembled on ai_server for authorized lab, HTB and
CTF work only.
