# Sedna + Hindsight, as a DSH stack

[![verify-seed](https://github.com/titagram/sedna_dsh/actions/workflows/verify-seed.yml/badge.svg)](https://github.com/titagram/sedna_dsh/actions/workflows/verify-seed.yml)

One repository that installs, on a machine that has nothing, a complete
offensive-security memory stack **for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) only**:

* **DSH** itself, installed by the installer when it is missing;
* **Sedna**, the curated, fail-closed knowledge engine, mounted as a DSH plugin
  (five `sedna_*` tools, available in every session);
* **Hindsight**, the long-term memory daemon, with its bank **restored from the
  seed committed in this repository**;
* the operator's own **knowledge base** (canonical bundles, guards, verification
  records) unpacked and ready to retrieve from.

No Hermes. No Hades. No containers. No pnpm.

```bash
git clone https://github.com/titagram/sedna_dsh.git
cd sedna_dsh
./install.sh
```

Three commands. The installer asks one question — which model the memory should use, an
API key or a local ollama — installs DSH when it is absent, and takes about ten minutes on
a machine with a warm package cache: most of it is Hindsight's local embedding stack,
[6.8 GB measured](docs/maintenance.md). It refuses to run as root, because Hindsight's
embedded PostgreSQL will not, and saying so up front is kinder than failing four minutes
later. `bash tools/doctor.sh` checks what a machine already has.

`./install.sh --dry-run` prints every command without changing anything.
`./install.sh --llm api|ollama|skip` answers the only question the installer
really has (see [The model](#the-model)).

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

| Path | What |
|---|---|
| `~/.dsh` | DSH, its profile, and the plugin row (`cordis.patch.yml`) |
| `~/.dsh/sedna/src` + `.venv` | the Sedna engine and its virtualenv |
| `~/.dsh/knowledge/sedna` | the knowledge base, unpacked from `seed/sedna-kb.tar.gz` |
| `~/.dsh/plugins/sedna` | the Cordis plugin exposing the `sedna_*` tools |
| `~/.hindsight` + `~/.pg0` | the memory daemon, its embedded PostgreSQL, and the imported bank |
| `~/.config/systemd/user/sedna-*.service` | two user units (memory daemon, DSH web UI) |

Prerequisites: **Node ≥ 24.2** (DSH uses `import.meta.main`; on Node 22/23 the CLI
starts and silently does nothing, which is why the version is checked explicitly),
**Python ≥ 3.11**, `git`, `curl`, `tar`. No `pnpm`: the plugin is mounted by
absolute path, not from a registry.

## The model

Nothing here works without a language model — Hindsight extracts facts with one and
Sedna plans and ingests with one. The installer therefore asks exactly once:

* `--llm ollama` uses a local [ollama](https://ollama.com) and discovers its models;
* `--llm api` takes any OpenAI-compatible base URL, key and model id;
* `--llm skip` installs the stack anyway and tells you retrieval will work while
  planning and ingestion will not.

Whatever you choose, the key is written to two files, both mode 0600:
`~/.dsh/settings.yaml` (DSH's own) and `~/.dsh/sedna/hindsight.env` (the daemon's).
It is never echoed, never passed as a command-line argument, and never committed.

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
them). `tools/doctor.sh` checks a machine against that list and says what is missing.

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
lib/00-common.sh        logging, dry-run, version checks, state file
lib/10-prereqs.sh       node >= 24.2, python >= 3.11, git/curl/tar
lib/20-dsh.sh           pinned install of @deepseek-ai/dsh, profile creation
lib/30-settings.sh      merges a model provider into settings.yaml (backup first)
lib/40-plugin.sh        plugin files, the host row, the skills
lib/50-engine.sh        vendored engine + virtualenv + import check
lib/60-kb.sh            unpacks the knowledge base seed
lib/70-hindsight.sh     daemon, environment, bank import
lib/80-services.sh      two systemd --user units, without stomping existing ones
lib/90-verify.sh        asks the running stack whether it works
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
