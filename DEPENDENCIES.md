# Dependencies

What this repository installs itself, what it expects to find already on the machine,
and what is entirely optional. Every claim below was read from a file in this repository;
the file is named next to the claim. Anything that could not be established from a file
in this repository is marked **unconfirmed** rather than guessed.

The principle, in one sentence: **the installer brings the software stack — DSH, the
Sedna engine and plugin, a Hindsight daemon and the seed banks — into `$HOME` as a
non-root user under `systemd --user`, and it neither installs nor checks the offensive
tooling the skills describe.**

Related documents: [README.md](README.md) (what ends up on the machine),
[docs/decisions.md](docs/decisions.md) (why it is shaped this way),
[docs/maintenance.md](docs/maintenance.md) (measured sizes and times),
[THIRD-PARTY.md](THIRD-PARTY.md) (what is vendored and under what licence).

## Hard requirements

| What | Why | How the installer detects / installs it | Without it |
|---|---|---|---|
| Linux user account, non-root, writable `$HOME` | Everything installs into `$HOME`; the two services are user units. Hindsight's embedded PostgreSQL refuses to run as root. | `step_hindsight` checks `id -u` **before** the download and dies with the reason (`lib/70-hindsight.sh`). | As root the install stops before the 6–7 GB download, deliberately. Linux is the only platform with measured support: `docs/maintenance.md` records macOS as unmeasured, and `docs/decisions.md` lists Linux-vs-macOS as an open question. |
| Node **>= 24.2** | DSH uses `import.meta.main` and `node:util.parseEnv`; on Node 22/23 the CLI starts and silently does nothing. | `node_ok()` compares major/minor (`lib/00-common.sh`); `step_prereqs` searches `PATH`, then `~/.nvm/versions/node/*/bin/node`, offers `nvm install 24` when nvm is present, and otherwise dies with `missing prerequisites: node>=24.2` **before changing anything** (`lib/10-prereqs.sh`). | Hard stop in the `prereqs` step. Nothing is installed. |
| npm (next to the resolved Node) | It is what installs DSH. | `step_dsh` looks for `npm` beside `$NODE_BIN`, then on `PATH`, and dies `npm not found next to $NODE_BIN` (`lib/20-dsh.sh`). | Hard stop in the `dsh` step. If the global npm prefix is unwritable the installer uses `--prefix $STACK_HOME/npm` plus a `~/.local/bin/dsh` wrapper instead of failing (`lib/20-dsh.sh`, `lib/00-common.sh: ensure_path_entry`). |
| Python **>= 3.11** (`python3`, one of 3.13/3.12/3.11) | The Sedna engine declares `requires-python = ">=3.11,<3.14"` (`engine/pyproject.toml`), and Hindsight wants >= 3.11 (`lib/00-common.sh: python_ok`). The installer itself also uses `python3` for its state file, the settings merge and the seed checks (`lib/00-common.sh`, `lib/40-plugin.sh`, `lib/60-kb.sh`, `lib/70-hindsight.sh`). | `step_prereqs` probes `python3.13 python3.12 python3.11 python3` with `python_ok`; dies with the distro package hints if none qualifies (`lib/10-prereqs.sh`). | Hard stop in the `prereqs` step. |
| `git` | The repository is cloned with it and checked by the installer; `tools/refresh-seed.sh` refuses to run on a dirty tree (`docs/maintenance.md`). | Checked in the `git`/`curl`/`tar` loop in `lib/10-prereqs.sh`; missing entries are collected into one `die`. | Hard stop in the `prereqs` step. |
| `curl` | The pip bootstrap when the distro has no ensurepip (`lib/00-common.sh: make_venv` downloads `https://bootstrap.pypa.io/get-pip.py`), ollama model discovery (`lib/30-settings.sh: ollama_models`), and the installer's own HTTP checks (`lib/00-common.sh: http_ok`). | Same `git`/`curl`/`tar` loop in `lib/10-prereqs.sh`. | Hard stop in the `prereqs` step. On Debian/Ubuntu without `python3-venv` it is also the only way the engine or Hindsight virtualenv gets a working pip. |
| `tar` | `lib/60-kb.sh` unpacks `seed/sedna-kb.tar.gz` with `tar xzf`. | Same loop in `lib/10-prereqs.sh`. | Hard stop in the `prereqs` step. |
| `systemd --user` | The two services are user units: `sedna-hindsight.service` (the memory daemon on 127.0.0.1:9177) and `sedna-dsh-web.service` (the DSH web UI on 127.0.0.1:3080) (`lib/80-services.sh`; the unit paths are listed in `README.md`). | There is **no pre-flight check**. `install_systemd_unit` warns if `systemctl --user daemon-reload` fails, and `service_enable_start` only warns when a unit does not become active — but `step_verify` then fails: the unit file exists, so it checks Hindsight on `/health` and fails that check (`lib/90-verify.sh`), and the install stops with "the stack is installed but not working". | `services` warns, `verify` fails on the Hindsight checks unless someone starts `hindsight-api` by hand. The plugin, engine and knowledge base work in the session regardless. `--llm skip` avoids the daemon entirely. The DSH web unit is a warning only. |
| Network access to npm, PyPI and `bootstrap.pypa.io` | First install downloads `@deepseek-ai/dsh` from npm (`lib/20-dsh.sh`), `hindsight-all` from PyPI (`lib/70-hindsight.sh`), and possibly `get-pip.py` (`lib/00-common.sh`). | Not checked; failures surface from the individual step. | The install stops at the step that needs the network. Re-running is safe (every step is idempotent by design, `install.sh` header) and steps whose work is already done are cheap. |
| ~7 GB free disk for the default install | `hindsight-all` pulls the local embedding stack; measured 6.8 GB on a bare host and 6.9 GB on the maintainer's machine (`docs/maintenance.md`). The installer prints this before starting. | Not checked as a prerequisite; `step_hindsight` logs the expected size before downloading. | The `hindsight` step fails during `pip install` if the disk fills. |
| Hindsight (`hindsight-all` from PyPI, embedded PostgreSQL under `~/.pg0`) | The memory daemon the stack is built around: it answers on 127.0.0.1:9177 and holds the bank restored from `seed/hindsight-bank.zip`. | Installed **by the installer**, not a prerequisite: `step_hindsight` creates `$STACK_HOME/hindsight-venv`, installs `hindsight-all==0.9.1` (override with `--hindsight-version`), and imports the seed bank; `step_services` writes `sedna-hindsight.service` (`lib/70-hindsight.sh`, `lib/80-services.sh`). | `--llm skip` is the one supported way to leave it out: the step returns early and `step_verify` reports its checks as *skipped*, so the install still exits 0 (`lib/70-hindsight.sh`, `lib/90-verify.sh`). It refuses to install as root. |

## Optional / external components

| Component | What it is | What uses it | Does the installer touch it? | How a user gets it | What still works without it |
|---|---|---|---|---|---|
| **A model provider** — an OpenAI-compatible endpoint + key, or a local ollama | The language model that Hindsight extracts facts with and that Sedna plans and ingests with (`README.md`, `lib/30-settings.sh`). | `step_settings` merges the provider into `~/.dsh/settings.yaml` (via DSH's own js-yaml, backup first) and writes `~/.dsh/sedna/hindsight.env`, both mode 0600, key never echoed and never passed in argv. | **Yes** — this is the one question the installer asks. `--llm api`, `--llm ollama`, or `--llm skip`. | Any OpenAI-compatible base URL + key (`OPENAI_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_MODEL`, defaults `https://api.openai.com/v1` / `gpt-4o-mini`), or `ollama` with `OLLAMA_BASE_URL` (default `http://127.0.0.1:11434`). | With `--llm skip` the stack installs and **retrieval works while planning and ingestion do not** (`lib/30-settings.sh`); `step_hindsight` is skipped entirely and `step_verify` reports the Hindsight checks as *skipped*, not failed (`lib/90-verify.sh`). The installer tells you how to come back: `./install.sh --only settings --llm api\|ollama && ./install.sh --only hindsight,services`. |
| **ollama** (a running ollama with at least one model) | Local model server. Used as one of the two provider choices, and by the Sedna semantic host the `sedna-cyber-workflow` skill recommends (`SEDNA_OLLAMA_LLM=1` → `semantic/ollama_host.py`, default `http://127.0.0.1:11434`, default model `qwen3.6:latest`). | `lib/30-settings.sh: ollama_models` queries `/api/tags`; `engine/src/sedna/knowledge/semantic/ollama_host.py` reads `SEDNA_OLLAMA_URL` / `SEDNA_OLLAMA_MODEL`. | **Probed, not installed.** `--llm ollama` fails the settings step with install advice if nothing answers on the base URL, or if it answers with no models. | Install ollama yourself (<https://ollama.com>) and pull a model. | The `--llm api` path, and everything that does not need a model. |
| **HexStrike** — Kali-based tool API, on the maintainer's machine the Docker container `hexstrike-kali` with `network_mode: host` and its API on `127.0.0.1:8888` | The scanning/tooling half of the offensive workflow: `/health`, `POST /api/intelligence/optimize-parameters`, scan tools (`nmap`, `httpx`, `ffuf`, `nuclei`, …). | The two offensive skills, not the installer: `sedna-cyber-workflow` (prerequisite 2, Steps 1 and 4, the verification checklist) and `sedna-dsh-bridge` (pre-flight `curl -fsS http://127.0.0.1:8888/health`, and "from DSH use the API or `docker exec hexstrike-kali …`"). The `mcp_hexstrike_*` tools named throughout those skills belong to the **Hermes** MCP bridge, which does not exist in DSH. | **No. The installer does not install, configure, check or even mention HexStrike.** It does install the skills that document it (`lib/40-plugin.sh` copies them to `~/.agents/skills/`), and nothing else. | Upstream is [`0x4m4/hexstrike-ai`](https://github.com/0x4m4/hexstrike-ai) — an MCP server that exposes 150+ cybersecurity tools to an agent (its own description); that repository is where the software comes from, and it is where to look for the current way to run it. **This repository does not pin, vendor or verify a HexStrike version**, and the container on the maintainer's machine is built from a *local* image (`local/hexstrike-kali:latest`, `network_mode: host`, API on `127.0.0.1:8888`, `/health` answering with per-tool availability) — that name is a local build, not a published distribution, so do not read it as a registry reference. Community images for HexStrike exist on Docker Hub; none of them has been audited here and this project takes no position on them. The related skills the workflow references (`hexstrike-kali-htb`, `noninvasive-recon-reporting`, `security-lab-tooling`, `security-lab-containers`) and the files they name (`webapp-recon-cdn-targets.md`, `run-lan-scan.sh`) are **not vendored here**. | Everything the installer installs: DSH, the five `sedna_*` tools, the four retrieval lanes, engagement journals, the memory daemon, the knowledge base. What stops is the target-facing half of `sedna-cyber-workflow` — its Steps 1 and 4 and the checklist items that name the API or the container. (`lab-pentest` is unusable on this stack for a different reason: it drives Hades/Ariadne tools that do not exist in DSH, as `plugin/sedna/plugin.json` and `sedna-dsh-bridge` both record — HexStrike is not what it needs.) |
| **Docker** (the container runtime behind `hexstrike-kali`) | Runs the Kali tooling container. | `preset/pentest/skills/sedna-cyber-workflow/scripts/verify-sedna-env.sh` starts with `docker ps` to look for the `hexstrike-kali` container; `sedna-dsh-bridge` names `docker exec hexstrike-kali` as the DSH-side path. | **No** — not installed, not checked. `README.md` is explicit that the installed stack is containerless ("No containers"); `docs/decisions.md` D3 records "native installer, not containers". | Your distribution's Docker packages. | The whole installed stack; only the containerised offensive tooling needs it. |
| **`pt-report.py`** — rolling pentest reports | Per-engagement report store: `init`, `import-nmap`, `render`, `add-evidence`, and the HTML rendered for Tailnet sharing. | `sedna-cyber-workflow` Steps 2, 4, 6 and its verification checklist; `sedna-dsh-bridge` gives its path as `~/hexstrike-kali-hermes/pt-report.py`; `references/unified-engagement-lifecycle.md` requires `--pt-report-script <path>` as a **mandatory** argument to `sync-engagement-report.py`, which opens the file no-follow and refuses anything not an owned, non-group/world-writable regular file. | **No** — not installed, not checked; and it is **not in this repository**. | **Unconfirmed.** The skills say "available in repo or path" and the bridge skill gives the maintainer's path; no upstream is named anywhere here. | Sedna retrieval, the engagement journal, proof lifecycle and memory all work; `sync-engagement-report.py` cannot run (its `--pt-report-script` argument has nothing to point at), and no rolling HTML report is produced. |
| **SysReptor** (containers, plus a `sysreptor-push.sh` helper) | Deliverable/report generator. `sedna-dsh-bridge` records it as "sysreptor containers on `127.0.0.1`", verified against image `syslifters/sysreptor:2026.68`, with the PDF coming from `POST <server>/api/v1/pentestprojects/<project_id>/generate/` (Bearer token in the header, never a query string). | Report publication. `lab-pentest` treats it as a boundary: "SysReptor bundle generation is offline-first; a network push is always a separate explicit choice", and `references/contract.md` pauses the autonomous loop on "SysReptor network push". | **No** — not installed, not checked. | **Unconfirmed** where the stack or `sysreptor-push.sh` comes from; neither is in this repository. | Everything except the SysReptor deliverable. The `lab-pentest` reports it does produce are local files (`walkthrough.md`, `professional.html`). |
| **HTB / lab VPN** (`tun0`, OpenVPN) | The tunnel to the authorised lab. | `sedna-cyber-workflow` prerequisite 1, and `scripts/verify-sedna-env.sh` (step 1 of 4). | **No** — not installed, not checked. | An OpenVPN profile from the platform. The skill's example command uses `~/machines_eu-5.ovpn` with passwordless sudo for `/usr/sbin/openvpn` only — a machine-specific path and sudo rule, **unconfirmed** for a fresh machine. | Everything except reaching lab targets. |
| **Tailscale / a Tailnet HTTPS endpoint** | Where `pt-report` HTML is shared. | `references/unified-engagement-lifecycle.md` verifies a Tailnet URL (`curl -I https://<host>:8899/engagements/<slug>/`) and `sedna-cyber-workflow` lists "rendered and verified on Tailnet URL" as a completion criterion. | **No** — not installed, not checked. | Tailscale. The skill's hostname is the maintainer's, **unconfirmed** here. | Everything locally; reports stay on the machine. |
| **The read-only Sedna operations console** | `~/sedna-operations-console`, HTTP on `127.0.0.1:8085`, run as the user unit `sedna-operations-console` (`sedna-dsh-bridge`). | Reading the KB without writing to it. | **No** — not in this repository, not installed. | **Unconfirmed** origin; the skills expect it to exist on the maintainer's machine. | The five `sedna_*` tools reach the same KB. |

### Also named by the skills, none of it installed or checked here

* `~/hexstrike-kali-hermes/tools/hindsight-bank.py` — the HTTP path to persist knowledge from
  a delegated lane when the `hindsight_*` tools are unavailable (gates G9 in
  `sedna-dsh-bridge` and `lab-pentest/references/procedure-gates.md`).
* Python `websockets` v16+ — used by the Kubernetes `nodes/proxy` technique in
  `sedna-cyber-workflow`. It is **not** among the engine's dependencies
  (`engine/pyproject.toml`).
* `codex` CLI (`SEDNA_CODEX_LLM=1` → `semantic/codex_host.py`, auth in `~/.codex/auth.json`)
  as the skill's "reliable paid fallback" for semantic extraction. The module is vendored in
  `engine/`; the CLI is the user's to install.
* `rsync` — `step_engine` prefers it and falls back to `cp -a` (`lib/50-engine.sh`):
  **used when present, not required**.
* `unzip` — `step_prereqs` only warns, "only needed if you inspect the seed archives"
  (`lib/10-prereqs.sh`).

### Where the skills and the installer disagree about paths

The skills were written against the maintainer's Hermes-era layout and are vendored
unchanged, so their paths are not this installer's paths. The installer writes
`~/.dsh/plugins/sedna/` and `~/.dsh/knowledge/sedna` and mounts the plugin from the
**host** plane (`lib/40-plugin.sh`, `README.md`); `sedna-dsh-bridge` describes
`~/.dsh/plugins/sedna-bridge/index.mjs` in `~/.dsh/.agent-presets/pentest/agent.cordis.yml`
and a knowledge root of `~/.hermes/knowledge/sedna/`. `docs/preset.md` covers mounting the
row in a preset instead of host-wide. Do not read the skill's paths as the installed layout.

## Checking a machine

`tools/doctor.sh` answers "is this machine ready" without changing anything:

```bash
bash tools/doctor.sh
```

It prints one line per component with an `ok`, `missing` or `optional` marker, a short
summary line at the end, exits `0` when every mandatory component is present and non-zero
otherwise. It checks exactly the hard requirements above (Node >= 24.2, npm, Python >= 3.11,
`git`, `curl`, `tar`, `systemd --user`, `dsh`, the Sedna plugin row in
`$DSH_HOME/cordis.patch.yml`, the engine virtualenv, the knowledge base root, Hindsight on
`127.0.0.1:9177`) and, as **optional** lines that never affect the exit code, HexStrike on
`127.0.0.1:8888`, ollama and `pt-report.py`. Hindsight is a mandatory line because it is part
of what the installer installs — the detail text names `--llm skip`, the one supported way to
omit it. It reads no credential file — it never opens
`settings.yaml`, `hindsight.env` or the plugin's `config.json` — and it prints no secrets,
only commands, paths, versions and HTTP status codes. Every network probe has a short
timeout, and the only hosts it touches are the three local endpoints above. SysReptor, the
VPN and the Tailnet endpoint are deliberately not probed: they are needed only at publication
time or on target-facing work, not for the stack to be installed and answering.

## What is deliberately not a dependency

* **pnpm** — `lib/10-prereqs.sh` logs "pnpm not found -- not needed: the plugin is installed
  as a file:// row, not from the registry"; `lib/40-plugin.sh` states "no pnpm, no registry,
  no node_modules"; `README.md` says it outright.
* **Docker or any container runtime** — `README.md` "No containers", `docs/decisions.md` D3.
  (The *skills* use a container; the *installer* never does. See HexStrike above.)
* **Hermes and Hades** — out of the product, not merely optional: `README.md` "No Hermes. No
  Hades.", `docs/decisions.md` D1. `lab-pentest` still names Hades/Ariadne tools and
  `sedna-cyber-workflow` names Hermes tools (`sedna_learn_local`, `sedna_plan_next`,
  `mcp_hexstrike_*`); those do not exist in DSH and `plugin/sedna/plugin.json` records them
  under `notProvided`.
* **A `sedna` CLI** — the vendored `pyproject.toml` declares no `console_scripts`, and
  `sedna-dsh-bridge` says explicitly: "Never invent a `sedna` CLI entry point". The engine is
  driven through `plugin/sedna/driver.py`.
* **A graph database, a vector database, a generic crawler or a separate RAG pipeline** —
  `lab-pentest` forbids introducing them; retrieval is the engine's own disposable SQLite
  FTS index (`engine/src/sedna/knowledge/retrieval/sqlite.py`,
  `plugin/sedna/driver.py`).
* **The offensive tools themselves** — HexStrike, its Kali image, `pt-report.py`, SysReptor,
  the VPN client and its profile, Tailscale. The installer installs none of them and checks
  none of them.
* **A GPU** — nothing in the repository checks for or requires one. The pinned
  `hindsight-all` does pull a torch build (measured 6.9 GB, `docs/maintenance.md` mentions the
  "CUDA build"), which runs on CPU here. Whether any Hindsight feature would *use* a GPU is
  **unconfirmed** from this repository.
* **Upstream's `tests/` and `raw_src/`** — deliberately not vendored (`engine/VENDORED.md`,
  `docs/decisions.md` D7, `THIRD-PARTY.md`); nothing at runtime needs them.
* **`unzip`** — only warned about, never required (`lib/10-prereqs.sh`).

## Unconfirmed from this repository

Listed so that nobody reads a guess as a fact:

* where HexStrike comes from (image, source, install command) — only the container name,
  `network_mode: host` and port `8888` are stated;
* where `pt-report.py` comes from, and the full set of its subcommands (the skills use
  `init`, `import-nmap`, `render`, `add-evidence`);
* where the SysReptor stack and `sysreptor-push.sh` come from;
* whether the installer's `--llm` configuration is what the Sedna semantic extraction hosts
  (`SEDNA_OLLAMA_LLM`, `SEDNA_CODEX_LLM`) actually use — the installer writes DSH's
  `settings.yaml` and the Hindsight env file, and never mentions those two variables;
* any measured install on macOS;
* the OpenVPN profile path, the sudoers rule, the Tailnet hostname and the
  `~/hexstrike-kali-hermes/` tree — all are the maintainer's machine, quoted by the skills.
