# What is in this repository, and under what terms

This repository is a distribution: it does not only contain its own code. This file
records what came from where. Every licence below was read from the artifact itself
(package metadata), not from memory.

## This repository's own code

`install.sh`, `lib/`, `tools/`, `tests/`, `plugin/`, `docs/` — **MIT**, see `LICENSE`.
That is the same licence as every component below, which is not a coincidence: this
repository exists to distribute them together.

## Vendored: the Sedna engine (`engine/`)

| | |
|---|---|
| Upstream | `titagram/sedna` |
| Licence | MIT — declared as `license = { text = "MIT" }` in the upstream `pyproject.toml`, and reproduced here because the engine is vendored with it |
| Revision | see `engine/VENDORED.md` |
| Modified | no; the vendored tree is byte-identical to the upstream revision, and `tools/check-engine-drift.sh` exists to keep that true |

## Installed, not vendored: Hindsight

The installer fetches `hindsight-all` from PyPI at install time; no Hindsight code is
copied into this repository.

| | |
|---|---|
| Licence | MIT — `License-Expression: MIT` in `hindsight_api_slim`'s package metadata |
| Pinned version | see `--hindsight-version` in `install.sh` |

## Installed, not vendored: DSH

The installer installs `@deepseek-ai/dsh` from npm if it is absent. No DSH code is
copied into this repository.

| | |
|---|---|
| Licence | MIT — `"license": "MIT"` in the package manifests of `@deepseek-ai/dsh` (0.1.5-rc.2), `dsh-agent-presets` |

## The memory backup (`seed/`)

`seed/hindsight-bank.zip` is not code. It is a memory: documents, extracted facts,
observations and mental models accumulated while doing authorised lab work. It is
published deliberately, as the point of the project, and:

* it is **sanitised** — `seed/REDACTION-REPORT.md` lists what was rewritten and how
  many times, and `tools/scan_secrets.py` gates the seed for flags, credentials, keys
  and tokens on every rebuild, fail-closed;
* it **contains lab target addresses, hostnames and paths on purpose**, because
  knowledge about a box is not useful without saying which box, and warnings are
  reported rather than removed for that reason;
* it is **not covered by the MIT grant in `LICENSE`**: it is not software. It is the
  author's own notes about authorised lab work, offered as-is and without warranty, and
  it grants no rights to any third-party material its notes may describe;
* it publishes **lab** names on purpose — target users, lab domains, private addresses —
  because a finding that cannot say what it was found on is worth less. What is redacted
  on every rebuild is what is *personal*: private keys, secret-shaped assignments,
  mailboxes at consumer providers, and the public addresses of the machine that rebuilt
  the seed. `seed/REDACTION-REPORT.md` lists every class and every count; `docs/decisions.md`
  D18 records why the rule is drawn there.

## Not here, deliberately

* Upstream's `tests/` — its fixtures contain flag-shaped literals on purpose, because
  they test flag detection. See `docs/decisions.md`.
* Upstream's `raw_src/` — collected write-ups, hundreds of megabytes, containing real
  flags. It is public upstream and it is not needed to run anything. See `SECURITY.md`.
