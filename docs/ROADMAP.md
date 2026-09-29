# What is not done yet

Kept here rather than in a chat, because the list has been accurate for a while and the
things on it are the difference between "the pieces are proven" and "the product is proven".
Ordered by what a user meets first, not by what is interesting to build.

## The container path (in progress)

The requirement changed and `docs/decisions.md` D19 records it: the stack must come up on any
machine, any architecture, any operating system, which the bash + `systemd --user` installer
cannot do. Compose replaces it, the provider becomes a `.env` choice (Ollama cloud, any
OpenAI-compatible endpoint, or a local model), and the seed becomes a bootstrap rather than
the knowledge base itself.

Still open on that path:

* **The stack itself is written** (`compose/`, validated by `docker compose config` on both
  profiles) but has never been started on a host that has nothing: that is the next proof, and
  the one this repository keeps promising in its README.
* **The provider matrix.** One place where the operator picks a provider, mapped to whatever
  each component calls it, with the components that need a model (the harness, Hindsight
  extraction, Sedna ingest, embeddings) configured together so they cannot disagree. The
  reranker stays `local` by default — the machine that runs Hindsight is powerful enough, and
  Hindsight already supports changing it — with `HINDSIGHT_API_RERANKER_PROVIDER` exposed so
  a lighter user can move to the CPU-only reranker or an API one instead of downloading torch.
* **A way to add knowledge that works.** This is the requirement, not a nicety: the base must
  grow, and today nothing shipped in this repository can grow it. The bridge driver has no
  ingest operation, the agent-populate scripts are not vendored and hardcode the author's
  paths, and the ingest model host is not wired. `docs/adding-knowledge.md` records what the
  pipeline actually is and the two traps that make a naive "point it at a file" interface
  wrong: a source is classified by its physical path (a file outside the corpus-family layout
  is quarantined *silently*), and a quarantined source must be reported loudly with a reason.
  The shape is an inbox directory with a fixed layout, an ingest operation on the driver, and
  a report that says what happened to your file.
* **The bank backup bucket.** The bank is too large for git and grows without bound. The
  design slot exists; the implementation comes later. The interface is deliberately
  S3-compatible, because that is the one shape every provider can present (R2 and B2 expose
  it), and the way to know the path works is to exercise it against a real endpoint — a MinIO
  container on the development server — rather than to write it and hope.
* **Restore on a fresh machine from the bucket alone.** Untested by definition until the
  bucket exists.

## Defects a user meets

* **The shipped bridge skill describes the author's machine.** `lib/40-plugin.sh` copies
  `preset/pentest/skills/*` into `~/.agents/skills/`, and inside
  `sedna-dsh-bridge/SKILL.md` the paths are the author's: `~/.dsh/plugins/sedna-bridge/index.mjs`,
  `~/.hermes/knowledge/sedna/`, `~/sedna-hermes-native-v2/.venv/bin/python`. Somebody who
  installs this gets a skill pointing at directories that do not exist for them. It must
  describe the layout the installer (or the image) actually creates.
* **One knowledge-base source of 95 is still left out.** It was promoted from an engagement
  journal and stays valid only while the artifact it was rendered from exists, and that
  artifact lives under `engagements/`, which is not published. Since artifact ids are
  content-addressed, the principled fix is a bundle rewriter: redact the text, recompute the
  ids, remap the references. That also removes the reason the seed shrinks as memory grows.

## Gaps in verification

* **The whole path has never been run in one go.** The pieces are proven: DSH, the plugin,
  the engine and the knowledge base install in a clean container; the Hindsight step was
  measured on an empty host (3m30s, 6.8 GB, import exit 0); the published clone passes the
  gate, the manifest check, `tools/doctor.sh` and a dry-run install. `clone -> install -> a
  DSH session that answers` has not. The README promises three commands and about ten
  minutes, so that is the claim to test.
* **`--llm ollama` has never been executed.** If the flag does not work, it is a lying flag.
* **macOS and arm64 are unmeasured.** Compose makes them plausible; only a machine can make
  them true. CI can build the images for both architectures without running them, which is
  worth doing and is not the same thing as testing.
* **HexStrike's installation from scratch is unverified.** The upstream is identified
  ([0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai)) and a local build runs on the
  development server, but nobody has followed documented steps from nothing to a working
  API.

## Hygiene

* **Engine drift.** `tools/check-engine-drift.sh` compares the vendored engine against an
  upstream checkout and nothing runs it; when `titagram/sedna` moves ahead, this repository
  does not notice. A scheduled workflow closes that loop.
* **Two checks skip in the test suite** and the emitter could not be found in the repository.
  `tests/test_seed_kb_audit.sh` says in as many words that a check which silently skips is
  the bug it is meant to catch; two unnamed skips are exactly how a coverage hole passes.
