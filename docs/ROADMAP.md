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

* **The stack runs.** It has been brought up and verified end to end on this machine — eight
  checks in `compose/verify.sh`, including a real retrieval through the engine's four lanes —
  and three problems found only by starting it are now fixed in the image: a global npm install
  cannot resolve DSH's bundles (they need one flat `node_modules`, reproduced from a pinned
  lock), the build now refuses to ship an image whose composition names a file it does not
  contain, and the bridge's config has to point at the container's paths or every `sedna_*`
  tool is inert. What is still unproven is the promise itself: **macOS, Windows and arm64 have
  never been started**, and neither has a machine with no images pre-pulled. The manifests are
  multi-arch and nothing in the compose is Linux-specific, but that is an argument, not a test.
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
* **The bank backup bucket is implemented** (`compose/backup/bank-backup.py`, profile `backup`):
  export, upload, prune, list and restore, exercised end to end against a real S3 gateway —
  bucket created by the script, a 4.1 MiB archive uploaded, listed, downloaded and importing
  into a second bank. It is deliberately S3-shaped, because that is the one interface every
  provider can present. What is *not* proven: a restore completed on a fresh machine, and the
  schedule — a sleeping loop in a container, not something the operating system owns. A cron
  on the host calling `backup once` would be the honest production shape.

* **`DEPENDENCIES.md` still reasons about the host installer.** Its table was written for the
  bash + systemd path and is now prefixed with a note saying so. The version floors and the
  reasons for them are still true and worth keeping; the *mechanisms* column describes steps
  that no longer exist (`lib/10-prereqs.sh`, `lib/70-hindsight.sh`). Rewriting it against the
  containers is a documentation job with a clear finish line, and it is the last file in the
  repository that describes the stack that was replaced.

* **arm64 can be proven on this machine; macOS and Windows cannot.** The images are multi-arch
  (Hindsight, pgvector and the Node base all publish arm64), so `docker run --privileged --rm
  tonistiigi/binfmt --install arm64` plus `DOCKER_DEFAULT_PLATFORM=linux/arm64` would boot the
  stack emulated and answer the question "does it run on arm64" without a Mac. It proves the
  *images and the composition*, not Docker Desktop on macOS or Windows, which remain the only
  claims in the README that rest on an argument rather than a measurement. The DSH image build
  under emulation is slow and the seed import would be glacial: the target is "pulls, boots,
  serves `/health`, the GUI answers", not a full ingest.

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
