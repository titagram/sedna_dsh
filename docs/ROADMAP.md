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

* **arm64: partially proven here, and one trap cost a wasted attempt.** What is measured: the
  arm64 variants of all three base images exist and pull (`hindsight:0.9.2`, `pgvector:pg17`,
  `node:24-bookworm-slim`), and PostgreSQL and Hindsight run as **genuine arm64 containers**
  under QEMU emulation — proven not by `uname`, which the emulator overrides to report the
  emulated architecture, but by the ELF header of `/bin/sh` inside the container (`b7 00` =
  AArch64, against `3e 00` in an amd64 container), and by `.ImageManifestDescriptor.Platform`,
  which is the per-container platform; `docker image inspect <tag>.Architecture` is not, because
  it reports the index's *default* platform and will contradict the container.
  Hindsight answers `/health` **200** emulated. The DSH image **builds and boots for arm64**: the build's own gate reports "DSH boots with the sedna-bridge row mounted" under emulation, `dsh --version` answers 0.1.5-rc.2, and Node's `process.arch` says `arm64` -- a value that comes from the binary, not from `uname`, so the emulator cannot fake it. **The engine works on arm64, measured**: the audit
  reports 94 canonical sources, the index rebuild succeeds with 675 artifacts indexed, and a
  retrieval returns all four lanes populated with no knowledge gap -- the same shape as on
  amd64. The rebuild took 211 s emulated against 24.5 s native, so budget roughly 9x for
  anything run under QEMU on this machine. Still unmeasured on arm64: the seed's bank import,
  which at that ratio would take hours -- a deliberate omission, not an oversight.
  The trap: `docker build --platform linux/arm64` fails at a `COPY` with "does not provide the
  specified platform (linux/arm64)" on this host, because **`docker buildx` is not installed**
  and the legacy builder cannot cross-build. The error reads like a Dockerfile bug and is not
  one. `docker compose build` works because Compose carries its own buildx; a single-platform
  build without an explicit `--platform` is unaffected either way.

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

## The one unverified claim, and exactly how to close it

Everything this repository asserts is now measured somewhere, with one exception: **the container
layer on macOS and Windows** -- Docker Desktop itself, and the file-sharing and bind-mount
behaviour that comes with it.

What is measured, and where:

* Linux x86_64: the full suite, in CI on every push.
* arm64: **natively**, in CI, on GitHub's arm64 runner -- the image builds there (boot gate
  included) and the engine audits the seed's 94 canonical sources, rebuilds the index and
  retrieves across all four lanes. This used to be an emulated result; it is not any more.
* macOS and Windows, everything before a container starts: the shell each one actually has
  (`/bin/bash` 3.2.57 on macOS, Git Bash on Windows), the line endings git delivers with
  `core.autocrlf=true` -- the Git for Windows default, where a `.env` value used to arrive with a
  trailing `\r` -- the installer's behaviour on a machine without Docker, and the portability
  lint. All of it on real runners, on every push.

What is not measured, and why it cannot be from here:

* GitHub provides no Docker on its macOS runners and cannot run Linux containers on Windows ones,
  so the container layer has nowhere to run there.
* The `macos-docker` CI job boots Colima -- a Linux VM -- and runs the same build and engine test
  that pass on the arm64 runner. It is deliberately non-blocking, and Colima is not Docker
  Desktop: different file sharing, different bind mounts. A pass there narrows this gap and does
  not close it. As of this writing the job has been queued for hours: GitHub annotates that
  macOS runners are capacity constrained.
* The peer DSH instance on the Mac has not answered, so the request it holds -- three commands to
  run a clone, `install.sh --dry-run`, `docker compose up -d` and `verify.sh`, expected `passed
  9, failed 0` -- is still the shortest path.

To close it: run those three commands on a machine with Docker Desktop, on macOS or on Windows,
and send back the `passed N, failed M` line and any `FAIL` line verbatim. Nothing else is needed,
and nothing that carries a token should travel.

## Open: the provider axis is documented everywhere and tested nowhere

The pluggability claim is the one part of the objective with no automated check behind it. A grep
for `OLLAMA`, `api_mode` or `ollama.com` across `tests/` returns nothing, while the behaviour is
described in `README.md`, `docs/adding-knowledge.md` and `docs/decisions.md`.

What is actually known, as opposed to documented:

* the whole stack runs with `SEDNA_OLLAMA_MODEL=glm-5.3:cloud` against Ollama cloud, through the
  seed import, an ingest of one new source (94 -> 95) and the verification suite;
* the mode is derived from the URL -- `openai` when it contains `ollama.com` or `/v1`, native
  otherwise -- and the reranker has been exercised through the local path.

What is not known: that the OpenAI-compatible mode composes a correct request, and that a
provider which is unreachable or answers with the wrong shape produces an error a user can act
on rather than a stack trace. Those are the two things that decide whether "point it at any
OpenAI-compatible endpoint" is a promise or a hope.

The test intended for it needs no cloud and no queue: a small recording server on the host, the
provider pointed at it through `host.docker.internal` in both modes, and the captured request
shape asserted -- path, `Authorization` header, body fields -- with the pipeline outcome
explicitly out of scope, because a recording server cannot satisfy the compiler's schema and
pretending otherwise would be the kind of check this repository has already learned to distrust.

## Two corrections and one defect, all measured

**The macOS queue was not hours long.** Three rounds of narration described the CI jobs as "queued
for hours"; the run timestamps show four runs created within two minutes of each other, with the
newest already executing. The queue is genuinely slow to schedule -- GitHub annotates that macOS
runners are capacity constrained -- but the "hours" was produced by counting my own rounds instead
of reading a clock. Adding `concurrency: cancel-in-progress` is right and stays, because a workflow
should not verify commits nobody is looking at; it was not, however, the cause of a long block.

**A queued job holds the run open**, so both macOS jobs are now bounded (20 and 40 minutes). Before
that, a congested pool could expire a job and turn the workflow red for a reason unrelated to the
commit, which teaches people to ignore a red workflow.

**`foundation_quarantined` arrives with `reason_codes: []`.** Measured, twice, on two different
files. `docs/adding-knowledge.md` states that a quarantined source "must be reported loudly, with
the reason", and the `failed` disposition does exactly that -- the provider probe gets
`missing_parsed_response` when a recording server answers with prose. So the contract is honoured
for one disposition and not for the other, and the difference matters most in the case a user is
most likely to hit: a correctly-formed file in the wrong place. The gate's condition is worth
finding anyway -- the disposition string is not in site-packages -- and the reason code should come
with it.
