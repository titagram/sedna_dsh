# Decisions

The log behind the shape of this repository. Dated entries, newest scope first.
Machine-specific detail (paths, addresses, the working inventory) stays in the
maintainer's private notes; this file is the part that is safe to publish.

## 2026-09-29 — the objective

**D1 · DSH-only.** The stack serves DeepSeek Harness and nothing else. Hermes and
Hades are out of the product, not merely optional.

**D2 · A new repository.** Rather than evolve the existing Sedna repository — whose
history carries collected write-ups — this repository starts clean, with the engine
vendored under `engine/`.

**D3 · Native installer, not containers.** `install.sh` + `systemd --user`. The
stack runs where DSH runs; no virtualization layer between the two.

**D4 · The model is chosen at first run.** Either an OpenAI-compatible endpoint with
a key the user supplies, or a local ollama. The stack is inert without a model, so
this is a first-class question rather than a config file to find later.

**D5 · Full memory.** The seed carries the complete bank, not a curated subset. The
discovery that made this affordable: `hindsight-admin export-bank` produces a
portable, embedding-free archive — 8.9 MB for a bank whose database is 553 MB —
because import re-embeds locally.

**D6 · The seed is data and gets a human.** The refresh job opens a pull request on
a `seed` branch; it does not push to `main`.

## 2026-09-29 — consequences worth recording

**D7 · Test suites are not vendored.** The Sedna test suite contains flag-shaped
literals in its fixtures — by design, because it tests flag detection. Shipping it
would mean either failing this repository's own gate or teaching the gate an
exception for its own vendored code. Neither is acceptable: the tests stay upstream,
and `engine/` carries the sources only.

**D8 · Warnings are allowed, and listed.** IP addresses, e-mail addresses and
machine paths are not treated as secrets. They are counted, printed, and published
deliberately; `--strict-warn` exists for a stricter line.

**D9 · The operator's home directories are normalised.** Home paths of the
maintainer's own machines are rewritten in the exported copy before publishing,
because they identify the source machine and mean nothing on the target. Home
directories inside target documents are knowledge and are left alone.

**D10 · Redaction happens on the export, never on the live bank.** The live bank is
the operator's working memory; rewriting it to make a seed publishable would trade a
publication problem for a data-integrity one.

**D11 · The seed refresh proposes, it does not publish.** `tools/refresh-seed.sh`
regenerates the seed, runs the gate, and commits on a `seed/refresh-<date>` branch;
it never touches the default branch. Memory is data, and the review is the point.

**D12 · An uninstall keeps the memory.** Removing the stack removes what the installer
created and restores what it changed, but the Hindsight bank survives by default: a
bank is a year of notes, not an installation artifact. `--purge-data` deletes it and
says so first.

**D15 · No bundled preset.** A preset is a complete composition, not an overlay, so
shipping one means copying the shipped `standard` preset's rows into this repository and
maintaining them against every DSH release. A stale copy would silently withhold new
tools from the agent that mounts it. Instead `docs/preset.md` documents the three edits
(the plugin row, the skills row, a persona) with the mount-validation procedure.

## Open

**D16 · Licence: MIT, with the memory carved out.** Every component this repository
vendors or installs is MIT — the Sedna engine, Hindsight, DSH — so MIT is what the
repository carries (`LICENSE`). The memory backup in `seed/` is not software and is
explicitly outside that grant: it is the author's own notes about authorised lab work,
published so a new installation starts with a memory rather than an empty one, with no
warranty and no rights to any third-party material it may describe.

**D17 · Name: `sedna_dsh`.** The repository is published under the author's own
spelling.

**D18 · The seed publishes the lab, not the person — and the first version of this rule
was wrong.** What is redacted on every rebuild: private keys, secret-shaped assignments,
**mailboxes at consumer providers** (a real person's address) and **this machine's own
public addresses** — its egress address and its tailnet address. That last rule asks the
machine (`tools/sanitize_export.py`), because a list of what must not be published would
itself publish it.

What is deliberately kept: lab users and lab domains (`ben@silentium.htb`,
`hr.trilocor.local`, `nexus.htb` — a target username *is* the finding: "user enumeration
distinguishes valid addresses"), private ranges, loopback, and addresses a lab scenario
names. The scanner still reports the kept classes as warnings rather than being tuned to
silence them.

The first version of this rule redacted **every** e-mail address and **every** public IPv4,
and it cost real knowledge: 65 of the bank's 106 addresses were lab domains, and three of
the knowledge base's sources were excluded — one of them for `ben@silentium.htb` and one
for an address a challenge attributes to an attacker. A blanket rule looked cautious and
was simply blunt: it removed the finding, not the exposure. Hence the narrower rule above,
and hence `tools/list_seed_unsafe_sources.py` importing the predicate from the sanitizer
instead of reimplementing it — one policy, two places it is applied, no drift.

One source remains excluded, for a structural reason rather than a privacy one: it was
promoted from an engagement journal, so it stays valid only while the artifact it was
rendered from exists, and that artifact lives under `engagements/`, which this seed does
not publish. `tools/list_journal_promoted.py` finds those.
