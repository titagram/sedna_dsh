# Sedna

HTB/CTF penetration testing plugin for Hades — tool wrappers, evidence collection, knowledge base.

## Status

Early development. See `pyproject.toml` for dependencies.

## Knowledge ingestion foundation

The deterministic foundation prepares heterogeneous lessons, references, and
walkthroughs without treating them as universal instructions:

```text
raw source -> inventory -> classification -> structural parser
           -> logical segments -> PreparedSource
```

`raw_src/` is immutable input. Inventory records stable source identities and
content hashes, classification chooses a deterministic parser profile and an
ingestion outcome, and the structural parser preserves headings, blocks, line
spans, and provenance. Logical segmentation then creates retrieval-safe units
while keeping related observations, actions, outputs, and conclusions together.
`IngestionPipeline` is the entry point for this flow. Its `prepare()` method
returns a typed `PreparedSource` when an accepted document is newly processed or
reprocessed; an unchanged accepted document returns `None` because its canonical
state already exists.

Generated JSON manifests retain the canonical disposition for every source:
accepted, excluded, or quarantined. A separate `IngestionReport` records each
run's outcomes, including unchanged sources and failures. Quarantine records
explain ambiguous or unsupported input; the raw files themselves remain the
canonical source material and are never rewritten. Prepared structural documents
may retain original source text for provenance review and therefore must not be
indexed directly. Only sanitized logical-segment fields are prepared for search,
and final flags such as `HTB{...}` or contextual user/root flag values are excluded
from those fields.

The deterministic foundation stops at `PreparedSource`. The M2 semantic compiler
can then process one supplied prepared source through a caller-provided Hades LLM
facade:

```text
PreparedSource -> host LLM extractor -> critic -> bounded repair
               -> canonical SemanticKnowledgeBundle
```

`SemanticIngestionService.compile_and_store()` checks canonical currentness
before invoking the model, returns the stored typed bundle and verification as
`unchanged` when all source and compiler versions match, and otherwise compiles
once. Verified bundles and explainable quarantines are persisted atomically;
transport or validation failures remain local to that run. Semantic artifacts
retain exact segment provenance, applicability conditions, and graded epistemic
metadata while keeping strategic intent separate from detailed Hades tool
operation.

M2's compiler still accepts one `PreparedSource` at a time. M4 composes that
boundary into a user-facing local file-or-folder workflow through the same host
LLM, as described below. PDF contents remain quarantined until a deterministic
PDF parser is added rather than being partially or silently extracted.

## Local strategic retrieval (M3)

Verified `SemanticKnowledgeBundle` JSON files under `semantic_bundles/` are the
canonical source of truth. The SQLite FTS5 database under `indexes/` is only a
disposable projection: it can be deleted, is ignored by Git, and must never be
used to reconstruct or overwrite canonical knowledge. Index writes accept only
strictly validated semantic bundles and store normalized artifacts, applicability
facets, parent links, provenance, and searchable strategic fields.

`SQLiteRetrievalIndex` supports source-scoped upsert/delete, exact artifact lookup,
and atomic full rebuild. Its internal schema is versioned and audited for integrity,
canonical projection parity, FTS rows, provenance, ownership, and source identity.
`RetrievalMaintenanceService` rebuilds exclusively from a stable snapshot of the
canonical repository and reports missing, stale, orphaned, or corrupt projection
state. A failed audit asks for a rebuild; it never repairs canonical JSON from the
index.

`KnowledgeRetrievalService` returns four independent epistemic lanes:

- references for source-backed technical or methodological knowledge;
- case steps as analogous experience that must be adapted to the current context;
- negative evidence that explains failed paths without declaring universal dead ends;
- decision guidance that connects observations to strategic action intent.

Scores are explainable and comparable only inside their lane. The current lexical
and facet thresholds are 0.40 for references, 0.45 for case steps, 0.35 for negative
evidence, and 0.50 for guidance. Known OS, architecture, identity, or environment
conflicts are hard exclusions. Missing required context remains conditional, lowers
applicability, and is returned as a question; it is not silently treated as a match.
Copied sources share an independence group so repeated copies cannot monopolize a
bounded result lane.

Every qualifying hit retains its exact canonical identity, provenance, score
components, matched facets, qualifications, and missing context. Invalid target
syntax such as `300.456.456.123` produces `invalid_target` before any index call.
An authorized query with no qualifying evidence produces
`no_applicable_knowledge`, including the observed domain, missing context, suggested
documents, and whether external research is eligible. Backend failure is a distinct
`retrieval_unavailable` gap and never masquerades as corpus absence.

Source-authored credential literals are historical, case-local examples: Sedna does
not decide whether they were “real,” and never promotes them to current-target
credentials. `case_specific_details` remain available in the canonical case for
provenance review but are removed from strategic search fields and ranked case-step
views. Final flags and runtime/provider secrets remain forbidden.

The versioned `retrieval-golden-v1` suite rebuilds a real SQLite index from canonical
M2 bundles and runs the real retrieval service. Its lexical/facet baseline gates are
recall@8 >= 0.90, precision@8 >= 0.70, zero hard-incompatibility violations,
deterministic repeated results, at most 5 seconds per scenario and 30 seconds total,
and an index no larger than 5 MiB for the fixture corpus. The suite also covers a
private IPv4 target, unknown and confirmed OS applicability, all evidence lanes,
invalid input with zero backend access, Android/ADB corpus absence, copied-source
diversity, exact lookup, and delete/rebuild equivalence.

Elasticsearch, embeddings, and vector databases remain deferred. A future backend
must use a new versioned suite and demonstrate at least a 0.05 absolute recall@K
gain without dropping below the lexical precision baseline, introducing any hard
incompatibility violation, or losing deterministic provenance before its operational
cost is considered.

## Autonomous local learning and Hades tools (M4/M5)

M4 exposes `sedna_learn_local` for one local file or folder. Documents are
classified and verified automatically through the host LLM's structured facade;
one malformed source does not stop the remaining folder. The workflow requires no
human approval, reports every candidate disposition, persists only verified
canonical semantics, and reconciles the disposable retrieval index after the run.

Compilation is idempotent across the exact source, parser/extractor, schema,
prompt, and compiler-version contract. An identical second learning run makes no
host-model call for current sources and produces no duplicate canonical or indexed artifacts.
A controlled version change reprocesses once and the next identical run is
unchanged.

Existing exact `2.4.0` bundles remain strategically retrievable during the `2.5.0` transition.
After a SQLite-v5 rebuild they expose zero execution-example locators and the typed
`legacy_bundle_without_examples` gap until their original bytes are relearned. Operators can run
`sedna_learn_local` one available original root at a time, then maintenance `rebuild` and `audit`;
unavailable originals stay strategic-only, with no in-place canonical migration or corpus outage.

The Hades plugin now registers four strategic-knowledge tools:

- `sedna_learn_local` learns a supplied local source selection;
- `sedna_retrieve_knowledge` validates authorization and target syntax, then
  retrieves independent reference, case, negative-evidence, and guidance lanes;
- `sedna_get_knowledge_artifact` loads exact canonical provenance for citation;
- `sedna_knowledge_maintenance` audits or rebuilds the disposable SQLite
  projection.

The plugin is zero-configuration for canonical storage. Unless a call supplies
`knowledge_root` or the host supplies `ctx.sedna_knowledge_root`, Sedna resolves
`<active Hades home>/knowledge/sedna` on each operation. The active home honors Hades context,
`HERMES_HOME`, `HADES_HOME`, and platform defaults, so installations and profiles remain
isolated without hardcoded paths. Existing custom or pilot stores are not automatically migrated
or merged.

Direct remote fetching remains outside Sedna's local learning tool. Hades may
perform authorized technical research under its own policy, save the material
locally with source metadata, and submit that file through the identical verified
pipeline. Exact machine solutions and final-answer material remain out of scope.
Operational tool syntax remains the responsibility of Hades `/learn` skills;
Sedna provides strategy, technical references, applicability, and adaptable case
experience.

The executable M5 demo covers a source-backed hypothetical private-IP query,
pre-backend invalid-IP rejection, a truthful Android/ADB knowledge gap, and exact
artifact drill-down. The granular LLM-facing call and response contract is in the
[Sedna knowledge tools guide](docs/llm/sedna-knowledge-tools.md).

The approved architecture for semantic compilation and later retrieval is
documented in the [semantic ingestion and retrieval design](docs/superpowers/specs/2026-08-07-sedna-semantic-ingestion-retrieval-design.md).
It defines the host-LLM extractor and critic, applicability facets, automatic
verification, canonical JSON/JSONL storage, SQLite FTS5 retrieval, the implemented
document-learning boundary, and the evaluation gate for any later vector database.

`ingest_markdown` remains available temporarily for callers of the original
SQLite-backed `KnowledgeChunk` workflow. It does not feed the strategic pipeline;
new ingestion integrations should use `IngestionPipeline`.

Third-party corpora are evaluated as pinned, untrusted reference sources rather
than installed as agent instructions. See the
[Claude-Red integration assessment](docs/architecture/2026-08-06-claude-red-integration-assessment.md)
for the proposed source adapter, Hades boundary, quality gates, and pilot rollout.

## M6 Engagement Journal and Adaptive Planner

Since `0.2.0`, the plugin registers persistent engagement control tools
(`sedna_manage_engagement`, `sedna_record_decision`, `sedna_add_source`), the adaptive
`sedna_plan_next` tool, and nine
observer hooks that retain host tool calls, results, decisions, and session checkpoints
inside a crash-safe local journal per engagement.

Planning is invocation-scoped: each plan or lifecycle settlement resolves the active knowledge
root, opens one complete host-backed runtime, and closes it before returning. `sedna_plan_next`
uses the exact host-bound session/task lane and accepts no caller-selected root. Proposals and
source-derived command examples are non-coercive suggestions that require host validation;
unplanned actions remain allowed and are assessed on the next planning pass.

- **Root layout.** Engagements live under the selected knowledge root in
  `engagements/<engagement-uuid>/`: `events.jsonl` (append-only, hash-chained events),
  `manifest.json`, `engagement-state.json`, `state.json`,
  `evidence/` (private blobs, session logbooks), and a `journal-head.json` commit anchor.
  Current runtimes treat both state files as one integrated engagement projection.
- **Explicit proofs.** `create` accepts explicit `required_proofs` (flag/access/custom).
  An empty list means *no proofs declared*, never "already complete".
- **Privacy.** Evidence blobs and logbooks are private to the engagement. Provider or host
  secrets are redacted before persistence and carry `capture_limitations`; proofs never
  appear in manifests, semantic bundles, retrieval inputs, `sources.md`, or public tool
  responses.
- **Session logbooks.** Each host session gets an inert, fence-protected rendered logbook
  with inline evidence and revision markers; the projection is rebuilt after every
  authoritative append.
- **Hooks.** Control tools emit only a versioned `control_tool_invoked` marker; operational
  tools are correlated, argument-sidecarred, and completed with their original result.
  Correlation is by stable tool-call identity when available, otherwise bounded and
  explicitly uncertain.
- **Recovery.** A partial trailing JSON record (host crash mid-write) is recovered
  atomically into a typed `recovery_warning` with quarantined tail evidence; orphaned
  in-flight calls are terminated explicitly via `resolve_call`.
- **Boundaries.** All paths are absolute; relative roots fail closed. The engagement adapter
  performs one settlement per mandatory plan/resume/finalize/close/reopen path through the
  planning port. Incomplete or unavailable settlement exposes only bounded safe status and never
  claims a clean lifecycle transition.
- **Reports and verified case promotion.** Closing an engagement commits immutable canonical JSON
  and inert Markdown report revisions before the lifecycle becomes terminal. A later explicit
  `verify` promotes only the sanitized, provenance-bound strategic case projection through the
  same canonical semantic repository and disposable retrieval index; report-private evidence,
  credentials, flags, and host-adapted commands never cross that boundary. Promotion is a durable,
  idempotent journal saga: `inspect` and `resume` recover interrupted work, index failure remains
  retryable without discarding canonical semantics, and exact retries do not duplicate cases.
  While that saga owns the engagement, foreign journal, evidence, report, and planning-projection
  writes fail closed with retryable `promotion_saga_in_progress`; promotion-owned recovery and
  cancellation remain available. Later private report revisions retain promoted, revoked, and
  superseded transitions in their timeline without exposing public case payloads.
  Rejecting a proof or reopening a verified engagement first revokes or supersedes the published
  lineage, then atomically reopens the lifecycle. If no canonical lineage was published, the same
  path proves its absence and performs no destructive cleanup.

The LLM-facing operating contract with complete JSON examples is in the
[Sedna engagement tools guide](docs/llm/sedna-engagement-tools.md).

## Exportable Hermes skill

[`skills/sedna-cyber-workflow/SKILL.md`](skills/sedna-cyber-workflow/SKILL.md) is the
official, exportable **Hermes skill** for operating Sedna as a closed-loop cyber workflow. The
whole `skills/sedna-cyber-workflow/` directory is the distributable unit: it includes the skill
manifest/instructions, references, templates, verification scripts, and skill tests.

Install it into a Hermes profile by copying the directory without modifying its internal layout:

```bash
cp -R skills/sedna-cyber-workflow \
  "${HERMES_HOME:-$HOME/.hermes}/skills/security/sedna-cyber-workflow"
```

The exported skill preserves the writeup authorization gate: searching, opening, downloading,
consulting, or ingesting a machine/challenge writeup is **default deny** until the user supplies
explicit prior authorization. Generic technical references are not writeups, but their provenance
must still be journaled. Never place engagement secrets, credentials, private proof blobs, or raw
flag values in the exported skill.
