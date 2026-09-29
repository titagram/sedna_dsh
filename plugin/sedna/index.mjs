// DSH sedna-bridge plugin — gives a DSH session native `sedna_*` tools.
//
// Sedna ships as a Hermes/Hades plugin (`~/.hermes/plugins/sedna/plugin.yaml`,
// `provides_tools: sedna_*`) whose registration ABI is not Cordis, and whose
// planning lane is bound with `HostKind.HADES`.  Without this bridge a DSH
// session can only reach Sedna through manual glue (the read-only console on
// 127.0.0.1:8085, or a hand-run `.venv/bin/python` with PYTHONPATH) — which is
// unreproducible and invisible to any ledger.
//
// This plugin is deliberately dependency-free (node builtins only, no bare
// imports), because it is loaded from a `file://` URL where the DSH packages are
// not resolvable.  `defineTool` is therefore unavailable: every tool is
// registered as a registry-ready definition with PLAIN JSON Schema (object-level
// `required` arrays), which is what `ctx.tools.register` asserts.
//
// The Sedna side lives in `driver.py` beside this file.  This plugin only
// marshals JSON: one request object on the child's stdin, one response object on
// its stdout, no shell, no string interpolation into a command line.
//
// SCOPE — minimal, no LLM needed.  Every op here constructs Sedna services from
// the knowledge root alone.  `sedna_plan_next` is NOT provided: the planning path
// needs the host structured-completion facade that Hermes supplies as `ctx.llm`
// and DSH does not expose here.  Journal writes ARE provided and are LLM-free:
// create / resume / abandon an engagement, and record one decision on it.
// (An earlier revision of this comment claimed record_decision was unavailable;
// it is provided, and was verified end to end.)
//
// Configuration, in order of precedence:
//   1. the `config:` block of the Cordis row that mounts this plugin (installer),
//   2. `config.json` beside this file (mode 0600),
//   3. the DEFAULTS below.
//
// The shipped installer writes (1), so a fresh machine needs no JSON file at all:
//   {
//     "python": "$HOME/.dsh/sedna/.venv/bin/python",
//     "driver": "$HOME/.dsh/plugins/sedna/driver.py",
//     "sednaSrc": "$HOME/.dsh/sedna/src",
//     "knowledgeRoot": "$HOME/.dsh/knowledge/sedna",
//     "timeoutMs": 120000
//   }
//
// Vendored from the ai_server bridge plugin (sedna-bridge) on 2026-09-29; the only
// change is that the defaults below point at the DSH-native layout instead of the
// Hermes layout this plugin was first written against.

import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const name = 'sedna-bridge'
export const inject = ['tools']

const DIR = process.env.DSH_SEDNA_DIR || join(homedir(), '.dsh', 'plugins', 'sedna')
const CONFIG_PATH = join(DIR, 'config.json')

const DEFAULTS = {
  python: join(homedir(), '.dsh', 'sedna', '.venv', 'bin', 'python'),
  driver: join(DIR, 'driver.py'),
  sednaSrc: join(homedir(), '.dsh', 'sedna', 'src'),
  knowledgeRoot: join(homedir(), '.dsh', 'knowledge', 'sedna'),
  timeoutMs: 120000,
}

function loadConfig() {
  try {
    return { ...DEFAULTS, ...JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) }
  } catch {
    return { ...DEFAULTS }
  }
}

/** Object-rooted JSON Schema helper: `required` is an array, never a per-property flag. */
const obj = (properties, required = []) => ({ type: 'object', additionalProperties: false, properties, required })

const text = (value) => [{ type: 'text', text: value }]

/**
 * Run one driver op.  Returns `{ ok: true, data }` or `{ ok: false, error }`;
 * a driver that dies, times out, or prints non-JSON becomes a structured error
 * rather than an exception thrown into the agent loop.
 */
function runDriver(settings, op, args) {
  const request = JSON.stringify({ op, args: args || {} })
  let stdout
  try {
    stdout = execFileSync(settings.python, [settings.driver], {
      input: request,
      encoding: 'utf8',
      timeout: settings.timeoutMs,
      maxBuffer: 8 * 1024 * 1024,
      env: {
        ...process.env,
        SEDNA_SRC: settings.sednaSrc,
        SEDNA_KB_ROOT: settings.knowledgeRoot,
        PYTHONDONTWRITEBYTECODE: '1',
      },
    })
  } catch (error) {
    const stderr = typeof error?.stderr === 'string' ? error.stderr.trim().split('\n').slice(-3).join(' | ') : ''
    return { ok: false, error: `driver_failed: ${error?.message || error}${stderr ? ` :: ${stderr}` : ''}` }
  }

  const line = String(stdout).trim().split('\n').filter(Boolean).pop()
  if (!line) return { ok: false, error: 'driver produced no output' }
  try {
    const parsed = JSON.parse(line)
    if (parsed && parsed.ok === true) return { ok: true, data: parsed.data }
    return { ok: false, error: JSON.stringify(parsed?.error ?? parsed) }
  } catch {
    return { ok: false, error: `driver produced non-JSON output: ${line.slice(0, 300)}` }
  }
}

const LANES = ['references', 'case_steps', 'negative_cases', 'decision_guidance']

function renderLanes(data) {
  const out = []
  if (data.knowledge_gap) out.push(`knowledge gap: ${data.knowledge_gap.code} (retryable=${data.knowledge_gap.retryable})`)
  for (const lane of LANES) {
    const items = data[lane] || []
    out.push(`${lane} (${items.length}):`)
    for (const item of items) out.push(`  - ${item.artifact_id} [${item.artifact_type}] ${item.label || '(no summary)'}`)
  }
  if (data.rejected_candidates) out.push(`rejected candidates: ${data.rejected_candidates}`)
  return out.join('\n')
}

export function apply(ctx, config) {
  const settings = { ...loadConfig(), ...(config && typeof config === 'object' ? config : {}) }

  ctx.tools.register({
    name: 'sedna_retrieve_knowledge',
    description:
      'Retrieve source-backed strategic knowledge from the Sedna knowledge base for an explicitly authorized lab/HTB/CTF target. Returns four lanes (references, case_steps, negative_cases, decision_guidance) plus an explicit knowledge gap. Read-only. Pass authorization_state="authorized" with the target in exact_targets: Sedna fails closed and returns a pre-backend gap for an unauthorized or invalid target.',
    parameters: obj(
      {
        target: { type: 'string', description: 'The authorized lab target: IP address or hostname.' },
        authorization_state: {
          type: 'string',
          description: 'Typed authorization decision: authorized | unknown | unauthorized. Default unknown (fails closed).',
        },
        exact_targets: {
          type: 'array',
          items: { type: 'string' },
          description: 'Targets inside the declared authorized scope. Must contain the target to get knowledge back.',
        },
        observed_terms: { type: 'array', items: { type: 'string' }, description: 'Live situation terms, e.g. ["websocket","ssrf"].' },
        observed_services: { type: 'array', items: { type: 'string' }, description: 'Services observed live, e.g. ["http"].' },
        query_terms: { type: 'array', items: { type: 'string' }, description: 'Retrieval query terms, e.g. ["privilege escalation"].' },
        query_synonyms: { type: 'array', items: { type: 'string' }, description: 'Bounded query synonyms.' },
        lane_limit: { type: 'integer', description: 'Max candidates per lane (1..20, default 5).' },
        max_candidates: { type: 'integer', description: 'Max candidates considered (1..100, default 32).' },
      },
      ['target'],
    ),
    output: {
      schema: obj(
        {
          ok: { type: 'boolean' },
          target: { type: 'string' },
          gap: { type: 'string' },
          counts: { type: 'string' },
          detail: { type: 'string' },
          error: { type: 'string' },
        },
        ['ok', 'target'],
      ),
      render: (_args, value) =>
        text(
          value.ok
            ? `sedna retrieve → ${value.target}\n${value.counts}\n\n${value.detail}`
            : `sedna retrieve FAILED: ${value.error}`,
        ),
    },
    async execute(args) {
      const result = runDriver(settings, 'retrieve', {
        target: args.target,
        authorization_state: args.authorization_state || 'unknown',
        exact_targets: args.exact_targets || [],
        observed_terms: args.observed_terms || [],
        observed_services: args.observed_services || [],
        query_terms: args.query_terms || [],
        query_synonyms: args.query_synonyms || [],
        lane_limit: args.lane_limit ?? 5,
        max_candidates: args.max_candidates ?? 32,
      })
      if (!result.ok) return { ok: false, target: String(args.target), error: result.error }
      const data = result.data
      return {
        ok: true,
        target: String(args.target),
        gap: data.knowledge_gap ? data.knowledge_gap.code : '',
        counts: LANES.map((lane) => `${lane}=${(data[lane] || []).length}`).join(' '),
        detail: renderLanes(data),
      }
    },
    presentCall: (args) => ({ card: 'generic', title: `Sedna retrieve → ${args.target}`, kind: 'other' }),
  })

  ctx.tools.register({
    name: 'sedna_get_knowledge_artifact',
    description:
      'Load one exact canonical Sedna knowledge artifact by its retrieval artifact id (the ids returned by sedna_retrieve_knowledge). Read-only.',
    parameters: obj({ artifact_id: { type: 'string', description: 'Retrieval artifact id, e.g. "case_step-…".' } }, ['artifact_id']),
    output: {
      schema: obj(
        { ok: { type: 'boolean' }, found: { type: 'boolean' }, artifact_id: { type: 'string' }, artifact: { type: 'string' }, error: { type: 'string' } },
        ['ok', 'found', 'artifact_id'],
      ),
      render: (_args, value) =>
        text(
          value.ok
            ? value.found
              ? value.artifact
              : `artifact ${value.artifact_id} not found in the retrieval index`
            : `sedna artifact FAILED: ${value.error}`,
        ),
    },
    async execute(args) {
      const result = runDriver(settings, 'artifact', { artifact_id: args.artifact_id })
      if (!result.ok) return { ok: false, found: false, artifact_id: String(args.artifact_id), error: result.error }
      const data = result.data
      return {
        ok: true,
        found: Boolean(data.found),
        artifact_id: String(data.artifact_id),
        artifact: data.found ? JSON.stringify(data.artifact, null, 2) : '',
      }
    },
    presentCall: (args) => ({ card: 'generic', title: `Sedna artifact ${args.artifact_id}`, kind: 'other' }),
  })

  ctx.tools.register({
    name: 'sedna_knowledge_maintenance',
    description:
      'Audit or rebuild the disposable Sedna retrieval index. "audit" reports whether the index still matches the canonical verified bundles; "rebuild" replaces it only after the whole canonical corpus validates. Use audit before trusting a retrieval that returns nothing, and rebuild only when the audit says it is required.',
    parameters: obj(
      { operation: { type: 'string', description: 'audit (default) or rebuild.' } },
      ['operation'],
    ),
    output: {
      schema: obj(
        { ok: { type: 'boolean' }, operation: { type: 'string' }, rebuild_required: { type: 'boolean' }, indexed_sources: { type: 'integer' }, issues: { type: 'string' }, error: { type: 'string' } },
        ['ok', 'operation'],
      ),
      render: (_args, value) =>
        text(value.ok ? `sedna ${value.operation}: ${value.issues}` : `sedna maintenance FAILED: ${value.error}`),
    },
    async execute(args) {
      const operation = args.operation || 'audit'
      const result = runDriver(settings, 'maintenance', { operation })
      if (!result.ok) return { ok: false, operation, error: result.error }
      const report = result.data.report || {}
      const issues = Array.isArray(report.issues) ? report.issues : []
      return {
        ok: true,
        operation: String(result.data.operation),
        rebuild_required: Boolean(report.rebuild_required),
        indexed_sources: Number(report.indexed_source_count ?? 0),
        issues:
          `rebuild_required=${Boolean(report.rebuild_required)} ` +
          `indexed_source_count=${Number(report.indexed_source_count ?? 0)} ` +
          `issues=${issues.length}` +
          (issues.length ? ` ${JSON.stringify(issues.slice(0, 5))}` : ''),
      }
    },
    presentCall: (args) => ({ card: 'generic', title: `Sedna maintenance ${args.operation || 'audit'}`, kind: 'other' }),
  })

  ctx.tools.register({
    name: 'sedna_manage_engagement',
    description:
      'Read or mutate the Sedna engagement journal. Read-only: action="list" lists engagement snapshots with their status; action="inspect" returns one engagement with its manifest, event count, revision, health and bound execution lanes. WRITE: action="create" opens a new engagement and binds the calling lane to it (needs display_name, objective, exact_targets); action="resume" binds the calling lane to an existing engagement (engagement_id, or the newest resumable one); action="abandon" closes one with a reason. Writes require session_id — the lane identity written into the append-only journal; this plugin has no trusted session context to infer one from. NOTE a measured asymmetry: record_decision is lane-gated and fails closed, but resume and abandon are NOT gated on the lane being bound to the target engagement (a never-bound lane can abandon an arbitrary engagement), so the bridge additionally requires confirm=true for those two. Abandon is reversible via reopen, and abandoning a stale engagement does not block later creation.',
    parameters: obj(
      {
        action: { type: 'string', description: 'list (default) | inspect | create | resume | abandon.' },
        engagement_id: { type: 'string', description: 'Engagement UUID; required for inspect, and for resume/abandon of a specific engagement.' },
        limit: { type: 'integer', description: 'Max engagements for list (default 50).' },
        session_id: { type: 'string', description: 'Lane identity; required for create, resume and abandon.' },
        host_kind: { type: 'string', description: 'Lane host kind: other (default) | hades | hermes.' },
        task_id: { type: 'string', description: 'Optional task identity within the lane.' },
        confirm: { type: 'boolean', description: 'Required true for resume and abandon, which Sedna does not lane-gate.' },
        display_name: { type: 'string', description: 'create: engagement name.' },
        objective: { type: 'string', description: 'create: the engagement objective.' },
        exact_targets: { type: 'array', description: 'create: the declared authorized scope, e.g. ["10.10.10.1"].' },
        authorization_state: { type: 'string', description: 'create: authorized | unknown | unauthorized.' },
        reason: { type: 'string', description: 'abandon: why the engagement is being closed.' },
      },
      ['action'],
    ),
    output: {
      schema: obj(
        { ok: { type: 'boolean' }, action: { type: 'string' }, count: { type: 'integer' }, detail: { type: 'string' }, error: { type: 'string' } },
        ['ok', 'action'],
      ),
      render: (_args, value) => text(value.ok ? value.detail : `sedna engagements FAILED: ${value.error}`),
    },
    async execute(args) {
      const action = args.action || 'list'
      const result = runDriver(settings, 'engagements', {
        action,
        engagement_id: args.engagement_id,
        limit: args.limit ?? 50,
        session_id: args.session_id,
        host_kind: args.host_kind || 'other',
        task_id: args.task_id,
        confirm: args.confirm === true,
        display_name: args.display_name,
        objective: args.objective,
        exact_targets: args.exact_targets,
        authorization_state: args.authorization_state,
        reason: args.reason,
      })
      if (!result.ok) return { ok: false, action, error: result.error }
      const data = result.data
      if (data.action === 'list') {
        const lines = (data.engagements || []).map(
          (item) => `  - ${item.engagement_id} [${item.status}] ${item.display_name}${item.objective ? ` — ${item.objective}` : ''}`,
        )
        return { ok: true, action: 'list', count: data.count, detail: `engagements (${data.count}):\n${lines.join('\n')}` }
      }
      if (data.action === 'inspect') {
        const lanes = (data.bound_lanes || []).map((lane) => `${lane.host_kind}:${lane.session_id}/${lane.task_id}`)
        return {
          ok: true,
          action: 'inspect',
          count: 1,
          detail:
            `engagement ${data.engagement_id}\n  name: ${data.display_name}\n  status: ${data.status}\n` +
            `  objective: ${data.objective}\n  events: ${data.event_count} (revision ${data.revision_sequence})\n` +
            `  journal_healthy: ${data.journal_healthy} closure_ready: ${data.closure_ready}\n` +
            `  bound lanes: ${lanes.join(', ') || '(none)'}`,
        }
      }
      const wrote = data.result || {}
      return {
        ok: true,
        action: data.action,
        count: 1,
        detail:
          `${data.action} ok: ${wrote.engagement_id} [${wrote.status}] "${wrote.display_name}"\n` +
          `  revision: ${wrote.revision_sequence} (+${wrote.created_events} event(s))\n` +
          `  lane: ${(data.lane || {}).host_kind}:${(data.lane || {}).session_id}\n` +
          `  lane_binding: ${data.lane_binding}`,
      }
    },
    presentCall: (args) => ({ card: 'generic', title: `Sedna engagements ${args.action || 'list'}`, kind: 'other' }),
  })

  ctx.tools.register({
    name: 'sedna_record_decision',
    description:
      'Record one custom strategy decision on a Sedna engagement journal, bound to the calling execution lane. This is the bridge\'s only WRITE tool: it appends to the engagement\'s append-only journal. Sedna fails closed, so the lane must already be bound to the engagement — a decision from a fresh DSH lane on an engagement that Hermes created is REFUSED ("decision_recorded requires a lane currently bound to this engagement"), and that refusal is the control working, not a bridge failure. Bind a lane by creating or resuming the engagement from the lane that will record. Supply session_id explicitly: it is the lane identity written into the journal, and this plugin has no trusted session context to infer it from.',
    parameters: obj(
      {
        engagement_id: { type: 'string', description: 'Engagement UUID the journal belongs to.' },
        session_id: { type: 'string', description: 'The calling lane\'s session identity; written into the journal.' },
        task_id: { type: 'string', description: 'Optional task identity within the session; defaults to the session identity.' },
        host_kind: { type: 'string', description: 'Lane host kind: other (default) | hades | hermes.' },
        strategy: { type: 'string', description: 'The chosen strategy, in prose (max 8192 chars).' },
        rationale: { type: 'string', description: 'Why this strategy; required whenever strategy is given.' },
      },
      ['engagement_id', 'session_id', 'strategy', 'rationale'],
    ),
    output: {
      schema: obj(
        { ok: { type: 'boolean' }, detail: { type: 'string' }, error: { type: 'string' } },
        ['ok'],
      ),
      render: (_args, value) => text(value.ok ? value.detail : `sedna record_decision FAILED: ${value.error}`),
    },
    async execute(args) {
      const result = runDriver(settings, 'record_decision', {
        engagement_id: args.engagement_id,
        session_id: args.session_id,
        task_id: args.task_id,
        host_kind: args.host_kind || 'other',
        strategy: args.strategy,
        rationale: args.rationale,
      })
      if (!result.ok) return { ok: false, detail: '', error: result.error }
      const data = result.data
      const r = data.result || {}
      const lane = data.lane || {}
      return {
        ok: true,
        detail:
          `decision recorded on ${r.engagement_id} (${r.display_name})\n` +
          `  lane: ${lane.host_kind}:${lane.session_id}/${lane.task_id}\n` +
          `  binding: ${data.lane_binding}\n` +
          `  status: ${r.status} revision: ${r.revision_sequence}\n` +
          `  events created: ${r.created_events} already present: ${r.existing_events}`,
      }
    },
    presentCall: (args) => ({ card: 'generic', title: `Sedna record decision → ${args.engagement_id}`, kind: 'other' }),
  })
}

if (!existsSync(CONFIG_PATH)) {
  console.warn(`sedna-bridge: no config at ${CONFIG_PATH}; using defaults`)
}
if (!existsSync(DEFAULTS.driver)) {
  console.warn(`sedna-bridge: driver.py missing at ${DEFAULTS.driver}`)
}
