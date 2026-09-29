# 4-Lane Retrieval Playbook

## Lane Definitions & Scoring Thresholds

| Lane | Epistemic Role | Threshold | Hard Exclusions |
|------|----------------|-----------|-----------------|
| References | Source-backed technical facts | 0.40 | OS/Arch mismatch |
| Case Steps | Analogous experience (must adapt) | 0.45 | Required prerequisites missing |
| Negative Evidence | Failed paths, counter-indications | 0.35 | None (always applicable) |
| Decision Guidance | Observation → intent rules | 0.50 | Conflicts with observed facts |

## Query Formulation Heuristics

### 1. Target + Authorization (Mandatory)
```json
{
  "target": "10.10.11.234",
  "authorization": {
    "state": "authorized",
    "exact_targets": ["10.10.11.234"]
  }
}
```

### 2. Observed Facts (Boosts relevance)
```json
"observed_facts": [
  {"namespace": "typed", "key": "os_family", "value": "linux", "confidence": 0.9},
  {"namespace": "typed", "key": "web_server", "value": "gitea", "confidence": 0.8}
]
```

### 3. Observed Services (Filters case steps)
```json
"observed_services": ["http-8080", "ssh-22"]
```

### 4. Query Terms (Lexical matching)
```json
"query_terms": ["authentication bypass", "default credentials", "gitea"]
```

## Lexical-Matching Reality (validated on Reactor + DanglingTree)

The FTS matcher is **lexical**, not semantic: a case-study bundle only surfaces if the
query/observed terms literally appear in the materialized artifact text. Two field names
matter and are easy to confuse:

- `observed_terms` — used by the retrieval matcher to rank case steps/references.
- `query_terms` — submitted with the query, but the per-artifact matcher runs on
  `observed_terms` (a bare `query_terms` without `observed_terms` still matches, but
  scoring weights `observed_terms`).

Concrete validation from two boxes:
- **Reactor**: bundle says "Next.js", so a term `nextjs` (no dot) does NOT match; use
  `reactor`, `node inspector`, `privilege escalation`, `sqlite`.
- **DanglingTree**: bundle says "EmployeeAuthTemplate is owned ... (ESC4)" and
  "nTSecurityDescriptor needs the SD_FLAGS control", so `employeeauthtemplate`,
  `sd-flags`, `nTSecurityDescriptor` surface it as top-ranked case step (score ~0.81,
  `verification status verified`).

**When a freshly-ingested case study doesn't appear in retrieval**, check the FTS index
directly before re-querying:
```sql
SELECT artifact_id FROM artifact_fts WHERE artifact_fts MATCH '<term>';
```
against `indexes/retrieval.sqlite`, then re-issue with terms that match the bundle's
actual wording.

## Lane Interpretation Guide

### References Lane
- **Use for**: Technology behavior, protocol details, configuration defaults
- **Ignore**: Specific exploit steps (those are in case steps)
- **Score ≥ 0.7**: High-confidence technical baseline

### Case Steps Lane
- **Use for**: "How did someone solve a similar problem?"
- **Check**: `transfer_conditions` — are prerequisites met?
- **Score ≥ 0.6**: Strong analogical candidate
- **Never**: Copy-paste without adaptation

### Negative Evidence Lane
- **Use for**: Deprioritize paths that historically failed
- **Interpret**: "This approach failed because X" not "This approach never works"
- **Score**: Lower is better (more negative evidence = stronger signal to avoid)

### Decision Guidance Lane
- **Use for**: "If I observe X, I should do Y"
- **Evaluate**: Does current observation match antecedent?
- **Score ≥ 0.6**: Actionable guidance

## Common Pitfalls

1. **Cross-lane score comparison** — Never compare 0.65 in References vs 0.65 in Case Steps
2. **Ignoring missing_context** — Returned as clarification questions; resolve before acting
3. **Treating case steps as recipes** — They are analogies requiring adaptation
4. **Skipping negative evidence** — Most valuable signal for avoiding wasted effort
