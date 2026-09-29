# Evidence Redaction Policy

This document defines strict data boundaries between Sedna's private engagement journal, promoted canonical knowledge, and public reports.

## Classification Levels

### LEVEL 0: PRIVATE (Sedna Journal Only)
**Never exported, never promoted, never in pt-report.**

| Data Type | Examples | Redaction Rule |
|-----------|----------|----------------|
| Raw flags | Platform proof values | Strip entirely; store only proof-of-capture metadata |
| Credential hashes | NTLM, SHA256, bcrypt, /etc/shadow lines | Strip entirely |
| API tokens | AWS keys, GitHub PATs, JWTs, session cookies | Strip entirely |
| Private IPs (internal) | `10.x.x.x`, `192.168.x.x` in evidence blobs | Redact to `10.x.x.x` format |
| Hostnames (internal) | `dc01.corp.local`, `gitlab.internal` | Redact to `<internal-hostname>` |
| File paths (host) | `/home/user/.ssh/id_rsa`, `/opt/app/config.yml` | Redact to `<host-path>` |
| Full command outputs | Raw nmap XML with scripts, ffuf full output | Store in private evidence blob only |
| Provider secrets | OpenRouter keys, Anthropic keys, Google keys | Strip entirely |

### LEVEL 1: SANITIZED (Promoted Cases + pt-report Internal)
**Used in canonical SemanticKnowledgeBundle and pt-report JSON, NOT in public HTML.**

| Data Type | Sanitization Rule | Example |
|-----------|-------------------|---------|
| Proof of concept | Last 6 chars only; prefix with `REDACTED_` | `REDACTED_...a1b2c3` |
| Exploit payloads | Replace with technique description | "SQLi via boolean-based blind in `id` parameter" |
| Credential values | Last 6 chars only | `user:REDACTED_...pass123` |
| Specific version exploits | CVE ID + affected version range only | "CVE-2023-1234 affects Gitea < 1.20.0" |
| Internal tool output snippets | Summarize; don't include raw | "Nmap found 3 open ports: 22, 80, 8080" |

### LEVEL 2: PUBLIC (pt-report HTML on Tailnet)
**Safe for sharing with stakeholders.**

| Data Type | Rule | Example |
|-----------|------|---------|
| Executive summary | No technical payload details | "Web application exposed default credentials" |
| Findings table | Service, port, severity, CWE, remediation | "Gitea 1.19 on 8080 — High — CWE-798 — Change defaults" |
| Timeline | Sanitized command descriptions | "Nmap service scan on target" not full command |
| Methodology | Tools & phases only | "Recon → Enumeration → Exploitation → Reporting" |
| Limitations | Scope & technical gaps | "SSRF to metadata not tested per scope" |

## Automated Redaction Pipeline

### Sedna Promotion Saga (Automatic)
1. **Input:** Closed verified engagement journal
2. **Process:**
   - Scan `events.jsonl` for `tool_call_settled` with raw outputs
   - Scan `evidence/` blobs for sensitive patterns
   - Apply regex redactors for flags, tokens, hashes, IPs
   - Generate sanitized `case_study.json` + Markdown summary
3. **Output:** Canonical `SemanticKnowledgeBundle` + case study in `semantic_bundles/`

### pt-report Sync (Automatic via `sync-engagement-report.py`)
1. **Input:** Sedna journal event envelopes
2. **Process:**
   - The sync helper never reads event payload fields.
   - Validate only the envelope `event_id` as a UUID.
   - For `decision_recorded` and `observation_extracted`, publish only a fixed label and
     the private event UUID; ignore every other event type.
3. **Output:** UUID-only pointers in rolling report JSON + HTML. Any descriptive content
   requires a separate, explicit sanitization and publication workflow.

### Manual Redaction (Operator)
For any evidence not captured by automation:
```bash
# View raw evidence (private)
cat ~/.hermes/knowledge/sedna/engagements/<uuid>/evidence/tool_output_123.txt

# Create a sanitized version with an independently reviewed redaction tool.
redact-evidence evidence.txt > evidence-sanitized.txt

# Add to pt-report
./pt-report.py add-evidence --engagement htb-target \
  --type file --caption "Sanitized nmap output" \
  --file evidence-sanitized.txt
```

## Regex Patterns for Automated Redaction

```python
REDACTION_PATTERNS = [
    # Flags
    (r'HTB\{[^}]+\}', 'REDACTED_FLAG'),
    (r'root\{[^}]+\}', 'REDACTED_FLAG'),
    (r'user\{[^}]+\}', 'REDACTED_FLAG'),
    (r'flag\{[^}]+\}', 'REDACTED_FLAG'),

    # API Keys / Tokens
    (r'(?i)(api[_-]?key|token|secret|password)[\s:=]+[\w\-\.]{20,}', r'\1=REDACTED'),
    (r'Bearer\s+[\w\-\.]{20,}', 'Bearer REDACTED'),
    (r'sk-[\w]{32,}', 'sk-REDACTED'),  # OpenAI
    (r'gh[pousr]_[A-Za-z0-9]{36,}', 'gh*_REDACTED'),  # GitHub
    (r'glpat-[A-Za-z0-9\-]{20,}', 'glpat-REDACTED'),  # GitLab

    # Cloud
    (r'AKIA[0-9A-Z]{16}', 'AKIAREDACTED'),  # AWS Access Key
    (r'(?i)aws[_-]?secret[\s:=]+[A-Za-z0-9/+=]{40}', 'aws_secret=REDACTED'),

    # Hashes
    (r'\b[a-fA-F0-9]{32}\b', 'REDACTED_MD5'),  # MD5
    (r'\b[a-fA-F0-9]{40}\b', 'REDACTED_SHA1'),  # SHA1
    (r'\b[a-fA-F0-9]{64}\b', 'REDACTED_SHA256'),  # SHA256
    (r'\$[0-9]\$[^\$]+\$[^\$]+\$', 'REDACTED_BCRYPT'),  # bcrypt

    # Private IPs
    (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '10.x.x.x'),
    (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', '192.168.x.x'),
    (r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b', '172.16-31.x.x'),

    # File paths
    (r'/home/[^/\s]+/\.ssh/[^\s]+', '<host-path>'),
    (r'/root/\.ssh/[^\s]+', '<host-path>'),
    (r'/etc/(shadow|passwd|sudoers)', '/etc/<sensitive>'),
]
```

## Verification Checklist

### Before Closing Engagement
- [ ] No raw flags in `events.jsonl` or `evidence/`
- [ ] No API tokens in any tool outputs
- [ ] Private IPs redacted in evidence blobs
- [ ] Host paths redacted

### Before Promoting Case Study
- [ ] `sedna_manage_engagement action=inspect` shows sanitized output
- [ ] Promoted `SemanticKnowledgeBundle` contains no LEVEL 0 data
- [ ] Case study Markdown readable without sensitive info

### Before Publishing pt-report HTML
- [ ] HTML has no raw flags, tokens, hashes
- [ ] Findings table uses sanitized descriptions only
- [ ] Timeline entries don't leak internal hostnames/IPs
- [ ] Tailnet URL verified accessible

## Exception Handling

| Scenario | Action |
|----------|--------|
| Operator needs raw evidence for legal/forensic | Export from private `evidence/` blobs directly — never through pt-report |
| Debugging requires full tool output | Use Sedna journal directly (`events.jsonl` + evidence blobs) |
| Third-party requires full technical details | Provide sanitized case study + separate encrypted evidence package |
| Accidental leak in promoted bundle | `sedna_manage_engagement action=reject` to revoke, then re-promote after fix |

## Tooling Integration

The `sync-engagement-report.py` script exports only fixed labels and validated event UUIDs; it does not inspect or redact event payloads. Custom evidence publication must use a separate, independently reviewed redaction workflow before calling `pt-report.py`.
