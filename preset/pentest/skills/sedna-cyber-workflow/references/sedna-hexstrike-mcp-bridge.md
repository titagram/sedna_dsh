# Sedna ↔ HexStrike MCP Bridge

This document maps Sedna's strategic planning output to HexStrike MCP tool calls, ensuring clean separation between strategic intent (Sedna) and tactical execution (HexStrike).

## Mapping Principles

1. **Sedna plans, HexStrike executes** — Sedna never runs raw exploit payloads; it produces structured proposals with rationale.
2. **HexStrike optimizes parameters** — Use `/api/intelligence/optimize-parameters` before scanning.
3. **Sedna hooks capture everything** — Observer hooks intercept tool calls for audit trail.
4. **Results flow back** — Scan outputs feed Sedna journal AND pt-report in parallel.

## Planning Proposal → MCP Tool Mapping

| Sedna Proposal Type | HexStrike MCP Tool | Parameters Source |
|---------------------|-------------------|-------------------|
| Network reconnaissance | `mcp_hexstrike_nmap` | `optimize-parameters` + proposal specifics |
| Service enumeration | `mcp_hexstrike_nmap` / `mcp_hexstrike_httpx` | Service hints from retrieval |
| Web content discovery | `mcp_hexstrike_ffuf` / `mcp_hexstrike_feroxbuster` | Wordlist from case steps |
| Vulnerability scanning | `mcp_hexstrike_nuclei` | Template selection from references |
| Subdomain enumeration | `mcp_hexstrike_subfinder` / `mcp_hexstrike_amass` | Domain from target |
| DNS reconnaissance | `mcp_hexstrike_dnsenum` / `mcp_hexstrike_fierce` | Target domain |
| Technology fingerprinting | `mcp_hexstrike_wafw00f` / `mcp_hexstrike_whatweb` | HTTP service detected |
| Credential testing | `mcp_hexstrike_hydra` / `mcp_hexstrike_netexec` | Only with explicit auth proof |
| Exploit generation | `mcp_hexstrike_generate_exploit_from_cve` | CVE from references/guidance |
| Payload generation | `mcp_hexstrike_generate_payload` / `mcp_hexstrike_msfvenom_generate` | Only for authorized proof-of-concept |

## Workflow: From Sedna Guidance to HexStrike Execution

### 1. Retrieve Strategic Guidance
```json
{
  "tool": "sedna_retrieve_knowledge",
  "arguments": {
    "target": "10.10.11.234",
    "authorization": {"state": "authorized", "exact_targets": ["10.10.11.234"]},
    "observed_services": ["http-8080"],
    "query_terms": ["gitea", "authentication bypass", "default credentials"]
  }
}
```

### 2. Extract Actionable Recommendations
From `decision_guidance` lane, identify:
- Recommended next action (e.g., "Test Gitea 1.19 default credentials")
- Associated case steps with transfer conditions
- Negative evidence to avoid

### 3. Optimize Tool Parameters via HexStrike Intelligence
```bash
# Before every scan, get optimized parameters
curl -s -X POST http://127.0.0.1:8888/api/intelligence/optimize-parameters \
  -H 'Content-Type: application/json' \
  -d '{"target":"10.10.11.234","tool":"nmap"}'
```

### 4. Execute via MCP or Container
**MCP (preferred for standard scans):**
```json
mcp_hexstrike_nmap(
  target="10.10.11.234",
  scan_type="-sV -sC",
  ports="8080"
)
```

**Container (for long/specialized scans):**
```bash
docker exec hexstrike-kali nmap -sV -sC -p 8080 10.10.11.234 -oX /tmp/scan.xml
```

### 5. Import Results to Both Systems
**Sedna:** Automatic via observer hooks (pre/post tool call).
**pt-report:** `sync-engagement-report.py` exports fixed-label
`decision_recorded` and `observation_extracted` UUID pointers only. Tool output
requires a separate reviewed manual import; the sync helper never reads payloads.

## Parameter Optimization Cache

Cache `optimize-parameters` responses to avoid repeated API calls for same target+tool:

```bash
# Cache key: target+tool
CACHE_DIR="/tmp/hexstrike-param-cache"
mkdir -p "$CACHE_DIR"
CACHE_FILE="$CACHE_DIR/$(echo -n "10.10.11.234+nmap" | sha256sum | cut -d' ' -f1).json"

if [ ! -f "$CACHE_FILE" ]; then
  curl -s -X POST http://127.0.0.1:8888/api/intelligence/optimize-parameters \
    -H 'Content-Type: application/json' \
    -d '{"target":"10.10.11.234","tool":"nmap"}' > "$CACHE_FILE"
fi
# Use cached params for scan
```

## MCP Tool Response Handling

### Success Path
1. Response parsed by Sedna hooks → private journal observation + evidence blob.
2. `sync-engagement-report.py` exports only fixed-label `decision_recorded` and
   `observation_extracted` UUID pointers; it does not export settled tool calls.
3. Structured scan output (XML/JSON) may be promoted separately through a
   reviewed `pt-report.py import-nmap` or equivalent import.

### Failure / Timeout Path
1. Sedna hooks record failure with exit code / error
2. `sedna_manage_engagement resolve_call` if orphaned
3. Decision guidance updated with "tool failed" context

## Safety Gates

| Gate | Enforced By | Action If Failed |
|------|-------------|------------------|
| Target in authorization scope | Sedna pre-backend validation | `invalid_target` / rejection |
| Destructive payload approved | `approval.py` + operator | Block & require explicit approval |
| VPN route verified | `verify-sedna-env.sh` pre-flight | Abort before scan |
| Container healthy | HexStrike `/health` endpoint | Abort & restart container |

## Special Cases

### Web Application Recon (CDN/WAF)
Follow `webapp-recon-cdn-targets.md` from `hexstrike-kali-htb` skill:
1. DNS recon → subdomain enum → WAF detection → origin discovery → origin scan
2. Sedna retrieval provides analogous CDN bypass cases
3. HexStrike tools: `subfinder`, `wafw00f`, `dnsenum`, `nmap` on origin

### HTB YAML Job Scheduler / AWS-like Endpoints
Follow `htb-http-yaml-job-scheduler.md`, `htb-aws-like-readonly-fingerprint.md`:
1. Map vhosts inside container
2. Preview-only YAML testing first
3. Only escalate to execution with explicit authorization

### LAN Scanning
Use `run-lan-scan.sh` wrapper from `hexstrike-kali-htb`:
```bash
./run-lan-scan.sh --name lan-scan --targets "192.168.1.0/24" --profile quick
```
Sedna hooks capture via `docker exec` interception if run through container.

## Error Handling Reference

| Error Pattern | Likely Cause | Recovery |
|---------------|--------------|----------|
| `mcp_hexstrike_*` not found | MCP not reloaded after config change | `/reload-mcp` or restart Hermes |
| `Operation not permitted` (nmap) | Missing `NET_RAW`/`NET_ADMIN` caps | Add to compose.yaml |
| Empty scan results | All ports filtered / target down | Verify VPN route, try `-Pn -sT` |
| `httpx -l` unsupported | Stripped binary in container | Use `httpx-toolkit` or direct target list |
| Promotion saga stuck | Index failure during verify | `sedna_manage_engagement inspect` → `resume` |

## Quick Reference Card

```bash
# Full cycle for one hypothesis
# 1. Plan
sedna_plan_next max_proposals=3

# 2. Decide (pick proposal UUID)
sedna_record_decision proposal_id="..."

# 3. Optimize
curl -s -X POST http://127.0.0.1:8888/api/intelligence/optimize-parameters \
  -H 'Content-Type: application/json' \
  -d '{"target":"10.10.11.234","tool":"nmap"}'

# 4. Execute
mcp_hexstrike_nmap target="10.10.11.234" scan_type="-sV" ports="8080"

# 5. Sync
./sync-engagement-report.py --engagement-id <uuid> --pt-engagement htb-target \
  --pt-report-script /trusted/path/pt-report.py
```