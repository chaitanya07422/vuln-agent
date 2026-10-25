# Implementation Plan — Highly Adaptable Vuln Agent

Goal: ship so that **adding or removing a feature = drop in / delete a module + register it**, not rewriting the core.

Aligned with: `vuln-agent-PRD.md`, `scan-architecture-last-2-days.md`  
Stack: FastAPI · workers on **OCI** · **MongoDB** · Redis · OCI Object Storage · Claude / Gemini / OpenAI  

---

## 1. Design principle

```
CORE (stable)          PLUGINS (change often)
─────────────          ─────────────────────
Lead runner            agents/*.py
Tool bus               playbooks/*.yaml
LLM provider iface     reporters/*.py
Mongo repos            guards/*.py (optional)
Scan job state         tech fingerprints
```

**Rule:** Core never imports a concrete agent by name.  
It only loads whatever is listed in a **registry** (config or entry points).

---

## 2. Repo layout (plugin-friendly)

```
vuln-agent/
├── pyproject.toml
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── README.md
│
├── config/
│   ├── default.yaml          # enabled_agents, rps, timeouts, llm roles
│   ├── staging.yaml
│   └── prod.yaml
│
├── playbooks/                # DATA only — add tech without code
│   ├── wordpress.yaml
│   ├── nestjs.yaml
│   ├── spa_upload.yaml
│   └── _template.yaml
│
├── src/vuln_agent/
│   ├── main.py               # FastAPI app factory
│   ├── settings.py           # pydantic-settings from env + yaml
│   │
│   ├── core/                 # DO NOT put product features here
│   │   ├── registry.py       # AgentRegistry, ToolRegistry, ReporterRegistry
│   │   ├── lead.py           # orchestrate: recon → fan-out → report
│   │   ├── context.py        # ScanContext (url, scope, fingerprint, emit)
│   │   ├── finding.py        # Finding model
│   │   ├── events.py         # audit event helpers
│   │   └── errors.py
│   │
│   ├── tools/                # shared capabilities
│   │   ├── base.py           # Tool protocol
│   │   ├── http.py
│   │   ├── dns.py
│   │   ├── ports.py
│   │   └── html_extract.py
│   │
│   ├── llm/                  # swappable providers
│   │   ├── base.py
│   │   ├── claude.py
│   │   ├── openai.py
│   │   ├── gemini.py
│   │   └── router.py         # LEAD→claude, ADAPT→gemini, …
│   │
│   ├── agents/               # ONE FILE / PACKAGE PER FEATURE
│   │   ├── base.py           # Agent protocol + BaseAgent
│   │   ├── recon.py
│   │   ├── users.py
│   │   ├── auth.py
│   │   ├── leaks.py
│   │   ├── cors_api.py
│   │   ├── upload.py
│   │   ├── uat_app.py
│   │   ├── ports_mail.py
│   │   ├── adapt.py
│   │   └── reporter.py
│   │
│   ├── playbook_loader.py    # load yaml by tech tags
│   ├── fingerprint.py        # map headers/html → tags
│   │
│   ├── db/                   # Mongo only
│   │   ├── client.py
│   │   ├── scans.py
│   │   ├── findings.py
│   │   └── audit.py
│   │
│   ├── storage/              # OCI Object Storage
│   │   └── oci_reports.py
│   │
│   ├── api/
│   │   ├── routes_scans.py
│   │   └── deps.py
│   │
│   └── worker/
│       └── job_scan.py       # ARQ task: run Lead
│
├── tests/
│   ├── agents/
│   ├── playbooks/
│   └── e2e/
│
└── web/                      # Next.js paste-URL UI
    └── ...
```

---

## 3. Core contracts (make features swappable)

### 3.1 Agent interface

```python
# agents/base.py
class Agent(Protocol):
    name: str
    # when to run: always | tags: ["wordpress"] | after: ["recon"]
    requires_tags: list[str]   # empty = always (after recon)
    skip_if_tags: list[str]    # e.g. upload skips if no "upload_signal"

    async def run(self, ctx: ScanContext) -> None:
        ...
```

**Add feature:** new file `agents/foo.py` + one line in `config/default.yaml`  
**Remove feature:** remove from `enabled_agents` (or delete file)

### 3.2 Tool interface

```python
class Tool(Protocol):
    name: str
    async def __call__(self, **kwargs) -> dict: ...
```

Agents only call `ctx.tools.http_request(...)` — never raw httpx in every agent (optional escape hatch for Adapt).

### 3.3 Finding

```python
class Finding(BaseModel):
    agent: str
    severity: Literal["critical","high","medium","low","info"]
    title: str
    evidence_url: str | None
    evidence_snippet: str | None
    fix: str | None
    tags: list[str] = []
```

`ctx.emit(Finding(...))` → Mongo + in-memory list for Reporter.

### 3.4 ScanContext

```python
@dataclass
class ScanContext:
    scan_id: str
    url: str
    scope: Scope
    fingerprint: dict          # filled by Recon
    tools: ToolBus
    llm: LLMRouter
    emit: Callable[[Finding], Awaitable[None]]
    audit: Callable[..., Awaitable[None]]
    playbooks: PlaybookStore
```

---

## 4. Registry — how add/remove stays easy

### `config/default.yaml`

```yaml
enabled_agents:
  - recon
  - users
  - auth
  - leaks
  - cors_api
  - upload
  - uat_app
  - ports_mail
  - adapt
  - reporter

# disable without deleting code:
# enabled_agents: [recon, leaks, ports_mail, reporter]

llm:
  lead: claude
  adapt: gemini-flash
  reporter: claude
  fallback: openai

limits:
  max_rps: 5
  max_adapt_paths: 8
  scan_timeout_sec: 480
```

### Registration (auto-discover)

```python
# core/registry.py
AGENT_ENTRYPOINTS = {
  "recon": "vuln_agent.agents.recon:ReconAgent",
  "users": "vuln_agent.agents.users:UsersAgent",
  # ...
}

def load_agents(enabled: list[str]) -> list[Agent]:
    return [import_string(AGENT_ENTRYPOINTS[n])() for n in enabled if n in AGENT_ENTRYPOINTS]
```

**Add:** implement class + add key to `AGENT_ENTRYPOINTS` + enable in yaml.  
**Remove:** drop from `enabled_agents` (code can stay for later).

---

## 5. Playbooks — change checks without redeploying agents

### `playbooks/wordpress.yaml`

```yaml
tech_tags: [wordpress]
users:
  - method: GET
    path: /wp-json/wp/v2/users?per_page=100
    finding_if_status: [200]
    severity: high
    title: "Public WordPress user enumeration"
auth:
  - method: POST
    path: /xmlrpc.php
    body: "<?xml ... system.listMethods ...>"
    finding_if_body_contains: ["wp.getUsersBlogs", "system.multicall"]
    severity: high
leaks:
  - path: /readme.html
  - path: /wp-config.php
  - path: /.env
```

Agents (`users`, `auth`, `leaks`) do:

```python
steps = ctx.playbooks.for_tech(ctx.fingerprint["tags"]).get(self.name)
for step in steps:
    resp = await ctx.tools.http_request(...)
    if match(step, resp):
        await ctx.emit(...)
```

**New CMS support:** add `playbooks/drupal.yaml` + fingerprint rule — often **zero agent code**.  
**Remove checks:** delete YAML steps.

---

## 6. Lead flow (stable)

```
1. Validate URL + attestation
2. Create scan doc in Mongo (status=running)
3. Run agents where requires_tags ⊆ fingerprint OR requires_tags empty
   - Always run: recon first (sync barrier)
   - Then asyncio.gather(all matching agents except reporter)
   - Adapt runs if fingerprint.unknown or config.force_adapt
   - Reporter last
4. Upload report.md to OCI Object Storage
5. status=done
```

Lead does not hardcode “run auth then users” — **registry + tags** decide.

---

## 7. Fingerprint → tags (extensible)

```python
# fingerprint.py
RULES = [
  (lambda h, html: "wp-json" in html or "WordPress" in html, "wordpress"),
  (lambda h, html: "X-Powered-By" in h and "Express" in h["X-Powered-By"], "express"),
  (lambda h, html: "/_next/" in html, "nextjs"),
  ...
]
```

**Add tech:** one rule + one playbook file.  
Unknown → tag `unknown` → Adapt agent.

---

## 8. LLM layer (swap models without touching agents)

```python
# llm/router.py
class LLMRouter:
    async def complete(self, role: Literal["lead","adapt","reporter"], prompt, tools=None):
        provider = self.mapping[role]  # from config
        try:
            return await provider.complete(...)
        except Exception:
            return await self.fallback.complete(...)
```

Agents call `ctx.llm.complete("adapt", ...)` — never `import anthropic` inside `adapt.py`.

**Change Claude → Gemini for reports:** one yaml line.

---

## 9. Phased implementation (build order)

### Phase 0 — Skeleton (2–3 days)
- [ ] Repo + Docker Compose (api, worker, mongo, redis)  
- [ ] Settings + Mongo client + OCI Object Storage stub (local filesystem fallback)  
- [ ] `ToolBus` + `http_request`  
- [ ] `Agent` protocol + `Registry` + empty Lead  
- [ ] FastAPI `POST /v1/scans` enqueue ARQ job  

**Exit:** paste URL → job completes with empty report.

### Phase 1 — Deterministic agents (1 week)
- [ ] Recon (headers + html tags + dig + ports)  
- [ ] Leaks + Ports_mail from playbook/generic paths  
- [ ] Users + Auth for wordpress.yaml only  
- [ ] CORS one Origin probe  
- [ ] Reporter → markdown template → save to Mongo + file  

**Exit:** DocTutorials-like WP site produces real findings **without LLM**.

### Phase 2 — Config toggles (2 days)
- [ ] `enabled_agents` works end-to-end  
- [ ] Demo: disable `auth` → no xmlrpc findings  
- [ ] Demo: add `playbooks/nestjs.yaml` + tag → new findings  

**Exit:** prove add/remove via config/yaml only.

### Phase 3 — LLM Adapt + Reporter prose (1 week)
- [ ] LLM router (Claude lead/reporter, Gemini adapt)  
- [ ] Adapt agent ≤8 paths  
- [ ] Reporter uses LLM to polish brief (findings still from tools)  

**Exit:** unknown stack still returns useful leak/API hits.

### Phase 4 — Remaining packs (1 week)
- [ ] Upload gate, UAT/APP  
- [ ] Fingerprint rules library expanded  
- [ ] Audit log UI / JSON download  

### Phase 5 — OCI production (3–5 days)
- [ ] Deploy Compose or dual VMs on OCI  
- [ ] Mongo data on block volume  
- [ ] Reports to OCI Object Storage  
- [ ] Secrets in OCI Vault  
- [ ] LB + HTTPS  

### Phase 6 — Next.js UI (parallel OK)
- [ ] Paste URL + attest checkbox  
- [ ] Poll scan status  
- [ ] Show/download report  

---

## 10. How to add a feature (cookbook)

### Example: add “GraphQL introspection” check

1. Create `playbooks/graphql.yaml` paths `POST /graphql` introspection query.  
2. Add fingerprint rule for GraphQL indicators.  
3. Either map to existing `cors_api` / `leaks` agent **or** new `agents/graphql.py` (copy BaseAgent).  
4. Register in `AGENT_ENTRYPOINTS` + `enabled_agents`.  
5. Add unit test with mocked httpx.  

No changes to Lead, Mongo schema, or LLM router.

### Example: remove Upload feature

```yaml
enabled_agents:
  # - upload   # commented out
```

Redeploy/restart worker. Done.

### Example: switch Reporter to Gemini

```yaml
llm:
  reporter: gemini-flash
```

---

## 11. Testing strategy (keeps refactors safe)

| Test | Purpose |
|---|---|
| Agent unit + respx/httpx mock | Feature works alone |
| Playbook snapshot tests | YAML steps still valid |
| Registry test | enabled list loads |
| Lead integration | recon barrier + parallel gather |
| Contract test | Finding schema frozen |

CI must pass before playbook merges.

---

## 12. Do / Don’t (adaptability)

| Do | Don’t |
|---|---|
| Put paths in YAML playbooks | Hardcode `/wp-json/...` inside Lead |
| One agent = one folder/file | God-class `scanner.py` |
| Config flag to disable | Delete core to disable a check |
| Tool bus for HTTP | Each agent opens raw sockets differently |
| LLM behind router | `import anthropic` in 10 files |
| Feature flag in Mongo per tenant (later) | Fork repo per customer |

---

## 13. MVP milestone checklist

- [ ] Registry loads agents from yaml  
- [ ] Disable agent via config verified  
- [ ] New playbook file picked up without code change (same agent)  
- [ ] Mongo stores scans/findings  
- [ ] Report in OCI Object Storage (or local stub)  
- [ ] URL-only API + worker on OCI VM  

---

## 14. Suggested first PR sequence

1. `chore: repo skeleton + docker mongo redis`  
2. `feat: core registry + ScanContext + http tool`  
3. `feat: recon + leaks agents + generic playbook`  
4. `feat: wordpress playbook + users/auth`  
5. `feat: reporter markdown`  
6. `feat: enable/disable via config`  
7. `feat: llm router + adapt`  
8. `feat: oci object storage + deploy compose on oracle`  
9. `feat: next.js paste UI`  

---

*Implementation plan for an adaptable, plugin-style vuln scanner on OCI + MongoDB.*
