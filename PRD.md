# PRD: URL-Only Multi-Agent Website Vulnerability Scanner

| Field | Value |
|---|---|
| **Product name** | (working) **ScanLead** / Vuln Agent |
| **Version** | PRD v1.0 |
| **Date** | 25 Oct 2026 |
| **Status** | Draft for build |
| **Related docs** | `scan-architecture-last-2-days.md`, `vuln-agent-plan.md` |

---

## 1. Vision

Paste a **website URL only** → parallel specialist agents run **one-shot “is it open?”** checks (auth, leaks, ports, CORS, uploads, UAT, …) → get a **company-ready security brief**.

Behaves like the recent authorized scans of DocTutorials / NetOpsys / Steps AI, but:

- No password sprays / long attack jobs  
- No extra user inputs beyond the URL  
- Adapts probes when new tech is detected  

---

## 2. Problem

Security reviews today need a human expert chaining curl, browser, and reports. Founders and small teams need:

- Fast external misconfiguration discovery  
- Clear Critical/High/Medium write-ups with links and fixes  
- Safe defaults (detect exposure, don’t exploit)

---

## 3. Goals / non-goals

### Goals (v1)
- URL-in → report-out in minutes  
- Multi-agent parallel packs (Recon, Users, Auth, Leaks, CORS/API, Upload, UAT, Ports/Mail, Adapt, Reporter)  
- Tech fingerprint + **adapt** for unknown stacks  
- Markdown (+ HTML) company brief  
- Authorship / scope guard (user attests ownership)  
- Audit log of every HTTP probe  

### Non-goals (v1)
- Password spraying, exploitation, PoC malware hosting  
- Authenticated deep IDOR after user login (optional v2)  
- Full DAST / burp replacement  
- Scanning arbitrary third parties without attestation  
- Mobile app / thick-client binary analysis  

---

## 4. Users & use cases

| Persona | Use |
|---|---|
| Founder / indie hacker | Paste staging/prod URL before launch |
| Small security team | First-pass external checklist + share brief |
| Agency | Run on client-owned URL with written OK |

**Primary flow**
1. User opens app → pastes `https://example.com`  
2. Checks “I own or am authorized to test this site”  
3. Clicks **Scan**  
4. Live status: agents running  
5. Downloads report  

---

## 5. Functional requirements

### 5.1 Input
- Single field: **URL** (http/https)  
- Checkbox: authorization attestation (required)  
- Optional (v1.1): max runtime, include/exclude Adapt  

### 5.2 Agents (must)

| Agent | Behavior |
|---|---|
| Lead | Parse URL, scope, spawn agents, timeouts, merge |
| Recon | Headers, HTML, dig, ports → fingerprint tags |
| Users | One enum-style GET (tech-specific path) |
| Auth | Login/xmlrpc/oauth surface open? ≤1 fail for lockout signal |
| Leaks | One GET per path (`.env`, `.git`, readme, swagger, … + tech paths) |
| CORS/API | Origin reflect; public `/api` or `/docs` if present |
| Upload | Unauth presign/upload gate only |
| UAT/APP | Follow staging/uat links from HTML once |
| Ports/Mail | Connect once per port; SMTP banner once if MX host in scope |
| Adapt | Unknown tech → propose ≤8 one-shot GETs |
| Reporter | Severity brief + retest checklist |

### 5.3 One-shot rule
Each check = limited HTTP/DNS/TCP probes. **No** dictionaries, no multi-minute sprays, no worker queues for cracking.

### 5.4 Output
- Markdown report (download)  
- JSON findings API for integrations  
- Severities: Critical / High / Medium / Low / Info  
- Each finding: title, evidence URL, status code snippet, fix, retest  

### 5.5 Safety
- Host allowlist = URL host + same-site links discovered (configurable)  
- Global RPS cap (default 5)  
- Stop auth fails on 429  
- Block private IP / localhost SSRF in Adapt proposals  
- Full probe audit log  

---

## 6. Non-functional requirements

| Area | Target |
|---|---|
| Latency | Typical site report &lt; 5–8 minutes |
| Concurrency | ≥ 10 scans in parallel (queue) |
| Availability | 99% for API (best-effort beta OK) |
| Retention | Reports 30 days (configurable) |
| Privacy | Don’t store full HTML bodies long-term; truncate evidence |

---

## 7. Tech stack (recommended)

### 7.1 Application

| Layer | Choice | Why |
|---|---|---|
| API / workers | **Python 3.12** + **FastAPI** | Fast to ship agents, httpx, good LLM SDKs |
| Agent orchestration | **LangGraph** (or custom asyncio fan-out) | Parallel specialists + shared state |
| Task queue | **Redis** on OCI + **ARQ** or **Celery** | Scan jobs async |
| DB | **MongoDB** (OCI Compute or **MongoDB Atlas** reachable from OCI) | Users, scans, findings, audit (document model fits findings JSON) |
| Object storage | **OCI Object Storage** | Report files (`.md` / JSON) |
| Frontend | **Next.js 15** (TypeScript) | Simple paste-URL UI |
| Auth (app users) | **Clerk** or custom JWT | Speed |
| Observability | **OpenTelemetry** + **Sentry** | Trace agent tool calls |

### 7.2 Tools runtime
- `httpx` / `curl` subprocess for HTTP  
- `dnspython` for DNS  
- TCP connect for ports  
- Optional later: Playwright (browser agent) in v1.5  

### 7.3 LLM recommendation

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **Claude** (Sonnet 4.x / latest) | Best tool-use + careful security reasoning; strong at report writing | Cost; Anthropic API | **Primary (Lead + Adapt + Reporter)** |
| **OpenAI** (GPT-4.1 / o4-mini) | Ubiquitous; good JSON tools; cheaper mini for Recon routing | Slightly weaker long structured reports | **Secondary / fallback**; use mini for cheap classifiers |
| **Gemini** (2.5 Pro / Flash) | Long context; Flash cheap for mass path scoring | Tool-calling maturity varies by model | **Good for Adapt path proposals + Flash for triage** |

**v1 default stack (LLM):**
- **Lead + Reporter + Adapt:** Claude Sonnet (quality)  
- **Per-agent “what next path?” micro-decisions:** Gemini Flash or GPT-4.1-mini (cost)  
- **Deterministic packs first:** WordPress/Express path lists in code — LLM only when fingerprint = unknown or for report prose  

**Abstraction:** one `LLMProvider` interface (`claude` | `openai` | `gemini`) via env so you can switch without rewrite.

```text
LLM_LEAD=claude
LLM_ADAPT=gemini-flash
LLM_REPORTER=claude
LLM_FALLBACK=openai
```

### 7.4 Playbooks
- YAML/JSON modules per tech: `playbooks/wordpress.yaml`, `nestjs.yaml`, …  
- Adapt can append candidate paths to `playbooks/generated/` after human or auto-approve  

---

## 8. System architecture

```
                    ┌──────────────┐
                    │  Next.js UI  │  (OCI or CDN in front of OCI)
                    └──────┬───────┘
                           │ HTTPS
                    ┌──────▼───────┐
                    │  FastAPI     │  POST /scans { url }
                    │  on OCI      │  GET  /scans/{id}/report
                    └──────┬───────┘
                           │ enqueue
                    ┌──────▼───────┐
                    │ Redis (OCI)  │
                    └──────┬───────┘
                           │
                    ┌──────▼──────────────────┐
                    │ Worker on OCI Compute    │
                    │  Lead → specialists      │
                    │  → Adapt → Reporter      │
                    └──────┬──────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   MongoDB            OCI Object         LLM APIs
   (findings/docs)    Storage (reports)  (Claude/OpenAI/Gemini)
```

---

## 9. Deployment — **Oracle Cloud Infrastructure (OCI)**

All compute, queue, DB access, and file storage run on / from **Oracle Cloud** (reuse free-tier / existing VMs like `oracle-jogi` pattern where useful).

### 9.1 OCI topology (recommended)

| Component | OCI service | Notes |
|---|---|---|
| API + workers | **Compute** (VM.Standard.E* / A1 Flex ARM) or **Container Instances** / **OKE** | Docker: `api` + `worker` |
| Load balancer | **OCI Flexible Load Balancer** + **WAF** optional | TLS terminate |
| Frontend | Next.js on same VM/Nginx **or** Object Storage static + API | Simplest: Nginx serves UI + proxies `/v1` |
| Database | **MongoDB** on OCI Compute (Docker/`mongod`) **or** MongoDB Atlas peered to OCI VCN | Prefer replica set for prod |
| Queue | **Redis** container on same VCN | ARQ/Celery broker |
| Reports / artifacts | **OCI Object Storage** bucket | Private bucket; pre-signed download URLs |
| Secrets | **OCI Vault** | LLM keys, Mongo URI |
| DNS / certs | OCI DNS + Let’s Encrypt or OCI certs | `scan.yourdomain.com` |
| Egress | NAT Gateway | Workers need outbound HTTPS for scans + LLM APIs |

### 9.2 Network sketch

```
Internet
   │
   ▼
OCI Load Balancer :443
   │
   ├─► VM/Container: Next.js + Nginx
   ├─► VM/Container: FastAPI (api)
   ├─► VM/Container: worker (agents)
   │
   └─ private subnet
         ├─ Redis
         ├─ MongoDB
         └─ → OCI Object Storage (service gateway)
```

### 9.3 Why MongoDB (instead of Postgres)

| Need | Mongo fit |
|---|---|
| Findings are nested JSON (evidence, agents, tags) | Natural documents |
| Fingerprint / Adapt playbooks | Flexible schema |
| Per-scan agent status arrays | Easy `$push` / embed |
| Fast MVP | Motor/PyMongo + Pydantic |

**Collections (v1):** `users`, `scans`, `findings`, `audit_events`, `playbooks`

### 9.4 Environments
- `dev` — Docker Compose on laptop (api, worker, mongo, redis)  
- `staging` — single OCI VM, all containers  
- `prod` — separate api/worker VMs or OKE; Mongo replica; Object Storage; Vault  

### 9.5 Docker Compose (local / single OCI VM)

```yaml
services:
  api:
  worker:
  web:          # optional Next build
  mongo:
  redis:
```

Prod: same images on OCI; Mongo data on **block volume**; reports on **Object Storage** (not local disk).

### 9.6 CI/CD
- GitHub Actions → build images → push **OCI Container Registry (OCIR)** → SSH/API deploy to Compute or update Container Instances  
- Playbook/prompt changes require review  

### 9.7 Cost note (Oracle)
- Always Free ARM shapes can host MVP api+worker+mongo+redis on one box  
- Object Storage pay for reports  
- Scale out workers as separate Compute instances behind the queue

---

## 10. API sketch

```http
POST /v1/scans
{ "url": "https://www.doctutorials.com", "attested": true }

→ { "id": "scn_123", "status": "queued" }

GET /v1/scans/scn_123
→ { "status": "running", "agents": ["recon","leaks",...] }

GET /v1/scans/scn_123/report.md
GET /v1/scans/scn_123/findings.json
```

---

## 11. Data model (MongoDB)

**Database:** `vuln_agent`

| Collection | Document shape (minimal) |
|---|---|
| `users` | `_id`, email, createdAt |
| `scans` | `_id`, userId, url, status, fingerprint `{}`, agentsStatus `[]`, createdAt, finishedAt |
| `findings` | `_id`, scanId, agent, severity, title, evidenceUrl, evidenceSnippet, fix, createdAt |
| `audit_events` | `_id`, scanId, tool, requestMeta, statusCode, ts |
| `playbooks` | `_id`, name, techTags `[]`, paths `[]`, updatedAt |

Indexes: `scans.userId`, `scans.status`, `findings.scanId`, `audit_events.scanId`.  
Reports file key in OCI Object Storage: `reports/{scanId}/report.md` (URL stored on `scans`).

---

## 12. Security of the scanner itself

- Workers cannot reach RFC1918 / metadata IPs (block SSRF)  
- Egress allowlist optional for enterprise  
- LLM prompts must not include customer secrets from `.env` bodies in full — redact  
- Attestation logged with IP + timestamp  
- Separate API keys per LLM provider; rotate  

---

## 13. Success metrics

| Metric | v1 target |
|---|---|
| Time to first report | &lt; 8 min p50 |
| False Critical rate | &lt; 20% (manual sample) |
| Crash-free scan completion | &gt; 95% |
| Cost per scan (LLM) | &lt; $0.50 average with hybrid models |

---

## 14. Roadmap

| Phase | Scope |
|---|---|
| **MVP (4 weeks)** | FastAPI + worker on **OCI**; **MongoDB** + Redis; Recon/Leaks/Ports/Users/Auth/CORS + Reporter; Claude lead; Next paste UI; Docker on Compute |
| **v1** | Upload/UAT/Adapt; playbook library; OCI Object Storage reports; OCI Vault secrets; auth |
| **v1.5** | Gemini Flash for Adapt; Playwright optional; PDF export |
| **v2** | Opt-in authenticated scans (cookie paste); OKE scale-out; integrations (Slack) |

---

## 15. Cost sketch (monthly, early)

| Item | Estimate |
|---|---|
| OCI Compute (Always Free / small paid) | $0–30 |
| OCI Object Storage | low (reports) |
| MongoDB on same VM or Atlas free/M0–M10 | $0–30 |
| Redis on VM | $0 (colocated) |
| Claude API | usage-based (biggest variable) |
| Gemini Flash | low (Adapt/triage) |
| OpenAI fallback | low |

Optimize: deterministic playbooks first; LLM for Adapt + report narrative only. Prefer **one OCI VM** for MVP.

---

## 16. LLM decision (summary)

| Role | Model |
|---|---|
| **Lead orchestration + final report** | **Claude Sonnet** |
| **Adapt / unknown tech path ideas** | **Gemini Flash** (cheap) or Claude if quality needed |
| **Fallback if Claude down** | **OpenAI GPT-4.1** |
| **Fingerprint classify only** | Small/cheap model or pure rules |

**Do not** put Gemini/OpenAI/Claude on every single GET — rules + YAML playbooks handle known stacks; LLMs handle routing prose, unknown tech, and the company brief.

---

## 17. Open questions

1. Multi-tenant SaaS vs single-tenant deploy for agencies?  
2. Require DNS TXT ownership proof in v1 or attestation checkbox only?  
3. Brand name / domain for the product?  
4. India hosting preference (data residency)?  

---

## 18. Acceptance criteria (MVP)

- [ ] User pastes URL only → scan starts  
- [ ] Parallel agents run; each probe audited  
- [ ] WordPress demo target produces users/xmlrpc/cors/uat-style findings when present  
- [ ] Unknown stack triggers Adapt ≤8 GETs  
- [ ] Report markdown downloadable  
- [ ] No password spray code paths in repo  
- [ ] Private IP targets rejected  
- [ ] Deployed on **OCI** with data in **MongoDB** and reports in **OCI Object Storage**  

---

*PRD aligned with scan-architecture-last-2-days.md (URL-only, one-shot, adaptive packs).*
