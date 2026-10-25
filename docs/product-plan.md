# Plan: Multi-Agent Vulnerability Scan (same style as our chats)

Build a scanner that works like a multi-agent assessment: several specialist agents decide **independently**, run tools in **parallel**, then a lead agent merges everything into one report.

---

## 1. Goal

Not one mega-prompt that does everything in order.

**Many agents**, each owning a surface:

| Agent | Owns (one-shot “is it open?”) |
|---|---|
| **Recon** | Home, tech stack, headers, CSP, cookies |
| **Ports / network** | 80/443/22/25/3306… — connect once per port |
| **DNS / email** | SPF, DMARC, MX |
| **Auth** | Login/XML-RPC **exists**? optional **one** fail for lockout signal — **no sprays** |
| **Secrets / leaks** | `/.env`, `.git`, readme, swagger — one GET each |
| **API / Swagger** | `/docs`, `/docs-json`, CORS reflect |
| **Upload / storage** | Unauth presign/upload gate only (open vs 401) |
| **Users / enum** | `/wp-json/wp/v2/users`, check-email once |
| **App surface** | UAT/staging links from HTML — one GET |
| **Cron / workers** | Route listed + auth required? — don’t enqueue jobs |
| **Reporter** | Merges findings → company brief |

**UX:** user pastes **URL only**.

Each agent:

1. Gets target + **tech tags** from Recon.  
2. Runs **one call per check** (paths chosen for that tech); if open → `emit_finding`.  
3. **No** long-running attacks / dictionaries / Oracle workers.  
4. `mark_done` → Lead merges.

### Adaptive modules (new technology)

Recon emits tags like `wordpress`, `next`, `laravel`, `shopify`, `unknown:cloudflare-workers`.

- **Known tag** → load playbook JSON (paths for USERS/AUTH/LEAKS…).  
- **Unknown tag** → **Adapt agent**: read scripts/headers, propose ≤8 in-scope one-shot URLs, run them, keep hits that look like vulns/leaks, optionally persist a new playbook snippet.  
- Core agents (CORS, Ports, Reporter) always run; tech-specific agents only change **which URL** they hit.

---

## 2. Architecture (multi-agent)

```
                    ┌──────────────────────────┐
                    │  Lead / Orchestrator     │
                    │  - scope + auth proof    │
                    │  - start Recon           │
                    │  - spawn specialists     │
                    │  - merge + report        │
                    └────────────┬─────────────┘
                                 │
              fingerprint (WP / SPA / API)
                                 │
        ┌────────────┬───────────┼───────────┬────────────┐
        ▼            ▼           ▼           ▼            ▼
   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐
   │ Ports   │ │ Auth    │ │ Leaks   │ │ Upload  │ │ Users    │ …
   │ agent   │ │ agent   │ │ agent   │ │ agent   │ │ agent    │
   └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬─────┘
        │           │           │           │            │
        └───────────┴─────┬─────┴───────────┴────────────┘
                          ▼
                   Shared tool runtime
                   (http, dns, ports, browser)
                          ▼
                   Finding store (JSON)
                          ▼
                   Reporter agent → .md
```

**Parallel by default** (like we ran DNS + HTML parse + API probes together).  
**Independent decisions:** Auth agent does not wait for Upload agent; each has its own LLM loop + tools.

---

## 3. How one specialist thinks (same as this chat)

Example — **Auth agent** after Recon says “WordPress”:

```
Thought: WP login + xmlrpc often open
Tool: http_request GET /wp-login.php
Obs: 200
Tool: http_request POST /xmlrpc.php listMethods
Obs: multicall, wp.getUsersBlogs present
Tool: http_request POST xmlrpc bad password ×3
Obs: still 200 fault, no 429
Finding: CRITICAL no lockout + HIGH xmlrpc enabled
Done (auth pack)
```

Example — **Leaks agent** (independent):

```
Tool: GET /.env → 403
Tool: GET /.git/HEAD → 404
Tool: GET /readme.html → 200
Tool: GET /wp-config.php → 403
Finding: MEDIUM readme disclosure; env/git not public
Done
```

Example — **Upload agent** (NetOpsys-style, only if fingerprint says SPA+upload):

```
Tool: POST /api/uploads/request-url unauth → 401
Tool: (if session) POST request-url text/html → 200 + objectPath
Tool: GET /objects/uploads/<uuid> unauth → 200 text/html
Finding: CRITICAL public HTML upload
Done
```

---

## 4. Tool calling (shared by all agents)

LLM never opens sockets. Every agent only emits tool calls; one runtime executes them.

### Shared tools

| Tool | Used by |
|---|---|
| `http_request` | almost all |
| `dns_lookup` | DNS/email, Recon |
| `port_scan` | Ports (bounded list) |
| `html_extract` | Recon, App surface |
| `browser_*` | Browser, Upload UI |
| `emit_finding` | every specialist |
| `mark_done` | every specialist |

### Example tool call → curl

**Agent emits:**

```json
{
  "tool": "http_request",
  "args": {
    "method": "GET",
    "url": "https://www.doctutorials.com/wp-json/wp/v2/users?per_page=100"
  }
}
```

**Runtime runs:**

```bash
curl -sS -D /tmp/h.txt -o /tmp/b.txt --max-time 25 \
  -H "User-Agent: VulnAgent/1.0" \
  "https://www.doctutorials.com/wp-json/wp/v2/users?per_page=100"
```

**Returns to that agent only:**

```json
{ "status": 200, "headers": {...}, "body_preview": "[{\"slug\":\"root\"}...]" }
```

---

## 5. Agent catalog (what each independently covers)

### A. Recon agent
- `GET /`, headers (HSTS, CSP, XFO, cookies)
- Generator / WP / Next / nginx
- Extract script URLs, forms, external hosts  
→ writes **fingerprint**: `{stack: "wordpress", hints: ["wp-json","xmlrpc"]}`

### B. Ports / network agent
```bash
# connect-only, no exploit
for p in 22 25 80 110 143 443 465 587 993 995 3306 5432 6379 8080 8443; do
  timeout 2 bash -c "echo >/dev/tcp/$IP/$p" 2>/dev/null && echo open $p
done
```
Also mail host if MX points elsewhere (like `mail.netopsys.in`).

### C. Auth agent
- `/wp-login.php`, `/login`, `/admin/login`, `/api/admin/login`
- XML-RPC auth methods + 3–5 fail probe for lockout
- OTP send endpoints: map only; **do not bomb**
- Decides: “spray allowed?” only if user opted in + cap

### D. Secrets / leak agent
```bash
for p in /.env /.git/HEAD /wp-config.php /wp-config.php.bak \
  /readme.html /license.txt /wp-content/debug.log /phpinfo.php \
  /server-status /actuator /swagger /api/docs /docs /docs-json; do
  curl -sS -o /dev/null -w "$p %{http_code}\n" "https://target$p"
done
```
Follows interesting 200s (swagger dump, openapi paths).

### E. Users / enum agent
- `/wp-json/wp/v2/users`
- `/?author=1`
- `check-email` / `check-phone-exists` style oracles  
Independent of Auth, but Auth may consume its user list later.

### F. API / CORS agent
- OPTIONS/GET with `Origin: https://evil.example`
- Public `/api/*` from HTML/JS map
- Swagger 623-path style harvest if `/docs-json` open

### G. Upload / storage agent
- Find `request-url`, `presign`, `multipart`
- Unauth vs auth
- Dangerous MIME / public object URL
- `resumePath` / href open redirects  
**Never** mass-host phishing pages in prod product mode unless “PoC lab” flag.

### H. App / UAT agent
- Regex HTML/JS for `uat.`, `staging.`, `admin.`, `webileapps`
- Probe those hosts if in scope

### I. Workers / cron agent
- Look for `/screening`, `/cron`, `/jobs/run`, ingest URL APIs
- Check auth gate only; no triggering expensive workers by default

### J. Reporter agent
- Reads all `emit_finding` records
- Dedupes, severities, company brief + retest checklist
- Same tone as `doctutorials-company-security-brief.md`

---

## 6. Orchestrator decisions (lead agent)

```
1. Validate scope + ownership
2. Run Recon agent (blocking)
3. Based on fingerprint, spawn in parallel:
     always: Ports, Leaks, DNS, App/UAT
     if wordpress: Auth, Users, (XML-RPC inside Auth)
     if spa/api: API/CORS, Upload, Workers
     if swagger: API pack deep
4. Wait with timeout (e.g. 15 min) or until all mark_done
5. Run Reporter
6. Return report URL / file
```

Lead does **not** micromanage every curl — specialists decide follow-ups (as in chat).

---

## 7. Finding schema (so agents stay independent but mergeable)

```json
{
  "agent": "auth",
  "id": "AUTH-XMLRPC-LOCKOUT",
  "severity": "critical",
  "title": "No lockout on XML-RPC auth",
  "url": "https://www.doctutorials.com/xmlrpc.php",
  "evidence": "3 failed wp.getUsersBlogs → HTTP 200 faults, no 429",
  "impact": "Online password guessing practical",
  "fix": "Disable xmlrpc; MFA; rate limit"
}
```

---

## 8. Guards (same rules we used)

| Rule | Why |
|---|---|
| Scope allowlist | No random internet scanning |
| Max RPS / max tool calls per agent | No DoS |
| Stop on 429 / lockout text | Like NetOpsys admin / Oracle pause |
| OTP: map only unless explicit flag | No cost abuse |
| Password spray: opt-in + bounded list | No rockyou by default |
| Upload PoC: lab mode only | Don’t leave public HTML on customer prod |

---

## 9. End-to-end user flow

1. User: `https://www.doctutorials.com` + “authorized”.  
2. Lead starts **Recon** → fingerprint `wordpress`.  
3. Parallel: **Ports | Leaks | DNS | Auth | Users | App/UAT | CORS**.  
4. Each agent tool-calls on its own until done.  
5. **Reporter** writes brief (Critical/High/Medium + links).  
6. User downloads report; optional “retest” re-runs same agents.

---

## 10. Build order

| Step | Deliverable |
|---|---|
| 1 | Shared tools: `http_request`, `dns_lookup`, `port_scan`, `emit_finding` |
| 2 | Recon + Leaks + Ports agents (no LLM first = fixed scripts) |
| 3 | Wrap each agent in LLM tool-loop (independent decisions) |
| 4 | Auth + Users + CORS (WordPress pack) |
| 5 | Upload + API/Swagger + Workers |
| 6 | Lead orchestrator (parallel spawn) + Reporter |
| 7 | API/UI + ownership check + audit log |

### Repo sketch

```
vuln-agent/
  src/
    lead.py                 # orchestrator
    agents/
      recon.py
      ports.py
      auth.py
      leaks.py
      users.py
      cors_api.py
      upload.py
      uat_app.py
      workers.py
      reporter.py
    tools/
      http.py
      dns.py
      ports.py
      browser.py
    guard/scope.py
  prompts/
    lead.md
    auth.md
    leaks.md
    ...
  templates/company_brief.md.j2
```

---

## 11. Why this matches “how you did it”

| In chat | In product |
|---|---|
| Parallel shell + browser | Parallel specialist agents |
| “Check users, then xmlrpc, then UAT” | Auth/Users/UAT agents decide next step |
| Separate NetOpsys upload deep-dive | Upload agent only when relevant |
| Stop Oracle sprays on request | Global kill + per-agent stop |
| Final company markdown | Reporter agent |

---

## 12. Next step

Say **“scaffold multi-agent vuln-agent MVP”** and we create:

1. Lead + Recon/Leaks/Ports/Auth agents  
2. Shared `http_request` tool  
3. Parallel run on one URL → merged markdown  

Same behavior as this session, productized.
