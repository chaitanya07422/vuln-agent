# Architecture: Website Vuln Scan (URL-only, one-shot probes)

Product shape derived from how we scanned NetOpsys / DocTutorials / Steps AI — **simplified**:

- User pastes **only a website URL** (nothing else).
- **No** long-running attacks / password sprays / Oracle workers.
- Each check = **one (or few) calls**: if it’s open → finding; then next check.

---

## 1. Big picture (product)

```
┌─────────────────────────────────────┐
│  USER                                │
│  paste: https://example.com          │
│  (only the URL — nothing more)       │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│  LEAD AGENT                          │
│  - normalize URL                     │
│  - spawn specialist agents parallel  │
│  - merge findings → report           │
└──────────────────┬──────────────────┘
                   │
     ┌─────────────┼─────────────┐
     ▼             ▼             ▼
  Recon         Auth/Users    Leaks/Upload…
  (1–2 curls)   (1 call each) (1 call each)
                   │
                   ▼
            Markdown / UI report
```

**Rule:** detect exposure, don’t exploit in a loop.  
`xmlrpc open?` → one listMethods (+ optional 1 fail) → finding.  
`/.env` → one GET → 200/403/404 → finding.  
**No** 10k password spray layer.

---

## 2. Layers (same order every target)

### Layer 0 — Input & rules
- **Input = URL only** (e.g. `https://www.doctutorials.com`)
- Derive host/scope from that URL (www + apex + same-site APIs if linked)
- No DoS; **one-shot probes** (no password dictionaries, no Oracle sprays)
- If 429 → record “rate limit present” and skip further auth fails

### Layer 1 — Recon (every site)
Parallel batch (few curls):

| Check | One call |
|---|---|
| Home + headers | `GET /` or `HEAD /` |
| HTML clues | parse for `wp-json`, `/api/`, uat/staging links |
| DNS / mail | `dig` A/MX/TXT/DMARC |
| Ports | connect once per port (80/443 + short list) |

**Output:** fingerprint → which specialist agents to spawn.

### Layer 2 — Fingerprint → parallel agents

| Fingerprint | Agents (each decides its own 1-call checks) |
|---|---|
| WordPress | Users · XML-RPC open? · Leaks · CORS · UAT links · OTP routes listed |
| SPA + `/api/` | Public APIs · Upload endpoint auth gate · Admin login exists? |
| API + Swagger | `/docs`/`docs-json` open? · sample auth route response shape |
| Always | Ports · Leaks · DNS/email |

### Layer 3 — Specialist loop (open? → finding → next)
**Not** attack loops. Pattern:

```
Users:    GET /wp-json/wp/v2/users          → 200 + slugs? → HIGH enum
Auth:     POST xmlrpc system.listMethods   → multicall? → HIGH
          (+ optional ONE bad login)       → 429? → note lockout OK
Leaks:    GET /.env .git readme swagger    → each path once
Upload:   POST request-url unauth          → 401 vs 200 → finding
API:      GET /docs-json                   → open? → CRITICAL map
CORS:     GET + Origin: evil.example       → reflect? → HIGH
UAT:      GET linked uat URL               → 200? → HIGH
```

If open → emit finding → agent `mark_done`.  
**No Layer-4 long-running attack workers.**

### Layer 4 — Report (end)
Lead merges findings → company-style markdown (severity, URL, fix, retest).

---

## 3. “Agents” as they existed in practice

Not separate processes — **roles** the lead switched between (often in one message with parallel tools):

```
┌──────────────────┐
│ USER             │  paste URL only
└────────┬─────────┘
         ▼
┌──────────────────┐
│ LEAD             │  spawn packs from fingerprint
└────────┬─────────┘
         │
         ├─► RECON        headers, HTML, dig, ports  → fingerprint + tech tags
         ├─► USERS        one GET users API          (adapts path to tech)
         ├─► AUTH         login/xmlrpc/oauth open?   (adapts to tech)
         ├─► LEAKS        .env .git readme swagger   (+ tech-specific paths)
         ├─► CORS/API     Origin reflect; /api|/docs (from discovered routes)
         ├─► UPLOAD       unauth presign/upload gate (if upload tech seen)
         ├─► UAT/APP      linked staging/uat once
         ├─► PORTS/MAIL   port open? SMTP banner once
         ├─► ADAPT        new tech detected → load/extend playbook
         └─► REPORTER     merge → brief
```

**Independence:** packs run in parallel; each stops after its one-shot checks.

### Auto-adapt when the site uses new technology

Core packs stay the same; **what they call** updates from Recon fingerprint.

```
RECON finds signals
        │
        ├─ known tech?  → enable matching playbook modules
        │                 WP → /wp-json/wp/v2/users, xmlrpc.php
        │                 Next/Vercel → /_next/, /.env, preview URLs
        │                 Django → /admin/, /static/, DEBUG paths
        │                 Laravel → /telescope, /.env, /horizon
        │                 Nest/Express → /docs, /docs-json, /api
        │                 Shopify → /.well-known, storefront APIs
        │
        └─ unknown tech? → ADAPT agent
                           1) read headers/scripts/generator/CDN
                           2) propose 3–8 one-shot paths (LLM + path DB)
                           3) Lead approves only in-scope GETs
                           4) hits that return interesting 200 → new finding
                           5) optionally save module for next scan
```

| Recon signal (examples) | Agents that wake / change probes |
|---|---|
| `WordPress` / `wp-json` | USERS→`/wp/v2/users`, AUTH→`xmlrpc.php` |
| `X-Powered-By: Express` / Nest | CORS/API→`/docs-json`, `/api/*` from HTML |
| `x-amz-request-id` / S3 | LEAKS→bucket list URLs if linked |
| `Shopify` / `cdn.shopify` | ADAPT→Shopify leak/auth paths |
| New JS framework CDN, odd `/_v1/` | ADAPT→discover routes from JS once, then one GET each |
| Upload strings (`presign`, `request-url`) | UPLOAD agent enabled |
| No upload signals | UPLOAD agent skipped |

**Rule:** adapt = **new one-shot checks**, never new attack loops. Playbooks can grow over time from successful ADAPT discoveries.

---

## 4. Tool channels (the real runtime)

```
LEAD
 ├─ http_request (curl/python) — main probe tool
 ├─ dns_lookup / port_scan — one shot per record/port
 ├─ html_extract — find UAT/api links from homepage
 └─ write_report — final markdown
```

### Typical run (URL only)

```
User pastes: https://www.doctutorials.com

LEAD:
  1) Recon GET / + dig + ports          (parallel)
  2) Fingerprint = wordpress
  3) Parallel specialists (one call each):
       Users GET /wp-json/wp/v2/users
       Auth  POST xmlrpc listMethods
       Leaks GET /.env .git readme
       CORS  GET + Origin evil
       UAT   GET linked uat URL
  4) Reporter → brief.md
```

No chat commands beyond the URL. No long spray jobs.

---

## 5. Example: URL in → findings out

**Input:** `https://www.doctutorials.com`

| Agent | One call | If open… |
|---|---|---|
| Users | `GET .../wp/v2/users` | HIGH user enum (+ list) |
| Auth | `POST xmlrpc listMethods` | HIGH xmlrpc (multicall/login) |
| Leaks | `GET /.env` | CRITICAL if 200 body secrets |
| CORS | `Origin: https://evil.example` | HIGH if ACAO reflects |
| UAT | `GET` link from HTML | HIGH if public login |
| Ports | connect 443/80/… | info/medium if unexpected open |

**Output:** brief with severities + links + fixes.

---

## 6. Decision rules (product)

| Signal | Decision |
|---|---|
| User pasted URL only | Scope = that host (+ same-site links found in HTML) |
| Known fingerprint (WP/SPA/API) | Spawn matching modules for USERS/AUTH/LEAKS/… |
| Unknown stack / new CDN / new paths in JS | Spawn **ADAPT** → propose one-shot GETs → emit findings |
| Path returns 200 with secrets/swagger/users | Emit finding; do not attack further |
| Auth endpoint returns 429 on 1 fail | Note “lockout OK”; stop auth fails |
| No upload/presign signals in HTML/JS | Skip UPLOAD agent |
| Upload unauth 401 | Note “upload gated” |
| Unexpected port open (e.g. 3306) | Finding; don’t brute |
| ADAPT finds stable pattern twice | Save as named module for future scans |

---

## 7. Data flow (evidence → report)

```
Raw tool output
    → Lead interprets (severity, title, URL, fix)
    → Accumulate in chat + optional /tmp JS dumps
    → Reporter writes CreditSea/*.md
    → You share brief with company
```

State = in-memory findings for the job + final report file.  
No Oracle / no spray progress store.

---

## 8. Chat / UI contract

```
User:  https://www.doctutorials.com
App:   [scanning…]
App:   ## Report
       Critical/High/Medium + links + fixes
```

Nothing else required (no “crack”, no wordlists, no SSH).

---

## 9. One diagram

```
         paste URL only
               │
               ▼
        ┌─────────────┐
        │ LEAD AGENT  │
        └──────┬──────┘
               │
     recon fingerprint
               │
     ┌─────────┼─────────┐
     ▼         ▼         ▼
  Auth      Leaks     Ports …   ← each: ONE call → open? → finding
     └─────────┴─────────┘
               │
               ▼
          REPORT (.md)
```

**Historical note:** long Oracle password sprays were used in chat experiments; **they are out of scope for this product architecture.**
