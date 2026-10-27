# vuln-agent

URL-only multi-agent vulnerability scanner.

Paste a URL → specialist agents run one-shot checks → company-ready markdown brief.

## Features

- Plugin agents via `config/default.yaml` (`enabled_agents`)
- YAML playbooks per tech (`playbooks/*.yaml`)
- Recon, users, auth, leaks, CORS/API, upload, UAT, ports/mail, adapt, reporter
- FastAPI + optional Mongo + docker-compose
- Web UI at `/`

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn vuln_agent.main:app --host 0.0.0.0 --port 8000
```

Open http://127.0.0.1:8000 or:

```bash
curl -s -X POST http://127.0.0.1:8000/v1/scans \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com","attested":true}'
```

## Docker

```bash
docker compose up --build
```

Set `VULN_AGENT_MONGO_URI=mongodb://mongo:27017` (already in compose).

## Add / remove a feature

1. Add agent file under `src/vuln_agent/agents/`
2. Register in `core/registry.py`
3. Enable in `config/default.yaml`
4. Or add checks only: edit `playbooks/<tech>.yaml`

## Tests

```bash
pytest -q
```

## Cursor / MCP (ScanLead CLI)

Use the stdio MCP server so Cursor (or any MCP client) can start scans, poll status, and fetch briefs with a personal API key—no browser login.

1. In the ScanLead web UI → **Settings** (Pro), create an API key (`sl_live_…`). Copy it once.
2. Install this package so `scanlead-mcp` is on your PATH:

```bash
pip install -e .
```

3. Add to `~/.cursor/mcp.json` (or project `.cursor/mcp.json`). Example: [`examples/mcp.json`](./examples/mcp.json).

```json
{
  "mcpServers": {
    "scanlead": {
      "command": "scanlead-mcp",
      "env": {
        "SCANLEAD_API_URL": "https://vulscan.duckdns.org",
        "SCANLEAD_API_KEY": "sl_live_YOUR_KEY"
      }
    }
  }
}
```

Env:
- `SCANLEAD_API_URL` — default `https://vulscan.duckdns.org`
- `SCANLEAD_API_KEY` — required Pro API key from Settings

Tools: `start_scan` (requires `attested: true`), `get_scan`, `list_scans`, `get_brief`, `get_quota`, `retry_scan`.

Scans started via MCP are saved on the key owner’s account. Free: **1 MCP scan** (then blocked) is separate from **5 Free web scans**. Pro: **one shared pool** (`VULN_AGENT_PRO_SCAN_LIMIT`) — web and MCP both increment the same counter. Keys respect freemium reveal rules.

## Docs

- [PRD](./PRD.md)
- [Implementation plan](./docs/implementation-plan.md)
- [Contributing](./CONTRIBUTING.md)
