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

## Docs

- [PRD](./PRD.md)
- [Implementation plan](./docs/implementation-plan.md)
- [Contributing](./CONTRIBUTING.md)
