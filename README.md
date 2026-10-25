# vuln-agent

URL-only multi-agent vulnerability scanner.

- **Stack:** FastAPI (Mongo / OCI later)
- **Scope:** detect and report — no exploit / spray workflows
- **Design:** plugin agents + YAML playbooks so features are easy to add or remove

## Docs

- [PRD](./PRD.md)
- [Implementation plan](./docs/implementation-plan.md)
- [Product plan](./docs/product-plan.md)
- [Scan architecture notes](./docs/scan-architecture.md)
- [Contributing](./CONTRIBUTING.md)

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn vuln_agent.main:app --app-dir src --host 0.0.0.0 --port 8000
```

```bash
curl -s -X POST http://127.0.0.1:8000/v1/scans \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com","attested":true}'
```

Poll `GET /v1/scans/{id}` then download `GET /v1/scans/{id}/report.md`.

## Tests

```bash
pytest -q
```

## Status

Feature slice: **scan API + recon agent** (in-memory store). Next: leaks agent, then Mongo.
