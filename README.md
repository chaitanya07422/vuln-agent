# vuln-agent

URL-only multi-agent vulnerability scanner.

- **Stack:** FastAPI, workers on OCI, MongoDB, Redis, Claude / Gemini / OpenAI
- **Scope:** detect and report — no exploit / spray workflows
- **Design:** plugin agents + YAML playbooks so features are easy to add or remove

## Docs

- [PRD](./PRD.md)
- [Implementation plan](./docs/implementation-plan.md)
- [Product plan](./docs/product-plan.md)
- [Scan architecture notes](./docs/scan-architecture.md)
- [Contributing](./CONTRIBUTING.md)

## Status

Planning / early scaffold. See `docs/implementation-plan.md` for the build order.
