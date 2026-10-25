# Contributing

## Branch names

Use short, purpose-based names. Prefer:

| Prefix | Use for |
|--------|---------|
| `feat/` | new feature |
| `fix/` | bug fix |
| `docs/` | docs only |
| `chore/` | tooling, deps, cleanup |
| `refactor/` | reshape without behavior change |

Examples:

- `feat/recon-agent`
- `fix/cors-false-positive`
- `docs/update-prd`
- `chore/add-gitignore`

Do not use personal names, tickets only, or vague names like `update` / `temp` / `wip`.

## Commits

- One clear change per commit
- Subject line: short, imperative, under ~50 chars
- Examples: `add recon agent`, `fix cors check timeout`, `update prd stack notes`
- No tool, product, or automation branding in messages
- No co-author or generated-by footers

## Merge flow

1. Branch from `main`
2. Push the branch and open a PR when the change is ready
3. Merge into `main` when review is done (squash or merge commit — keep history readable)
4. Delete the branch after merge

Keep `main` deployable. Long-lived feature branches should be rebased or merged from `main` often.

## What not to commit

- Secrets, `.env`, API keys, tokens
- Scan reports for third-party targets
- Large binaries or local experiment dumps
