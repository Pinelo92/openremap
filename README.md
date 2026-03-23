# openremap — monorepo

Private development workspace. Contains two packages:

| Package | Directory | Visibility | Description |
|---|---|---|---|
| `openremap` | [`core/`](core/) | **Public** (auto-mirrored) | ECU engine + CLI |
| `openremap-api` | [`server/`](server/) | **Private** (never published) | FastAPI REST server |

---

## Structure

```
.
├── core/                     ← mirrored to the public GitHub repo on every push to main
│   ├── src/openremap/
│   │   ├── tuning/           engine: identifier, extractor registry, recipe builder, patcher, validators
│   │   └── cli/              typer CLI (openremap identify / cook / validate / patch / scan)
│   ├── tests/                677 tests, all tuning-engine coverage
│   ├── docs/
│   ├── public/               sample binary for tests
│   └── pyproject.toml        deps: typer, rarfile only
│
├── server/                   stays here — never pushed to any public repo
│   ├── src/api/              FastAPI routers, core infra, background tasks
│   ├── main.py
│   ├── .env.example
│   └── pyproject.toml        deps: fastapi, motor, redis, uvicorn + openremap (workspace)
│
├── .github/workflows/
│   └── sync-public.yml       auto-mirrors core/ → public repo on push to main
│
├── pyproject.toml            uv workspace root (no package itself)
└── .python-version
```

---

## Quickstart

```bash
# Install everything (one venv, one lockfile for both packages)
uv sync

# Run the full test suite
uv run pytest

# Start the API server (needs server/.env filled in first)
cp server/.env.example server/.env
uv run uvicorn server.main:app --reload --port 8000

# Use the CLI
uv run openremap identify ecu.bin
```

---

## Working on this project

You work in **this repo only.** You never touch the public repo directly.

```
You edit code here
        │
        ▼
git push origin main
        │
        ▼
GitHub Action runs sync-public.yml
        │
        ▼
core/ is pushed to the public repo automatically
```

- Changes to `core/` trigger the sync action and become public within seconds of merging to `main`.
- Changes to `server/` never leave this repo.
- The action only runs on pushes to `main` — feature branches stay private even if they touch `core/`.

---

## Running tests

```bash
# All 677 tests (from workspace root)
uv run pytest

# Watch mode during development
uv run pytest --tb=short -q

# Specific module
uv run pytest core/tests/tuning/test_patcher.py
```

---

## Adding a new ECU extractor

All extractors live in `core/src/openremap/tuning/manufacturers/`.  
See [`core/CONTRIBUTING.md`](core/CONTRIBUTING.md) for the full guide.

---

## Setting up the public mirror (one-time)

1. Create an empty public GitHub repo (e.g. `your-org/openremap`).
2. In **this** (private) repo → **Settings → Secrets and variables → Actions**:
   - Secret `PUBLIC_REPO_TOKEN` — a PAT with `Contents: Read and write` on the public repo.
   - Variable `PUBLIC_REPO` — `your-org/openremap`.
3. Push anything to `main` that touches `core/`, or trigger the workflow manually.

The public repo will receive the full, real commit history of `core/` — not a squashed copy.

---

## Package dependency

`openremap-api` depends on `openremap`. During development the uv workspace resolves this automatically from `core/` — no manual install needed. The `[tool.uv.sources]` block in `server/pyproject.toml` handles it:

```toml
[tool.uv.sources]
openremap = { workspace = true }
```

When deploying to production, publish `openremap` to PyPI (or a private index) and remove that block.