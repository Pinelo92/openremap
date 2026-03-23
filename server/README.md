# openremap-api (private)

FastAPI server that exposes the [openremap](../core/README.md) engine over HTTP.

> **This package is private.** It is not published to PyPI and must not be made public while authentication and hardening are incomplete.

---

## Requirements

- Python 3.14+
- [uv](https://github.com/astral-sh/uv)
- MongoDB instance (local or Atlas)
- Redis instance (local or managed)

---

## Setup

```bash
# From the workspace root (one directory up):
uv sync

# Copy the example env file and fill in your values
cp server/.env.example server/.env
```

Minimum required values in `.env`:

| Variable | Description |
|---|---|
| `MONGO_URL` | MongoDB connection string |
| `REDIS_URL` | Redis connection string |
| `JWT_SECRET_KEY` | Secret for signing tokens (generate with `openssl rand -hex 32`) |

---

## Run

```bash
# From the workspace root:
uv run uvicorn server.main:app --reload --port 8000
```

Swagger UI → `http://localhost:8000/docs`

---

## Architecture

```
server/
├── src/api/
│   ├── core/
│   │   ├── bootstrap.py     — app wiring (middleware, routers, error handlers)
│   │   ├── config.py        — pydantic-settings env config
│   │   ├── lifespan.py      — startup / shutdown hooks
│   │   ├── limiter.py       — slowapi rate-limit config
│   │   ├── logger.py        — async queue-based logging
│   │   ├── mongodb.py       — Motor async client
│   │   ├── redis_client.py  — aioredis client + memory monitor
│   │   └── router_v1.py     — v1 router assembly
│   ├── routers/v1/
│   │   ├── system.py        — /v1/system/status
│   │   └── tuning.py        — /v1/tuning/* (identify, cook, validate, patch)
│   └── bg_tasks/
│       └── redis_monitor.py — background memory-usage alerting
└── main.py                  — FastAPI app entry point
```

The server has **no business logic** of its own. All ECU analysis, patching, and validation is delegated to the `openremap` core package (`openremap.tuning.*`).

---

## Dependency on core

During development the workspace resolves `openremap` from `../core` automatically via the uv workspace. No manual install step is needed.

When deploying to production, either:
- Publish `openremap` to PyPI and pin the version in `server/pyproject.toml`, or
- Use a private package index or a direct Git URL.

---

## TODO before any public exposure

- [ ] Implement JWT authentication middleware
- [ ] Add user/token issuance endpoints
- [ ] Harden MongoDB and Redis connection error handling
- [ ] Integration tests for all API endpoints
- [ ] Audit logs to ensure no VINs or hardware keys are leaked
- [ ] Rate-limit tuning per authenticated user (not just by IP)
- [ ] Add deployment guide (Docker, reverse proxy, TLS)