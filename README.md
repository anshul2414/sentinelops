# SentinelOps SIEM

A full-stack **Security Information & Event Management** platform — a Splunk/Elastic-style
SIEM with an SPL-like search language, a correlation/detection engine, an AI Security
Analyst, live dashboards, **server-side authentication with RBAC**, and a **Model Context
Protocol (MCP)** server so AI agents can query telemetry and drive investigations.

Green/cream UI inspired by the Starbucks design system.

## Security (hardened)
- **Server-side rendered** login & registration (Jinja2) — not client-side.
- Passwords hashed with **PBKDF2-HMAC-SHA256** (600k iterations, per-user salt, constant-time compare).
- **Signed, httpOnly session cookies** (HMAC-SHA256) with expiry; `Secure` + SameSite in prod.
- **CSRF protection** (double-submit cookie) on all cookie-authenticated state changes.
- **RBAC**: `admin` › `analyst` › `viewer`; mutating endpoints require `analyst`+.
- **Login rate-limiting** with lockout; **audit log** of auth & security actions.
- **Security headers**: CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy.
- No secrets in code (env-driven `SECRET_KEY`); `.env` git-ignored; API docs disabled in prod.
- Parameterized ORM access only (no raw SQL); strict Pydantic validation; Bearer-token auth for programmatic/MCP use.
- CI: **CodeQL** + **pip-audit** workflow (`.github/workflows/security.yml`).

```
┌──────────────┐     REST + MCP      ┌────────────────────┐      ┌──────────────┐
│  Frontend    │  ◀───────────────▶  │   FastAPI backend  │ ◀──▶ │  Database    │
│  (SPA, JS)   │   /api/* /mcp/*     │  search · detect   │      │ SQLite / PG  │
│  Chart.js    │                     │  AI analyst · MCP  │      │ SQLAlchemy   │
└──────────────┘                     └────────────────────┘      └──────────────┘
```

## Stack
- **Backend:** Python 3.12, FastAPI, SQLAlchemy, Uvicorn
- **Database:** SQLite by default (zero config) · PostgreSQL via `DATABASE_URL`
- **Frontend:** vanilla JS SPA + Chart.js (served by the backend)
- **AI:** built-in deterministic analyst; optional LLM via `OPENAI_API_KEY`
- **MCP:** HTTP endpoint (`/mcp/tools`, `/mcp/call`) + stdio server (`app.mcp_server`)

## Quick start

### Option A — Docker (Postgres, production-like)
```bash
docker compose up --build
# open http://localhost:8000
```

### Option B — Local (SQLite, no Docker)
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# open http://localhost:8000
```
On first launch the DB is auto-created and seeded with ~2,400 events across 8 sources,
9 detection rules, and 8 realistic attack scenarios; the detection engine runs once to
populate findings.

**First run:** open `http://localhost:8000` → you're redirected to `/login`. Click
**Create an account** — the **first user becomes `admin`**. (Or set `ADMIN_USERNAME` /
`ADMIN_PASSWORD` in `.env` to auto-create an admin on boot.)

## Deploy live
- **Render (one click):** push to GitHub, then *New → Blueprint* and point at the repo —
  `render.yaml` provisions the web service + Postgres and generates a `SECRET_KEY`.
- **Any Docker host / Fly.io / Railway:** the included `Dockerfile` runs the whole stack.
- **PaaS:** `backend/Procfile` is provided. Always set `SECRET_KEY`, `ENV=prod`,
  `COOKIE_SECURE=true`, and a Postgres `DATABASE_URL` in production.

## Features
- **Search & Investigate** — SPL-like language: `field=value`, `!=`, `>`, `<`, wildcards,
  `AND/OR/NOT`, and pipes: `stats`, `timechart`, `top`, `rare`, `sort`, `table`, `where`,
  `dedup`, `head`/`tail`. Example: `action=failure | stats count by src_ip`.
- **Overview dashboard** — risk score, KPIs, severity timeline, source mix, geo & talkers, source health.
- **AI Security Analyst** — chat that explains detections, recommends actions, and queries the data.
- **Findings / Incidents** — correlated detections with severity, MITRE ATT&CK, evidence, remediation; one-click "Create incident".
- **Detection rules** — toggle detectors on/off; findings recompute server-side.
- **Live stream**, **data sources**, **MCP connectors** page.

## Detections
Brute-force · port scan · SQLi/web attack · credential dumping · C2 beaconing ·
data exfiltration · cloud privilege escalation · impossible travel · IDS signatures.

## API (selected)
| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | liveness + counts |
| GET | `/api/stats/overview?range=24h` | dashboard data |
| POST | `/api/search` | run an SPL query |
| GET | `/api/findings` | correlated findings |
| POST | `/api/analyze` | re-run detection engine |
| GET/PATCH | `/api/rules` , `/api/rules/{id}` | manage rules |
| POST | `/api/ingest` | ingest an external event |
| POST | `/api/ai/chat` | ask the AI analyst |
| GET | `/mcp/tools` · POST `/mcp/call` | MCP tool interface |

Interactive API docs: `http://localhost:8000/docs`

## MCP for AI agents
Run the stdio server and point an MCP client (e.g. Claude Desktop) at it:
```json
{ "mcpServers": { "sentinelops": {
  "command": "python", "args": ["-m", "app.mcp_server"],
  "env": { "SIEM_API_URL": "http://localhost:8000" } } } }
```
(Install the SDK with `pip install mcp`.) Tools: `siem.search`, `siem.get_findings`,
`siem.analyze`, `siem.overview`, `siem.create_incident`.

## Notes
- Seed data is realistic synthetic telemetry. Point real log sources at `POST /api/ingest`
  (or add syslog/HEC collectors) to ingest production data.
- The built-in analyst is rule-based so it runs offline with no errors; set `OPENAI_API_KEY`
  to enable LLM answers for free-form questions.
- Reference for containerized deployment patterns: splunk/docker-splunk.
