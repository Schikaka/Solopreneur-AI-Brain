# NarrativeAI

NarrativeAI turns marketing performance CSVs into report-ready summaries for
agency client updates.

## What It Does

- Upload a CSV with spend, clicks, impressions, conversions, and revenue.
- Review executive stats, daily trend bars, and insight badges.
- Generate a narrative summary using the Emergent LLM API when configured.
- Fall back to a deterministic narrative when no API key is present.

## Required CSV Columns

```csv
Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue
```

## Local Setup

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
venv/bin/python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Production Run

Use a WSGI server instead of Flask's development server:

```bash
gunicorn "app:create_app()" --bind 0.0.0.0:${PORT:-5000}
```

Set these environment variables before deploying:

- `APP_ENV=production`
- `SECRET_KEY`
- `DATABASE_ENCRYPTION_KEY`
- `GATEKEEPER_JWT_SECRET`
- `EMERGENT_LLM_KEY`
- `LICENSE_DB_PATH`
- `LICENSE_SEED_KEYS`
- `PORT`
- `MAX_UPLOAD_MB`

The Gatekeeper stores license hashes in `database.db` through SQLCipher when
`pysqlcipher3` is installed. Production deployments should set
`SQLCIPHER_REQUIRED=1` and use a long random `DATABASE_ENCRYPTION_KEY`.

The Gatekeeper also runs a semantic firewall, OpenAI circuit breaker, idempotent
fallback cache, and JSON structured logs. Set `REDIS_URL` to persist fallback
cache entries outside process memory.

## Security Architecture

NarrativeAI splits the local report builder from the Gatekeeper service so
license validation, model-provider access, audit storage, and compliance state
stay on the protected backend boundary.

- Startup validation: Gatekeeper runs `tests/security_scan.py` during startup and
  exits with a critical error if required security controls fail.
- Database protection: license records are stored as hashes, with SQLCipher
  enforced in production through `SQLCIPHER_REQUIRED=1` and
  `DATABASE_ENCRYPTION_KEY`.
- Request integrity: the local app signs Gatekeeper requests with JWTs and a
  payload SHA-256 header.
- Intrusion tripwire: `/api/v1/debug_admin` is a honey-pot route. Any request to
  it blacklists the source IP in memory and emits a critical structured log.
- Compliance dashboard: the Admin page surfaces Database Encryption, SAST Scan,
  and IPS Blacklist count in the Security & Compliance Health widget.

## Checks

```bash
venv/bin/python tests/security_scan.py
venv/bin/python -m py_compile app.py gatekeeper_server.py narrative_logic.py security_tokens.py license_store.py
venv/bin/python -m pytest
```

## Health Check

```bash
curl http://127.0.0.1:5000/healthz
```
