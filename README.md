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
gunicorn "gatekeeper_server:app" --bind 0.0.0.0:${PORT:-5001}
```

The Gatekeeper reads Render's `PORT` environment variable, exposes `/healthz`,
`/HEALTHZ`, `/readyness`, and `/readiness`, and defaults to `0.0.0.0` in
production or Render runtimes.

Set these environment variables before deploying:

- `APP_ENV=production`
- `SECRET_KEY`
- `DATABASE_ENCRYPTION_KEY`
- `GATEKEEPER_JWT_SECRET`
- `STRIPE_WEBHOOK_SECRET`
- `EMERGENT_LLM_KEY`
- `LICENSE_DB_PATH`
- `LICENSE_SEED_KEYS`
- `PORT`
- `MAX_UPLOAD_MB`
- `DOMAIN_URL`
- `SQLCIPHER_REQUIRED=1`
- `WAF_HEADER_CHECK=1`

The Gatekeeper stores license hashes in `database.db` through SQLCipher when
`pysqlcipher3` is installed. Production deployments must set
`SQLCIPHER_REQUIRED=1` and use a long random `DATABASE_ENCRYPTION_KEY`.

The Gatekeeper also runs a semantic firewall, OpenAI circuit breaker, idempotent
fallback cache, strict Stripe webhook signature verification, WAF-friendly edge
header checks, and JSON structured logs. Set `REDIS_URL` to persist fallback
cache entries outside process memory.

## How To Deploy On Render

1. Push the latest `main` branch to GitHub.

2. Open the Render Blueprint flow:
   [https://dashboard.render.com/blueprint/new?repo=https://github.com/Schikaka/Solopreneur-AI-Brain](https://dashboard.render.com/blueprint/new?repo=https://github.com/Schikaka/Solopreneur-AI-Brain)

3. Render will read `render.yaml`. Confirm the service is `narrativeai-gatekeeper`, the runtime is Python, the start command uses Gunicorn, and the health check path is `/readyness`.

4. Fill every secret marked `sync: false` in the Render dashboard:
   - `DATABASE_ENCRYPTION_KEY`: long random SQLCipher key.
   - `GATEKEEPER_JWT_SECRET`: long random shared signing secret. Use the same value in any client app that calls Gatekeeper.
   - `SECRET_KEY`: long random Flask secret.
   - `LICENSE_SEED_KEYS`: comma-separated paid or pilot license keys.
   - `STRIPE_WEBHOOK_SECRET`: the Stripe endpoint signing secret beginning with `whsec_`.
   - `EMERGENT_LLM_KEY`: production model key.
   - `REDIS_URL`: optional, but recommended for persistent fallback cache.
   - `ALLOWED_HOSTS`: optional custom domains, comma-separated. Render's own hostname is accepted automatically.
   - `DOMAIN_URL`: production service URL. Use Render's generated URL first, for example `https://narrativeai-gatekeeper.onrender.com`, then replace it with the custom domain when DNS is live.

5. In Stripe, create a production webhook endpoint:
   - Endpoint URL: `https://<your-render-service>.onrender.com/stripe/webhook`
   - Event: `checkout.session.completed`
   - Copy the endpoint signing secret into Render as `STRIPE_WEBHOOK_SECRET`.

6. Apply the Blueprint and wait for the deployment to become live.

7. Verify the pre-flight checks:
   - Render logs must show `startup_security_validation_passed`.
   - The same log line must include `database_encryption` as `encrypted`.
   - `sast_scan` must be `passed`.
   - `curl https://<your-render-service>.onrender.com/readyness` must return `{"ok":true,"status":"ready",...}`.
   - `curl https://<your-render-service>.onrender.com/healthz` must return `{"service":"gatekeeper","status":"ok"}`.
   - A Stripe webhook test with the wrong signature must return `400`.

8. Point the client at production:

```bash
export GATEKEEPER_URL=https://<your-render-service>.onrender.com
# or
export GATEKEEPER_PUBLIC_URL=https://<your-render-service>.onrender.com
# preferred production sync variable
export DOMAIN_URL=https://<your-render-service>.onrender.com
```

9. For real paying customers, add persistent storage before relying on the
   SQLite license/event database long term. Mount a Render disk and change
   `LICENSE_DB_PATH` to a path on that disk, for example
   `/var/data/database.db`.

10. Optional local Blueprint validation:

```bash
render blueprints validate
```

## Launch Day Checklist

Use this checklist before opening sales traffic or sending demo keys:

1. GitHub `main` contains the latest launch commit and Render is connected to the repository.
2. Render Blueprint is applied from `render.yaml`, with `healthCheckPath` set to `/readyness`.
3. Render environment variables are complete:
   - `APP_ENV=production`
   - `SQLCIPHER_REQUIRED=1`
   - `WAF_HEADER_CHECK=1`
   - `DOMAIN_URL=https://<your-render-service>.onrender.com`
   - `DATABASE_ENCRYPTION_KEY`
   - `GATEKEEPER_JWT_SECRET`
   - `SECRET_KEY`
   - `LICENSE_SEED_KEYS`
   - `STRIPE_WEBHOOK_SECRET`
   - `EMERGENT_LLM_KEY`
4. Render logs show `startup_security_validation_passed`.
5. Readiness checks are live:
   - `/readyness` returns `ok: true`.
   - Database check reports `encrypted: true`.
   - Startup validation reports `status: pass`.
6. HTTPS hardening is confirmed:
   - `Strict-Transport-Security` is present.
   - Any production `http://` service URL has been replaced with `https://`.
   - `ALLOWED_HOSTS` includes the production hostname or custom domain.
7. Stripe production webhook is configured at `/stripe/webhook`, and a bad signature returns `400`.
8. Admin Panel checks:
   - Security & Compliance Health is green.
   - Session Monitor shows no unexplained flagged keys.
   - Sales & Leads can save a test lead.
   - Generate 48h Demo Key returns a `DEMO-` key with an expiry timestamp.
9. Main dashboard checks:
   - About page shows the Elite Privacy Guarantee.
   - Upgrade to Pro button opens the Stripe Payment Link.
   - Sample report generation succeeds with a production license key.
10. Rollback plan is ready: redeploy the previous successful Render deploy from the dashboard and rotate any exposed secrets before retrying launch.

## Standalone Distribution

Build a single-file desktop-style executable with PyInstaller:

```bash
venv/bin/python build_dist.py
```

The build runs PyInstaller in one-file, windowed mode and bundles `templates/`,
`static/`, and the sample CSV into the binary. The client app performs a startup
version handshake against Gatekeeper `/check-updates` and shows a gated license
splash before the dashboard loads when no local license key is saved.

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
