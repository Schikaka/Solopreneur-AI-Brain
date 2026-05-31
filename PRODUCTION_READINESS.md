# Production Readiness Handoff

## Verdict

Pass with follow-up: ready for a small production deployment after real
environment secrets are configured.

## What Is Covered

- Flask app factory for WSGI servers.
- Gunicorn runtime command through `Procfile`.
- Health endpoint at `/healthz`.
- CSV upload validation with file type and max-size limits.
- Uploaded files are deleted after analysis.
- Required CSV columns and non-negative metrics are validated.
- Deterministic narrative fallback when the LLM key is missing.
- Frontend escapes dynamic API strings before inserting report HTML.
- Desktop and mobile browser smoke checks pass.
- Unit and route tests pass.
- Gatekeeper calls are protected with short-lived signed JWTs and a payload hash.
- License validation reads from an encrypted SQLCipher-backed `database.db`
  when `pysqlcipher3` is installed.
- Gatekeeper report generation is rate limited to 5 requests per minute per IP.
- Client pages receive nonce-based CSP headers for script execution.

## Required Environment

- `APP_ENV=production`
- `SECRET_KEY`
- `DATABASE_ENCRYPTION_KEY`
- `GATEKEEPER_JWT_SECRET`
- `EMERGENT_LLM_KEY`
- `LICENSE_DB_PATH`
- `LICENSE_SEED_KEYS`
- `PORT`
- `MAX_UPLOAD_MB`

## Validation Commands

```bash
venv/bin/python -m py_compile app.py narrative_logic.py
venv/bin/python -m pytest
APP_ENV=production SECRET_KEY=change-me PORT=5050 \
  venv/bin/gunicorn "app:create_app()" --bind 127.0.0.1:5050 --workers 2
curl http://127.0.0.1:5050/healthz
curl http://127.0.0.1:5050/api/sample
```

## Rollback

Revert the production-readiness commit or redeploy the previous main-branch
commit. Rotate `DATABASE_ENCRYPTION_KEY` only with a planned database
re-encryption or rebuild from trusted license seed material.

## Follow-Up

- Add persistent observability if deploying beyond a single small instance.
- Replace the deterministic fallback with a visible "AI key missing" admin
  status if non-technical customers will operate the app.
