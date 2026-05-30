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

## Required Environment

- `APP_ENV=production`
- `SECRET_KEY`
- `EMERGENT_LLM_KEY`
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
commit. No database migration or persistent data migration is involved.

## Follow-Up

- Add real authentication before storing user history or customer reports.
- Add persistent observability if deploying beyond a single small instance.
- Replace the deterministic fallback with a visible "AI key missing" admin
  status if non-technical customers will operate the app.
