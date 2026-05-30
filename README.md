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
- `EMERGENT_LLM_KEY`
- `PORT`
- `MAX_UPLOAD_MB`

## Checks

```bash
venv/bin/python -m py_compile app.py narrative_logic.py
venv/bin/python -m pytest
```

## Health Check

```bash
curl http://127.0.0.1:5000/healthz
```
