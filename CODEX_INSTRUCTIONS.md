# Codex Build & Management Instructions

Use these command-oriented workflows to manage, build, and scale NarrativeAI on
this local machine.

## Command: "Initialize Project"

1. Create a virtual environment: `python3 -m venv venv`.
2. Install runtime and development dependencies:
   `venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt`.
3. Check for `.env`. If missing, create it from `.env.example`.
4. Ensure the `uploads/` folder exists.

## Command: "Run App"

1. Start the Flask development server: `venv/bin/python app.py`.
2. Provide the local URL: `http://127.0.0.1:5000`.
3. Monitor the console for POST errors during CSV uploads.

## Command: "Run Production Server"

1. Start Gunicorn:
   `venv/bin/gunicorn "app:create_app()" --bind 0.0.0.0:${PORT:-5000}`.
2. Verify the health endpoint: `curl http://127.0.0.1:5000/healthz`.

## Command: "Test with Dummy Data"

1. Verify `dummy_marketing_data.csv` exists.
2. Run `venv/bin/python narrative_logic.py`.
3. Run `venv/bin/python -m pytest`.

## Command: "Add Insights Feature"

1. Open `narrative_logic.py`.
2. Add or update logic for:
   - The day with the highest ROAS.
   - The campaign with the lowest cost-per-click.
   - Total conversion growth when a date series is present.
3. Update the JSON return object to include an `insights` array.

## Command: "Sync UI with Logic"

1. Open `templates/index.html`.
2. Update the JavaScript `fetch` block to handle backend insight data.
3. Display insights in the `insights-container` area as visual badges.

## Command: "Push Update"

1. Review the diff: `git diff`.
2. Stage intended changes: `git add <files>`.
3. Commit with a descriptive message.
4. Push to main: `git push origin main`.
