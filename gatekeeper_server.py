import json
import os

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request


load_dotenv()

VALID_LICENSE_KEYS = {"DEMO123", "TEST456"}
OPENAI_TIMEOUT_SECONDS = 30


def _env_int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return int(default)


def _format_money(value):
    return f"${float(value):,.2f}"


def _fallback_narrative(stats):
    return (
        "**Executive Summary**\n"
        f"Gatekeeper verified the license and analyzed {_format_money(stats['total_revenue'])} "
        f"in revenue from {_format_money(stats['total_spend'])} in spend. Average ROAS was "
        f"{stats['avg_roas']}x, with {stats['total_conversions']} conversions led by "
        f"{stats['top_campaign']}.\n\n"
        "The OpenAI API key is not configured on this Gatekeeper instance yet, so this "
        "deterministic narrative confirms the secure split is working without exposing "
        "any private key to the local client."
    )


def generate_narrative(stats):
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("EMERGENT_LLM_KEY")
    if not api_key:
        return _fallback_narrative(stats)

    prompt = (
        "You are a Senior Marketing Account Manager. Write a 3-paragraph "
        "professional executive summary based on these stats: "
        f"{json.dumps(stats)}"
    )
    response = requests.post(
        os.getenv(
            "OPENAI_API_URL",
            os.getenv("EMERGENT_LLM_URL", "https://api.openai.com/v1/chat/completions"),
        ),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": os.getenv("OPENAI_MODEL", os.getenv("EMERGENT_LLM_MODEL", "gpt-4o-mini")),
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=OPENAI_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def create_app():
    app = Flask(__name__)

    @app.get("/healthz")
    def health_check():
        return jsonify({"status": "ok", "service": "gatekeeper"})

    @app.post("/verify-and-generate")
    def verify_and_generate():
        payload = request.get_json(silent=True) or {}
        stats = payload.get("stats")
        license_key = str(payload.get("license_key", "")).strip()

        if license_key not in VALID_LICENSE_KEYS:
            return jsonify({"error": "Invalid license key."}), 403

        if not isinstance(stats, dict):
            return jsonify({"error": "Stats payload must be a JSON object."}), 400

        try:
            return jsonify({"narrative": generate_narrative(stats)})
        except Exception as exc:
            app.logger.exception("Gatekeeper narrative generation failed")
            return jsonify({"error": f"Gatekeeper generation failed: {str(exc)}"}), 502

    return app


app = create_app()


if __name__ == "__main__":
    port = _env_int("PORT", 5001)
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=port, debug=debug)
