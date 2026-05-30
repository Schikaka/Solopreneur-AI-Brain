from pathlib import Path

import pandas as pd
import pytest

from narrative_logic import analyze_data, get_top_3_insights, read_marketing_csv


def test_analyze_data_returns_expected_sample_stats():
    result = analyze_data("dummy_marketing_data.csv")

    assert result["stats"]["total_spend"] == 2980.0
    assert result["stats"]["total_revenue"] == 13650.0
    assert result["stats"]["avg_roas"] == 4.58
    assert result["stats"]["top_campaign"] == "Summer Sale Search"
    assert len(result["insights"]) == 3
    assert len(result["daily_trends"]) == 4


def test_analyze_data_calls_gatekeeper_with_license(monkeypatch):
    captured = {}

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"narrative": "Narrative from gatekeeper"}

    def post(url, json, timeout):
        captured["url"] = url
        captured["payload"] = json
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("GATEKEEPER_URL", "http://gatekeeper.test")
    monkeypatch.setattr("narrative_logic.requests.post", post)

    result = analyze_data("dummy_marketing_data.csv", license_key="DEMO123")

    assert captured["url"] == "http://gatekeeper.test/verify-and-generate"
    assert captured["payload"]["license_key"] == "DEMO123"
    assert captured["payload"]["stats"]["total_revenue"] == 13650.0
    assert result["narrative"] == "Narrative from gatekeeper"


def test_get_top_3_insights_returns_daily_significance():
    insights = get_top_3_insights("dummy_marketing_data.csv")

    assert len(insights) == 3
    assert insights[0]["type"] == "highest_conversions"
    assert insights[0]["date"] == "2026-05-04"


def test_read_marketing_csv_rejects_missing_columns(tmp_path):
    csv_path = tmp_path / "missing.csv"
    csv_path.write_text("Date,Campaign,Spend\n2026-05-01,Test,100\n", encoding="utf-8")

    with pytest.raises(ValueError, match="missing required columns"):
        read_marketing_csv(csv_path)


def test_read_marketing_csv_rejects_negative_metrics(tmp_path):
    csv_path = tmp_path / "negative.csv"
    csv_path.write_text(
        "\n".join(
            [
                "Date,Campaign,Spend,Clicks,Impressions,Conversions,Revenue",
                "2026-05-01,Search,-1,10,100,1,50",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="negative values"):
        read_marketing_csv(csv_path)


def test_uploaded_normal_csv_is_supported(tmp_path):
    csv_path = tmp_path / "normal.csv"
    pd.DataFrame(
        [
            {
                "Date": "2026-05-01",
                "Campaign": "Search",
                "Spend": 100,
                "Clicks": 50,
                "Impressions": 1000,
                "Conversions": 5,
                "Revenue": 300,
            }
        ]
    ).to_csv(csv_path, index=False)

    df = read_marketing_csv(csv_path)

    assert list(df["Campaign"]) == ["Search"]
    assert df["Spend"].sum() == 100
