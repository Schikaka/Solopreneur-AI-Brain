import base64
import io
import json
import os
from pathlib import Path

import pandas as pd
import requests
from dotenv import load_dotenv

from security_tokens import authorization_header, gatekeeper_payload, payload_hash


load_dotenv()

REQUIRED_COLUMNS = {
    "Date",
    "Campaign",
    "Spend",
    "Clicks",
    "Impressions",
    "Conversions",
    "Revenue",
}
NUMERIC_COLUMNS = ["Spend", "Clicks", "Impressions", "Conversions", "Revenue"]
AI_TIMEOUT_SECONDS = 30


def _missing_columns(df):
    return sorted(REQUIRED_COLUMNS.difference(df.columns))


def _decode_base64_csv(file_path):
    encoded = Path(file_path).read_text(encoding="utf-8").strip()
    decoded_csv = base64.b64decode(encoded, validate=True).decode("utf-8")
    return pd.read_csv(io.StringIO(decoded_csv))


def _safe_divide(numerator, denominator):
    return numerator / denominator.where(denominator != 0)


def _format_money(value):
    return f"${float(value):,.2f}"


def _fallback_narrative(stats):
    return (
        f"Revenue reached {_format_money(stats['total_revenue'])} from "
        f"{_format_money(stats['total_spend'])} in spend, producing an "
        f"average ROAS of {stats['avg_roas']}. The strongest campaign was "
        f"{stats['top_campaign']}. Add a valid license key to generate the "
        "full AI-written client narrative through the Gatekeeper."
    )


def normalize_marketing_data(df):
    if df.empty:
        raise ValueError("CSV does not contain any campaign rows.")

    missing = _missing_columns(df)
    if missing:
        raise ValueError(f"CSV is missing required columns: {missing}")

    normalized = df.copy()
    normalized["Date"] = pd.to_datetime(normalized["Date"], errors="raise").dt.date.astype(str)
    normalized["Campaign"] = normalized["Campaign"].astype(str).str.strip()

    for column in NUMERIC_COLUMNS:
        normalized[column] = pd.to_numeric(normalized[column], errors="raise")

    if normalized["Campaign"].eq("").any():
        raise ValueError("Campaign values cannot be blank.")

    if (normalized[NUMERIC_COLUMNS] < 0).any().any():
        raise ValueError("Metric columns cannot contain negative values.")

    if normalized["Spend"].sum() <= 0:
        raise ValueError("Total spend must be greater than zero.")

    if normalized["Clicks"].sum() <= 0:
        raise ValueError("Total clicks must be greater than zero.")

    if normalized["Impressions"].sum() <= 0:
        raise ValueError("Total impressions must be greater than zero.")

    return normalized


def read_marketing_csv(file_path):
    try:
        df = pd.read_csv(file_path)
    except Exception:
        df = _decode_base64_csv(file_path)

    if _missing_columns(df):
        try:
            df = _decode_base64_csv(file_path)
        except Exception as exc:
            raise ValueError(f"CSV is missing required columns: {_missing_columns(df)}") from exc

    return normalize_marketing_data(df)


def get_ai_narrative(stats, license_key):
    gatekeeper_url = os.getenv("GATEKEEPER_URL", "http://localhost:5001").rstrip("/")
    payload = gatekeeper_payload(stats, license_key)

    try:
        response = requests.post(
            f"{gatekeeper_url}/verify-and-generate",
            json=payload,
            headers={
                "Authorization": authorization_header(payload),
                "X-Payload-SHA256": payload_hash(payload),
            },
            timeout=AI_TIMEOUT_SECONDS,
        )
        if response.status_code == 403:
            error = response.json().get("error", "Invalid license key.")
            raise PermissionError(error)
        response.raise_for_status()
        return response.json()["narrative"]
    except PermissionError:
        raise
    except Exception as exc:
        return f"Analysis complete. Gatekeeper request failed: {str(exc)}"


def build_daily_frame(df):
    daily = (
        df.groupby("Date", as_index=False)
        .agg(
            Spend=("Spend", "sum"),
            Clicks=("Clicks", "sum"),
            Impressions=("Impressions", "sum"),
            Conversions=("Conversions", "sum"),
            Revenue=("Revenue", "sum"),
        )
        .sort_values("Date")
    )

    daily["ROAS"] = _safe_divide(daily["Revenue"], daily["Spend"])
    daily["ROI"] = _safe_divide(daily["Revenue"] - daily["Spend"], daily["Spend"]) * 100
    daily["CTR"] = _safe_divide(daily["Clicks"], daily["Impressions"]) * 100
    daily["ConversionRate"] = _safe_divide(daily["Conversions"], daily["Clicks"]) * 100
    return daily.fillna(0)


def build_campaign_frame(df):
    campaign = (
        df.groupby("Campaign", as_index=False)
        .agg(
            Spend=("Spend", "sum"),
            Clicks=("Clicks", "sum"),
            Revenue=("Revenue", "sum"),
        )
        .sort_values("Campaign")
    )
    campaign["CPC"] = _safe_divide(campaign["Spend"], campaign["Clicks"])
    return campaign.fillna(0)


def build_daily_trends(df):
    daily = build_daily_frame(df)

    return [
        {
            "date": str(row.Date),
            "spend": round(float(row.Spend), 2),
            "revenue": round(float(row.Revenue), 2),
            "conversions": int(row.Conversions),
            "roas": round(float(row.ROAS), 2),
            "roi": round(float(row.ROI), 2),
            "ctr": round(float(row.CTR), 2),
        }
        for row in daily.itertuples(index=False)
    ]


def get_insights(df):
    daily = build_daily_frame(df)
    campaign = build_campaign_frame(df)

    highest_roas = daily.loc[daily["ROAS"].idxmax()]
    clickable_campaigns = campaign[campaign["Clicks"] > 0]
    lowest_cpc = clickable_campaigns.loc[clickable_campaigns["CPC"].idxmin()]

    insights = [
        {
            "title": "Highest ROAS day",
            "value": f"{float(highest_roas.ROAS):.2f}x",
            "detail": (
                f"{highest_roas.Date} returned {_format_money(highest_roas.Revenue)} "
                f"on {_format_money(highest_roas.Spend)} spend."
            ),
        },
        {
            "title": "Lowest cost-per-click",
            "value": _format_money(lowest_cpc.CPC),
            "detail": f"{lowest_cpc.Campaign} had the most efficient traffic cost.",
        },
    ]

    if len(daily) > 1:
        first_conversions = float(daily.iloc[0]["Conversions"])
        last_conversions = float(daily.iloc[-1]["Conversions"])
        growth = (
            ((last_conversions - first_conversions) / first_conversions) * 100
            if first_conversions
            else 0
        )
        insights.append(
            {
                "title": "Conversion growth",
                "value": f"{growth:.2f}%",
                "detail": (
                    f"Conversions moved from {int(first_conversions)} to "
                    f"{int(last_conversions)} across the date series."
                ),
            }
        )

    return insights


def get_top_3_insights(file_path):
    df = read_marketing_csv(file_path)
    daily = build_daily_frame(df)
    metrics = [
        ("highest_roas", "ROAS", "ROAS", lambda value: f"{value:.2f}x"),
        ("highest_roi", "ROI", "ROI", lambda value: f"{value:.2f}%"),
        ("highest_revenue", "Revenue", "revenue", _format_money),
        ("highest_conversions", "Conversions", "conversions", lambda value: f"{int(value):,}"),
        ("highest_ctr", "CTR", "CTR", lambda value: f"{value:.2f}%"),
    ]

    insights = []
    for insight_type, column, label, formatter in metrics:
        row = daily.loc[daily[column].idxmax()]
        value = float(row[column])
        average = float(daily[column].mean())
        lift_pct = ((value - average) / abs(average) * 100) if average else 0

        insights.append(
            {
                "type": insight_type,
                "date": str(row["Date"]),
                "metric": label,
                "value": formatter(value),
                "daily_average": formatter(average),
                "lift_vs_average": f"{lift_pct:.2f}%",
                "significance_score": round(float(lift_pct), 2),
                "summary": (
                    f"{row['Date']} had the highest {label} at "
                    f"{formatter(value)}, {lift_pct:.2f}% above the daily average."
                ),
            }
        )

    return sorted(
        insights,
        key=lambda item: item["significance_score"],
        reverse=True,
    )[:3]


def analyze_data(file_path, license_key=""):
    df = read_marketing_csv(file_path)

    total_spend = df["Spend"].sum()
    total_clicks = df["Clicks"].sum()
    total_impressions = df["Impressions"].sum()
    total_conversions = df["Conversions"].sum()
    total_revenue = df["Revenue"].sum()
    avg_roas = total_revenue / total_spend
    avg_ctr = (total_clicks / total_impressions) * 100
    top_campaign = df.groupby("Campaign")["Revenue"].sum().idxmax()

    stats = {
        "total_spend": round(float(total_spend), 2),
        "total_clicks": int(total_clicks),
        "total_conversions": int(total_conversions),
        "total_revenue": round(float(total_revenue), 2),
        "avg_ctr": round(float(avg_ctr), 2),
        "avg_roas": round(float(avg_roas), 2),
        "top_campaign": top_campaign,
    }

    return {
        "stats": stats,
        "insights": get_insights(df),
        "top_daily_insights": get_top_3_insights(file_path),
        "daily_trends": build_daily_trends(df),
        "narrative": get_ai_narrative(stats, license_key) if license_key else _fallback_narrative(stats),
    }


if __name__ == "__main__":
    result = analyze_data("dummy_marketing_data.csv")
    print(json.dumps(result, indent=2))
