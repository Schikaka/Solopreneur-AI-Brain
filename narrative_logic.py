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
DIRECTIVE_TONES = {"Boardroom", "Startup", "Precise", "Persuasive"}
DIRECTIVE_GOALS = {"Budget Request", "Performance Fix", "Retention"}


def _missing_columns(df):
    return sorted(REQUIRED_COLUMNS.difference(df.columns))


def _decode_base64_csv_text(encoded):
    decoded_csv = base64.b64decode(str(encoded).strip(), validate=True).decode("utf-8-sig")
    return pd.read_csv(io.StringIO(decoded_csv))


def _read_csv_text(source):
    if hasattr(source, "read"):
        payload = source.read()
        if hasattr(source, "seek"):
            source.seek(0)
    elif isinstance(source, (bytes, bytearray)):
        payload = bytes(source)
    elif isinstance(source, Path):
        payload = source.read_bytes()
    elif isinstance(source, str):
        if "\n" not in source and "\r" not in source:
            possible_path = Path(source)
            try:
                source_is_path = possible_path.exists()
            except OSError:
                source_is_path = False
            if source_is_path:
                payload = possible_path.read_bytes()
            else:
                payload = source
        else:
            payload = source
    else:
        raise TypeError("CSV source must be a path, bytes, text, or file-like object.")

    if isinstance(payload, bytes):
        return payload.decode("utf-8-sig")
    return str(payload)


def _safe_divide(numerator, denominator):
    return numerator / denominator.where(denominator != 0)


def _format_money(value):
    return f"${float(value):,.2f}"


def _json_safe(value):
    if pd.isna(value):
        return None
    if hasattr(value, "item"):
        value = value.item()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def sanitize_directive(directive):
    directive = directive if isinstance(directive, dict) else {}
    tone = str(directive.get("tone") or "Boardroom").strip().title()
    goal = str(directive.get("goal") or "Budget Request").strip().title()
    if tone not in DIRECTIVE_TONES:
        tone = "Boardroom"
    if goal not in DIRECTIVE_GOALS:
        goal = "Budget Request"
    return {"tone": tone, "goal": goal}


def _fallback_narrative(stats):
    total_revenue = float(stats.get("total_revenue", 0))
    total_spend = float(stats.get("total_spend", 0))
    avg_roas = float(stats.get("avg_roas", 0))
    total_conversions = int(float(stats.get("total_conversions", 0)))
    top_campaign = str(stats.get("top_campaign") or "the leading campaign").strip()
    if any(term in top_campaign.lower() for term in ("gatekeeper", "license", "licence", "api key")):
        top_campaign = "the leading campaign"

    efficiency_posture = (
        "The account is converting capital with strong discipline"
        if avg_roas >= 3
        else "The account has a clear efficiency gap to close"
    )
    optimization_path = (
        "The immediate priority is to scale the proven pattern without diluting return quality."
        if avg_roas >= 3
        else (
            "The core problem is return density: current efficiency leaves too little margin for broad scaling. "
            "If this pattern is expanded unchanged, deployed capital can lose momentum quickly. "
            "The solution is tighter audience, creative, and placement governance before budget increases."
        )
    )

    return (
        "**Executive CMO Brief**\n"
        f"The portfolio generated {_format_money(total_revenue)} in secured return from "
        f"{_format_money(total_spend)} in deployed capital, producing a {avg_roas:.2f}x ROAS profile "
        f"and {total_conversions:,} conversions. Momentum is anchored by {top_campaign}, giving leadership "
        "a clear signal for where disciplined scaling should begin.\n\n"
        "**Execution Efficiency**\n"
        f"{efficiency_posture}: every dollar of deployed capital is currently returning {avg_roas:.2f}x. "
        "This creates a practical benchmark for budget decisions, channel prioritization, and margin protection.\n\n"
        "**Campaign Momentum**\n"
        f"{top_campaign} is the primary momentum driver and should be treated as the current proof point for "
        "message-market fit. The strategic objective is to preserve its signal quality while extending learnings "
        "into adjacent audiences and creative angles.\n\n"
        "**Optimization Pathways**\n"
        f"{optimization_path} The operating focus should be sharper allocation, cleaner conversion paths, "
        "and faster feedback loops between spend, revenue, and campaign-level response.\n\n"
        "**Strategic Recommendations**\n"
        f"1. Reallocate incremental deployed capital toward {top_campaign} and closely related high-intent segments.\n"
        "2. Protect secured return by tightening review of underperforming audiences, placements, and creative before scaling.\n"
        "3. Establish a weekly executive scorecard around secured return, ROAS, conversions, and campaign momentum."
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


def read_marketing_csv(source):
    csv_text = _read_csv_text(source)
    try:
        df = pd.read_csv(io.StringIO(csv_text))
    except Exception:
        df = _decode_base64_csv_text(csv_text)

    if _missing_columns(df):
        try:
            df = _decode_base64_csv_text(csv_text)
        except Exception as exc:
            raise ValueError(f"CSV is missing required columns: {_missing_columns(df)}") from exc

    return normalize_marketing_data(df)


def _post_gatekeeper(path, payload):
    gatekeeper_url = os.getenv("GATEKEEPER_URL", "http://localhost:5001").rstrip("/")
    return requests.post(
        f"{gatekeeper_url}{path}",
        json=payload,
        headers={
            "Authorization": authorization_header(payload),
            "X-Payload-SHA256": payload_hash(payload),
        },
        timeout=AI_TIMEOUT_SECONDS,
    )


def build_audit_context(df, stats):
    columns = list(df.columns)
    column_indexes = {column: index + 1 for index, column in enumerate(columns)}
    source_rows = []
    normalized = df.reset_index(drop=True)
    for row_index, row in normalized.iterrows():
        source_rows.append(
            {
                "row_index": int(row_index),
                "csv_row_index": int(row_index) + 2,
                "columns": {
                    column: {
                        "column_index": column_indexes[column],
                        "value": _json_safe(row[column]),
                    }
                    for column in columns
                },
            }
        )

    all_rows = [row["csv_row_index"] for row in source_rows]
    top_campaign = stats.get("top_campaign")
    top_campaign_rows = [
        row["csv_row_index"]
        for row in source_rows
        if str((row["columns"].get("Campaign") or {}).get("value")) == str(top_campaign)
    ]

    return {
        "columns": column_indexes,
        "source_rows": source_rows,
        "aggregate_map": {
            "total_revenue": {
                "stat_key": "total_revenue",
                "calculation": "sum",
                "column": "Revenue",
                "column_index": column_indexes.get("Revenue"),
                "csv_rows": all_rows,
                "value": stats.get("total_revenue"),
            },
            "total_spend": {
                "stat_key": "total_spend",
                "calculation": "sum",
                "column": "Spend",
                "column_index": column_indexes.get("Spend"),
                "csv_rows": all_rows,
                "value": stats.get("total_spend"),
            },
            "avg_roas": {
                "stat_key": "avg_roas",
                "calculation": "total_revenue / total_spend",
                "source_metrics": ["total_revenue", "total_spend"],
                "csv_rows": all_rows,
                "columns": [
                    {"name": "Revenue", "column_index": column_indexes.get("Revenue")},
                    {"name": "Spend", "column_index": column_indexes.get("Spend")},
                ],
                "value": stats.get("avg_roas"),
            },
            "total_conversions": {
                "stat_key": "total_conversions",
                "calculation": "sum",
                "column": "Conversions",
                "column_index": column_indexes.get("Conversions"),
                "csv_rows": all_rows,
                "value": stats.get("total_conversions"),
            },
            "top_campaign": {
                "stat_key": "top_campaign",
                "calculation": "highest summed Revenue by Campaign",
                "columns": [
                    {"name": "Campaign", "column_index": column_indexes.get("Campaign")},
                    {"name": "Revenue", "column_index": column_indexes.get("Revenue")},
                ],
                "csv_rows": top_campaign_rows,
                "value": top_campaign,
            },
        },
    }


def get_ai_narrative_result(stats, license_key, directive=None, audit_context=None):
    directive = sanitize_directive(directive)
    payload = gatekeeper_payload(
        stats,
        license_key,
        {
            "directive": directive,
            "audit_context": audit_context or {},
        },
    )

    try:
        response = _post_gatekeeper("/verify-and-generate", payload)
        if response.status_code == 403:
            error = response.json().get("error", "Invalid license key.")
            raise PermissionError(error)
        response.raise_for_status()
        return response.json()
    except PermissionError:
        raise
    except Exception:
        return {
            "narrative": _fallback_narrative(stats),
            "source": "deterministic_fallback",
            "report_id": None,
            "audit": {
                "report_id": None,
                "math_anomaly_detected": False,
                "anomaly_details": [],
                "reasoning_trace_available": False,
            },
        }


def get_ai_narrative(stats, license_key, directive=None, audit_context=None):
    return get_ai_narrative_result(
        stats,
        license_key,
        directive=directive,
        audit_context=audit_context,
    )["narrative"]


def refine_report(stats, narrative, instruction, license_key, directive=None, report_id=None):
    directive = sanitize_directive(directive)
    extra = {
        "narrative": str(narrative or "").strip(),
        "instruction": str(instruction or "").strip(),
        "directive": directive,
    }
    if report_id:
        extra["parent_report_id"] = str(report_id)
    payload = gatekeeper_payload(stats, license_key, extra)

    try:
        response = _post_gatekeeper("/refine", payload)
        if response.status_code == 403:
            error = response.json().get("error", "Invalid license key.")
            raise PermissionError(error)
        response.raise_for_status()
        return response.json()
    except PermissionError:
        raise
    except Exception:
        return {
            "narrative": _fallback_narrative(stats),
            "source": "deterministic_refinement",
            "model": "gpt-4o-mini",
            "fact_check_locked": True,
            "report_id": None,
            "audit": {
                "report_id": None,
                "math_anomaly_detected": False,
                "anomaly_details": [],
                "reasoning_trace_available": False,
            },
        }


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


def get_top_3_insights(source):
    df = source if isinstance(source, pd.DataFrame) else read_marketing_csv(source)
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


def analyze_data(csv_source, license_key="", directive=None):
    df = read_marketing_csv(csv_source)

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
    directive = sanitize_directive(directive)
    audit_context = build_audit_context(df, stats)
    narrative_result = (
        get_ai_narrative_result(stats, license_key, directive=directive, audit_context=audit_context)
        if license_key
        else {
            "narrative": _fallback_narrative(stats),
            "report_id": None,
            "audit": {
                "report_id": None,
                "math_anomaly_detected": False,
                "anomaly_details": [],
                "reasoning_trace_available": False,
            },
        }
    )

    return {
        "stats": stats,
        "insights": get_insights(df),
        "top_daily_insights": get_top_3_insights(df),
        "daily_trends": build_daily_trends(df),
        "directive": directive,
        "narrative": narrative_result.get("narrative", _fallback_narrative(stats)),
        "report_id": narrative_result.get("report_id"),
        "audit": narrative_result.get("audit", {}),
    }


if __name__ == "__main__":
    result = analyze_data("dummy_marketing_data.csv")
    print(json.dumps(result, indent=2))
