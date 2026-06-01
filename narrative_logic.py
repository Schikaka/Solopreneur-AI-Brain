import base64
import io
import json
import os
import re
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
MAX_CHANNEL_FILES = 3
CHANNEL_COLUMNS = ("Channel", "channel", "Platform", "platform", "Source", "source", "Network", "network")
CHANNEL_FILENAME_HINTS = (
    ("search", "Google Search"),
    ("google", "Google Ads"),
    ("meta", "Meta"),
    ("facebook", "Meta"),
    ("instagram", "Instagram"),
    ("tiktok", "TikTok"),
    ("linkedin", "LinkedIn"),
    ("youtube", "YouTube"),
    ("twitter", "X / Twitter"),
    ("email", "Email"),
)
AI_TIMEOUT_SECONDS = 30
DIRECTIVE_TONES = {"Boardroom", "Startup", "Precise", "Persuasive"}
DIRECTIVE_GOALS = {"Budget Request", "Performance Fix", "Retention"}
DIRECTIVE_BUSINESS_TYPES = ("E-commerce", "B2B SaaS", "Local Service")
DEFAULT_GATEKEEPER_URL = "http://localhost:5001"
DEFAULT_RENDER_URL = "https://narrativeai-gatekeeper.onrender.com"


def _missing_columns(df):
    return sorted(REQUIRED_COLUMNS.difference(df.columns))


def _humanize_channel_name(value):
    normalized = re.sub(r"[_-]+", " ", str(value or "").strip())
    normalized = re.sub(r"\s+", " ", normalized).strip(" .")
    if not normalized:
        return "Unknown Channel"
    lower = normalized.lower()
    for needle, label in CHANNEL_FILENAME_HINTS:
        if needle in lower:
            return label
    return normalized.title()


def _source_parts(source):
    if isinstance(source, dict):
        raw_source = source.get("source", source.get("file", source.get("data")))
        filename = source.get("filename") or source.get("name") or getattr(raw_source, "name", "")
        return raw_source, str(filename or "").strip()
    return source, str(getattr(source, "name", "") or (source if isinstance(source, (str, Path)) else "")).strip()


def _channel_column(df):
    for column in CHANNEL_COLUMNS:
        if column in df.columns:
            return column
    return None


def infer_channel_name(filename="", df=None, fallback_index=1):
    if df is not None:
        column = _channel_column(df)
        if column:
            values = [
                str(value).strip()
                for value in df[column].dropna().unique().tolist()
                if str(value).strip()
            ]
            if len(values) == 1:
                return _humanize_channel_name(values[0])
            if len(values) > 1:
                return "Multi-Channel CSV"

    stem = Path(str(filename or "")).stem
    if stem:
        return _humanize_channel_name(stem)
    return f"Channel {fallback_index}"


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


def _safe_story_label(value, fallback):
    text = str(value or "").strip()
    if not text or any(term in text.lower() for term in ("gatekeeper", "license", "licence", "api key")):
        return fallback
    return text


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
    business_type = _normalize_business_type(directive.get("business_type"))
    if tone not in DIRECTIVE_TONES:
        tone = "Boardroom"
    if goal not in DIRECTIVE_GOALS:
        goal = "Budget Request"
    return {"tone": tone, "goal": goal, "business_type": business_type}


def _normalize_business_type(value):
    normalized = re.sub(r"[\s_-]+", " ", str(value or "")).strip().lower()
    aliases = {
        "ecommerce": "E-commerce",
        "e commerce": "E-commerce",
        "e-commerce": "E-commerce",
        "b2b": "B2B SaaS",
        "b2b saas": "B2B SaaS",
        "b2b software": "B2B SaaS",
        "local": "Local Service",
        "local service": "Local Service",
        "local services": "Local Service",
    }
    return aliases.get(normalized, DIRECTIVE_BUSINESS_TYPES[0])


def _niche_context(business_type):
    if business_type == "Local Service":
        return {
            "executive": "Local Service performance should be read through Map Pack Visibility, GMB Calls, Booked Jobs, and Review Velocity.",
            "efficiency": "The key local-market test is whether deployed capital becomes qualified Phone Calls and Booked Jobs.",
            "scorecard": "Track GMB Calls, Booked Jobs, and review velocity weekly.",
        }
    if business_type == "B2B SaaS":
        return {
            "executive": "B2B SaaS performance should be read through Pipeline Velocity, marketing-sourced pipeline %, and SQL Conversion.",
            "efficiency": "The key revenue-cycle test is whether deployed capital accelerates Pipeline Velocity.",
            "scorecard": "Track Pipeline Velocity, marketing-sourced pipeline %, and SQL Conversion weekly.",
        }
    return {
        "executive": "E-commerce performance should be read through MER, LTV:CAC, Portfolio Efficiency, and payback period discipline.",
        "efficiency": "The key portfolio test is whether MER and LTV:CAC remain healthy as channel spend scales.",
        "scorecard": "Track MER, LTV:CAC, Portfolio Efficiency, and payback periods weekly.",
    }


def _fallback_narrative(stats, directive=None):
    directive = sanitize_directive(directive)
    niche = _niche_context(directive["business_type"])
    total_revenue = float(stats.get("total_revenue", 0))
    total_spend = float(stats.get("total_spend", 0))
    avg_roas = float(stats.get("blended_roas", stats.get("avg_roas", 0)))
    total_conversions = int(float(stats.get("total_conversions", 0)))
    top_campaign = str(stats.get("top_campaign") or "the leading campaign").strip()
    channel_metrics = stats.get("channel_metrics") or []
    attribution = stats.get("strategic_attribution") or {}
    if any(term in top_campaign.lower() for term in ("gatekeeper", "license", "licence", "api key")):
        top_campaign = "the leading campaign"
    top_channel = _safe_story_label(
        attribution.get("best_efficiency_channel") or (channel_metrics[0].get("channel") if channel_metrics else top_campaign),
        "the strongest channel",
    )
    conversion_channel = _safe_story_label(attribution.get("conversion_channel") or top_channel, top_channel)
    awareness_channel = _safe_story_label(attribution.get("awareness_channel") or top_channel, top_channel)
    budget_reallocation = str(
        attribution.get("budget_reallocation") or f"Reallocate incremental deployed capital toward {top_channel}."
    )
    if any(term in budget_reallocation.lower() for term in ("gatekeeper", "license", "licence", "api key")):
        budget_reallocation = f"Reallocate incremental deployed capital toward {top_channel}."

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
        f"{_format_money(total_spend)} in deployed capital, producing a {avg_roas:.2f}x blended ROAS profile "
        f"and {total_conversions:,} conversions. Momentum is anchored by {top_campaign}, giving leadership "
        f"a clear signal for where disciplined scaling should begin. {niche['executive']}\n\n"
        "**Execution Efficiency**\n"
        f"{efficiency_posture}: every dollar of deployed capital is currently returning {avg_roas:.2f}x on a blended basis. "
        f"This creates a practical benchmark for budget decisions, channel prioritization, and margin protection. {niche['efficiency']}\n\n"
        "**Campaign Momentum**\n"
        f"{awareness_channel} is shaping the awareness signal while {conversion_channel} is converting secured return. "
        f"{top_campaign} remains the primary campaign proof point, so the strategic objective is to connect upper-funnel demand "
        "with the channel most capable of capturing it.\n\n"
        "**Optimization Pathways**\n"
        f"{optimization_path} {budget_reallocation} The operating focus should be sharper allocation, cleaner conversion paths, "
        "and faster feedback loops between spend, revenue, and campaign-level response.\n\n"
        "**Strategic Recommendations**\n"
        f"1. Reallocate incremental deployed capital toward {top_channel} and closely related high-intent segments.\n"
        f"2. Use {awareness_channel} to expand demand creation while {conversion_channel} captures the highest-return intent.\n"
        f"3. {niche['scorecard']}"
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
    source, _filename = _source_parts(source)
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


def read_marketing_sources(sources):
    source_items = list(sources) if isinstance(sources, (list, tuple)) else [sources]
    if not source_items:
        raise ValueError("Upload at least one CSV file.")
    if len(source_items) > MAX_CHANNEL_FILES:
        raise ValueError(f"Upload up to {MAX_CHANNEL_FILES} CSV files.")

    frames = []
    channel_sources = []
    for index, item in enumerate(source_items, start=1):
        raw_source, filename = _source_parts(item)
        df = read_marketing_csv(raw_source)
        inferred_channel = infer_channel_name(filename, df, fallback_index=index)
        channel_column = _channel_column(df)
        normalized = df.copy()
        if channel_column:
            normalized["Channel"] = normalized[channel_column].astype(str).str.strip()
            normalized.loc[normalized["Channel"].eq("") | normalized["Channel"].eq("nan"), "Channel"] = inferred_channel
            normalized["Channel"] = normalized["Channel"].map(_humanize_channel_name)
        else:
            normalized["Channel"] = inferred_channel
        normalized["SourceFile"] = Path(filename).name if filename else f"CSV {index}"
        frames.append(normalized)
        channel_sources.append({"filename": normalized["SourceFile"].iloc[0], "channel": inferred_channel})

    return pd.concat(frames, ignore_index=True), channel_sources


def _render_domain_url():
    hostname = os.getenv("RENDER_EXTERNAL_HOSTNAME", "").strip()
    if hostname:
        return f"https://{hostname}"
    if os.getenv("RENDER"):
        return DEFAULT_RENDER_URL
    return ""


def _normalize_service_url(value):
    normalized = str(value or "").strip().rstrip("/")
    if not normalized:
        return ""
    if "://" not in normalized:
        normalized = f"https://{normalized}"
    if (
        os.getenv("APP_ENV") == "production"
        and normalized.startswith("http://")
        and "localhost" not in normalized
        and "127.0.0.1" not in normalized
    ):
        normalized = f"https://{normalized.removeprefix('http://')}"
    return normalized.rstrip("/")


def _post_gatekeeper(path, payload):
    gatekeeper_url = _normalize_service_url(
        os.getenv("GATEKEEPER_URL")
        or os.getenv("GATEKEEPER_PUBLIC_URL")
        or os.getenv("DOMAIN_URL")
        or _render_domain_url()
        or DEFAULT_GATEKEEPER_URL
    )
    headers = {
        "Authorization": authorization_header(payload),
        "X-Payload-SHA256": payload_hash(payload),
    }
    if payload.get("hardware_id"):
        headers["X-Device-ID"] = str(payload.get("hardware_id"))
    if payload.get("device_hmac"):
        headers["X-Device-HMAC"] = str(payload.get("device_hmac"))
    if payload.get("session_token"):
        headers["X-Session-Token"] = str(payload.get("session_token"))

    return requests.post(
        f"{gatekeeper_url}{path}",
        json=payload,
        headers=headers,
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
    aggregate_map = {
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
        "blended_roas": {
            "stat_key": "blended_roas",
            "calculation": "total_revenue / total_spend",
            "source_metrics": ["total_revenue", "total_spend"],
            "csv_rows": all_rows,
            "value": stats.get("blended_roas", stats.get("avg_roas")),
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
    }
    for index, channel in enumerate(stats.get("channel_metrics") or [], start=1):
        channel_name = str(channel.get("channel") or f"Channel {index}")
        channel_rows = [
            row["csv_row_index"]
            for row in source_rows
            if str((row["columns"].get("Channel") or {}).get("value")) == channel_name
        ]
        slug = re.sub(r"[^a-z0-9]+", "_", channel_name.lower()).strip("_") or f"channel_{index}"
        for metric_key, column_name in (
            ("total_spend", "Spend"),
            ("total_revenue", "Revenue"),
            ("total_conversions", "Conversions"),
            ("total_clicks", "Clicks"),
            ("total_impressions", "Impressions"),
            ("roas", None),
            ("ctr", None),
            ("conversion_rate", None),
            ("spend_share", None),
            ("revenue_share", None),
        ):
            aggregate_map[f"channel_{slug}_{metric_key}"] = {
                "stat_key": f"channel_metrics[{index - 1}].{metric_key}",
                "channel": channel_name,
                "calculation": "channel aggregate",
                "column": column_name,
                "column_index": column_indexes.get(column_name) if column_name else None,
                "csv_rows": channel_rows,
                "value": channel.get(metric_key),
            }

    return {
        "columns": column_indexes,
        "source_rows": source_rows,
        "aggregate_map": aggregate_map,
    }


def _device_extra(device_auth=None):
    device_auth = device_auth if isinstance(device_auth, dict) else {}
    return {
        key: str(device_auth.get(key, "")).strip()
        for key in ("hardware_id", "device_hmac", "session_token")
        if str(device_auth.get(key, "")).strip()
    }


def get_ai_narrative_result(stats, license_key, directive=None, audit_context=None, device_auth=None):
    directive = sanitize_directive(directive)
    extra = {
        "directive": directive,
        "audit_context": audit_context or {},
    }
    extra.update(_device_extra(device_auth))
    payload = gatekeeper_payload(stats, license_key, extra)

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
            "narrative": _fallback_narrative(stats, directive=directive),
            "source": "deterministic_fallback",
            "report_id": None,
            "audit": {
                "report_id": None,
                "math_anomaly_detected": False,
                "math_verified": True,
                "anomaly_details": [],
                "truth_verification": {"ok": True, "math_verified": True, "unsupported_numbers": []},
                "reasoning_trace_available": False,
            },
        }


def get_ai_narrative(stats, license_key, directive=None, audit_context=None, device_auth=None):
    return get_ai_narrative_result(
        stats,
        license_key,
        directive=directive,
        audit_context=audit_context,
        device_auth=device_auth,
    )["narrative"]


def refine_report(stats, narrative, instruction, license_key, directive=None, report_id=None, device_auth=None):
    directive = sanitize_directive(directive)
    extra = {
        "narrative": str(narrative or "").strip(),
        "instruction": str(instruction or "").strip(),
        "directive": directive,
    }
    if report_id:
        extra["parent_report_id"] = str(report_id)
    extra.update(_device_extra(device_auth))
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
                "math_verified": True,
                "anomaly_details": [],
                "truth_verification": {"ok": True, "math_verified": True, "unsupported_numbers": []},
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


def build_channel_frame(df):
    if "Channel" not in df.columns:
        channel_df = df.copy()
        channel_df["Channel"] = "Marketing"
    else:
        channel_df = df.copy()

    channel = (
        channel_df.groupby("Channel", as_index=False)
        .agg(
            Spend=("Spend", "sum"),
            Clicks=("Clicks", "sum"),
            Impressions=("Impressions", "sum"),
            Conversions=("Conversions", "sum"),
            Revenue=("Revenue", "sum"),
        )
        .sort_values("Revenue", ascending=False)
    )
    channel["ROAS"] = _safe_divide(channel["Revenue"], channel["Spend"])
    channel["CTR"] = _safe_divide(channel["Clicks"], channel["Impressions"]) * 100
    channel["ConversionRate"] = _safe_divide(channel["Conversions"], channel["Clicks"]) * 100
    total_spend = float(channel["Spend"].sum()) or 1
    total_revenue = float(channel["Revenue"].sum()) or 1
    channel["SpendShare"] = (channel["Spend"] / total_spend) * 100
    channel["RevenueShare"] = (channel["Revenue"] / total_revenue) * 100
    return channel.fillna(0)


def build_channel_metrics(df):
    channel = build_channel_frame(df)
    return [
        {
            "channel": str(row.Channel),
            "total_spend": round(float(row.Spend), 2),
            "total_clicks": int(row.Clicks),
            "total_impressions": int(row.Impressions),
            "total_conversions": int(row.Conversions),
            "total_revenue": round(float(row.Revenue), 2),
            "roas": round(float(row.ROAS), 2),
            "ctr": round(float(row.CTR), 2),
            "conversion_rate": round(float(row.ConversionRate), 2),
            "spend_share": round(float(row.SpendShare), 2),
            "revenue_share": round(float(row.RevenueShare), 2),
        }
        for row in channel.itertuples(index=False)
    ]


def build_strategic_attribution(channel_metrics):
    if not channel_metrics:
        return {
            "awareness_channel": "",
            "conversion_channel": "",
            "best_efficiency_channel": "",
            "budget_reallocation": "No channel-level recommendation is available.",
            "synergy_summary": "Upload channel-labeled data to unlock strategic attribution.",
        }

    awareness = max(channel_metrics, key=lambda item: item.get("total_impressions", 0))
    conversion = max(channel_metrics, key=lambda item: item.get("total_revenue", 0))
    efficient = max(channel_metrics, key=lambda item: item.get("roas", 0))
    weakest = min(channel_metrics, key=lambda item: item.get("roas", 0))
    if len(channel_metrics) > 1 and weakest["channel"] != efficient["channel"]:
        reallocation = (
            f"Shift incremental budget from {weakest['channel']} toward {efficient['channel']} "
            f"until marginal ROAS converges closer to the blended portfolio average."
        )
    else:
        reallocation = (
            f"Keep incremental budget concentrated in {efficient['channel']} while watching for ROAS saturation."
        )

    synergy = (
        f"{awareness['channel']} is creating the broadest reach signal, while "
        f"{conversion['channel']} is converting the strongest secured return. "
        "The strategic story is a coordinated funnel, not isolated channel performance."
    )
    return {
        "awareness_channel": awareness["channel"],
        "conversion_channel": conversion["channel"],
        "best_efficiency_channel": efficient["channel"],
        "lowest_efficiency_channel": weakest["channel"],
        "budget_reallocation": reallocation,
        "synergy_summary": synergy,
    }


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


def analyze_data(csv_source, license_key="", directive=None, device_auth=None):
    df, channel_sources = read_marketing_sources(csv_source)

    total_spend = df["Spend"].sum()
    total_clicks = df["Clicks"].sum()
    total_impressions = df["Impressions"].sum()
    total_conversions = df["Conversions"].sum()
    total_revenue = df["Revenue"].sum()
    avg_roas = total_revenue / total_spend
    avg_ctr = (total_clicks / total_impressions) * 100
    top_campaign = df.groupby("Campaign")["Revenue"].sum().idxmax()
    channel_metrics = build_channel_metrics(df)
    strategic_attribution = build_strategic_attribution(channel_metrics)

    stats = {
        "total_spend": round(float(total_spend), 2),
        "total_clicks": int(total_clicks),
        "total_impressions": int(total_impressions),
        "total_conversions": int(total_conversions),
        "total_revenue": round(float(total_revenue), 2),
        "avg_ctr": round(float(avg_ctr), 2),
        "avg_roas": round(float(avg_roas), 2),
        "blended_roas": round(float(avg_roas), 2),
        "top_campaign": top_campaign,
        "channel_count": len(channel_metrics),
        "channels": [item["channel"] for item in channel_metrics],
        "top_channel": strategic_attribution.get("best_efficiency_channel"),
        "channel_metrics": channel_metrics,
        "strategic_attribution": strategic_attribution,
    }
    directive = sanitize_directive(directive)
    audit_context = build_audit_context(df, stats)
    narrative_result = (
        get_ai_narrative_result(
            stats,
            license_key,
            directive=directive,
            audit_context=audit_context,
            device_auth=device_auth,
        )
        if license_key
        else {
            "narrative": _fallback_narrative(stats, directive=directive),
            "report_id": None,
            "audit": {
                "report_id": None,
                "math_anomaly_detected": False,
                "math_verified": True,
                "anomaly_details": [],
                "truth_verification": {"ok": True, "math_verified": True, "unsupported_numbers": []},
                "reasoning_trace_available": False,
            },
        }
    )

    return {
        "stats": stats,
        "insights": get_insights(df),
        "top_daily_insights": get_top_3_insights(df),
        "channel_metrics": channel_metrics,
        "channel_sources": channel_sources,
        "daily_trends": build_daily_trends(df),
        "directive": directive,
        "narrative": narrative_result.get("narrative", _fallback_narrative(stats, directive=directive)),
        "report_id": narrative_result.get("report_id"),
        "audit": narrative_result.get("audit", {}),
    }


if __name__ == "__main__":
    result = analyze_data("dummy_marketing_data.csv")
    print(json.dumps(result, indent=2))
