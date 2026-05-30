import base64
import io
import json

import pandas as pd
import requests


REQUIRED_MARKETING_COLUMNS = {
    "Date",
    "Campaign",
    "Spend",
    "Clicks",
    "Impressions",
    "Conversions",
    "Revenue",
}


def read_marketing_csv(file_path):
    df = pd.read_csv(file_path)

    if REQUIRED_MARKETING_COLUMNS.issubset(df.columns):
        return df

    # Some uploaded project files were saved as base64 text. Fall back to
    # decoding that format so the existing sample CSV still works.
    with open(file_path, "r", encoding="utf-8") as file:
        decoded_csv = base64.b64decode(file.read()).decode("utf-8")

    decoded_df = pd.read_csv(io.StringIO(decoded_csv))
    if not REQUIRED_MARKETING_COLUMNS.issubset(decoded_df.columns):
        missing_columns = REQUIRED_MARKETING_COLUMNS.difference(decoded_df.columns)
        raise ValueError(f"CSV is missing required columns: {sorted(missing_columns)}")

    return decoded_df


def get_ai_narrative(stats):
    url = "https://integrations.emergentagent.com/llm/v1/chat/completions"
    headers = {
        "Authorization": "Bearer sk-emergent-7Ab0d141b1bF2E1Cc9",
        "Content-Type": "application/json",
    }

    prompt = f"""
    You are a Senior Marketing Account Manager. Write a 3-paragraph professional executive summary for a client report based on these stats:
    {json.dumps(stats, indent=2)}

    Paragraph 1: Overall performance overview (Revenue vs Spend).
    Paragraph 2: Specific campaign performance (The winner).
    Paragraph 3: Recommendations for next month.

    Keep the tone professional, confident, and data-driven.
    """

    data = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
    }

    try:
        response = requests.post(url, headers=headers, json=data)
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error generating narrative: {str(e)}"


def get_top_3_insights(file_path):
    df = read_marketing_csv(file_path)

    daily = (
        df.groupby("Date", as_index=False)
        .agg(
            {
                "Spend": "sum",
                "Clicks": "sum",
                "Impressions": "sum",
                "Conversions": "sum",
                "Revenue": "sum",
            }
        )
        .sort_values("Date")
    )

    spend = daily["Spend"].where(daily["Spend"] != 0)
    clicks = daily["Clicks"].where(daily["Clicks"] != 0)
    impressions = daily["Impressions"].where(daily["Impressions"] != 0)

    daily["roi"] = (((daily["Revenue"] - daily["Spend"]) / spend) * 100).fillna(0)
    daily["roas"] = (daily["Revenue"] / spend).fillna(0)
    daily["ctr"] = ((daily["Clicks"] / impressions) * 100).fillna(0)
    daily["conversion_rate"] = ((daily["Conversions"] / clicks) * 100).fillna(0)

    insight_metrics = [
        {
            "key": "highest_roi",
            "column": "roi",
            "label": "ROI",
            "formatter": lambda value: f"{value:.2f}%",
        },
        {
            "key": "highest_revenue",
            "column": "Revenue",
            "label": "revenue",
            "formatter": lambda value: f"${value:,.2f}",
        },
        {
            "key": "highest_conversions",
            "column": "Conversions",
            "label": "conversions",
            "formatter": lambda value: f"{int(value):,}",
        },
        {
            "key": "highest_ctr",
            "column": "ctr",
            "label": "CTR",
            "formatter": lambda value: f"{value:.2f}%",
        },
        {
            "key": "highest_conversion_rate",
            "column": "conversion_rate",
            "label": "conversion rate",
            "formatter": lambda value: f"{value:.2f}%",
        },
    ]

    insights = []
    for metric in insight_metrics:
        column = metric["column"]
        row = daily.loc[daily[column].idxmax()]
        value = float(row[column])
        average = float(daily[column].mean())
        lift_pct = ((value - average) / abs(average) * 100) if average else 0

        insights.append(
            {
                "type": metric["key"],
                "date": str(row["Date"]),
                "metric": metric["label"],
                "value": metric["formatter"](value),
                "daily_average": metric["formatter"](average),
                "lift_vs_average": f"{lift_pct:.2f}%",
                "significance_score": round(float(lift_pct), 2),
                "summary": (
                    f"{row['Date']} had the highest {metric['label']} at "
                    f"{metric['formatter'](value)}, {lift_pct:.2f}% above the "
                    "daily average."
                ),
            }
        )

    return sorted(insights, key=lambda item: item["significance_score"], reverse=True)[:3]


def analyze_data(file_path):
    df = read_marketing_csv(file_path)

    total_spend = df["Spend"].sum()
    total_clicks = df["Clicks"].sum()
    total_conversions = df["Conversions"].sum()
    total_revenue = df["Revenue"].sum()
    avg_ctr = (total_clicks / df["Impressions"].sum()) * 100
    avg_roas = total_revenue / total_spend
    campaign_performance = df.groupby("Campaign")["Revenue"].sum().idxmax()

    stats = {
        "total_spend": round(float(total_spend), 2),
        "total_clicks": int(total_clicks),
        "total_conversions": int(total_conversions),
        "total_revenue": round(float(total_revenue), 2),
        "avg_ctr": f"{round(float(avg_ctr), 2)}%",
        "avg_roas": round(float(avg_roas), 2),
        "top_campaign": campaign_performance,
    }

    narrative = get_ai_narrative(stats)

    return {
        "stats": stats,
        "top_insights": get_top_3_insights(file_path),
        "narrative": narrative,
    }


if __name__ == "__main__":
    result = analyze_data("dummy_marketing_data.csv")
    print(json.dumps(result, indent=2))
