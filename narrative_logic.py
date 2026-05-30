import pandas as pd
import json
import requests
import os
from dotenv import load_dotenv

load_dotenv()

def get_ai_narrative(stats):
    key = os.getenv('EMERGENT_LLM_KEY')
    url = "https://integrations.emergentagent.com/llm/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    
    prompt = f"You are a Senior Marketing Account Manager. Write a 3-paragraph professional executive summary based on these stats: {json.dumps(stats)}"
    data = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]}
    
    try:
        response = requests.post(url, headers=headers, json=data)
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        return f"Analysis complete. Error in AI generation: {str(e)}"

def analyze_data(file_path):
    df = pd.read_csv(file_path)
    total_spend = df['Spend'].sum()
    total_revenue = df['Revenue'].sum()
    avg_roas = total_revenue / total_spend
    
    stats = {
        "total_spend": round(float(total_spend), 2),
        "total_revenue": round(float(total_revenue), 2),
        "avg_roas": round(float(avg_roas), 2)
    }
    return {"stats": stats, "narrative": get_ai_narrative(stats)}