import os
from dotenv import load_dotenv

load_dotenv()

config_list ={
        "model": os.getenv('MODEL_TO_USE'),
        "api_key": os.getenv('OPENAI_API_KEY'),
        "base_url": os.getenv('BASE_AI_API_URL'),
    }

if not config_list["api_key"] or config_list["api_key"] == "sk-YourActualOpenAIKeyGoesHere": # Generic placeholder check
    print("ERROR: OpenAI API key placeholder not replaced with your api key")
    raise ValueError("OpenAI API key placeholder not replaced.")

llm_config = {
    "config_list": [config_list],
    "timeout": 300,
    "temperature": 1
}

REPORT_TEMPLATE = '''
## 🔍 Report: {agent_name}

### 💠 Assumption: {analysis_assumption}

### 🟡 Summary
{summary}

### 🔑 Key Indicators
{key_indicators}

### 🧪 Confidence Level
{confidence}

### 📌 Recommendations
{recommendations}
'''