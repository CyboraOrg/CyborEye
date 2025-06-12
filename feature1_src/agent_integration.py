import json
import os
from autogen import ConversableAgent, AssistantAgent
from typing import List, Dict
from correlate_events import correlate_events

# === تنظیمات LLM ===
# لطفاً کلید API معتبر OpenAI را وارد کنید
llm_config = {
    "model": "gpt-4o-mini",
    "api_key": "", 
    "api_type": "openai",
}

# === تابع خواندن رویدادها ===
def load_events(file_path: str) -> List[Dict]:
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"خطا: فایل {file_path} پیدا نشد.")
        return []

# === Agent تحلیل‌گر هشدار ===
alert_analyzer = AssistantAgent(
    name="AlertAnalyzer",
    system_message="""شما یک تحلیل‌گر امنیت سایبری هستید. وظیفه شما دریافت هشدارهای تولیدشده توسط CorrelationService، تحلیل آن‌ها، نگاشت به تکنیک‌های MITRE ATT&CK (در صورت امکان)، و ارائه توضیحات متنی واضح است. برای هر هشدار:
1. الگو (pattern) و امتیاز (score) را بررسی کنید.
2. رویدادهای مرتبط (related_event_ids) را تحلیل کنید.
3. تکنیک‌های MITRE ATT&CK مربوطه را پیشنهاد دهید (مثلاً T1566 برای فیشینگ).
4. یک روایت مختصر برای توضیح حادثه ارائه دهید.
خروجی را به فارسی و با فرمت JSON ارائه دهید.""",
    llm_config=llm_config,
)

# === Agent هماهنگ‌کننده ===
coordinator = ConversableAgent(
    name="Coordinator",
    system_message="""شما یک هماهنگ‌کننده هستید که رویدادها را از فایل JSON می‌خواند، آن‌ها را به تابع correlate_events ارسال می‌کند، و هشدارهای تولیدشده را به AlertAnalyzer برای تحلیل می‌فرستد.""",
    llm_config=llm_config,
)

# === منطق اصلی ===
def run_pipeline():
    # خواندن رویدادها
    file_path = "feature1/scenario_noisy.json"
    events = load_events(file_path)
    if not events:
        return {"error": "هیچ رویدادی بارگذاری نشد."}

    # تولید هشدارها
    alerts = correlate_events(events)
    if not alerts:
        return {"error": "هیچ هشداری تولید نشد."}

    # ارسال هشدارها به AlertAnalyzer
    alert_message = json.dumps(alerts, indent=2, ensure_ascii=False)
    try:
        response = alert_analyzer.generate_reply(
            messages=[{"content": f"لطفاً این هشدارها را تحلیل کنید:\n{alert_message}", "role": "user"}]
        )
        return json.loads(response)
    except json.JSONDecodeError:
        return {"error": "خطا در پردازش پاسخ LLM. پاسخ دریافتی: " + response}

# === اجرای نمونه ===
if __name__ == "__main__":
    try:
        result = run_pipeline()
        print(json.dumps(result, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"خطا در اجرای خط لوله: {str(e)}")