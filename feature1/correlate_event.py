from typing import List, Dict
from .CorrelationService import CorrelationService

def correlate_events(events: List[Dict]) -> List[Dict]:
    """
    همبستگی رویدادها و بازگشت هشدارها برای پردازش LLM.
    ورودی:
        events: لیست دیکشنری‌های رویداد.
    خروجی:
        لیست دیکشنری‌های هشدار با پتانسیل نگاشت MITRE.
    """
    cs = CorrelationService(window_minutes=10)
    for event in events:
        cs.ingest(event)
    alarms = cs.correlate()
    return [alarm.dict() for alarm in alarms]