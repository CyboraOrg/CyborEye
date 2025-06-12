import json
from datetime import datetime, timedelta
from collections import defaultdict
from pydantic import BaseModel
from typing import List

# === مدل‌ها ===
class RawEvent(BaseModel):
    id: str
    timestamp: datetime
    event_source: str
    event_type: str
    hostname: str = None
    user: str = None

class Alarm(BaseModel):
    alert_id: str
    pattern: str
    related_event_ids: List[str]
    first_seen: datetime
    last_seen: datetime
    score: int

# === کمک‌کننده‌های امتیازدهی ===
WEIGHTS = {
    "email_received": 5,
    "process_creation": 10,
    "registry_key_created": 15,
    "connection_attempt": 20,
    "data_exfil": 25,
}

def calculate_score(event_types: List[str]) -> int:
    base = sum(WEIGHTS.get(evt, 0) for evt in set(event_types))
    return min(base, 100)

def contextual_score(base: int, duration_min: float, rep: str, user: str) -> int:
    score = base
    if duration_min < 5:
        score *= 1.2
    if rep == "malicious":
        score *= 1.5
    if user and user.lower() in ("admin", "serviceuser", "ceo"):
        score += 10
    return min(int(score), 100)

# === سرویس همبستگی ===
class CorrelationService:
    def __init__(self, window_minutes: int = 15):
        self.time_window = timedelta(minutes=window_minutes)
        self.events: List[RawEvent] = []

    def ingest(self, raw: dict):
        # فیلتر نویز: نادیده گرفتن رویدادهای خوش‌خیم (مانند لاگین‌ها)
        if raw.get('event_type') == '4624':
            return
        e = RawEvent.model_validate(raw)
        self.events.append(e)

    def _compute_alert_score(self, events: List[RawEvent]) -> int:
        ev_types = [e.event_type for e in events]
        base = calculate_score(ev_types)
        dur = (events[-1].timestamp - events[0].timestamp).total_seconds() / 60
        dst_ips = [getattr(e, 'dst_ip', None) for e in events if hasattr(e, 'dst_ip')]
        rep = 'malicious' if '198.51.100.25' in dst_ips else 'unknown'
        user = next((e.user for e in events if e.user), '')
        return contextual_score(base, dur, rep, user)

    def correlate(self) -> List[Alarm]:
        by_host = defaultdict(list)
        for e in self.events:
            host = e.hostname or 'UNKNOWN'
            by_host[host].append(e)

        alerts = []
        for host, evts in by_host.items():
            evts.sort(key=lambda x: x.timestamp)
            for i in range(len(evts)):
                start = evts[i].timestamp
                window = [e for e in evts if start <= e.timestamp <= start + self.time_window]
                types = [e.event_type for e in window]
                ids = [e.id for e in window]
                
                # الگو 1: Phishing-Execution-Persistence
                if all(p in types for p in ['email_received', 'process_creation', 'registry_key_created']):
                    score = self._compute_alert_score(window)
                    alerts.append(Alarm(
                        alert_id=f"ALRT-{host}-{start.strftime('%H%M')}-PEP",
                        pattern="Phishing-Execution-Persistence",
                        related_event_ids=ids,
                        first_seen=start,
                        last_seen=window[-1].timestamp,
                        score=score
                    ))
                    continue
                
                # الگو 2: ارتباط C2
                if any(t in ['connection_attempt', 'dns_query'] for t in types):
                    dst_ips = [getattr(e, 'dst_ip', None) for e in window if hasattr(e, 'dst_ip')]
                    if '198.51.100.25' in dst_ips:
                        score = self._compute_alert_score(window)
                        alerts.append(Alarm(
                            alert_id=f"ALRT-{host}-{start.strftime('%H%M')}-C2",
                            pattern="C2-Communication",
                            related_event_ids=ids,
                            first_seen=start,
                            last_seen=window[-1].timestamp,
                            score=score
                        ))
                
                # الگو 3: حرکت جانبی
                if any(t == 'process_creation' for t in types):
                    users = [e.user for e in window if e.user and e.event_type == 'process_creation']
                    commands = [getattr(e, 'command_line', '') for e in window if e.event_type == 'process_creation']
                    if any(u in ['admin', 'serviceuser', 'ceo'] for u in users) and any(c in ['wmic', 'powershell'] for c in commands):
                        score = self._compute_alert_score(window)
                        alerts.append(Alarm(
                            alert_id=f"ALRT-{host}-{start.strftime('%H%M')}-LM",
                            pattern="Lateral-Movement",
                            related_event_ids=ids,
                            first_seen=start,
                            last_seen=window[-1].timestamp,
                            score=score
                        ))
                
                # الگو 4: استخراج داده
                if 'data_exfil' in types:
                    score = self._compute_alert_score(window)
                    alerts.append(Alarm(
                        alert_id=f"ALRT-{host}-{start.strftime('%H%M')}-EXF",
                        pattern="Data-Exfiltration",
                        related_event_ids=ids,
                        first_seen=start,
                        last_seen=window[-1].timestamp,
                        score=score
                    ))
        return alerts

# === اجرای نمونه ===
if __name__ == '__main__':
    try:
        with open('feature1/scenario_noisy.json') as f:
            data = json.load(f)
        
        cs = CorrelationService(window_minutes=10)
        for r in data:
            cs.ingest(r)
        
        # دیباگ: چاپ رویدادها بر اساس hostname
        by_host = defaultdict(list)
        for e in cs.events:
            host = e.hostname or 'UNKNOWN'
            by_host[host].append(e)
        for host, evts in by_host.items():
            print(f"Host: {host}, Events: {[e.dict() for e in evts]}")
        
        alerts = cs.correlate()
        print(json.dumps([a.dict() for a in alerts], default=str, indent=2))
    except FileNotFoundError:
        print("not found")