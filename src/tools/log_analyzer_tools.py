import json
from datetime import datetime, timedelta
from collections import defaultdict
from pydantic import BaseModel, Field, Extra
from typing import List, Dict, Any, Optional

# --- Pydantic Models for Structured Data ---
# Using Extra.allow to handle various event fields without errors
class RawEvent(BaseModel, extra=Extra.allow):
    id: str
    timestamp: datetime
    event_source: str
    event_type: str
    hostname: Optional[str] = None
    user: Optional[str] = Field(None, alias='account_name')

class Alarm(BaseModel):
    alert_id: str
    pattern: str
    related_event_ids: List[str]
    first_seen: datetime
    last_seen: datetime
    score: int
    summary: str

# --- Scoring Logic ---
WEIGHTS = {
    "email_received": 5, "process_creation": 10, "registry_key_created": 20,
    "connection_attempt": 15, "data_exfil": 30, "dns_query": 10
}

def _calculate_score(events: List[RawEvent]) -> int:
    """Calculates a score for a cluster of events based on type, speed, and context."""
    event_types = [e.event_type for e in events]
    # 1. Base score from unique event types
    base_score = sum(WEIGHTS.get(evt, 0) for evt in set(event_types))

    # 2. Contextual Modifiers
    duration_minutes = (events[-1].timestamp - events[0].timestamp).total_seconds() / 60
    if duration_minutes < 5:  # Fast attack chain
        base_score *= 1.2

    dst_ips = [getattr(e, 'dst_ip', None) for e in events if hasattr(e, 'dst_ip')]
    if '198.51.100.25' in dst_ips:  # Known bad IP from scenario
        base_score *= 1.5

    users = [e.user for e in events if e.user]
    if any(u and u.lower() in ("admin", "serviceuser") for u in users): # High-privilege user
        base_score += 15

    return min(int(base_score), 100)

# --- Correlation Service ---
class CorrelationService:
    def __init__(self, raw_events: List[Dict[str, Any]], window_minutes: int = 15):
        self.time_window = timedelta(minutes=window_minutes)
        self.events: List[RawEvent] = [RawEvent.model_validate(e) for e in raw_events]

    def correlate_events(self) -> List[Alarm]:
        """Groups events by hostname and time to find malicious patterns."""
        by_host = defaultdict(list)
        for e in self.events:
            # Group events by hostname, or a generic bucket if none exists
            key = e.hostname or f"ip-{getattr(e, 'src_ip', 'unknown')}"
            by_host[key].append(e)

        alerts = []
        # Pattern 1: Phishing -> Execution -> Persistence on a single host
        for host, host_events in by_host.items():
            host_events.sort(key=lambda x: x.timestamp)
            for i in range(len(host_events)):
                window_start_time = host_events[i].timestamp
                # Find all events within the time window on that host
                window_events = [e for e in host_events if window_start_time <= e.timestamp <= window_start_time + self.time_window]
                event_types_in_window = {e.event_type for e in window_events}

                # Check if the pattern exists in the window
                if all(p in event_types_in_window for p in ['email_received', 'process_creation', 'registry_key_created']):
                    score = _calculate_score(window_events)
                    if score > 40: # Only create high-confidence alerts
                        alerts.append(Alarm(
                            alert_id=f"ALERT-{host}-{window_start_time.strftime('%H%M%S')}",
                            pattern="Phishing > Execution > Persistence",
                            related_event_ids=[e.id for e in window_events],
                            first_seen=window_events[0].timestamp,
                            last_seen=window_events[-1].timestamp,
                            score=score,
                            summary=f"A high-confidence alert on host '{host}'. A suspicious email led to process creation and then registry modification for persistence."
                        ))
                        break # Move to next host after finding the first pattern match
        return alerts

# --- The Agent-Callable Tool ---
def ingest_and_correlate_logs(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Ingests a list of raw log events, correlates them to find malicious patterns,
    and returns a list of generated alerts.

    :param raw_events: A list of dictionaries, where each dictionary is a raw log event.
    :return: A list of dictionaries, where each dictionary is a generated alert.
    """
    print(f"[Log Tool] Ingesting {len(raw_events)} events for correlation...")
    service = CorrelationService(raw_events)
    alarms = service.correlate_events()
    print(f"[Log Tool] Correlation complete. Found {len(alarms)} new alerts.")
    # Return alarms as dictionaries for the agent
    return [json.loads(a.model_dump_json()) for a in alarms]