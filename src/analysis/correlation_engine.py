# src/analysis/correlation_engine.py
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any

class CorrelationEngine:
    """
    A stateful engine that consumes 'Findings' and correlates them into 'Incidents'
    using an in-memory graph-like structure, as described in the architecture.
    
    NOTE: This is a simplified, in-memory implementation. A production system
    would use a dedicated graph database (e.g., Neo4j, Neptune) for scalability
    and persistence.
    """

    def __init__(self, incident_time_window_hours: int = 24):
        """
        Initializes the correlation engine.
        
        :param incident_time_window_hours: The time window to group related findings
                                           into a single incident.
        """
        self.incidents: List[Dict[str, Any]] = []
        self.incident_time_window = timedelta(hours=incident_time_window_hours)
        print("[CorrelationEngine] Initialized.")

    def _get_entities_from_finding(self, finding: Dict[str, Any]) -> List[str]:
        """Extracts key entities (host, user) from a finding for correlation."""
        event = finding.get('event_details', {})
        # Use the canonical 'user_name' field
        entities = []
        if event.get('hostname'):
            entities.append(f"host:{event['hostname']}")
        if event.get('user_name'):
            entities.append(f"user:{event['user_name']}")
        return list(set(entities))

    def process_finding(self, finding: Dict[str, Any]):
        """
        Processes a single finding, adding it to an existing incident or creating a new one.
        """
        finding_entities = self._get_entities_from_finding(finding)
        # Ensure timestamp is a datetime object
        finding_timestamp_str = finding['finding_timestamp']
        if isinstance(finding_timestamp_str, str):
            finding_timestamp = datetime.fromisoformat(finding_timestamp_str.replace('Z', '+00:00'))
        else:
            finding_timestamp = finding_timestamp_str # Assume it's already a datetime object

        best_match_incident = None
        for incident in self.incidents:
            # Check if incident shares any entities and is within the time window
            if any(entity in incident['entities'] for entity in finding_entities):
                time_diff = abs(finding_timestamp - incident['last_seen'])
                if time_diff <= self.incident_time_window:
                    best_match_incident = incident
                    break
        
        if best_match_incident:
            # Add to existing incident
            best_match_incident['findings'].append(finding)
            best_match_incident['entities'].update(finding_entities)
            best_match_incident['last_seen'] = max(best_match_incident['last_seen'], finding_timestamp)
            best_match_incident['tactics'].add(finding['mitre_attack']['tactic'])
            best_match_incident['risk_score'] = self._calculate_risk_score(best_match_incident)
        else:
            # Create a new incident
            new_incident = {
                'incident_id': f"INC-{len(self.incidents) + 1}",
                'first_seen': finding_timestamp,
                'last_seen': finding_timestamp,
                'findings': [finding],
                'entities': set(finding_entities),
                'tactics': {finding['mitre_attack']['tactic']},
                'risk_score': 0,
                'narrative': ""
            }
            new_incident['risk_score'] = self._calculate_risk_score(new_incident)
            self.incidents.append(new_incident)

    def _calculate_risk_score(self, incident: Dict[str, Any]) -> int:
        """Calculates a risk score for an incident."""
        score = 0
        severity_map = {'Low': 10, 'Medium': 40, 'High': 70, 'Critical': 100}
        
        for finding in incident['findings']:
            score += severity_map.get(finding['rule']['severity'], 0)
        
        if len(incident['tactics']) > 1:
            score += len(incident['tactics']) * 20
            
        return score

    def _generate_narrative(self, incident: Dict[str, Any]) -> str:
        """Generates a human-readable narrative for an incident."""
        sorted_findings = sorted(incident['findings'], key=lambda x: x['finding_timestamp'])
        
        start_time = incident['first_seen'].strftime('%Y-%m-%d %H:%M:%S UTC')
        entities_str = ", ".join(list(incident['entities']))
        
        narrative = f"Incident {incident['incident_id']} began at {start_time} involving entities: {entities_str}. "
        narrative += f"The attack involved {len(incident['tactics'])} distinct MITRE ATT&CK tactics. "
        
        first_finding = sorted_findings[0]
        narrative += (f"The initial activity detected was '{first_finding['rule']['name']}' "
                      f"({first_finding['mitre_attack']['technique_id']}). ")

        highest_sev_finding = max(sorted_findings, key=lambda x: self._calculate_risk_score({'findings': [x], 'tactics': {x['mitre_attack']['tactic']}}))
        if highest_sev_finding != first_finding:
            narrative += (f"The most critical action observed was '{highest_sev_finding['rule']['name']}' "
                          f"({highest_sev_finding['mitre_attack']['technique_id']}). ")

        narrative += f"The incident concluded at {incident['last_seen'].strftime('%H:%M:%S UTC')} after {len(sorted_findings)} suspicious findings."
        return narrative

    def finalize_incidents(self) -> List[Dict[str, Any]]:
        """Sorts incidents by risk and generates narratives and final data formats."""
        for incident in self.incidents:
            incident['narrative'] = self._generate_narrative(incident)
            incident['entities'] = list(incident['entities'])
            incident['tactics'] = list(incident['tactics'])
            
            # FIX: Explicitly format datetime objects to ISO 8601 strings with 'T' separator.
            # This ensures a consistent format for the frontend UI.
            incident['first_seen'] = incident['first_seen'].isoformat()
            incident['last_seen'] = incident['last_seen'].isoformat()
            
        return sorted(self.incidents, key=lambda x: x['risk_score'], reverse=True)
