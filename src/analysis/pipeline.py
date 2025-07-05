# src/analysis/pipeline.py
import json
from typing import List, Dict, Any
from src.analysis.triage_engine import SmartTriageEngine
from src.analysis.correlation_engine import CorrelationEngine
# Import the new normalization service
from src.analysis.normalization import CanonicalDataModelMapper

class AnalysisPipeline:
    """
    Orchestrates the end-to-end log analysis process, from raw logs to
    correlated incidents.
    """
    def __init__(self):
        """Initializes all the necessary engine components."""
        print("[Pipeline] Initializing analysis pipeline...")
        # Add the normalizer to the pipeline
        self.normalizer = CanonicalDataModelMapper()
        self.triage_engine = SmartTriageEngine()
        self.correlation_engine = CorrelationEngine()
        print("[Pipeline] Initialization complete.")

    def run(self, raw_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes the full analysis pipeline on a set of raw log events.
        
        :param raw_events: A list of dictionaries, each a raw log event.
        :return: A dictionary containing the final list of correlated incidents.
        """
        print(f"[Pipeline] Starting analysis of {len(raw_events)} events.")
        
        # STAGE 1 & 2: Ingestion & Normalization
        print("[Pipeline] Executing Normalization Engine...")
        normalized_events = [self.normalizer.normalize(event) for event in raw_events]
        print(f"[Pipeline] Normalization complete.")
        
        # STAGE 3: Smart Triage - Generate Findings
        all_findings = []
        print("[Pipeline] Executing Smart Triage Engine...")
        for event in normalized_events: # Use the normalized events now
            findings = self.triage_engine.process_event(event)
            if findings:
                all_findings.extend(findings)
        print(f"[Pipeline] Triage complete. Generated {len(all_findings)} findings.")

        # If no findings, we can stop early.
        if not all_findings:
            print("[Pipeline] No findings were generated. Halting analysis.")
            return {
                "summary": f"Analysis complete. Found 0 potential incidents from {len(raw_events)} events.",
                "incidents": []
            }

        # STAGE 4: Scalable Analysis - Correlate Findings into Incidents
        print("[Pipeline] Executing Correlation Engine...")
        for finding in all_findings:
            self.correlation_engine.process_finding(finding)
        
        correlated_incidents = self.correlation_engine.finalize_incidents()
        print(f"[Pipeline] Correlation complete. Identified {len(correlated_incidents)} incidents.")
        
        # STAGE 5: Actioning & Exposition
        return {
            "summary": f"Analysis complete. Found {len(correlated_incidents)} potential incidents from {len(raw_events)} events.",
            "incidents": correlated_incidents
        }

def run_full_analysis(log_filepath: str) -> Dict[str, Any]:
    """
    A convenience function to load a log file and run the pipeline.
    This will be the main entry point for the agent tool.
    """
    try:
        with open(log_filepath, 'r') as f:
            # FIX: Load the entire scenario object first.
            scenario_data = json.load(f)
            # Then, extract ONLY the 'events' list to pass to the pipeline.
            # This ensures the engine is blind to the scenario's name and description.
            raw_events = scenario_data.get("events", [])
            
            if not raw_events:
                return {"error": "The log file does not contain an 'events' list or is empty."}
        
        pipeline = AnalysisPipeline()
        results = pipeline.run(raw_events)
        return results
    except FileNotFoundError:
        return {"error": f"Log file not found at {log_filepath}"}
    except json.JSONDecodeError:
        return {"error": f"Invalid JSON in log file: {log_filepath}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}
