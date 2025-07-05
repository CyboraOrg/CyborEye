# src/tools/log_analyzer_tools.py
import json
from typing import Dict, Any

# Import the new pipeline entry point
from src.analysis.pipeline import run_full_analysis

def analyze_log_file(filepath: str) -> str:
    """
    Agent-callable tool that runs the full CyborEye analysis pipeline on a log file.
    
    This function replaces the previous `ingest_and_correlate_logs`. It acts as a
    simple wrapper around the more sophisticated analysis pipeline.

    :param filepath: The path to the JSON log file.
    :return: A JSON string representing the structured analysis report.
    """
    print(f"[Log Tool] Received request to analyze log file: {filepath}")
    
    # Run the full analysis pipeline
    analysis_result = run_full_analysis(filepath)
    
    # The pipeline returns a dictionary. We serialize it to a JSON string
    # for the agent framework. Using default=str to handle datetime objects.
    return json.dumps(analysis_result, indent=2, default=str)

