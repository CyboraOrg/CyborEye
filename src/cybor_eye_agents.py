import autogen
import json
from src.consts import llm_config
from src.tools.tier1_tools import scan_file_with_yara, calculate_file_hash_and_entropy, query_virustotal_by_hash
from src.tools.tier3_tools import parse_pe_file, disassemble_pe_file
# Import the actual correlation function, not the whole file
from src.tools.log_analyzer_tools import ingest_and_correlate_logs

# --- Manually Defined Tool Schemas ---

# Schemas for T1 and T3 Analysts remain the same
tier1_tools_schema = [
    {"type": "function", "function": {"name": "scan_file_with_yara", "description": "Scans a file with YARA rules to detect malicious patterns.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "calculate_file_hash_and_entropy", "description": "Calculates the SHA256 hash and entropy of a file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "query_virustotal_by_hash", "description": "Queries VirusTotal for a report on a file's SHA256 hash.", "parameters": {"type": "object", "properties": {"file_hash": {"type": "string"}}, "required": ["file_hash"]}}}
]
tier3_tools_schema = [
    {"type": "function", "function": {"name": "parse_pe_file", "description": "Parses a Portable Executable (PE) file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "disassemble_pe_file", "description": "Disassembles the entry point of a PE file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}}
]
# Manager schema is now simpler for log analysis
manager_tools_schema = [
    {"type": "function", "function": {"name": "run_tier1_analysis", "description": "Runs a Tier 1 analysis for quick triage.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}, "user_request": {"type": "string"}}, "required": ["filepath", "user_request"]}}},
    {"type": "function", "function": {"name": "run_tier3_analysis", "description": "Runs a Tier 3 analysis for deep static analysis.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}, "user_request": {"type": "string"}}, "required": ["filepath", "user_request"]}}},
    # The log analysis tool is now simpler
    {"type": "function", "function": {"name": "run_log_analysis", "description": "Reads a JSON log file, correlates events, and returns found alerts.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}}
]

# --- Specialist Agent Definitions ---

tier1_analyst = autogen.AssistantAgent(
    name="Tier1_Analyst",
    llm_config={**llm_config, "tools": tier1_tools_schema},
    system_message="""
    You are a Tier 1 Analyst. You perform file analysis by strictly following a plan.

    # INSTRUCTIONS
    - If the user asks for a specific scan (e.g., 'yara only'), call only that tool.
    - If the user asks for a 'full tier 1 triage' or 'quick scan', you MUST follow the Standard Triage Workflow below, step-by-step.
    - You must call the tools sequentially. Do not proceed to the next step until the previous one is complete.
    - After all steps are complete, combine all results into a single, final markdown report and end your message with the keyword TERMINATE.

    # Standard Triage Workflow
    1.  **Call `calculate_file_hash_and_entropy`** on the file.
    2.  **Wait for the result.** You will receive the SHA256 hash.
    3.  **Call `query_virustotal_by_hash`** using the hash from the previous step.
    4.  **Wait for the result.**
    5.  **Call `scan_file_with_yara`** on the original file path.
    6.  **Wait for the result.**
    7.  **Create a final summary report** including the results from all three tools.
    """
)

tier3_analyst = autogen.AssistantAgent(
    name="Tier3_Analyst", llm_config={**llm_config, "tools": tier3_tools_schema},
    system_message="You are a Tier 3 Analyst. Use your disassembler and PE parsing tools to perform deep static analysis, create a detailed technical report, and then end your message with the keyword TERMINATE."
)

# --- "Agent-as-a-Tool" Function Wrappers ---

def run_tier1_analysis(filepath: str, user_request: str) -> str:
    # This function's inner workings remain the same
    print(f"\n--- Manager delegating to Tier 1 Analyst ---")
    executor = autogen.UserProxyAgent("T1_Executor", human_input_mode="NEVER", is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"), code_execution_config={"work_dir": "agent_output"}, function_map={"scan_file_with_yara": scan_file_with_yara, "calculate_file_hash_and_entropy": calculate_file_hash_and_entropy, "query_virustotal_by_hash": query_virustotal_by_hash})
    chat_result = executor.initiate_chat(recipient=tier1_analyst, message=f"Analyze the file at `{filepath}`. The user's specific request is: '{user_request}'", max_turns=7, summary_method="last_msg")
    return chat_result.chat_history[-1]["content"]

def run_tier3_analysis(filepath: str, user_request: str) -> str:
    # This function's inner workings remain the same
    print(f"\n--- Manager delegating to Tier 3 Analyst ---")
    executor = autogen.UserProxyAgent("T3_Executor", human_input_mode="NEVER", is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"), code_execution_config={"work_dir": "agent_output"}, function_map={"parse_pe_file": parse_pe_file, "disassemble_pe_file": disassemble_pe_file})
    chat_result = executor.initiate_chat(recipient=tier3_analyst, message=f"Analyze the file at `{filepath}`. The user's specific request is: '{user_request}'", max_turns=5, summary_method="last_msg")
    return chat_result.chat_history[-1]["content"]

# **KEY CHANGE**: The Log Analyst agent is removed. This function now does all the work.
def run_log_analysis(filepath: str) -> str:
    """
    Reads a log file, calls the correlation engine, and returns a formatted string of the results.
    This function no longer uses an agent, making it faster and more reliable.
    """
    print(f"\n--- SOC Manager executing log analysis tool for: {filepath} ---")
    try:
        with open(filepath, 'r') as f:
            events_data = json.load(f)
    except Exception as e:
        return f"Error: Could not read or parse the log file '{filepath}'. Reason: {e}"

    # Call the correlation tool directly with the file data
    alerts = ingest_and_correlate_logs(events_data)

    if not alerts:
        return "Log analysis complete. No high-confidence alerts were found."

    # Format the results into a clean string
    report = "Log analysis complete. The following high-confidence alerts were generated:\n\n"
    for alert in alerts:
        report += f"- **Alert ID:** {alert.get('alert_id')}\n"
        report += f"  - **Pattern:** {alert.get('pattern')}\n"
        report += f"  - **Score:** {alert.get('score')}\n"
        report += f"  - **Summary:** {alert.get('summary')}\n\n"
    return report

# --- SOC Manager Agent Definition ---

soc_manager = autogen.AssistantAgent(
    name="SOC_Manager",
    llm_config={**llm_config, "tools": manager_tools_schema},
    # **KEY CHANGE**: The prompt is hardened to be less conversational and more direct.
    system_message="""You are the SOC Manager, a dispatch agent.
    1.  Analyze the user's request to determine the correct tool: `run_tier1_analysis`, `run_tier3_analysis`, or `run_log_analysis`.
    2.  You MUST call the selected tool with the correct arguments.
    3.  After the tool returns a report, your ONLY job is to present that exact report to the user.
    4.  Your final response MUST be ONLY the report, followed by the keyword `TERMINATE`. Do not add any extra conversational text like "Here is the report" or "Let me know if you need anything else".
    """
)

# --- Main Entry Point ---

user_proxy = autogen.UserProxyAgent(
    name="User_Proxy", human_input_mode="NEVER",
    is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"),
    code_execution_config={"work_dir": "agent_output"},
    function_map={
        "run_tier1_analysis": run_tier1_analysis,
        "run_tier3_analysis": run_tier3_analysis,
        "run_log_analysis": run_log_analysis,
    }
)

def run_analysis_conversation(filepath: str, user_request: str) -> str:
    """This function kicks off the main conversation with the SOC_Manager."""
    user_proxy.reset()
    soc_manager.reset()
    chat_result = user_proxy.initiate_chat(
        recipient=soc_manager,
        message=f"Please handle this user request for the file at `{filepath}`. The request is: '{user_request}'",
    )
    # The summary is the most reliable way to get the final, clean output
    summary = chat_result.chat_history[-1]["content"] if chat_result.chat_history[-1]["content"] else "Analysis concluded without a final summary."
    return summary.replace("TERMINATE", "").strip()