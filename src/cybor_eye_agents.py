# src/cybor_eye_agents.py
import autogen
import json
from typing import Optional
from src.consts import llm_config
# Import all tier1 tools, including the new rule management functions
from src.tools.tier1_tools import scan_file_with_yara, calculate_file_hash_and_entropy, query_virustotal_by_hash, get_yara_rules, update_yara_rule_status
from src.tools.tier3_tools import parse_pe_file, disassemble_pe_file
from src.tools.log_analyzer_tools import analyze_log_file

# ======================================================================================
# 1. TOOL SCHEMAS: Defining the capabilities of each agent
# ======================================================================================

# Tier 1 Analyst Tool Schema: Defines the basic triage tools for file analysis.
# UPDATED: The schema for scan_file_with_yara now includes the optional 'rule_name' parameter.
tier1_tools_schema = [
    {"type": "function", "function": {
        "name": "scan_file_with_yara", 
        "description": "Scans a file with YARA rules. Can scan with a specific rule or all enabled rules.", 
        "parameters": {
            "type": "object", 
            "properties": {
                "filepath": {"type": "string"},
                "rule_name": {"type": "string", "description": "Optional. The specific rule (namespace) to scan with. If omitted, all enabled rules are used."}
            }, 
            "required": ["filepath"]
        }
    }},
    {"type": "function", "function": {"name": "calculate_file_hash_and_entropy", "description": "Calculates the SHA256 hash and entropy of a file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "query_virustotal_by_hash", "description": "Queries VirusTotal for a report on a file's SHA256 hash.", "parameters": {"type": "object", "properties": {"file_hash": {"type": "string"}}, "required": ["file_hash"]}}}
]

# Tier 3 Analyst Tool Schema: Defines advanced tools for deep static analysis.
tier3_tools_schema = [
    {"type": "function", "function": {"name": "parse_pe_file", "description": "Parses a Portable Executable (PE) file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "disassemble_pe_file", "description": "Disassembles the entry point of a PE file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}}
]

# SOC Manager Tool Schema: Defines the high-level tasks the manager can delegate or perform.
manager_tools_schema = [    
    {"type": "function", "function": {"name": "run_tier1_analysis", "description": "Runs a Tier 1 analysis for quick triage of a file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}, "user_request": {"type": "string"}}, "required": ["filepath", "user_request"]}}},
    {"type": "function", "function": {"name": "run_tier3_analysis", "description": "Runs a Tier 3 analysis for deep static analysis of a file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}, "user_request": {"type": "string"}}, "required": ["filepath", "user_request"]}}},
    {"type": "function", "function": {"name": "analyze_log_file", "description": "Runs the deterministic log analysis pipeline on a JSON log file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "get_yara_rules", "description": "Retrieves a list of all available YARA rules and their current status.", "parameters": {}}},
    {"type": "function", "function": {"name": "update_yara_rule_status", "description": "Enables or disables a specific YARA rule.", "parameters": {"type": "object", "properties": {"rule_name": {"type": "string"}, "enabled": {"type": "boolean"}}, "required": ["rule_name", "enabled"]}}},
]

# ======================================================================================
# 2. SPECIALIST AGENT DEFINITIONS
# ======================================================================================

# Tier 1 Analyst: The first line of automated defense, focused on initial triage.
# UPDATED: The system prompt now instructs the agent on how to use the new targeted scan feature.
tier1_analyst = autogen.AssistantAgent(
    name="Tier1_Analyst",
    llm_config={**llm_config, "tools": tier1_tools_schema},
    system_message="""You are a Tier 1 Analyst. You perform file analysis by strictly following a plan.
    - If the user asks for a 'full tier 1 triage' or 'quick scan', you MUST follow the Standard Triage Workflow below.
    - If the user asks to scan with a specific rule (e.g., 'scan with apt_lolbas'), you should call `scan_file_with_yara` and provide the `rule_name`.
    - After all steps are complete, combine all results into a single, final markdown report and end your message with the keyword TERMINATE.

    # Standard Triage Workflow
    1. Call `calculate_file_hash_and_entropy` on the file.
    2. Wait for the result.
    3. Call `query_virustotal_by_hash` using the hash from the previous step.
    4. Wait for the result.
    5. Call `scan_file_with_yara` on the original file path. **Do not specify a rule_name** to scan with all enabled rules.
    6. Wait for the result.
    7. Create a final summary report including the results from all three tools.
    """
)

# Tier 3 Analyst: The deep-dive expert for advanced static analysis.
tier3_analyst = autogen.AssistantAgent(
    name="Tier3_Analyst", 
    llm_config={**llm_config, "tools": tier3_tools_schema},
    system_message="You are a Tier 3 Analyst. Use your disassembler and PE parsing tools to perform deep static analysis, create a detailed technical report, and then end your message with the keyword TERMINATE."
)

# ======================================================================================
# 3. "AGENT-AS-A-TOOL" WRAPPER FUNCTIONS
# ======================================================================================

def run_tier1_analysis(filepath: str, user_request: str) -> str:
    """Triggers a sub-conversation with the Tier1_Analyst agent."""
    print(f"\n--- Manager delegating to Tier 1 Analyst ---")
    t1_function_map = {
        "scan_file_with_yara": scan_file_with_yara,
        "calculate_file_hash_and_entropy": calculate_file_hash_and_entropy,
        "query_virustotal_by_hash": query_virustotal_by_hash
    }
    executor = autogen.UserProxyAgent("T1_Executor", human_input_mode="NEVER", is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"), code_execution_config={"work_dir": "agent_output"}, function_map=t1_function_map)
    
    chat_result = executor.initiate_chat(recipient=tier1_analyst, message=f"Analyze the file at `{filepath}`. The user's specific request is: '{user_request}'", max_turns=7, summary_method="last_msg")
    return chat_result.chat_history[-1]["content"]

def run_tier3_analysis(filepath: str, user_request: str) -> str:
    """Triggers a sub-conversation with the Tier3_Analyst agent."""
    print(f"\n--- Manager delegating to Tier 3 Analyst ---")
    t3_function_map = {
        "parse_pe_file": parse_pe_file,
        "disassemble_pe_file": disassemble_pe_file
    }
    executor = autogen.UserProxyAgent("T3_Executor", human_input_mode="NEVER", is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"), code_execution_config={"work_dir": "agent_output"}, function_map=t3_function_map)
    
    chat_result = executor.initiate_chat(recipient=tier3_analyst, message=f"Analyze the file at `{filepath}`. The user's specific request is: '{user_request}'", max_turns=5, summary_method="last_msg")
    return chat_result.chat_history[-1]["content"]

# ======================================================================================
# 4. ORCHESTRATION LAYER: The SOC Manager and User Proxy
# ======================================================================================

soc_manager = autogen.AssistantAgent(
    name="SOC_Manager",
    llm_config={**llm_config, "tools": manager_tools_schema},
    system_message="""You are the SOC Manager, a dispatch agent.
    1. Analyze the user's request to determine the correct tool. The available tools are `run_tier1_analysis`, `run_tier3_analysis`, `analyze_log_file`, `get_yara_rules`, and `update_yara_rule_status`.
    2. You MUST call the selected tool with the correct arguments.
    3. After the tool returns a report, your ONLY job is to present that exact report to the user.
    4. Your final response MUST be ONLY the report, followed by the keyword `TERMINATE`. Do not add any extra conversational text.
    """
)

FUNCTION_MAP = {
    "run_tier1_analysis": run_tier1_analysis,
    "run_tier3_analysis": run_tier3_analysis,
    "analyze_log_file": analyze_log_file,
    "get_yara_rules": get_yara_rules,
    "update_yara_rule_status": update_yara_rule_status,
}

user_proxy = autogen.UserProxyAgent(
    name="User_Proxy",
    human_input_mode="NEVER",
    is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"),
    code_execution_config={"work_dir": "agent_output"},
    function_map=FUNCTION_MAP
)

# ======================================================================================
# 5. MAIN ENTRY POINT: The function called by the UI
# ======================================================================================

def run_analysis_conversation(user_request: str, filepath: Optional[str] = None) -> str:
    """
    Kicks off the main conversation with the SOC_Manager.
    The filepath is optional to support file-less commands like rule management.
    """
    user_proxy.reset()
    soc_manager.reset()
    
    if filepath:
        message = f"Please handle this user request for the file at `{filepath}`. The request is: '{user_request}'"
    else:
        message = user_request

    chat_result = user_proxy.initiate_chat(
        recipient=soc_manager,
        message=message,
    )
    
    summary = chat_result.chat_history[-1]["content"] if chat_result.chat_history and chat_result.chat_history[-1]["content"] else "Analysis concluded without a final summary."
    return summary.replace("TERMINATE", "").strip()
