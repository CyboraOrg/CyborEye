import autogen
from src.consts import llm_config
from src.tools.tier1_tools import scan_file_with_yara, calculate_file_hash_and_entropy, query_virustotal_by_hash
from src.tools.tier3_tools import parse_pe_file, disassemble_pe_file

# --- Manually Defined Tool Schemas (Unchanged) ---
tier1_tools_schema = [
    {"type": "function", "function": {"name": "scan_file_with_yara", "description": "Scans a file with YARA rules to detect malicious patterns.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "calculate_file_hash_and_entropy", "description": "Calculates the SHA256 hash and entropy of a file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "query_virustotal_by_hash", "description": "Queries VirusTotal for a report on a file's SHA256 hash.", "parameters": {"type": "object", "properties": {"file_hash": {"type": "string"}}, "required": ["file_hash"]}}}
]
tier3_tools_schema = [
    {"type": "function", "function": {"name": "parse_pe_file", "description": "Parses a Portable Executable (PE) file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}},
    {"type": "function", "function": {"name": "disassemble_pe_file", "description": "Disassembles the entry point of a PE file.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}}, "required": ["filepath"]}}}
]
manager_tools_schema = [
    {"type": "function", "function": {"name": "run_tier1_analysis", "description": "Runs a Tier 1 analysis for quick triage.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}, "user_request": {"type": "string"}}, "required": ["filepath", "user_request"]}}},
    {"type": "function", "function": {"name": "run_tier3_analysis", "description": "Runs a Tier 3 analysis for deep static analysis.", "parameters": {"type": "object", "properties": {"filepath": {"type": "string"}, "user_request": {"type": "string"}}, "required": ["filepath", "user_request"]}}}
]


# --- Specialist Agent Definitions ---

# **THE FIX**: The Tier1_Analyst prompt is now a strict, step-by-step checklist.
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
    name="Tier3_Analyst",
    llm_config={**llm_config, "tools": tier3_tools_schema},
    system_message="""You are a Tier 3 Analyst. Use your disassembler and PE parsing tools to perform deep static analysis.
    Combine the output of your tools into a detailed technical report, and then end your message with the keyword TERMINATE."""
)

# --- "Agent-as-a-Tool" Function Wrappers (Unchanged) ---

def run_tier1_analysis(filepath: str, user_request: str) -> str:
    """Runs a Tier 1 analysis for quick triage, YARA scans, and hash lookups."""
    print(f"\n--- Manager delegating to Tier 1 Analyst ---")
    executor = autogen.UserProxyAgent(
        name="T1_Executor",
        human_input_mode="NEVER",
        is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"),
        code_execution_config={"work_dir": "agent_output"},
        function_map={
            "scan_file_with_yara": scan_file_with_yara,
            "calculate_file_hash_and_entropy": calculate_file_hash_and_entropy,
            "query_virustotal_by_hash": query_virustotal_by_hash,
        }
    )
    chat_result = executor.initiate_chat(
        recipient=tier1_analyst,
        message=f"Analyze the file at `{filepath}`. The user's specific request is: '{user_request}'",
        max_turns=7, # Increased turns to allow for the multi-step chain
        summary_method="last_msg"
    )
    return chat_result.chat_history[-1]["content"]

def run_tier3_analysis(filepath: str, user_request: str) -> str:
    """Runs a Tier 3 analysis for deep static analysis, including PE parsing and disassembly."""
    print(f"\n--- Manager delegating to Tier 3 Analyst ---")
    executor = autogen.UserProxyAgent(
        name="T3_Executor",
        human_input_mode="NEVER",
        is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"),
        code_execution_config={"work_dir": "agent_output"},
        function_map={
            "parse_pe_file": parse_pe_file,
            "disassemble_pe_file": disassemble_pe_file,
        }
    )
    chat_result = executor.initiate_chat(
        recipient=tier3_analyst,
        message=f"Analyze the file at `{filepath}`. The user's specific request is: '{user_request}'",
        max_turns=5, summary_method="last_msg"
    )
    return chat_result.chat_history[-1]["content"]

# --- SOC Manager Agent Definition (Unchanged) ---

soc_manager = autogen.AssistantAgent(
    name="SOC_Manager",
    llm_config={**llm_config, "tools": manager_tools_schema},
    system_message="""You are the SOC Manager. Your job is to understand the user's request and delegate it to the correct specialist tool.
- For requests like 'yara scan', 'quick scan', 'check this file', or 'triage', call the `run_tier1_analysis` tool.
- For requests like 'disassemble', 'parse pe', 'deep dive', or 'reverse engineer', call the `run_tier3_analysis` tool.
- After the specialist tool returns a report, present that report to the user in a clean format and then terminate the conversation.
- You MUST end your final message with the keyword `TERMINATE`.
"""
)

# --- Main Entry Point (Unchanged) ---

user_proxy = autogen.UserProxyAgent(
    name="User_Proxy",
    human_input_mode="NEVER",
    is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"),
    code_execution_config={"work_dir": "agent_output"},
    function_map={
        "run_tier1_analysis": run_tier1_analysis,
        "run_tier3_analysis": run_tier3_analysis,
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
    
    summary = chat_result.chat_history[-1]["content"] if chat_result.chat_history[-1]["content"] else "Analysis concluded without a final summary."
    return summary.replace("TERMINATE", "").strip()