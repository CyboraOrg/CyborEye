import autogen
from src.consts import llm_config
from src.tools.tier1_tools import (
    scan_file_with_yara,
    calculate_file_hash_and_entropy,
    query_virustotal_by_hash,
)

# --- Define a Tool Schema for the LLM ---
# This explicitly tells the AssistantAgent what functions are available as tools.
tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "scan_file_with_yara",
            "description": "Scans a file with YARA rules to detect malicious patterns.",
            "parameters": {
                "type": "object",
                "properties": {"filepath": {"type": "string", "description": "The full path to the file to be scanned."}},
                "required": ["filepath"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_file_hash_and_entropy",
            "description": "Calculates the SHA256 hash and entropy of a file.",
            "parameters": {
                "type": "object",
                "properties": {"filepath": {"type": "string", "description": "The full path to the file."}},
                "required": ["filepath"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_virustotal_by_hash",
            "description": "Queries VirusTotal for a report on a file's SHA256 hash.",
            "parameters": {
                "type": "object",
                "properties": {"file_hash": {"type": "string", "description": "The SHA256 hash of the file."}},
                "required": ["file_hash"],
            },
        },
    },
]

# --- Create the specialized LLM config for the Analyst ---
analyst_llm_config = llm_config.copy()
analyst_llm_config["tools"] = tools_schema

# --- Define the Agents ---

# The SOC_Analyst is the "Brain". It decides which tool to call.
# It does NOT need a function_map or code_execution_config.
soc_analyst_agent = autogen.AssistantAgent(
    name="SOC_Analyst",
    llm_config=analyst_llm_config,
    system_message="""
    You are a Tier 1 Security Analyst. Your job is to analyze files by creating a plan and suggesting calls to the functions available to you.

    1. Read the user's request to understand their goal (e.g., 'full triage', 'yara only').
    2. Based on the request, suggest the appropriate tool call with the correct arguments. You MUST suggest a function call to get a result.
    3. The User agent will execute the function and return the result to you.
    4. Analyze the result. If more steps are needed, suggest the next tool call.
    5. Once the plan is complete, provide a final, user-friendly detail of all findings in structured output.
    6. You MUST end your final detailed report message with the keyword `TERMINATE`.
    """,
)

# The user_proxy is the "Hands" or "Executor".
# It executes the tool calls suggested by the SOC_Analyst.
user_proxy = autogen.UserProxyAgent(
    name="User",
    human_input_mode="NEVER",
    is_termination_msg=lambda x: isinstance(x.get("content"), str) and x.get("content", "").rstrip().endswith("TERMINATE"),
    # **THE DEFINITIVE FIX**: The UserProxyAgent that executes the code MUST have the
    # code_execution_config and the function_map.
    code_execution_config={"work_dir": "agent_output"},
    function_map={
        "scan_file_with_yara": scan_file_with_yara,
        "calculate_file_hash_and_entropy": calculate_file_hash_and_entropy,
        "query_virustotal_by_hash": query_virustotal_by_hash,
    }
)

# --- Main Entry Point ---
def run_analysis_conversation(filepath: str, user_request: str) -> str:
    """
    This function kicks off the simple and direct 2-agent chat.
    """
    user_proxy.reset()
    soc_analyst_agent.reset()

    # The User Proxy starts the conversation with the Analyst Agent.
    chat_result = user_proxy.initiate_chat(
        recipient=soc_analyst_agent,
        message=f"Please analyze the file at `{filepath}`. My request is: '{user_request}'",
    )

    # **THE FIX**: The chat_result.summary contains the final summary from the run.
    # This is the most reliable way to get the intended final response.
    summary = chat_result.chat_history[-1]["content"] if chat_result.chat_history[-1]["content"] else "Analysis concluded without a final summary."
    
    return summary.replace("TERMINATE", "").strip()