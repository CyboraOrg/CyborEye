from src.prompts import disassembler_agent as da
from src.prompts import parser_agent as pa
from src.prompts import verdict_agent as va
from autogen import AssistantAgent, UserProxyAgent
from src.consts import llm_config
import json
import os

pe_parser_agent = AssistantAgent(
    name="pe_parser",
    llm_config=llm_config,
    system_message=pa.system_prompt,
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
)

disasm_agent = AssistantAgent(
    name="disasm_agent",
    llm_config=llm_config,
    system_message=da.system_prompt,
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
)

verdict_agent = AssistantAgent(
    name="verdict_agent",
    llm_config=llm_config,
    system_message=va.system_prompt,
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
)

def is_termination_msg(message):
    return "#" in message.get("content", "")

user_proxy = UserProxyAgent(
    name="user",
    code_execution_config={"work_dir": ".", "use_docker": False},
    is_termination_msg=is_termination_msg,
    human_input_mode="NEVER",
    max_consecutive_auto_reply=1,
)


#  -------------------- Agent Work Flow --------------------

from src.tools.virus_total import query_virustotal
from src.tools.hash_entropy import calculate_hash_entropy
from src.tools.parser import parse_pe
from src.tools.disassembler import disassemble_pe


def analyze_file(filepath):
    print(f"[INFO] Analyzing file: {filepath}")
    hash_data = calculate_hash_entropy(filepath)
    if "error" in hash_data:
        return {"error": hash_data["error"]}

    vt_result = query_virustotal(hash_data["sha256"])
    if int(vt_result.get("malicious", 0)) >= 5:
        return {
            "verdict": "Likely Malicious",
            "reason": "VirusTotal reported the file as malicious.",
            "hashes": hash_data,
            "vt": vt_result
        }

    pe_data = parse_pe(filepath)
    print("[INFO] PE Parsed")
    disasm_data = disassemble_pe(filepath)
    print("[INFO] PE Disassembled")
    pe_analysis = user_proxy.initiate_chat(
        pe_parser_agent,
        message=json.dumps(pe_data, indent=2),
        silent=True,
        max_consecutive_auto_reply=1,
        max_turns=1
    )
    print("[INFO] Parsed PE reported.")
    
    disasm_analysis = user_proxy.initiate_chat(
        disasm_agent,
        message=json.dumps(disasm_data, indent=2),
        silent=True,
        max_consecutive_auto_reply=1,
        max_turns=1
    )
    print("[INFO] Disassembled PE reported.")
    
    pe_analysis_content = pe_analysis.chat_history[-1]["content"]
    disasm_analysis_content = disasm_analysis.chat_history[-1]["content"]

    print("[INFO] Generating combined input ...")
    combined_input = f"""
--- Hash + Entropy
{json.dumps(hash_data, indent=2)}

--- Virus Total Result
{json.dumps(vt_result, indent=2)}

--- PE Metadata Insight ---
{pe_analysis_content}

--- Disassembly Insight ---
{disasm_analysis_content}
"""

    final_verdict = user_proxy.initiate_chat(
        verdict_agent,
        message=combined_input,
        # silent=True,
        max_consecutive_auto_reply=1,
        max_turns=1
    )
    print("[INFO] Static Analysis finished.")
    x = None
    url = os.getenv('REPORT_AGENT_API')
    if url not in ["", None]:
        import requests
        myobj = {
                "data": [
                    {
                        "name": "Portable Executable summary report",
                        "data": [{"value":pe_analysis_content}]
                    },
                    {
                        "name": "Disassembly summary report",
                        "data": [{"value":disasm_analysis_content}]
                    }
                ],
                "targets": "Use this report and make me a great representation"
            }
        headers = {'Content-Type': 'application/json'}
        
        print("Initiating Post request ...")
        x = requests.post(str(url), json.dumps(myobj), headers=headers)

    result = {
        "hash_data": hash_data,
        "vt_result": vt_result,
        "pe_summary": pe_analysis_content,
        "disasm_summary": disasm_analysis_content,
        "verdict": final_verdict.chat_history[-1]["content"]
    }
    
    if x != None:
        result["report"] = x.json()["report"]
    
    return result