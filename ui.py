# ui.py
import streamlit as st
import tempfile
import os
import json
import pandas as pd
from src.cybor_eye_agents import run_analysis_conversation
# Import the deterministic tool functions directly for the UI
from src.tools.tier1_tools import get_yara_rules, update_yara_rule_status, get_yara_rule_content, save_yara_rule, delete_yara_rule

# --- Page Configuration ---
st.set_page_config(page_title="CyborEye SOC", page_icon="🛡️", layout="wide")

# --- Page Title ---
st.title("🛡️ CyborEye: Agentic Security Operations")

# --- Session State Initialization ---
if "messages" not in st.session_state: st.session_state.messages = []
if "current_file_path" not in st.session_state: st.session_state.current_file_path = None
if "current_file_name" not in st.session_state: st.session_state.current_file_name = None
if "yara_rules" not in st.session_state: st.session_state.yara_rules = None
if "editing_rule_name" not in st.session_state: st.session_state.editing_rule_name = None
if "editing_rule_content" not in st.session_state: st.session_state.editing_rule_content = ""
# New state to control the main view
if "active_view" not in st.session_state: st.session_state.active_view = "analysis"


# --- Helper Functions for UI Rendering ---
def display_incident(incident):
    # (This function remains the same as the previous version)
    risk_score = incident.get('risk_score', 0)
    if risk_score > 80: st.error(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    elif risk_score > 40: st.warning(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    else: st.info(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    st.markdown(f"**Narrative:** {incident.get('narrative', 'N/A')}")
    with st.expander("View Incident Details and Findings"):
        col1, col2, col3 = st.columns(3)
        first_seen_str = incident.get('first_seen', '').split('T')[1].split('+')[0]
        last_seen_str = incident.get('last_seen', '').split('T')[1].split('+')[0]
        col1.metric("First Seen", first_seen_str); col2.metric("Last Seen", last_seen_str)
        col3.metric("# of Findings", len(incident.get('findings', [])))
        st.write("**Involved Entities:**", ", ".join(incident.get('entities', [])))
        st.write("**MITRE ATT&CK Tactics:**", ", ".join(incident.get('tactics', [])))
        st.subheader("Associated Findings")
        for finding in sorted(incident.get('findings', []), key=lambda x: x.get('finding_timestamp', '')):
            display_finding(finding)

def display_finding(finding):
    # (This function remains the same as the previous version)
    rule, mitre, event = finding.get('rule', {}), finding.get('mitre_attack', {}), finding.get('event_details', {})
    with st.container():
        st.markdown(f"---"); st.markdown(f"**{rule.get('name', 'Unknown Rule')}** ({rule.get('id')})")
        st.caption(f"Timestamp: {finding.get('finding_timestamp', 'N/A')}")
        st.markdown(f"**Tactic:** {mitre.get('tactic', 'N/A')} | **Technique:** {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
        st.code(f"Description: {event.get('process_commandline') or event.get('description', 'No description')}", language="bash")
        st.markdown("###### Raw Event Data"); st.json(event)

# --- Sidebar ---
with st.sidebar:
    st.header("Controls")
    if st.button("💬 Conversational Analysis", use_container_width=True, type="primary" if st.session_state.active_view == "analysis" else "secondary"):
        st.session_state.active_view = "analysis"
    if st.button("📝 YARA Rule Management", use_container_width=True, type="primary" if st.session_state.active_view == "rules" else "secondary"):
        st.session_state.active_view = "rules"

    st.markdown("---")
    st.header("Upload Artifact for Analysis")
    uploaded_file = st.file_uploader("Upload a file for analysis", type=None, key="file_uploader")
    if uploaded_file:
        if st.button("Load File for Analysis"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                st.session_state.current_file_path = tmp_file.name
                st.session_state.current_file_name = uploaded_file.name
            st.session_state.messages = []
            st.success(f"Loaded `{uploaded_file.name}`.")
            st.session_state.active_view = 'analysis' # Switch to analysis view after loading

# ==============================================================================
# View Controller
# ==============================================================================
if st.session_state.active_view == "analysis":
    # --- Conversational Analysis View ---
    st.header("Conversational Analysis Interface")
    if st.session_state.current_file_name:
        st.info(f"**Current file for analysis:** `{st.session_state.current_file_name}`")
    else:
        st.info("Upload and load a file from the sidebar to begin analysis.")

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            try:
                content_data = json.loads(message["content"])
                if "incidents" in content_data:
                    st.markdown(content_data.get("summary", "Analysis complete."))
                    for incident in content_data["incidents"]: display_incident(incident)
                else: st.json(content_data)
            except (json.JSONDecodeError, TypeError): st.markdown(message["content"])

    if prompt := st.chat_input("Ask CyborEye to analyze the uploaded file..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"): st.markdown(prompt)
        if not st.session_state.current_file_path:
            st.warning("Please load a file using the sidebar before starting the analysis.")
        else:
            with st.chat_message("assistant"):
                with st.spinner("CyborEye is thinking..."):
                    try:
                        response_str = run_analysis_conversation(user_request=prompt, filepath=st.session_state.current_file_path)
                        st.session_state.messages.append({"role": "assistant", "content": response_str})
                        try:
                            response_data = json.loads(response_str)
                            if "incidents" in response_data:
                                st.markdown(response_data.get("summary", "Analysis complete."))
                                for incident in response_data["incidents"]: display_incident(incident)
                            else: st.json(response_data)
                        except (json.JSONDecodeError, TypeError): st.markdown(response_str)
                    except Exception as e:
                        error_message = f"An error occurred during analysis: {e}"
                        st.error(error_message)
                        st.session_state.messages.append({"role": "assistant", "content": error_message})

elif st.session_state.active_view == "rules":
    # --- YARA Rule Management View ---
    st.header("YARA Rule Editor & Manager")

    @st.dialog("YARA Rule Editor")
    def rule_editor_dialog(rule_name, content):
        st.subheader(f"Editing: {rule_name}" if rule_name else "Create New Rule")
        if not rule_name:
            st.session_state.editing_rule_name = st.text_input("New Rule Name (alphanumeric, no extension)", key="new_rule_name_input")
        else:
            st.session_state.editing_rule_name = rule_name
        
        edited_content = st.text_area("Rule Content", value=content, height=400, key="rule_content_editor")
        
        col1, col2 = st.columns([1,1])
        if col1.button("Save Rule", type="primary"):
            final_rule_name = st.session_state.editing_rule_name
            if not final_rule_name:
                st.error("Rule name cannot be empty.")
            else:
                result = save_yara_rule(final_rule_name, edited_content)
                if result.get("status") == "success":
                    st.toast(result.get("message"), icon="✅")
                    st.session_state.yara_rules = None # Force refresh
                    st.rerun()
                else:
                    st.error(f"Failed to save: {result.get('message')}")
        if col2.button("Cancel"):
            st.rerun()

    # --- Main Rule Management UI ---
    if st.button("➕ Add New Rule"):
        rule_editor_dialog(None, 'rule NewRuleName\n{\n    meta:\n        description = "My new rule"\n        author = "Analyst"\n        severity = "Medium"\n    strings:\n        $hex_string = { E2 34 A1 C8 23 FB }\n\n    condition:\n        $hex_string\n}')

    st.markdown("---")
    st.subheader("Loaded Detection Rules")

    if st.session_state.yara_rules is None:
        st.session_state.yara_rules = get_yara_rules()

    if st.session_state.yara_rules:
        # Create header row
        header_cols = st.columns([3, 4, 1, 1, 1])
        header_cols[0].write("**Rule Name**")
        header_cols[1].write("**Description**")
        header_cols[2].write("**Enabled**")
        header_cols[3].write("**Edit**")
        header_cols[4].write("**Delete**")

        for rule_name, details in st.session_state.yara_rules.items():
            st.markdown("---")
            rule_cols = st.columns([3, 4, 1, 1, 1])
            with rule_cols[0]:
                st.code(rule_name, language=None)
            with rule_cols[1]:
                st.write(details.get('meta', {}).get('description', 'N/A'))
            with rule_cols[2]:
                is_enabled = st.checkbox("", value=details.get('enabled', True), key=f"enable_{rule_name}", label_visibility="collapsed")
                if is_enabled != details.get('enabled', True):
                    update_yara_rule_status(rule_name, is_enabled)
                    st.session_state.yara_rules[rule_name]['enabled'] = is_enabled
                    st.toast(f"Updated '{rule_name}' status.")
                    st.rerun()
            with rule_cols[3]:
                if st.button("✏️", key=f"edit_{rule_name}", help=f"Edit {rule_name}"):
                    content_data = get_yara_rule_content(rule_name)
                    rule_editor_dialog(rule_name, content_data.get("content", ""))
            with rule_cols[4]:
                if st.button("🗑️", key=f"del_{rule_name}", help=f"Delete {rule_name}"):
                    delete_yara_rule(rule_name)
                    st.toast(f"Rule '{rule_name}' deleted.", icon="🗑️")
                    st.session_state.yara_rules = None # Force refresh
                    st.rerun()
    else:
        st.write("No YARA rules found or loaded. Add a new rule to begin.")
