# ui.py
import streamlit as st
import tempfile
import os
import json
from src.cybor_eye_agents import run_analysis_conversation
# FIX: Import the deterministic tool functions directly for the UI
from src.tools.tier1_tools import get_yara_rules, update_yara_rule_status

# --- Page Configuration ---
st.set_page_config(page_title="CyborEye SOC", page_icon="🛡️", layout="wide")

# --- Page Title ---
st.title("🛡️ CyborEye: Agentic Security Operations")
st.caption("A conversational interface for the CyborEye multi-agent SOC team.")

# --- Session State Initialization ---
if "messages" not in st.session_state:
    st.session_state.messages = []
if "current_file_path" not in st.session_state:
    st.session_state.current_file_path = None
if "current_file_name" not in st.session_state:
    st.session_state.current_file_name = None
if "yara_rules" not in st.session_state:
    st.session_state.yara_rules = None

# --- Helper Functions for UI Rendering ---
def display_incident(incident):
    risk_score = incident.get('risk_score', 0)
    if risk_score > 80: st.error(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    elif risk_score > 40: st.warning(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    else: st.info(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    st.markdown(f"**Narrative:** {incident.get('narrative', 'N/A')}")
    with st.expander("View Incident Details and Findings"):
        col1, col2, col3 = st.columns(3)
        first_seen_str = incident.get('first_seen', '').split('T')[1].split('+')[0]
        last_seen_str = incident.get('last_seen', '').split('T')[1].split('+')[0]
        col1.metric("First Seen", first_seen_str)
        col2.metric("Last Seen", last_seen_str)
        col3.metric("# of Findings", len(incident.get('findings', [])))
        st.write("**Involved Entities:**", ", ".join(incident.get('entities', [])))
        st.write("**MITRE ATT&CK Tactics:**", ", ".join(incident.get('tactics', [])))
        st.subheader("Associated Findings")
        for finding in sorted(incident.get('findings', []), key=lambda x: x.get('finding_timestamp', '')):
            display_finding(finding)

def display_finding(finding):
    rule, mitre, event = finding.get('rule', {}), finding.get('mitre_attack', {}), finding.get('event_details', {})
    with st.container():
        st.markdown(f"---")
        st.markdown(f"**{rule.get('name', 'Unknown Rule')}** ({rule.get('id')})")
        st.caption(f"Timestamp: {finding.get('finding_timestamp', 'N/A')}")
        st.markdown(f"**Tactic:** {mitre.get('tactic', 'N/A')} | **Technique:** {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
        st.code(f"Description: {event.get('process_commandline') or event.get('description', 'No description')}", language="bash")
        st.markdown("###### Raw Event Data")
        st.json(event)

# --- Sidebar ---
with st.sidebar:
    st.header("Upload Artifact")
    uploaded_file = st.file_uploader("Upload a file for analysis", type=None, key="file_uploader")
    if uploaded_file:
        if st.session_state.get("current_file_name") != uploaded_file.name:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                st.session_state.current_file_path = tmp_file.name
                st.session_state.current_file_name = uploaded_file.name
            st.session_state.messages = []
            st.success(f"Loaded `{uploaded_file.name}`.")

    st.markdown("---")
    st.header("YARA Rule Management")

    # FIX: Fetch rules directly, not through an agent.
    if st.session_state.yara_rules is None:
        st.session_state.yara_rules = get_yara_rules()

    def handle_rule_toggle(rule_name):
        new_status = st.session_state[f"toggle_{rule_name}"]
        # FIX: Update the rule status directly.
        update_yara_rule_status(rule_name=rule_name, enabled=new_status)
        st.toast(f"Rule '{rule_name}' is now {'enabled' if new_status else 'disabled'}.")

    if st.session_state.yara_rules:
        for rule_name, details in st.session_state.yara_rules.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                st.checkbox(
                    rule_name, 
                    value=details.get('enabled', True), 
                    key=f"toggle_{rule_name}",
                    on_change=handle_rule_toggle,
                    args=(rule_name,)
                )
            with col2:
                with st.popover("ℹ️", help=f"Details for {rule_name}"):
                    st.subheader(rule_name)
                    meta = details.get('meta', {})
                    if meta:
                        for key, val in meta.items():
                            st.markdown(f"**{key.replace('_', ' ').title()}:** {val}")
                    else:
                        st.write("No metadata available for this rule.")
    else:
        st.write("No YARA rules loaded.")

# --- Main Conversational Interface ---
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        try:
            content_data = json.loads(message["content"])
            if "incidents" in content_data:
                st.markdown(content_data.get("summary", "Analysis complete."))
                for incident in content_data["incidents"]: display_incident(incident)
            else: st.json(content_data)
        except (json.JSONDecodeError, TypeError):
            st.markdown(message["content"])

if prompt := st.chat_input("Ask CyborEye to analyze the uploaded file..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"): st.markdown(prompt)

    if not st.session_state.current_file_path:
        st.warning("Please upload a file using the sidebar before starting the analysis.")
        st.stop()

    with st.chat_message("assistant"):
        with st.spinner("CyborEye is thinking..."):
            try:
                # The main chat still uses the agent for conversational analysis
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
