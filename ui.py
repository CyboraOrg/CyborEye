# ui.py
import streamlit as st
import tempfile
import os
import json
from src.cybor_eye_agents import run_analysis_conversation

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

# --- Helper Functions for UI Rendering ---
def display_incident(incident):
    """Renders a single incident from the log analysis pipeline."""
    risk_score = incident.get('risk_score', 0)
    
    if risk_score > 80:
        st.error(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    elif risk_score > 40:
        st.warning(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")
    else:
        st.info(f"**Incident {incident['incident_id']} (Risk Score: {risk_score})**")

    st.markdown(f"**Narrative:** {incident.get('narrative', 'N/A')}")
    
    # This is the main expander for the whole incident
    with st.expander("View Incident Details and Findings"):
        col1, col2, col3 = st.columns(3)
        # Use .get() to avoid errors if the key is missing
        first_seen_str = incident.get('first_seen', '').split('T')[1].split('+')[0]
        last_seen_str = incident.get('last_seen', '').split('T')[1].split('+')[0]
        col1.metric("First Seen", first_seen_str)
        col2.metric("Last Seen", last_seen_str)
        col3.metric("# of Findings", len(incident.get('findings', [])))

        st.write("**Involved Entities:**")
        st.write(", ".join(incident.get('entities', [])))

        st.write("**MITRE ATT&CK Tactics:**")
        st.write(", ".join(incident.get('tactics', [])))

        st.subheader("Associated Findings")
        for finding in sorted(incident.get('findings', []), key=lambda x: x.get('finding_timestamp', '')):
            display_finding(finding)

def display_finding(finding):
    """Renders a single finding within an incident. This no longer uses an expander."""
    rule = finding.get('rule', {})
    mitre = finding.get('mitre_attack', {})
    event = finding.get('event_details', {})
    
    # Use a container to group the finding's elements visually
    with st.container():
        st.markdown(f"---")
        st.markdown(f"**{rule.get('name', 'Unknown Rule')}** ({rule.get('id')})")
        st.caption(f"Timestamp: {finding.get('finding_timestamp', 'N/A')}")
        
        st.markdown(f"**Tactic:** {mitre.get('tactic', 'N/A')} | **Technique:** {mitre.get('technique_id', 'N/A')} - {mitre.get('technique_name', 'N/A')}")
        
        # FIX: Use the canonical 'process_commandline' field for consistency.
        st.code(f"Description: {event.get('process_commandline') or event.get('description', 'No description')}", language="bash")
        
        # FIX: Removed the nested expander. Display the JSON directly.
        st.markdown("###### Raw Event Data")
        st.json(event)


# --- Sidebar for File Upload ---
with st.sidebar:
    st.header("Upload Artifact")
    st.write("Upload a file or log for analysis. Then, instruct the agent in the chat.")
    uploaded_file = st.file_uploader(
        "Upload Artifact",
        type=None,
        key="file_uploader"
    )

    if uploaded_file is not None:
        if st.session_state.current_file_name != uploaded_file.name:
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                st.session_state.current_file_path = tmp_file.name
                st.session_state.current_file_name = uploaded_file.name
            
            st.session_state.messages = [] # Clear chat history for new file
            st.success(f"Loaded `{uploaded_file.name}`. You can now analyze it via chat.")

# --- Main Conversational Interface ---

# Display existing messages in the chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        try:
            content_data = json.loads(message["content"])
            if "incidents" in content_data:
                st.markdown(content_data.get("summary", "Analysis complete."))
                for incident in content_data["incidents"]:
                    display_incident(incident)
            else:
                st.json(content_data)
        except (json.JSONDecodeError, TypeError):
            st.markdown(message["content"])

# Get new user input
if prompt := st.chat_input("Ask CyborEye to analyze the uploaded file..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    if not st.session_state.current_file_path:
        st.warning("Please upload a file using the sidebar before starting the analysis.")
        st.stop()

    with st.chat_message("assistant"):
        with st.spinner("CyborEye is thinking..."):
            try:
                response_str = run_analysis_conversation(
                    st.session_state.current_file_path,
                    prompt
                )
                
                st.session_state.messages.append({"role": "assistant", "content": response_str})
                
                try:
                    response_data = json.loads(response_str)
                    if "incidents" in response_data:
                        st.markdown(response_data.get("summary", "Analysis complete."))
                        for incident in response_data["incidents"]:
                            display_incident(incident)
                    else:
                        st.json(response_data)
                except (json.JSONDecodeError, TypeError):
                    st.markdown(response_str)

            except Exception as e:
                error_message = f"An error occurred during analysis: {e}"
                st.error(error_message)
                st.session_state.messages.append({"role": "assistant", "content": error_message})
