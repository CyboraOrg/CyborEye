import streamlit as st
import tempfile
import os
from src.cybor_eye_agents import run_analysis_conversation

# --- Page Configuration ---
st.set_page_config(page_title="Agentic SOC", page_icon="🛡️", layout="wide")

# --- Page Title ---
st.title("🛡️ Agentic SOC")
st.caption("A Tier 1 AI Analyst for conversational security analysis.")

# --- Session State Initialization ---
if "messages" not in st.session_state:
    st.session_state.messages = []
if "current_file" not in st.session_state:
    st.session_state.current_file = None

# --- Sidebar for File Upload ---
with st.sidebar:
    st.header("File Upload")
    uploaded_file = st.file_uploader("Upload a file for analysis", type=None, key="file_uploader")

    if uploaded_file is not None:
        # When a new file is uploaded, clear old analysis and save the new file
        if st.session_state.current_file is None or st.session_state.current_file["name"] != uploaded_file.name:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(uploaded_file.read())
                st.session_state.current_file = {
                    "path": tmp_file.name,
                    "name": uploaded_file.name
                }
            st.success(f"Uploaded `{uploaded_file.name}`. Ready for analysis.")

# --- Main Chat Interface ---
# Display previous chat messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Handle new user input
if prompt := st.chat_input("Ask the analyst to triage the file..."):
    # Add user message to UI
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Check if a file is ready for analysis
    if not st.session_state.current_file:
        st.warning("Please upload a file using the sidebar before starting the analysis.")
        st.stop()

    # Initiate agent workflow
    with st.chat_message("assistant"):
        with st.spinner("The T1 Analyst is investigating..."):
            try:
                filepath = st.session_state.current_file["path"]
                response = run_analysis_conversation(filepath, prompt)
                st.markdown(response)
                # Add assistant response to session state
                st.session_state.messages.append({"role": "assistant", "content": response})

            except Exception as e:
                error_message = f"An error occurred: {str(e)}"
                st.error(error_message)
                st.session_state.messages.append({"role": "assistant", "content": error_message})
            finally:
                # Clean up the temp file after analysis is complete
                if os.path.exists(st.session_state.current_file["path"]):
                    os.remove(st.session_state.current_file["path"])
                st.session_state.current_file = None