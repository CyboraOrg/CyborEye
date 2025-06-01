import streamlit as st
from src.agents import analyze_file
import tempfile
import os

st.set_page_config(page_title="Agentic SOC - File Analyzer", layout="centered")
st.title("🛡️ Agentic SOC - PE File Analyzer")

uploaded_file = st.file_uploader("Upload a PE file (.exe, .dll)", type=["exe", "dll"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_file_path = tmp_file.name

    with st.spinner("Analyzing file..."):
        try:
            st.info(f"Analyzing file: {uploaded_file.name}")
            result = analyze_file(tmp_file_path)
            st.success("Analysis complete!")
            # Create tabs
            f, p, d = st.tabs(["Final", "PE", "Disassembler"])
            # Store the selected tab in session state
            with f:
                st.session_state["selected_tab"] = "Final"
                st.markdown(result["verdict"])
            with p:
                st.session_state["selected_tab"] = "PE"
                st.markdown(result["pe_summary"])
            with d:
                st.session_state["selected_tab"] = "Disassembler"
                st.markdown(result["disasm_summary"])
            
        except Exception as e:
            st.error(f"Error during analysis: {str(e)}")
        finally:
            os.remove(tmp_file_path)
