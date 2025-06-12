import streamlit as st
from src.agents import analyze_file_t1, analyze_file_t3
import tempfile
import os

st.set_page_config(page_title="Agentic SOC", layout="centered")
st.title("🛡️ Agentic SOC")

# Create main tabs
tier1_tab, tier3_tab = st.tabs(["Tier 1", "Tier 3"])

with tier1_tab:
    st.subheader("Tier 1 Analysis")
    uploaded_file_t1 = st.file_uploader("Upload a file for Tier 1 analysis", key="uploader_t1")
    
    if uploaded_file_t1 is not None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file_t1.read())
            tmp_file_path = tmp_file.name

        with st.spinner("Analyzing file with Tier 1..."):
            try:
                st.info(f"Analyzing file: {uploaded_file_t1.name}")
                result = analyze_file_t1(tmp_file_path, uploaded_file_t1.name)
                st.success("Tier 1 Analysis complete!")
                
                # Simple output for Tier 1 without nested tabs
                st.markdown("### Analysis Results")
                st.markdown(result["report"])
                
            except Exception as e:
                st.error(f"Error during Tier 1 analysis: {str(e)}")
            finally:
                os.remove(tmp_file_path)

with tier3_tab:
    st.subheader("Tier 3 Analysis")
    uploaded_file_t3 = st.file_uploader("Upload a PE file for Tier 3 analysis", 
                                      type=["exe", "dll"], 
                                      key="uploader_t3")
    
    if uploaded_file_t3 is not None:
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(uploaded_file_t3.read())
            tmp_file_path = tmp_file.name

        with st.spinner("Analyzing file with Tier 3..."):
            try:
                st.info(f"Analyzing file: {uploaded_file_t3.name}")
                result = analyze_file_t3(tmp_file_path)
                st.success("Tier 3 Analysis complete!")
                
                # Nested tabs only for Tier 3
                f3, p3, d3 = st.tabs(["Final", "PE", "Disassembler"])
                with f3:
                    st.session_state["selected_tab_t3"] = "Final_T3"
                    st.markdown(result["verdict"])
                with p3:
                    st.session_state["selected_tab_t3"] = "PE_T3"
                    st.markdown(result["pe_summary"])
                with d3:
                    st.session_state["selected_tab_t3"] = "Disassembler_T3"
                    st.markdown(result["disasm_summary"])
            except Exception as e:
                st.error(f"Error during Tier 3 analysis: {str(e)}")
            finally:
                os.remove(tmp_file_path)