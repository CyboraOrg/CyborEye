import os
import subprocess
import argparse

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

DEFAULT_HOST = os.getenv("DEFAULT_HOST", "127.0.0.1")
DEFAULT_PORT = os.getenv("DEFAULT_PORT", "8000")  # Optional addition

def run_streamlit():
    """
    Runs the Streamlit user interface.
    """
    print(f"✅ Starting Streamlit UI at http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    subprocess.run([
        "streamlit", "run", "ui.py",
        "--server.address", DEFAULT_HOST,
        "--server.port", DEFAULT_PORT
    ])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Agentic SOC - AI-Powered Security Operations")
    parser.add_argument("--report", type=str, default="")
    args = parser.parse_args()

    if args.report:
        os.environ["REPORT_AGENT_API"] = args.report
    
    run_streamlit()