from src.api import app as flask_app
from dotenv import load_dotenv
import os
import sys
import subprocess
import argparse

load_dotenv()

DEFAULT_HOST = os.getenv("DEFAULT_HOST", "127.0.0.1")
DEFAULT_PORT = os.getenv("DEFAULT_PORT", "8000")  # Optional addition

def run_flask():
    print(f"[INFO] Flask API running at http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    flask_app.run(host=DEFAULT_HOST, port=int(DEFAULT_PORT), debug=True)

def run_streamlit():
    print(f"[INFO] Streamlit UI running at http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    subprocess.run(["streamlit", "run", "ui.py", "--server.address", DEFAULT_HOST, "--server.port", DEFAULT_PORT])

if __name__ == '__main__':
    parser = argparse.ArgumentParser("Agentic SOC")
    parser.add_argument("--ui", default=False, action="store_true")
    parser.add_argument("--report", type=str, default="")
    args = parser.parse_args()
    
    if args.report:
        os.environ["REPORT_AGENT_API"] = args.report
        
    if args.ui:
        run_streamlit()
    else:
        run_flask()