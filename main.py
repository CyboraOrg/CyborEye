from src.api import app as flask_app
from dotenv import load_dotenv
import os
import sys
import subprocess

load_dotenv()

DEFAULT_HOST = os.getenv("DEFAULT_HOST", "127.0.0.1")
DEFAULT_PORT = os.getenv("DEFAULT_PORT", "8000")  # Optional addition

def run_flask():
    print(f"[INFO] Flask API running at http://{DEFAULT_HOST}:{DEFAULT_PORT}")
    flask_app.run(host=DEFAULT_HOST, port=int(DEFAULT_PORT), debug=True)

def run_streamlit(host="127.0.0.1", port="8000"):
    print(f"[INFO] Streamlit UI running at http://{host}:{port}")
    subprocess.run(["streamlit", "run", "ui.py", "--server.address", host, "--server.port", port])

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "ui":
        streamlit_host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
        streamlit_port = sys.argv[3] if len(sys.argv) > 3 else "8000"
        run_streamlit(streamlit_host, streamlit_port)
    else:
        run_flask()
