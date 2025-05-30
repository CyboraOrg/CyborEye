import requests
import os
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')

def query_virustotal(sha256):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            return {
                "source": "VirusTotal",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected
            }
        elif response.status_code == 404:
            return {"source": "VirusTotal", "status": "not found"}
        else:
            return {"error": f"VT API error: {response.status_code}"}

    except Exception as e:
        return {"error": f"Error querying VirusTotal: {str(e)}"}