import yara
import hashlib
import math
import os
import requests
from typing import Dict, Any

# --- New YaraScanner Class for Efficiency ---

class YaraScanner:
    """
    A class to manage YARA rules by compiling them only once.
    """
    def __init__(self, rules_directory: str = 'src/yara_rules'):
        print("[INFO] Compiling YARA rules... This should only happen once at startup.")
        try:
            rule_paths = {f.split('.')[0]: os.path.join(rules_directory, f) for f in os.listdir(rules_directory) if f.endswith(('.yar', '.yara'))}
            if not rule_paths:
                print(f"[WARNING] No YARA rules found in {rules_directory}. Scanner will be inactive.")
                self.rules = None
            else:
                self.rules = yara.compile(filepaths=rule_paths)
                print("[INFO] YARA rules compiled successfully.")
                print(f"[INFO] Compiled {len(rule_paths)} YARA rules from {rules_directory}.")
        except Exception as e:
            print(f"[ERROR] Failed to compile YARA rules: {e}")
            self.rules = None

    def scan_file(self, filepath: str) -> Dict[str, Any]:
        """
        Scans a file using the pre-compiled rules and returns the results,
        including the names of matched rules.
        """
        if self.rules is None:
            return {"error": "YARA scanner is not active."}

        print(f"[T1 Tool] Scanning {filepath} with pre-compiled YARA rules...")
        try:
            matches = self.rules.match(filepath)
            matched_details = []
            for match in matches:
                matched_details.append({
                    "rule": match.rule,
                    "meta": match.meta,
                    "tags": match.tags
                })
            return {
                "file": filepath,
                "matched_details": matched_details,
                "match_count": len(matched_details)
            }
        except Exception as e:
            return {"error": f"An error occurred during YARA scan: {e}"}


# --- Instantiate the scanner once when the module is loaded ---
_yara_scanner_instance = YaraScanner()


# --- Tool Functions for Agents ---

def scan_file_with_yara(filepath: str) -> Dict[str, Any]:
    """
    Scans a file using the pre-compiled YARA rules. This is a primary Tier 1 analysis tool.
    """
    return _yara_scanner_instance.scan_file(filepath)


def calculate_file_hash_and_entropy(filepath: str) -> Dict[str, Any]:
    """
    Calculates the SHA256 hash and entropy of a file. The hash can be used for VirusTotal lookups.
    """
    print(f"[T1 Tool] Calculating hash and entropy for {filepath}...")
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        sha256_hash = hashlib.sha256(data).hexdigest()
        entropy = 0.0
        if data:
            byte_counts = [data.count(byte) for byte in range(256)]
            for count in byte_counts:
                if count > 0:
                    p_x = count / len(data)
                    entropy -= p_x * math.log2(p_x)
        return {"sha256": sha256_hash, "entropy": entropy}
    except Exception as e:
        return {"error": str(e)}


def query_virustotal_by_hash(file_hash: str) -> Dict[str, Any]:
    """
    Queries the VirusTotal API for a report on a given file hash (SHA256).
    Requires a VIRUSTOTAL_API_KEY environment variable.
    """
    print(f"[T1 Tool] Querying VirusTotal for hash {file_hash}...")
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key: return {"error": "VIRUSTOTAL_API_KEY not set."}
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            return {"status": "Not Found", "hash": file_hash}
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_scans": sum(stats.values()),
            "link": f"https://www.virustotal.com/gui/file/{file_hash}"
        }
    except Exception as e:
        return {"error": str(e)}