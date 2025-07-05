# src/tools/tier1_tools.py
import yara
import hashlib
import math
import os
import requests
from typing import Dict, Any, List, Optional

class YaraScanner:
    """
    A class to manage YARA rules. It compiles each rule file individually to allow
    for both broad scanning (all enabled rules) and targeted scanning (a single rule).
    It now supports dynamic reloading of rules.
    """
    def __init__(self, rules_directory: str = 'src/rules/yara'):
        print("[INFO] Initializing YARA Scanner...")
        self.rules_directory = rules_directory
        # Ensure the rules directory exists
        os.makedirs(self.rules_directory, exist_ok=True)
        self.rule_details: Dict[str, Dict[str, Any]] = {}
        self.compiled_rules: Dict[str, yara.Rules] = {}
        self._load_and_parse_rules()
        self._compile_individual_rules()

    def _load_and_parse_rules(self):
        """Parses metadata from .yar files and stores it."""
        self.rule_details.clear() # Clear previous state before loading
        print("[INFO] Parsing YARA rule metadata...")
        rule_files = [f for f in os.listdir(self.rules_directory) if f.endswith(('.yar', '.yara'))]
        for filename in rule_files:
            rule_name = os.path.splitext(filename)[0]
            filepath = os.path.join(self.rules_directory, filename)
            meta = {}
            try:
                with open(filepath, 'r') as f:
                    in_meta_block = False
                    for line in f:
                        stripped_line = line.strip()
                        if stripped_line.lower().startswith("meta:"):
                            in_meta_block = True
                        elif in_meta_block and stripped_line == "}":
                            in_meta_block = False
                        elif in_meta_block and "=" in stripped_line:
                            key, val = stripped_line.split("=", 1)
                            meta[key.strip()] = val.strip().strip('"')
                
                # Preserve existing enabled/disabled state if possible
                enabled_status = self.rule_details.get(rule_name, {}).get('enabled', True)
                self.rule_details[rule_name] = {"meta": meta, "enabled": enabled_status, "filepath": filepath}
            except Exception as e:
                print(f"[ERROR] Could not parse metadata from {filename}: {e}")

    def _compile_individual_rules(self):
        """Compiles each YARA rule file individually for targeted scanning."""
        self.compiled_rules.clear() # Clear previous state
        print("[INFO] Compiling individual YARA rules...")
        for rule_name, details in self.rule_details.items():
            try:
                self.compiled_rules[rule_name] = yara.compile(filepaths={rule_name: details['filepath']})
            except Exception as e:
                print(f"[ERROR] Failed to compile rule {rule_name}: {e}")
        print(f"[INFO] Compiled {len(self.compiled_rules)} individual YARA rules.")
        
    def reload_rules(self):
        """Public method to reload and recompile all rules from disk."""
        print("[INFO] Reloading and recompiling all YARA rules...")
        self._load_and_parse_rules()
        self._compile_individual_rules()
        print("[INFO] YARA rules reloaded successfully.")

    def get_all_rules(self) -> Dict[str, Dict[str, Any]]:
        """Returns metadata and status for all loaded rules."""
        return {name: {"meta": details["meta"], "enabled": details["enabled"]} for name, details in self.rule_details.items()}

    def update_rule_status(self, rule_name: str, enabled: bool) -> Dict[str, Any]:
        """Enables or disables a specific rule."""
        if rule_name in self.rule_details:
            self.rule_details[rule_name]["enabled"] = enabled
            print(f"[INFO] Set rule '{rule_name}' status to {'Enabled' if enabled else 'Disabled'}")
            return {"status": "success", "rule": rule_name, "enabled": enabled}
        return {"status": "error", "message": f"Rule '{rule_name}' not found."}

    def scan_file(self, filepath: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Scans a file with either a specific rule or all enabled rules."""
        # This method's logic remains the same
        final_matches = []
        if rule_name:
            if rule_name not in self.compiled_rules: return {"error": f"Rule '{rule_name}' not found or not compiled."}
            if not self.rule_details.get(rule_name, {}).get("enabled", False): return {"matches": [], "count": 0, "info": f"Rule '{rule_name}' is currently disabled."}
            print(f"[T1 Tool] Scanning {filepath} with specific rule: {rule_name}...")
            try:
                matches = self.compiled_rules[rule_name].match(filepath=filepath)
                for match in matches: final_matches.append({"rule": match.rule, "namespace": match.namespace, "tags": match.tags, "meta": match.meta})
            except Exception as e: return {"error": f"Failed to scan file with rule {rule_name}: {str(e)}"}
        else:
            print(f"[T1 Tool] Scanning {filepath} with all enabled YARA rules...")
            for name, rule_set in self.compiled_rules.items():
                if self.rule_details.get(name, {}).get("enabled", False):
                    try:
                        matches = rule_set.match(filepath=filepath)
                        for match in matches: final_matches.append({"rule": match.rule, "namespace": name, "tags": match.tags, "meta": match.meta})
                    except Exception as e: print(f"[WARNING] Error during scan with rule {name}: {e}")
        return {"matches": final_matches, "count": len(final_matches)}

# --- Singleton instance to maintain state across the application ---
yara_scanner = YaraScanner()

# --- New Tool Functions for Rule CRUD Operations ---

def get_yara_rule_content(rule_name: str) -> Dict[str, Any]:
    """Reads and returns the content of a specific YARA rule file."""
    if rule_name in yara_scanner.rule_details:
        filepath = yara_scanner.rule_details[rule_name]['filepath']
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            return {"status": "success", "rule_name": rule_name, "content": content}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "error", "message": f"Rule '{rule_name}' not found."}

def save_yara_rule(rule_name: str, rule_content: str) -> Dict[str, Any]:
    """Saves content to a YARA rule file (creates or overwrites)."""
    # Basic validation for the rule name to prevent path traversal
    if not rule_name or not rule_name.isalnum():
        return {"status": "error", "message": "Rule name must be alphanumeric."}
    
    filepath = os.path.join(yara_scanner.rules_directory, f"{rule_name}.yar")
    try:
        with open(filepath, 'w') as f:
            f.write(rule_content)
        # Reload all rules to include the new/updated one
        yara_scanner.reload_rules()
        return {"status": "success", "message": f"Rule '{rule_name}' saved successfully."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def delete_yara_rule(rule_name: str) -> Dict[str, Any]:
    """Deletes a YARA rule file from the disk."""
    if rule_name in yara_scanner.rule_details:
        filepath = yara_scanner.rule_details[rule_name]['filepath']
        try:
            os.remove(filepath)
            # Reload all rules to reflect the deletion
            yara_scanner.reload_rules()
            return {"status": "success", "message": f"Rule '{rule_name}' deleted."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    return {"status": "error", "message": f"Rule '{rule_name}' not found."}


# --- Existing Agent-Callable Functions ---
def scan_file_with_yara(filepath: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
    return yara_scanner.scan_file(filepath, rule_name)

def get_yara_rules() -> Dict[str, Any]:
    return yara_scanner.get_all_rules()

def update_yara_rule_status(rule_name: str, enabled: bool) -> Dict[str, Any]:
    return yara_scanner.update_rule_status(rule_name, enabled)

def calculate_file_hash_and_entropy(filepath: str) -> Dict[str, Any]:
    try:
        sha256_hash = hashlib.sha256(); entropy = 0
        with open(filepath, "rb") as f: data = f.read()
        sha256_hash.update(data)
        if data:
            byte_counts = [data.count(byte) for byte in range(256)]
            for count in byte_counts:
                if count > 0: p_x = count / len(data); entropy -= p_x * math.log2(p_x)
        return {"sha256": sha256_hash.hexdigest(), "entropy": entropy}
    except Exception as e: return {"error": str(e)}

def query_virustotal_by_hash(file_hash: str) -> Dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key: return {"error": "VIRUSTOTAL_API_KEY not set."}
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"; headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 404: return {"status": "Not Found", "hash": file_hash}
        response.raise_for_status(); return response.json()
    except Exception as e: return {"error": str(e)}
