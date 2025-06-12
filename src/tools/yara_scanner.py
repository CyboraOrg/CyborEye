import os
import yara
import json

class YaraScanner:
    def __init__(self, rules_directory: str):
        self.rules_directory = rules_directory
        self.rules = self._compile_rules()

    def _compile_rules(self):
        files = {
            fname: os.path.join(self.rules_directory, fname)
            for fname in os.listdir(self.rules_directory)
            if fname.endswith(('.yar', '.yara'))
        }
        if not files:
            raise FileNotFoundError("No YARA rule files found.")
        try:
            return yara.compile(filepaths=files)
        except yara.SyntaxError as e:
            raise RuntimeError(f"YARA compile error: {e}")

    def scan_file(self, file_path: str) -> dict:
        result = {"file": os.path.basename(file_path), "matches": [], "error": None}
        if not os.path.isfile(file_path):
            result["error"] = "File not found"
            return result
        try:
            matches = self.rules.match(filepath=file_path)
            for m in matches:
                result["matches"].append({
                    "rule": m.rule,
                    "meta": m.meta
                })
        except Exception as e:
            result["error"] = str(e)
        return result

# Example usage
# if __name__ == '__main__':
#     scanner = YaraScanner(rules_directory='src/yara_rules')
#     out = scanner.scan_file('samples/file/malware_eicar.txt')
#     print(json.dumps(out, indent=2))