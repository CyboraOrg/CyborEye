import json
import lief

def parse_pe(filepath):
    try:
        binary = lief.parse(filepath)
        return json.loads(lief.to_json(binary))
    except Exception as e:
        return {"error": f"Failed to parse PE file: {str(e)}"}