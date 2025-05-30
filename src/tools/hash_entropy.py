import hashlib
import math

def calculate_hash_entropy(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        byte_freq = [0] * 256
        for b in data:
            byte_freq[b] += 1

        entropy = -sum((f / len(data)) * math.log2(f / len(data))
                       for f in byte_freq if f > 0)

        return {
            "md5": md5,
            "sha256": sha256,
            "entropy": round(entropy, 2),
            "filesize": len(data)
        }
    except Exception as e:
        return {"error": f"Failed to process file: {str(e)}"}