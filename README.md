# 🛡️ Agentic SOC - Static File Analysis (MVP)

Agentic SOC is an AI-powered Security Operations Center framework in development. This MVP demonstrates autonomous, multi-agent coordination to perform in-depth static analysis on Portable Executable (PE) files. It combines AI agents for metadata inspection, disassembly analysis, reputation checking, and verdict generation — paving the way for a fully automated malware triage pipeline.

---

## 📦 Requirements

- Python ≥ 3.9
- [LIEF](https://lief.quarkslab.com/) for parsing PE files
- OpenAI-compatible LLM (e.g., OpenAI, TapSage)
- VirusTotal API key (for threat reputation check)
- Internet access for API queries

---

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/agentic-soc.git
cd agentic-soc
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file based on the provided template:

```bash
cp .env.example .env
```

Then, edit `.env` to include your actual API keys:

```env
MODEL_TO_USE=gpt-4o-mini
OPENAI_API_KEY=sk-your-openai-key
BASE_AI_API_URL=https://api.tapsage.com/api/v1/wrapper/openai_chat_completion

VT_API_KEY=your-virustotal-api-key
HOST_IP=127.0.0.1
```

Environment variables are automatically loaded using `python-dotenv`.

---

## 🚀 How to Run

### 🧠 Agentic Static PE Analyzer via API

Run the system:

```bash
python main.py
```

This launches a Flask API server and loads the agentic analysis system.

---

## 📤 API Usage

### 📌 Endpoint

```
POST /upload
```

### 🧪 Example Request with `curl`

```bash
curl -X POST -F "file=@yourfile.exe" http://127.0.0.1:5000/upload
```

### ✅ Response Format

```json
{
  "status": "success",
  "filename": "yourfile.exe",
  "result": {
    "hash_data": { ... },
    "vt_result": { ... },
    "pe_summary": "...",
    "disasm_summary": "...",
    "verdict": "..."
  }
}
```

The system automatically performs:

- Hash and entropy analysis
- VirusTotal reputation check
- PE metadata reasoning
- Disassembly-based inspection
- Final verdict generation (with confidence and justification)

---

## 🔭 Future Work

Planned enhancements for evolving Agentic SOC into a full-scale autonomous security solution:

- ⚙️ **ELF & Mach-O support** for cross-platform analysis
- 🧵 **String extractor** for IOCs and readable content
- 🕸 **YARA rule engine** integration
- 🔐 **Entropy visualization** and section heatmaps
- 🧠 **LLM-based feature extraction** and vector embeddings
- 🗃 **Dynamic sandbox stub** for hybrid analysis
- 📡 **Threat intelligence fusion** (OTX, AbuseIPDB, etc.)
- 🧩 **Agent memory and recall** for cross-case reasoning
- 🔁 **Multi-agent orchestration** with retry/error handling
- 📊 **Web UI for SOC operators** (Streamlit dashboard)

Suggestions welcome! Open an issue or PR.

---

## 🤝 Contributing

We welcome contributions of all types — features, bugfixes, or feedback.

1. Fork the repository
2. Create your feature branch:  
   `git checkout -b feature/my-feature`
3. Commit your changes:  
   `git commit -m 'Add my feature'`
4. Push the branch:  
   `git push origin feature/my-feature`
5. Open a pull request

Please follow clean code practices and write descriptive commits.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.  
You are free to use, modify, and distribute it, as long as you **preserve this license** and release derivative works under the **same license**.

---

## 🧠 Credits

Built with ❤️ using [AutoGen](https://github.com/microsoft/autogen), [LIEF](https://lief.quarkslab.com/), and a dash of agentic reasoning.