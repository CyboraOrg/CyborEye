# 🛡️ CyborEye: Agentic Security Operations Framework

**CyborEye** is a next-generation, AI-powered framework designed to automate and augment the capabilities of a Security Operations Center (SOC). By leveraging a multi-agent system, CyborEye orchestrates complex analysis tasks across both log data and static files, dramatically reducing manual effort and accelerating incident response.

The core of CyborEye is its **hybrid AI architecture**, which combines the speed and reliability of a deterministic rule engine with the advanced reasoning and narrative-generation capabilities of Large Language Models (LLMs). This approach ensures that analysis is both fast and auditable for known threats, while still providing deep insights for novel or complex incidents.

---

## ✨ Core Features

-   **🤖 Multi-Agent System:** A hierarchical team of AI agents, led by a `SOC_Manager`, that can delegate tasks to specialized `Tier1` and `Tier3` analysts for in-depth analysis.
-   **🪵 Advanced Log Analysis Engine:**
    -   **Normalization:** Ingests diverse log formats into a Canonical Data Model (CDM).
    -   **Smart Triage Engine:** Uses a high-speed, deterministic engine with YAML-based rules to generate initial findings.
    -   **Correlation Engine:** Builds an "incident graph" in memory to connect disparate findings into a single, coherent incident narrative.
-   **🔬 Static File Analysis:**
    -   **YARA Engine:** Performs deep static analysis on files using a fully manageable set of YARA rules.
    -   **PE & Binary Analysis:** Extracts metadata, disassembles code, and checks file reputation against threat intelligence sources like VirusTotal.
-   **🖥️ Interactive UI:**
    -   **Conversational Interface:** A chat-based UI allows analysts to interact with the agentic system using natural language.
    -   **Full Rule Management:** A dedicated dashboard for viewing, editing, adding, deleting, and toggling both detection (`.yml`) and YARA (`.yar`) rules in real-time.

---

## 📦 Requirements

-   Python ≥ 3.9
-   [AutoGen](https://github.com/microsoft/autogen) for agent orchestration
-   [Streamlit](https://streamlit.io/) for the interactive web UI
-   [YARA-Python](https://yara-python.readthedocs.io/) for file scanning
-   An OpenAI-compatible LLM API
-   VirusTotal API key (optional, for threat reputation)

---

## 🔧 Installation & Setup

### 1. Clone the Repository

```bash
git clone [https://github.com/CyboraOrg/CyborEye.git](https://github.com/CyboraOrg/CyborEye.git)
cd CyborEye
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a .env file from the example template:

```bash
cp .env.example .env
```

Then, edit `.env` to include your actual API keys. The `BASE_AI_API_URL` is optional and can be used for custom or self-hosted models.

```
MODEL_TO_USE=gpt-4o-mini
OPENAI_API_KEY=sk-your-openai-key
BASE_AI_API_URL=[https://api.openai.com/v1](https://api.openai.com/v1)

# Optional key for file reputation checks
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

---

## 🚀 Running CyborEye
Launch the interactive web UI using Streamlit:

```Bash
python main.py
```

Navigate to the URL provided by Streamlit (usually `http://127.0.0.1:8000`) in your browser to access the CyborEye dashboard.

---

## 📝 How to Use
The CyborEye UI is designed to be intuitive for security analysts.

**Conversational Analysis**

1. **Upload an Artifact**: Use the sidebar to upload a file you want to analyze (this can be a log file like a `.json`, or a binary file like a `.exe` or `.dll`).
2. **Load the File**: Click the "Load File for Analysis" button to stage the artifact.
3. **Start Chatting**: Use the chat input at the bottom of the "Conversational Analysis" view to make requests in natural language.

**Example Prompts**:

- `"analyze this log file and give me a summary"`

- `"run a full tier 1 triage on the uploaded file"`

- `"scan this file with the APT29_VBS_Dropper yara rule"`

**Rule Management**

1. **Open Manager**: In the sidebar, click the "YARA Rule Management" button.
2. **View & Toggle**: See a list of all loaded YARA rules. Use the checkbox to enable or disable them for scans.
3. **Edit, Add, Delete**: Use the inline action buttons to edit existing rules, delete them, or add new rules from scratch using a live editor. All changes are re-compiled in real-time.

---

## 🔭 Future Work
1. **Graph Database Integration**: Migrate the in-memory Correlation Engine to a persistent graph database (like Neo4j) for advanced, cross-incident analysis.
2. **Stateful Correlation Rules**: Enhance the YAML rule engine to support stateful conditions (e.g., "alert if event A is followed by event B within 5 minutes").
3. **Automated Response Actions**: Equip agents with the ability to perform response actions, such as isolating a host or blocking an IP via API calls.
4. **Expanded Toolset**: Integrate more open-source tools for dynamic analysis (sandboxing), memory forensics, and network traffic analysis.
5. **LLM Fine-Tuning**: Fine-tune a smaller, open-source LLM on security-specific data to act as a more efficient SOC_Manager.

---

## 🤝 Contributing
Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License
This project is licensed under the GNU General Public License v3.0. See LICENSE for more information.

---

## 🧠 Credits
Built with ❤️ using AutoGen, Streamlit, YARA, and a whole lot of agentic reasoning.