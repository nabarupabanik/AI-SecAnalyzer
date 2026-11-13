# 🔐 AI SecAnalyzer — Web Application Security Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react)
![Semgrep](https://img.shields.io/badge/Semgrep-integrated-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

> An AI-powered static security analysis platform that scans web application codebases for vulnerabilities, exploit chains, malicious patterns, and tamperability risks — with dual-AI remediation powered by **Groq (Llama-3.1)** and **local Ollama**.

---

## 🚀 Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-Language Static Analysis** | Detects vulnerabilities across Python, JavaScript, Java, YAML, and more |
| 🧠 **Dual-AI Remediation Engine** | Combines deterministic AST transformations + Groq Cloud LLM + local Ollama for hallucination-free fix suggestions |
| 🔗 **Exploit Chain Graph (ECG)** | Visualises how individual vulnerabilities chain into full attack paths |
| 🌊 **Taint / Process Flow Analysis** | Tracks user-controlled data from source to sink across function boundaries |
| 🛡️ **Semgrep + CodeQL + PMD + SpotBugs** | Integrates best-in-class open-source SAST engines under one roof |
| 🦠 **Malicious Code Correlation** | Detects reverse shells, obfuscation, and exfiltration indicators |
| 🔧 **Tamperability Analysis** | Flags debug modes, exposed configs, weak session tokens, and admin backdoors |
| 📊 **Security Debt Scoring** | Quantifies long-term security risk with a composite risk formula |
| ⚡ **Live Streaming Scan (SSE)** | Real-time progress updates to the React dashboard via Server-Sent Events |
| 🗃️ **Scan History & Reports** | Persists all results in SQLite; export any scan as JSON |
| 🧪 **Patent-Grade Novel Claims Engine** | Generates patentable technical claims from unique analysis findings |

---

## 🏗️ Architecture

```mermaid
flowchart TD
    A[Input Sources] --> A1[Upload Folder from Frontend]
    A --> A2[Server Path Queue]
    A1 --> B[API Layer: Flask]
    A2 --> B

    B --> B1[/api/upload-scan-stream]
    B --> B2[/api/upload-scan]
    B --> B3[/api/scan-async → ScanJob Worker]
    B1 --> C
    B2 --> C
    B3 --> C

    C[Scan Orchestrator\nstream_project_scan] --> D1[Stage 1: Initialization]
    D1 --> D2[Stage 2: File Scanning + Language Detection]
    D2 --> D3[Stage 3: AST Parsing]
    D3 --> D4[Stage 4: Static Analysis\nAST + Binary + Semgrep + CodeQL]
    D4 --> D5[Stage 5: Taint & Process Flow Analysis]
    D5 --> D6[Stage 6: Malicious Code Correlation]
    D6 --> D7[Stage 7: Tamperability Analysis]
    D7 --> D8[Stage 8: Risk Scoring\nR = 0.30S + 0.30P + 0.25M + 0.15T]
    D8 --> D9[Stage 9: Report Assembly]

    D9 --> G[Live SSE Logs + Result JSON]
    D9 --> H[SQLite via SQLAlchemy]
    D9 --> I[React Frontend Dashboard]
```

---

## 🛠️ Tech Stack

**Backend**
- Python 3.10+, Flask 3.x, SQLAlchemy 2.x
- Semgrep, CodeQL, PMD, SpotBugs (pluggable SAST engines)
- Groq API (Llama-3.1-70B), Ollama (local LLM)
- NetworkX (exploit chain graph), YARA (binary rules)

**Frontend**
- React 18 + TypeScript + Vite
- Interactive graph visualisations (ECG, STG, Process Graph)
- Server-Sent Events for live scan streaming

**Database**
- SQLite (via SQLAlchemy ORM) — zero-config, fully embedded

---

## ⚙️ Installation

```bash
# 1. Clone the repo
git clone https://github.com/nabarupabanik/AI-SecAnalyzer.git
cd AI-SecAnalyzer

# 2. Install Python dependencies
pip install -r requirements-api.txt

# 3. (Optional) Install frontend dependencies
cd frontend
npm install
npm run dev
cd ..
```

---

## 🖥️ Running the Project

### CLI Scanner (Quick Scan)
```bash
python main.py ./your_project_path
# With JSON output
python main.py ./your_project_path --output results.json
```

### Full API Server (with Frontend)
```bash
# Start the Flask API backend
python api_server.py

# In a separate terminal, start the React frontend
cd frontend && npm run dev
```

Then open **http://localhost:5173** in your browser.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Run a full scan on a path |
| `POST` | `/api/upload-scan-stream` | Streaming scan via file upload (SSE) |
| `GET` | `/api/scans` | List all past scans |
| `GET` | `/api/scans/<id>` | Get full scan detail |
| `GET` | `/api/scans/<id>/export` | Export scan as JSON report |
| `DELETE` | `/api/scans/<id>` | Delete a scan record |

---

## 📊 Sample Scan Output

```
  +=======================================================+
  |   AI SecAnalyzer — Application Security Scanner      |
  +=======================================================+

  Scanning: ./sample_project

  ┌──────────────────────┬───────┬──────────────┐
  │ Language / Type      │ Files │ % of Project │
  ├──────────────────────┼───────┼──────────────┤
  │ Python               │     3 │        50.0% │
  │ JavaScript           │     1 │        16.7% │
  │ YAML                 │     1 │        16.7% │
  └──────────────────────┴───────┴──────────────┘

  Vulnerabilities Detected:
  🔴 CRITICAL  app.py:36   Command Injection (subprocess.run with shell=True)
  🔴 CRITICAL  app.py:36   User Input → System Call (tainted data flow)
  🟠 HIGH      app.py:28   SQL Injection (unsanitised f-string query)
  🟡 MEDIUM    app.py:14   Hardcoded Secret (DB_PASSWORD)
  🟡 MEDIUM    login.py:11 Weak Cryptography (MD5 password hashing)

  Overall Risk Score: 24 / 100
  ✔ Report saved → output/app_model.json
```

---

## 🧠 Dual-AI Remediation

The remediation engine uses a **three-layer approach** to generate safe, production-ready fixes:

1. **Deterministic AST Transformations** — 100% rule-based, zero hallucination risk (e.g. auto-replace `MD5` → `bcrypt`)
2. **Local Ollama** — Air-gapped LLM for sensitive/private codebases
3. **Groq Llama-3.1-70B** — Cloud LLM for complex multi-file reasoning

Each fix goes through a **Feasibility & Safety Validation Layer** (AST syntax check + hallucination index scoring) before being presented.

---

## 📁 Project Structure

```
AI-SecAnalyzer/
├── scanner/                   # Core analysis engine (45+ modules)
│   ├── static_analyzer.py     # Python AST rule engine
│   ├── analyzer_semgrep.py    # Semgrep integration
│   ├── analyzer_codeql.py     # CodeQL integration
│   ├── ecg_builder.py         # Exploit Chain Graph builder
│   ├── stg_builder.py         # Symbolic Taint Graph builder
│   ├── dual_ai_remediation.py # Groq + Ollama AI fix engine
│   ├── tamper_analyzer.py     # Tamperability detection
│   ├── security_debt_analyzer.py
│   └── ...
├── frontend/                  # React + TypeScript dashboard
│   └── src/pages/             # Vulnerabilities, Process Graph, Reports...
├── database/                  # SQLAlchemy ORM models + SQLite
├── api_server.py              # Flask REST API (2000+ lines)
├── main.py                    # CLI entry point
├── sample_project/            # Intentionally vulnerable app (for testing)
└── tests/                     # pytest test suite (30+ test files)
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 🔬 Novel Technical Contributions

- **Constraint-Satisfying Attack Reasoning (CSAR)** — prunes false-positive exploit chains using symbolic constraint solving
- **Exploit Chain Graph (ECG)** with visual proof panels
- **Symbolic Taint Graph (STG)** for cross-function taint propagation
- **Incremental Semgrep Manifest** — caches prior scan results for faster re-scans
- **Patent Claims Engine** — auto-generates patentable technical claims from findings

---

## 👩‍💻 Author

**Nabarupa Banik**
- GitHub: [@nabarupabanik](https://github.com/nabarupabanik)

---

> ⭐ If you find this project useful, consider starring the repo!
