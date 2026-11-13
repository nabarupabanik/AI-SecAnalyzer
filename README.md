# AI SecAnalyzer — Web Application Security Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![React](https://img.shields.io/badge/React-TypeScript-61DAFB?logo=react)
![Semgrep](https://img.shields.io/badge/Semgrep-integrated-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

An AI-powered static security analysis platform that scans web application codebases for vulnerabilities, exploit chains, malicious patterns, and tamperability risks — with dual-AI remediation powered by **Groq (Llama-3.1)** and **local Ollama**.

---

## Features

| Feature | Description |
|---------|-------------|
| Multi-Language Static Analysis | Detects vulnerabilities across Python, JavaScript, Java, YAML, and more |
| Dual-AI Remediation Engine | Combines deterministic AST transformations + Groq Cloud LLM + local Ollama for hallucination-free fix suggestions |
| Exploit Chain Graph (ECG) | Visualises how individual vulnerabilities chain into full attack paths |
| Taint / Process Flow Analysis | Tracks user-controlled data from source to sink across function boundaries |
| Semgrep + CodeQL + PMD + SpotBugs | Integrates best-in-class open-source SAST engines under one roof |
| Malicious Code Correlation | Detects reverse shells, obfuscation, and exfiltration indicators |
| Tamperability Analysis | Flags debug modes, exposed configs, weak session tokens, and admin backdoors |
| Security Debt Scoring | Quantifies long-term security risk with a composite risk formula |
| Live Streaming Scan (SSE) | Real-time progress updates to the React dashboard via Server-Sent Events |
| Scan History and Reports | Persists all results in SQLite; export any scan as JSON |

---

## Architecture

```mermaid
flowchart TD
    A[Input Sources] --> A1[Upload Folder from Frontend]
    A --> A2[Server Path Queue]
    A1 --> B[API Layer: Flask]
    A2 --> B

    B --> B1[/api/upload-scan-stream]
    B --> B2[/api/upload-scan]
    B --> B3[/api/scan-async - ScanJob Worker]
    B1 --> C
    B2 --> C
    B3 --> C

    C[Scan Orchestrator - stream_project_scan] --> D1[Stage 1: Initialization]
    D1 --> D2[Stage 2: File Scanning and Language Detection]
    D2 --> D3[Stage 3: AST Parsing]
    D3 --> D4[Stage 4: Static Analysis - AST + Binary + Semgrep + CodeQL]
    D4 --> D5[Stage 5: Taint and Process Flow Analysis]
    D5 --> D6[Stage 6: Malicious Code Correlation]
    D6 --> D7[Stage 7: Tamperability Analysis]
    D7 --> D8[Stage 8: Risk Scoring - R = 0.30S + 0.30P + 0.25M + 0.15T]
    D8 --> D9[Stage 9: Report Assembly]

    D9 --> G[Live SSE Logs and Result JSON]
    D9 --> H[SQLite via SQLAlchemy]
    D9 --> I[React Frontend Dashboard]
```

---

## Tech Stack

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
- SQLite via SQLAlchemy ORM — zero-config, fully embedded

---

## Installation

```bash
# Clone the repository
git clone https://github.com/nabarupabanik/AI-SecAnalyzer.git
cd AI-SecAnalyzer

# Install Python dependencies
pip install -r requirements-api.txt

# Install frontend dependencies (optional)
cd frontend
npm install
npm run dev
cd ..
```

---

## Usage

### CLI Scanner

```bash
python main.py ./your_project_path

# With JSON output
python main.py ./your_project_path --output results.json
```

### API Server with Frontend

```bash
# Start the Flask API backend
python api_server.py

# In a separate terminal, start the React frontend
cd frontend && npm run dev
```

Open `http://localhost:5173` in your browser.

### API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan` | Run a full scan on a directory path |
| POST | `/api/upload-scan-stream` | Streaming scan via file upload (SSE) |
| GET | `/api/scans` | List all past scans |
| GET | `/api/scans/<id>` | Get full scan detail |
| GET | `/api/scans/<id>/export` | Export scan as JSON report |
| DELETE | `/api/scans/<id>` | Delete a scan record |

---

## Sample Output

```
  +=======================================================+
  |   AI SecAnalyzer - Application Security Scanner      |
  +=======================================================+

  Scanning: ./sample_project

  Language Breakdown:
  Python               3 files   50.0%
  JavaScript           1 file    16.7%
  YAML                 1 file    16.7%

  Vulnerabilities Detected:
  [CRITICAL]  app.py:36   Command Injection (subprocess.run with shell=True)
  [CRITICAL]  app.py:36   User Input to System Call (tainted data flow)
  [HIGH]      app.py:28   SQL Injection (unsanitised f-string query)
  [MEDIUM]    app.py:14   Hardcoded Secret (DB_PASSWORD)
  [MEDIUM]    login.py:11 Weak Cryptography (MD5 password hashing)

  Overall Risk Score: 24 / 100
  Report saved -> output/app_model.json
```

---

## Dual-AI Remediation

The remediation engine uses a three-layer approach to generate safe, production-ready fixes:

1. **Deterministic AST Transformations** — Rule-based, zero hallucination risk (e.g. auto-replace MD5 with bcrypt)
2. **Local Ollama** — Air-gapped LLM for sensitive or private codebases
3. **Groq Llama-3.1-70B** — Cloud LLM for complex multi-file reasoning

Each fix passes through a **Feasibility and Safety Validation Layer** (AST syntax check + hallucination index scoring) before being presented to the user.

---

## Project Structure

```
AI-SecAnalyzer/
├── scanner/                      # Core analysis engine (45+ modules)
│   ├── static_analyzer.py        # Python AST rule engine
│   ├── analyzer_semgrep.py       # Semgrep integration
│   ├── analyzer_codeql.py        # CodeQL integration
│   ├── ecg_builder.py            # Exploit Chain Graph builder
│   ├── stg_builder.py            # Symbolic Taint Graph builder
│   ├── dual_ai_remediation.py    # Groq + Ollama AI fix engine
│   ├── tamper_analyzer.py        # Tamperability detection
│   ├── security_debt_analyzer.py # Security debt scoring
│   └── ...
├── frontend/                     # React + TypeScript dashboard
│   └── src/pages/                # Vulnerabilities, Process Graph, Reports...
├── database/                     # SQLAlchemy ORM models + SQLite
├── api_server.py                 # Flask REST API
├── main.py                       # CLI entry point
├── sample_project/               # Intentionally vulnerable app (for testing)
└── tests/                        # pytest test suite (30+ test files)
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Novel Technical Contributions

- **Constraint-Satisfying Attack Reasoning (CSAR)** — Prunes false-positive exploit chains using symbolic constraint solving
- **Exploit Chain Graph (ECG)** — Directed graph with visual proof panels linking individual findings into full attack scenarios
- **Symbolic Taint Graph (STG)** — Cross-function taint propagation with source-to-sink path resolution
- **Incremental Semgrep Manifest** — Caches prior scan results for faster re-scans on unchanged files
- **Patent Claims Engine** — Auto-generates patentable technical claims from novel analysis findings

---

## Author

**Nabarupa Banik**  
GitHub: [nabarupabanik](https://github.com/nabarupabanik)
