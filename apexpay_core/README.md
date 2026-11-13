# ApexPay-Core: Demonstration Showcase Application

`ApexPay-Core` is a purpose-built, realistic financial transaction and banking microservice designed specifically to showcase all the capabilities of the **AI Application Security & Risk Analyst** platform in live presentations.

---

## Architecture Overview

```
apexpay_core/
├── app.py             # Main REST API service (routing, HTTP controllers)
├── auth.py            # Authentication, JWT handling, role checks, password hashing
├── ledger.py          # Financial ledger, balance updates, transaction records
├── admin.py           # Administrative diagnostics, backup scripts, log management
├── database.py        # SQLite schema initialization and corporate mock seed
├── requirements.txt   # Outdated dependencies with known CVEs (SCA demo)
└── README.md          # Demonstration script & architecture walkthrough
```

---

## Vulnerabilities & Feature Mapping for Live Demos

| Component | Code Location | Vulnerability Type | Detection Engine | Exploit Chain / Platform Feature |
| :--- | :--- | :--- | :--- | :--- |
| **`auth.py`** | Line 10 | Hardcoded JWT Secret Key | AST / Semgrep / Pattern | Secret detection, credential exposure risk |
| **`auth.py`** | Line 18 | Insecure MD5 Password Hash | CodeQL / Semgrep Crypto | Cryptographic weakness |
| **`auth.py`** | Line 78 | Broken Access Control / Role Tampering | AST / Logic Analyzer | **Step 1 in Exploit Chain**: Privilege Escalation |
| **`ledger.py`** | Line 35 | Tainted SQL Query (`UPDATE accounts...`) | CodeQL / Semgrep Injection | **Critical Sink**: Financial ledger manipulation |
| **`app.py`** | Line 47 | Insecure Direct Object Reference (IDOR) | Process Analyzer / AST | **Entry Point**: Unauthorized account data access |
| **`app.py`** | Line 85 | Reflected Cross-Site Scripting (XSS) | Semgrep / CodeQL | Client-side injection vulnerability |
| **`admin.py`** | Line 21 | OS Command Injection (`subprocess.run`) | CodeQL Dataflow / Semgrep | **Critical Sink**: Remote Code Execution (RCE) |
| **`admin.py`** | Line 48 | Path Traversal (`open(...)`) | CodeQL / Semgrep | Arbitrary file disclosure |
| **`requirements.txt`** | - | Outdated `requests` & `urllib3` | Dependency Engine (SCA) | CVE tracking, automated fix recommendations |

---

## The 3-Step Live Exploit Chain Demonstration

When presenting the **Exploit Graph (ECG)** tab, walk the audience through this realistic attack scenario:

1. **Step 1 — Entry & Reconnaissance (IDOR):**  
   Attacker queries `/api/accounts/<account_id>` without session ownership verification to harvest corporate account IDs.
2. **Step 2 — Privilege Escalation (Broken Access Control):**  
   Attacker tampers with the unvalidated JWT claim or role header in `auth.py` (`check_is_admin`) to gain administrator context.
3. **Step 3 — Critical Exploitation (Remote Code Execution):**  
   With the escalated admin token, the attacker reaches `/api/admin/ping` where untrusted input reaches `subprocess.run(shell=True)` in `admin.py`, achieving full server takeover.

> **Key Presentation Point:** Point to the **Exploit Graph** tab to show how our **Constraint Satisfaction Attack Resolution (CSAR)** proves this 3-step chain is **feasible (rendered in green)**, while mathematically eliminating dozens of infeasible paths (cutting false alarms).

---

## Step-by-Step Presentation Script

1. **Start the Scan:**
   - In the Web UI dashboard, enter the path:  
     `c:\Users\vcvan\Downloads\Web-Application-Analyst-main\Web-Application-Analyst-main\apexpay_core`
   - Click **Run Scan**.
   - Show the live **streaming log terminal** as Semgrep, Python AST, Dependency Scanner, and the Graph Builders execute.
   - Total scan duration: **~15–25 seconds**.

2. **Executive Dashboard:**
   - Highlight the **Overall Risk Score** and **Risk Level (Critical/High)**.
   - Show the breakdown of Vulnerability Categories (Injection, Cryptography, Broken Access Control).

3. **Exploit Graph (Patent / Unique Feature):**
   - Click **Exploit Graph** on the sidebar.
   - Toggle between **STG (Semantic Transaction Graph)** and **ECG (Exploit Constraint Graph)**.
   - Point out the **green feasible edges** showing the verified attack paths.
   - Point out the **eliminated paths counter** proving how we filter out impossible exploit combinations that plague other SAST tools.

4. **Security Debt & Financial ROI:**
   - Open the **Security Debt** tab.
   - Show the calculated financial exposure ($ impact) and hours required for remediation.

5. **AI Dual-Remediation:**
   - Open **Dual AI Remediation**.
   - Select the SQL Injection finding from `ledger.py` or the Command Injection from `admin.py`.
   - Click **Generate Fix**.
   - Show the generated parameterized query / `subprocess` fix, and highlight the **AST syntax validation badge** that proves zero hallucination.
