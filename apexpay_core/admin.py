"""
ApexPay-Core Administrative Diagnostics & Maintenance Service
Provides server diagnostics, backup triggers, and operational maintenance.
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Any


def run_network_diagnostic(target_host: str) -> Dict[str, Any]:
    """
    Run network ping and reachability diagnostic for payment clearing houses.
    
    VULNERABILITY (Critical OS Command Injection):
    User-supplied target_host parameter is concatenated directly into a shell command
    without sanitization or escaping.
    """
    # VULNERABILITY: OS Command Injection via shell=True
    cmd = f"ping -n 1 {target_host}"
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "status": "success",
            "host": target_host,
            "output": proc.stdout or proc.stderr,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def trigger_database_backup(backup_target_name: str) -> Dict[str, Any]:
    """
    Trigger scheduled database archive.
    VULNERABILITY: Second command injection sink using os.system.
    """
    # VULNERABILITY: os.system with user-supplied parameter
    archive_cmd = f"tar -czf backups/{backup_target_name}.tar.gz apexpay.db"
    exit_code = os.system(archive_cmd)
    return {"status": "initiated", "target": backup_target_name, "code": exit_code}


def read_system_audit_log(filename: str) -> str:
    """
    Read an administrative audit log from disk.
    
    VULNERABILITY (Path Traversal / Arbitrary File Read):
    Directly concatenates user filename parameter without resolving realpath
    or checking directory boundary escapes (e.g., ../../../etc/passwd).
    """
    logs_dir = Path(__file__).parent / "logs"
    logs_dir.mkdir(exist_ok=True)
    
    target_path = logs_dir / filename
    # VULNERABILITY: Insecure direct file opening without boundary validation
    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()
