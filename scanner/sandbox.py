"""
Sandbox-style subprocess execution for external analyzers (Semgrep).

Controlled by environment:
  SAST_SANDBOX=1          Prefer isolated flags (no new window on Windows, process group on Unix)
  SAST_SEMGREP_TIMEOUT    Override default timeout seconds (default 180)

Semgrep noise control (see analyzer_semgrep.py):
  SAST_SEMGREP_MIN_SEVERITY   high | medium | low — default medium for default comprehensive stack, low for lighter profiles
  SAST_SEMGREP_EXCLUDE_RULE_SUBSTR  comma-separated substrings; matching check_id is dropped (case-insensitive)
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Any


def semgrep_timeout_s() -> int:
    raw = os.environ.get("SAST_SEMGREP_TIMEOUT", "180").strip()
    try:
        return max(30, int(raw))
    except ValueError:
        return 180


def run_subprocess_sandboxed(
    cmd: list[str],
    *,
    cwd: str | None = None,
    timeout: float | None = None,
    capture_output: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    """
    Run a subprocess with conservative sandbox-ish defaults.
    Not a real OS sandbox; reduces accidental shell injection and UI noise.
    """
    timeout = timeout if timeout is not None else float(semgrep_timeout_s())
    kwargs: dict[str, Any] = {
        "cwd": cwd,
        "capture_output": capture_output,
        "text": text,
        "timeout": timeout,
        "shell": False,
        "check": False,
    }
    if os.environ.get("SAST_SANDBOX", "").strip() in ("1", "true", "yes"):
        if sys.platform == "win32":
            # Avoid console window flash for GUI-launched API servers.
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            kwargs["start_new_session"] = True

    return subprocess.run(cmd, **kwargs)
