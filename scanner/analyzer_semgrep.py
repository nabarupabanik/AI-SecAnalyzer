"""
Semgrep-backed static analyzer plugin.

This plugin runs Semgrep against the scanned project directory and maps
Semgrep JSON findings to VulnerabilityFinding entries.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import VulnerabilityFinding
from .sandbox import run_subprocess_sandboxed, semgrep_timeout_s


@dataclass
class SemgrepRunResult:
    findings: list[VulnerabilityFinding]
    engine_available: bool
    error: Optional[str] = None
    # Findings dropped by SAST_SEMGREP_MIN_SEVERITY / exclude rules (noise control).
    filtered_from_results: int = 0


_COMPREHENSIVE_PACKS = [
    # Default multi-repo SAST stack: OWASP, CWE, injection classes, Node/JS, secrets, JWT, multi-language, etc.
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/security-audit",
    "p/r2c-security-audit",
    "p/secrets",
    "p/gitleaks",
    "p/command-injection",
    "p/sql-injection",
    "p/xss",
    "p/javascript",
    "p/nodejs",
    "p/jwt",
    "p/trailofbits",
    "p/react",
    "p/java",
    "p/findsecbugs",
    "p/python",
    "p/bandit",
]

SEMGREP_PROFILES: dict[str, list[str]] = {
    # Good default signal/noise ratio for appsec scanning.
    "balanced": ["p/owasp-top-ten", "p/security-audit"],
    # More aggressive checks, higher noise.
    "strict": ["p/owasp-top-ten", "p/security-audit", "p/secrets", "p/command-injection"],
    # Experimental profile can include noisier ecosystem rules.
    "experimental": ["p/owasp-top-ten", "p/security-audit", "p/secrets", "p/trailofbits"],
    # Java-focused profile for Java-heavy repositories.
    "java": ["p/java", "p/security-audit"],
    "comprehensive": list(_COMPREHENSIVE_PACKS),
    "dvws": list(_COMPREHENSIVE_PACKS),  # alias for API/backward compatibility
}


def default_semgrep_profile_name() -> str:
    """Default multi-language SAST rule stack for any repository (backend default, not UI opt-in)."""
    return "comprehensive"


def semgrep_profile_from_env_only() -> str:
    """Honor SAST_SEMGREP_PROFILE when set and known; otherwise default_semgrep_profile_name()."""
    raw = os.environ.get("SAST_SEMGREP_PROFILE", "").strip().lower()
    if raw and raw in SEMGREP_PROFILES:
        return raw
    return default_semgrep_profile_name()


def _map_semgrep_severity(raw: str) -> str:
    """Map Semgrep severities to our Low/Medium/High scale."""
    s = (raw or "").strip().lower()
    if s in {"error", "high", "critical"}:
        return "High"
    if s in {"warning", "medium"}:
        return "Medium"
    return "Low"


def _severity_floor_rank(sev: str) -> int:
    """Higher = more serious. Used with min-severity threshold."""
    s = (sev or "").strip().lower()
    if s == "high":
        return 2
    if s == "medium":
        return 1
    return 0


def _effective_min_severity_for_profile(profile: str) -> str:
    """
    Minimum finding severity to keep after Semgrep runs.

    Env SAST_SEMGREP_MIN_SEVERITY: high | medium | low (default depends on profile).
    Default comprehensive stack uses medium (drop Low) to cut noise unless env set.
    Lighter profiles (e.g. balanced) keep all severities unless env set.
    """
    raw = os.environ.get("SAST_SEMGREP_MIN_SEVERITY", "").strip().lower()
    if raw in ("high", "medium", "low"):
        return raw
    if profile in ("comprehensive", "dvws"):
        return "medium"
    return "low"


def _exclude_rule_substrings() -> list[str]:
    raw = os.environ.get("SAST_SEMGREP_EXCLUDE_RULE_SUBSTR", "").strip()
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def _finding_passes_noise_filters(
    check_id: str,
    mapped_severity: str,
    *,
    min_severity: str,
    exclude_substrings: list[str],
) -> bool:
    if _severity_floor_rank(mapped_severity) < _severity_floor_rank(min_severity):
        return False
    low = check_id.lower()
    for sub in exclude_substrings:
        if sub.lower() in low:
            return False
    return True


def semgrep_filter_fingerprint(profile: str) -> str:
    """Serialized noise controls for incremental Semgrep cache invalidation."""
    ms = _effective_min_severity_for_profile(profile)
    ex = ",".join(sorted({x.strip().lower() for x in _exclude_rule_substrings() if x.strip()}))
    return f"{ms}|{ex}"


def _short_type(check_id: str, message: str) -> str:
    cid = (check_id or "").strip()
    msg = (message or "").strip()
    if not cid and not msg:
        return "Semgrep Finding"

    # Favor readable "type" text for UI; keep a short check id suffix if useful.
    base = msg.split(".")[0].strip() if msg else cid.replace(".", " ").replace("-", " ")
    if len(base) > 100:
        base = base[:97] + "..."
    if cid and cid not in base and len(cid) <= 36:
        return f"{base} [{cid}]"
    return base or "Semgrep Finding"


def _confidence_for_semgrep(extra: dict) -> str:
    sev = _map_semgrep_severity(str(extra.get("severity") or ""))
    # Semgrep metadata confidence is not guaranteed; use severity-weighted default.
    meta = extra.get("metadata") or {}
    c = str(meta.get("confidence") or "").strip().lower()
    if c in {"high", "medium", "low"}:
        return c.capitalize()
    if sev == "High":
        return "High"
    if sev == "Medium":
        return "Medium"
    return "Low"


def _semgrep_timeout_for_profile(profile: str) -> float:
    base = float(semgrep_timeout_s())
    if profile in ("comprehensive", "dvws", "experimental", "strict"):
        return max(base, 900.0)
    return base


def run_semgrep_project_scan(project_path: str, profile: str = "balanced") -> SemgrepRunResult:
    """
    Run semgrep recursively on project_path and return mapped findings.
    Gracefully degrades when semgrep is unavailable or returns malformed JSON.
    """
    path = str(Path(project_path))

    # Semgrep exits non-zero when findings exist depending on flags; we use --error
    # handling by parsing JSON output regardless of exit code.
    chosen = profile if profile in SEMGREP_PROFILES else "balanced"
    configs = SEMGREP_PROFILES[chosen]

    cmd = [
        "semgrep",
        "--json",
        "--quiet",
        "--metrics=off",
        "--exclude",
        "node_modules",
        "--exclude",
        ".venv",
        "--exclude",
        "venv",
        "--exclude",
        ".git",
        "--exclude",
        "dist",
        "--exclude",
        "build",
    ]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.append(path)

    try:
        proc = run_subprocess_sandboxed(
            cmd,
            cwd=path if os.path.isdir(path) else None,
            capture_output=True,
            text=True,
            timeout=_semgrep_timeout_for_profile(chosen),
        )
    except FileNotFoundError:
        return SemgrepRunResult(
            findings=[],
            engine_available=False,
            error="semgrep executable not found",
        )
    except subprocess.TimeoutExpired:
        return SemgrepRunResult(
            findings=[],
            engine_available=True,
            error="semgrep timed out",
        )
    except Exception as e:
        return SemgrepRunResult(
            findings=[],
            engine_available=True,
            error=f"semgrep failed: {e}",
        )

    output = (proc.stdout or "").strip()
    if not output:
        # If semgrep outputs only stderr for failures, surface it as warning.
        err = (proc.stderr or "").strip() or "empty semgrep output"
        return SemgrepRunResult(findings=[], engine_available=True, error=err)

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        err_text = (proc.stderr or "").strip()
        return SemgrepRunResult(
            findings=[],
            engine_available=True,
            error=f"invalid semgrep json output{': ' + err_text if err_text else ''}",
        )

    results = payload.get("results") or []
    min_sev = _effective_min_severity_for_profile(chosen)
    exclude_subs = _exclude_rule_substrings()
    out: list[VulnerabilityFinding] = []
    filtered = 0
    for r in results:
        p = str(r.get("path") or "")
        start = r.get("start") or {}
        line = int(start.get("line") or 1)
        extra = r.get("extra") or {}
        msg = str(extra.get("message") or "").strip()
        sev = _map_semgrep_severity(str(extra.get("severity") or ""))
        check_id = str(r.get("check_id") or "").strip()
        if not _finding_passes_noise_filters(check_id, sev, min_severity=min_sev, exclude_substrings=exclude_subs):
            filtered += 1
            continue
        code = str(extra.get("lines") or "").rstrip("\n")
        if not code:
            code = msg

        out.append(
            VulnerabilityFinding(
                file=p,
                line=line,
                type=_short_type(check_id, msg),
                severity=sev,  # type: ignore[arg-type]
                code=code,
                analyzer="semgrep",
                rule_id=check_id,
                confidence=_confidence_for_semgrep(extra),
            )
        )

    return SemgrepRunResult(findings=out, engine_available=True, error=None, filtered_from_results=filtered)

