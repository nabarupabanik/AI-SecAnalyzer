"""
Static analyzer dispatcher (plugin-style).

Combines:
- Python AST static rules (existing)
- Semgrep multi-language static analysis

Also performs normalization + deduplication before writing findings to model.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from typing import Iterable

from .models import ApplicationModel, VulnerabilityFinding
from .static_analyzer import analyze_single_python_file_static
from .analyzer_semgrep import run_semgrep_project_scan, semgrep_profile_from_env_only


SeverityValue = str


@dataclass
class StaticDispatchResult:
    findings: list[VulnerabilityFinding]
    python_findings: int
    semgrep_findings: int
    deduped: int
    semgrep_available: bool
    semgrep_profile: str
    semgrep_error: str | None = None


def normalize_severity(sev: str) -> SeverityValue:
    s = (sev or "").strip().lower()
    if s in {"critical", "high", "error"}:
        return "High"
    if s in {"medium", "warning"}:
        return "Medium"
    return "Low"


def normalize_type(vtype: str) -> str:
    s = (vtype or "").strip()
    low = s.lower()
    aliases = {
        "sqli": "SQL Injection",
        "sql injection": "SQL Injection",
        "command injection": "Command Injection",
        "xss": "Cross-Site Scripting (XSS)",
        "cross site scripting": "Cross-Site Scripting (XSS)",
        "hardcoded secret": "Hardcoded Secret",
        "weak cryptography": "Weak Cryptography",
    }
    for k, v in aliases.items():
        if k in low:
            return v
    return s or "Static Finding"


def _normalize_file_path(fp: str, project_path: str) -> str:
    if not fp:
        return fp
    
    # Normalize slashes first
    fp_norm = fp.replace("\\", "/")
    pp_norm = project_path.replace("\\", "/")
    
    # Check if fp_norm is under project_path (handling Windows drive prefix case-insensitively)
    fp_lower = fp_norm.lower()
    pp_lower = pp_norm.lower()
    
    if fp_lower.startswith(pp_lower):
        rel = fp_norm[len(pp_norm):]
        if rel.startswith("/"):
            rel = rel[1:]
        return rel
        
    p = Path(fp)
    base = Path(project_path)
    try:
        # If absolute and under project path, make it relative for consistency.
        if p.is_absolute():
            return str(p.relative_to(base)).replace("\\", "/")
    except Exception:
        pass
    return fp_norm


def _normalize_confidence(c: str) -> str:
    s = (c or "").strip().lower()
    if s in {"high", "medium", "low"}:
        return s.capitalize()
    return "Medium"


def _canonical_code_snippet(code: str) -> str:
    return " ".join((code or "").split()).strip().lower()


def _compute_fingerprint(v: VulnerabilityFinding) -> str:
    """
    Stable fingerprint intended to survive line-number shifts and small refactors.
    """
    p = Path(v.file or "")
    base = p.name.lower()
    material = "|".join(
        [
            (v.type or "").strip().lower(),
            (v.rule_id or "").strip().lower(),
            _canonical_code_snippet(v.code)[:280],
            base,
        ]
    )
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:40]


def normalize_finding(v: VulnerabilityFinding, project_path: str) -> VulnerabilityFinding:
    out = VulnerabilityFinding(
        file=_normalize_file_path(v.file, project_path),
        line=max(1, int(v.line or 1)),
        type=normalize_type(v.type),
        severity=normalize_severity(v.severity),  # type: ignore[arg-type]
        code=(v.code or "").strip(),
        analyzer=(v.analyzer or "python_ast").strip(),
        rule_id=(v.rule_id or "").strip(),
        confidence=_normalize_confidence(v.confidence),
        fingerprint=(v.fingerprint or "").strip(),
    )
    if not out.fingerprint:
        out.fingerprint = _compute_fingerprint(out)
    return out


def dedupe_findings(findings: Iterable[VulnerabilityFinding], project_path: str) -> list[VulnerabilityFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[VulnerabilityFinding] = []
    for raw in findings:
        v = normalize_finding(raw, project_path)
        key = (v.file, v.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def run_static_analysis_all_files(
    model: ApplicationModel,
    *,
    include_python_ast: bool = True,
    include_semgrep: bool = True,
) -> StaticDispatchResult:
    """
    Run static analysis plugins and update model.vulnerabilities.
    """
    collected: list[VulnerabilityFinding] = []
    py_count = 0
    semgrep_count = 0
    semgrep_available = False
    semgrep_error: str | None = None
    semgrep_profile = semgrep_profile_from_env_only()
    java_for_semgrep = [f for f in model.files if f.extension == ".java"]
    if semgrep_profile == "balanced" and java_for_semgrep:
        semgrep_profile = "java"

    if include_python_ast:
        for f in model.files:
            findings = analyze_single_python_file_static(f)
            for vv in findings:
                vv.analyzer = "python_ast"
                if not vv.rule_id:
                    vv.rule_id = f"pyast.{normalize_type(vv.type).lower().replace(' ', '_')}"
                if not vv.confidence:
                    vv.confidence = "Medium"
            py_count += len(findings)
            collected.extend(findings)

    if include_semgrep:
        sres = run_semgrep_project_scan(model.project_path, profile=semgrep_profile)
        semgrep_available = sres.engine_available
        semgrep_error = sres.error
        semgrep_count = len(sres.findings)
        collected.extend(sres.findings)

    deduped = dedupe_findings(collected, model.project_path)
    deduped_n = max(0, len(collected) - len(deduped))
    model.vulnerabilities = deduped

    return StaticDispatchResult(
        findings=deduped,
        python_findings=py_count,
        semgrep_findings=semgrep_count,
        deduped=deduped_n,
        semgrep_available=semgrep_available,
        semgrep_profile=semgrep_profile,
        semgrep_error=semgrep_error,
    )

