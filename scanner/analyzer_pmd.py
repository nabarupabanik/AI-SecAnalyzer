"""
PMD adapter (optional, Java-focused).

Runs PMD CLI when available and maps XML findings to VulnerabilityFinding.
Gracefully degrades when PMD is not installed or invocation fails.
"""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import VulnerabilityFinding
from .sandbox import run_subprocess_sandboxed


@dataclass
class PMDRunResult:
    findings: list[VulnerabilityFinding]
    engine_available: bool
    error: Optional[str] = None


def _sev(priority: str) -> str:
    # PMD priority 1..5 (1 highest)
    p = int(priority or 5)
    if p <= 2:
        return "High"
    if p <= 3:
        return "Medium"
    return "Low"


def parse_pmd_xml(xml_text: str) -> list[VulnerabilityFinding]:
    out: list[VulnerabilityFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out

    for file_node in root.findall(".//file"):
        file_name = (file_node.get("name") or "").replace("\\", "/")
        for v in file_node.findall("violation"):
            line = int(v.get("beginline", "1") or 1)
            rule = v.get("rule", "PMD Finding")
            ruleset = v.get("ruleset", "")
            priority = v.get("priority", "5")
            msg = (v.text or "").strip()
            out.append(
                VulnerabilityFinding(
                    file=file_name,
                    line=max(1, line),
                    type=rule[:120],
                    severity=_sev(priority),  # type: ignore[arg-type]
                    code=(msg or rule)[:240],
                    analyzer="pmd",
                    rule_id=f"{ruleset}:{rule}" if ruleset else rule,
                    confidence="Medium",
                )
            )
    return out


def run_pmd_project_scan(project_path: str) -> PMDRunResult:
    p = str(Path(project_path))
    with tempfile.TemporaryDirectory(prefix="sast_pmd_") as td:
        out_xml = str(Path(td) / "pmd.xml")
        cmd = [
            "pmd",
            "check",
            "-d",
            p,
            "-R",
            "rulesets/java/quickstart.xml",
            "-f",
            "xml",
            "-r",
            out_xml,
        ]
        try:
            cp = run_subprocess_sandboxed(cmd, cwd=p, capture_output=True, text=True, timeout=300.0)
        except FileNotFoundError:
            return PMDRunResult(findings=[], engine_available=False, error="pmd executable not found")
        except Exception as e:
            return PMDRunResult(findings=[], engine_available=True, error=f"pmd failed: {e}")

        # PMD may return non-zero when violations exist; still parse report if present.
        try:
            payload = Path(out_xml).read_text(encoding="utf-8", errors="replace")
        except Exception:
            err = (cp.stderr or cp.stdout or "").strip()
            return PMDRunResult(findings=[], engine_available=True, error=f"pmd error: {err[:260]}")
        return PMDRunResult(findings=parse_pmd_xml(payload), engine_available=True, error=None)

