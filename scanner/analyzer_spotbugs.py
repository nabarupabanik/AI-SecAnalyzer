"""
SpotBugs adapter (optional, Java-focused).

Runs SpotBugs CLI when available and maps XML findings to VulnerabilityFinding.
Gracefully degrades when SpotBugs is not installed or invocation fails.
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
class SpotBugsRunResult:
    findings: list[VulnerabilityFinding]
    engine_available: bool
    error: Optional[str] = None


def _severity(rank: int) -> str:
    if rank <= 4:
        return "High"
    if rank <= 10:
        return "Medium"
    return "Low"


def parse_spotbugs_xml(xml_text: str) -> list[VulnerabilityFinding]:
    out: list[VulnerabilityFinding] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out

    for bug in root.findall(".//BugInstance"):
        bug_type = bug.get("type", "SpotBugs Finding")
        rank = int(bug.get("rank", "15") or 15)
        priority = bug.get("priority", "")
        line = 1
        file_path = ""
        src = bug.find(".//SourceLine")
        if src is not None:
            file_path = src.get("sourcepath") or src.get("classname") or ""
            line = int(src.get("start", "1") or 1)

        msg = ""
        long_msg = bug.find("LongMessage")
        short_msg = bug.find("ShortMessage")
        if long_msg is not None and long_msg.text:
            msg = long_msg.text.strip()
        elif short_msg is not None and short_msg.text:
            msg = short_msg.text.strip()

        out.append(
            VulnerabilityFinding(
                file=file_path.replace("\\", "/"),
                line=max(1, line),
                type=msg.split(".")[0][:120] if msg else bug_type,
                severity=_severity(rank),  # type: ignore[arg-type]
                code=(msg or bug_type)[:240],
                analyzer="spotbugs",
                rule_id=bug_type,
                confidence="High" if str(priority) in ("1", "2") else "Medium",
            )
        )
    return out


def run_spotbugs_project_scan(project_path: str) -> SpotBugsRunResult:
    p = str(Path(project_path))
    with tempfile.TemporaryDirectory(prefix="sast_spotbugs_") as td:
        out_xml = str(Path(td) / "spotbugs.xml")
        cmd = [
            "spotbugs",
            "-textui",
            "-xml:withMessages",
            "-output",
            out_xml,
            p,
        ]
        try:
            cp = run_subprocess_sandboxed(cmd, cwd=p, capture_output=True, text=True, timeout=300.0)
        except FileNotFoundError:
            return SpotBugsRunResult(findings=[], engine_available=False, error="spotbugs executable not found")
        except Exception as e:
            return SpotBugsRunResult(findings=[], engine_available=True, error=f"spotbugs failed: {e}")

        if cp.returncode != 0:
            err = (cp.stderr or cp.stdout or "").strip()
            return SpotBugsRunResult(findings=[], engine_available=True, error=f"spotbugs error: {err[:260]}")

        try:
            payload = Path(out_xml).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return SpotBugsRunResult(findings=[], engine_available=True, error=f"spotbugs output read error: {e}")
        return SpotBugsRunResult(findings=parse_spotbugs_xml(payload), engine_available=True, error=None)

