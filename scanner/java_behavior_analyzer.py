"""
Java process/malicious heuristics (lightweight regex pass).

Goal: add baseline behavioral visibility for Java projects without heavy parsers.
"""

from __future__ import annotations

import re
from typing import Any

import networkx as nx

from .models import FileModel, MaliciousIndicator, ProcessEvent

_LINE_SPLIT = re.compile(r"\r\n|\r|\n")
_SOURCE = re.compile(r"\b(request\.getParameter|request\.getHeader|request\.getQueryString|System\.getProperty)\s*\(")
_SINKS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("Process Execution", "Runtime.exec", "High", re.compile(r"\bRuntime\.getRuntime\(\)\.exec\s*\(")),
    ("Process Execution", "ProcessBuilder.start", "High", re.compile(r"\bnew\s+ProcessBuilder\s*\(")),
    ("Dynamic Loading", "Class.forName", "Medium", re.compile(r"\bClass\.forName\s*\(")),
    ("Reflection Invoke", "Method.invoke", "Medium", re.compile(r"\b\.invoke\s*\(")),
]
_SQL_SINK = re.compile(r"\b(?:executeQuery|executeUpdate|execute|createNativeQuery)\s*\(")
_URL_IP = re.compile(r"\bhttps?://[^\s\"']+|\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SAN = re.compile(r"\b(?:PreparedStatement|setString|StringEscapeUtils\.escape)\b")
_B64 = re.compile(r"\bBase64\.(?:getDecoder|getMimeDecoder)\(\)\.decode\s*\(")


def _is_java_analyzable(f: FileModel) -> bool:
    return f.extension == ".java" and f.content is not None and not f.read_error


def _add_edge(g: nx.DiGraph, src: str, dst: str, file_path: str) -> None:
    if src and dst:
        g.add_edge(src, dst, file=file_path)


def analyze_single_file_java_process_flow(
    f: FileModel,
    g: nx.DiGraph,
) -> tuple[list[ProcessEvent], list[MaliciousIndicator], list[dict[str, Any]]]:
    if not _is_java_analyzable(f):
        return [], [], []
    lines = _LINE_SPLIT.split(f.content or "")
    events: list[ProcessEvent] = []
    mals: list[MaliciousIndicator] = []
    tpaths: list[dict[str, Any]] = []

    saw_exec = False
    saw_external = False
    saw_b64 = False

    for idx, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        src_hit = bool(_SOURCE.search(text))
        if _URL_IP.search(text):
            saw_external = True
        if _B64.search(text):
            saw_b64 = True

        for etype, fn, base_risk, pat in _SINKS:
            if pat.search(text):
                tainted = src_hit
                risk = "Critical" if (tainted and fn in ("Runtime.exec", "ProcessBuilder.start")) else base_risk
                events.append(
                    ProcessEvent(
                        file=f.file_path,
                        line=idx,
                        type=etype,
                        function=fn,
                        risk=risk,  # type: ignore[arg-type]
                        detail=f"source={'request' if tainted else 'code'}; confidence={'High' if tainted else 'Medium'}",
                        tainted=tainted,
                    )
                )
                _add_edge(g, "request" if tainted else "code", fn, f.file_path)
                if fn in ("Runtime.exec", "ProcessBuilder.start"):
                    saw_exec = True
                if tainted:
                    tpaths.append(
                        {
                            "source": "request",
                            "sink": fn,
                            "file": f.file_path,
                            "line": idx,
                            "severity": "Critical" if risk == "Critical" else "High",
                            "sanitized": False,
                            "category": "system",
                            "confidence": "High",
                            "evidence": text[:260],
                        }
                    )

        if _SQL_SINK.search(text):
            tainted = src_hit
            sanitized = bool(_SAN.search(text))
            if tainted:
                risk = "Medium" if sanitized else "High"
                events.append(
                    ProcessEvent(
                        file=f.file_path,
                        line=idx,
                        type="Database Query",
                        function="SQL Execute",
                        risk=risk,  # type: ignore[arg-type]
                        detail=f"source=request; sanitized={sanitized}",
                        tainted=True,
                    )
                )
                _add_edge(g, "request", "SQL Execute", f.file_path)
                tpaths.append(
                    {
                        "source": "request",
                        "sink": "SQL Execute",
                        "file": f.file_path,
                        "line": idx,
                        "severity": "Medium" if sanitized else "High",
                        "sanitized": sanitized,
                        "category": "sql",
                        "confidence": "Medium" if sanitized else "High",
                        "evidence": text[:260],
                    }
                )
                if not sanitized:
                    mals.append(
                        MaliciousIndicator(
                            file=f.file_path,
                            line=idx,
                            type="Potential SQL Injection Path",
                            severity="High",  # type: ignore[arg-type]
                            evidence=text[:260],
                        )
                    )

    if saw_exec and saw_external:
        mals.append(
            MaliciousIndicator(
                file=f.file_path,
                line=1,
                type="Suspicious Command+Network Correlation",
                severity="High",  # type: ignore[arg-type]
                evidence="Runtime/ProcessBuilder execution combined with external URL/IP usage",
            )
        )
    if saw_exec and saw_b64:
        mals.append(
            MaliciousIndicator(
                file=f.file_path,
                line=1,
                type="Obfuscated Execution Pattern",
                severity="Medium",  # type: ignore[arg-type]
                evidence="Base64 decode usage near command execution flow",
            )
        )
    return events, mals, tpaths

