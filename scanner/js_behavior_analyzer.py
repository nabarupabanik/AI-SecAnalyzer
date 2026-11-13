"""
JS/TS — Process Flow + Risk Heuristics (lightweight, dependency-free).

Goal: Provide useful process-risk + malicious-pattern signals and a basic graph for
Node/Express projects, similar to the Python behavior analyzer.

This is intentionally heuristic (regex-based) to avoid pulling in heavy JS parsers.
It focuses on common dangerous sinks and common request sources.
"""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

import networkx as nx

from .models import FileModel, ProcessEvent, MaliciousIndicator


_LINE_SPLIT = re.compile(r"\r\n|\r|\n")

# --- Sources (Express/Fastify/etc. + CLI) ---
_SOURCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("express.req.query", re.compile(r"\breq\.query\b")),
    ("express.req.body", re.compile(r"\breq\.body\b")),
    ("express.req.params", re.compile(r"\breq\.params\b")),
    ("express.req.headers", re.compile(r"\breq\.headers\b")),
    ("express.req.cookies", re.compile(r"\breq\.cookies\b")),
    ("express.req.signedCookies", re.compile(r"\breq\.signedCookies\b")),
    ("express.req.get", re.compile(r"\breq\.(?:get|header)\s*\(")),
    ("koa.ctx.query", re.compile(r"\bctx\.query\b")),
    ("koa.ctx.params", re.compile(r"\bctx\.params\b")),
    ("koa.ctx.request.body", re.compile(r"\bctx\.request\.body\b")),
    ("fastify.request.query", re.compile(r"\brequest\.query\b")),
    ("fastify.request.body", re.compile(r"\brequest\.body\b")),
    ("fastify.request.params", re.compile(r"\brequest\.params\b")),
    ("fastify.request.headers", re.compile(r"\brequest\.headers\b")),
    ("hapi.request.payload", re.compile(r"\brequest\.payload\b")),
    ("process.argv", re.compile(r"\bprocess\.argv\b")),
]

# --- Sinks / risky APIs ---
_SINKS: list[tuple[str, str, str, re.Pattern[str]]] = [
    ("Command Exec", "child_process.exec", "High", re.compile(r"\bexec\s*\(")),
    ("Command Exec", "child_process.execSync", "High", re.compile(r"\bexecSync\s*\(")),
    ("Command Exec", "child_process.execFile", "High", re.compile(r"\bexecFile\s*\(")),
    ("Command Exec", "child_process.execFileSync", "High", re.compile(r"\bexecFileSync\s*\(")),
    ("Command Exec", "child_process.spawn", "Medium", re.compile(r"\bspawn\s*\(")),
    ("Command Exec", "child_process.spawnSync", "Medium", re.compile(r"\bspawnSync\s*\(")),
    ("Command Exec", "child_process.fork", "Medium", re.compile(r"\bfork\s*\(")),
    ("Command Exec", "shelljs.exec", "Medium", re.compile(r"\bshelljs\.exec\s*\(")),
    ("Dynamic Eval", "eval", "High", re.compile(r"\beval\s*\(")),
    ("Dynamic Eval", "Function", "High", re.compile(r"\bnew\s+Function\s*\(")),
    ("Command Exec", "execa", "High", re.compile(r"\bexeca\s*\(")),
    ("Command Exec", "execaCommand", "High", re.compile(r"\bexecaCommand\s*\(")),
    ("Template Rendering", "express.res.render", "High", re.compile(r"\bres\.render\s*\(")),
]
_SANITIZER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bvalidator\.(?:escape|whitelist|blacklist|normalizeEmail)\s*\("),
    re.compile(r"\b(?:escape|sanitize|xssFilters)\s*\("),
    re.compile(r"\bencodeURIComponent\s*\("),
]

_IMPORT_CP = re.compile(r"(require\(['\"]child_process['\"]\)|from\s+['\"]child_process['\"])")
_SOCKET_CONNECT = re.compile(r"\b(net\.Socket|tls\.connect|socket\.connect)\b")
_HTTP_URL = re.compile(r"\bhttps?://[^\s'\"`]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def _is_js_analyzable(f: FileModel) -> bool:
    return (
        f.extension in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")
        and f.content is not None
        and not f.read_error
    )


def _add_edge(g: nx.DiGraph, src: str, dst: str, file_path: str) -> None:
    if not src or not dst:
        return
    g.add_edge(src, dst, file=file_path)


def analyze_single_file_js_process_flow(
    f: FileModel,
    g: nx.DiGraph,
) -> tuple[list[ProcessEvent], list[MaliciousIndicator], list[dict[str, Any]]]:
    """
    Returns (process_events, malicious_indicators, taint_paths) for a JS/TS file.
    """
    if not _is_js_analyzable(f):
        return [], [], []

    lines = _LINE_SPLIT.split(f.content or "")
    proc_events: list[ProcessEvent] = []
    malicious: list[MaliciousIndicator] = []
    taint_paths: list[dict[str, Any]] = []

    tainted_vars: set[str] = set()
    sanitized_vars: set[str] = set()
    saw_cp = bool(_IMPORT_CP.search(f.content or ""))
    saw_socket = False
    saw_exec = False
    saw_external = False

    for idx, line in enumerate(lines, start=1):
        l = line.strip()
        if not l:
            continue

        # Detect external IP/URL literals (very rough signal)
        if _HTTP_URL.search(l) or _IPV4.search(l):
            saw_external = True

        if _SOCKET_CONNECT.search(l):
            saw_socket = True

        # Taint assignment: const x = req.query.foo / req.body / req.params etc.
        m_assign = re.search(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)", l)
        if m_assign:
            var_name = m_assign.group(1)
            rhs = m_assign.group(2)
            for src_name, pat in _SOURCE_PATTERNS:
                if pat.search(rhs):
                    tainted_vars.add(var_name)
                    break
            if any(p.search(rhs) for p in _SANITIZER_PATTERNS):
                sanitized_vars.add(var_name)
                if var_name in tainted_vars:
                    tainted_vars.discard(var_name)

        # Find sinks and mark as process events. Mark "tainted" when line contains a source token.
        src_hit = None
        for src_name, pat in _SOURCE_PATTERNS:
            if pat.search(l):
                src_hit = src_name
                break

        for etype, fn, risk, pat in _SINKS:
            if pat.search(l):
                clean_line = line.rstrip("\n\r")
                uses_tainted_var = any(re.search(rf"\b{re.escape(v)}\b", l) for v in tainted_vars)
                uses_sanitized_var = any(re.search(rf"\b{re.escape(v)}\b", l) for v in sanitized_vars)
                sanitized_inline = any(p.search(l) for p in _SANITIZER_PATTERNS)
                tainted = src_hit is not None or uses_tainted_var
                sanitized = bool(uses_sanitized_var or sanitized_inline)
                conf = "High" if tainted and not sanitized else "Medium" if tainted else "Low"
                effective_risk = risk
                if tainted and sanitized and risk == "High":
                    effective_risk = "Medium"
                proc_events.append(
                    ProcessEvent(
                        file=f.file_path,
                        line=idx,
                        type=etype,
                        function=fn,
                        risk=effective_risk,  # type: ignore[arg-type]
                        detail=f"{clean_line[:220]}; sanitized={sanitized}; confidence={conf}",
                        tainted=tainted,
                    )
                )
                _add_edge(g, f"file:{f.file_path}", fn, f.file_path)
                if tainted:
                    if src_hit is None:
                        # If tainted via variable, attribute to a generic request source.
                        src_hit = "request.*"
                    # Add an explicit taint-flow edge for explainability.
                    _add_edge(g, "tainted", fn, f.file_path)
                    taint_paths.append(
                        {
                            "source": src_hit,
                            "sink": fn,
                            "file": f.file_path,
                            "line": idx,
                            "severity": "High" if effective_risk == "High" else "Medium",
                            "sanitized": sanitized,
                            "category": "template" if etype == "Template Rendering" else "system",
                            "confidence": conf,
                            "evidence": clean_line[:260],
                        }
                    )
                if "exec" in fn or "eval" in fn or "Function" in fn:
                    saw_exec = True

    # Malicious correlations (heuristic)
    if saw_cp and saw_exec and (saw_socket or saw_external):
        malicious.append(
            MaliciousIndicator(
                file=f.file_path,
                line=1,
                type="Suspicious Command+Network Correlation",
                severity="High",  # type: ignore[arg-type]
                evidence="child_process usage combined with network/connect or external endpoints",
            )
        )

    if saw_socket and saw_external:
        malicious.append(
            MaliciousIndicator(
                file=f.file_path,
                line=1,
                type="External Network Endpoint Usage",
                severity="Medium",  # type: ignore[arg-type]
                evidence="socket/connect with URL/IP literal detected",
            )
        )

    return proc_events, malicious, taint_paths


def analyze_js_process_flow(model) -> None:
    """
    Populate process_events, process_graph, malicious_indicators for JS/TS files.
    Adds to existing lists (Python analysis may have already run).
    """
    g = nx.DiGraph()
    process_events: list[ProcessEvent] = []
    malicious: list[MaliciousIndicator] = []
    taint_paths: list[dict[str, Any]] = []

    for f in getattr(model, "files", []) or []:
        pe, mal, tpaths = analyze_single_file_js_process_flow(f, g)
        process_events.extend(pe)
        malicious.extend(mal)
        taint_paths.extend(tpaths)

    nodes = sorted({n for n in g.nodes})
    edges = [
        {"from": u, "to": v, "file": (g.edges[u, v].get("file") if g.has_edge(u, v) else None)}
        for (u, v) in g.edges
    ]

    # Merge into existing model payloads if present
    model.process_events = (getattr(model, "process_events", []) or []) + process_events
    model.malicious_indicators = (getattr(model, "malicious_indicators", []) or []) + malicious

    existing_pg = getattr(model, "process_graph", {}) or {}
    existing_nodes = set(existing_pg.get("nodes") or [])
    existing_edges = existing_pg.get("edges") or []
    existing_tp = existing_pg.get("taint_paths") or []

    merged_nodes = sorted(existing_nodes | set(nodes))
    merged_edges = existing_edges + edges
    merged_tp = existing_tp + taint_paths
    model.process_graph = {"nodes": merged_nodes, "edges": merged_edges, "taint_paths": merged_tp}

