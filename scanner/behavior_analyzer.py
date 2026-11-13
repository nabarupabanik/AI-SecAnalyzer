"""
Sprint 3 — Process Flow Analysis + Malicious Behavior Detection (Python AST)

Outputs are stored on ApplicationModel:
- process_events
- process_graph (nodes + edges)
- malicious_indicators

Taint model (Sprint 3 minimal):
- Sources: input()
- Propagation: simple assignments (x = tainted_var), binary ops, f-strings, string joins
- Sinks: os.system, subprocess.run/Popen/call/check_output, eval/exec
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict
from typing import Any, Optional

import networkx as nx

from .models import (
    ApplicationModel,
    FileModel,
    ProcessEvent,
    MaliciousIndicator,
)
from .static_analyzer import attach_python_ast, _get_line  # reuse safe AST attach + line extraction


_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SANITIZER_CALLS = {
    "int",
    "float",
    "bool",
    "html.escape",
    "markupsafe.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "re.escape",
    "shlex.quote",
    # Framework/common validation helpers
    "bleach.clean",
    "werkzeug.utils.secure_filename",
    "pydantic.constr",
    "pydantic.field",
    "pydantic.validator",
    "validators.url",
    "validators.domain",
}
_FRAMEWORK_CALL_SOURCE_HINTS = (
    ".args.get",
    ".form.get",
    ".values.get",
    ".json.get",
    ".headers.get",
    ".cookies.get",
    ".files.get",
    ".query_params.get",
    ".path_params.get",
    ".get_json",
    ".get_data",
)


def _is_python_analyzable(f: FileModel) -> bool:
    return f.extension == ".py" and f.content is not None and not f.read_error


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _contains_ip_literal(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if _IPV4_RE.search(sub.value):
                return True
    return False


def _node_line(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 1) or 1)


def _collect_passthrough_functions(tree: ast.AST) -> dict[str, set[int]]:
    """
    Infer simple passthrough functions where return value is one of params.
    Example: def clean(x): return x  -> {"clean": {0}}
    """
    out: dict[str, set[int]] = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.FunctionDef):
            continue
        arg_names = [a.arg for a in n.args.args]
        passthrough_idxs: set[int] = set()
        for sub in ast.walk(n):
            if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Name):
                name = sub.value.id
                if name in arg_names:
                    passthrough_idxs.add(arg_names.index(name))
        if passthrough_idxs:
            out[n.name] = passthrough_idxs
    return out


def _collect_sink_wrapper_functions(tree: ast.AST) -> dict[str, dict[str, Any]]:
    """
    Infer lightweight interprocedural wrappers where function parameters flow
    into dangerous sinks.
    Example:
      def run_cmd(x): os.system(x) -> {"run_cmd": {"sink": "os.system", "param_idxs": {0}, "risk": "High"}}
    """
    system_sinks = {
        "os.system": "High",
        "os.popen": "High",
        "subprocess.run": "High",
        "subprocess.Popen": "High",
        "subprocess.call": "High",
        "subprocess.check_output": "High",
        "subprocess.getoutput": "High",
        "subprocess.getstatusoutput": "High",
        "exec": "High",
        "eval": "High",
    }
    out: dict[str, dict[str, Any]] = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.FunctionDef):
            continue
        params = [a.arg for a in n.args.args]
        if not params:
            continue
        for sub in ast.walk(n):
            if not isinstance(sub, ast.Call):
                continue
            sink = _call_name(sub.func)
            if sink not in system_sinks:
                continue
            idxs: set[int] = set()
            for i, a in enumerate(sub.args):
                if isinstance(a, ast.Name) and a.id in params:
                    idxs.add(params.index(a.id))
                # wrapper forwarding: foo(str(x))
                for inner in ast.walk(a):
                    if isinstance(inner, ast.Name) and inner.id in params:
                        idxs.add(params.index(inner.id))
            if idxs:
                out[n.name] = {"sink": sink, "param_idxs": idxs, "risk": system_sinks[sink]}
                break
    return out


def _collect_local_function_names(tree: ast.AST) -> set[str]:
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}


def _risk_rank(risk: str) -> int:
    return {"Low": 1, "Medium": 2, "High": 3}.get(risk, 1)


def dedupe_process_events(events: list[ProcessEvent]) -> list[ProcessEvent]:
    """
    Collapse repeated process events by (file, line, type, function), keeping the
    higher-risk / tainted-richer variant when duplicates exist.
    """
    best: dict[tuple[str, int, str, str], ProcessEvent] = {}
    for e in events:
        key = (e.file, int(e.line or 1), e.type, e.function)
        prev = best.get(key)
        if prev is None:
            best[key] = e
            continue
        prev_score = _risk_rank(prev.risk) + (1 if prev.tainted else 0)
        cur_score = _risk_rank(e.risk) + (1 if e.tainted else 0)
        if cur_score > prev_score:
            best[key] = e
    return sorted(best.values(), key=lambda x: (x.file, int(x.line or 1), x.type, x.function))


def dedupe_malicious_indicators(items: list[MaliciousIndicator]) -> list[MaliciousIndicator]:
    """
    Collapse duplicate malicious indicators by (file, line, type), preferring
    higher severity.
    """
    best: dict[tuple[str, int, str], MaliciousIndicator] = {}
    for m in items:
        key = (m.file, int(m.line or 1), m.type)
        prev = best.get(key)
        if prev is None or _risk_rank(m.severity) > _risk_rank(prev.severity):
            best[key] = m
    return sorted(best.values(), key=lambda x: (x.file, int(x.line or 1), x.type))


class _TaintAndProcessVisitor(ast.NodeVisitor):
    def __init__(
        self,
        file_model: FileModel,
        graph: nx.DiGraph,
        passthrough_map: Optional[dict[str, set[int]]] = None,
        sink_wrapper_map: Optional[dict[str, dict[str, Any]]] = None,
    ):
        self.f = file_model
        self.g = graph
        self.process_events: list[ProcessEvent] = []
        self.malicious: list[MaliciousIndicator] = []

        self.tainted: set[str] = set()
        self.imported: dict[str, str] = {}  # alias -> module (very light)
        self.passthrough_map = passthrough_map or {}
        self.sink_wrapper_map = sink_wrapper_map or {}
        self._saw_socket_connect: list[tuple[int, str]] = []  # (line, evidence)
        self._saw_shell_exec: list[tuple[int, str]] = []
        self._saw_external_ip: list[tuple[int, str]] = []
        self.taint_paths: list[dict[str, Any]] = []

    # --- graph helpers ---
    def _add_edge(self, src: str, dst: str):
        if src and dst:
            self.g.add_edge(src, dst, file=self.f.file_path)

    # --- taint helpers ---
    def _infer_source_label(self, node: ast.AST) -> str:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = _call_name(sub.func).lower()
                if fn.startswith("request.args") or ".args.get" in fn:
                    return "flask.request.args"
                if fn.startswith("request.form") or ".form.get" in fn:
                    return "flask.request.form"
                if fn.startswith("request.get_json") or ".json.get" in fn:
                    return "flask.request.json"
                if fn.startswith("request.values") or ".values.get" in fn:
                    return "flask.request.values"
                if fn.startswith("request.files") or ".files.get" in fn:
                    return "flask.request.files"
                if ".query_params" in fn or ".path_params" in fn:
                    return "fastapi.request.params"
                if ".headers.get" in fn:
                    return "request.headers"
                if ".cookies.get" in fn:
                    return "request.cookies"
            if isinstance(sub, ast.Subscript):
                root = _call_name(sub.value).lower()
                if root == "request.get":
                    return "django.request.GET"
                if root == "request.post":
                    return "django.request.POST"
                if root == "request.cookies":
                    return "django.request.COOKIES"
                if root == "request.meta":
                    return "django.request.META"
                if root == "request.headers":
                    return "request.headers"
                if root == "request.args":
                    return "flask.request.args"
                if root == "request.form":
                    return "flask.request.form"
        if self._is_framework_source(node):
            return "framework.request"
        return "input()"

    def _is_framework_source(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = _call_name(sub.func).lower()
                if fn.startswith("request.") and any(k in fn for k in _FRAMEWORK_CALL_SOURCE_HINTS):
                    return True
            if isinstance(sub, ast.Subscript):
                root = _call_name(sub.value).lower()
                if root in (
                    "request.get",
                    "request.post",
                    "request.cookies",
                    "request.meta",
                    "request.headers",
                    "request.args",
                    "request.form",
                    "request.values",
                    "request.files",
                ):
                    return True
            if isinstance(sub, ast.Attribute):
                a = _call_name(sub).lower()
                if a in (
                    "request.args",
                    "request.form",
                    "request.values",
                    "request.json",
                    "request.headers",
                    "request.cookies",
                    "request.files",
                    "request.query_params",
                    "request.path_params",
                    "request.get",
                    "request.post",
                ):
                    return True
        return False

    def _is_sanitizer_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        fn = _call_name(node.func).lower()
        return fn in _SANITIZER_CALLS

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_framework_source(node):
            return True
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "input":
                return True
            if isinstance(sub, ast.Call):
                fn = _call_name(sub.func)
                passthrough_idxs = self.passthrough_map.get(fn, set())
                for i in passthrough_idxs:
                    if i < len(sub.args) and self._expr_is_tainted(sub.args[i]):
                        return True
        return False

    def _mark_targets_tainted(self, targets: list[ast.expr]):
        for t in targets:
            if isinstance(t, ast.Name):
                self.tainted.add(t.id)

    # --- event emitters ---
    def _emit_event(self, node: ast.AST, etype: str, function: str, risk: str, detail: str = "", tainted: bool = False):
        line = _node_line(node)
        self.process_events.append(
            ProcessEvent(
                file=self.f.file_path,
                line=line,
                type=etype,
                function=function,
                risk=risk,  # type: ignore[arg-type]
                detail=detail or _get_line(self.f.content or "", line),
                tainted=tainted,
            )
        )

    def _emit_mal(self, node: ast.AST, mtype: str, severity: str, evidence: str = ""):
        line = _node_line(node)
        self.malicious.append(
            MaliciousIndicator(
                file=self.f.file_path,
                line=line,
                type=mtype,
                severity=severity,  # type: ignore[arg-type]
                evidence=evidence or _get_line(self.f.content or "", line),
            )
        )

    def _emit_taint_path(
        self,
        node: ast.AST,
        *,
        sink: str,
        source: str = "tainted-input",
        severity: str = "High",
        sanitized: bool = False,
        category: str = "system",
        confidence: str = "Medium",
    ):
        line = _node_line(node)
        self.taint_paths.append(
            {
                "source": source,
                "sink": sink,
                "file": self.f.file_path,
                "line": line,
                "severity": severity,
                "sanitized": bool(sanitized),
                "category": category,
                "confidence": confidence,
                "evidence": _get_line(self.f.content or "", line),
            }
        )

    # --- imports (light normalization) ---
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.imported[asname] = name
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            asname = alias.asname or alias.name
            self.imported[asname] = f"{mod}.{alias.name}" if mod else alias.name
        return self.generic_visit(node)

    # --- assignments for taint tracking + flow edges ---
    def visit_Assign(self, node: ast.Assign):
        # input source
        if (
            (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "input")
            or self._is_framework_source(node.value)
        ):
            self._mark_targets_tainted(node.targets)
            source_label = self._infer_source_label(node.value)
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._add_edge(source_label, t.id)

        # propagation: if RHS uses tainted vars, mark LHS tainted
        if self._expr_is_tainted(node.value):
            self._mark_targets_tainted(node.targets)
            for t in node.targets:
                if isinstance(t, ast.Name):
                    # best-effort source labeling
                    self._add_edge("tainted", t.id)

        return self.generic_visit(node)

    # --- calls for system/process/network detection ---
    def visit_Call(self, node: ast.Call):
        fn = _call_name(node.func)

        # normalize common aliases like sp.run when imported as sp
        if fn and "." in fn:
            head, tail = fn.split(".", 1)
            if head in self.imported:
                fn = f"{self.imported[head]}.{tail}"

        tainted_args = any(self._expr_is_tainted(a) for a in node.args) or any(self._expr_is_tainted(k.value) for k in node.keywords)
        sanitized_tainted_args = any(
            isinstance(a, ast.Call) and self._is_sanitizer_call(a) and any(self._expr_is_tainted(x) for x in a.args)
            for a in node.args
        ) or any(
            isinstance(k.value, ast.Call) and self._is_sanitizer_call(k.value) and any(self._expr_is_tainted(x) for x in k.value.args)
            for k in node.keywords
        )

        # System calls / process creation
        system_calls = {
            "os.system": ("System Call", "Medium"),
            "os.popen": ("System Call", "Medium"),
            "subprocess.run": ("Child Process Creation", "Medium"),
            "subprocess.Popen": ("Child Process Creation", "Medium"),
            "subprocess.call": ("Child Process Creation", "Medium"),
            "subprocess.check_output": ("Child Process Creation", "Medium"),
            "subprocess.getoutput": ("Child Process Creation", "Medium"),
            "subprocess.getstatusoutput": ("Child Process Creation", "Medium"),
            "exec": ("System Call", "High"),
            "eval": ("System Call", "High"),
        }
        if fn in system_calls:
            etype, base_risk = system_calls[fn]
            risk = base_risk
            source_label = (
                self._infer_source_label(node)
                if tainted_args
                else "code"
            )
            if fn in ("exec", "eval"):
                self._emit_mal(node, "exec/eval Usage", "High")
            if tainted_args and fn not in ("exec", "eval"):
                if sanitized_tainted_args:
                    risk = "Medium"
                else:
                    risk = "High"
                    self._emit_mal(node, "User Input to System Call", "Critical", evidence=_get_line(self.f.content or "", _node_line(node)))
                    self._emit_mal(node, "Command Injection", "Critical", evidence=_get_line(self.f.content or "", _node_line(node)))
                self._emit_taint_path(
                    node,
                    sink=fn,
                    source=source_label,
                    severity="Medium" if sanitized_tainted_args else "Critical",
                    sanitized=sanitized_tainted_args,
                    category="system",
                    confidence="Medium" if sanitized_tainted_args else "High",
                )

            explain = (
                f"source={source_label}; "
                f"sink={fn}; sanitized={sanitized_tainted_args}; "
                f"confidence={'Medium' if sanitized_tainted_args else 'High' if tainted_args else 'Low'}"
            )
            self._emit_event(node, etype, fn, risk, detail=explain, tainted=tainted_args)
            self._add_edge(source_label if tainted_args else "code", fn)

        # Interprocedural wrapper sink call:
        # user_input -> helper(param) where helper internally calls dangerous sink.
        if fn in self.sink_wrapper_map:
            meta = self.sink_wrapper_map[fn]
            wrapper_tainted = any(
                i < len(node.args) and self._expr_is_tainted(node.args[i])
                for i in (meta.get("param_idxs") or set())
            )
            if wrapper_tainted:
                sink = str(meta.get("sink") or fn)
                source_label = self._infer_source_label(node)
                detail = f"interprocedural wrapper={fn}; sink={sink}; source={source_label}; confidence=High"
                self._emit_event(node, "Interprocedural Sink Call", fn, "High", detail=detail, tainted=True)
                self._emit_taint_path(
                    node,
                    sink=sink,
                    source=source_label,
                    severity="High",
                    sanitized=False,
                    category="system",
                    confidence="High",
                )
                self._emit_mal(node, "User Input to Wrapper Sink", "High")
                self._add_edge(source_label, fn)
                self._add_edge(fn, sink)

        # SQL sinks (framework/db API aware)
        sql_sinks = {
            "cursor.execute",
            "cursor.executemany",
            "session.execute",
            "db.session.execute",
            "engine.execute",
            "connection.execute",
            "raw",
        }
        if fn in sql_sinks and node.args:
            query_arg = node.args[0]
            query_tainted = self._expr_is_tainted(query_arg)
            has_params = len(node.args) >= 2
            if query_tainted:
                source_label = self._infer_source_label(query_arg)
                risk = "Medium" if has_params else "High"
                detail = f"source={source_label}; sink={fn}; parameterized={has_params}"
                self._emit_event(node, "Database Query", fn, risk, detail=detail, tainted=True)
                self._emit_taint_path(
                    node,
                    sink=fn,
                    source=source_label,
                    severity="Medium" if has_params else "High",
                    sanitized=has_params,
                    category="sql",
                    confidence="Medium" if has_params else "High",
                )
                if not has_params:
                    self._emit_mal(node, "Potential SQL Injection Path", "High")

        # Template rendering sinks
        template_sinks = {
            "flask.render_template_string",
            "render_template_string",
            "jinja2.template.render",
            "jinja2.environment.from_string",
            "templates.templateresponse",
            "templateresponse",
            "template.render",
        }
        if fn in template_sinks:
            template_tainted = any(self._expr_is_tainted(a) for a in node.args) or any(self._expr_is_tainted(k.value) for k in node.keywords)
            if template_tainted:
                source_label = self._infer_source_label(node)
                self._emit_event(
                    node,
                    "Template Rendering",
                    fn,
                    "High",
                    detail=f"source={source_label}; sink={fn}; context=template",
                    tainted=True,
                )
                self._emit_taint_path(
                    node,
                    sink=fn,
                    source=source_label,
                    severity="High",
                    sanitized=False,
                    category="template",
                    confidence="High",
                )
                self._emit_mal(node, "Template Injection Risk", "High")

        # socket.connect(("<ip>", port))
        if fn.endswith("socket.connect") or fn.endswith("connect"):
            if _contains_ip_literal(node):
                self._saw_external_ip.append((_node_line(node), _get_line(self.f.content or "", _node_line(node))))
                self._emit_event(node, "Suspicious Network", fn, "Medium")
                self._emit_mal(node, "External IP Connection", "Medium")
            self._saw_socket_connect.append((_node_line(node), _get_line(self.f.content or "", _node_line(node))))

        # base64 + exec detection: exec(base64.b64decode(x))
        if fn == "exec" and node.args:
            arg0 = node.args[0]
            for sub in ast.walk(arg0):
                if isinstance(sub, ast.Attribute) and _call_name(sub) == "base64.b64decode":
                    self._emit_mal(node, "Obfuscated Execution", "High")
                    self._emit_event(node, "System Call", "exec(base64.b64decode)", "High")

        return self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            s = node.value
            if "/bin/sh" in s or "bash -i" in s or "nc " in s or "powershell -enc" in s:
                self._saw_shell_exec.append((_node_line(node), s))
        return self.generic_visit(node)

    def finalize_correlations(self):
        # Reverse shell heuristic: socket connect + shell string + system call already emitted
        if self._saw_socket_connect and self._saw_shell_exec:
            # Emit one indicator near first connect
            line, ev = self._saw_socket_connect[0]
            self.malicious.append(
                MaliciousIndicator(
                    file=self.f.file_path,
                    line=line,
                    type="Reverse Shell Pattern",
                    severity="High",
                    evidence=ev,
                )
            )

        # Malicious pattern correlation: socket + system call + IP
        if self._saw_socket_connect and self._saw_shell_exec and self._saw_external_ip:
            line, ev = self._saw_external_ip[0]
            self.malicious.append(
                MaliciousIndicator(
                    file=self.f.file_path,
                    line=line,
                    type="Malicious Pattern Correlation",
                    severity="High",
                    evidence=ev,
                )
            )

        # Chain scoring heuristic (Phase 1 correlation):
        # score suspicious behavior clusters and emit one consolidated indicator.
        chain_score = 0
        if self._saw_socket_connect:
            chain_score += 2
        if self._saw_shell_exec:
            chain_score += 3
        if self._saw_external_ip:
            chain_score += 3
        chain_score += min(4, sum(1 for e in self.process_events if e.tainted))

        if chain_score >= 6:
            sev = "High" if chain_score >= 8 else "Medium"
            evidence = (
                f"behavior_chain_score={chain_score}; "
                f"socket_connect={len(self._saw_socket_connect)}; "
                f"shell_exec={len(self._saw_shell_exec)}; "
                f"external_ip={len(self._saw_external_ip)}; "
                f"tainted_events={sum(1 for e in self.process_events if e.tainted)}"
            )
            line = self._saw_external_ip[0][0] if self._saw_external_ip else (
                self._saw_socket_connect[0][0] if self._saw_socket_connect else 1
            )
            self.malicious.append(
                MaliciousIndicator(
                    file=self.f.file_path,
                    line=line,
                    type="Behavior Correlation Chain",
                    severity=sev,  # type: ignore[arg-type]
                    evidence=evidence,
                )
            )


class _CrossFileWrapperVisitor(ast.NodeVisitor):
    """
    Lightweight cross-file pass:
    - Tracks taint in current module.
    - Resolves imported wrapper calls.
    - Emits events when tainted args flow into wrapper functions defined in other files.
    """

    def __init__(self, f: FileModel, wrapper_registry: dict[str, dict[str, Any]], local_functions: set[str]):
        self.f = f
        self.wrapper_registry = wrapper_registry
        self.local_functions = local_functions
        self.imported_aliases: dict[str, str] = {}
        self.tainted: set[str] = set()
        self.process_events: list[ProcessEvent] = []
        self.malicious: list[MaliciousIndicator] = []
        self.taint_paths: list[dict[str, Any]] = []

    def _is_framework_source(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                fn = _call_name(sub.func).lower()
                if fn.startswith("request.") and any(
                    k in fn for k in (".args.get", ".form.get", ".json.get", ".get_json", ".query_params.get", ".path_params.get")
                ):
                    return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "input":
                return True
        return False

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        if self._is_framework_source(node):
            return True
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == "input":
                return True
        return False

    def _emit_event(self, node: ast.AST, function: str, sink: str, source: str):
        line = _node_line(node)
        self.process_events.append(
            ProcessEvent(
                file=self.f.file_path,
                line=line,
                type="Interprocedural Cross-File Sink Call",
                function=function,
                risk="High",
                detail=f"source={source}; wrapper={function}; sink={sink}; cross_file=true; confidence=High",
                tainted=True,
            )
        )
        self.malicious.append(
            MaliciousIndicator(
                file=self.f.file_path,
                line=line,
                type="User Input to Cross-File Wrapper Sink",
                severity="High",
                evidence=_get_line(self.f.content or "", line),
            )
        )
        self.taint_paths.append(
            {
                "source": source,
                "sink": sink,
                "file": self.f.file_path,
                "line": line,
                "severity": "High",
                "sanitized": False,
                "category": "system",
                "confidence": "High",
                "evidence": _get_line(self.f.content or "", line),
            }
        )

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            local = alias.asname or alias.name
            self.imported_aliases[local] = alias.name
        return self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            mod = alias.name.split(".")[-1]
            local = alias.asname or mod
            self.imported_aliases[local] = mod
        return self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if self._expr_is_tainted(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted.add(t.id)
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        fn = _call_name(node.func)
        target_name = ""
        if isinstance(node.func, ast.Name):
            # Imported symbol or direct function call
            target_name = self.imported_aliases.get(node.func.id, node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            # module_alias.func(...)
            target_name = node.func.attr

        if not target_name:
            return self.generic_visit(node)
        if target_name in self.local_functions:
            # In-file wrappers are handled by the primary visitor.
            return self.generic_visit(node)
        meta = self.wrapper_registry.get(target_name)
        if not meta:
            return self.generic_visit(node)
        idxs = meta.get("param_idxs") or set()
        tainted = any(i < len(node.args) and self._expr_is_tainted(node.args[i]) for i in idxs)
        if tainted:
            self._emit_event(node, fn or target_name, str(meta.get("sink") or target_name), source="tainted-input")
        return self.generic_visit(node)


def analyze_single_file_process_flow(
    f: FileModel, g: Any
) -> tuple[list[ProcessEvent], list[MaliciousIndicator], list[dict[str, Any]]]:
    """
    Run process/taint/malicious analysis for one Python file and merge into shared graph.
    """
    if not _is_python_analyzable(f):
        return [], [], []
    err = attach_python_ast(f)
    if err:
        return [], [], []
    tree = getattr(f, "ast_tree", None)
    if tree is None:
        return [], [], []

    passthrough_map = _collect_passthrough_functions(tree)
    sink_wrapper_map = _collect_sink_wrapper_functions(tree)
    visitor = _TaintAndProcessVisitor(
        f,
        g,
        passthrough_map=passthrough_map,
        sink_wrapper_map=sink_wrapper_map,
    )
    visitor.visit(tree)
    visitor.finalize_correlations()
    return visitor.process_events, visitor.malicious, visitor.taint_paths


def analyze_cross_file_process_flow(model: ApplicationModel) -> tuple[list[ProcessEvent], list[MaliciousIndicator], list[dict[str, Any]]]:
    """
    Cross-file interprocedural pass for Python wrappers.
    It identifies wrapper functions that sink parameters and flags tainted calls
    from other modules that invoke those wrappers.
    """
    wrappers: dict[str, dict[str, Any]] = {}
    trees: list[tuple[FileModel, ast.AST]] = []

    for f in model.files:
        if not _is_python_analyzable(f):
            continue
        err = attach_python_ast(f)
        if err:
            continue
        tree = getattr(f, "ast_tree", None)
        if tree is None:
            continue
        trees.append((f, tree))
        local_wrappers = _collect_sink_wrapper_functions(tree)
        for name, meta in local_wrappers.items():
            wrappers.setdefault(name, meta)

    if not wrappers:
        return [], [], []

    process_events: list[ProcessEvent] = []
    malicious: list[MaliciousIndicator] = []
    taint_paths: list[dict[str, Any]] = []

    for f, tree in trees:
        local_funcs = _collect_local_function_names(tree)
        visitor = _CrossFileWrapperVisitor(f, wrappers, local_funcs)
        visitor.visit(tree)
        process_events.extend(visitor.process_events)
        malicious.extend(visitor.malicious)
        taint_paths.extend(visitor.taint_paths)

    return process_events, malicious, taint_paths


def analyze_process_flow(model: ApplicationModel) -> None:
    """
    Populate process_events, process_graph, malicious_indicators for Python files.
    This is additive; does not modify Sprint 1/2 fields.
    """
    g = nx.DiGraph()
    process_events: list[ProcessEvent] = []
    malicious: list[MaliciousIndicator] = []
    taint_paths: list[dict[str, Any]] = []

    for f in model.files:
        pe, mal, tpaths = analyze_single_file_process_flow(f, g)
        process_events.extend(pe)
        malicious.extend(mal)
        taint_paths.extend(tpaths)

    cpe, cmal, ctpaths = analyze_cross_file_process_flow(model)
    process_events.extend(cpe)
    malicious.extend(cmal)
    taint_paths.extend(ctpaths)

    # Serialize graph
    nodes = sorted({n for n in g.nodes})
    edges = [
        {"from": u, "to": v, "file": (g.edges[u, v].get("file") if g.has_edge(u, v) else None)}
        for (u, v) in g.edges
    ]

    model.process_events = dedupe_process_events(process_events)
    model.malicious_indicators = dedupe_malicious_indicators(malicious)
    model.process_graph = {"nodes": nodes, "edges": edges, "taint_paths": taint_paths}

