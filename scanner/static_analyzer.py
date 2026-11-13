"""
Sprint 2 — Static Vulnerability Scanner (Python AST)

This module analyzes Python files using the stdlib `ast` module and emits
JSON-serializable VulnerabilityFinding entries on the ApplicationModel.

Implementation notes:
- We attach `file_model.ast_tree` dynamically (NOT a dataclass field) so
  `dataclasses.asdict()` won't try to serialize AST objects.
"""

from __future__ import annotations

import ast
import re
from dataclasses import asdict
from typing import Iterable, Optional

from .models import ApplicationModel, FileModel, VulnerabilityFinding


_SECRET_RE = re.compile(r"(password|api_key|secret|token)\s*=\s*(['\"]).+?\2", re.IGNORECASE)
_SECRET_PLACEHOLDER_RE = re.compile(
    r"^(changeme|change_me|example|sample|test|dummy|placeholder|your_.*|<.*>)$",
    re.IGNORECASE,
)
_SENSITIVE_FILE_PATH_RE = re.compile(r"(secret|key|token|passwd|password|credential|\.env|config|settings)", re.IGNORECASE)


def _get_line(content: str, line_no: int) -> str:
    if not content:
        return ""
    lines = content.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].rstrip("\n\r")
    return ""


def _is_python_analyzable(f: FileModel) -> bool:
    return (
        f.extension == ".py"
        and f.content is not None
        and not f.read_error
    )


def attach_python_ast(file_model: FileModel) -> Optional[str]:
    """
    Parse and attach `file_model.ast_tree`.
    Returns a parse error string (if any); otherwise None.
    """
    try:
        tree = ast.parse(file_model.content or "", filename=file_model.file_path)
        # Attach as a dynamic attribute (not in dataclass fields)
        file_model.ast_tree = tree  # type: ignore[attr-defined]
        file_model.ast_error = None  # type: ignore[attr-defined]
        return None
    except SyntaxError as e:
        file_model.ast_tree = None  # type: ignore[attr-defined]
        file_model.ast_error = f"SyntaxError: {e.msg} (line {getattr(e, 'lineno', '?')})"  # type: ignore[attr-defined]
        return file_model.ast_error  # type: ignore[return-value]
    except Exception as e:
        file_model.ast_tree = None  # type: ignore[attr-defined]
        file_model.ast_error = f"AST parse error: {e}"  # type: ignore[attr-defined]
        return file_model.ast_error  # type: ignore[return-value]


class _PythonVulnVisitor(ast.NodeVisitor):
    def __init__(self, file_model: FileModel):
        self.f = file_model
        self.findings: list[VulnerabilityFinding] = []
        self._input_vars: set[str] = set()
        self._tainted_vars: set[str] = set()
        self._dynamic_sql_vars: set[str] = set()

    def _add(
        self,
        node: ast.AST,
        vtype: str,
        severity: str,
        code_line: Optional[str] = None,
        *,
        confidence: str = "Medium",
        rule_id: str = "",
    ):
        line = int(getattr(node, "lineno", 1) or 1)
        code = code_line if code_line is not None else _get_line(self.f.content or "", line)
        self.findings.append(
            VulnerabilityFinding(
                file=self.f.file_path,
                line=line,
                type=vtype,
                severity=severity,  # type: ignore[arg-type]
                code=code,
                confidence=confidence,
                rule_id=rule_id,
            )
        )

    def _contains_name(self, node: ast.AST, names: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in names:
                return True
        return False

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _is_framework_source(self, node: ast.AST) -> bool:
        """
        Framework-aware request input sources:
        Flask/FastAPI: request.args/form/values/json/headers/cookies/path_params/query_params
        Django: request.GET/POST/COOKIES/META
        """
        for sub in ast.walk(node):
            # request.args.get("x"), request.form.get(...)
            if isinstance(sub, ast.Call):
                fn = self._call_name(sub.func).lower()
                if fn.startswith("request.") and any(
                    k in fn
                    for k in (
                        ".args.get",
                        ".form.get",
                        ".values.get",
                        ".json.get",
                        ".headers.get",
                        ".cookies.get",
                        ".query_params.get",
                        ".path_params.get",
                        ".get_json",
                    )
                ):
                    return True
            # request.GET["x"], request.POST["x"]
            if isinstance(sub, ast.Subscript):
                root = self._call_name(sub.value).lower()
                if root in ("request.get", "request.post", "request.cookies", "request.meta"):
                    return True
            # direct request attribute usage
            if isinstance(sub, ast.Attribute):
                a = self._call_name(sub).lower()
                if a in (
                    "request.args",
                    "request.form",
                    "request.values",
                    "request.json",
                    "request.headers",
                    "request.cookies",
                    "request.query_params",
                    "request.path_params",
                    "request.get",
                    "request.post",
                ):
                    return True
        return False

    def _expr_is_tainted(self, node: ast.AST) -> bool:
        return (
            self._contains_name(node, self._input_vars | self._tainted_vars)
            or self._is_framework_source(node)
        )

    def _is_sanitizer_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        fn = self._call_name(node.func).lower()
        return fn in {
            "int",
            "float",
            "bool",
            "html.escape",
            "markupsafe.escape",
            "urllib.parse.quote",
            "urllib.parse.quote_plus",
            "re.escape",
        }

    def _is_sql_string_constant(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value.lower()
            return any(k in s for k in ("select ", "insert ", "update ", "delete ", " where ", " from "))
        return False

    def _is_sqlish_expression(self, node: ast.AST) -> bool:
        # Stronger precision: require SQL-ish token in the expression tree.
        return any(self._is_sql_string_constant(x) for x in ast.walk(node))

    def _is_tainted_or_dynamic_sql(self, node: ast.AST) -> bool:
        if self._expr_is_tainted(node):
            return True
        # Dynamic concat / f-string / format/%-formatting.
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return True
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.Call):
            fn = self._call_name(node.func).lower()
            if fn.endswith(".format") or fn == "format":
                return True
        return False

    def visit_Assign(self, node: ast.Assign):
        # Track input() sources
        if (
            (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "input")
            or self._is_framework_source(node.value)
        ):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._input_vars.add(t.id)
                    self._tainted_vars.add(t.id)
        # Propagate taint through assignments
        elif self._expr_is_tainted(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._tainted_vars.add(t.id)

        # SQL injection heuristic: query/sql variable built via concatenation/formatting
        target_names = {t.id for t in node.targets if isinstance(t, ast.Name)}
        # Track any variable assigned from SQL-ish dynamic expression so execute(var) can be resolved later.
        if self._is_sqlish_expression(node.value) and self._is_tainted_or_dynamic_sql(node.value):
            for n in target_names:
                self._dynamic_sql_vars.add(n)

        if any(n.lower() in ("query", "sql", "statement") for n in target_names):
            if self._is_sqlish_expression(node.value) and self._is_tainted_or_dynamic_sql(node.value):
                conf = "High" if self._expr_is_tainted(node.value) else "Medium"
                self._add(node, "SQL Injection", "High", confidence=conf, rule_id="pyast.sqli.assignment")

        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Weak crypto: hashlib.md5 / hashlib.sha1
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib" and node.func.attr in ("md5", "sha1"):
                self._add(node, "Weak Cryptography", "Medium", confidence="High", rule_id="pyast.crypto.weak_hash")

        # Unsafe file write: open(path, "w"/"a"/"x")
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if len(node.args) >= 2:
                mode_node = node.args[1]
                if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                    mode = mode_node.value
                    if any(m in mode for m in ("w", "a", "x")):
                        path_expr = node.args[0]
                        path_tainted = self._expr_is_tainted(path_expr)
                        path_sensitive = False
                        if isinstance(path_expr, ast.Constant) and isinstance(path_expr.value, str):
                            path_sensitive = _SENSITIVE_FILE_PATH_RE.search(path_expr.value) is not None

                        # Reduce noise: only flag when path is tainted OR clearly sensitive.
                        if path_tainted or path_sensitive:
                            sev = "Medium" if path_tainted else "Low"
                            conf = "High" if path_tainted else "Medium"
                            self._add(
                                node,
                                "Unsafe File Operation",
                                sev,
                                confidence=conf,
                                rule_id="pyast.file.write_sensitive_or_tainted",
                            )

        # SQL injection heuristic at sink: cursor.execute(<dynamic string>, ...)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany"):
            if node.args:
                q = node.args[0]
                dynamic = self._is_tainted_or_dynamic_sql(q)
                # Parameterized execute(query, params) is generally safer; don't flag by default.
                has_params = len(node.args) >= 2
                if has_params:
                    pass
                elif dynamic and (
                    self._is_sqlish_expression(q)
                    or (isinstance(q, ast.Name) and q.id in self._dynamic_sql_vars)
                ):
                    conf = "High" if self._expr_is_tainted(q) else "Medium"
                    self._add(node, "SQL Injection", "High", confidence=conf, rule_id="pyast.sqli.execute_dynamic")

        # Dangerous sinks for unvalidated input
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if node.args and self._expr_is_tainted(node.args[0]) and not self._is_sanitizer_call(node.args[0]):
                self._add(node, "Unvalidated Input", "High", confidence="High", rule_id="pyast.eval.tainted")

        return self.generic_visit(node)


def analyze_single_python_file_static(f: FileModel) -> list[VulnerabilityFinding]:
    """
    Run static vulnerability rules on a single Python file.
    Attaches ast_tree when successful; returns all findings for this file.
    """
    findings: list[VulnerabilityFinding] = []
    if not _is_python_analyzable(f):
        return findings

    parse_error = attach_python_ast(f)
    if parse_error:
        return findings

    tree = getattr(f, "ast_tree", None)
    if tree is None:
        return findings

    visitor = _PythonVulnVisitor(f)
    visitor.visit(tree)

    for m in _SECRET_RE.finditer(f.content or ""):
        line = (f.content or "")[: m.start()].count("\n") + 1
        code_line = _get_line(f.content or "", line)
        value_match = re.search(r"=\s*(['\"])(.+?)\1", code_line)
        secret_val = (value_match.group(2).strip() if value_match else "")
        if len(secret_val) < 8 or _SECRET_PLACEHOLDER_RE.match(secret_val):
            # Reduce false positives for obvious placeholders in demos/tests.
            continue
        findings.append(
            VulnerabilityFinding(
                file=f.file_path,
                line=line,
                type="Hardcoded Secret",
                severity="Medium",
                code=code_line,
                confidence="High",
                rule_id="pyast.secret.hardcoded",
            )
        )

    findings.extend(visitor.findings)
    return findings


def analyze_python_files(model: ApplicationModel) -> None:
    """
    Mutates `model` by populating `model.vulnerabilities`.
    Also attaches `ast_tree` to each analyzable Python FileModel.
    """
    findings: list[VulnerabilityFinding] = []

    for f in model.files:
        findings.extend(analyze_single_python_file_static(f))

    model.vulnerabilities = findings

