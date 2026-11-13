"""
Sprint 4 — Tamperability Detection Engine (Python-first heuristics)

Detects:
- Debug mode enabled (DEBUG=True, app.run(debug=True), app.debug=True)
- Hardcoded admin flags (is_admin=True, admin=True, role='admin')
- Exposed config files (.env, config.*, settings.*, etc.)
- Writable sensitive files (open(<sensitive path>, 'w'/'a'/'x'))
- Environment variable dependency (os.environ / getenv usage)
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Optional

from .models import ApplicationModel, FileModel, TamperIssue
from .static_analyzer import attach_python_ast, _get_line


_SENSITIVE_PATH_RE = re.compile(r"(config|secret|key|passwd|password|credential|token|\.env)", re.IGNORECASE)
_JAVA_ENV_RE = re.compile(r"\b(System\.getenv|System\.getProperty)\s*\(")
_JAVA_DEBUG_RE = re.compile(r"\b(setDebugEnabled\s*\(\s*true\s*\)|debug\s*=\s*true)\b", re.IGNORECASE)
_JAVA_ADMIN_RE = re.compile(r"\b(isAdmin|admin|superuser)\s*=\s*true\b", re.IGNORECASE)
_JAVA_ROLE_ADMIN_RE = re.compile(r"\b(role|userRole)\s*=\s*[\"']admin[\"']", re.IGNORECASE)
_JAVA_CORS_WILDCARD_RE = re.compile(r"\ballowedOrigins\s*\(\s*[\"']\*[\"']\s*\)")
_JAVA_COOKIE_INSECURE_RE = re.compile(r"\bsetSecure\s*\(\s*false\s*\)")
_JAVA_COOKIE_HTTPONLY_OFF_RE = re.compile(r"\bsetHttpOnly\s*\(\s*false\s*\)")
_JAVA_WRITABLE_SENSITIVE_RE = re.compile(
    r"\b(FileWriter|Files\.write|new\s+FileOutputStream)\b.*(config|secret|token|password|credential|\.env)",
    re.IGNORECASE,
)
_PROPS_DEBUG_RE = re.compile(r"^\s*(debug|spring\.devtools\.restart\.enabled|server\.error\.include-stacktrace)\s*=\s*(true|always)\s*$", re.IGNORECASE)
_PROPS_CORS_WILDCARD_RE = re.compile(r"^\s*(cors\.allowed-origins|spring\.web\.cors\.allowed-origins)\s*=\s*\*\s*$", re.IGNORECASE)
_PROPS_SECURE_FALSE_RE = re.compile(r"^\s*server\.servlet\.session\.cookie\.secure\s*=\s*false\s*$", re.IGNORECASE)
_PROPS_HTTPONLY_FALSE_RE = re.compile(r"^\s*server\.servlet\.session\.cookie\.http-only\s*=\s*false\s*$", re.IGNORECASE)


def _add_issue_line(
    issues: list[TamperIssue],
    f: FileModel,
    *,
    line: int,
    t: str,
    risk: str,
    score: int,
    evidence: str = "",
) -> None:
    issues.append(
        TamperIssue(
            file=f.file_path,
            line=max(1, int(line or 1)),
            type=t,
            risk=risk,  # type: ignore[arg-type]
            evidence=evidence or _get_line(f.content or "", max(1, int(line or 1))),
            score=score,
        )
    )


def _is_python_analyzable(f: FileModel) -> bool:
    return f.extension == ".py" and f.content is not None and not f.read_error


def _node_line(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 1) or 1)


def _add_issue(issues: list[TamperIssue], f: FileModel, node: ast.AST, t: str, risk: str, score: int, evidence: str = ""):
    line = _node_line(node)
    issues.append(
        TamperIssue(
            file=f.file_path,
            line=line,
            type=t,
            risk=risk,  # type: ignore[arg-type]
            evidence=evidence or _get_line(f.content or "", line),
            score=score,
        )
    )


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_str(node: ast.AST, s: str) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.lower() == s.lower()


def _tamper_profile() -> str:
    profile = os.environ.get("SAST_TAMPER_PROFILE", "web_api").strip().lower()
    if profile not in {"web_api", "desktop", "service"}:
        return "web_api"
    return profile


class _TamperVisitor(ast.NodeVisitor):
    def __init__(self, f: FileModel, profile: str = "web_api"):
        self.f = f
        self.profile = profile
        self.issues: list[TamperIssue] = []
        self.saw_env_dep = False

    def visit_Assign(self, node: ast.Assign):
        # DEBUG = True / FLASK_DEBUG = 1 patterns (Python-level)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id.upper() in ("DEBUG", "FLASK_DEBUG"):
                if _is_true(node.value) or (isinstance(node.value, ast.Constant) and str(node.value.value) == "1"):
                    _add_issue(self.issues, self.f, node, "Debug Mode Enabled", "Medium", 10)

            # Hardcoded admin flags
            if isinstance(tgt, ast.Name) and tgt.id.lower() in ("is_admin", "admin", "is_superuser", "superuser"):
                if _is_true(node.value):
                    _add_issue(self.issues, self.f, node, "Hardcoded Admin Flag", "High", 15)

            if isinstance(tgt, ast.Name) and tgt.id.lower() in ("role", "user_role"):
                if _is_str(node.value, "admin"):
                    _add_issue(self.issues, self.f, node, "Hardcoded Admin Role", "Medium", 10)

        return self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # app.debug = True
        if node.attr == "debug":
            # handled in Assign when value True by inspecting parent is hard; detect via simple pattern in visit_Assign too
            pass
        return self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # app.run(debug=True)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and _is_true(kw.value):
                    _add_issue(self.issues, self.f, node, "Debug Mode Enabled", "Medium", 10)

        # open(<path>, "w"/"a"/"x") where path looks sensitive
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if len(node.args) >= 2:
                mode = node.args[1]
                if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(m in mode.value for m in ("w", "a", "x")):
                    path_arg = node.args[0]
                    if isinstance(path_arg, ast.Constant) and isinstance(path_arg.value, str) and _SENSITIVE_PATH_RE.search(path_arg.value):
                        _add_issue(self.issues, self.f, node, "Writable Sensitive File", "High", 15)

        # Environment variable dependency
        # os.environ.get("X"), os.getenv("X"), getenv("X"), environ["X"]
        fn = ""
        if isinstance(node.func, ast.Attribute):
            # os.getenv / os.environ.get
            if isinstance(node.func.value, ast.Name):
                fn = f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func.value, ast.Attribute):
                # os.environ.get
                base = []
                cur = node.func.value
                while isinstance(cur, ast.Attribute):
                    base.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name):
                    base.append(cur.id)
                base = list(reversed(base))
                fn = ".".join(base + [node.func.attr])
        elif isinstance(node.func, ast.Name):
            fn = node.func.id

        if fn in ("os.getenv", "getenv", "os.environ.get"):
            self.saw_env_dep = True

        # Web profile: permissive CORS
        if self.profile == "web_api":
            if fn.endswith("CORS") or fn.endswith("add_middleware"):
                text = ast.dump(node, include_attributes=False)
                if "origins" in text.lower() and "'*'" in text:
                    _add_issue(self.issues, self.f, node, "Permissive CORS", "High", 15, evidence="origins='*' detected")

            # Cookie security flags disabled
            if isinstance(node.func, ast.Attribute) and node.func.attr == "set_cookie":
                insecure = False
                missing_httponly = False
                for kw in node.keywords:
                    if kw.arg == "secure" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        insecure = True
                    if kw.arg == "httponly" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        missing_httponly = True
                if insecure:
                    _add_issue(self.issues, self.f, node, "Insecure Cookie Flag", "Medium", 10, evidence="set_cookie(..., secure=False)")
                if missing_httponly:
                    _add_issue(self.issues, self.f, node, "HttpOnly Disabled Cookie", "Medium", 10, evidence="set_cookie(..., httponly=False)")

        return self.generic_visit(node)


def analyze_tamperability(model: ApplicationModel) -> None:
    issues: list[TamperIssue] = []
    profile = _tamper_profile()

    # Exposed config files (presence-based, repo-level)
    exposed_names = {
        ".env",
        "config.py",
        "settings.py",
        "config.json",
        "config.yaml",
        "config.yml",
        "settings.json",
    }
    if profile == "desktop":
        exposed_names.update({"app.config", "appsettings.json", "settings.ini"})
    elif profile == "service":
        exposed_names.update({"service.yaml", "service.yml", "application.properties"})
    for f in model.files:
        name = Path(f.file_path).name.lower()
        if name in exposed_names:
            issues.append(
                TamperIssue(
                    file=f.file_path,
                    line=1,
                    type="Exposed Config File",
                    risk="Medium",
                    evidence=f.file_path,
                    score=10,
                )
            )

    # Python AST-based checks + Java/config heuristics
    saw_env_dep_any = False
    for f in model.files:
        if _is_python_analyzable(f):
            err = attach_python_ast(f)
            if err:
                continue
            tree = getattr(f, "ast_tree", None)
            if tree is None:
                continue

            v = _TamperVisitor(f, profile=profile)
            v.visit(tree)
            issues.extend(v.issues)
            saw_env_dep_any = saw_env_dep_any or v.saw_env_dep
            continue

        if f.extension == ".java" and f.content and not f.read_error:
            lines = (f.content or "").splitlines()
            for i, ln in enumerate(lines, start=1):
                s = ln.strip()
                if not s:
                    continue
                if _JAVA_DEBUG_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Debug Mode Enabled", risk="Medium", score=10, evidence=s)
                if _JAVA_ADMIN_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Hardcoded Admin Flag", risk="High", score=15, evidence=s)
                if _JAVA_ROLE_ADMIN_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Hardcoded Admin Role", risk="Medium", score=10, evidence=s)
                if profile == "web_api" and _JAVA_CORS_WILDCARD_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Permissive CORS", risk="High", score=15, evidence=s)
                if _JAVA_COOKIE_INSECURE_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Insecure Cookie Flag", risk="Medium", score=10, evidence=s)
                if _JAVA_COOKIE_HTTPONLY_OFF_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="HttpOnly Disabled Cookie", risk="Medium", score=10, evidence=s)
                if _JAVA_WRITABLE_SENSITIVE_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Writable Sensitive File", risk="High", score=15, evidence=s)
                if _JAVA_ENV_RE.search(s):
                    saw_env_dep_any = True
            continue

        if f.extension in (".properties", ".yml", ".yaml") and f.content and not f.read_error:
            lines = (f.content or "").splitlines()
            for i, ln in enumerate(lines, start=1):
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                if _PROPS_DEBUG_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Debug Mode Enabled", risk="Medium", score=10, evidence=s)
                if _PROPS_CORS_WILDCARD_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Permissive CORS", risk="High", score=15, evidence=s)
                if _PROPS_SECURE_FALSE_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="Insecure Cookie Flag", risk="Medium", score=10, evidence=s)
                if _PROPS_HTTPONLY_FALSE_RE.search(s):
                    _add_issue_line(issues, f, line=i, t="HttpOnly Disabled Cookie", risk="Medium", score=10, evidence=s)

    if saw_env_dep_any:
        issues.append(
            TamperIssue(
                file=model.project_path,
                line=1,
                type="Environment Variable Dependency",
                risk="Medium",
                evidence="os.getenv / os.environ.get detected",
                score=10,
            )
        )

    # Score = sum of issue scores, capped at 100
    tamper_score = sum(i.score for i in issues)
    model.tamperability = issues
    model.tamper_score = max(0, min(100, int(tamper_score)))

