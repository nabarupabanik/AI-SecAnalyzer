"""
CodeQL-backed static analyzer (Phase 1 integration).

This adapter is optional and disabled by default.
Enable with:
  SAST_ENABLE_CODEQL=1

Current scope:
  - python
  - javascript / typescript (as javascript suite)
  - java
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .models import FileModel, VulnerabilityFinding
from .sandbox import run_subprocess_sandboxed


@dataclass
class CodeQLRunResult:
    findings: list[VulnerabilityFinding]
    enabled: bool
    engine_available: bool
    error: Optional[str] = None


def _is_enabled() -> bool:
    return os.environ.get("SAST_ENABLE_CODEQL", "").strip().lower() in ("1", "true", "yes")


def _timeout_s() -> int:
    raw = os.environ.get("SAST_CODEQL_TIMEOUT", "600").strip()
    try:
        return max(120, int(raw))
    except ValueError:
        return 600


def _resolve_codeql_executable() -> Optional[str]:
    """
    Locate the CodeQL CLI. The bundle is often unzipped without adding bin to PATH;
    subprocess then fails with FileNotFoundError and scans show 0 CodeQL findings.
    """
    for key in ("SAST_CODEQL", "CODEQL_PATH"):
        raw = os.environ.get(key, "").strip()
        if raw:
            cand = Path(raw)
            if cand.is_file():
                return str(cand)
    for key in ("SAST_CODEQL_HOME", "CODEQL_HOME"):
        home = os.environ.get(key, "").strip()
        if not home:
            continue
        base = Path(home)
        for name in ("codeql.cmd", "codeql.exe", "codeql"):
            cand = base / name
            if cand.is_file():
                return str(cand)
    which = shutil.which("codeql")
    if which:
        return which
    if sys.platform == "win32":
        profile = os.environ.get("USERPROFILE", "").strip()
        if profile:
            for rel in (
                ("codeql-win64", "codeql", "codeql.cmd"),
                ("codeql", "codeql.cmd"),
            ):
                cand = Path(profile).joinpath(*rel)
                if cand.is_file():
                    return str(cand)
    return None


def _pick_language(files: list[FileModel]) -> Optional[str]:
    py = sum(1 for f in files if f.extension == ".py")
    js = sum(1 for f in files if f.extension in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    java = sum(1 for f in files if f.extension == ".java")
    if py == 0 and js == 0 and java == 0:
        return None
    scores = {
        "python": py,
        "javascript": js,
        "java": java,
    }
    # Deterministic tie-break by order in this tuple.
    for lang in ("python", "javascript", "java"):
        if scores[lang] == max(scores.values()):
            return lang
    return None


def _suite_for(lang: str) -> str:
    if lang == "python":
        return "codeql/python-queries:codeql-suites/python-security-and-quality.qls"
    if lang == "java":
        return "codeql/java-queries:codeql-suites/java-security-and-quality.qls"
    return "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls"


def _query_pack_name_for_language(lang: str) -> Optional[str]:
    """Standard library pack (from GitHub CodeQL) required for _suite_for()."""
    if lang == "python":
        return "codeql/python-queries"
    if lang == "java":
        return "codeql/java-queries"
    if lang == "javascript":
        return "codeql/javascript-queries"
    return None


def _has_local_pack(lang: str) -> bool:
    """Check whether a query pack for this language is already present in local cache."""
    pack = _query_pack_name_for_language(lang)
    if not pack:
        return False
    packages_dir = Path.home() / ".codeql" / "packages"
    target = packages_dir.joinpath(*pack.split("/"))
    if target.is_dir():
        for child in target.iterdir():
            if child.is_dir() and (child / "qlpack.yml").is_file():
                return True
    return False


def _ensure_query_pack(codeql_exe: str, lang: str) -> Optional[str]:
    """
    Ensure the CodeQL query pack is installed. The CLI zip often ships without
    javascript/python/java query packs; analyze then fails with "Query pack ... cannot be found".
    Packs are cached under ~/.codeql/packages after `codeql pack download`.

    Set SAST_CODEQL_SKIP_PACK_DOWNLOAD=1 to skip (offline installs where packs are pre-fetched).
    If a local pack is already installed, skip downloading to prevent network aborts.
    """
    if os.environ.get("SAST_CODEQL_SKIP_PACK_DOWNLOAD", "").strip().lower() in ("1", "true", "yes"):
        return None
    if _has_local_pack(lang):
        return None
    pack = _query_pack_name_for_language(lang)
    if not pack:
        return None
    dl_timeout = float(_timeout_s())
    try:
        cp = run_subprocess_sandboxed(
            [codeql_exe, "pack", "download", pack],
            cwd=None,
            timeout=min(dl_timeout, 900.0),
            capture_output=True,
            text=True,
        )
    except Exception as e:
        if _has_local_pack(lang):
            return None
        return f"codeql pack download failed: {e}"
    if cp.returncode != 0:
        if _has_local_pack(lang):
            return None
        err = (cp.stderr or cp.stdout or "").strip()
        return f"codeql pack download ({pack}): {err[:400]}"
    return None


def _javascript_build_command(project_path: str) -> str | None:
    """
    Optional install step so CodeQL JavaScript extraction resolves dependencies.
    Uses --ignore-scripts to avoid running arbitrary package lifecycle hooks during scans.
    """
    root = Path(project_path)
    if not (root / "package.json").exists():
        return None
    if (root / "yarn.lock").exists():
        return "yarn install --ignore-scripts"
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm install --ignore-scripts"
    if (root / "package-lock.json").exists() or (root / "npm-shrinkwrap.json").exists():
        return "npm ci --ignore-scripts"
    return "npm install --ignore-scripts"


def _java_build_command(project_path: str) -> str | None:
    """
    Pick a pragmatic Java build command for CodeQL database extraction.
    Returns None when no common Java build file is present.
    """
    root = Path(project_path)
    if (root / "pom.xml").exists():
        return "mvn -q -DskipTests compile"
    if (root / "gradlew.bat").exists():
        return "gradlew.bat classes -x test"
    if (root / "gradlew").exists():
        return "./gradlew classes -x test"
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        return "gradle classes -x test"
    return None


def _map_level(level: str) -> str:
    s = (level or "").strip().lower()
    if s in ("error", "high", "critical"):
        return "High"
    if s in ("warning", "medium"):
        return "Medium"
    return "Low"


def parse_sarif_findings(payload: dict) -> list[VulnerabilityFinding]:
    out: list[VulnerabilityFinding] = []
    runs = payload.get("runs") or []
    for run in runs:
        rules = {r.get("id"): r for r in ((run.get("tool") or {}).get("driver") or {}).get("rules", [])}
        for res in run.get("results") or []:
            rid = str(res.get("ruleId") or "").strip()
            msg_obj = res.get("message") or {}
            msg = str(msg_obj.get("text") or msg_obj.get("markdown") or "CodeQL finding").strip()
            locs = res.get("locations") or []
            file = ""
            line = 1
            if locs:
                pl = (locs[0] or {}).get("physicalLocation") or {}
                art = pl.get("artifactLocation") or {}
                file = str(art.get("uri") or "")
                reg = pl.get("region") or {}
                line = int(reg.get("startLine") or 1)

            level = str(res.get("level") or ((rules.get(rid) or {}).get("defaultConfiguration") or {}).get("level") or "")
            confidence = "Medium"
            props = res.get("properties") or {}
            prec = str(props.get("precision") or "").strip().lower()
            if prec in ("very-high", "high"):
                confidence = "High"
            elif prec in ("low", "very-low"):
                confidence = "Low"

            out.append(
                VulnerabilityFinding(
                    file=file,
                    line=max(1, line),
                    type=(msg.split(".")[0][:120] or "CodeQL Finding"),
                    severity=_map_level(level),  # type: ignore[arg-type]
                    code=msg[:240],
                    analyzer="codeql",
                    rule_id=rid,
                    confidence=confidence,
                )
            )
    return out


def run_codeql_project_scan(project_path: str, files: list[FileModel], *, enabled: bool | None = None) -> CodeQLRunResult:
    effective_enabled = _is_enabled() if enabled is None else bool(enabled)
    if not effective_enabled:
        return CodeQLRunResult(findings=[], enabled=False, engine_available=False, error=None)

    lang = _pick_language(files)
    if lang is None:
        return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error="no supported language for CodeQL in this project")

    codeql_exe = _resolve_codeql_executable()
    if not codeql_exe:
        return CodeQLRunResult(
            findings=[],
            enabled=True,
            engine_available=False,
            error="codeql executable not found (add CodeQL to PATH or set CODEQL_HOME to the folder containing codeql.cmd)",
        )

    p = str(Path(project_path))
    timeout = float(_timeout_s())
    suite = _suite_for(lang)

    with tempfile.TemporaryDirectory(prefix="sast_codeql_") as td:
        db = str(Path(td) / "db")
        sarif_out = str(Path(td) / "out.sarif")

        # 1) Create database
        create_cmd = [
            codeql_exe,
            "database",
            "create",
            db,
            "--language",
            lang,
            "--source-root",
            p,
        ]
        if lang == "java":
            build_cmd = _java_build_command(p)
            if not build_cmd:
                return CodeQLRunResult(
                    findings=[],
                    enabled=True,
                    engine_available=True,
                    error="java project detected for CodeQL, but no Maven/Gradle build file found",
                )
            create_cmd.extend(["--command", build_cmd])
        elif lang == "javascript":
            js_cmd = _javascript_build_command(p)
            if js_cmd:
                create_cmd.extend(["--command", js_cmd])
        try:
            cp_create = run_subprocess_sandboxed(
                create_cmd,
                cwd=p if os.path.isdir(p) else None,
                timeout=timeout,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return CodeQLRunResult(
                findings=[],
                enabled=True,
                engine_available=False,
                error=f"codeql executable not found at {codeql_exe!r}",
            )
        except Exception as e:
            return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error=f"codeql db create failed: {e}")

        if cp_create.returncode != 0:
            err = (cp_create.stderr or cp_create.stdout or "").strip()
            return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error=f"codeql db create error: {err[:260]}")

        pack_err = _ensure_query_pack(codeql_exe, lang)
        if pack_err:
            return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error=pack_err)

        # 2) Analyze database
        analyze_cmd = [
            codeql_exe,
            "database",
            "analyze",
            db,
            suite,
            "--format=sarif-latest",
            "--output",
            sarif_out,
        ]
        try:
            cp_an = run_subprocess_sandboxed(
                analyze_cmd,
                cwd=p if os.path.isdir(p) else None,
                timeout=timeout,
                capture_output=True,
                text=True,
            )
        except Exception as e:
            return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error=f"codeql analyze failed: {e}")

        if cp_an.returncode != 0:
            err = (cp_an.stderr or cp_an.stdout or "").strip()
            return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error=f"codeql analyze error: {err[:260]}")

        try:
            payload = json.loads(Path(sarif_out).read_text(encoding="utf-8"))
        except Exception as e:
            return CodeQLRunResult(findings=[], enabled=True, engine_available=True, error=f"invalid codeql sarif: {e}")

        return CodeQLRunResult(findings=parse_sarif_findings(payload), enabled=True, engine_available=True, error=None)

