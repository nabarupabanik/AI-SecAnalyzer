"""
Flask API Bridge — Sprint 1.5 + Database
Connects the React frontend to the Python ApplicationModel scanner
and persists every scan result to SQLite (via SQLAlchemy).

Endpoints
─────────
  GET  /api/health                 Health check
  POST /api/validate-path          Check if a directory path exists
  POST /api/scan                   Run scanner + save scan to DB
  GET  /api/scans                  List all past scans (scan history)
  GET  /api/scans/<id>             Get full detail of one scan
  DELETE /api/scans/<id>           Delete a scan record
  GET  /api/scans/<id>/export      Export scan as JSON report file

Run with:
    python api_server.py
"""
import sys
import json
import time
from typing import Any
import datetime
import shutil
import tempfile
import os
import threading
from dataclasses import asdict
from urllib import request as urlrequest, error as urlerror
from pathlib import Path

from flask import Flask, request, jsonify, send_file, Response, stream_with_context
from sqlalchemy import func, and_, or_
from sqlalchemy.orm import selectinload
from flask_cors import CORS

# Make the scanner and database packages importable
sys.path.insert(0, str(Path(__file__).parent))

from scanner.models import ApplicationModel
from scanner.streaming_scan import stream_project_scan, make_ts_logger
from scanner.analysis_modules import normalize_analysis_modules
from database import (
    init_db,
    SessionLocal,
    Scan,
    Language,
    ScanFile,
    Vulnerability,
    ProcessEventRow,
    MaliciousIndicatorRow,
    ProcessGraphEdge,
    TamperIssueRow,
    VulnerabilitySuppression,
    SemgrepManifestCache,
    ScanJob,
    ScanTelemetry,
)
from scanner.models import VulnerabilityFinding as VulnerabilityFindingModel


def _utc_now() -> datetime.datetime:
    """Return timezone-naive UTC datetime for SQLite/SQLAlchemy compatibility without deprecation warnings."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

# ── Paths ─────────────────────────────────────────────────────
REPORTS_DIR = Path(__file__).parent / "output" / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__)
# Large folder uploads (multipart) — increase if needed (also set reverse-proxy limits in prod)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024   # 1 GB upload limit
CORS(
    app,
    origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
)

# Create tables on startup (no-op if they already exist)
init_db()


def _semgrep_cache_loader(project_path: str, manifest_hash: str) -> list[VulnerabilityFindingModel] | None:
    """Load cached Semgrep findings for incremental scans (Phase 4)."""
    db = SessionLocal()
    try:
        row = (
            db.query(SemgrepManifestCache)
            .filter(
                SemgrepManifestCache.project_path == project_path,
                SemgrepManifestCache.manifest_hash == manifest_hash,
            )
            .first()
        )
        if not row or not row.findings_json:
            return None
        data = json.loads(row.findings_json)
        return [VulnerabilityFindingModel(**d) for d in data]
    except Exception:
        return None
    finally:
        db.close()


def _noop_stream_delay(_sec: float) -> None:
    """Skip artificial pacing when draining stream_project_scan outside SSE."""


def _coerce_analysis_modules(value: Any) -> dict[str, bool] | None:
    """Parse `modules` from JSON (form body or API). None = use engine defaults (all enabled)."""
    if value is None:
        return None
    if isinstance(value, dict):
        return normalize_analysis_modules(value)
    if isinstance(value, str) and value.strip():
        try:
            data = json.loads(value)
            if isinstance(data, dict):
                return normalize_analysis_modules(data)
        except Exception:
            return None
    return None


def _sync_stream_project_scan(
    project_path: str | Path,
    *,
    incremental: bool = False,
    codeql_enabled: bool | None = None,
    pacing_delays: bool = False,
    load_content: bool = True,
    analysis_modules: dict[str, bool] | None = None,
    scan_mode: str | None = None,
    semgrep_profile: str | None = None,
) -> tuple[ApplicationModel, float]:
    """
    Run the same pipeline as SSE upload / worker: Semgrep, dedupe, graph, risk, etc.
    Returns (model, elapsed_ms).
    """
    path_str = str(project_path)
    t0 = time.perf_counter()
    delay_fn = time.sleep if pacing_delays else _noop_stream_delay
    gen = stream_project_scan(
        path_str,
        delay_fn=delay_fn,
        incremental_semgrep=incremental and load_content,
        semgrep_cache_loader=_semgrep_cache_loader if incremental and load_content else None,
        codeql_enabled=codeql_enabled,
        load_content=load_content,
        analysis_modules=analysis_modules,
        scan_mode=scan_mode,
        semgrep_profile=semgrep_profile,
    )
    model: ApplicationModel | None = None
    while True:
        try:
            next(gen)
        except StopIteration as ex:
            model = ex.value
            break
    if model is None:
        raise RuntimeError("Scan engine returned no model.")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return model, elapsed_ms


# ── Helpers ──────────────────────────────────────────────────
def _save_scan_to_db(model_dict: dict, scan_mode: str, *, scan_time_ms: float | None = None) -> int:
    """
    Persist an ApplicationModel dict to the database.
    Returns the new scan.id.
    """
    db = SessionLocal()
    try:
        extras = model_dict.pop("runtime_extras", None) or {}
        vuln_n = len(model_dict.get("vulnerabilities") or [])

        scan = Scan(
            project_path     = model_dict["project_path"],
            scan_mode        = scan_mode,
            file_count       = model_dict["file_count"],
            total_size_bytes = model_dict["total_size_bytes"],
            total_size_kb    = model_dict["total_size_bytes"] / 1024,
            risk_score       = model_dict.get("overall_score"),
            risk_level       = model_dict.get("risk_level"),
            scan_time_ms     = float(scan_time_ms) if scan_time_ms is not None else None,
            # === CSAR / Exploit Chain data ===
            stg_graph_json      = json.dumps(model_dict.get("stg_graph") or {}, ensure_ascii=False),
            ecg_graph_json      = json.dumps(model_dict.get("ecg_graph") or {}, ensure_ascii=False),
            exploit_chains_json = json.dumps(model_dict.get("exploit_chains") or [], ensure_ascii=False),
            exploit_chain_score = int(model_dict.get("exploit_chain_score") or 0),
            eliminated_paths    = int(model_dict.get("eliminated_paths_count") or (model_dict.get("ecg_graph") or {}).get("statistics", {}).get("eliminated_paths", 0) or 0),
            constraint_stats_json = json.dumps(model_dict.get("constraint_satisfaction_stats") or {}, ensure_ascii=False),
            # Pre-computed counts — avoids parsing 37MB+ blobs in to_dict()
            stg_node_count  = int((model_dict.get("stg_graph") or {}).get("summary", {}).get("total_nodes", 0) or 0),
            stg_edge_count  = int((model_dict.get("stg_graph") or {}).get("summary", {}).get("total_edges", 0) or 0),
            ecg_node_count  = int(len((model_dict.get("ecg_graph") or {}).get("nodes", []))),
            ecg_edge_count  = int(len((model_dict.get("ecg_graph") or {}).get("edges", []))),
            security_debt_json = json.dumps(model_dict.get("security_debt_analysis") or {}, ensure_ascii=False),
            dual_ai_remediation_json = json.dumps(model_dict.get("dual_ai_remediation_analysis") or {}, ensure_ascii=False),
        )
        db.add(scan)
        db.flush()  # get scan.id before adding children

        # Languages
        for lang, count in model_dict.get("language_breakdown", {}).items():
            db.add(Language(scan_id=scan.id, name=lang, file_count=count))

        # Files (without content — keep DB lean)
        for f in model_dict.get("files", []):
            db.add(ScanFile(
                scan_id    = scan.id,
                file_name  = f["file_name"],
                file_path  = f["file_path"],
                file_type  = f["file_type"],
                extension  = f["extension"],
                file_size  = f["file_size"],
                read_error = f.get("read_error"),
            ))

        # Vulnerabilities (Sprint 2)
        for v in model_dict.get("vulnerabilities", []) or []:
            db.add(Vulnerability(
                scan_id=scan.id,
                file=v.get("file", ""),
                line=int(v.get("line", 1) or 1),
                type=v.get("type", "Unknown"),
                severity=v.get("severity", "Low"),
                code=v.get("code", ""),
                fingerprint=v.get("fingerprint") or None,
                analyzer=v.get("analyzer") or None,
                rule_id=v.get("rule_id") or None,
                confidence=v.get("confidence") or None,
            ))

        # Sprint 3: process events + malicious indicators
        for e in model_dict.get("process_events", []) or []:
            db.add(ProcessEventRow(
                scan_id=scan.id,
                file=e.get("file", ""),
                line=int(e.get("line", 1) or 1),
                type=e.get("type", "Unknown"),
                function=e.get("function", ""),
                risk=e.get("risk", "Low"),
                detail=e.get("detail", ""),
                tainted=bool(e.get("tainted", False)),
            ))

        for m in model_dict.get("malicious_indicators", []) or []:
            db.add(MaliciousIndicatorRow(
                scan_id=scan.id,
                file=m.get("file", ""),
                line=int(m.get("line", 1) or 1),
                type=m.get("type", "Unknown"),
                severity=m.get("severity", "Low"),
                evidence=m.get("evidence", ""),
            ))

        # Sprint 3: process graph edges (nodes derived later)
        pg = model_dict.get("process_graph") or {}
        for edge in (pg.get("edges") or []):
            db.add(ProcessGraphEdge(
                scan_id=scan.id,
                src=edge.get("from", ""),
                dst=edge.get("to", ""),
                file=edge.get("file"),
            ))

        # Sprint 4: tamper issues
        for t in model_dict.get("tamperability", []) or []:
            db.add(TamperIssueRow(
                scan_id=scan.id,
                file=t.get("file", ""),
                line=int(t.get("line", 1) or 1),
                type=t.get("type", "Unknown"),
                risk=t.get("risk", "Low"),
                evidence=t.get("evidence", ""),
                score=int(t.get("score", 0) or 0),
            ))

        db.add(
            ScanTelemetry(
                scan_id=scan.id,
                duration_ms=float(scan_time_ms or 0.0),
                vulnerability_count=vuln_n,
                file_count=int(model_dict.get("file_count") or 0),
                semgrep_cache_hit=bool(extras.get("semgrep_cache_hit")),
                codeql_enabled=bool(extras.get("codeql_enabled")),
                codeql_finding_count=int(extras.get("codeql_finding_count") or 0),
                error=None,
            )
        )

        snap = extras.get("semgrep_findings_snap") or []
        cache_key = str(extras.get("semgrep_cache_key") or extras.get("semgrep_manifest_hash") or "")
        if snap and not extras.get("semgrep_cache_hit") and cache_key:
            exists = (
                db.query(SemgrepManifestCache)
                .filter(
                    SemgrepManifestCache.project_path == model_dict["project_path"],
                    SemgrepManifestCache.manifest_hash == cache_key,
                )
                .first()
            )
            if not exists:
                db.add(
                    SemgrepManifestCache(
                        project_path=model_dict["project_path"],
                        manifest_hash=cache_key,
                        findings_json=json.dumps(snap, ensure_ascii=False),
                        source_scan_id=scan.id,
                    )
                )

        db.commit()
        return scan.id
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _execute_scan_job(job_id: int) -> None:
    """Run a queued path scan in the background worker (Phase 4)."""
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job:
            return
        path = job.project_path
        mode = job.scan_mode
        load_content = bool(job.load_content)
        incremental = bool(job.incremental)
        codeql_enabled = bool(getattr(job, "codeql_enabled", False))
        semgrep_profile = getattr(job, "semgrep_profile", None)
        raw_mods = getattr(job, "analysis_modules_json", None)
    finally:
        db.close()

    if not load_content:
        _fail_job(job_id, "Async scans require load_content=true for this engine.")
        return

    analysis_modules = _coerce_analysis_modules(raw_mods)

    try:
        model, elapsed_ms = _sync_stream_project_scan(
            path,
            incremental=incremental,
            codeql_enabled=codeql_enabled,
            pacing_delays=False,
            analysis_modules=analysis_modules,
            scan_mode=mode,
            semgrep_profile=str(semgrep_profile).strip() if semgrep_profile else None,
        )
        model_dict = asdict(model)
        for f in model_dict.get("files", []):
            f.pop("content", None)
        scan_id = _save_scan_to_db(model_dict, mode, scan_time_ms=elapsed_ms)
        _dispatch_integrations(scan_id, mode, model_dict)

        db = SessionLocal()
        try:
            j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
            if j:
                j.status = "completed"
                j.result_scan_id = scan_id
                j.completed_at = _utc_now()
                db.commit()
        finally:
            db.close()
    except Exception as e:
        _fail_job(job_id, str(e))


def _fail_job(job_id: int, message: str) -> None:
    db = SessionLocal()
    try:
        j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if j:
            j.status = "failed"
            j.error_message = message[:4000]
            j.completed_at = _utc_now()
            db.commit()
    finally:
        db.close()


def _worker_loop() -> None:
    while True:
        time.sleep(0.25)
        db = SessionLocal()
        jid: int | None = None
        try:
            job = (
                db.query(ScanJob)
                .filter(ScanJob.status == "queued")
                .order_by(ScanJob.id.asc())
                .first()
            )
            if not job:
                continue
            job.status = "running"
            job.started_at = _utc_now()
            db.commit()
            jid = job.id
        except Exception:
            db.rollback()
            continue
        finally:
            db.close()
        if jid is not None:
            _execute_scan_job(jid)


def _start_background_worker() -> None:
    if os.environ.get("SAST_DISABLE_WORKER", "").strip().lower() in ("1", "true", "yes"):
        return
    t = threading.Thread(target=_worker_loop, name="sast-scan-worker", daemon=True)
    t.start()


def _active_suppression_fingerprints(db, project_path: str) -> set[str]:
    """Active suppressions for project_path + global suppressions."""
    now = _utc_now()
    rows = (
        db.query(VulnerabilitySuppression)
        .filter(
            or_(
                VulnerabilitySuppression.project_path == project_path,
                VulnerabilitySuppression.project_path.is_(None),
                VulnerabilitySuppression.project_path == "",
            ),
            or_(
                VulnerabilitySuppression.expires_at.is_(None),
                VulnerabilitySuppression.expires_at > now,
            ),
        )
        .all()
    )
    return {r.fingerprint for r in rows if r.fingerprint}


def _severity_rank(s: str) -> int:
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(s, 0)


def _confidence_rank(c: str) -> int:
    return {"High": 3, "Medium": 2, "Low": 1}.get(c, 0)


def _to_sarif(scan_dict: dict) -> dict:
    """
    Convert scan payload to SARIF 2.1.0.
    """
    vulns = scan_dict.get("vulnerabilities", []) or []
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []
    for v in vulns:
        rid = (v.get("rule_id") or v.get("type") or "custom.rule").strip().replace(" ", "_").lower()
        severity = str(v.get("severity") or "Low")
        confidence = str(v.get("confidence") or "Medium")
        if rid not in rules_by_id:
            rules_by_id[rid] = {
                "id": rid,
                "name": str(v.get("type") or rid),
                "shortDescription": {"text": str(v.get("type") or rid)},
                "properties": {
                    "precision": confidence.lower(),
                    "security-severity": {"Critical": "9.0", "High": "8.0", "Medium": "5.0", "Low": "3.0"}.get(severity, "5.0"),
                },
            }

        results.append(
            {
                "ruleId": rid,
                "level": {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}.get(severity, "warning"),
                "message": {"text": str(v.get("type") or "Security finding")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(v.get("file") or "")},
                            "region": {"startLine": int(v.get("line", 1) or 1)},
                        }
                    }
                ],
                "properties": {
                    "severity": severity,
                    "confidence": confidence,
                    "fingerprint": str(v.get("fingerprint") or ""),
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI Application Security Analyzer",
                        "informationUri": "https://example.local/sast",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _evaluate_policy(scan_dict: dict, diff: dict | None, profile: str = "default") -> dict:
    """
    Policy engine for CI/build gates.
    """
    profile = (profile or "default").strip().lower()
    vulns = scan_dict.get("vulnerabilities", []) or []
    critical_total = len([v for v in vulns if str(v.get("severity")) == "Critical"])
    high_total = len([v for v in vulns if str(v.get("severity")) == "High"])
    diff = diff or {}
    new_critical = int(diff.get("new_critical_count", 0) or 0)
    new_high_critical = int(diff.get("new_high_or_critical", 0) or 0)

    cfg = {
        "fail_on_new_critical": True,
        "max_new_high_or_critical": 9999,
    }
    if profile == "strict":
        cfg["max_new_high_or_critical"] = 0
    elif profile == "balanced":
        cfg["max_new_high_or_critical"] = 2

    violations: list[dict] = []
    if cfg["fail_on_new_critical"] and new_critical > 0:
        violations.append(
            {
                "code": "NEW_CRITICAL_FINDINGS",
                "message": f"Detected {new_critical} new critical finding(s) versus baseline.",
                "actual": new_critical,
                "expected": 0,
            }
        )
    if new_high_critical > cfg["max_new_high_or_critical"]:
        violations.append(
            {
                "code": "NEW_HIGH_CRITICAL_THRESHOLD",
                "message": (
                    f"Detected {new_high_critical} new high/critical finding(s), "
                    f"limit is {cfg['max_new_high_or_critical']} for profile '{profile}'."
                ),
                "actual": new_high_critical,
                "expected": cfg["max_new_high_or_critical"],
            }
        )

    return {
        "profile": profile,
        "pass": len(violations) == 0,
        "fail_build": len(violations) > 0,
        "violations": violations,
        "summary": {
            "critical_total": critical_total,
            "high_total": high_total,
            "new_critical_count": new_critical,
            "new_high_or_critical": new_high_critical,
            "has_baseline": bool(diff.get("has_baseline")),
        },
    }


def _post_json_webhook(url: str, payload: dict, timeout_s: int = 5) -> tuple[bool, str]:
    try:
        req = urlrequest.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlrequest.urlopen(req, timeout=timeout_s) as resp:
            code = getattr(resp, "status", 200)
        return True, f"http_{code}"
    except urlerror.HTTPError as e:
        return False, f"http_{e.code}"
    except Exception as e:
        return False, str(e)


def _dispatch_integrations(scan_id: int, scan_mode: str, model_dict: dict) -> dict:
    """
    Optional outbound integrations for webhooks/Jira automation.
    Controlled by env vars:
      SAST_WEBHOOK_URL
      SAST_JIRA_WEBHOOK_URL
    """
    summary = {
        "scan_id": scan_id,
        "project_path": model_dict.get("project_path", ""),
        "risk_score": model_dict.get("overall_score"),
        "risk_level": model_dict.get("risk_level"),
        "critical_count": len([v for v in model_dict.get("vulnerabilities", []) or [] if str(v.get("severity")) == "Critical"]),
        "high_count": len([v for v in model_dict.get("vulnerabilities", []) or [] if str(v.get("severity")) == "High"]),
        "scan_mode": scan_mode,
        "timestamp": _utc_now().isoformat() + "Z",
    }
    payload = {"event": "scan.completed", "summary": summary}

    hooks = []
    primary = os.environ.get("SAST_WEBHOOK_URL", "").strip()
    jira = os.environ.get("SAST_JIRA_WEBHOOK_URL", "").strip()
    if primary:
        hooks.append(("webhook", primary))
    if jira:
        hooks.append(("jira_webhook", jira))
    statuses = []
    for name, url in hooks:
        ok, detail = _post_json_webhook(url, payload)
        statuses.append({"target": name, "ok": ok, "detail": detail})
    return {"attempted": len(hooks), "statuses": statuses}


def _scan_to_dict_with_suppressions(db, scan: Scan, include_suppressed: bool) -> dict:
    base = scan.to_dict()
    vulns = base.get("vulnerabilities", []) or []
    suppressed_set = _active_suppression_fingerprints(db, scan.project_path)
    for v in vulns:
        fp = (v.get("fingerprint") or "").strip()
        v["suppressed"] = bool(fp and fp in suppressed_set)

    if include_suppressed:
        base["vulnerabilities"] = vulns
    else:
        base["vulnerabilities"] = [v for v in vulns if not v.get("suppressed")]
    base["suppression_summary"] = {
        "total": len(vulns),
        "suppressed": len([v for v in vulns if v.get("suppressed")]),
        "active_rules": len(suppressed_set),
    }
    base["taint_paths"] = _derive_taint_paths_from_events(base)
    
    # Enrich constraint satisfaction breakdown if not already present
    cstats = base.get("constraint_satisfaction_stats", {}) or {}
    if not cstats.get("data_flow_constraints_total") and getattr(scan, "ecg_graph_json", None):
        try:
            _ecg = json.loads(scan.ecg_graph_json) if scan.ecg_graph_json else {}
            _matrix = _ecg.get("constraint_matrix", {})
            if _matrix:
                _tot = len(_matrix)
                _df = sum(1 for v in _matrix.values() if v.get("data_flow_valid"))
                _eo = sum(1 for v in _matrix.values() if v.get("execution_order_valid"))
                _pr = sum(1 for v in _matrix.values() if v.get("privilege_valid"))
                _elim = _ecg.get("statistics", {}).get("eliminated_paths", _tot)
                cstats.update({
                    "data_flow_constraints_satisfied": _df,
                    "data_flow_constraints_total": _tot,
                    "execution_order_constraints_satisfied": _eo,
                    "execution_order_constraints_total": _tot,
                    "privilege_constraints_satisfied": _pr,
                    "privilege_constraints_total": _tot,
                    "eliminated_paths_count": _elim,
                    "total_paths_evaluated": _tot,
                    "elimination_rate": _elim / _tot if _tot > 0 else 0,
                })
                base["constraint_satisfaction_stats"] = cstats
                if not base.get("eliminated_paths_count"):
                    base["eliminated_paths_count"] = _elim
        except Exception:
            pass

    elim_paths = base.get("eliminated_paths_count", 0) or cstats.get("eliminated_paths_count", 0)
    base["eliminated_paths_count"] = elim_paths

    base["exploit_chain_analysis"] = {
        "exploit_chains": base.get("exploit_chains", []),
        "stg_summary": base.get("stg_summary", {}),
        "ecg_summary": base.get("ecg_summary", {}),
        "statistics": {
            "total_chains": len(base.get("exploit_chains", [])),
            "confirmed_chains": len([c for c in base.get("exploit_chains", []) if c.get("feasibility") == "confirmed"]),
            "eliminated_paths": elim_paths,
            "elimination_rate": cstats.get("elimination_rate", 0),
            "stg_nodes": base.get("stg_summary", {}).get("total_nodes", 0),
            "ecg_edges": base.get("ecg_summary", {}).get("total_edges", 0),
            "data_flow_constraints_satisfied": cstats.get("data_flow_constraints_satisfied", 0),
            "data_flow_constraints_total": cstats.get("data_flow_constraints_total", 0),
            "execution_order_constraints_satisfied": cstats.get("execution_order_constraints_satisfied", 0),
            "execution_order_constraints_total": cstats.get("execution_order_constraints_total", 0),
            "privilege_constraints_satisfied": cstats.get("privilege_constraints_satisfied", 0),
            "privilege_constraints_total": cstats.get("privilege_constraints_total", 0),
        },
        "risk_impact": {
            "exploit_chain_score": base.get("exploit_chain_score", 0),
            "dependency_involved": any(chain.get("dependency_involved", False) for chain in base.get("exploit_chains", [])),
            "max_chain_length": max([chain.get("chain_length", 0) for chain in base.get("exploit_chains", [])], default=0),
            "confirmed_feasible_chains": len([c for c in base.get("exploit_chains", []) if c.get("feasibility") == "confirmed"])
        }
    }
    
    if not base.get("dual_ai_remediation_analysis") or not base.get("dual_ai_remediation_analysis").get("patches"):
        try:
            from scanner.dual_ai_remediation import analyze_dual_ai_remediation
            from scanner.models import VulnerabilityFinding
            findings = [
                VulnerabilityFinding(
                    file=v.get("file", ""),
                    line=int(v.get("line", 1) or 1),
                    type=v.get("type", "Unknown"),
                    severity=v.get("severity", "Low"),
                    code=v.get("code", ""),
                    analyzer=v.get("analyzer", "python_ast"),
                    rule_id=v.get("rule_id", "")
                )
                for v in base.get("vulnerabilities", [])
            ]
            base["dual_ai_remediation_analysis"] = analyze_dual_ai_remediation(findings, max_live_ai=0)
        except Exception:
            pass

    return base


def _derive_taint_paths_from_events(scan_dict: dict) -> list[dict]:
    """
    Build explicit source->sink path objects from process_events.
    This keeps explainability available for scans persisted before taint_paths were stored.
    """
    def _derive_confidence(risk: str, sanitized: bool, category: str, detail: str) -> str:
        d = detail.lower()
        if sanitized:
            return "Medium"
        if risk in ("Critical", "High"):
            return "High"
        if category in ("sql", "template") and ("tainted" in d or "source=" in d):
            return "High"
        if "source=code" in d:
            return "Low"
        return "Medium"

    def _group_paths(paths: list[dict]) -> list[dict]:
        grouped: dict[tuple[str, str, str, str, bool], dict] = {}
        for p in paths:
            key = (
                str(p.get("source") or "tainted-input"),
                str(p.get("sink") or ""),
                str(p.get("file") or ""),
                str(p.get("category") or "system"),
                bool(p.get("sanitized", False)),
            )
            cur = grouped.get(key)
            if cur is None:
                grouped[key] = {
                    "source": key[0],
                    "sink": key[1],
                    "file": key[2],
                    "category": key[3],
                    "sanitized": key[4],
                    "count": 1,
                    "line": int(p.get("line", 1) or 1),
                    "line_samples": [int(p.get("line", 1) or 1)],
                    "severity": str(p.get("severity") or "Low"),
                    "confidence": str(p.get("confidence") or "Medium"),
                    "evidence": str(p.get("evidence") or ""),
                }
                continue
            cur["count"] = int(cur.get("count", 1)) + 1
            line = int(p.get("line", 1) or 1)
            cur["line"] = min(int(cur.get("line", line)), line)
            samples = list(cur.get("line_samples", []))
            if line not in samples and len(samples) < 5:
                samples.append(line)
            cur["line_samples"] = sorted(samples)
            if _severity_rank(str(p.get("severity") or "Low")) > _severity_rank(str(cur.get("severity") or "Low")):
                cur["severity"] = str(p.get("severity") or "Low")
            if _confidence_rank(str(p.get("confidence") or "Medium")) > _confidence_rank(str(cur.get("confidence") or "Medium")):
                cur["confidence"] = str(p.get("confidence") or "Medium")
            if not cur.get("evidence") and p.get("evidence"):
                cur["evidence"] = str(p.get("evidence"))
        out = list(grouped.values())
        out.sort(
            key=lambda p: (
                -_severity_rank(str(p.get("severity") or "Low")),
                -_confidence_rank(str(p.get("confidence") or "Medium")),
                str(p.get("file") or ""),
                int(p.get("line", 1) or 1),
                str(p.get("sink") or ""),
            )
        )
        return out

    out: list[dict] = []
    # Prefer scanner-emitted taint_paths if available; still merge with event-derived paths.
    raw_tp = (scan_dict.get("process_graph") or {}).get("taint_paths") or scan_dict.get("taint_paths") or []
    for p in raw_tp:
        out.append(
            {
                "source": str(p.get("source") or "tainted-input"),
                "sink": str(p.get("sink") or ""),
                "file": str(p.get("file") or ""),
                "line": int(p.get("line", 1) or 1),
                "severity": str(p.get("severity") or "Medium"),
                "sanitized": bool(p.get("sanitized", False)),
                "category": str(p.get("category") or "system"),
                "confidence": str(p.get("confidence") or "Medium"),
                "evidence": str(p.get("evidence") or ""),
            }
        )

    for ev in scan_dict.get("process_events", []) or []:
        risk = str(ev.get("risk") or "Low")
        tainted = bool(ev.get("tainted", False))
        detail = str(ev.get("detail") or "")
        if not (tainted or risk in ("High", "Critical")):
            continue
        fn = str(ev.get("function") or "").lower()
        category = "system"
        if "execute" in fn or "session" in fn or "engine" in fn or "cursor" in fn:
            category = "sql"
        elif "template" in fn or "jinja" in fn:
            category = "template"
        elif "socket" in fn or "connect" in fn:
            category = "network"
        low_detail = detail.lower()
        sanitized = ("sanitized=true" in low_detail) or ("parameterized=true" in low_detail)
        source = "tainted-input"
        if "source=" in low_detail:
            # parse detail fragments: source=..., sink=...
            for part in [x.strip() for x in detail.split(";")]:
                if part.lower().startswith("source="):
                    source = part.split("=", 1)[1].strip() or source
                    break
        out.append(
            {
                "source": source,
                "sink": ev.get("function", ""),
                "file": ev.get("file", ""),
                "line": int(ev.get("line", 1) or 1),
                "severity": risk,
                "sanitized": sanitized,
                "category": category,
                "confidence": _derive_confidence(risk, sanitized, category, detail),
                "evidence": detail,
            }
        )
    # Keep frontend payload compact and deterministic.
    return _group_paths(out)[:120]


def _diff_against_previous(db, scan: Scan, include_suppressed: bool = False) -> dict:
    prev = (
        db.query(Scan)
        .filter(
            Scan.project_path == scan.project_path,
            Scan.id < scan.id,
        )
        .order_by(Scan.id.desc())
        .first()
    )
    if not prev:
        return {
            "has_baseline": False,
            "baseline_scan_id": None,
            "new_count": 0,
            "resolved_count": 0,
            "unchanged_count": 0,
            "new_high_or_critical": 0,
            "new_fingerprints": [],
        }

    cur_v = _scan_to_dict_with_suppressions(db, scan, include_suppressed)["vulnerabilities"]
    prev_v = _scan_to_dict_with_suppressions(db, prev, include_suppressed)["vulnerabilities"]

    cur_map = {
        (v.get("fingerprint") or f"{v.get('file')}:{v.get('line')}:{v.get('type')}"): v
        for v in cur_v
    }
    prev_map = {
        (v.get("fingerprint") or f"{v.get('file')}:{v.get('line')}:{v.get('type')}"): v
        for v in prev_v
    }

    cur_keys = set(cur_map.keys())
    prev_keys = set(prev_map.keys())
    new_keys = sorted(cur_keys - prev_keys)
    resolved_keys = sorted(prev_keys - cur_keys)
    unchanged_keys = sorted(cur_keys & prev_keys)
    new_high = 0
    new_critical = 0
    for k in new_keys:
        sev = str(cur_map[k].get("severity") or "")
        if sev in ("High", "Critical"):
            new_high += 1
        if sev == "Critical":
            new_critical += 1

    return {
        "has_baseline": True,
        "baseline_scan_id": prev.id,
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "unchanged_count": len(unchanged_keys),
        "new_high_or_critical": new_high,
        "new_critical_count": new_critical,
        "new_fingerprints": new_keys[:50],
    }


# ── /api/health ──────────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "AI Security Analyzer API", "sprint": "1.5"})


# ── /api/scan-dependencies ────────────────────────────────────
@app.route("/api/scan-dependencies", methods=["POST"])
def scan_dependencies_only():
    """
    Fast dependency-only vulnerability scan.
    Returns dependency vulnerabilities without full code analysis.
    """
    from scanner.analyzer_dependencies import scan_all_dependencies, convert_to_vulnerability_findings
    
    data = request.get_json(force=True, silent=True) or {}
    project_path = data.get("path", "").strip()
    
    if not project_path:
        return jsonify({"error": "Missing 'path' in request body"}), 400
    
    if not os.path.exists(project_path):
        return jsonify({"error": f"Path does not exist: {project_path}"}), 400
    
    try:
        # Scan dependencies for all ecosystems
        print(f"[DEBUG] Starting dependency scan for: {project_path}")
        dependency_vulns = scan_all_dependencies(project_path)
        print(f"[DEBUG] Found {len(dependency_vulns)} dependency vulnerabilities")
        dependency_findings = convert_to_vulnerability_findings(dependency_vulns)
        print(f"[DEBUG] Converted to {len(dependency_findings)} findings")
        
        # Calculate dependency score
        from scanner.risk_scoring import compute_dependency_score
        from scanner.models import ApplicationModel
        
        temp_model = ApplicationModel(project_path=project_path)
        temp_model.dependency_vulnerabilities = dependency_vulns  # type: ignore
        dependency_score = compute_dependency_score(temp_model)
        
        # Group by ecosystem for better visualization
        ecosystems = {}
        for vuln in dependency_vulns:
            eco = vuln.ecosystem
            if eco not in ecosystems:
                ecosystems[eco] = {"vulnerabilities": [], "count": 0}
            ecosystems[eco]["vulnerabilities"].append({
                "dependency_name": vuln.dependency_name,
                "installed_version": vuln.installed_version,
                "fixed_version": vuln.fixed_version,
                "vulnerability_id": vuln.vulnerability_id,
                "severity": vuln.severity,
                "description": vuln.description,
                "references": vuln.references,
                "file_path": vuln.file_path
            })
            ecosystems[eco]["count"] += 1
        
        return jsonify({
            "project_path": project_path,
            "dependency_vulnerabilities": [
                {
                    "dependency_name": v.dependency_name,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "vulnerability_id": v.vulnerability_id,
                    "severity": v.severity,
                    "description": v.description,
                    "references": v.references,
                    "ecosystem": v.ecosystem,
                    "file_path": v.file_path
                }
                for v in dependency_vulns
            ],
            "summary": {
                "total_vulnerabilities": len(dependency_vulns),
                "dependency_score": dependency_score,
                "ecosystems": ecosystems,
                "severity_breakdown": {
                    "critical": len([v for v in dependency_vulns if v.severity == "Critical"]),
                    "high": len([v for v in dependency_vulns if v.severity == "High"]),
                    "medium": len([v for v in dependency_vulns if v.severity == "Medium"]),
                    "low": len([v for v in dependency_vulns if v.severity == "Low"])
                }
            },
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "type": f.type,
                    "severity": f.severity,
                    "code": f.code,
                    "fingerprint": f.fingerprint,
                    "analyzer": f.analyzer,
                    "rule_id": f.rule_id,
                    "confidence": f.confidence
                }
                for f in dependency_findings
            ]
        })
        
    except Exception as e:
        return jsonify({
            "error": f"Dependency scanning failed: {str(e)}",
            "project_path": project_path,
            "dependency_vulnerabilities": [],
            "summary": {
                "total_vulnerabilities": 0,
                "dependency_score": 0,
                "ecosystems": {},
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0}
            },
            "findings": []
        }), 500


# ── /api/validate-path ───────────────────────────────────────
@app.route("/api/validate-path", methods=["POST"])
def validate_path():
    data = request.get_json(force=True, silent=True) or {}
    project_path = data.get("path", "").strip()

    if not project_path:
        return jsonify({"valid": False, "message": "No path provided."})

    p = Path(project_path)
    if not p.exists():
        return jsonify({"valid": False, "message": f"Path does not exist: {project_path}"})
    if not p.is_dir():
        return jsonify({"valid": False, "message": f"Not a directory: {project_path}"})

    return jsonify({"valid": True, "message": "Path is valid.", "resolved": str(p.resolve())})


# ── /api/scan ────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def run_scan():
    """
    Run the ApplicationModel scanner and auto-save to DB.

    Body:
    {
        "path":         "/absolute/path/to/project",
        "load_content": false,        // optional, default false — structure-only (matches legacy API)
        "scan_mode":    "behavioral", // optional, default "behavioral"
        "incremental":  false,        // optional — Semgrep cache (ignored when load_content is false)
        "codeql_enabled": false,      // optional — explicit CodeQL deep pass toggle
        "semgrep_profile": "balanced", // optional — override; default on server is full community packs (comprehensive)
        "modules": { "static": true, "process": true, ... }  // optional — analysis module toggles (same as upload-scan)
    }
    """
    data = request.get_json(force=True, silent=True) or {}
    project_path = data.get("path", "").strip()
    load_content = data.get("load_content", False)
    scan_mode    = data.get("scan_mode", "behavioral")
    incremental = bool(data.get("incremental", False))
    codeql_enabled = bool(data.get("codeql_enabled", False))
    analysis_modules = _coerce_analysis_modules(data.get("modules"))
    raw_sgp = data.get("semgrep_profile")
    semgrep_profile = str(raw_sgp).strip() if raw_sgp is not None and str(raw_sgp).strip() else None

    if not project_path:
        return jsonify({"status": "error", "error": "No project path provided."}), 400

    p = Path(project_path)
    if not p.exists() or not p.is_dir():
        return jsonify({"status": "error", "error": f"Invalid directory: {project_path}"}), 400

    try:
        model, elapsed_ms = _sync_stream_project_scan(
            str(p.resolve()),
            incremental=incremental,
            codeql_enabled=codeql_enabled,
            pacing_delays=False,
            load_content=load_content,
            analysis_modules=analysis_modules,
            scan_mode=str(scan_mode),
            semgrep_profile=semgrep_profile,
        )

        model_dict = asdict(model)

        # Strip heavy content before returning / storing
        for f in model_dict.get("files", []):
            f.pop("content", None)

        # ── Save to database ──────────────────────────────────
        scan_id = _save_scan_to_db(model_dict, scan_mode, scan_time_ms=elapsed_ms)
        integration = _dispatch_integrations(scan_id, scan_mode, model_dict)

        return jsonify({
            "status":     "success",
            "scan_id":    scan_id,
            "elapsed_ms": round(elapsed_ms, 1),
            "model":      model_dict,
            "integrations": integration,
        })

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


# ── /api/scan-async (Phase 4: background queue) ───────────────
@app.route("/api/scan-async", methods=["POST"])
def run_scan_async():
    """
    Queue a path-based scan on the worker thread.
    Body: { "path": "...", "scan_mode": "behavioral", "load_content": true, "incremental": false,
            "codeql_enabled": false, "modules": { ... } }
    """
    data = request.get_json(force=True, silent=True) or {}
    project_path = (data.get("path") or "").strip()
    scan_mode = data.get("scan_mode", "behavioral")
    load_content = data.get("load_content", True)
    incremental = bool(data.get("incremental", False))
    codeql_enabled = bool(data.get("codeql_enabled", False))
    analysis_modules = _coerce_analysis_modules(data.get("modules"))
    raw_sgp = data.get("semgrep_profile")
    semgrep_profile_job = str(raw_sgp).strip() if raw_sgp is not None and str(raw_sgp).strip() else None

    if not project_path:
        return jsonify({"status": "error", "error": "No project path provided."}), 400
    p = Path(project_path)
    if not p.exists() or not p.is_dir():
        return jsonify({"status": "error", "error": f"Invalid directory: {project_path}"}), 400

    resolved = str(p.resolve())
    db = SessionLocal()
    try:
        job = ScanJob(
            project_path=resolved,
            scan_mode=str(scan_mode),
            load_content=bool(load_content),
            incremental=incremental,
            codeql_enabled=codeql_enabled,
            analysis_modules_json=json.dumps(analysis_modules, ensure_ascii=False) if analysis_modules is not None else None,
            status="queued",
        )
        db.add(job)
        db.commit()
        jid = job.id
        return jsonify({"status": "success", "job_id": jid})
    except Exception as e:
        db.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/jobs/<int:job_id>", methods=["GET"])
def get_scan_job(job_id: int):
    db = SessionLocal()
    try:
        j = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not j:
            return jsonify({"status": "error", "error": "Job not found."}), 404
        return jsonify({
            "status": "success",
            "job": {
                "id": j.id,
                "status": j.status,
                "project_path": j.project_path,
                "scan_mode": j.scan_mode,
                "load_content": j.load_content,
                "incremental": j.incremental,
                "codeql_enabled": bool(getattr(j, "codeql_enabled", False)),
                "result_scan_id": j.result_scan_id,
                "error_message": j.error_message or "",
                "created_at": j.created_at.isoformat() if j.created_at else None,
                "started_at": j.started_at.isoformat() if j.started_at else None,
                "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            },
        })
    finally:
        db.close()


@app.route("/api/telemetry/summary", methods=["GET"])
def telemetry_summary():
    """Phase 4 — aggregate scan duration and reliability counters."""
    limit = min(200, max(1, int(request.args.get("limit", "40"))))
    db = SessionLocal()
    try:
        total_n = db.query(func.count(ScanTelemetry.id)).scalar() or 0
        avg_ms = db.query(func.avg(ScanTelemetry.duration_ms)).scalar()
        cache_hits = (
            db.query(func.count(ScanTelemetry.id))
            .filter(ScanTelemetry.semgrep_cache_hit == True)  # noqa: E712
            .scalar()
            or 0
        )
        codeql_runs = (
            db.query(func.count(ScanTelemetry.id))
            .filter(ScanTelemetry.codeql_enabled == True)  # noqa: E712
            .scalar()
            or 0
        )
        codeql_findings = db.query(func.sum(ScanTelemetry.codeql_finding_count)).scalar() or 0
        recent = (
            db.query(ScanTelemetry)
            .order_by(ScanTelemetry.id.desc())
            .limit(limit)
            .all()
        )
        return jsonify({
            "status": "success",
            "total_samples": int(total_n),
            "avg_duration_ms": round(float(avg_ms or 0.0), 2),
            "semgrep_cache_hits_recorded": int(cache_hits),
            "codeql_runs_recorded": int(codeql_runs),
            "codeql_findings_recorded": int(codeql_findings),
            "recent": [
                {
                    "scan_id": r.scan_id,
                    "duration_ms": r.duration_ms,
                    "vulnerability_count": r.vulnerability_count,
                    "file_count": r.file_count,
                    "semgrep_cache_hit": r.semgrep_cache_hit,
                    "codeql_enabled": bool(getattr(r, "codeql_enabled", False)),
                    "codeql_finding_count": int(getattr(r, "codeql_finding_count", 0) or 0),
                    "error": r.error or "",
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in recent
            ],
        })
    finally:
        db.close()


# ── /api/upload-scan ────────────────────────────────────────
@app.route("/api/upload-scan", methods=["POST"])
def upload_scan():
    """
    Accept uploaded project files from the browser, reconstruct the
    folder structure in a temp directory, run the scanner, save to DB.

    Form fields:
        scan_mode   (str)             e.g. 'behavioral'
        folder_name (str)             root folder label (for display)
        incremental (str)             '1' / 'true' — Semgrep manifest cache (same as SSE)
        files       (FileStorage[])   the actual files
        paths       (str[])           relative paths matching files[]
        modules     (str, JSON)     optional — { "static": true, "process": true, ... }
    """
    scan_mode   = request.form.get("scan_mode",   "behavioral")
    folder_name = request.form.get("folder_name", "uploaded_project")
    incremental = request.form.get("incremental", "0") in ("1", "true", "yes")
    codeql_enabled = request.form.get("codeql_enabled", "0") in ("1", "true", "yes")
    analysis_modules = _coerce_analysis_modules(request.form.get("modules"))
    semgrep_profile_raw = (request.form.get("semgrep_profile") or "").strip()
    semgrep_profile = semgrep_profile_raw or None
    files       = request.files.getlist("files")
    paths       = request.form.getlist("paths")

    if not files:
        return jsonify({"status": "error", "error": "No files uploaded."}), 400
    if len(files) != len(paths):
        return jsonify({"status": "error", "error": "File/path count mismatch."}), 400

    tmp_dir = tempfile.mkdtemp(prefix="ai_sec_scan_")
    try:
        # Reconstruct folder structure
        for f, rel_path in zip(files, paths):
            # Security: strip leading slashes and path traversal
            safe_rel = Path(rel_path.lstrip('/').replace('..', ''))
            target   = Path(tmp_dir) / safe_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            f.save(str(target))

        # Same engine as SSE stream: AST + Semgrep + process graph + risk (optional incremental)
        model, elapsed_ms = _sync_stream_project_scan(
            tmp_dir,
            incremental=incremental,
            codeql_enabled=codeql_enabled,
            pacing_delays=False,
            analysis_modules=analysis_modules,
            scan_mode=scan_mode,
            semgrep_profile=semgrep_profile,
        )

        model_dict = asdict(model)
        for fdata in model_dict.get("files", []):
            fdata.pop("content", None)

        scan_id = _save_scan_to_db(model_dict, scan_mode, scan_time_ms=elapsed_ms)
        integration = _dispatch_integrations(scan_id, scan_mode, model_dict)

        return jsonify({
            "status":     "success",
            "scan_id":    scan_id,
            "elapsed_ms": round(elapsed_ms, 1),
            "model":      model_dict,
            "integrations": integration,
        })

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ── /api/upload-scan-stream (SSE) ─────────────────────────────
@app.route("/api/upload-scan-stream", methods=["POST"])
def upload_scan_stream():
    """
    SSE version of /api/upload-scan.

    Returns a text/event-stream response and emits events:
      - event: log       data: <string>
      - event: progress  data: <json string>  {"percent": number, ...}
      - event: result    data: <json string>  {"status":"success", ...}
      - event: error     data: <string>
      - event: done      data: ok

    Note: EventSource cannot POST multipart, so the frontend uses fetch() and
    parses the SSE stream manually.
    """

    def sse(event: str, data: str) -> str:
        # Ensure no bare newlines break SSE frames
        safe = data.replace("\r", "").split("\n")
        payload = "".join([f"data: {line}\n" for line in safe]) if safe else "data:\n"
        return f"event: {event}\n{payload}\n"

    scan_mode = request.form.get("scan_mode", "behavioral")
    folder_name = request.form.get("folder_name", "uploaded_project")
    incremental = request.form.get("incremental", "0") in ("1", "true", "yes")
    codeql_enabled = request.form.get("codeql_enabled", "0") in ("1", "true", "yes")
    analysis_modules = _coerce_analysis_modules(request.form.get("modules"))
    semgrep_profile_raw = (request.form.get("semgrep_profile") or "").strip()
    semgrep_profile = semgrep_profile_raw or None
    files = request.files.getlist("files")
    paths = request.form.getlist("paths")

    if not files:
        return Response(sse("error", "No files uploaded."), mimetype="text/event-stream", status=400)
    if len(files) != len(paths):
        return Response(sse("error", "File/path count mismatch."), mimetype="text/event-stream", status=400)

    tmp_dir = tempfile.mkdtemp(prefix="ai_sec_scan_")
    total = len(files)

    # ── CRITICAL: save ALL multipart files BEFORE any SSE yield ─────────────
    # Once the streaming Response starts yielding, Werkzeug may close upload
    # streams → "I/O operation on closed file" on f.save(). Non-streaming
    # /api/upload-scan already did this safely; SSE must match that pattern.
    try:
        for f, rel_path in zip(files, paths):
            safe_rel = Path(rel_path.lstrip("/").replace("..", ""))
            target = Path(tmp_dir) / safe_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            f.save(str(target))
    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return Response(sse("error", str(e)), mimetype="text/event-stream", status=400)

    @stream_with_context
    def generate():
        try:
            log_line, log_finding = make_ts_logger()
            yield sse("log", log_line("Initializing scan engine…"))
            yield sse("progress", json.dumps({"percent": 1, "stage": "init"}))
            yield sse("log", log_line(f"Reconstructed project folder: {folder_name} ({total} file(s))"))
            yield sse(
                "progress",
                json.dumps(
                    {
                        "percent": 35,
                        "stage": "upload",
                        "saved": total,
                        "total": total,
                        "files": total,
                    }
                ),
            )
            yield sse("log", log_line("Starting full analysis pipeline (static → process → malicious → tamper → risk)…"))
            yield sse("progress", json.dumps({"percent": 35, "stage": "scan_start"}))

            t0 = time.perf_counter()
            gen = stream_project_scan(
                tmp_dir,
                line_fn=log_line,
                finding_fn=log_finding,
                incremental_semgrep=incremental,
                semgrep_cache_loader=_semgrep_cache_loader if incremental else None,
                codeql_enabled=codeql_enabled,
                analysis_modules=analysis_modules,
                scan_mode=scan_mode,
                semgrep_profile=semgrep_profile,
            )
            model = None
            while True:
                try:
                    evt = next(gen)
                except StopIteration as ex:
                    model = ex.value
                    break
                if evt.get("type") == "log":
                    yield sse("log", evt.get("line", ""))
                    pr = dict(evt.get("progress") or {})
                    # Map engine 0–100% → UI 35–100% (upload used 0–35%)
                    raw = float(pr.get("percent", 0))
                    pr["percent"] = round(35 + (raw / 100.0) * 65, 1)
                    yield sse("progress", json.dumps(pr, ensure_ascii=False))

            elapsed_ms = (time.perf_counter() - t0) * 1000

            if model is None:
                raise RuntimeError("Scan engine did not return a model.")

            model_dict = asdict(model)
            for fdata in model_dict.get("files", []):
                fdata.pop("content", None)

            yield sse("log", log_line("Persisting results to SQLite database…"))
            yield sse("progress", json.dumps({"percent": 99, "stage": "persist"}))

            scan_id = _save_scan_to_db(model_dict, scan_mode, scan_time_ms=elapsed_ms)
            integration = _dispatch_integrations(scan_id, scan_mode, model_dict)

            yield sse("progress", json.dumps({"percent": 100, "stage": "complete", "scan_id": scan_id}))

            result = {
                "status": "success",
                "scan_id": scan_id,
                "elapsed_ms": round(elapsed_ms, 1),
                "model": model_dict,
                "integrations": integration,
            }
            yield sse("result", json.dumps(result, ensure_ascii=False))
            yield sse("done", "ok")
        except Exception as e:
            yield sse("error", str(e))
            yield sse("done", "ok")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── /api/scans (history list) ────────────────────────────────
@app.route("/api/scans", methods=["GET"])
def list_scans():
    """
    Return all past scans, newest first.
    Query params:
        limit  (int, default 50)
        offset (int, default 0)
    """
    limit  = int(request.args.get("limit",  50))
    offset = int(request.args.get("offset",  0))

    db = SessionLocal()
    try:
        scans = (
            db.query(Scan)
            .order_by(Scan.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        total = db.query(Scan).count()

        scan_ids = [s.id for s in scans]
        vuln_totals = {}
        vuln_crit = {}
        if scan_ids:
            vuln_totals = dict(
                db.query(Vulnerability.scan_id, func.count(Vulnerability.id))
                .filter(Vulnerability.scan_id.in_(scan_ids))
                .group_by(Vulnerability.scan_id)
                .all()
            )
            vuln_crit = dict(
                db.query(Vulnerability.scan_id, func.count(Vulnerability.id))
                .filter(
                    Vulnerability.scan_id.in_(scan_ids),
                    Vulnerability.severity == "Critical",
                )
                .group_by(Vulnerability.scan_id)
                .all()
            )

        return jsonify({
            "status": "success",
            "total":  total,
            "scans":  [
                {
                    "id":           s.id,
                    "project_path": s.project_path,
                    "scan_mode":    s.scan_mode,
                    "file_count":   s.file_count,
                    "total_size_kb":round(s.total_size_kb, 2),
                    "created_at":   s.created_at.isoformat() if s.created_at else None,
                    "languages":    [lang.name for lang in s.languages],
                    "risk_score":   s.risk_score,
                    "risk_level":   s.risk_level,
                    "vulnerability_count": vuln_totals.get(s.id, 0),
                    "critical_count":    vuln_crit.get(s.id, 0),
                }
                for s in scans
            ],
        })
    finally:
        db.close()


# ── /api/scans/<id> (single scan detail) ─────────────────────
@app.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """
    Return full detail of one scan including all files.
    Query params:
      include_suppressed=1   include suppressed vulnerabilities
      include_diff=1         include baseline diff payload
      include_policy=1       include policy gate evaluation
      policy_profile=default|balanced|strict
    """
    db = SessionLocal()
    try:
        scan = (
            db.query(Scan)
            .filter(Scan.id == scan_id)
            .options(
                selectinload(Scan.languages),
                selectinload(Scan.files),
                selectinload(Scan.vulnerabilities),
                selectinload(Scan.process_events),
                selectinload(Scan.malicious_indicators),
                selectinload(Scan.process_graph_edges),
                selectinload(Scan.tamper_issues),
            )
            .first()
        )
        if not scan:
            return jsonify({"status": "error", "error": "Scan not found."}), 404
        include_suppressed = request.args.get("include_suppressed", "0") in ("1", "true", "yes")
        include_diff = request.args.get("include_diff", "0") in ("1", "true", "yes")
        include_policy = request.args.get("include_policy", "0") in ("1", "true", "yes")
        policy_profile = request.args.get("policy_profile", "default")
        payload = _scan_to_dict_with_suppressions(db, scan, include_suppressed=include_suppressed)
        tel = (
            db.query(ScanTelemetry)
            .filter(ScanTelemetry.scan_id == scan_id)
            .order_by(ScanTelemetry.id.desc())
            .first()
        )
        payload["telemetry"] = (
            {
                "duration_ms": round(float(tel.duration_ms), 1),
                "semgrep_cache_hit": bool(tel.semgrep_cache_hit),
                "codeql_enabled": bool(getattr(tel, "codeql_enabled", False)),
                "codeql_finding_count": int(getattr(tel, "codeql_finding_count", 0) or 0),
                "error": (tel.error or "").strip(),
            }
            if tel
            else None
        )
        out = {"status": "success", "scan": payload}
        diff_payload = None
        if include_diff:
            diff_payload = _diff_against_previous(db, scan, include_suppressed=include_suppressed)
            out["diff"] = diff_payload
        if include_policy:
            if diff_payload is None:
                diff_payload = _diff_against_previous(db, scan, include_suppressed=include_suppressed)
            out["policy"] = _evaluate_policy(payload, diff_payload, profile=policy_profile)
        return jsonify(out)
    finally:
        db.close()


# ── /api/scans/<id>/diff (baseline vs previous scan) ─────────────────────
@app.route("/api/scans/<int:scan_id>/diff", methods=["GET"])
def scan_diff(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"status": "error", "error": "Scan not found."}), 404
        include_suppressed = request.args.get("include_suppressed", "0") in ("1", "true", "yes")
        return jsonify({
            "status": "success",
            "scan_id": scan.id,
            "diff": _diff_against_previous(db, scan, include_suppressed=include_suppressed),
        })
    finally:
        db.close()


# ── /api/scans/<id>/policy (build gate evaluation) ─────────────────────────
@app.route("/api/scans/<int:scan_id>/policy", methods=["GET"])
def scan_policy(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"status": "error", "error": "Scan not found."}), 404
        include_suppressed = request.args.get("include_suppressed", "0") in ("1", "true", "yes")
        profile = request.args.get("profile", "default")
        payload = _scan_to_dict_with_suppressions(db, scan, include_suppressed=include_suppressed)
        diff_payload = _diff_against_previous(db, scan, include_suppressed=include_suppressed)
        policy = _evaluate_policy(payload, diff_payload, profile=profile)
        return jsonify({"status": "success", "scan_id": scan.id, "policy": policy, "diff": diff_payload})
    finally:
        db.close()


# ── /api/scans/<id>/sarif (SARIF export) ───────────────────────────────────
@app.route("/api/scans/<int:scan_id>/sarif", methods=["GET"])
def export_scan_sarif(scan_id: int):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"status": "error", "error": "Scan not found."}), 404
        include_suppressed = request.args.get("include_suppressed", "1") in ("1", "true", "yes")
        payload = _scan_to_dict_with_suppressions(db, scan, include_suppressed=include_suppressed)
        sarif = _to_sarif(payload)
        return Response(
            json.dumps(sarif, indent=2, ensure_ascii=False),
            mimetype="application/sarif+json",
            headers={"Content-Disposition": f'attachment; filename="scan_report_{scan_id}.sarif"'},
        )
    finally:
        db.close()


# ── /api/suppressions (list/create) ───────────────────────────────────────
@app.route("/api/suppressions", methods=["GET", "POST"])
def suppressions():
    db = SessionLocal()
    try:
        if request.method == "GET":
            project_path = (request.args.get("project_path") or "").strip()
            now = _utc_now()
            q = db.query(VulnerabilitySuppression)
            if project_path:
                q = q.filter(
                    or_(
                        VulnerabilitySuppression.project_path == project_path,
                        VulnerabilitySuppression.project_path.is_(None),
                        VulnerabilitySuppression.project_path == "",
                    )
                )
            q = q.filter(
                or_(
                    VulnerabilitySuppression.expires_at.is_(None),
                    VulnerabilitySuppression.expires_at > now,
                )
            ).order_by(VulnerabilitySuppression.created_at.desc())
            rows = q.all()
            return jsonify({
                "status": "success",
                "suppressions": [
                    {
                        "id": r.id,
                        "fingerprint": r.fingerprint,
                        "project_path": r.project_path,
                        "reason": r.reason or "",
                        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
                        "created_at": r.created_at.isoformat() if r.created_at else None,
                    }
                    for r in rows
                ],
            })

        data = request.get_json(force=True, silent=True) or {}
        fp = (data.get("fingerprint") or "").strip()
        if not fp:
            return jsonify({"status": "error", "error": "fingerprint is required"}), 400
        project_path = (data.get("project_path") or "").strip() or None
        reason = (data.get("reason") or "").strip() or None
        expires_at_raw = (data.get("expires_at") or "").strip()
        expires_at = None
        if expires_at_raw:
            try:
                expires_at = datetime.datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00"))
            except Exception:
                return jsonify({"status": "error", "error": "Invalid expires_at ISO datetime"}), 400

        row = VulnerabilitySuppression(
            fingerprint=fp,
            project_path=project_path,
            reason=reason,
            expires_at=expires_at,
        )
        db.add(row)
        db.commit()
        return jsonify({"status": "success", "suppression_id": row.id})
    except Exception as e:
        db.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500
    finally:
        db.close()


# ── /api/suppressions/<id> DELETE ──────────────────────────────────────────
@app.route("/api/suppressions/<int:suppression_id>", methods=["DELETE"])
def delete_suppression(suppression_id: int):
    db = SessionLocal()
    try:
        row = db.query(VulnerabilitySuppression).filter(VulnerabilitySuppression.id == suppression_id).first()
        if not row:
            return jsonify({"status": "error", "error": "Suppression not found"}), 404
        db.delete(row)
        db.commit()
        return jsonify({"status": "success", "deleted_id": suppression_id})
    except Exception as e:
        db.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500
    finally:
        db.close()


# ── /api/scans/<id> DELETE ───────────────────────────────────
@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id: int):
    """Delete a scan record and all its child rows."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"status": "error", "error": "Scan not found."}), 404
        db.delete(scan)
        db.commit()
        return jsonify({"status": "success", "deleted_id": scan_id})
    except Exception as e:
        db.rollback()
        return jsonify({"status": "error", "error": str(e)}), 500
    finally:
        db.close()


# ── /api/scans/<id>/export ────────────────────────────────────
@app.route("/api/scans/<int:scan_id>/export", methods=["GET"])
def export_scan(scan_id: int):
    """
    Export a scan from the database as a JSON report file.
    Writes to output/reports/scan_report_<id>.json and returns it
    as a file download.

    The JSON is the canonical export format — SQLite is the source of truth.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"status": "error", "error": "Scan not found."}), 404

        # Build report dict
        payload = _scan_to_dict_with_suppressions(db, scan, include_suppressed=True)
        diff_payload = _diff_against_previous(db, scan, include_suppressed=True)
        policy_payload = _evaluate_policy(payload, diff_payload, profile="default")
        report = {
            "report_meta": {
                "generated_at":  _utc_now().isoformat() + "Z",
                "scan_id":       scan.id,
                "format_version": "1.0",
                "tool":          "Application Security & Risk Analyzer",
            },
            "scan_summary": {
                "project_path":  scan.project_path,
                "scan_mode":     scan.scan_mode,
                "file_count":    scan.file_count,
                "total_size_kb": round(scan.total_size_kb, 2),
                "scanned_at":    scan.created_at.isoformat() if scan.created_at else None,
                "languages":     [lang.name for lang in scan.languages],
                "language_breakdown": {
                    lang.name: lang.file_count for lang in scan.languages
                },
            },
            "files": [
                {
                    "file_name":  f.file_name,
                    "file_path":  f.file_path,
                    "file_type":  f.file_type,
                    "extension":  f.extension,
                    "file_size":  f.file_size,
                    "read_error": f.read_error,
                }
                for f in scan.files
            ],
            "vulnerabilities": payload.get("vulnerabilities", []),
            "process_events": [e.to_dict() for e in scan.process_events],
            "malicious_indicators": [m.to_dict() for m in scan.malicious_indicators],
            "process_graph": scan.to_dict().get("process_graph", {"nodes": [], "edges": []}),
            "taint_paths": payload.get("taint_paths", []),
            "tamperability": [t.to_dict() for t in scan.tamper_issues],
            "diff": diff_payload,
            "policy": policy_payload,
            "risk": {
                "overall_score": scan.risk_score,
                "risk_level": scan.risk_level,
                "tamper_score": sum((t.score or 0) for t in scan.tamper_issues),
            },
        }

        # Write to output/reports/
        report_path = REPORTS_DIR / f"scan_report_{scan_id}.json"
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        return send_file(
            str(report_path.resolve()),
            mimetype="application/json",
            as_attachment=True,
            download_name=f"scan_report_{scan_id}.json",
        )

    finally:
        db.close()


# ── /api/scans/<id>/exploit-graph (Graph Visualization) ──────────────────────
@app.route("/api/scans/<int:scan_id>/exploit-graph", methods=["GET"])
def get_exploit_graph(scan_id: int):
    """
    Get exploit chain graph data for visualization.
    Returns STG and ECG graph structures with nodes and edges.
    """
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        
        # Use to_graph_dict() which loads the full STG/ECG JSON blobs.
        # This is intentionally separated from to_dict() to keep the
        # main /api/scans/<id> endpoint fast (no 37MB+ JSON parsing).
        model_data = scan.to_graph_dict()
        
        # Extract STG graph data
        stg_graph = model_data.get("stg_graph", {})
        stg_nodes = []
        stg_edges = []
        
        if stg_graph:
            # Convert STG nodes to graph format
            nodes_data = stg_graph.get("nodes", {})
            if isinstance(nodes_data, dict):
                for node_id, node_data in nodes_data.items():
                    stg_nodes.append({
                        "id": node_id,
                        "label": node_data.get("function_name", node_id),
                        "type": "transaction",
                        "file": node_data.get("file", "unknown"),
                        "line": node_data.get("line", 0),
                        "transaction_type": node_data.get("transaction_type", "unknown"),
                        "data": node_data
                    })
            elif isinstance(nodes_data, list):
                for node_data in nodes_data:
                    stg_nodes.append({
                        "id": node_data.get("id", "unknown"),
                        "label": node_data.get("function_name", node_data.get("id", "unknown")),
                        "type": "transaction",
                        "file": node_data.get("file", "unknown"),
                        "line": node_data.get("line", 0),
                        "transaction_type": node_data.get("transaction_type", "unknown"),
                        "data": node_data
                    })
            
            # Convert STG edges to graph format (capped at 500 max for browser UI performance)
            for edge in stg_graph.get("edges", [])[:500]:
                stg_edges.append({
                    "source": edge.get("from", edge.get("from_node", "unknown")),
                    "target": edge.get("to", edge.get("to_node", "unknown")),
                    "type": edge.get("type", "data_flow"),
                    "status": "valid",
                    "data": edge
                })
        
        # Extract ECG graph data
        ecg_graph = model_data.get("ecg_graph", {})
        ecg_nodes = []
        ecg_edges = []
        eliminated_edges = []
        
        if ecg_graph:
            # Convert ECG nodes to graph format
            nodes_data = ecg_graph.get("nodes", {})
            if isinstance(nodes_data, dict):
                for node_id, node_data in nodes_data.items():
                    ecg_nodes.append({
                        "id": node_id,
                        "label": node_data.get("vulnerability_type", node_id),
                        "type": "vulnerability",
                        "severity": node_data.get("severity", "unknown"),
                        "file": node_data.get("file", "unknown"),
                        "line": node_data.get("line", 0),
                        "stg_mapping": node_data.get("stg_node_id", ""),
                        "data": node_data
                    })
            elif isinstance(nodes_data, list):
                for node_data in nodes_data:
                    ecg_nodes.append({
                        "id": node_data.get("id", "unknown"),
                        "label": node_data.get("vulnerability_type", node_data.get("id", "unknown")),
                        "type": "vulnerability",
                        "severity": node_data.get("severity", "unknown"),
                        "file": node_data.get("file", "unknown"),
                        "line": node_data.get("line", 0),
                        "stg_mapping": node_data.get("stg_node_id", ""),
                        "data": node_data
                    })
            
            # Convert ECG edges to graph format
            for edge in ecg_graph.get("edges", []):
                constraints = edge.get("constraints_satisfied", {})
                if "all_constraints_satisfied" in constraints:
                    is_valid = bool(constraints["all_constraints_satisfied"])
                elif constraints:
                    is_valid = all(bool(v) for v in constraints.values())
                else:
                    is_valid = True

                status = "valid" if is_valid else "eliminated"
                edge_data = {
                    "source": edge.get("from", edge.get("from_node", "unknown")),
                    "target": edge.get("to", edge.get("to_node", "unknown")),
                    "status": status,
                    "data": edge
                }
                
                if status == "eliminated":
                    # Add constraint failure details (supporting both camelCase and snake_case for UI tooltip)
                    df_valid = bool(constraints.get("data_flow", constraints.get("data_flow_valid", constraints.get("dataFlow", False))))
                    eo_valid = bool(constraints.get("execution_order", constraints.get("execution_order_valid", constraints.get("executionOrder", False))))
                    pr_valid = bool(constraints.get("privilege", constraints.get("privilege_valid", False)))
                    edge_data["constraint_failed"] = {
                        "dataFlow": df_valid,
                        "data_flow": df_valid,
                        "executionOrder": eo_valid,
                        "execution_order": eo_valid,
                        "privilege": pr_valid
                    }
                    eliminated_edges.append(edge_data)
                else:
                    ecg_edges.append(edge_data)
        
        # Add dependency vulnerabilities as special nodes
        dependency_vulns = model_data.get("dependency_vulnerabilities", [])
        for dep_vuln in dependency_vulns:
            ecg_nodes.append({
                "id": f"dep_{dep_vuln.get('vulnerability_id', 'unknown')}",
                "label": f"{dep_vuln.get('dependency_name', 'unknown')} - {dep_vuln.get('vulnerability_id', 'unknown')}",
                "type": "dependency",
                "severity": dep_vuln.get("severity", "unknown"),
                "file": dep_vuln.get("file_path", "dependency"),
                "line": 0,
                "stg_mapping": "",
                "data": dep_vuln
            })
        
        # ── Enrich ECG nodes with constraint_analysis from the stored matrix ──────
        ecg_constraint_matrix = ecg_graph.get("constraint_matrix", {}) if ecg_graph else {}
        for ecg_node_entry in ecg_nodes:
            node_id = ecg_node_entry.get("id", "")
            node_constraints = {
                k: v for k, v in ecg_constraint_matrix.items()
                if k.startswith(f"{node_id}->") or k.endswith(f"->{node_id}")
            }
            ecg_node_entry["constraint_analysis"] = node_constraints

        # ── Pull exploit chains from the scan model ────────────────────────────
        exploit_chains = model_data.get("exploit_chains", [])
        constraint_stats = model_data.get("constraint_satisfaction_stats", {})
        exploit_chain_score = model_data.get("exploit_chain_score", 0)
        eliminated_paths_count = model_data.get("eliminated_paths_count", 0)

        # ── Minimal fallback for legacy scans that pre-date the CSAR engine ────
        is_demo_data = False
        if len(stg_nodes) == 0 and len(ecg_nodes) == 0 and not exploit_chains:
            is_demo_data = True
            # Return an informative empty state rather than fake data
            app.logger.info(f"Scan {scan_id} has no STG/ECG data (pre-CSAR scan). Returning empty state.")

        response = {
            "is_demo_data": is_demo_data,
            "stg": {
                "nodes": stg_nodes,
                "edges": stg_edges
            },
            "ecg": {
                "nodes": ecg_nodes,
                "edges": ecg_edges,
                "eliminated_edges": eliminated_edges
            },
            "exploit_chains": exploit_chains,
            "constraint_satisfaction_stats": constraint_stats,
            "statistics": {
                "stg_nodes_count": len(stg_nodes),
                "stg_edges_count": len(stg_edges),
                "ecg_nodes_count": len(ecg_nodes),
                "ecg_edges_count": len(ecg_edges),
                "eliminated_edges_count": len(eliminated_edges),
                "total_vulnerabilities": max(len(model_data.get("vulnerabilities", [])), len(ecg_nodes)),
                "exploit_chain_score": exploit_chain_score,
                "eliminated_paths_count": eliminated_paths_count,
                "confirmed_chains": len([c for c in exploit_chains if c.get("feasibility") == "confirmed"]),
                "total_chains": len(exploit_chains),
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        app.logger.error(f"Error getting exploit graph: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    finally:
        db.close()


# ── Start background worker (after all handlers are defined) ─
_start_background_worker()


# ── Entrypoint ───────────────────────────────────────────────
if __name__ == "__main__":
    print()
    # ASCII-only startup text to avoid Windows console encoding issues.
    print("  AI Application Security Analyzer - API Server")
    print("  Database : SQLite -> database/scans.db")
    print("  Listening: http://localhost:5001")
    print()
    app.run(host="0.0.0.0", port=5001, debug=True)
