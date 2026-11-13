"""
database/models.py
ORM table definitions for the security analyzer.

Tables
──────
  scans      – one row per scan run
  languages  – detected languages per scan (one row per language)
  scan_files – file-level metadata per scan (one row per file)
  vulnerabilities – findings per scan (one row per issue)
  process_events – detected process/system/network events
  malicious_indicators – correlated malicious patterns
  process_graph_edges – directed flow edges per scan

All foreign keys reference scans.id.
"""
import datetime
import json as _json
from sqlalchemy import (
    Column, Integer, String, Float, DateTime,
    ForeignKey, Text, Boolean, UniqueConstraint,
)
from sqlalchemy.orm import relationship
from database.db import Base


class Scan(Base):
    """Top-level scan record."""
    __tablename__ = "scans"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    project_path    = Column(String(1024), nullable=False)
    scan_mode       = Column(String(64),   nullable=False, default="behavioral")
    file_count      = Column(Integer,      nullable=False, default=0)
    total_size_bytes= Column(Integer,      nullable=False, default=0)
    total_size_kb   = Column(Float,        nullable=False, default=0.0)
    scan_time_ms    = Column(Float,        nullable=True)  # future: track duration
    risk_score      = Column(Integer,      nullable=True)
    risk_level      = Column(String(16),   nullable=True)
    created_at      = Column(DateTime,     default=datetime.datetime.utcnow)
    # === CSAR / Exploit Chain columns (added for CSAR engine) ===
    stg_graph_json      = Column(Text, nullable=True)   # JSON: Semantic Transaction Graph
    ecg_graph_json      = Column(Text, nullable=True)   # JSON: Exploit Constraint Graph
    exploit_chains_json = Column(Text, nullable=True)   # JSON: list of exploit chains
    exploit_chain_score = Column(Integer, nullable=True, default=0)
    eliminated_paths    = Column(Integer, nullable=True, default=0)
    constraint_stats_json = Column(Text, nullable=True)  # JSON: constraint satisfaction stats
    # Lightweight counts so to_dict() never parses the large blobs
    stg_node_count      = Column(Integer, nullable=True, default=0)
    stg_edge_count      = Column(Integer, nullable=True, default=0)
    ecg_node_count      = Column(Integer, nullable=True, default=0)
    ecg_edge_count      = Column(Integer, nullable=True, default=0)

    # Security Debt Portfolio column
    security_debt_json   = Column(Text, nullable=True)  # JSON: Security Debt & ROI Analysis
    
    # Dual-AI Remediation column
    dual_ai_remediation_json = Column(Text, nullable=True)  # JSON: Dual-AI Remediation Analysis

    # Relationships
    languages = relationship("Language",  back_populates="scan", cascade="all, delete-orphan")
    files     = relationship("ScanFile",  back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    process_events = relationship("ProcessEventRow", back_populates="scan", cascade="all, delete-orphan")
    malicious_indicators = relationship("MaliciousIndicatorRow", back_populates="scan", cascade="all, delete-orphan")
    process_graph_edges = relationship("ProcessGraphEdge", back_populates="scan", cascade="all, delete-orphan")
    tamper_issues = relationship("TamperIssueRow", back_populates="scan", cascade="all, delete-orphan")

    def to_dict(self):
        import json as _json
        # Reconstruct graph from stored edges (nodes derived)
        edges = [e.to_dict() for e in self.process_graph_edges]
        nodes = sorted({n for e in edges for n in (e["from"], e["to"]) if n})
        def _load(col):
            try: return _json.loads(col) if col else {}
            except Exception: return {}
        def _load_list(col):
            try: return _json.loads(col) if col else []
            except Exception: return []

        # Use pre-computed integer counts — O(1), no blob parsing.
        stg_summary = {
            "total_nodes": self.stg_node_count or 0,
            "total_edges": self.stg_edge_count or 0,
        }
        ecg_stats = {
            "total_nodes": self.ecg_node_count or 0,
            "total_edges": self.ecg_edge_count or 0,
        }
        chains = _load_list(self.exploit_chains_json)


        return {
            "id":               self.id,
            "project_path":     self.project_path,
            "scan_mode":        self.scan_mode,
            "file_count":       self.file_count,
            "total_size_kb":    round(self.total_size_kb, 2),
            "risk_score":       self.risk_score,
            "risk_level":       self.risk_level,
            "created_at":       self.created_at.isoformat() if self.created_at else None,
            "scan_time_ms":     round(float(self.scan_time_ms), 1) if self.scan_time_ms is not None else None,
            "languages":        [lang.name for lang in self.languages],
            "files":            [f.to_dict() for f in self.files],
            "vulnerabilities":  [v.to_dict() for v in self.vulnerabilities],
            "process_events":   [e.to_dict() for e in self.process_events],
            "malicious_indicators": [m.to_dict() for m in self.malicious_indicators],
            "process_graph": {"nodes": nodes, "edges": edges},
            "tamperability": [t.to_dict() for t in self.tamper_issues],
            # === CSAR summary (counts only — full graph is at /exploit-graph) ===
            "exploit_chains":   chains,
            "exploit_chain_score": self.exploit_chain_score or 0,
            "eliminated_paths_count": self.eliminated_paths or 0,
            "constraint_satisfaction_stats": _load(self.constraint_stats_json),
            "stg_summary":      stg_summary,
            "ecg_summary":      ecg_stats,
            "security_debt_analysis": _load(self.security_debt_json),
            "dual_ai_remediation_analysis": _load(self.dual_ai_remediation_json),
        }

    def to_graph_dict(self):
        """Return full STG + ECG graph data for the exploit-graph endpoint."""
        import json as _json
        def _load(col):
            try: return _json.loads(col) if col else {}
            except Exception: return {}
        def _load_list(col):
            try: return _json.loads(col) if col else []
            except Exception: return []
        return {
            "stg_graph":        _load(self.stg_graph_json),
            "ecg_graph":        _load(self.ecg_graph_json),
            "exploit_chains":   _load_list(self.exploit_chains_json),
            "exploit_chain_score": self.exploit_chain_score or 0,
            "eliminated_paths_count": self.eliminated_paths or 0,
            "constraint_satisfaction_stats": _load(self.constraint_stats_json),
        }


class Language(Base):
    """Detected language per scan."""
    __tablename__ = "languages"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    scan_id    = Column(Integer, ForeignKey("scans.id"), nullable=False)
    name       = Column(String(64),  nullable=False)   # e.g. "Python"
    file_count = Column(Integer,     nullable=False, default=1)

    scan = relationship("Scan", back_populates="languages")


class ScanFile(Base):
    """File-level metadata per scan."""
    __tablename__ = "scan_files"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    scan_id    = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file_name  = Column(String(512),  nullable=False)
    file_path  = Column(String(1024), nullable=False)
    file_type  = Column(String(64),   nullable=False)
    extension  = Column(String(16),   nullable=False)
    file_size  = Column(Integer,      nullable=False, default=0)
    read_error = Column(Text,         nullable=True)

    scan = relationship("Scan", back_populates="files")

    def to_dict(self):
        return {
            "file_name":  self.file_name,
            "file_path":  self.file_path,
            "file_type":  self.file_type,
            "extension":  self.extension,
            "file_size":  self.file_size,
            "read_error": self.read_error,
        }


class Vulnerability(Base):
    """Vulnerability finding per scan."""
    __tablename__ = "vulnerabilities"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    scan_id  = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file     = Column(String(1024), nullable=False)
    line     = Column(Integer, nullable=False, default=1)
    type     = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)
    code     = Column(Text, nullable=True)
    fingerprint = Column(String(64), nullable=True, index=True)
    analyzer = Column(String(64), nullable=True)
    rule_id = Column(String(128), nullable=True)
    confidence = Column(String(16), nullable=True)

    scan = relationship("Scan", back_populates="vulnerabilities")

    def to_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "severity": self.severity,
            "code": self.code or "",
            "fingerprint": self.fingerprint or "",
            "analyzer": self.analyzer or "",
            "rule_id": self.rule_id or "",
            "confidence": self.confidence or "",
        }


class ProcessEventRow(Base):
    __tablename__ = "process_events"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    scan_id  = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file     = Column(String(1024), nullable=False)
    line     = Column(Integer, nullable=False, default=1)
    type     = Column(String(128), nullable=False)
    function = Column(String(256), nullable=False)
    risk     = Column(String(16), nullable=False)
    detail   = Column(Text, nullable=True)
    tainted  = Column(Boolean, nullable=False, default=False)

    scan = relationship("Scan", back_populates="process_events")

    def to_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "function": self.function,
            "risk": self.risk,
            "detail": self.detail or "",
            "tainted": bool(self.tainted),
        }


class MaliciousIndicatorRow(Base):
    __tablename__ = "malicious_indicators"

    id       = Column(Integer, primary_key=True, autoincrement=True)
    scan_id  = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file     = Column(String(1024), nullable=False)
    line     = Column(Integer, nullable=False, default=1)
    type     = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)
    evidence = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="malicious_indicators")

    def to_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "severity": self.severity,
            "evidence": self.evidence or "",
        }


class ProcessGraphEdge(Base):
    __tablename__ = "process_graph_edges"

    id      = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    src     = Column(String(256), nullable=False)
    dst     = Column(String(256), nullable=False)
    file    = Column(String(1024), nullable=True)

    scan = relationship("Scan", back_populates="process_graph_edges")

    def to_dict(self):
        return {"from": self.src, "to": self.dst, "file": self.file}


class TamperIssueRow(Base):
    __tablename__ = "tamper_issues"

    id      = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    file    = Column(String(1024), nullable=False)
    line    = Column(Integer, nullable=False, default=1)
    type    = Column(String(128), nullable=False)
    risk    = Column(String(16), nullable=False)
    evidence = Column(Text, nullable=True)
    score   = Column(Integer, nullable=False, default=0)

    scan = relationship("Scan", back_populates="tamper_issues")

    def to_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "type": self.type,
            "risk": self.risk,
            "evidence": self.evidence or "",
            "score": self.score,
        }


class VulnerabilitySuppression(Base):
    __tablename__ = "vulnerability_suppressions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    project_path = Column(String(1024), nullable=True)  # null => global suppression
    reason = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class SemgrepManifestCache(Base):
    """Phase 4 — incremental Semgrep: cache keyed by project path + file manifest hash."""
    __tablename__ = "semgrep_manifest_cache"
    __table_args__ = (UniqueConstraint("project_path", "manifest_hash", name="uq_semgrep_manifest_project"),)

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_path = Column(String(1024), nullable=False, index=True)
    manifest_hash = Column(String(64), nullable=False, index=True)
    findings_json = Column(Text, nullable=False)
    source_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class ScanJob(Base):
    """Phase 4 — async scan queue (path-based scans)."""
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    status = Column(String(32), nullable=False, default="queued")  # queued|running|completed|failed
    project_path = Column(String(1024), nullable=False)
    scan_mode = Column(String(64), nullable=False, default="behavioral")
    load_content = Column(Boolean, nullable=False, default=True)
    incremental = Column(Boolean, nullable=False, default=False)
    codeql_enabled = Column(Boolean, nullable=False, default=False)
    semgrep_profile = Column(String(32), nullable=True)  # optional API override; default comprehensive on worker
    analysis_modules_json = Column(Text, nullable=True)  # JSON dict matching scanner.analysis_modules.MODULE_KEYS
    error_message = Column(Text, nullable=True)
    result_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class ScanTelemetry(Base):
    """Phase 4 — per-scan reliability / timing metrics."""
    __tablename__ = "scan_telemetry"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    duration_ms = Column(Float, nullable=False, default=0.0)
    vulnerability_count = Column(Integer, nullable=False, default=0)
    file_count = Column(Integer, nullable=False, default=0)
    semgrep_cache_hit = Column(Boolean, nullable=False, default=False)
    codeql_enabled = Column(Boolean, nullable=False, default=False)
    codeql_finding_count = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
