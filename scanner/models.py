"""
Sprint 1 — Application Model
Defines the central data structures used by all scanner modules.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Literal, Any

# Import dependency vulnerability type for type hints
try:
    from .analyzer_dependencies import DependencyVulnerability
except ImportError:
    # Fallback type definition if import fails
    @dataclass
    class DependencyVulnerability:
        dependency_name: str
        installed_version: str
        fixed_version: Optional[str]
        vulnerability_id: str
        severity: str
        description: str
        references: List[str]
        ecosystem: str
        file_path: str


@dataclass
class FileModel:
    """Represents a single file discovered during scanning."""
    file_name: str          # e.g. "app.py"
    file_path: str          # absolute or relative path
    file_type: str          # language/type label, e.g. "Python"
    extension: str          # raw extension, e.g. ".py"
    file_size: int          # size in bytes
    mtime_ns: int = 0       # file mtime (ns) for incremental manifests
    content: Optional[str] = None   # raw text content (None for binary/unreadable)
    read_error: Optional[str] = None  # populated if content could not be read


Severity = Literal["Low", "Medium", "High"]
RiskLevel = Literal["Very Low", "Low", "Medium", "High", "Critical"]


@dataclass
class VulnerabilityFinding:
    file: str
    line: int
    type: str
    severity: Severity
    code: str
    fingerprint: str = ""
    analyzer: str = "python_ast"
    rule_id: str = ""
    confidence: str = "Medium"


@dataclass
class ProcessEvent:
    file: str
    line: int
    type: str
    function: str
    risk: Severity
    detail: str = ""
    tainted: bool = False


@dataclass
class MaliciousIndicator:
    file: str
    line: int
    type: str
    severity: Severity
    evidence: str = ""


@dataclass
class TamperIssue:
    file: str
    line: int
    type: str
    risk: Severity
    evidence: str = ""
    score: int = 0


@dataclass
class ApplicationModel:
    """
    Central model for a scanned project.
    All future sprint modules (vulnerability scanner, process analyser, etc.)
    consume this object as their primary input.
    """
    project_path: str                        # Root path that was scanned
    files: List[FileModel] = field(default_factory=list)
    folder_structure: List[str] = field(default_factory=list)   # Pretty-printed tree lines
    languages_detected: List[str] = field(default_factory=list) # Unique languages found
    file_count: int = 0
    total_size_bytes: int = 0
    language_breakdown: Dict[str, int] = field(default_factory=dict)  # lang -> file count
    skipped_files: List[str] = field(default_factory=list)   # Binary / unreadable files
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    dependency_vulnerabilities: List[DependencyVulnerability] = field(default_factory=list)
    process_events: List[ProcessEvent] = field(default_factory=list)
    malicious_indicators: List[MaliciousIndicator] = field(default_factory=list)
    process_graph: Dict[str, Any] = field(default_factory=dict)  # JSON-serializable graph
    tamperability: List[TamperIssue] = field(default_factory=list)
    tamper_score: int = 0

    # Sprint 4 final intelligence
    static_score: int = 0
    process_score: int = 0
    malicious_score: int = 0
    dependency_score: int = 0  # NEW: Sprint 5 dependency vulnerability score
    overall_score: int = 0
    risk_level: RiskLevel = "Very Low"
    
    # === NEW: Exploit Chain Analysis Fields (Patent Critical) ===
    stg_graph: Dict[str, Any] = field(default_factory=dict)  # Semantic Transaction Graph
    ecg_graph: Dict[str, Any] = field(default_factory=dict)  # Exploit Constraint Graph
    exploit_chains: List[Dict[str, Any]] = field(default_factory=list)  # Feasible exploit chains
    eliminated_paths_count: int = 0  # Number of infeasible paths eliminated
    constraint_satisfaction_stats: Dict[str, Any] = field(default_factory=dict)
    exploit_chain_score: int = 0  # Risk score from exploit chains
    
    # === Security Debt & ROI Analysis ===
    security_debt_analysis: Dict[str, Any] = field(default_factory=dict)

    # === Dual-AI Remediation Analysis (Ollama + Groq + AST) ===
    dual_ai_remediation_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Phase 4: non-persisted pipeline metadata (JSON-serializable values only)
    runtime_extras: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        langs = ", ".join(self.languages_detected) if self.languages_detected else "Unknown"
        return (
            f"Files Detected: {self.file_count} | "
            f"Languages: {langs} | "
            f"Total Size: {self.total_size_bytes / 1024:.1f} KB"
        )
