from scanner.models import VulnerabilityFinding
from scanner.static_dispatcher import normalize_finding, dedupe_findings


def test_normalize_adds_fingerprint_and_metadata():
    v = VulnerabilityFinding(
        file="C:\\repo\\app.py",
        line=12,
        type="sqli",
        severity="error",
        code="cursor.execute(query + user_input)",
    )
    n = normalize_finding(v, "C:\\repo")
    assert n.file == "app.py"
    assert n.type == "SQL Injection"
    assert n.severity == "High"
    assert n.fingerprint
    assert n.analyzer == "python_ast"
    assert n.confidence == "Medium"


def test_dedupe_collapses_same_fingerprint_per_file():
    a = VulnerabilityFinding(
        file="app.py",
        line=8,
        type="SQL Injection",
        severity="High",
        code="cursor.execute(query + user_input)",
    )
    b = VulnerabilityFinding(
        file="app.py",
        line=18,
        type="SQL injection",  # different case + line
        severity="error",
        code="cursor.execute(query + user_input)",
        analyzer="semgrep",
    )
    out = dedupe_findings([a, b], ".")
    assert len(out) == 1
