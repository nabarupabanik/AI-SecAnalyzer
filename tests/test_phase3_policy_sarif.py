from api_server import _evaluate_policy, _to_sarif, _derive_taint_paths_from_events


def test_policy_fails_on_new_critical_default():
    scan = {"vulnerabilities": [{"severity": "Critical"}]}
    diff = {"has_baseline": True, "new_critical_count": 1, "new_high_or_critical": 1}
    out = _evaluate_policy(scan, diff, profile="default")
    assert out["fail_build"] is True
    assert out["pass"] is False
    assert any(v["code"] == "NEW_CRITICAL_FINDINGS" for v in out["violations"])


def test_policy_passes_with_no_new_critical():
    scan = {"vulnerabilities": [{"severity": "High"}]}
    diff = {"has_baseline": True, "new_critical_count": 0, "new_high_or_critical": 1}
    out = _evaluate_policy(scan, diff, profile="balanced")
    assert out["fail_build"] is False
    assert out["pass"] is True


def test_sarif_contains_rule_and_result():
    scan = {
        "vulnerabilities": [
            {
                "file": "app.py",
                "line": 12,
                "type": "SQL Injection",
                "severity": "High",
                "rule_id": "pyast.sql_injection",
                "confidence": "High",
                "fingerprint": "abc123",
            }
        ]
    }
    sarif = _to_sarif(scan)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "pyast.sql_injection"


def test_grouped_taint_paths_from_events():
    scan = {
        "process_events": [
            {
                "file": "app.py",
                "line": 10,
                "function": "os.system",
                "risk": "High",
                "tainted": True,
                "detail": "source=flask.request.args; sink=os.system; sanitized=False; confidence=High",
            },
            {
                "file": "app.py",
                "line": 11,
                "function": "os.system",
                "risk": "High",
                "tainted": True,
                "detail": "source=flask.request.args; sink=os.system; sanitized=False; confidence=High",
            },
        ]
    }
    paths = _derive_taint_paths_from_events(scan)
    assert len(paths) == 1
    assert paths[0]["count"] == 2
    assert paths[0]["source"] == "flask.request.args"
