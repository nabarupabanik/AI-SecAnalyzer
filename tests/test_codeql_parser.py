from scanner.analyzer_codeql import parse_sarif_findings


def test_parse_codeql_sarif_basic():
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "py/sql-injection", "defaultConfiguration": {"level": "error"}},
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "message": {"text": "Possible SQL injection in query builder."},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                        "properties": {"precision": "high"},
                    }
                ],
            }
        ]
    }
    out = parse_sarif_findings(payload)
    assert len(out) == 1
    f = out[0]
    assert f.file == "app.py"
    assert f.line == 42
    assert f.rule_id == "py/sql-injection"
    assert f.analyzer == "codeql"
    assert f.severity == "High"
    assert f.confidence == "High"

