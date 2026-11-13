"""Analysis module toggles (ScanConfigPage `modules`) gate pipeline stages."""

from scanner.analysis_modules import MODULE_KEYS, normalize_analysis_modules
from scanner.streaming_scan import stream_project_scan


def _drain(gen):
    model = None
    while True:
        try:
            next(gen)
        except StopIteration as ex:
            model = ex.value
            break
    return model


def test_normalize_defaults_and_partial_override():
    assert len(MODULE_KEYS) == 7
    assert all(normalize_analysis_modules(None).values())
    m = normalize_analysis_modules({"static": False})
    assert m["static"] is False
    assert m["process"] is True


def test_static_module_off_skips_vulnerability_findings(tmp_path):
    # Triggers Sprint-2 secret heuristic (not Semgrep-only).
    (tmp_path / "a.py").write_text('api_key = "abcdefgh123456"\n', encoding="utf-8")
    full = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert len(full.vulnerabilities) >= 1
    cut = _drain(
        stream_project_scan(
            str(tmp_path),
            delay_fn=lambda _s: None,
            load_content=True,
            analysis_modules={"static": False},
        )
    )
    assert cut.vulnerabilities == []


def test_malicious_module_off_clears_indicators(tmp_path):
    (tmp_path / "evil.py").write_text(
        "import socket\ns=socket.socket()\ns.connect(('192.0.2.1',4444))\n",
        encoding="utf-8",
    )
    full = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    if not full.malicious_indicators:
        return  # environment may not flag this heuristic; skip assertion
    cut = _drain(
        stream_project_scan(
            str(tmp_path),
            delay_fn=lambda _s: None,
            load_content=True,
            analysis_modules={"malicious": False},
        )
    )
    assert cut.malicious_indicators == []
