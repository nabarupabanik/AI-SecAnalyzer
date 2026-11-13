"""stream_project_scan(load_content=false) matches structure-only API semantics."""

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


def test_load_content_false_skips_vulns_and_risk(tmp_path):
    (tmp_path / "a.py").write_text("import os\nos.system('echo x')\n", encoding="utf-8")
    model = _drain(
        stream_project_scan(
            str(tmp_path),
            load_content=False,
            delay_fn=lambda _s: None,
        )
    )
    assert model is not None
    assert model.file_count >= 1
    assert model.vulnerabilities == []
    assert model.process_events == []
    assert model.tamperability == []
    assert model.overall_score == 0
