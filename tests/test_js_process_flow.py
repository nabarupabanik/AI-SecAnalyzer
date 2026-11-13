from scanner.models import FileModel
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


def test_js_process_flow_detects_exec_and_taint(tmp_path):
    # Minimal Node/Express pattern: req.query -> exec()
    content = """
    const { exec } = require('child_process');
    app.get('/pwn', (req, res) => {
      const cmd = req.query.cmd;
      exec(cmd);
    });
    """
    (tmp_path / "a.js").write_text(content, encoding="utf-8")
    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None
    assert any(e.function in ("child_process.exec", "eval", "Function") for e in model.process_events)
    assert any(getattr(e, "tainted", False) for e in model.process_events)
    pg = model.process_graph or {}
    assert len(pg.get("edges") or []) >= 1
    # Explainability: taint should show an explicit tainted -> sink edge
    assert any((e.get("from") == "tainted" or e.get("to") == "tainted") for e in (pg.get("edges") or []))

