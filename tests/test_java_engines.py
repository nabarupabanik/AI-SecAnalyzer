from scanner.analyzer_pmd import parse_pmd_xml
from scanner.analyzer_spotbugs import parse_spotbugs_xml
from scanner.java_behavior_analyzer import analyze_single_file_java_process_flow
from scanner.models import FileModel
import networkx as nx


def test_parse_spotbugs_xml_basic():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
  <BugInstance type="SQL_INJECTION_JDBC" rank="4" priority="1">
    <ShortMessage>Possible SQL injection</ShortMessage>
    <LongMessage>Possible SQL injection in JDBC execute call.</LongMessage>
    <SourceLine sourcepath="src/main/java/App.java" start="42" />
  </BugInstance>
</BugCollection>
"""
    out = parse_spotbugs_xml(xml)
    assert len(out) == 1
    assert out[0].analyzer == "spotbugs"
    assert out[0].severity == "High"
    assert out[0].file.endswith("App.java")


def test_parse_pmd_xml_basic():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<pmd>
  <file name="src/main/java/App.java">
    <violation beginline="10" priority="2" rule="AvoidCatchingThrowable" ruleset="Java Error Prone">
      Avoid catching Throwable.
    </violation>
  </file>
</pmd>
"""
    out = parse_pmd_xml(xml)
    assert len(out) == 1
    assert out[0].analyzer == "pmd"
    assert out[0].severity == "High"
    assert out[0].line == 10


def test_java_behavior_detects_exec_and_taint():
    f = FileModel(
        file_name="App.java",
        file_path="src/main/java/App.java",
        file_type="Java",
        extension=".java",
        file_size=100,
        content='String cmd = request.getParameter("cmd"); Runtime.getRuntime().exec(cmd);',
        read_error=None,
    )
    g = nx.DiGraph()
    events, malicious, tpaths = analyze_single_file_java_process_flow(f, g)
    assert events
    assert any(e.function == "Runtime.exec" for e in events)
    assert any(e.tainted for e in events)
    assert tpaths
    assert any(m.type in ("Suspicious Command+Network Correlation", "Potential SQL Injection Path", "Obfuscated Execution Pattern") for m in malicious) or malicious == []

