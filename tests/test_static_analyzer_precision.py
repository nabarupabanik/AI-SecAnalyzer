from scanner.models import FileModel
from scanner.static_analyzer import analyze_single_python_file_static


def _file(src: str) -> FileModel:
    return FileModel(
        file_name="app.py",
        file_path="app.py",
        file_type="Python",
        extension=".py",
        file_size=len(src.encode("utf-8")),
        content=src,
    )


def test_does_not_flag_parameterized_execute_as_sqli():
    src = """
def f(cursor, user_id):
    q = "SELECT * FROM users WHERE id=%s"
    cursor.execute(q, (user_id,))
"""
    findings = analyze_single_python_file_static(_file(src))
    assert not any(f.type == "SQL Injection" for f in findings)


def test_flags_tainted_dynamic_execute_with_high_confidence():
    src = """
def f(cursor):
    user_input = input("id: ")
    q = "SELECT * FROM users WHERE id=" + user_input
    cursor.execute(q)
"""
    findings = analyze_single_python_file_static(_file(src))
    sqli = [f for f in findings if f.type == "SQL Injection"]
    assert sqli, "expected SQL Injection finding"
    assert any(f.confidence == "High" for f in sqli)


def test_skips_placeholder_secrets():
    src = """
API_KEY = "changeme"
SECRET = "test"
PASSWORD = "dummy"
"""
    findings = analyze_single_python_file_static(_file(src))
    assert not any(f.type == "Hardcoded Secret" for f in findings)

