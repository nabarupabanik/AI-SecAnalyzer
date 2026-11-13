from scanner.analyzer_codeql import _java_build_command, _pick_language, _suite_for
from scanner.models import FileModel


def _f(path: str) -> FileModel:
    return FileModel(
        file_name=path.split("/")[-1],
        file_path=path,
        file_type="Unknown",
        extension=f".{path.split('.')[-1]}",
        file_size=1,
        content="x",
    )


def test_pick_language_includes_java():
    files = [_f("src/main/java/App.java"), _f("src/main/java/User.java"), _f("src/main/java/Db.java")]
    assert _pick_language(files) == "java"


def test_suite_for_java():
    assert _suite_for("java") == "codeql/java-queries:codeql-suites/java-security-and-quality.qls"


def test_java_build_command_prefers_maven(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    assert _java_build_command(str(tmp_path)) == "mvn -q -DskipTests compile"

