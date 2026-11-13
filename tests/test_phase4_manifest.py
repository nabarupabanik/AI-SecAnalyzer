from scanner.incremental_manifest import compute_project_manifest_hash, semgrep_cache_key
from scanner.models import FileModel


def test_manifest_changes_when_mtime_changes():
    a = FileModel(
        file_name="a.py",
        file_path="a.py",
        file_type="Python",
        extension=".py",
        file_size=10,
        mtime_ns=100,
        content="x",
    )
    b = FileModel(
        file_name="a.py",
        file_path="a.py",
        file_type="Python",
        extension=".py",
        file_size=10,
        mtime_ns=200,
        content="x",
    )
    assert compute_project_manifest_hash([a]) != compute_project_manifest_hash([b])


def test_semgrep_cache_key_includes_profile():
    h = "a" * 40
    assert semgrep_cache_key(h, "balanced") != semgrep_cache_key(h, "comprehensive")
    assert semgrep_cache_key(h, "balanced") == semgrep_cache_key(h, "balanced")
    assert semgrep_cache_key(h, "comprehensive", "medium|") != semgrep_cache_key(h, "comprehensive", "low|")
