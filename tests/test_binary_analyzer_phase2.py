import types

from scanner.analyzer_binary import analyze_binary_file
from scanner.models import FileModel


class _FakeSection:
    Name = b".packed\x00"
    Characteristics = 0x20000000 | 0x80000000  # EXECUTE | WRITE

    @staticmethod
    def get_entropy():
        return 7.9


class _FakeImport:
    name = b"CreateRemoteThread"


class _FakeImportEntry:
    imports = [_FakeImport()]


class _FakeSecDir:
    Size = 0


class _FakeOptHdr:
    DATA_DIRECTORY = [None, None, None, None, _FakeSecDir()]


class _FakePE:
    sections = [_FakeSection()]
    DIRECTORY_ENTRY_IMPORT = [_FakeImportEntry()]
    OPTIONAL_HEADER = _FakeOptHdr()

    def __init__(self, *_args, **_kwargs):
        pass

    def parse_data_directories(self):
        return None


def test_phase2_pe_metadata_findings(monkeypatch, tmp_path):
    # Inject a fake `pefile` module so test does not require external dependency.
    fake_mod = types.SimpleNamespace(PE=_FakePE)
    monkeypatch.setitem(__import__("sys").modules, "pefile", fake_mod)

    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 256)

    fm = FileModel(
        file_name="tool.exe",
        file_path="tool.exe",
        file_type="Binary",
        extension=".exe",
        file_size=exe.stat().st_size,
    )
    findings = analyze_binary_file(str(tmp_path), fm)
    rule_ids = {f.rule_id for f in findings}

    assert "bin.pe.section.rwx_high_entropy" in rule_ids
    assert "bin.pe.import.createremotethread" in rule_ids
    assert "bin.pe.signature.missing" in rule_ids
