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


def test_binary_analyzer_flags_suspicious_markers(tmp_path):
    # Minimal fake PE-like payload with suspicious markers in string table/imports.
    payload = b"MZ" + b"\x00" * 64 + b"VirtualAllocEx\x00WriteProcessMemory\x00powershell\x00"
    (tmp_path / "dropper.exe").write_bytes(payload)

    model = _drain(stream_project_scan(str(tmp_path), delay_fn=lambda _s: None, load_content=True))
    assert model is not None

    bin_findings = [v for v in model.vulnerabilities if (v.analyzer or "") == "binary_static"]
    assert len(bin_findings) >= 1
    assert any("process injection" in (v.type or "").lower() or "shell command" in (v.type or "").lower() for v in bin_findings)
