"""
Binary static analyzer (Phase 1 + Phase 2).

Phase 1:
- Fast marker scan in raw bytes for suspicious API/import/string patterns.

Phase 2:
- Optional PE metadata analysis via `pefile` (sections/imports/signing hints).
- Optional YARA matching via `yara-python`.

All optional engines degrade gracefully when unavailable.
"""
from __future__ import annotations

import os
from pathlib import Path

from .models import FileModel, VulnerabilityFinding

_TARGET_EXTS = {".exe", ".dll"}
_MAX_READ_BYTES = 8 * 1024 * 1024  # 8 MB
_MAX_FINDINGS_PER_FILE = 20


# (rule_id, marker_bytes, finding_type, severity, confidence)
_MARKERS: list[tuple[str, bytes, str, str, str]] = [
    ("bin.exec.powershell", b"powershell", "Embedded shell command capability", "High", "High"),
    ("bin.exec.cmd", b"cmd.exe", "Embedded shell command capability", "High", "High"),
    ("bin.inject.virtualallocex", b"VirtualAllocEx", "Possible process injection primitive", "High", "High"),
    ("bin.inject.writeprocessmemory", b"WriteProcessMemory", "Possible process injection primitive", "High", "High"),
    ("bin.inject.createremotethread", b"CreateRemoteThread", "Possible process injection primitive", "High", "High"),
    ("bin.net.winhttp", b"WinHttpOpen", "Network communication primitive in binary", "Medium", "Medium"),
    ("bin.net.internetopen", b"InternetOpen", "Network communication primitive in binary", "Medium", "Medium"),
    ("bin.net.urlmon", b"URLDownloadToFile", "Binary may download remote payloads", "High", "High"),
    ("bin.persistence.registry_run", b"\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Potential autorun persistence string", "Medium", "Medium"),
    ("bin.packer.upx", b"UPX!", "Packed binary marker (UPX)", "Medium", "Medium"),
]

_PHASE2_IMPORT_APIS = {
    "virtualallocex": ("Possible process injection primitive", "High", "High", "bin.pe.import.virtualallocex"),
    "writeprocessmemory": ("Possible process injection primitive", "High", "High", "bin.pe.import.writeprocessmemory"),
    "createremotethread": ("Possible process injection primitive", "High", "High", "bin.pe.import.createremotethread"),
    "ntunmapviewofsection": ("Possible process hollowing primitive", "High", "High", "bin.pe.import.ntunmapviewofsection"),
    "urldownloadtofilea": ("Binary may download remote payloads", "High", "High", "bin.pe.import.urldownloadtofilea"),
    "urldownloadtofilew": ("Binary may download remote payloads", "High", "High", "bin.pe.import.urldownloadtofilew"),
    "winhttpreaddata": ("Network communication primitive in binary", "Medium", "Medium", "bin.pe.import.winhttpreaddata"),
    "internetreadfile": ("Network communication primitive in binary", "Medium", "Medium", "bin.pe.import.internetreadfile"),
    "winexec": ("Legacy command execution primitive", "High", "High", "bin.pe.import.winexec"),
    "shellexecutea": ("Command execution primitive", "High", "High", "bin.pe.import.shellexecutea"),
    "shellexecutew": ("Command execution primitive", "High", "High", "bin.pe.import.shellexecutew"),
}


def _read_binary(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read(_MAX_READ_BYTES)


def _append_finding(out: list[VulnerabilityFinding], finding: VulnerabilityFinding) -> None:
    if len(out) < _MAX_FINDINGS_PER_FILE:
        out.append(finding)


def _phase1_marker_scan(file_path: str, payload: bytes) -> list[VulnerabilityFinding]:
    out: list[VulnerabilityFinding] = []
    lower = payload.lower()

    if not payload.startswith(b"MZ"):
        _append_finding(
            out,
            VulnerabilityFinding(
                file=file_path,
                line=1,
                type="Executable extension but missing MZ header",
                severity="Medium",
                code="Binary has .exe/.dll extension but does not look like a PE header.",
                analyzer="binary_static",
                rule_id="bin.pe.invalid_header",
                confidence="Medium",
            ),
        )

    for rule_id, marker, finding_type, sev, conf in _MARKERS:
        if marker.lower() not in lower:
            continue
        _append_finding(
            out,
            VulnerabilityFinding(
                file=file_path,
                line=1,
                type=finding_type,
                severity=sev,  # type: ignore[arg-type]
                code=f"Detected marker `{marker.decode('latin-1', errors='ignore')}` in binary strings/imports.",
                analyzer="binary_static",
                rule_id=rule_id,
                confidence=conf,
            ),
        )
    return out


def _phase2_pe_metadata_scan(file_path: str, abs_path: Path) -> list[VulnerabilityFinding]:
    out: list[VulnerabilityFinding] = []

    try:
        import pefile  # type: ignore
    except Exception:
        return out

    try:
        pe = pefile.PE(str(abs_path), fast_load=True)
        pe.parse_data_directories()
    except Exception:
        return out

    # Suspicious sections: executable + writable + high entropy.
    for s in getattr(pe, "sections", []) or []:
        try:
            name = (getattr(s, "Name", b"") or b"").decode("latin-1", errors="ignore").strip("\x00")
            ent = float(s.get_entropy() or 0.0)
            ch = int(getattr(s, "Characteristics", 0) or 0)
            is_exec = bool(ch & 0x20000000)
            is_write = bool(ch & 0x80000000)
            if is_exec and is_write and ent >= 7.2:
                _append_finding(
                    out,
                    VulnerabilityFinding(
                        file=file_path,
                        line=1,
                        type="Suspicious executable+writable high-entropy section",
                        severity="High",
                        code=f"Section `{name or 'unknown'}` entropy={ent:.2f} with EXECUTE+WRITE characteristics.",
                        analyzer="binary_static",
                        rule_id="bin.pe.section.rwx_high_entropy",
                        confidence="High",
                    ),
                )
        except Exception:
            continue

    # Import-based heuristics.
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in getattr(entry, "imports", []) or []:
            name_b = getattr(imp, "name", None)
            if not name_b:
                continue
            fn = str(name_b.decode("latin-1", errors="ignore")).strip().lower()
            meta = _PHASE2_IMPORT_APIS.get(fn)
            if not meta:
                continue
            finding_type, sev, conf, rule_id = meta
            _append_finding(
                out,
                VulnerabilityFinding(
                    file=file_path,
                    line=1,
                    type=finding_type,
                    severity=sev,  # type: ignore[arg-type]
                    code=f"PE import table contains `{fn}`.",
                    analyzer="binary_static",
                    rule_id=rule_id,
                    confidence=conf,
                ),
            )

    # Signing hint: no security directory often means unsigned binary.
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
        sec_size = int(getattr(sec_dir, "Size", 0) or 0)
        if sec_size <= 0:
            _append_finding(
                out,
                VulnerabilityFinding(
                    file=file_path,
                    line=1,
                    type="Unsigned executable artifact",
                    severity="Low",
                    code="PE security directory is empty; binary appears unsigned.",
                    analyzer="binary_static",
                    rule_id="bin.pe.signature.missing",
                    confidence="Low",
                ),
            )
    except Exception:
        pass

    return out


def _phase2_yara_scan(file_path: str, abs_path: Path) -> list[VulnerabilityFinding]:
    out: list[VulnerabilityFinding] = []
    # Auto-enable YARA by default. Allow explicit opt-out for constrained environments.
    # Supported OFF values: 0, false, no, off
    yara_flag = os.environ.get("SAST_ENABLE_YARA", "").strip().lower()
    if yara_flag in ("0", "false", "no", "off"):
        return out

    try:
        import yara  # type: ignore
    except Exception:
        return out

    rules_path = os.environ.get("SAST_YARA_RULES", "").strip()
    if not rules_path:
        default = Path(__file__).resolve().parent / "yara_rules" / "binaries.yar"
        rules_path = str(default)
    p = Path(rules_path)
    if not p.exists() or not p.is_file():
        return out

    try:
        rules = yara.compile(filepath=str(p))
        matches = rules.match(str(abs_path), timeout=8)
    except Exception:
        return out

    for m in matches[:_MAX_FINDINGS_PER_FILE]:
        name = str(getattr(m, "rule", "yara_rule"))
        tags = [str(t) for t in (getattr(m, "tags", []) or [])]
        sev = "Medium"
        if any(t.lower() in ("critical", "high", "malware", "ransomware") for t in tags):
            sev = "High"
        _append_finding(
            out,
            VulnerabilityFinding(
                file=file_path,
                line=1,
                type=f"YARA match: {name}",
                severity=sev,  # type: ignore[arg-type]
                code=f"Matched rule `{name}` with tags={tags or ['n/a']}.",
                analyzer="binary_static",
                rule_id=f"bin.yara.{name}",
                confidence="Medium",
            ),
        )
    return out


def analyze_binary_file(project_path: str, f: FileModel) -> list[VulnerabilityFinding]:
    if f.extension not in _TARGET_EXTS:
        return []

    abs_path = (Path(project_path) / Path(f.file_path)).resolve()
    if not abs_path.exists() or not abs_path.is_file():
        return []

    try:
        payload = _read_binary(abs_path)
    except Exception:
        return []

    out: list[VulnerabilityFinding] = []
    out.extend(_phase1_marker_scan(f.file_path, payload))
    out.extend(_phase2_pe_metadata_scan(f.file_path, abs_path))
    out.extend(_phase2_yara_scan(f.file_path, abs_path))

    # Keep order stable and enforce overall cap.
    return out[:_MAX_FINDINGS_PER_FILE]
