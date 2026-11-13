"""
Project file manifest for incremental Semgrep caching (mtime + size + path).
"""

from __future__ import annotations

import hashlib

from .models import FileModel


def compute_project_manifest_hash(files: list[FileModel]) -> str:
    """Stable hash over sorted file paths and filesystem metadata."""
    lines: list[str] = []
    for f in sorted(files, key=lambda x: x.file_path):
        err = "1" if f.read_error else "0"
        bin_hint = "0" if f.content is not None else "1"
        lines.append(f"{f.file_path}|{f.mtime_ns}|{f.file_size}|{err}|{bin_hint}")
    blob = "\n".join(lines).encode("utf-8", errors="replace")
    return hashlib.sha256(blob).hexdigest()[:40]


def semgrep_cache_key(manifest_hash: str, semgrep_profile: str, filter_fingerprint: str = "") -> str:
    """Include rules profile + noise-filter settings so cache stays valid when those change."""
    p = (semgrep_profile or "balanced").strip().lower() or "balanced"
    fp = (filter_fingerprint or "").strip()
    raw = f"{manifest_hash}:{p}:{fp}".encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:40]
