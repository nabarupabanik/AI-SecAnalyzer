"""
Scan config: Analysis Modules toggles from the UI (static, process, taint, …).

When omitted, all modules default to enabled so API clients behave as before.
"""

from __future__ import annotations

from typing import Any

# Keys must match frontend `MODULES` ids in ScanConfigPage.tsx
MODULE_KEYS = ("static", "process", "taint", "malicious", "tamper", "ai", "graph")


def normalize_analysis_modules(raw: dict[str, Any] | None) -> dict[str, bool]:
    defaults = {k: True for k in MODULE_KEYS}
    if not raw:
        return defaults
    out = {**defaults}
    for k in MODULE_KEYS:
        if k in raw:
            out[k] = bool(raw[k])
    return out
