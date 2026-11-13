import pytest

from scanner.analyzer_semgrep import (
    _effective_min_severity_for_profile,
    _finding_passes_noise_filters,
    semgrep_filter_fingerprint,
)


def test_effective_min_severity_defaults():
    assert _effective_min_severity_for_profile("balanced") == "low"
    assert _effective_min_severity_for_profile("comprehensive") == "medium"
    assert _effective_min_severity_for_profile("dvws") == "medium"


def test_effective_min_severity_env_overrides(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SAST_SEMGREP_MIN_SEVERITY", "high")
    assert _effective_min_severity_for_profile("comprehensive") == "high"
    assert _effective_min_severity_for_profile("balanced") == "high"


def test_finding_passes_noise_filters():
    assert _finding_passes_noise_filters("x", "Low", min_severity="medium", exclude_substrings=[]) is False
    assert _finding_passes_noise_filters("x", "Medium", min_severity="medium", exclude_substrings=[]) is True
    assert _finding_passes_noise_filters("yaml.kubernetes.security", "High", min_severity="high", exclude_substrings=["kubernetes"]) is False


def test_filter_fingerprint_reflects_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SAST_SEMGREP_MIN_SEVERITY", raising=False)
    monkeypatch.delenv("SAST_SEMGREP_EXCLUDE_RULE_SUBSTR", raising=False)
    assert "medium" in semgrep_filter_fingerprint("comprehensive")
    monkeypatch.setenv("SAST_SEMGREP_MIN_SEVERITY", "high")
    assert semgrep_filter_fingerprint("comprehensive").startswith("high|")
