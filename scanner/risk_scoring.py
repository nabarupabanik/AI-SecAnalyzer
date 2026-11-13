"""
Sprint 4 — Risk Scoring Engine

Final score:
R = 0.25S + 0.25P + 0.20M + 0.15T + 0.15D

Where:
S = static score (Sprint 2)
P = process score (Sprint 3)
M = malicious score (Sprint 3)
T = tamper score (Sprint 4)
D = dependency score (Sprint 5) - NEW!
"""

from __future__ import annotations

from collections import Counter

from .models import ApplicationModel


def _clamp_int(x: float, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(round(x))))


def classify_risk_level(score: int) -> str:
    if score <= 20:
        return "Very Low"
    if score <= 40:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def compute_static_score(model: ApplicationModel) -> int:
    # Simple severity weights (tunable)
    weights = {"Low": 5, "Medium": 10, "High": 20}
    score = 0
    for v in model.vulnerabilities:
        score += weights.get(v.severity, 5)
    return _clamp_int(score)


def compute_process_score(model: ApplicationModel) -> int:
    weights = {"Low": 5, "Medium": 10, "High": 20}
    score = 0
    for e in model.process_events:
        score += weights.get(e.risk, 5)
        if e.tainted:
            score += 10  # tainted execution is more risky
    return _clamp_int(score)


def compute_malicious_score(model: ApplicationModel) -> int:
    weights = {"Low": 10, "Medium": 20, "High": 30}
    score = 0
    for m in model.malicious_indicators:
        score += weights.get(m.severity, 10)
    return _clamp_int(score)


def compute_dependency_score(model: ApplicationModel) -> int:
    """
    Calculate risk score from dependency vulnerabilities.
    Dependencies often pose the highest risk due to supply chain attacks.
    """
    weights = {"Low": 8, "Medium": 15, "High": 25, "Critical": 35}
    score = 0
    
    for dep in model.dependency_vulnerabilities:
        # Weight dependency vulnerabilities higher than code vulnerabilities
        severity_weight = weights.get(dep.severity, 15)
        
        # Additional weight for critical ecosystems (npm, pip)
        ecosystem_multiplier = 1.0
        if dep.ecosystem in ["npm", "pip"]:
            ecosystem_multiplier = 1.2  # 20% boost for most common ecosystems
        
        # Additional weight if no fix is available
        fix_multiplier = 1.0
        if not dep.fixed_version:
            fix_multiplier = 1.3  # 30% boost for unfixed vulnerabilities
        
        score += severity_weight * ecosystem_multiplier * fix_multiplier
    
    return _clamp_int(score)


def compute_overall_risk(model: ApplicationModel) -> None:
    S = compute_static_score(model)
    P = compute_process_score(model)
    M = compute_malicious_score(model)
    T = int(model.tamper_score or 0)
    D = compute_dependency_score(model)

    # Updated formula: R = 0.25S + 0.25P + 0.20M + 0.15T + 0.15D
    R = 0.25 * S + 0.25 * P + 0.20 * M + 0.15 * T + 0.15 * D
    overall = _clamp_int(R)

    model.static_score = S
    model.process_score = P
    model.malicious_score = M
    # Add dependency score to model for tracking
    model.dependency_score = D
    model.overall_score = overall
    model.risk_level = classify_risk_level(overall)  # type: ignore[assignment]

