
"""Generate explainable attack hypotheses from detected indicators."""

import json
from pathlib import Path

from hypothesis.evidence_analyzer import analyze_evidence
from hypothesis.hypothesis_ranker import rank_hypotheses

_RULES_PATH = Path(__file__).with_name("hypothesis_rules.json")

with _RULES_PATH.open("r", encoding="utf-8") as f:
    HYPOTHESIS_RULES = json.load(f)


def _to_float(value, default=0.0):
    """Safely convert a value to a numeric score."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_signals(preprocessed):
    """Collect indicators from the known preprocessing structures."""
    preprocessed = preprocessed or {}
    signals = {}

    security = preprocessed.get("security_features", {}) or {}
    obfuscation = preprocessed.get("obfuscation", {}) or {}

    # Support indicators stored as a dictionary.
    if isinstance(security, dict):
        signals.update(security)

    # Support the existing obfuscation score.
    if isinstance(obfuscation, dict):
        signals["obfuscation_score"] = _to_float(
            obfuscation.get("obfuscation_score", 0)
        )
    elif isinstance(obfuscation, (int, float)):
        signals["obfuscation_score"] = _to_float(obfuscation)

    # Normalize numeric indicator values where possible.
    for key, value in list(signals.items()):
        if isinstance(value, str):
            signals[key] = value.strip().lower() in {
                "true", "yes", "1", "detected"
            }

    return signals


def _extract_detector_signals(rule_result, semantic_result):
    """Extract explicitly reported indicators without assuming their schema."""
    extra_signals = {}

    if isinstance(rule_result, dict):
        # Only use indicator maps when the detector explicitly provides them.
        for field in ("indicators", "security_features", "matched_indicators"):
            value = rule_result.get(field)
            if isinstance(value, dict):
                extra_signals.update(value)
            elif isinstance(value, (list, tuple, set)):
                extra_signals.update({name: True for name in value})

    if isinstance(semantic_result, dict):
        for field in ("indicators", "matched_indicators"):
            value = semantic_result.get(field)
            if isinstance(value, dict):
                extra_signals.update(value)
            elif isinstance(value, (list, tuple, set)):
                extra_signals.update({name: True for name in value})

    return extra_signals


def generate_hypotheses(
    preprocessed,
    ml_probability,
    threat_score,
    rule_result,
    semantic_result,
    limit=5,
):
    """Generate ranked hypotheses from explicit attack indicators."""

    signals = _extract_signals(preprocessed)
    detector_signals = _extract_detector_signals(
        rule_result, semantic_result
    )

    # Preserve explicitly detected indicators from detector outputs.
    for key, value in detector_signals.items():
        if value and not signals.get(key):
            signals[key] = value

    ml_probability = _to_float(ml_probability)
    threat_score = _to_float(threat_score)

    if not isinstance(semantic_result, dict):
        semantic_result = {}

    semantic_score = _to_float(semantic_result.get("score", 0))

    try:
        evidence_details = analyze_evidence(
            preprocessed or {}, rule_result
        )
    except Exception as exc:
        evidence_details = {"error": str(exc)}

    print("\n===== ATHS HYPOTHESIS DEBUG =====")
    print("Preprocessed keys:", list((preprocessed or {}).keys()))
    print("Available signals:", signals)
    print("Rule detector output:", rule_result)
    print("Semantic detector output:", semantic_result)
    print("Evidence analysis:", evidence_details)

    results = []

    for key, rule in HYPOTHESIS_RULES.items():
        required = rule.get("indicators", [])
        supporting = rule.get("supporting_indicators", [])

        matched_required = [
            indicator for indicator in required
            if bool(signals.get(indicator, 0))
        ]
        matched_supporting = [
            indicator for indicator in supporting
            if bool(signals.get(indicator, 0))
        ]

        # A hypothesis needs at least one matching required indicator.
        if not matched_required:
            print(f"{key}: skipped; no required indicators matched")
            continue

        coverage = len(matched_required) / max(len(required), 1)
        support_ratio = (
            len(matched_supporting) / max(len(supporting), 1)
        )

        # This is a heuristic ranking score, not a probability.
        score = min(
            0.99,
            0.45 * coverage
            + 0.15 * support_ratio
            + 0.25 * ml_probability
            + 0.15 * semantic_score / 100,
        )

        matched = matched_required + matched_supporting

        results.append({
            "type": key,
            "name": rule["display_name"],
            "confidence_score": round(score, 3),
            "confidence_label": (
                "HIGH" if score >= 0.75
                else "MEDIUM" if score >= 0.50
                else "LOW"
            ),
            "evidence": matched,
            "evidence_descriptions": [
                indicator.replace("_", " ").title()
                + " indicator detected"
                for indicator in matched
            ],
            "description": rule["description"],
            "global_threat_score": int(threat_score),
            "scoring_note": (
                "Heuristic ranking score, not a calibrated probability."
            ),
        })

        print(f"{key}: matched {matched}")

    print("Hypotheses before ranking:", len(results))

    ranked = rank_hypotheses(results, limit=limit)

    print("Hypotheses after ranking:", len(ranked))
    print("=================================\n")

    return ranked
