
"""Transparent rule-based threat indicators. Scores are heuristics, not probabilities."""
RULE_WEIGHTS = {
    "instruction_override": 20,
    "system_prompt_reference": 18,
    "role_change_attempt": 12,
    "data_extraction_attempt": 12,
    "tool_manipulation": 12,
    "policy_bypass": 15,
    "prompt_leakage": 18,
    "sensitive_data_reference": 8,
    "imperative_signal": 4,
}

def score_rules(preprocessed):
    security = preprocessed.get("security_features", {}) or {}
    obfuscation = preprocessed.get("obfuscation", {}) or {}
    raw = 0.0
    triggered = []
    for feature, weight in RULE_WEIGHTS.items():
        if bool(security.get(feature, 0)):
            raw += weight
            triggered.append({
                "feature": feature, "points": weight,
                "description": feature.replace("_", " ").title() + " indicator detected"
            })
    obs = float(obfuscation.get("obfuscation_score", 0) or 0)
    if obs > 0:
        points = min(10.0, obs * 10.0)
        raw += points
        triggered.append({
            "feature": "obfuscation_score", "points": round(points, 2),
            "description": "Obfuscation signal detected"
        })
    return {
        "score": int(round(min(100.0, raw))),
        "raw_points": round(raw, 2),
        "triggered_rules": triggered,
        "note": "Transparent heuristic; tune against validation data before production use."
    }
