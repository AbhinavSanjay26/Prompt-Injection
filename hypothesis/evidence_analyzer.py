
"""Collect evidence in a consistent, UI-friendly structure."""
def analyze_evidence(preprocessed, rule_result):
    security = preprocessed.get("security_features", {}) or {}
    obfuscation = preprocessed.get("obfuscation", {}) or {}
    nlp = preprocessed.get("nlp", {}) or {}
    features = {}
    for name, value in security.items():
        if name.endswith("_hits"):
            continue
        if isinstance(value, (int, float, bool)):
            features[name] = value
    for name, value in obfuscation.items():
        if isinstance(value, (int, float, bool)):
            features[name] = value
    return {
        "triggered_rules": rule_result.get("triggered_rules", []),
        "active_features": [k for k, v in features.items() if bool(v)],
        "feature_values": features,
        "nlp_summary": {k: nlp.get(k) for k in (
            "token_count", "word_count", "sentence_count", "unique_word_count", "lexical_diversity"
        ) if k in nlp},
        "obfuscation_features": obfuscation,
    }
