
"""Combine ML, rules, and semantic similarity into a transparent starter score."""
ML_WEIGHT = 0.60
RULE_WEIGHT = 0.25
SEMANTIC_WEIGHT = 0.15

def severity_for(score):
    if score < 20: return "LOW"
    if score < 45: return "MEDIUM"
    if score < 70: return "HIGH"
    return "CRITICAL"

def fuse_scores(ml_probability, rule_score, semantic_score):
    ml_pct = max(0.0, min(1.0, float(ml_probability))) * 100
    rule_pct = max(0.0, min(100.0, float(rule_score)))
    semantic_pct = max(0.0, min(100.0, float(semantic_score)))
    score = int(round(ML_WEIGHT*ml_pct + RULE_WEIGHT*rule_pct + SEMANTIC_WEIGHT*semantic_pct))
    return {
        "threat_score": score,
        "classification": "malicious" if score >= 50 else "benign",
        "severity": severity_for(score),
        "components": {
            "ml_probability": round(float(ml_probability), 4),
            "ml_percent": round(ml_pct, 2),
            "rule_score": round(rule_pct, 2),
            "semantic_score": round(semantic_pct, 2),
            "weights": {"ml": ML_WEIGHT, "rules": RULE_WEIGHT, "semantic": SEMANTIC_WEIGHT}
        },
        "formula": f"{ML_WEIGHT:.2f}*ML% + {RULE_WEIGHT:.2f}*RuleScore + {SEMANTIC_WEIGHT:.2f}*SemanticScore",
        "calibration_note": "Starter heuristic weights/thresholds; not calibrated probabilities. Validate on held-out data."
    }
