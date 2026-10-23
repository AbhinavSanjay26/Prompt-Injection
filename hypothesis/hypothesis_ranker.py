
"""Rank hypotheses by evidence coverage and supporting indicators."""
def rank_hypotheses(hypotheses, limit=5):
    ranked = sorted(
        hypotheses,
        key=lambda h: (h.get("confidence_score", 0), len(h.get("evidence", []))),
        reverse=True
    )
    return ranked[:limit]
