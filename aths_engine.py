
"""Public ATHS interface for prompt analysis."""
from pathlib import Path
import numpy as np
from preprocessing.pipeline import PreprocessingPipeline
from detection.feature_loader import build_live_vector, TABULAR_FEATURES
from detection.ml_detector import MLThreatDetector
from detection.embedding_detector import EmbeddingSimilarityDetector
from detection.rule_detector import score_rules
from detection.threat_fusion import fuse_scores
from hypothesis.hypothesis_engine import generate_hypotheses

class ATHSEngine:
    def __init__(self, model_path=None, centroids_path=None, enable_embeddings=True):
        self.preprocessor = PreprocessingPipeline(enable_embeddings=enable_embeddings)
        self.detector = MLThreatDetector(model_path)
        self.embedding_detector = EmbeddingSimilarityDetector(centroids_path)
        self.enable_embeddings = enable_embeddings
        self.bundle = self.detector.bundle

    def analyze(self, prompt, context_source="user_prompt", trust_level="untrusted"):
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("Please provide a non-empty prompt.")
        pre = self.preprocessor.process_text(prompt)
        embedding = pre.get("semantic_embedding")
        if not isinstance(embedding, (list, tuple, np.ndarray)):
            detail = embedding.get("error") if isinstance(embedding, dict) else None
            raise RuntimeError("Semantic embedding unavailable. Check sentence-transformers/model download. " + str(detail or ""))
        vector = build_live_vector(pre, embedding, self.bundle.get("tabular_features", TABULAR_FEATURES))
        ml_probability = self.detector.predict_probability(vector)
        rules = score_rules(pre)
        semantic = self.embedding_detector.score(embedding)
        detection = fuse_scores(ml_probability, rules["score"], semantic["score"])
        hypotheses = generate_hypotheses(pre, ml_probability, detection["threat_score"], rules, semantic)
        if detection["severity"] in {"HIGH", "CRITICAL"}:
            action = "REVIEW_OR_BLOCK"
        elif detection["severity"] == "MEDIUM":
            action = "REVIEW"
        else:
            action = "ALLOW_WITH_MONITORING"
        return {
            "input": {"prompt": prompt},
            "detection": {
                "label": detection["classification"], "threat_score": detection["threat_score"],
                "severity": detection["severity"], "ml_probability": round(ml_probability, 4),
                "rule_score": rules["score"], "semantic_score": semantic["score"],
                "score_components": detection["components"], "formula": detection["formula"],
                "calibration_note": detection["calibration_note"]
            },
            "hypotheses": hypotheses,
            "explainability": {
                "evidence": rules["triggered_rules"],
                "feature_analysis": __import__("hypothesis.evidence_analyzer", fromlist=["analyze_evidence"]).analyze_evidence(pre, rules),
                "semantic_similarity": semantic,
                "security_features": pre.get("security_features", {}),
                "obfuscation_features": pre.get("obfuscation", {}),
                "nlp_features": pre.get("nlp", {})
            },
            "context": {"source": context_source, "trust_level": trust_level},
            "recommendation": {
                "action": action,
                "note": "Advisory starter policy only. Do not automatically block real activity without validation and human/security-policy review."
            }
        }
