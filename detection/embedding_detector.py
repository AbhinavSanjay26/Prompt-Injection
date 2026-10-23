
"""Class-centroid semantic similarity detector using training-only embeddings."""
from pathlib import Path
import joblib
import numpy as np

def _normalize_rows(x):
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    return x / np.maximum(norms, 1e-12)

class EmbeddingSimilarityDetector:
    def __init__(self, artifact_path=None):
        root = Path(__file__).resolve().parents[1]
        self.path = Path(artifact_path) if artifact_path else root / "models" / "embedding_centroids.joblib"
        if not self.path.exists():
            raise FileNotFoundError(f"Embedding centroids not found at {self.path}. Run train_model.py first.")
        self.artifact = joblib.load(self.path)
        self.benign = np.asarray(self.artifact["benign_centroid"], dtype=np.float32).reshape(1, -1)
        self.malicious = np.asarray(self.artifact["malicious_centroid"], dtype=np.float32).reshape(1, -1)

    def score(self, embedding):
        v = np.asarray(embedding, dtype=np.float32).reshape(1, -1)
        if v.shape[1] != self.benign.shape[1]:
            raise ValueError(f"Embedding dimension mismatch: {v.shape[1]}")
        v = _normalize_rows(v)
        benign_sim = float((_normalize_rows(self.benign) @ v.T)[0, 0])
        malicious_sim = float((_normalize_rows(self.malicious) @ v.T)[0, 0])
        # Convert similarity difference to a bounded score. This is a heuristic, not probability.
        margin = malicious_sim - benign_sim
        score = float(100.0 / (1.0 + np.exp(-8.0 * margin)))
        return {
            "score": round(score, 2),
            "benign_centroid_similarity": round(benign_sim, 4),
            "malicious_centroid_similarity": round(malicious_sim, 4),
            "margin": round(margin, 4),
            "note": "Centroid similarity score is a heuristic, not a calibrated probability."
        }
