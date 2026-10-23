
"""Load and run the trained binary classifier."""
from pathlib import Path
import joblib
import numpy as np

class MLThreatDetector:
    def __init__(self, model_path=None):
        root = Path(__file__).resolve().parents[1]
        self.model_path = Path(model_path) if model_path else root / "models" / "threat_classifier.joblib"
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Trained model not found at {self.model_path}. Run `python train_model.py` first."
            )
        self.bundle = joblib.load(self.model_path)
        self.model = self.bundle["model"]

    def predict_probability(self, X):
        X = np.asarray(X, dtype=np.float32)
        probs = self.model.predict_proba(X)
        classes = list(self.model.classes_)
        if 1 not in classes:
            raise ValueError("Classifier does not contain positive class label 1.")
        return float(probs[0, classes.index(1)])
