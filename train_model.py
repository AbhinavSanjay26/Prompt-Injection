
"""Train/evaluate ATHS baseline; writes classifier, semantic centroids, and metrics."""
from __future__ import annotations
import argparse, json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, normalize
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
from detection.feature_loader import load_processed_data, make_combined_matrix, TABULAR_FEATURES

ROOT = Path(__file__).resolve().parent

def split_indices(X, y, groups):
    # Group-aware split when useful group IDs exist; fallback is stratified random split.
    if groups is not None and len(set(map(str, groups))) >= 10:
        try:
            first = GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=42)
            trainval, test = next(first.split(X, y, groups))
            second = GroupShuffleSplit(n_splits=1, test_size=(0.15/0.85), random_state=43)
            tr_rel, val_rel = next(second.split(X[trainval], y[trainval], groups[trainval]))
            return trainval[tr_rel], trainval[val_rel], test, "GroupShuffleSplit using group_id"
        except Exception:
            pass
    all_idx = np.arange(len(y))
    trainval, test = train_test_split(all_idx, test_size=0.15, random_state=42, stratify=y)
    train, val = train_test_split(trainval, test_size=(0.15/0.85), random_state=43, stratify=y[trainval])
    return train, val, test, "Stratified random split (group-aware split unavailable)"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", default="dataset/processed/features.csv")
    parser.add_argument("--embeddings", default="dataset/processed/embeddings.npy")
    parser.add_argument("--model-out", default="models/threat_classifier.joblib")
    parser.add_argument("--centroids-out", default="models/embedding_centroids.joblib")
    parser.add_argument("--report-out", default="evaluation/evaluation.json")
    args = parser.parse_args()
    features_path, embeddings_path = Path(args.features), Path(args.embeddings)
    df, embeddings = load_processed_data(features_path, embeddings_path)
    X = make_combined_matrix(df, embeddings)
    y = pd.to_numeric(df["label"], errors="raise").to_numpy(dtype=int)
    if set(np.unique(y)) != {0, 1}:
        raise ValueError(f"Expected labels 0 and 1, found {np.unique(y).tolist()}")
    groups = df["group_id"].astype(str).to_numpy() if "group_id" in df.columns else None
    train_idx, val_idx, test_idx, split_strategy = split_indices(X, y, groups)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=3000, class_weight="balanced", random_state=42))
    ])
    model.fit(X[train_idx], y[train_idx])
    val_prob = model.predict_proba(X[val_idx])[:, list(model.classes_).index(1)]
    # Use a fixed baseline threshold; validation metrics are reported for transparency.
    val_pred = (val_prob >= 0.5).astype(int)
    test_prob = model.predict_proba(X[test_idx])[:, list(model.classes_).index(1)]
    test_pred = (test_prob >= 0.5).astype(int)
    cm = confusion_matrix(y[test_idx], test_pred, labels=[0,1])
    auc = float(roc_auc_score(y[test_idx], test_prob)) if len(np.unique(y[test_idx])) > 1 else None

    # Build normalized class centroids using training split only (avoids test leakage).
    E = np.asarray(embeddings, dtype=np.float32)
    E_train = E[train_idx]
    y_train = y[train_idx]
    benign_centroid = E_train[y_train == 0].mean(axis=0)
    malicious_centroid = E_train[y_train == 1].mean(axis=0)
    centroids = {
        "benign_centroid": normalize(benign_centroid.reshape(1,-1))[0],
        "malicious_centroid": normalize(malicious_centroid.reshape(1,-1))[0],
        "embedding_dimensions": int(E.shape[1]),
        "training_rows": int(len(train_idx)),
        "note": "Centroids use training split only."
    }
    model_bundle = {
        "model": model, "tabular_features": TABULAR_FEATURES,
        "embedding_dimensions": int(E.shape[1]), "vector_dimensions": int(X.shape[1]),
        "positive_label": 1, "training_rows": int(len(train_idx)),
        "model_type": "StandardScaler + LogisticRegression"
    }
    model_out, centroids_out, report_out = Path(args.model_out), Path(args.centroids_out), Path(args.report_out)
    for out in (model_out, centroids_out, report_out): out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_bundle, model_out)
    joblib.dump(centroids, centroids_out)
    metrics = {
        "dataset_rows": int(len(df)), "feature_columns": TABULAR_FEATURES,
        "embedding_dimensions": int(E.shape[1]), "vector_dimensions": int(X.shape[1]),
        "split_strategy": split_strategy,
        "split_sizes": {"train": int(len(train_idx)), "validation": int(len(val_idx)), "test": int(len(test_idx))},
        "test_metrics": {
            "accuracy": float(accuracy_score(y[test_idx], test_pred)),
            "precision_malicious": float(precision_score(y[test_idx], test_pred, zero_division=0)),
            "recall_malicious": float(recall_score(y[test_idx], test_pred, zero_division=0)),
            "f1_malicious": float(f1_score(y[test_idx], test_pred, zero_division=0)),
            "roc_auc": auc, "confusion_matrix_labels_0_1": cm.tolist(),
            "classification_report": classification_report(y[test_idx], test_pred, labels=[0,1], target_names=["benign","malicious"], output_dict=True, zero_division=0),
            "false_positive_rate": float(cm[0,1] / max(cm[0,0] + cm[0,1], 1)),
            "false_negative_rate": float(cm[1,0] / max(cm[1,0] + cm[1,1], 1))
        },
        "validation_metrics_at_threshold_0_5": {
            "accuracy": float(accuracy_score(y[val_idx], val_pred)),
            "precision_malicious": float(precision_score(y[val_idx], val_pred, zero_division=0)),
            "recall_malicious": float(recall_score(y[val_idx], val_pred, zero_division=0)),
            "f1_malicious": float(f1_score(y[val_idx], val_pred, zero_division=0))
        },
        "notes": [
            "This is a baseline model and one held-out split, not a guarantee of real-world performance.",
            "Fusion weights and severity thresholds are heuristics, not calibrated probabilities.",
            "Embeddings are used as input features; centroids are trained using training data only."
        ],
        "sklearn_version": sklearn.__version__
    }
    report_out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({"model_saved": str(model_out), "centroids_saved": str(centroids_out), "report_saved": str(report_out), "test_metrics": metrics["test_metrics"], "split_sizes": metrics["split_sizes"]}, indent=2))

if __name__ == "__main__":
    main()
