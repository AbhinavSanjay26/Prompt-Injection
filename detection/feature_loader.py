
"""Feature loading and feature-vector construction for ATHS."""
from __future__ import annotations
from pathlib import Path
import numpy as np
import pandas as pd

TABULAR_FEATURES = [
    "word_count", "sentence_count", "unique_word_count", "lexical_diversity",
    "instruction_density", "obfuscation_score", "instruction_override",
    "system_prompt_reference", "role_change_attempt", "data_extraction_attempt",
    "tool_manipulation", "policy_bypass", "prompt_leakage",
    "sensitive_data_reference", "imperative_signal",
]

LABEL_COLUMN = "label"

def load_processed_data(features_path, embeddings_path):
    df = pd.read_csv(features_path)
    embeddings = np.load(embeddings_path)
    if len(df) != len(embeddings):
        raise ValueError(f"Row mismatch: features={len(df)}, embeddings={len(embeddings)}")
    if embeddings.ndim != 2 or embeddings.shape[1] != 384:
        raise ValueError(f"Expected embeddings shape (n, 384); got {embeddings.shape}")
    missing = [c for c in TABULAR_FEATURES + [LABEL_COLUMN] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in features.csv: {missing}")
    return df, embeddings

def make_tabular_matrix(df):
    # Only the explicitly listed numeric features are used; text/metadata columns are excluded.
    return df[TABULAR_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(dtype=np.float32)

def make_combined_matrix(df, embeddings):
    tabular = make_tabular_matrix(df)
    return np.hstack([tabular, embeddings.astype(np.float32)]).astype(np.float32)

def build_live_vector(preprocessed, embedding, tabular_feature_names=TABULAR_FEATURES):
    nlp = preprocessed.get("nlp", {}) or {}
    security = preprocessed.get("security_features", {}) or {}
    obfuscation = preprocessed.get("obfuscation", {}) or {}
    values = {
        "word_count": nlp.get("word_count", 0),
        "sentence_count": nlp.get("sentence_count", 0),
        "unique_word_count": nlp.get("unique_word_count", 0),
        "lexical_diversity": nlp.get("lexical_diversity", 0),
        "instruction_density": security.get("instruction_density", 0),
        "obfuscation_score": obfuscation.get("obfuscation_score", 0),
        "instruction_override": security.get("instruction_override", 0),
        "system_prompt_reference": security.get("system_prompt_reference", 0),
        "role_change_attempt": security.get("role_change_attempt", 0),
        "data_extraction_attempt": security.get("data_extraction_attempt", 0),
        "tool_manipulation": security.get("tool_manipulation", 0),
        "policy_bypass": security.get("policy_bypass", 0),
        "prompt_leakage": security.get("prompt_leakage", 0),
        "sensitive_data_reference": security.get("sensitive_data_reference", 0),
        "imperative_signal": security.get("imperative_signal", 0),
    }
    tab = np.array([float(values.get(k, 0) or 0) for k in tabular_feature_names], dtype=np.float32)
    emb = np.asarray(embedding, dtype=np.float32).reshape(-1)
    if emb.shape[0] != 384:
        raise ValueError(f"Expected a 384-dimensional embedding, got {emb.shape[0]}")
    return np.concatenate([tab, emb]).reshape(1, -1)
