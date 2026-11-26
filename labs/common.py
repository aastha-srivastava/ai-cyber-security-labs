"""Shared loading / encoding helpers for the four lab scripts."""

import json
import os

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV = os.path.join(ROOT, "data", "network_flows.csv")
RESULTS = os.path.join(ROOT, "results")

CATEGORICAL = ["protocol_type", "flag"]


def load():
    df = pd.read_csv(CSV)
    df["is_attack"] = (df["label"] != 0).astype(int)
    X = pd.get_dummies(df.drop(columns=["label", "attack_family", "is_attack"]),
                       columns=CATEGORICAL)
    return X, df["is_attack"].to_numpy(), df["label"].to_numpy()


def split_all(X, y_bin, y_multi, seed=1337):
    """One split for every lab, so all reports score identical rows."""
    idx = np.arange(len(y_bin))
    idx_tr, idx_te = train_test_split(idx, test_size=0.30, random_state=seed,
                                      stratify=y_multi)
    return (X.iloc[idx_tr], X.iloc[idx_te],
            y_bin[idx_tr], y_bin[idx_te],
            y_multi[idx_te])


def save(name, payload):
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    print(f"wrote {path}")
    return path


def top_features(names, weights, k=8):
    pairs = sorted(zip(names, weights), key=lambda p: -abs(p[1]))
    return [{"feature": f, "weight": round(float(w), 5)} for f, w in pairs[:k]]
