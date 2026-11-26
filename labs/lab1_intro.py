"""Lab 1 - Introduction to AI and Cyber Security.

Baseline: a linear (logistic regression) intrusion detector on network-flow
features, used to establish the attack taxonomy and the baseline metrics every
later lab is compared against.
"""

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_recall_fscore_support)

from common import load, split_all, save, top_features


def main():
    X, y_bin, y_multi = load()
    Xtr, Xte, ytr, yte, ym_te = split_all(X, y_bin, y_multi)

    model = LogisticRegression(max_iter=2000, class_weight="balanced")
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)

    p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="binary")
    cm = confusion_matrix(yte, pred)

    payload = {
        "lab": "Lab 1 - Introduction to AI and Cyber Security",
        "task": "binary intrusion detection (attack vs normal)",
        "model": "LogisticRegression (balanced)",
        "n_train": int(Xtr.shape[0]),
        "n_test": int(Xte.shape[0]),
        "n_features": int(X.shape[1]),
        "accuracy": round(float(accuracy_score(yte, pred)), 4),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "confusion_matrix": cm.tolist(),
        "per_class": classification_report(yte, pred, output_dict=True, digits=4),
        "feature_weights": top_features(list(X.columns), model.coef_[0]),
        "attack_families": sorted(set(y_multi.tolist())),
    }
    save("lab1_metrics.json", payload)


if __name__ == "__main__":
    main()

