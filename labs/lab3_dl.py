"""Lab 3 - Deep Learning Techniques for Cyber Security.

Multi-layer perceptron detector, compared against the Lab 2 ensemble, plus a
per-family breakdown so we can see where the network loses recall (typically
R2L and U2R, the low-volume classes).
"""

import numpy as np
from sklearn.inspection import permutation_importance
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from common import load, split_all, save

RNG = 1337


def main():
    X, y_bin, y_multi = load()
    Xtr, Xte, ytr, yte, ym_te = split_all(X, y_bin, y_multi)

    scaler = StandardScaler().fit(Xtr)
    Xtr_s, Xte_s = scaler.transform(Xtr), scaler.transform(Xte)

    mlp = MLPClassifier(hidden_layer_sizes=(64, 32), activation="relu",
                        alpha=1e-4, max_iter=300, random_state=RNG,
                        early_stopping=True, n_iter_no_change=15)
    mlp.fit(Xtr_s, ytr)
    pred = mlp.predict(Xte_s)
    proba = mlp.predict_proba(Xte_s)[:, 1]

    p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="binary")

    # per-family recall on the multiclass labels of the same test rows
    fam_recall = {}
    for fam in sorted(set(ym_te.tolist())):
        mask = ym_te == fam
        if mask.sum():
            fam_recall[str(fam)] = round(float((pred[mask] == (0 if fam == 0 else 1)).mean()), 4)

    imp = permutation_importance(mlp, Xte_s, yte, n_repeats=3, random_state=RNG, n_jobs=-1)
    order = np.argsort(-imp.importances_mean)[:8]

    save("lab3_metrics.json", {
        "lab": "Lab 3 - Deep Learning Techniques for Cyber Security",
        "model": "MLP 64-32 relu, scaled features",
        "accuracy": round(float(accuracy_score(yte, pred)), 4),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(yte, proba)), 4),
        "epochs_run": int(getattr(mlp, "n_iter_", 0)),
        "confusion_matrix": confusion_matrix(yte, pred).tolist(),
        "per_family_recall": fam_recall,
        "permutation_importance": [
            {"feature": str(X.columns[i]), "drop": round(float(imp.importances_mean[i]), 5)}
            for i in order],
        "report": classification_report(yte, pred, output_dict=True, digits=4),
    })


if __name__ == "__main__":
    main()

