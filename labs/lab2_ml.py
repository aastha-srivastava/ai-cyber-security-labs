"""Lab 2 - Machine Learning Techniques for Cyber Security.

Compares a tree ensemble against an RBF SVM, reports per-family detection, and
runs a simple evasion experiment: how far a detector degrades when an adversary
nudges flow features toward the normal-class distribution.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             roc_auc_score)
from sklearn.svm import SVC

from common import load, split_all, save

RNG = 1337


def scores(model, Xte):
    return model.predict_proba(Xte)[:, 1]


def main():
    X, y_bin, y_multi = load()
    Xtr, Xte, ytr, yte, ym_te = split_all(X, y_bin, y_multi)

    rf = RandomForestClassifier(n_estimators=250, random_state=RNG, n_jobs=-1,
                                class_weight="balanced_subsample")
    rf.fit(Xtr, ytr)
    rf_pred, rf_score = rf.predict(Xte), scores(rf, Xte)

    # SVM is quadratic in samples; train it on the same data but score on test.
    svm = SVC(kernel="rbf", gamma="scale", class_weight="balanced",
              probability=True, random_state=RNG)
    svm.fit(Xtr, ytr)
    svm_pred, svm_score = svm.predict(Xte), scores(svm, Xte)

    def stats(pred, score):
        p, r, f1, _ = precision_recall_fscore_support(yte, pred, average="binary")
        return dict(accuracy=round(float(accuracy_score(yte, pred)), 4),
                    precision=round(float(p), 4), recall=round(float(r), 4),
                    f1=round(float(f1), 4), roc_auc=round(float(roc_auc_score(yte, score)), 4))

    imp = permutation_importance(rf, Xte, yte, n_repeats=3, random_state=RNG, n_jobs=-1)
    order = np.argsort(-imp.importances_mean)[:8]
    perm = [{"feature": str(X.columns[i]),
             "drop": round(float(imp.importances_mean[i]), 5)} for i in order]

    # --- evasion experiment -------------------------------------------------
    # Move attack flows a fraction of the way toward the normal-class centroid,
    # which is the cheapest evasion an attacker can attempt.
    normal_centroid = Xtr[ytr == 0].mean(axis=0).to_numpy()
    attack_idx = np.where(yte == 1)[0]
    Xatk = Xte.iloc[attack_idx].to_numpy().copy()

    curve = []
    for eps in (0.0, 0.1, 0.2, 0.3, 0.5):
        pert = Xatk + eps * (normal_centroid - Xatk)
        evaded = 1 - rf.predict(pert).mean()
        curve.append({"eps": eps, "evasion_rate": round(float(evaded), 4)})

    save("lab2_metrics.json", {
        "lab": "Lab 2 - Machine Learning Techniques for Cyber Security",
        "models": {"random_forest": stats(rf_pred, rf_score),
                   "svm_rbf": stats(svm_pred, svm_score)},
        "permutation_importance": perm,
        "evasion_curve": curve,
        "n_test": int(len(yte)),
        "n_attack_test": int(len(attack_idx)),
    })


if __name__ == "__main__":
    main()

