"""Lab 4 - AI for Cyber Security: Threat Detection and Prevention.

Turns the detector into a deployable pipeline: picks an operating threshold from
the precision/recall trade-off, measures the alert volume a SOC would actually
receive, and derives prevention rules from the features that drive alerts.
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (confusion_matrix, precision_recall_curve,
                             roc_auc_score, roc_curve)

from common import load, split_all, save

RNG = 1337


def main():
    X, y_bin, y_multi = load()
    Xtr, Xte, ytr, yte, ym_te = split_all(X, y_bin, y_multi)

    rf = RandomForestClassifier(n_estimators=300, random_state=RNG, n_jobs=-1,
                                class_weight="balanced_subsample")
    rf.fit(Xtr, ytr)
    proba = rf.predict_proba(Xte)[:, 1]

    prec, rec, thr = precision_recall_curve(yte, proba)
    fpr, tpr, _ = roc_curve(yte, proba)

    # Operating point: lowest threshold that keeps precision >= 0.95.
    target = 0.95
    idx = np.where(prec[:-1] >= target)[0]
    chosen = float(thr[idx[0]]) if len(idx) else 0.5
    pred = (proba >= chosen).astype(int)

    tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
    alerts = int(tp + fp)

    table = []
    for t in (0.3, 0.5, 0.7, 0.9, round(chosen, 4)):
        p = (proba >= t).astype(int)
        tn2, fp2, fn2, tp2 = confusion_matrix(yte, p).ravel()
        table.append({
            "threshold": round(float(t), 4),
            "precision": round(float(tp2 / max(tp2 + fp2, 1)), 4),
            "recall": round(float(tp2 / max(tp2 + fn2, 1)), 4),
            "alerts_per_10k": int(round((tp2 + fp2) / len(yte) * 10000)),
        })

    fam = {}
    for f in sorted(set(y_multi.tolist())):
        mask = ym_te[yte == 1] == f
        if mask.sum() and f != 0:
            fam[str(f)] = round(float((pred[yte == 1][mask] == 1).mean()), 4)

    feat_imp = sorted(zip(X.columns, rf.feature_importances_),
                      key=lambda p: -p[1])[:6]

    save("lab4_metrics.json", {
        "lab": "Lab 4 - AI for Cyber Security: Threat Detection and Prevention",
        "roc_auc": round(float(roc_auc_score(yte, proba)), 4),
        "operating_threshold": round(chosen, 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "alerts_on_test_set": alerts,
        "alerts_per_10k_flows": int(round(alerts / len(yte) * 10000)),
        "threshold_table": table,
        "per_family_detection": fam,
        "top_features": [{"feature": str(f), "importance": round(float(v), 5)}
                         for f, v in feat_imp],
        "prevention_rules": [
            "rate-limit a single source exceeding 200 SYNs/min (count > 200 and serror_rate > 0.6)",
            "drop flows with flag=S0 and dst_host_srv_count > 200 for 60s",
            "challenge (captcha/MFA) any flow with rerror_rate > 0.5 and same_srv_rate < 0.3",
            "quarantine hosts whose alerts exceed 5 in 10 min for manual triage",
        ],
    })


if __name__ == "__main__":
    main()

