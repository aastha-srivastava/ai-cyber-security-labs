"""Build the four capstone PDF reports from the measured results.

Run after the labs: python reports/build_reports.py
"""

import json
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (ListFlowable, ListItem, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STUDENT = "Aastha Srivastava"
ROLL = "2301350027"
COURSE = "ENSP305 - AI in Cyber Security"
REPO = "https://github.com/aastha-srivastava/ai-cyber-security-labs"

styles = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16, spaceAfter=4)
H2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=11.5, spaceBefore=8, spaceAfter=3)
BODY = ParagraphStyle("BODY", parent=styles["BodyText"], fontSize=9.4, leading=13)
SMALL = ParagraphStyle("SMALL", parent=styles["BodyText"], fontSize=8, textColor=colors.grey)


def load(name):
    with open(os.path.join(ROOT, "results", name), encoding="utf-8") as fh:
        return json.load(fh)


def bullets(items):
    return ListFlowable([ListItem(Paragraph(t, BODY), leftIndent=10) for t in items],
                        bulletType="bullet", start="•", leftIndent=12)


def table(rows, widths):
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b9c2cc")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def build(spec, out):
    doc = SimpleDocTemplate(out, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=spec["title"], author=STUDENT)
    s = []
    s.append(Paragraph(spec["title"], H1))
    s.append(Paragraph(f"{COURSE} · {STUDENT} · {ROLL}", SMALL))
    s.append(Spacer(1, 6))

    s.append(Paragraph("1. Attack type and AI/ML detection strategy", H2))
    for p in spec["attack"]:
        s.append(Paragraph(p, BODY))

    s.append(Paragraph("2. Engineered features and rationale", H2))
    s.append(Paragraph(spec["features_intro"], BODY))
    s.append(bullets(spec["features"]))

    s.append(Paragraph("3. Adversarial compromise and mitigation", H2))
    for p in spec["adversarial"]:
        s.append(Paragraph(p, BODY))

    s.append(Paragraph("4. Explaining an alert to a non-technical stakeholder", H2))
    for p in spec["xai"]:
        s.append(Paragraph(p, BODY))

    s.append(Paragraph("5. Ethical / privacy concern", H2))
    for p in spec["ethics"]:
        s.append(Paragraph(p, BODY))

    s.append(Paragraph("Measured results", H2))
    s.append(Paragraph(spec["results_intro"], BODY))
    s.append(Spacer(1, 4))
    s.append(table(spec["table_rows"], spec["table_widths"]))
    if spec.get("results_note"):
        s.append(Spacer(1, 4))
        s.append(Paragraph(spec["results_note"], BODY))

    s.append(Paragraph("Reproducing", H2))
    s.append(Paragraph(
        f"All figures above are produced by the scripts in <font color='#1f4e79'>{REPO}</font>. "
        "Generate the dataset with <i>python data/generate_dataset.py</i>, run each lab under "
        "<i>labs/</i>, then rebuild these reports with <i>python reports/build_reports.py</i>. "
        "Every run is seeded, so the numbers reproduce exactly.", BODY))
    s.append(Spacer(1, 6))
    s.append(Paragraph(f"Repository: {REPO}", SMALL))

    doc.build(s)
    print("wrote", out)


COMMON_FEATURES = [
    "<b>flag_SF / flag_S0 / flag_REJ</b> - TCP termination state. S0 (no reply) is the single "
    "strongest signal of a flood or a filtered scan, which is why it dominates the tree ensemble.",
    "<b>serror_rate, rerror_rate</b> - share of connections to the same host that failed at "
    "SYN or at reset. Sustained error rates separate automated tooling from human traffic.",
    "<b>count, srv_count</b> - connections to the same host and service in a 2-second window. "
    "This is the rate signal an analogue firewall cannot see on a per-packet basis.",
    "<b>same_srv_rate, diff_srv_rate</b> - service dispersion. A scanner touches many ports "
    "(low same_srv_rate); a flood concentrates on one (high same_srv_rate).",
    "<b>dst_host_count, dst_host_srv_count</b> - fan-out of the destination, which distinguishes "
    "one victim receiving a flood from many victims being swept.",
    "<b>src_bytes, dst_bytes, duration</b> - payload asymmetry. Scans send little and receive "
    "little; bulk exfiltration inverts the ratio.",
]


def lab1():
    d = load("lab1_metrics.json")
    return dict(
        title="Lab 1 - Introduction to AI and Cyber Security",
        attack=[
            "The scenario modelled here is a <b>volumetric denial-of-service flood</b>, "
            "specifically the SYN-flood family. The attacker opens a large number of half-open "
            "TCP connections from spoofed sources so the victim's backlog fills and legitimate "
            "clients cannot complete the handshake.",
            "Detection strategy: a <b>supervised binary classifier</b> over per-flow records, "
            "trained to separate normal from attack traffic. A linear model (logistic regression) "
            "is deliberately used first to establish the baseline that the later labs improve on. "
            "It is cheap, explains itself through coefficients, and tells us whether a linear "
            "decision boundary is already sufficient for this feature set.",
        ],
        features_intro="The model consumes the following engineered features:",
        features=COMMON_FEATURES,
        adversarial=[
            "A flood can be made to look normal by <b>rate shaping</b>: slow the SYN rate below "
            "the count threshold and complete the handshake often enough to keep serror_rate low. "
            "That trades volume for duration, which is exactly the boundary a linear model is "
            "worst at representing.",
            "Mitigation: add <b>temporal features</b> (rate over a 60-second and a 10-minute "
            "window) so that a slow flood accumulates evidence, and retrain with adversarially "
            "shaped samples so the classifier has seen the evasive regime.",
        ],
        xai=[
            "For a non-technical stakeholder the alert is presented as: <i>\"At 14:02 this host "
            "received 480 connection attempts in two seconds and 92% of them were never answered. "
            "Normal traffic on this segment peaks at 40 attempts with under 3% unanswered.\"</i>",
            "The coefficient view supports that sentence directly: flag_S0 and serror_rate carry "
            "the decision, and both translate into plain operational language (unanswered "
            "connections) rather than model jargon.",
        ],
        ethics=[
            "Flow records contain source and destination addresses, and retaining them for model "
            "training turns a monitoring system into a location and behaviour archive. The concern "
            "is <b>function creep</b>: data collected for flood detection can later be used to "
            "profile individual users.",
            "Mitigation: store flow metadata under a short retention window, hash or truncate "
            "source addresses in the training extract, and document the permitted uses at "
            "collection time.",
        ],
        results_intro="Logistic regression, 70/30 stratified split, balanced class weights.",
        table_rows=[
            ["Metric", "Value"],
            ["Accuracy", str(d["accuracy"])],
            ["Precision", str(d["precision"])],
            ["Recall", str(d["recall"])],
            ["F1", str(d["f1"])],
            ["Features after one-hot", str(d["n_features"])],
            ["Train / test rows", f"{d['n_train']} / {d['n_test']}"],
        ],
        table_widths=[90 * mm, 60 * mm],
        results_note=(
            f"Confusion matrix [[TN, FP], [FN, TP]] = {d['confusion_matrix']}. "
            f"Strongest coefficients: "
            + ", ".join(f"{f['feature']} ({f['weight']})" for f in d["feature_weights"][:3])
            + "."),
    )


def lab2():
    d = load("lab2_metrics.json")
    rf, sv = d["models"]["random_forest"], d["models"]["svm_rbf"]
    ev = d["evasion_curve"]
    imp = d["permutation_importance"][:4]
    return dict(
        title="Lab 2 - Machine Learning Techniques for Cyber Security",
        attack=[
            "The scenario is a <b>network probe / port scan</b>: an adversary maps reachable "
            "services before a targeted intrusion. Probe traffic is low-volume and deliberately "
            "varied, so it is the natural test of whether a non-linear model beats the linear "
            "baseline from Lab 1.",
            "Detection strategy: compare a <b>random forest</b> against an <b>RBF support vector "
            "machine</b> on the same split. The forest captures threshold interactions "
            "(a high count matters only when serror_rate is also high); the SVM provides a "
            "smooth margin-based contrast.",
        ],
        features_intro="Features are shared with Lab 1, with the emphasis different for scanning:",
        features=[
            "<b>rerror_rate</b> - scans hit closed ports, so reset rates climb before SYN error "
            "rates do. This is the earliest scan signal.",
            "<b>diff_srv_rate</b> - the fraction of connections to different services. Scanners "
            "fan out across ports, which is close to a direct measurement of scanning behaviour.",
            "<b>count and dst_host_count</b> - scanning is a rate phenomenon, so windowed counts "
            "carry most of the discriminative weight.",
            "<b>flag_REJ</b> - rejected connections indicate probes against filtered ports.",
            "<b>src_bytes, dst_bytes</b> - scans transfer almost nothing in either direction.",
        ],
        adversarial=[
            "The purest evasion of a scan detector is to <b>scan slowly and from many sources</b>, "
            "keeping each individual source below the rate threshold. A distributed scan never "
            "triggers a per-host count rule.",
            f"The evasion experiment quantifies the related tabular attack: moving attack flows "
            f"part-way toward the normal-class centroid degrades the forest from "
            f"{ev[0]['evasion_rate']:.2%} to {ev[-1]['evasion_rate']:.2%} evasion at "
            f"eps={ev[-1]['eps']}. That is a real but modest shift, which is the useful result - "
            "a tree ensemble on this feature set is not trivially fooled by linear perturbation.",
            "Mitigation: aggregate features across sources (cardinality of distinct sources per "
            "destination), and add a second detector trained on the aggregated view so a "
            "distributed scan becomes visible as a single coordinated event.",
        ],
        xai=[
            "The alert reads: <i>\"This host contacted 187 different ports in two minutes and 61% "
            "of those attempts were rejected. A workstation on this network typically contacts "
            "fewer than 6 ports in the same window.\"</i>",
            "Permutation importance is what makes that honest: "
            + ", ".join(f"{i['feature']} ({i['drop']})" for i in imp)
            + " are the features whose shuffling actually degrades the model, so the explanation "
            "names causes rather than correlated noise.",
        ],
        ethics=[
            "Aggregating flows per source improves detection but also builds a <b>behavioural "
            "profile of every host</b>, including the ones that never attack. Once that profile "
            "exists it invites secondary uses - productivity monitoring, disciplinary action - "
            "that were never part of the security mandate.",
            "Mitigation: keep the aggregate view ephemeral (rolling window, not stored history), "
            "restrict access to the security team, and publish the retention period.",
        ],
        results_intro="Random forest (250 trees) versus RBF SVM, identical split.",
        table_rows=[
            ["Model", "Accuracy", "Precision", "Recall", "F1", "ROC-AUC"],
            ["Random forest", str(rf["accuracy"]), str(rf["precision"]), str(rf["recall"]),
             str(rf["f1"]), str(rf["roc_auc"])],
            ["RBF SVM", str(sv["accuracy"]), str(sv["precision"]), str(sv["recall"]),
             str(sv["f1"]), str(sv["roc_auc"])],
        ],
        table_widths=[45 * mm, 24 * mm, 24 * mm, 22 * mm, 20 * mm, 22 * mm],
        results_note=(
            "Evasion rate as attack flows are blended toward the normal centroid: "
            + ", ".join(f"eps={e['eps']} -> {e['evasion_rate']:.2%}" for e in ev) + "."),
    )


def lab3():
    d = load("lab3_metrics.json")
    fam = d["per_family_recall"]
    imp = d["permutation_importance"][:4]
    return dict(
        title="Lab 3 - Deep Learning Techniques for Cyber Security",
        attack=[
            "The scenario is <b>remote-to-local (R2L) intrusion</b> - credential stuffing and "
            "brute-force login attempts against exposed services. R2L is the class that the "
            "shallow models handle worst because a successful login looks almost exactly like a "
            "legitimate one at the flow level.",
            "Detection strategy: a <b>multi-layer perceptron (64-32, ReLU)</b> over standardised "
            "features. Standardisation matters here: rate features are bounded in [0,1] while "
            "byte counts reach thousands, and an unscaled network would be dominated by the "
            "large-magnitude columns.",
        ],
        features_intro="The network uses the same feature set, with scaling applied first:",
        features=[
            "<b>duration</b> - interactive intrusion sessions run far longer than automated "
            "traffic, which completes or fails in milliseconds.",
            "<b>src_bytes</b> - credential attempts carry small credential payloads but repeat "
            "many times per session.",
            "<b>rerror_rate</b> - repeated failed authentication is the defining R2L signal.",
            "<b>same_srv_rate</b> - R2L concentrates on a single service (ssh, ftp, telnet) "
            "rather than fanning out.",
            "<b>dst_host_srv_count</b> - repeated hits on the same service from the same "
            "destination pair.",
        ],
        adversarial=[
            "A deep model is vulnerable to <b>gradient-based evasion</b>: an attacker who can "
            "observe the model's output can nudge flow features just enough to cross the decision "
            "boundary. For R2L the practical version is <b>low-and-slow credential stuffing</b> - "
            "one attempt per account per hour stays inside the normal duration and count ranges.",
            "Mitigation: rate features computed over long windows (hours, not seconds) so that "
            "slow campaigns accumulate, plus an ensemble of independently trained models so a "
            "perturbation tuned to one model does not transfer cleanly to all of them.",
        ],
        xai=[
            "The alert reads: <i>\"This account was tried against the SSH service 41 times in 20 "
            "minutes from one host, and 38 of those attempts failed. A normal user fails twice "
            "and then succeeds or stops.\"</i>",
            "Permutation importance on the trained network ranks "
            + ", ".join(f"{i['feature']} ({i['drop']})" for i in imp)
            + ", so the explanation points at concrete measurable quantities rather than an "
            "opaque score.",
        ],
        ethics=[
            "R2L detection watches <b>authentication behaviour</b>, which is close to watching "
            "people. A false positive here can lock a student out of their account during an "
            "assessment, and the model's errors land hardest on users with unusual but legitimate "
            "patterns - shared lab machines, travellers, users with accessibility tooling.",
            "Mitigation: treat the model as a triage aid rather than an automatic blocker, and "
            "require human review before any account action.",
        ],
        results_intro="MLP 64-32, standardised inputs, early stopping.",
        table_rows=[
            ["Metric", "Value"],
            ["Accuracy", str(d["accuracy"])],
            ["Precision", str(d["precision"])],
            ["Recall", str(d["recall"])],
            ["F1", str(d["f1"])],
            ["ROC-AUC", str(d["roc_auc"])],
            ["Epochs run", str(d["epochs_run"])],
            ["Recall on DoS / Probe / R2L / U2R",
             " / ".join(f"{fam[k]:.3f}" for k in sorted(fam) if k != "0")],
        ],
        table_widths=[90 * mm, 60 * mm],
        results_note=f"Confusion matrix [[TN, FP], [FN, TP]] = {d['confusion_matrix']}.",
    )


def lab4():
    d = load("lab4_metrics.json")
    c = d["confusion"]
    fam = d["per_family_detection"]
    thr = d["threshold_table"]
    return dict(
        title="Lab 4 - AI for Cyber Security: Threat Detection and Prevention",
        attack=[
            "The scenario is <b>user-to-root (U2R) privilege escalation</b> combined with the "
            "wider SOC problem: the detector has to run at a threshold a human team can actually "
            "service. U2R is rare, so this lab focuses on the deployment side - alert volume, "
            "base rate, and prevention actions.",
            "Detection strategy: a 300-tree random forest with an <b>operating threshold chosen "
            "from the precision-recall curve</b> rather than the default 0.5, then converted into "
            "concrete prevention rules that a firewall or IAM system can enforce.",
        ],
        features_intro="Features driving the production rules:",
        features=[
            "<b>count > 200 with serror_rate > 0.6</b> - the flood signature used for a "
            "per-source rate limit.",
            "<b>flag_S0 with dst_host_srv_count > 200</b> - unanswered connections concentrated "
            "on one service, used for a 60-second drop rule.",
            "<b>rerror_rate > 0.5 with same_srv_rate < 0.3</b> - failed attempts spread across "
            "services, used to trigger a step-up authentication challenge.",
            "<b>dst_host_count</b> - fan-out across destinations, used to quarantine a scanning "
            "host.",
        ],
        adversarial=[
            "Against a deployed detector the realistic attack is <b>alert fatigue as a weapon</b>: "
            "generate many low-confidence events so analysts triage noise while the real U2R "
            "attempt hides in the queue. The model is not fooled so much as the humans are.",
            "Mitigation: cap the alert budget per host, deduplicate near-identical alerts, and "
            "route the lowest-confidence band to automated containment rather than to a human.",
        ],
        xai=[
            "The alert reads: <i>\"This host escalated privileges on a service it had contacted "
            "only twice before, after 14 failed attempts. We are recommending a temporary "
            "credential reset.\"</i>",
            "That sentence is assembled from the top forest features, so each clause corresponds "
            "to something the analyst can independently verify in the logs.",
        ],
        ethics=[
            "The <b>base-rate problem</b> is the ethical issue that matters most here. This "
            "benchmark is roughly balanced, but a real network runs at around 1% attack traffic. "
            f"At the chosen threshold the false-positive rate is "
            f"{c['fp'] / max(c['fp'] + c['tn'], 1):.1%}; applied to a 1%-attack feed, most alerts "
            "would be false, and acting on them automatically would disrupt legitimate users "
            "at scale.",
            "Mitigation: never automate a punitive action on a single model score; require either "
            "a second independent signal or human confirmation before containment.",
        ],
        results_intro=(
            f"Operating threshold {d['operating_threshold']} selected for precision >= 0.95."),
        table_rows=[["Threshold", "Precision", "Recall", "Alerts / 10k flows"]] + [
            [str(t["threshold"]), str(t["precision"]), str(t["recall"]), str(t["alerts_per_10k"])]
            for t in thr] + [["ROC-AUC", str(d["roc_auc"]), "", ""],
                             ["Detected per family (DoS/Probe/R2L/U2R)",
                              " / ".join(f"{fam[k]:.3f}" for k in sorted(fam)), "", ""]],
        table_widths=[55 * mm, 30 * mm, 30 * mm, 40 * mm],
        results_note=(
            f"Confusion at the operating point: TN={c['tn']}, FP={c['fp']}, "
            f"FN={c['fn']}, TP={c['tp']} over {c['tn'] + c['fp'] + c['fn'] + c['tp']} test flows."),
    )


if __name__ == "__main__":
    out = os.path.join(ROOT, "reports")
    os.makedirs(out, exist_ok=True)
    for i, fn in enumerate([lab1, lab2, lab3, lab4], start=1):
        build(fn(), os.path.join(out, f"lab{i}_report.pdf"))
