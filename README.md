# AI in Cyber Security — Lab Portfolio (ENSP305)

Course: **ENSP305 — AI in Cyber Security** · B.Tech CSE, Semester V
Student: **Aastha Srivastava** · **2301350027**

Four lab exercises covering the AI/ML side of network intrusion detection, from a
linear baseline through to a deployable detector with prevention rules. Each lab
carries the same 120-mark capstone: identify the attack, propose a detection
strategy, justify the features, discuss adversarial compromise, show how the
alert is explained to a non-technical stakeholder, and name the ethical concern.

## Labs

| # | Topic | Attack modelled | Model | Accuracy | F1 |
|---|-------|-----------------|-------|----------|----|
| 1 | Introduction to AI and Cyber Security | DoS / SYN flood | Logistic regression | 0.9828 | 0.9832 |
| 2 | Machine Learning Techniques | Probe / port scan | Random forest vs RBF SVM | 0.9850 / 0.9572 | 0.9854 / 0.9593 |
| 3 | Deep Learning Techniques | R2L / credential stuffing | MLP 64-32 | 0.9839 | 0.9843 |
| 4 | Threat Detection and Prevention | U2R + SOC deployment | Random forest + threshold tuning | ROC-AUC 0.9858 | — |

Reports: `reports/lab1_report.pdf` … `reports/lab4_report.pdf`

## Layout

```
data/generate_dataset.py     synthetic flow corpus (seeded, reproducible)
data/network_flows.csv       generated corpus, 6000 rows
labs/common.py               shared loading, encoding, split
labs/lab1_intro.py           linear baseline
labs/lab2_ml.py              RF vs SVM, permutation importance, evasion curve
labs/lab3_dl.py              MLP, per-family recall
labs/lab4_detection.py       threshold selection, alert budget, prevention rules
results/*.json               measured metrics from the last run
reports/build_reports.py     renders the four PDFs from results/
```

## Running

```bash
pip install -r requirements.txt
python data/generate_dataset.py
python labs/lab1_intro.py
python labs/lab2_ml.py
python labs/lab3_dl.py
python labs/lab4_detection.py
python reports/build_reports.py
```

All randomness is seeded (`random.Random(1337)`, `random_state=1337`), so every
number in the reports reproduces exactly.

## About the dataset

`data/generate_dataset.py` builds the corpus rather than shipping a captured
pcap. The flow features and class profiles are modelled on the KDD'99 / NSL-KDD
family of benchmarks (duration, byte counts, windowed connection counts, SYN and
reset error rates, service dispersion), but the rows are generated.

Two deliberate properties:

- **Feature jitter** — numeric columns are multiplied by a Gaussian factor and
  rate columns get additive noise, so classes overlap the way real flow exports
  do. Without it every model scored 1.000 and permutation importance collapsed
  to a single feature.
- **3% label noise** — a small fraction of rows carry the wrong family, standing
  in for imperfect analyst triage. This is what keeps the scores at 0.95–0.99
  rather than perfect, and it is the honest reason the numbers are not 1.0.

Nothing here is presented as measured traffic from a real network. The models,
metrics and importances are computed from this corpus by the scripts in `labs/`.

## Findings worth carrying forward

- `flag_SF` / `flag_S0` and `same_srv_rate` dominate every model. That is a
  property of flow-level features, and it is also the known weakness of this
  benchmark family: the corpus is easier than production traffic.
- Linear and tree models land within 0.3 points of each other here. The extra
  capacity of the MLP does not buy accuracy on this feature set — it buys a
  differentiable surface, which is precisely what an attacker can exploit.
- The forest resists linear centroid perturbation well: blending attack flows
  50% toward the normal centroid raised evasion only from 2.5% to 10.6%.
- The most useful number in Lab 4 is not accuracy but the false-positive rate at
  the operating threshold. At a realistic 1% attack base rate, most alerts would
  be false — which is why no prevention rule here fires without a second signal
  or human confirmation.
