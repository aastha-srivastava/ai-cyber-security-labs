"""Generate a synthetic network-flow dataset for the AI in Cyber Security labs.

The dataset models a labelled flow-capture with the five classic attack families
(Normal, DoS, Probe, R2L, U2R). It is generated with a fixed seed so every lab
run is reproducible. See README.md for why this is synthetic rather than a
captured pcap.
"""

import csv
import os
import random

FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "protocol_type",
    "flag",
]

# class -> (weight, parameter ranges)
# Numbers are drawn from ranges loosely modelled on KDD'99 / NSL-KDD statistics
# so the classes are separable but not trivially so.
PROFILES = {
    "normal": dict(
        weight=0.50, duration=(0, 300), src=(40, 2000), dst=(200, 9000),
        count=(1, 120), srv=(1, 110), serr=(0.0, 0.05), rerr=(0.0, 0.05),
        same=(0.70, 1.0), diff=(0.0, 0.25), dhc=(1, 200), dhs=(1, 180),
    ),
    "dos": dict(
        weight=0.22, duration=(0, 2), src=(0, 120), dst=(0, 60),
        count=(200, 511), srv=(180, 511), serr=(0.55, 1.0), rerr=(0.0, 0.05),
        same=(0.90, 1.0), diff=(0.0, 0.08), dhc=(200, 255), dhs=(200, 255),
    ),
    "probe": dict(
        weight=0.13, duration=(0, 20), src=(0, 300), dst=(0, 200),
        count=(1, 380), srv=(1, 60), serr=(0.10, 0.60), rerr=(0.10, 0.70),
        same=(0.05, 0.45), diff=(0.40, 0.95), dhc=(1, 255), dhs=(1, 60),
    ),
    "r2l": dict(
        weight=0.10, duration=(1, 600), src=(100, 12000), dst=(0, 400),
        count=(1, 40), srv=(1, 40), serr=(0.0, 0.15), rerr=(0.30, 0.90),
        same=(0.20, 0.70), diff=(0.10, 0.60), dhc=(1, 90), dhs=(1, 90),
    ),
    "u2r": dict(
        weight=0.05, duration=(2, 900), src=(50, 6000), dst=(0, 900),
        count=(1, 12), srv=(1, 12), serr=(0.0, 0.10), rerr=(0.0, 0.20),
        same=(0.10, 0.55), diff=(0.20, 0.80), dhc=(1, 40), dhs=(1, 40),
    ),
}

LABEL_NAMES = {"normal": 0, "dos": 1, "probe": 2, "r2l": 3, "u2r": 4}


def sample(cls, rng):
    p = PROFILES[cls]
    lo, hi = p["serr"]
    serr = rng.uniform(lo, hi)
    lo, hi = p["rerr"]
    rerr = rng.uniform(lo, hi)

    if cls == "normal":
        flag = "SF"
        proto = "tcp"
    elif cls == "dos":
        flag = rng.choice(["S0", "S0", "S0", "REJ"])
        proto = rng.choice(["tcp", "tcp", "icmp", "udp"])
    elif cls == "probe":
        flag = rng.choice(["REJ", "S0", "RSTO"])
        proto = rng.choice(["tcp", "icmp", "udp"])
    elif cls == "r2l":
        flag = rng.choice(["SF", "RSTO", "REJ"])
        proto = rng.choice(["tcp", "tcp", "udp"])
    else:
        flag = rng.choice(["SF", "RSTO"])
        proto = "tcp"

    def u(key):
        a, b = p[key]
        return rng.uniform(a, b)

    row = {
        "duration": round(u("duration"), 3),
        "src_bytes": round(u("src"), 1),
        "dst_bytes": round(u("dst"), 1),
        "count": round(u("count"), 1),
        "srv_count": round(u("srv"), 1),
        "serror_rate": round(serr, 4),
        "rerror_rate": round(rerr, 4),
        "same_srv_rate": round(u("same"), 4),
        "diff_srv_rate": round(u("diff"), 4),
        "dst_host_count": round(u("dhc"), 1),
        "dst_host_srv_count": round(u("dhs"), 1),
        "protocol_type": proto,
        "flag": flag,
        "label": LABEL_NAMES[cls],
        "attack_family": cls,
    }
    return row


def main(rows=6000, seed=1337, out="data/network_flows.csv",
         label_noise=0.03, jitter=0.25):
    rng = random.Random(seed)
    classes = list(PROFILES)
    weights = [PROFILES[c]["weight"] for c in classes]

    numeric = ["duration", "src_bytes", "dst_bytes", "count", "srv_count",
               "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate",
               "dst_host_count", "dst_host_srv_count"]

    os.makedirs(os.path.dirname(out), exist_ok=True)
    data = []
    for _ in range(rows):
        cls = rng.choices(classes, weights=weights, k=1)[0]
        row = sample(cls, rng)

        # sensor/measurement jitter: real flow exporters are not exact
        for f in numeric:
            if f.endswith("rate") or f.endswith("_rate"):
                row[f] = round(min(1.0, max(0.0, row[f] + rng.gauss(0, 0.08))), 4)
            else:
                row[f] = round(max(0.0, row[f] * (1 + rng.gauss(0, jitter))), 3)

        # labelling noise: analyst triage is imperfect, so some flows are
        # recorded under the wrong family
        if rng.random() < label_noise:
            wrong = rng.choice([c for c in classes if c != cls])
            row["attack_family"] = wrong
            row["label"] = LABEL_NAMES[wrong]

        data.append(row)

    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FEATURES + ["label", "attack_family"])
        w.writeheader()
        w.writerows(data)

    print(f"wrote {len(data)} rows to {out}")
    counts = {}
    for r in data:
        counts[r["attack_family"]] = counts.get(r["attack_family"], 0) + 1
    for k, v in sorted(counts.items()):
        print(f"  {k:7s} {v}")


if __name__ == "__main__":
    main()
