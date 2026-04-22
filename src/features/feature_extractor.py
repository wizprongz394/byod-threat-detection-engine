import json
import numpy as np
import pandas as pd


def compute_features(flow):
    packets = flow["packets"]

    timestamps = [p["timestamp"] for p in packets]
    sizes = [p["length"] for p in packets]

    # 🔹 Basic features
    duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
    total_bytes = sum(sizes)
    packet_count = len(packets)

    # 🔹 Time intervals
    if len(timestamps) > 1:
        timestamps_sorted = sorted(timestamps)
        intervals = np.diff(timestamps_sorted)
        interval_mean = np.mean(intervals)
        interval_variance = np.var(intervals)
    else:
        interval_mean = 0
        interval_variance = 0

    return {
        "duration": duration,
        "total_bytes": total_bytes,
        "packet_count": packet_count,
        "interval_mean": interval_mean,
        "interval_variance": interval_variance
    }


def extract_features(json_file):
    with open(json_file, "r") as f:
        data = json.load(f)

    rows = []

    for scenario in data:
        attack_type = scenario["attack_type"]

        # 🔹 Labeling rule
        label = 0 if "random" in attack_type else 1

        for flow in scenario["flows"]:
            features = compute_features(flow)

            features["label"] = label
            features["attack_type"] = attack_type

            rows.append(features)

    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = extract_features("../../flow_output.json")
    df = df[df["packet_count"] > 1]
    df["label"].value_counts()

    df.to_csv("dataset.csv", index=False)

    print("[SUCCESS] Dataset created: dataset.csv")
    print(df.head())