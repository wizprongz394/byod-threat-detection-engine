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

    # 🔥 Derived features (V1 improvements)

    bytes_per_packet = total_bytes / packet_count if packet_count > 0 else 0

    packets_per_second = (
        packet_count / duration if duration > 0 else 0
    )

    byte_rate = (
        total_bytes / duration if duration > 0 else 0
    )

    # 🔥 FINAL FEATURE
    burst_ratio = (
        interval_variance / interval_mean if interval_mean > 0 else 0
    )

    return {
        "duration": duration,
        "total_bytes": total_bytes,
        "packet_count": packet_count,
        "interval_mean": interval_mean,
        "interval_variance": interval_variance,
        "bytes_per_packet": bytes_per_packet,
        "packets_per_second": packets_per_second,
        "byte_rate": byte_rate,
        "burst_ratio": burst_ratio
    }
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

    # 🔥 NEW FEATURES

    bytes_per_packet = total_bytes / packet_count if packet_count > 0 else 0

    packets_per_second = (
        packet_count / duration if duration > 0 else 0
    )

    byte_rate = (
        total_bytes / duration if duration > 0 else 0
    )

    return {
        "duration": duration,
        "total_bytes": total_bytes,
        "packet_count": packet_count,
        "interval_mean": interval_mean,
        "interval_variance": interval_variance,
        "bytes_per_packet": bytes_per_packet,
        "packets_per_second": packets_per_second,
        "byte_rate": byte_rate
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

    # 🔹 Remove weak flows
    df = df[df["packet_count"] > 1]

    # 🔹 Optional: remove zero-duration noise
    df = df[df["duration"] > 0]

    print(df["label"].value_counts())

    df.to_csv("dataset.csv", index=False)

    print("[SUCCESS] Dataset created: dataset.csv")
    print(df.head())    
    df = extract_features("../../flow_output.json")
    df = df[df["packet_count"] > 1]
    df["label"].value_counts()

    df.to_csv("dataset.csv", index=False)

    print("[SUCCESS] Dataset created: dataset.csv")
    print(df.head())