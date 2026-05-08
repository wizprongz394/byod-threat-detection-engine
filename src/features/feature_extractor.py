import os
import numpy as np
import pandas as pd

from scipy.stats import entropy


# CONFIGURATION

RESULTS_DIR = "results"

DATASET_FILE = "dataset.csv"

os.makedirs(RESULTS_DIR, exist_ok=True)

dataset_path = os.path.join(
    RESULTS_DIR,
    DATASET_FILE
)


# FEATURE COMPUTATION

def compute_features(flow):

    packets = flow["packets"]

    timestamps = [
        p["timestamp"]
        for p in packets
    ]

    sizes = [
        p["length"]
        for p in packets
    ]

    # BASIC FEATURES

    duration = (
        max(timestamps) - min(timestamps)
        if len(timestamps) > 1
        else 0
    )

    total_bytes = sum(sizes)

    packet_count = len(packets)

    # INTERVAL FEATURES

    if len(timestamps) > 1:

        timestamps_sorted = sorted(timestamps)

        intervals = np.diff(
            timestamps_sorted
        )

        interval_mean = np.mean(intervals)

        interval_variance = np.var(intervals)

        # Entropy
        hist, _ = np.histogram(
            intervals,
            bins=10
        )

        interval_entropy = entropy(
            hist + 1e-6
        )

    else:

        interval_mean = 0
        interval_variance = 0
        interval_entropy = 0

    # SIZE FEATURES

    size_variance = (
        np.var(sizes)
        if len(sizes) > 1
        else 0
    )

    # DERIVED FEATURES

    bytes_per_packet = (
        total_bytes / packet_count
        if packet_count > 0
        else 0
    )

    packets_per_second = (
        packet_count / duration
        if duration > 0
        else 0
    )

    byte_rate = (
        total_bytes / duration
        if duration > 0
        else 0
    )

    burst_ratio = (
        interval_variance / interval_mean
        if interval_mean > 0
        else 0
    )

    # FINAL FEATURE VECTOR

    return {

        "duration": duration,

        "total_bytes": total_bytes,

        "packet_count": packet_count,

        "interval_mean": interval_mean,

        "interval_variance": interval_variance,

        "interval_entropy": interval_entropy,

        "size_variance": size_variance,

        "bytes_per_packet": bytes_per_packet,

        "packets_per_second": packets_per_second,

        "byte_rate": byte_rate,

        "burst_ratio": burst_ratio
    }


# FLOWS TO DATAFRAME

def extract_features(flows, attack_type):

    rows = []

    # Labeling rule:
    # 0 = normal
    # 1 = attack

    label = (
        0
        if "normal" in attack_type.lower()
        else 1
    )

    for flow in flows:

        features = compute_features(flow)

        features["attack_type"] = attack_type

        features["label"] = label

        rows.append(features)

    df = pd.DataFrame(rows)

    # CLEAN WEAK FLOWS

    df = df[
        df["packet_count"] > 1
    ]

    df = df[
        df["duration"] > 0
    ]

    return df


# SAVE DATASET

def save_dataset(df):

    df.to_csv(
        dataset_path,
        index=False
    )

    print(
        f"\n[SUCCESS] Dataset saved to: {dataset_path}"
    )