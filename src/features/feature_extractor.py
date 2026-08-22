import os

import numpy as np
import pandas as pd

from scipy.stats import entropy

from src.models.train_model import DATASET_PATH


# =========================================================
# STABLE V2 CONFIGURATION
# =========================================================

RESULTS_DIR = "results"

DATASET_FILE = "dataset.csv"

os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)

dataset_path = os.path.join(
    RESULTS_DIR,
    DATASET_FILE
)


# =========================================================
# FEATURE COMPUTATION
# =========================================================

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

    # -----------------------------------------------------
    # BASIC FEATURES
    # -----------------------------------------------------

    duration = (
        max(timestamps) - min(timestamps)
        if len(timestamps) > 1
        else 0
    )

    total_bytes = sum(sizes)

    packet_count = len(packets)

    # -----------------------------------------------------
    # INTERVAL FEATURES
    # -----------------------------------------------------

    if len(timestamps) > 1:

        timestamps_sorted = sorted(
            timestamps
        )

        intervals = np.diff(
            timestamps_sorted
        )

        interval_mean = np.mean(
            intervals
        )

        interval_variance = np.var(
            intervals
        )

        # -------------------------------------------------
        # INTERVAL ENTROPY
        # -------------------------------------------------

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

    # -----------------------------------------------------
    # SIZE FEATURES
    # -----------------------------------------------------

    size_variance = (
        np.var(sizes)
        if len(sizes) > 1
        else 0
    )

    # -----------------------------------------------------
    # DERIVED FEATURES
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # FINAL FEATURE VECTOR
    # -----------------------------------------------------

    return {

        # INTELLIGENCE METADATA

        "source_ip": flow.get(
            "source_ip"
        ),

        "destination_ip": flow.get(
            "destination_ip"
        ),

        "source_port": flow.get(
            "source_port"
        ),

        "destination_port": flow.get(
            "destination_port"
        ),

        "protocol": flow.get(
            "protocol"
        ),

        # BEHAVIORAL FEATURES

        "duration": duration,

        "total_bytes": total_bytes,

        "packet_count": packet_count,

        "interval_mean": interval_mean,

        "interval_variance": (
            interval_variance
        ),

        "interval_entropy": (
            interval_entropy
        ),

        "size_variance": (
            size_variance
        ),

        "bytes_per_packet": (
            bytes_per_packet
        ),

        "packets_per_second": (
            packets_per_second
        ),

        "byte_rate": byte_rate,

        "burst_ratio": burst_ratio
    }


# =========================================================
# SHARED SESSION FEATURE BUILDER
# =========================================================
#
# This contains the session-level feature construction
# already used by Stable V2.
#
# It is kept separate so that V3.1 can use the same
# behavioral representation without modifying the
# Stable V2 extraction path.
# =========================================================

def _build_session_features(
    flows,
    attack_type,
    label
):

    rows = []

    # -----------------------------------------------------
    # SESSION GROUPING
    # -----------------------------------------------------

    session_groups = {}

    for flow in flows:

        session_id = flow.get(
            "session_id"
        )

        if session_id not in session_groups:

            session_groups[
                session_id
            ] = []

        session_groups[
            session_id
        ].append(flow)

    # -----------------------------------------------------
    # PROCESS FLOWS
    # -----------------------------------------------------

    for flow in flows:

        features = compute_features(
            flow
        )

        # -------------------------------------------------
        # SESSION INTELLIGENCE
        # -------------------------------------------------

        session_id = flow.get(
            "session_id"
        )

        session_flows = (
            session_groups[
                session_id
            ]
        )

        # -------------------------------------------------
        # SESSION FLOW COUNT
        # -------------------------------------------------

        session_flow_count = len(
            session_flows
        )

        # -------------------------------------------------
        # SESSION DURATION
        # -------------------------------------------------

        session_start = min(
            f["start_time"]
            for f in session_flows
        )

        session_end = max(
            f["end_time"]
            for f in session_flows
        )

        session_duration = (
            session_end
            - session_start
        )

        # -------------------------------------------------
        # FLOW TIMING ANALYSIS
        # -------------------------------------------------

        flow_start_times = sorted(

            f["start_time"]

            for f in session_flows
        )

        if len(flow_start_times) > 1:

            flow_gaps = np.diff(
                flow_start_times
            )

            average_flow_gap = np.mean(
                flow_gaps
            )

            flow_gap_variance = np.var(
                flow_gaps
            )

        else:

            average_flow_gap = 0

            flow_gap_variance = 0

        # -------------------------------------------------
        # SESSION TOTAL PACKETS
        # -------------------------------------------------

        session_total_packets = sum(

            len(f["packets"])

            for f in session_flows
        )

        # -------------------------------------------------
        # SESSION TOTAL BYTES
        # -------------------------------------------------

        session_total_bytes = sum(

            sum(
                p["length"]
                for p in f["packets"]
            )

            for f in session_flows
        )

        # -------------------------------------------------
        # STORE SESSION FEATURES
        # -------------------------------------------------

        features["session_id"] = (
            session_id
        )

        features[
            "session_flow_count"
        ] = session_flow_count

        features[
            "session_duration"
        ] = session_duration

        features[
            "session_total_packets"
        ] = session_total_packets

        features[
            "session_total_bytes"
        ] = session_total_bytes

        features[
            "average_flow_gap"
        ] = average_flow_gap

        features[
            "flow_gap_variance"
        ] = flow_gap_variance

        # -------------------------------------------------
        # GROUND TRUTH
        # -------------------------------------------------

        features["attack_type"] = (
            attack_type
        )

        features["label"] = label

        rows.append(
            features
        )

    df = pd.DataFrame(
        rows
    )

    # -----------------------------------------------------
    # CLEAN WEAK FLOWS
    # -----------------------------------------------------

    if not df.empty:

        df = df[
            df["packet_count"] > 1
        ]

        df = df[
            df["duration"] > 0
        ]

    return df


# =========================================================
# STABLE V2 FLOW → DATAFRAME
# =========================================================

def extract_features(
    flows,
    attack_type
):

    # -----------------------------------------------------
    # STABLE V2 LABELING RULE
    # -----------------------------------------------------
    #
    # Preserved exactly for the Stable V2 path.
    #
    # 0 = normal
    # 1 = attack
    # -----------------------------------------------------

    label = (
        0
        if "normal"
        in attack_type.lower()
        else 1
    )

    return _build_session_features(
        flows,
        attack_type,
        label
    )


# =========================================================
# V3.1 BENCHMARK FEATURE EXTRACTION
# =========================================================
#
# V3.1 does NOT infer ground truth from the PCAP filename.
#
# Ground truth comes from benchmark_manifest.csv:
#
# traffic_class = benign → label 0
# traffic_class = attack → label 1
#
# This function also DOES NOT write to results/dataset.csv.
#
# The benchmark runner is responsible for deciding where
# benchmark artifacts are stored.
# =========================================================

def extract_features_for_benchmark(
    flows,
    traffic_class,
    attack_type
):

    # -----------------------------------------------------
    # EXPLICIT BENCHMARK GROUND TRUTH
    # -----------------------------------------------------

    if traffic_class == "benign":

        label = 0

    elif traffic_class == "attack":

        label = 1

    else:

        raise ValueError(
            "Unsupported traffic class: "
            f"{traffic_class}. "
            "Expected 'benign' or 'attack'."
        )

    # -----------------------------------------------------
    # REUSE THE SAME FEATURE REPRESENTATION
    # -----------------------------------------------------

    return _build_session_features(
        flows,
        attack_type,
        label
    )


# =========================================================
# STABLE V2 DATASET STORAGE
# =========================================================
#
# IMPORTANT:
#
# This function remains unchanged for Stable V2.
#
# V3.1 must NOT call this function because it appends
# benchmark data into the shared V2 results dataset.
# =========================================================

def save_dataset(df):

    if os.path.exists(
        DATASET_PATH
    ):

        existing_df = pd.read_csv(
            DATASET_PATH
        )

        combined_df = pd.concat(
            [
                existing_df,
                df
            ],
            ignore_index=True
        )

        combined_df.to_csv(
            DATASET_PATH,
            index=False
        )

        print(
            "\n[INFO] Existing dataset found."
        )

        print(
            "[INFO] Appended new rows."
        )

        print(
            f"[INFO] Total rows: "
            f"{len(combined_df)}"
        )

    else:

        df.to_csv(
            DATASET_PATH,
            index=False
        )

        print(
            "\n[INFO] New dataset created."
        )

        print(
            f"[INFO] Rows saved: "
            f"{len(df)}"
        )