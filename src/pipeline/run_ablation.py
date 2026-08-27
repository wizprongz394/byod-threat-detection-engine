import os
import pandas as pd

from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows
from src.features.feature_extractor import extract_features

from src.models.train_model_ablation import (
    train_from_training_data,
    evaluate_dataset
)


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

BENCHMARK_DIR = os.path.join(
    BASE_DIR,
    "data",
    "benchmark"
)

MANIFEST_PATH = os.path.join(
    BENCHMARK_DIR,
    "benchmark_manifest.csv"
)

BENCHMARK_RESULTS_DIR = os.path.join(
    BENCHMARK_DIR,
    "results"
)

ABLATION_RESULTS_DIR = os.path.join(
    BENCHMARK_RESULTS_DIR,
    "ablation"
)

os.makedirs(
    ABLATION_RESULTS_DIR,
    exist_ok=True
)


# =========================================================
# V3.1 ML FEATURE SET
#
# This is the complete feature vector used by the
# established V3.1 benchmark baseline.
#
# IMPORTANT:
# Do not add/remove features here during an experiment.
# Individual experiments remove exactly one feature.
# =========================================================

ALL_FEATURES = [
    "source_port",
    "destination_port",
    "duration",
    "total_bytes",
    "packet_count",
    "interval_mean",
    "interval_variance",
    "interval_entropy",
    "size_variance",
    "bytes_per_packet",
    "packets_per_second",
    "byte_rate",
    "burst_ratio",
    "session_flow_count",
    "session_duration",
    "session_total_packets",
    "session_total_bytes",
    "average_flow_gap",
    "flow_gap_variance"
]


# =========================================================
# LOAD BENCHMARK MANIFEST
# =========================================================

def load_manifest():

    if not os.path.exists(
        MANIFEST_PATH
    ):

        raise FileNotFoundError(
            f"[ERROR] Benchmark manifest not found: "
            f"{MANIFEST_PATH}"
        )

    manifest = pd.read_csv(
        MANIFEST_PATH
    )

    required_columns = [
        "pcap_file",
        "traffic_class",
        "attack_type",
        "split"
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in manifest.columns
    ]

    if missing_columns:

        raise ValueError(
            "[ERROR] Benchmark manifest is missing "
            f"columns: {missing_columns}"
        )

    print(
        "\n[INFO] Benchmark manifest loaded."
    )

    print(
        f"[INFO] Total benchmark captures: "
        f"{len(manifest)}"
    )

    return manifest


# =========================================================
# VALIDATE BENCHMARK STRUCTURE
# =========================================================

def validate_manifest(
    manifest
):

    print(
        "\n========== BENCHMARK VALIDATION =========="
    )

    expected_splits = {
        "train",
        "validation",
        "test"
    }

    actual_splits = set(
        manifest["split"].unique()
    )

    missing_splits = (
        expected_splits
        - actual_splits
    )

    if missing_splits:

        raise ValueError(
            "[ERROR] Missing benchmark splits: "
            f"{missing_splits}"
        )

    train_rows = manifest[
        manifest["split"] == "train"
    ]

    validation_rows = manifest[
        manifest["split"] == "validation"
    ]

    test_rows = manifest[
        manifest["split"] == "test"
    ]

    if train_rows.empty:
        raise ValueError(
            "[ERROR] No training capture found."
        )

    if validation_rows.empty:
        raise ValueError(
            "[ERROR] No validation capture found."
        )

    if test_rows.empty:
        raise ValueError(
            "[ERROR] No test captures found."
        )

    if not all(
        train_rows["traffic_class"] == "benign"
    ):
        raise ValueError(
            "[ERROR] Training data must contain "
            "benign traffic only."
        )

    if not all(
        validation_rows["traffic_class"] == "benign"
    ):
        raise ValueError(
            "[ERROR] Validation data must contain "
            "benign traffic."
        )

    if not all(
        test_rows["traffic_class"] == "attack"
    ):
        raise ValueError(
            "[ERROR] Test data must contain "
            "attack traffic."
        )

    if manifest["pcap_file"].duplicated().any():

        duplicates = (
            manifest[
                manifest["pcap_file"].duplicated(
                    keep=False
                )
            ]["pcap_file"]
            .unique()
            .tolist()
        )

        raise ValueError(
            "[ERROR] Duplicate PCAP entries found "
            f"in benchmark manifest: {duplicates}"
        )

    print(
        "[SUCCESS] Benchmark split validation passed."
    )

    print(
        f"[INFO] Training captures: "
        f"{len(train_rows)}"
    )

    print(
        f"[INFO] Validation captures: "
        f"{len(validation_rows)}"
    )

    print(
        f"[INFO] Test captures: "
        f"{len(test_rows)}"
    )


# =========================================================
# RESOLVE PCAP PATH
# =========================================================

def get_pcap_path(
    row
):

    path = os.path.join(
        BENCHMARK_DIR,
        row["split"],
        row["pcap_file"]
    )

    if not os.path.exists(
        path
    ):

        raise FileNotFoundError(
            f"[ERROR] Benchmark PCAP not found: "
            f"{path}"
        )

    return path


# =========================================================
# PROCESS ONE PCAP
# =========================================================

def process_pcap(
    row
):

    pcap_path = get_pcap_path(
        row
    )

    print(
        "\n-----------------------------------------"
    )

    print(
        f"[INFO] Processing: {row['pcap_file']}"
    )

    print(
        f"[INFO] Split: {row['split']}"
    )

    print(
        f"[INFO] Traffic class: "
        f"{row['traffic_class']}"
    )

    print(
        f"[INFO] Attack type: "
        f"{row['attack_type']}"
    )

    packets = read_pcap(
        pcap_path
    )

    print(
        f"[INFO] Packets loaded: {len(packets)}"
    )

    flows = build_flows(
        packets
    )

    print(
        f"[INFO] Flows built: {len(flows)}"
    )

    attack_type = row["attack_type"]

    if row["traffic_class"] == "benign":
        attack_type = "normal"

    df = extract_features(
        flows,
        attack_type
    )

    df["benchmark_split"] = row["split"]
    df["benchmark_file"] = row["pcap_file"]
    df["benchmark_class"] = row["traffic_class"]
    df["benchmark_attack_type"] = row["attack_type"]

    # Ground truth comes from the benchmark manifest.
    df["label"] = (
        0
        if row["traffic_class"] == "benign"
        else 1
    )

    print(
        f"[INFO] Feature rows: {len(df)}"
    )

    return df


# =========================================================
# BUILD DATASET FOR SPLIT
#
# PCAP processing happens ONCE.
#
# The same generated datasets are reused across every
# ablation experiment. This makes experiments faster and
# ensures every feature experiment sees identical data.
# =========================================================

def build_split_dataset(
    manifest,
    split
):

    rows = []

    split_manifest = manifest[
        manifest["split"] == split
    ]

    print(
        f"\n========== BUILDING "
        f"{split.upper()} DATA =========="
    )

    for _, row in split_manifest.iterrows():

        df = process_pcap(
            row
        )

        if not df.empty:
            rows.append(df)

    if not rows:

        raise ValueError(
            f"[ERROR] No feature rows generated "
            f"for split: {split}"
        )

    combined = pd.concat(
        rows,
        ignore_index=True
    )

    print(
        f"\n[SUCCESS] {split.upper()} dataset built."
    )

    print(
        f"[INFO] Total rows: {len(combined)}"
    )

    return combined


# =========================================================
# METRIC CALCULATION
# =========================================================

def calculate_metrics(
    results
):

    labels = results["label"]
    predictions = results["prediction"]

    true_negative = (
        (labels == 0)
        & (predictions == 0)
    ).sum()

    false_positive = (
        (labels == 0)
        & (predictions == 1)
    ).sum()

    true_positive = (
        (labels == 1)
        & (predictions == 1)
    ).sum()

    false_negative = (
        (labels == 1)
        & (predictions == 0)
    ).sum()

    normal_total = (
        labels == 0
    ).sum()

    attack_total = (
        labels == 1
    ).sum()

    precision_denominator = (
        true_positive
        + false_positive
    )

    recall_denominator = (
        true_positive
        + false_negative
    )

    f1_denominator = (
        2 * true_positive
        + false_positive
        + false_negative
    )

    fpr = (
        false_positive / normal_total
        if normal_total
        else 0.0
    )

    recall = (
        true_positive / attack_total
        if attack_total
        else 0.0
    )

    precision = (
        true_positive / precision_denominator
        if precision_denominator
        else 0.0
    )

    f1 = (
        (2 * true_positive) / f1_denominator
        if f1_denominator
        else 0.0
    )

    return {
        "true_negative": int(true_negative),
        "false_positive": int(false_positive),
        "true_positive": int(true_positive),
        "false_negative": int(false_negative),
        "validation_fpr": fpr,
        "test_recall": recall,
        "precision": precision,
        "f1": f1
    }


# =========================================================
# RUN ONE EXPERIMENT
# =========================================================

def run_experiment(
    experiment_name,
    removed_features,
    train_df,
    validation_df,
    test_df
):

    print(
        "\n========================================="
    )

    print(
        f"          {experiment_name}"
    )

    print(
        "========================================="
    )

    print(
        f"[INFO] Removed features: "
        f"{removed_features}"
    )

    print(
        f"[INFO] Remaining feature count: "
        f"{len(ALL_FEATURES) - len(removed_features)}"
    )

    # -----------------------------------------------------
    # TRAIN
    #
    # A fresh model and scaler are fitted for EVERY
    # experiment using TRAIN data only.
    # -----------------------------------------------------

    model, scaler = (
        train_from_training_data(
            train_df,
            removed_features
        )
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    validation_results = (
        evaluate_dataset(
            model,
            scaler,
            validation_df,
            "validation",
            removed_features
        )
    )

    # -----------------------------------------------------
    # TEST
    # -----------------------------------------------------

    test_results = (
        evaluate_dataset(
            model,
            scaler,
            test_df,
            "test",
            removed_features
        )
    )

    # -----------------------------------------------------
    # CALCULATE OVERALL METRICS
    #
    # Validation contains benign traffic, so its FPR is
    # the primary false-positive measurement.
    #
    # Test contains attack traffic, so its recall is the
    # primary attack-detection measurement.
    # -----------------------------------------------------

    validation_metrics = calculate_metrics(
        validation_results
    )

    test_metrics = calculate_metrics(
        test_results
    )

    result = {
        "experiment": experiment_name,
        "removed_features": (
            ",".join(removed_features)
            if removed_features
            else "NONE"
        ),
        "feature_count": (
            len(ALL_FEATURES)
            - len(removed_features)
        ),

        "validation_total": len(
            validation_results
        ),
        "validation_tn": (
            validation_metrics["true_negative"]
        ),
        "validation_fp": (
            validation_metrics["false_positive"]
        ),
        "validation_fpr": (
            validation_metrics["validation_fpr"]
        ),

        "test_total": len(
            test_results
        ),
        "test_tp": (
            test_metrics["true_positive"]
        ),
        "test_fn": (
            test_metrics["false_negative"]
        ),
        "test_recall": (
            test_metrics["test_recall"]
        ),

        "precision": (
            test_metrics["precision"]
        ),
        "f1": (
            test_metrics["f1"]
        )
    }

    print(
        "\n[RESULT]"
    )

    print(
        f"Validation FPR: "
        f"{result['validation_fpr']:.4f}"
    )

    print(
        f"Test Recall: "
        f"{result['test_recall']:.4f}"
    )

    print(
        f"Test Precision: "
        f"{result['precision']:.4f}"
    )

    print(
        f"Test F1: "
        f"{result['f1']:.4f}"
    )

    return (
        result,
        validation_results,
        test_results
    )


# =========================================================
# SAVE INDIVIDUAL EXPERIMENT RESULTS
# =========================================================

def save_experiment_outputs(
    experiment_name,
    validation_results,
    test_results
):

    validation_path = os.path.join(
        ABLATION_RESULTS_DIR,
        f"{experiment_name}_validation.csv"
    )

    test_path = os.path.join(
        ABLATION_RESULTS_DIR,
        f"{experiment_name}_test.csv"
    )

    validation_results.to_csv(
        validation_path,
        index=False
    )

    test_results.to_csv(
        test_path,
        index=False
    )


# =========================================================
# MAIN
# =========================================================

def main():

    print(
        "\n========================================="
    )

    print(
        "      BYOD THREAT DETECTION V3.1"
    )

    print(
        "       AUTOMATED ABLATION STUDY"
    )

    print(
        "========================================="
    )

    print(
        f"[INFO] Total ML features: "
        f"{len(ALL_FEATURES)}"
    )

    # -----------------------------------------------------
    # LOAD + VALIDATE BENCHMARK
    # -----------------------------------------------------

    manifest = load_manifest()

    validate_manifest(
        manifest
    )

    # -----------------------------------------------------
    # BUILD EACH SPLIT ONCE
    # -----------------------------------------------------

    train_df = build_split_dataset(
        manifest,
        "train"
    )

    validation_df = build_split_dataset(
        manifest,
        "validation"
    )

    test_df = build_split_dataset(
        manifest,
        "test"
    )

    # -----------------------------------------------------
    # DEFINE EXPERIMENTS
    #
    # Experiment 0:
    #   Baseline, remove nothing.
    #
    # Experiments 1-19:
    #   Remove exactly one feature.
    # -----------------------------------------------------

    experiments = [
        (
            "baseline",
            []
        )
    ]

    for index, feature in enumerate(
        ALL_FEATURES,
        start=1
    ):

        experiments.append(
            (
                f"ablation_{index:02d}",
                [feature]
            )
        )

    print(
        f"\n[INFO] Experiments scheduled: "
        f"{len(experiments)}"
    )

    # -----------------------------------------------------
    # RUN ALL EXPERIMENTS
    # -----------------------------------------------------

    summary_rows = []

    for experiment_name, removed_features in experiments:

        (
            result,
            validation_results,
            test_results
        ) = run_experiment(
            experiment_name,
            removed_features,
            train_df,
            validation_df,
            test_df
        )

        summary_rows.append(
            result
        )

        save_experiment_outputs(
            experiment_name,
            validation_results,
            test_results
        )

    # -----------------------------------------------------
    # SAVE MASTER ABLATION TABLE
    # -----------------------------------------------------

    summary_df = pd.DataFrame(
        summary_rows
    )

    summary_path = os.path.join(
        ABLATION_RESULTS_DIR,
        "feature_ablation_results.csv"
    )

    summary_df.to_csv(
        summary_path,
        index=False
    )

    # -----------------------------------------------------
    # PRINT RANKED RESULTS
    # -----------------------------------------------------

    print(
        "\n========================================="
    )

    print(
        "       ABLATION STUDY COMPLETE"
    )

    print(
        "========================================="
    )

    print(
        "\n========== RANKED BY VALIDATION FPR =========="
    )

    fpr_view = (
        summary_df[
            [
                "experiment",
                "removed_features",
                "feature_count",
                "validation_fpr",
                "test_recall",
                "precision",
                "f1"
            ]
        ]
        .sort_values(
            "validation_fpr",
            ascending=True
        )
    )

    print(
        fpr_view.to_string(
            index=False
        )
    )

    print(
        "\n[INFO] Master ablation results saved:"
    )

    print(
        f"       {summary_path}"
    )

    print(
        "\n[INFO] Individual experiment outputs saved:"
    )

    print(
        f"       {ABLATION_RESULTS_DIR}"
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()
