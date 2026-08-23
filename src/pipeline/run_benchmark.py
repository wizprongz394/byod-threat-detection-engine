import os
import pandas as pd

from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows
from src.features.feature_extractor import extract_features

from src.models.train_model import (
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
            "[ERROR] Benchmark manifest "
            "is missing columns: "
            f"{missing_columns}"
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

def validate_manifest(manifest):

    print(
        "\n========== BENCHMARK VALIDATION =========="
    )

    expected_splits = {
        "train",
        "validation",
        "test"
    }

    actual_splits = set(
        manifest["split"]
        .unique()
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

    # -----------------------------------------------------
    # TRAIN MUST BE BENIGN
    # -----------------------------------------------------

    if not all(
        train_rows["traffic_class"]
        == "benign"
    ):

        raise ValueError(
            "[ERROR] Training data must "
            "contain benign traffic only."
        )

    # -----------------------------------------------------
    # VALIDATION MUST BE BENIGN
    # -----------------------------------------------------

    if not all(
        validation_rows["traffic_class"]
        == "benign"
    ):

        raise ValueError(
            "[ERROR] Validation data must "
            "contain benign traffic."
        )

    # -----------------------------------------------------
    # TEST MUST BE ATTACK
    # -----------------------------------------------------

    if not all(
        test_rows["traffic_class"]
        == "attack"
    ):

        raise ValueError(
            "[ERROR] Test data must "
            "contain attack traffic."
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

def get_pcap_path(row):

    split = row["split"]

    pcap_file = row["pcap_file"]

    path = os.path.join(
        BENCHMARK_DIR,
        split,
        pcap_file
    )

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"[ERROR] Benchmark PCAP not found: "
            f"{path}"
        )

    return path


# =========================================================
# PROCESS ONE PCAP
# =========================================================

def process_pcap(row):

    pcap_path = get_pcap_path(
        row
    )

    print(
        "\n-----------------------------------------"
    )

    print(
        f"[INFO] Processing: "
        f"{row['pcap_file']}"
    )

    print(
        f"[INFO] Split: "
        f"{row['split']}"
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
        f"[INFO] Packets loaded: "
        f"{len(packets)}"
    )

    flows = build_flows(
        packets
    )

    print(
        f"[INFO] Flows built: "
        f"{len(flows)}"
    )

    # -----------------------------------------------------
    # BENCHMARK GROUND TRUTH
    # -----------------------------------------------------

    attack_type = row["attack_type"]

    if row["traffic_class"] == "benign":

        attack_type = "normal"

    df = extract_features(
        flows,
        attack_type
    )

    # -----------------------------------------------------
    # EXPLICIT BENCHMARK LABEL
    # -----------------------------------------------------

    df["benchmark_split"] = (
        row["split"]
    )

    df["benchmark_file"] = (
        row["pcap_file"]
    )

    df["benchmark_class"] = (
        row["traffic_class"]
    )

    df["benchmark_attack_type"] = (
        row["attack_type"]
    )

    # Use manifest ground truth.
    df["label"] = (
        0
        if row["traffic_class"] == "benign"
        else 1
    )

    print(
        f"[INFO] Feature rows: "
        f"{len(df)}"
    )

    return df


# =========================================================
# BUILD DATASET FOR SPLIT
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
        f"[INFO] Total rows: "
        f"{len(combined)}"
    )

    return combined


# =========================================================
# MAIN BENCHMARK PIPELINE
# =========================================================

def main():

    print(
        "\n========================================="
    )

    print(
        "      BYOD THREAT DETECTION V3.1"
    )

    print(
        "        BENCHMARK PIPELINE"
    )

    print(
        "========================================="
    )

    # -----------------------------------------------------
    # LOAD + VALIDATE MANIFEST
    # -----------------------------------------------------

    manifest = load_manifest()

    validate_manifest(
        manifest
    )

    # -----------------------------------------------------
    # BUILD TRAINING DATA
    # -----------------------------------------------------

    train_df = build_split_dataset(
        manifest,
        "train"
    )

    # -----------------------------------------------------
    # TRAIN MODEL
    # -----------------------------------------------------

    model, scaler = (
        train_from_training_data(
            train_df
        )
    )

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    validation_df = build_split_dataset(
        manifest,
        "validation"
    )

    validation_results = (
        evaluate_dataset(
            model,
            scaler,
            validation_df,
            "validation"
        )
    )

    # -----------------------------------------------------
    # FINAL TEST
    # -----------------------------------------------------

    test_df = build_split_dataset(
        manifest,
        "test"
    )

    test_results = (
        evaluate_dataset(
            model,
            scaler,
            test_df,
            "test"
        )
    )

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    print(
        "\n========================================="
    )

    print(
        "          V3.1 BENCHMARK COMPLETE"
    )

    print(
        "========================================="
    )

    print(
        f"[INFO] Training rows: "
        f"{len(train_df)}"
    )

    print(
        f"[INFO] Validation rows: "
        f"{len(validation_results)}"
    )

    print(
        f"[INFO] Test rows: "
        f"{len(test_results)}"
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()