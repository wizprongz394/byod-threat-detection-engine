import os

from src.ingestion.pcap_reader import read_pcap
from src.processing.flow_builder import build_flows

from src.features.feature_extractor import (
    extract_features,
    save_dataset
)

from src.models.train_model import (
    prepare_data,
    scale_data,
    train_model,
    predict,
    add_risk_scores,
    add_risk_levels,
    evaluate,
    save_results
)
from src.models.report_generator import (
    build_report,
    save_report,
    display_summary
)


# FILE INPUT

def get_file_path():

    file_path = input(
        "Enter PCAP file path: "
    ).strip()

    if not file_path:
        raise ValueError(
            "[ERROR] PCAP path cannot be empty"
        )

    if not os.path.exists(file_path):
        raise FileNotFoundError(
            f"[ERROR] File not found: {file_path}"
        )

    return file_path


# MAIN PIPELINE

if __name__ == "__main__":

    print("\n========== BYOD THREAT PIPELINE ==========")

    # INPUT

    file_path = get_file_path()

    attack_type = os.path.splitext(
        os.path.basename(file_path)
    )[0]

    print(f"\n[INFO] Attack Type: {attack_type}")

    # INGESTION

    print("\n[INFO] Reading packets...")

    packets = read_pcap(file_path)

    print(f"[INFO] Packets loaded: {len(packets)}")

    # FLOW BUILDING

    print("\n[INFO] Building flows...")

    flows = build_flows(packets)

    print(f"[INFO] Flows built: {len(flows)}")

    # FEATURE EXTRACTION

    print("\n[INFO] Extracting features...")

    df = extract_features(
        flows,
        attack_type
    )

    save_dataset(df)

    print(f"[INFO] Feature rows: {len(df)}")

    # ML PREPARATION


    print("\n[INFO] Preparing ML data...")

    X, X_train = prepare_data(df)

    # SCALING

    print("\n[INFO] Scaling features...")

    X_scaled, X_train_scaled, scaler = scale_data(
        X,
        X_train
    )

    #  MODEL TRAINING

    print("\n[INFO] Training Isolation Forest...")

    model = train_model(
        X_train_scaled
    )

    # PREDICTIONS

    print("\n[INFO] Running predictions...")

    df = predict(
        model,
        X_scaled,
        df
    )

    # RISK SCORING

    print("\n[INFO] Calculating risk scores...")

    df = add_risk_scores(
        model,
        X_scaled,
        df
    )

    df = add_risk_levels(df)

    # EVALUATION

    print("\n[INFO] Evaluating model...")

    evaluate(df)

    # SAVE RESULTS

    print("\n[INFO] Saving results...")

    save_results(df)
    print("\n[INFO] Generating threat report...")

    report = build_report(df)

    save_report(report)

    display_summary(report)
    
    print("\n Pipeline completed successfully!")