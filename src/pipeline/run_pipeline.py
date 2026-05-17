import os

from src.ingestion.pcap_reader import read_pcap

from src.processing.flow_builder import (
    build_flows
)

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

            f"[ERROR] File not found: "
            f"{file_path}"
        )

    return file_path


# CONTEXT VALIDATION

def validate_context_propagation(df):

    print(
        "\n========== CONTEXT VALIDATION =========="
    )

    required_columns = [

        "source_ip",
        "destination_ip",

        "source_port",
        "destination_port",

        "protocol"
    ]

    missing_columns = []

    for column in required_columns:

        if column not in df.columns:

            missing_columns.append(
                column
            )

    # VALIDATION RESULT

    if missing_columns:

        print(
            "\n[WARNING] Missing context columns:"
        )

        for column in missing_columns:

            print(f" - {column}")

    else:

        print(
            "\n[SUCCESS] Context propagation verified."
        )

        print(
            "[INFO] Metadata preserved through:"
        )

        print("  PCAP → Packets")
        print("  Packets → Flows")
        print("  Flows → Features")
        print("  Features → Results")
        print("  Results → Threat Reports")

    # SAMPLE CONTEXT

    if len(df) > 0:

        sample = df.iloc[0]

        print(
            "\n========== SAMPLE CONTEXT =========="
        )

        print(
            f"Source IP: "
            f"{sample.get('source_ip')}"
        )

        print(
            f"Destination IP: "
            f"{sample.get('destination_ip')}"
        )

        print(
            f"Source Port: "
            f"{sample.get('source_port')}"
        )

        print(
            f"Destination Port: "
            f"{sample.get('destination_port')}"
        )

        print(
            f"Protocol: "
            f"{sample.get('protocol')}"
        )


#  MAIN PIPELINE

def main():

    print(
        "\n========== BYOD THREAT PIPELINE =========="
    )

    # INPUT

    file_path = get_file_path()

    attack_type = os.path.splitext(
        os.path.basename(file_path)
    )[0]

    print(
        f"\n[INFO] Attack Type: "
        f"{attack_type}"
    )

    # PACKET INGESTION

    print(
        "\n[INFO] Reading packets..."
    )

    packets = read_pcap(
        file_path
    )

    print(
        f"[INFO] Packets loaded: "
        f"{len(packets)}"
    )

    # FLOW CONSTRUCTION

    print(
        "\n[INFO] Building flows..."
    )

    flows = build_flows(
        packets
    )

    print(
        f"[INFO] Flows built: "
        f"{len(flows)}"
    )

    # FEATURE EXTRACTION

    print(
        "\n[INFO] Extracting features..."
    )

    df = extract_features(
        flows,
        attack_type
    )

    print(
        f"[INFO] Feature rows: "
        f"{len(df)}"
    )

    # CONTEXT VALIDATION

    validate_context_propagation(
        df
    )

    # SAVE DATASET

    print(
        "\n[INFO] Saving dataset..."
    )

    save_dataset(df)

    # ML PREPARATION

    print(
        "\n[INFO] Preparing ML data..."
    )

    X, X_train = prepare_data(
        df
    )

    # FEATURE SCALING

    print(
        "\n[INFO] Scaling features..."
    )

    (
        X_scaled,
        X_train_scaled,
        scaler

    ) = scale_data(
        X,
        X_train
    )

    # MODEL TRAINING

    print(
        "\n[INFO] Training Isolation Forest..."
    )

    model = train_model(
        X_train_scaled
    )

    # PREDICTIONS

    print(
        "\n[INFO] Running predictions..."
    )

    df = predict(
        model,
        X_scaled,
        df
    )

    # RISK ENGINE

    print(
        "\n[INFO] Calculating risk scores..."
    )

    df = add_risk_scores(
        model,
        X_scaled,
        df
    )

    df = add_risk_levels(
        df
    )

    # MODEL EVALUATION

    print(
        "\n[INFO] Evaluating model..."
    )

    evaluate(df)

    # SAVE RESULTS

    print(
        "\n[INFO] Saving results..."
    )

    save_results(
        df
    )

    # THREAT REPORT GENERATION

    print(
        "\n[INFO] Generating threat report..."
    )

    report = build_report(
        df
    )

    save_report(
        report
    )

    display_summary(
        report
    )

    # PIPELINE COMPLETE

    print(
        "\n[SUCCESS] Pipeline completed successfully!"
    )


# ENTRY POINT

if __name__ == "__main__":
    main()