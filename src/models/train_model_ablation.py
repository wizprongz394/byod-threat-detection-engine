import os

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


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

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

DATASET_PATH = os.path.join(
    RESULTS_DIR,
    "dataset.csv"
)

RESULTS_PATH = os.path.join(
    RESULTS_DIR,
    "results.csv"
)

os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)


# =========================================================
# LOAD DATASET
# =========================================================

def load_data():

    if not os.path.exists(DATASET_PATH):

        raise FileNotFoundError(
            f"[ERROR] Dataset not found: "
            f"{DATASET_PATH}"
        )

    df = pd.read_csv(
        DATASET_PATH
    )

    print(
        f"\n[INFO] Dataset loaded: "
        f"{len(df)} rows"
    )

    return df


# =========================================================
# PREPARE FEATURE MATRIX - ABLATION VERSION
# =========================================================

# =========================================================
# PREPARE FEATURE MATRIX
# =========================================================
def prepare_data(df, ablation_features=None):

    # -----------------------------------------------------
    # NON-ML METADATA
    #
    # These columns must NEVER reach the scaler or model.
    # -----------------------------------------------------

    metadata_columns = [

        # Original metadata
        "label",
        "attack_type",
        "session_id",
        "source_ip",
        "destination_ip",
        "protocol",

        # Legacy benchmark metadata
        "split",
        "traffic_class",
        "description",
        "pcap_file",

        # V3.1 benchmark metadata
        "benchmark_split",
        "benchmark_file",
        "benchmark_class",
        "benchmark_attack_type"
    ]

    # Keep only metadata columns that actually exist.
    metadata_columns = [
        col
        for col in metadata_columns
        if col in df.columns
    ]

    # -----------------------------------------------------
    # BUILD FEATURE MATRIX
    # -----------------------------------------------------

    X = df.drop(
        columns=metadata_columns
    )

    # -----------------------------------------------------
    # ABLATION CONFIGURATION
    #
    # If no features are supplied, this is the baseline
    # experiment and no ML features are removed.
    # -----------------------------------------------------

    if ablation_features is None:

        ablation_features = []

    features_to_remove = [
        col
        for col in ablation_features
        if col in X.columns
    ]

    # -----------------------------------------------------
    # REMOVE SELECTED FEATURES
    # -----------------------------------------------------

    X = X.drop(
        columns=features_to_remove
    )

    print(
        "\n[ABLATION] Removed ML features:"
    )

    print(
        features_to_remove
    )

    # -----------------------------------------------------
    # HANDLE MISSING VALUES
    # -----------------------------------------------------

    X = X.fillna(0)

    # -----------------------------------------------------
    # SAFETY CHECK
    #
    # sklearn must receive numeric values only.
    # -----------------------------------------------------

    non_numeric_columns = (
        X.select_dtypes(
            exclude=["number"]
        )
        .columns
        .tolist()
    )

    if non_numeric_columns:

        raise ValueError(
            "[ERROR] Non-numeric columns remain "
            "in the ML feature matrix: "
            f"{non_numeric_columns}"
        )

    print(
        f"[ABLATION] Remaining ML features: "
        f"{len(X.columns)}"
    )

    print(
        "[ABLATION] Feature columns:"
    )

    print(
        list(X.columns)
    )

    return X


# =========================================================
# PREPARE TRAINING DATA
# =========================================================

def prepare_training_data(
    df,
    ablation_features=None
):

    if "label" not in df.columns:

        raise ValueError(
            "[ERROR] Training data must contain "
            "a 'label' column."
        )

    # -----------------------------------------------------
    # TRAINING MUST USE BENIGN TRAFFIC ONLY
    # -----------------------------------------------------

    normal_df = df[
        df["label"] == 0
    ].copy()

    if normal_df.empty:

        raise ValueError(
            "[ERROR] Training data contains "
            "no benign traffic."
        )

    X_train = prepare_data(
        normal_df,
        ablation_features
    )

    print(
        "\n[INFO] Training data prepared."
    )

    print(
        f"[INFO] Benign training rows: "
        f"{len(X_train)}"
    )

    print(
        f"[INFO] Training features: "
        f"{len(X_train.columns)}"
    )

    return X_train


# =========================================================
# FIT SCALER ON TRAINING DATA ONLY
# =========================================================

def fit_scaler(X_train):

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    print(
        "\n[INFO] StandardScaler fitted "
        "using TRAINING data only."
    )

    return (
        scaler,
        X_train_scaled
    )


# =========================================================
# TRANSFORM DATA USING EXISTING SCALER
# =========================================================

def transform_data(
    scaler,
    X
):

    X = X.fillna(0)

    X_scaled = scaler.transform(
        X
    )

    print(
        "[INFO] Dataset transformed "
        "using frozen training scaler."
    )

    return X_scaled


# =========================================================
# TRAIN MODEL
# =========================================================

def train_model(
    X_train_scaled
):

    model = IsolationForest(

        contamination=0.20,

        random_state=42
    )

    model.fit(
        X_train_scaled
    )

    print(
        "\n[INFO] Isolation Forest "
        "fitted using TRAINING data only."
    )

    return model


# =========================================================
# GENERATE PREDICTIONS
# =========================================================

def predict(
    model,
    X_scaled,
    df
):

    predictions = model.predict(
        X_scaled
    )

    # Isolation Forest:
    #
    #  1  = normal
    # -1  = anomaly
    #
    # Project representation:
    #
    #  0  = normal
    #  1  = anomaly

    mapped_predictions = [

        0 if prediction == 1 else 1

        for prediction in predictions
    ]

    df = df.copy()

    df["prediction"] = (
        mapped_predictions
    )

    missing_predictions = (

        df["prediction"]
        .isna()
        .sum()
    )

    if missing_predictions > 0:

        print(
            "\n[WARNING] Missing predictions:"
            f" {missing_predictions}"
        )

    else:

        print(
            "\n[INFO] Prediction generation successful."
        )

    return df


# =========================================================
# ADD RISK SCORES
# =========================================================

def add_risk_scores(
    model,
    X_scaled,
    df
):

    # Isolation Forest decision_function:
    #
    # Higher = more normal
    # Lower  = more anomalous
    #
    # Invert so that higher values represent
    # greater anomaly/risk.

    scores = model.decision_function(
        X_scaled
    )

    scores_inverted = -scores

    min_score = np.min(
        scores_inverted
    )

    max_score = np.max(
        scores_inverted
    )

    score_range = (
        max_score - min_score
    )

    # Prevent division by zero if every score
    # happens to be identical.

    if score_range == 0:

        risk_scores = np.zeros(
            len(scores_inverted)
        )

    else:

        risk_scores = (

            (
                scores_inverted
                - min_score
            )
            /
            score_range
        )

    df = df.copy()

    df["risk_score"] = (
        risk_scores
    )

    print(
        "\n[INFO] Risk scoring complete."
    )

    return df


# =========================================================
# RISK CLASSIFICATION
# =========================================================

def classify_risk(score):

    if score < 0.30:

        return "LOW"

    elif score < 0.70:

        return "MEDIUM"

    else:

        return "HIGH"


# =========================================================
# SESSION ESCALATION
# =========================================================

def apply_session_escalation(df):

    if "session_id" not in df.columns:

        return df

    df = df.copy()

    if "risk_reason" not in df.columns:

        df["risk_reason"] = ""

    session_groups = df.groupby(
        "session_id"
    )

    for session_id, group in session_groups:

        avg_risk = group[
            "risk_score"
        ].mean()

        flow_count = len(
            group
        )

        if (

            flow_count >= 3

            and

            avg_risk >= 0.6
        ):

            df.loc[

                df["session_id"]
                == session_id,

                "risk_level"

            ] = "HIGH"

            df.loc[

                df["session_id"]
                == session_id,

                "risk_reason"

            ] += (

                " | Repeated suspicious "
                "session behavior detected"
            )

    return df


# =========================================================
# EXPLAINABILITY ENGINE
# =========================================================

def explain_risk(row):

    reasons = []

    # -----------------------------------------------------
    # BASIC BEHAVIORAL ANOMALIES
    # -----------------------------------------------------

    if row.get(
        "interval_entropy",
        0
    ) > 1.5:

        reasons.append(
            "Highly irregular timing behavior detected"
        )

    if row.get(
        "burst_ratio",
        0
    ) > 5:

        reasons.append(
            "Burst communication behavior observed"
        )

    if row.get(
        "packets_per_second",
        0
    ) > 50:

        reasons.append(
            "Elevated packet transmission rate detected"
        )

    if row.get(
        "size_variance",
        0
    ) > 10000:

        reasons.append(
            "Abnormal packet size variation detected"
        )

    if row.get(
        "byte_rate",
        0
    ) > 100000:

        reasons.append(
            "Unusually high data transfer behavior detected"
        )

    # -----------------------------------------------------
    # SESSION INTELLIGENCE
    # -----------------------------------------------------

    if row.get(
        "session_flow_count",
        0
    ) >= 5:

        reasons.append(
            "Persistent multi-flow communication session observed"
        )

    if row.get(
        "session_duration",
        0
    ) > 300:

        reasons.append(
            "Long-duration communication persistence detected"
        )

    if row.get(
        "session_total_bytes",
        0
    ) > 50000:

        reasons.append(
            "Sustained high-volume session transfer observed"
        )

    # -----------------------------------------------------
    # TEMPORAL BEHAVIORAL INTELLIGENCE
    # -----------------------------------------------------

    if (

        row.get(
            "session_flow_count",
            0
        ) >= 3

        and

        row.get(
            "flow_gap_variance",
            999
        ) < 5

        and

        row.get(
            "interval_entropy",
            0
        ) > 0.5
    ):

        reasons.append(
            "Persistent periodic communication behavior observed"
        )

        reasons.append(
            "Possible beaconing activity detected"
        )

    if (

        row.get(
            "burst_ratio",
            0
        ) > 5

        and

        row.get(
            "flow_gap_variance",
            0
        ) > 10
    ):

        reasons.append(
            "Irregular burst communication pattern observed"
        )

    # -----------------------------------------------------
    # EXFILTRATION-LIKE BEHAVIOR
    # -----------------------------------------------------

    if (

        row.get(
            "byte_rate",
            0
        ) > 100000

        and

        row.get(
            "session_total_bytes",
            0
        ) > 50000

        and

        row.get(
            "packets_per_second",
            0
        ) > 50
    ):

        reasons.append(
            "Sustained elevated transfer behavior detected"
        )

        reasons.append(
            "Potential data exfiltration pattern observed"
        )

    # -----------------------------------------------------
    # DESTINATION INTELLIGENCE
    # -----------------------------------------------------

    destination_observations = (
        interpret_destination_behavior(
            row
        )
    )

    reasons.extend(
        destination_observations
    )

    # -----------------------------------------------------
    # INTERNAL VS EXTERNAL AWARENESS
    # -----------------------------------------------------

    source_ip = str(
        row.get(
            "source_ip",
            ""
        )
    )

    destination_ip = str(
        row.get(
            "destination_ip",
            ""
        )
    )

    internal_prefixes = (
        "192.168.",
        "10.",
        "172."
    )

    if (

        source_ip.startswith(
            internal_prefixes
        )

        and

        destination_ip.startswith(
            internal_prefixes
        )
    ):

        reasons.append(
            "Internal network communication behavior observed"
        )

    if (

        source_ip.startswith(
            internal_prefixes
        )

        and

        not destination_ip.startswith(
            internal_prefixes
        )
    ):

        reasons.append(
            "Outbound communication toward external destination detected"
        )

    # -----------------------------------------------------
    # DESTINATION TARGETING ANALYSIS
    # -----------------------------------------------------

    if row.get(
        "repeated_destination_count",
        0
    ) >= 5:

        reasons.append(
            "Repeated communication toward specific destination observed"
        )

    if row.get(
        "unique_destination_count",
        0
    ) >= 20:

        reasons.append(
            "High-volume multi-destination communication pattern detected"
        )

    # -----------------------------------------------------
    # CONFIDENCE REINFORCEMENT
    # -----------------------------------------------------

    if (

        row.get(
            "risk_score",
            0
        ) >= 0.85

        and

        row.get(
            "session_flow_count",
            0
        ) >= 3
    ):

        reasons.append(
            "High-confidence anomalous behavioral pattern identified"
        )

    # -----------------------------------------------------
    # FALLBACK
    # -----------------------------------------------------

    if not reasons:

        reasons.append(
            "Behavior within expected operational range"
        )

    # Remove duplicate explanations while preserving order.

    return list(
        dict.fromkeys(
            reasons
        )
    )


# =========================================================
# THREAT CATEGORY ENGINE
# =========================================================

def categorize_threat(reasons):

    joined = " ".join(
        reasons
    ).lower()

    if (
        "timing" in joined
        or
        "burst" in joined
    ):

        return (
            "Possible Beaconing Activity"
        )

    elif (
        "transfer" in joined
        or
        "packet size" in joined
    ):

        return (
            "Potential Data Exfiltration"
        )

    else:

        return (
            "General Behavioral Anomaly"
        )


# =========================================================
# POLICY ENGINE
# =========================================================

def suggest_action(risk_level):

    if risk_level == "HIGH":

        return (
            "Immediate investigation recommended. "
            "Consider isolating session or "
            "blocking traffic."
        )

    elif risk_level == "MEDIUM":

        return (
            "Monitor behavior and log activity "
            "for further analysis."
        )

    else:

        return (
            "No immediate action required."
        )


# =========================================================
# DESTINATION BEHAVIOR INTERPRETER
# =========================================================

def interpret_destination_behavior(row):

    observations = []

    protocol = str(
        row.get(
            "protocol",
            ""
        )
    ).upper()

    destination_port = row.get(
        "destination_port"
    )

    session_flow_count = row.get(
        "session_flow_count",
        0
    )

    packets_per_second = row.get(
        "packets_per_second",
        0
    )

    byte_rate = row.get(
        "byte_rate",
        0
    )

    # -----------------------------------------------------
    # HTTPS / ENCRYPTED TRAFFIC
    # -----------------------------------------------------

    if (

        protocol == "TCP"

        and

        destination_port == 443
    ):

        observations.append(
            "Encrypted outbound communication observed"
        )

    # -----------------------------------------------------
    # WEB TRAFFIC
    # -----------------------------------------------------

    if destination_port in [80, 443]:

        observations.append(
            "Web-based communication activity observed"
        )

    # -----------------------------------------------------
    # DNS ACTIVITY
    # -----------------------------------------------------

    if destination_port == 53:

        observations.append(
            "DNS communication behavior detected"
        )

    # -----------------------------------------------------
    # REMOTE ACCESS
    # -----------------------------------------------------

    if destination_port == 22:

        observations.append(
            "Remote shell communication behavior observed"
        )

    # -----------------------------------------------------
    # HIGH UDP ACTIVITY
    # -----------------------------------------------------

    if (

        protocol == "UDP"

        and

        packets_per_second > 100
    ):

        observations.append(
            "High-frequency UDP communication detected"
        )

    # -----------------------------------------------------
    # PERSISTENT ENCRYPTED CALLBACKS
    # -----------------------------------------------------

    if (

        destination_port == 443

        and

        session_flow_count >= 5
    ):

        observations.append(
            "Repeated outbound encrypted callbacks observed"
        )

    # -----------------------------------------------------
    # HIGH TRANSFER BEHAVIOR
    # -----------------------------------------------------

    if byte_rate > 100000:

        observations.append(
            "Elevated outbound transfer behavior detected"
        )

    return observations


# =========================================================
# POLICY ACTION
# =========================================================

def determine_policy_action(
    risk_level
):

    if risk_level == "HIGH":

        return "ALERT"

    elif risk_level == "MEDIUM":

        return "MONITOR"

    else:

        return "IGNORE"


# =========================================================
# ANOMALY STRENGTH
# =========================================================

def estimate_confidence(score):

    if score >= 0.85:

        return "HIGH"

    elif score >= 0.50:

        return "MEDIUM"

    else:

        return "LOW"


# =========================================================
# ADD RISK LAYERS
# =========================================================

def add_risk_levels(df):

    df = df.copy()

    # -----------------------------------------------------
    # BASE RISK LEVEL
    # -----------------------------------------------------

    df["risk_level"] = (
        df["risk_score"]
        .apply(
            classify_risk
        )
    )

    # -----------------------------------------------------
    # SESSION ESCALATION
    # -----------------------------------------------------

    df = apply_session_escalation(
        df
    )

    # -----------------------------------------------------
    # BEHAVIOR SUMMARY
    # -----------------------------------------------------

    df["behavior_summary"] = (
        df.apply(
            explain_risk,
            axis=1
        )
    )

    # -----------------------------------------------------
    # THREAT CATEGORY
    # -----------------------------------------------------

    df["threat_category"] = (
        df["behavior_summary"]
        .apply(
            categorize_threat
        )
    )

    # -----------------------------------------------------
    # POLICY ACTION
    # -----------------------------------------------------

    df["policy_action"] = (
        df["risk_level"]
        .apply(
            determine_policy_action
        )
    )

    # -----------------------------------------------------
    # SUGGESTED ACTION
    # -----------------------------------------------------

    df["suggested_action"] = (
        df["risk_level"]
        .apply(
            suggest_action
        )
    )

    # -----------------------------------------------------
    # ANOMALY STRENGTH
    # -----------------------------------------------------

    df["anomaly_strength"] = (
        df["risk_score"]
        .apply(
            estimate_confidence
        )
    )

    return df


# =========================================================
# EVALUATION
# =========================================================

def evaluate(df):

    print(
        "\n=== RESULTS ==="
    )

    if (
        "label" in df.columns
        and
        "prediction" in df.columns
    ):

        print(
            pd.crosstab(
                df["label"],
                df["prediction"]
            )
        )

    print(
        "\n=== RISK DISTRIBUTION ==="
    )

    print(
        df["risk_level"]
        .value_counts()
    )

    print(
        "\n=== THREAT CATEGORIES ==="
    )

    print(
        df["threat_category"]
        .value_counts()
    )


# =========================================================
# SAVE RESULTS
# =========================================================

def save_results(df):

    if os.path.exists(
        RESULTS_PATH
    ):

        existing_df = pd.read_csv(
            RESULTS_PATH
        )

        combined_df = pd.concat(
            [
                existing_df,
                df
            ],
            ignore_index=True
        )

        combined_df.to_csv(
            RESULTS_PATH,
            index=False
        )

        print(
            "\n[INFO] Existing results found."
        )

        print(
            "[INFO] Appended new results."
        )

        print(
            f"[INFO] Total rows: "
            f"{len(combined_df)}"
        )

    else:

        df.to_csv(
            RESULTS_PATH,
            index=False
        )

        print(
            "\n[INFO] New results file created."
        )

        print(
            f"[INFO] Rows saved: "
            f"{len(df)}"
        )


# =========================================================
# V3.1 TRAINING PIPELINE
# =========================================================

def train_from_training_data(
    training_df,
    ablation_features=None
):

    print(
        "\n========== V3.1 TRAINING =========="
    )

    # Training data is filtered to benign traffic
    # inside prepare_training_data().

    X_train = prepare_training_data(
        training_df,
        ablation_features
    )

    # CRITICAL BENCHMARK RULE:
    #
    # The scaler is fitted ONLY here,
    # using TRAINING data.

    scaler, X_train_scaled = (
        fit_scaler(
            X_train
        )
    )

    # The model is also fitted ONLY using
    # the training dataset.

    model = train_model(
        X_train_scaled
    )

    return (
        model,
        scaler
    )


# =========================================================
# V3.1 EVALUATION PIPELINE
# =========================================================

def evaluate_dataset(
    model,
    scaler,
    df,
    dataset_name,
    ablation_features=None
):

    print(
        f"\n========== "
        f"V3.1 {dataset_name.upper()} "
        f"=========="
    )

    # -----------------------------------------------------
    # PREPARE FEATURES
    # -----------------------------------------------------

    X = prepare_data(
        df,
        ablation_features
    )

    # -----------------------------------------------------
    # NEVER FIT THE SCALER HERE
    #
    # Validation and test data use the frozen
    # scaler fitted on training data.
    # -----------------------------------------------------

    X_scaled = transform_data(
        scaler,
        X
    )

    # -----------------------------------------------------
    # PREDICTIONS
    # -----------------------------------------------------

    evaluated_df = predict(
        model,
        X_scaled,
        df
    )

    # -----------------------------------------------------
    # RISK SCORING
    # -----------------------------------------------------

    evaluated_df = add_risk_scores(
        model,
        X_scaled,
        evaluated_df
    )

    # -----------------------------------------------------
    # RISK / EXPLAINABILITY LAYERS
    # -----------------------------------------------------

    evaluated_df = add_risk_levels(
        evaluated_df
    )

    print(
        f"\n[INFO] {dataset_name} evaluation complete."
    )

    evaluate(
        evaluated_df
    )

    return evaluated_df


# =========================================================
# MAIN
# =========================================================

def main():

    print(
        "\n========== MODEL PIPELINE =========="
    )

    # -----------------------------------------------------
    # LOAD CURRENT DATASET
    # -----------------------------------------------------

    df = load_data()

    # -----------------------------------------------------
    # TRAIN ONLY USING BENIGN ROWS
    # -----------------------------------------------------

    model, scaler = (
        train_from_training_data(
            df,
            []
        )
    )

    # -----------------------------------------------------
    # EVALUATE CURRENT DATASET
    # -----------------------------------------------------

    evaluated_df = evaluate_dataset(
        model,
        scaler,
        df,
        "dataset"
    )

    # -----------------------------------------------------
    # SAVE RESULTS
    # -----------------------------------------------------

    save_results(
        evaluated_df
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()