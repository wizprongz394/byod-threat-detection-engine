import os
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# PATH CONFIGURATION

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


# LOAD DATASET

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
# PREPARE ML DATA
# =========================================================

def prepare_data(df):

    # =========================================
    # NON-NUMERIC / METADATA COLUMNS
    # =========================================

    metadata_columns = [

        "label",
        "attack_type",

        "session_id",

        "source_ip",
        "destination_ip",

        "protocol"
    ]

    # REMOVE ONLY EXISTING COLUMNS

    metadata_columns = [

        col

        for col in metadata_columns

        if col in df.columns
    ]

    # =========================================
    # ML FEATURE MATRIX
    # =========================================

    X = df.drop(
        columns=metadata_columns
    )

    # =========================================
    # NORMAL-ONLY TRAINING
    # =========================================

    normal_df = df[
        df["label"] == 0
    ]

    # FALLBACK IF NO NORMAL TRAFFIC

    if normal_df.empty:

        print(
            "\n[WARNING] No normal traffic found."
        )

        print(
            "[WARNING] Falling back to full dataset for training."
        )

        X_train = X.copy()

    else:

        X_train = normal_df.drop(
            columns=metadata_columns
        )

    # =========================================
    # SAFETY CLEANING
    # =========================================

    X = X.fillna(0)

    X_train = X_train.fillna(0)

    return X, X_train


#  SCALE FEATURES

def scale_data(X, X_train):

    scaler = StandardScaler()

    # FIT ONLY ON TRAINING DATA

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    # TRANSFORM FULL DATASET

    X_scaled = scaler.transform(
        X
    )

    print(
        "\n[INFO] Feature scaling complete."
    )

    return (
        X_scaled,
        X_train_scaled,
        scaler
    )


# TRAIN MODEL

def train_model(X_train_scaled):

    model = IsolationForest(

        contamination=0.20,

        random_state=42
    )

    model.fit(
        X_train_scaled
    )

    print(
        "\n[INFO] Isolation Forest "
        "training complete."
    )

    return model


# GENERATE PREDICTIONS

def predict(model, X_scaled, df):

    # RAW PREDICTIONS

    predictions = model.predict(
        X_scaled
    )

    # CONVERT OUTPUT

    # Isolation Forest:  1  -> normal -1 -> anomaly
    # Convert into: 0 -> normal 1 -> anomaly

    mapped_predictions = [

        0 if prediction == 1 else 1

        for prediction in predictions
    ]

    # SAFE ASSIGNMENT

    df["prediction"] = (
        mapped_predictions
    )

    #  VALIDATION

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


# ADD RISK SCORES

def add_risk_scores(
    model,
    X_scaled,
    df
):

    # RAW ANOMALY SCORES

    scores = model.decision_function(
        X_scaled
    )

    # INVERT SCORES

    # Lower score = more anomalous So invert.

    scores_inverted = -scores

    # NORMALIZE

    min_score = np.min(
        scores_inverted
    )

    max_score = np.max(
        scores_inverted
    )

    risk_scores = (

        (scores_inverted - min_score)

        /

        (max_score - min_score)
    )

    df["risk_score"] = (
        risk_scores
    )

    print(
        "\n[INFO] Risk scoring complete."
    )

    return df


# RISK CLASSIFICATION

def classify_risk(score):

    if score < 0.30:

        return "LOW"

    elif score < 0.70:

        return "MEDIUM"

    else:

        return "HIGH"

def apply_session_escalation(df):

    # ---------------------------------------------
    # GROUP BY SESSION
    # ---------------------------------------------

    session_groups = df.groupby(
        "session_id"
    )

    # ---------------------------------------------
    # PROCESS EACH SESSION
    # ---------------------------------------------

    for session_id, group in session_groups:

        avg_risk = group[
            "risk_score"
        ].mean()

        flow_count = len(group)

        # -----------------------------------------
        # ESCALATION CONDITION
        # -----------------------------------------

        if (

            flow_count >= 3

            and

            avg_risk >= 0.6
        ):

            # Escalate all flows
            # inside session

            df.loc[

                df["session_id"]
                == session_id,

                "risk_level"

            ] = "HIGH"

            # Add escalation note

            df.loc[

                df["session_id"]
                == session_id,

                "risk_reason"

            ] += (

                " | Repeated suspicious "
                "session behavior detected"
            )

    return df



# EXPLAINABILITY ENGINE

# =========================================================
# DESTINATION + BEHAVIORAL INTELLIGENCE ENGINE
# =========================================================

def explain_risk(row):

    reasons = []

    # =====================================================
    # BASIC BEHAVIORAL ANOMALIES
    # =====================================================

    # TIMING IRREGULARITY

    if row.get(
        "interval_entropy",
        0
    ) > 1.5:

        reasons.append(

            "Highly irregular timing behavior detected"
        )

    # BURST COMMUNICATION

    if row.get(
        "burst_ratio",
        0
    ) > 5:

        reasons.append(

            "Burst communication behavior observed"
        )

    # HIGH PACKET RATE

    if row.get(
        "packets_per_second",
        0
    ) > 50:

        reasons.append(

            "Elevated packet transmission rate detected"
        )

    # PACKET SIZE IRREGULARITY

    if row.get(
        "size_variance",
        0
    ) > 10000:

        reasons.append(

            "Abnormal packet size variation detected"
        )

    # HIGH BYTE TRANSFER RATE

    if row.get(
        "byte_rate",
        0
    ) > 100000:

        reasons.append(

            "Unusually high data transfer behavior detected"
        )

    # =====================================================
    # SESSION INTELLIGENCE
    # =====================================================

    # REPEATED SESSION COMMUNICATION

    if row.get(
        "session_flow_count",
        0
    ) >= 5:

        reasons.append(

            "Persistent multi-flow communication session observed"
        )

    # LONG SESSION DURATION

    if row.get(
        "session_duration",
        0
    ) > 300:

        reasons.append(

            "Long-duration communication persistence detected"
        )

    # HIGH SESSION TRANSFER

    if row.get(
        "session_total_bytes",
        0
    ) > 50000:

        reasons.append(

            "Sustained high-volume session transfer observed"
        )

    # =====================================================
    # TEMPORAL BEHAVIORAL INTELLIGENCE
    # =====================================================

    # PERIODIC COMMUNICATION

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

    # IRREGULAR BURST BEHAVIOR

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

    # =====================================================
    # EXFILTRATION-LIKE BEHAVIOR
    # =====================================================

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

    # =====================================================
    # DESTINATION INTELLIGENCE
    # =====================================================

    destination_observations = (

        interpret_destination_behavior(
            row
        )
    )

    reasons.extend(
        destination_observations
    )

    # =====================================================
    # INTERNAL vs EXTERNAL AWARENESS
    # =====================================================

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

    # INTERNAL COMMUNICATION

    if (

        source_ip.startswith(
            ("192.168.", "10.", "172.")
        )

        and

        destination_ip.startswith(
            ("192.168.", "10.", "172.")
        )
    ):

        reasons.append(

            "Internal network communication behavior observed"
        )

    # OUTBOUND EXTERNAL COMMUNICATION

    if (

        source_ip.startswith(
            ("192.168.", "10.", "172.")
        )

        and

        not destination_ip.startswith(
            ("192.168.", "10.", "172.")
        )
    ):

        reasons.append(

            "Outbound communication toward external destination detected"
        )

    # =====================================================
    # DESTINATION TARGETING ANALYSIS
    # =====================================================

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

    # =====================================================
    # CONFIDENCE REINFORCEMENT
    # =====================================================

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

    # =====================================================
    # FALLBACK
    # =====================================================

    if not reasons:

        reasons.append(

            "Behavior within expected operational range"
        )

    # REMOVE DUPLICATES

    reasons = list(
        dict.fromkeys(reasons)
    )

    return reasons


# THREAT CATEGORY ENGINE

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


# POLICY ENGINE

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
# DESTINATION BEHAVIOR INTERPRETER

def interpret_destination_behavior(row):

    observations = []

    protocol = str(
        row.get("protocol", "")
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

    # =========================================
    # HTTPS / ENCRYPTED TRAFFIC
    # =========================================

    if (
        protocol == "TCP"
        and destination_port == 443
    ):

        observations.append(

            "Encrypted outbound communication observed"
        )

    # =========================================
    # WEB TRAFFIC
    # =========================================

    if destination_port in [80, 443]:

        observations.append(

            "Web-based communication activity observed"
        )

    # =========================================
    # DNS ACTIVITY
    # =========================================

    if destination_port == 53:

        observations.append(

            "DNS communication behavior detected"
        )

    # =========================================
    # REMOTE ACCESS
    # =========================================

    if destination_port == 22:

        observations.append(

            "Remote shell communication behavior observed"
        )

    # =========================================
    # HIGH UDP ACTIVITY
    # =========================================

    if (
        protocol == "UDP"
        and packets_per_second > 100
    ):

        observations.append(

            "High-frequency UDP communication detected"
        )

    # =========================================
    # PERSISTENT ENCRYPTED CALLBACKS
    # =========================================

    if (
        destination_port == 443
        and session_flow_count >= 5
    ):

        observations.append(

            "Repeated outbound encrypted callbacks observed"
        )

    # =========================================
    # HIGH TRANSFER BEHAVIOR
    # =========================================

    if byte_rate > 100000:

        observations.append(

            "Elevated outbound transfer behavior detected"
        )

    return observations


# POLICY ACTION

def determine_policy_action(
    risk_level
):

    if risk_level == "HIGH":

        return "ALERT"

    elif risk_level == "MEDIUM":

        return "MONITOR"

    else:

        return "IGNORE"


# ANOMALY STRENGTH

def estimate_confidence(score):

    if score >= 0.85:

        return "HIGH"

    elif score >= 0.50:

        return "MEDIUM"

    else:

        return "LOW"


# ADD RISK LAYERS

def add_risk_levels(df):

    # RISK LEVEL

    df["risk_level"] = (

        df["risk_score"]
        .apply(classify_risk)
    )
    df = apply_session_escalation(df)

    # BEHAVIOR SUMMARY

    df["behavior_summary"] = (

        df.apply(
            explain_risk,
            axis=1
        )
    )

    # THREAT CATEGORY

    df["threat_category"] = (

        df["behavior_summary"]
        .apply(categorize_threat)
    )

    # POLICY ACTION

    df["policy_action"] = (

        df["risk_level"]
        .apply(determine_policy_action)
    )

    # SUGGESTED ACTION

    df["suggested_action"] = (

        df["risk_level"]
        .apply(suggest_action)
    )

    # ANOMALY STRENGTH

    df["anomaly_strength"] = (

        df["risk_score"]
        .apply(estimate_confidence)
    )

    return df



# EVALUATION

def evaluate(df):

    print(
        "\n=== RESULTS ==="
    )

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


# SAVE RESULTS

def save_results(df):

    if os.path.exists(
        RESULTS_PATH
    ):

        existing_df = pd.read_csv(
            RESULTS_PATH
        )

        combined_df = pd.concat(
            [existing_df, df],
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


# MAIN

def main():

    print(
        "\n========== MODEL PIPELINE =========="
    )

    # LOAD DATA

    df = load_data()

    # PREPARE FEATURES

    X, X_train = prepare_data(
        df
    )

    # SCALE DATA

    (
        X_scaled,
        X_train_scaled,
        scaler

    ) = scale_data(
        X,
        X_train
    )

    # TRAIN MODEL

    model = train_model(
        X_train_scaled
    )

    # PREDICTIONS

    df = predict(
        model,
        X_scaled,
        df
    )

    # RISK ENGINE

    df = add_risk_scores(
        model,
        X_scaled,
        df
    )

    df = add_risk_levels(
        df
    )

    # EVALUATE

    evaluate(df)

    # SAVE

    save_results(df)


# ENTRY POINT

if __name__ == "__main__":
    main()