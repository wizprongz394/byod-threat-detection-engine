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


# PREPARE FEATURES

def prepare_data(df):

    # REMOVE NON-NUMERIC COLUMNS

    X = df.drop(
        columns=[

            "label",
            "attack_type",

            "source_ip",
            "destination_ip",

            "source_port",
            "destination_port",

            "protocol"
        ],
        errors="ignore"
    )

    # TRAIN ONLY ON NORMAL TRAFFIC

    X_train = df[
        df["label"] == 0
    ].drop(
        columns=[

            "label",
            "attack_type",

            "source_ip",
            "destination_ip",

            "source_port",
            "destination_port",

            "protocol"
        ],
        errors="ignore"
    )

    # FALLBACK SAFETY If no normal traffic exists, fallback to entire dataset.

    if len(X_train) == 0:

        print(
            "\n[WARNING] No normal traffic found."
        )

        print(
            "[WARNING] Falling back to "
            "full dataset for training."
        )

        X_train = X.copy()

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

def explain_risk(row):

    reasons = []

    # INTERVAL ENTROPY

    if row.get(
        "interval_entropy",
        0
    ) > 1.5:

        reasons.append(
            "Highly irregular timing behavior detected"
        )

    # BURST RATIO

    if row.get(
        "burst_ratio",
        0
    ) > 5:

        reasons.append(
            "Burst communication behavior observed"
        )

    # PACKET RATE

    if row.get(
        "packets_per_second",
        0
    ) > 50:

        reasons.append(
            "Elevated packet transmission rate"
        )

    # SIZE VARIANCE

    if row.get(
        "size_variance",
        0
    ) > 10000:

        reasons.append(
            "Abnormal packet size variation detected"
        )

    # BYTE RATE

    if row.get(
        "byte_rate",
        0
    ) > 100000:

        reasons.append(
            "Unusually high data transfer rate"
        )
    # -----------------------------------------
    # BEACONING-LIKE PATTERN
    # -----------------------------------------

    if (

        row["session_flow_count"] >= 3

        and

        row["flow_gap_variance"] < 5

        and

        row["interval_entropy"] > 0.5
    ):

        reasons.append(

            "Persistent periodic communication "
            "behavior observed"

        )

        reasons.append(

            "Possible beaconing activity detected"
        )

    # -----------------------------------------
    # EXFILTRATION-LIKE PATTERN
    # -----------------------------------------

    if (

        row["byte_rate"] > 100000

        and

        row["session_total_bytes"] > 50000

        and

        row["packets_per_second"] > 50
    ):

        reasons.append(

            "Sustained elevated transfer "
            "behavior detected"
        )

        reasons.append(

            "Potential data exfiltration "
            "pattern observed"
        )

    # -----------------------------------------
    # IRREGULAR BURST BEHAVIOR
    # -----------------------------------------

    if (

        row["burst_ratio"] > 5

        and

        row["flow_gap_variance"] > 10
    ):

        reasons.append(

            "Irregular burst communication "
            "pattern observed"
        )


    # FALLBACK

    if not reasons:

        reasons.append(
            "Behavior within expected operational range"
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