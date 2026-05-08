import os
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


<<<<<<< HEAD
# =========================================================
# CONFIGURATION
# =========================================================

FEATURE_DIR = "../../results"
RESULTS_DIR = "../../results"
=======
# CONFIGURATION

FEATURE_DIR = "results"
RESULTS_DIR = "results"
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c

DATASET_FILE = "dataset.csv"
RESULTS_FILE = "results.csv"

dataset_path = os.path.join(
    FEATURE_DIR,
    DATASET_FILE
)

<<<<<<< HEAD
=======
os.makedirs(RESULTS_DIR, exist_ok=True)

>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
results_path = os.path.join(
    RESULTS_DIR,
    RESULTS_FILE
)

<<<<<<< HEAD
os.makedirs(RESULTS_DIR, exist_ok=True)


# =========================================================
# LOAD DATA
# =========================================================
=======

# LOAD DATASET
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c

def load_data():

    if not os.path.exists(dataset_path):
<<<<<<< HEAD
=======

>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
        raise FileNotFoundError(
            f"[ERROR] Dataset not found: {dataset_path}"
        )

    df = pd.read_csv(dataset_path)

    return df


# PREPARE FEATURES

def prepare_data(df):

    # Full feature set
    X = df.drop(
        columns=["label", "attack_type"]
<<<<<<< HEAD
    )

    # Train ONLY on normal traffic
    X_train = (
        df[df["label"] == 0]
        .drop(columns=["label", "attack_type"])
=======
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
    )

    # --------------------------------------
    # Train ONLY on normal traffic
    # --------------------------------------

    normal_df = df[
        df["label"] == 0
    ]

    # If normal traffic exists
    if len(normal_df) > 0:

        X_train = normal_df.drop(
            columns=["label", "attack_type"]
        )

    # Fallback for pure attack datasets
    else:

        print(
            "\n[WARNING] No normal traffic found."
        )

        print(
            "[WARNING] Using full dataset for training."
        )

        X_train = X.copy()

    return X, X_train


<<<<<<< HEAD
# =========================================================
# SCALE FEATURES
# =========================================================
=======
# SCALE FEATURES
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c

def scale_data(X, X_train):

    scaler = StandardScaler()

    # Fit ONLY on training data
    X_train_scaled = scaler.fit_transform(
        X_train
    )

    # Transform full dataset
    X_scaled = scaler.transform(X)

    return X_scaled, X_train_scaled, scaler


<<<<<<< HEAD
# =========================================================
# TRAIN ISOLATION FOREST
# =========================================================
=======
# TRAIN ISOLATION FOREST
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c

def train_model(X_train_scaled):

    model = IsolationForest(
        contamination=0.15,
        random_state=42
    )

    model.fit(X_train_scaled)

    return model


<<<<<<< HEAD
# =========================================================
# GENERATE RISK SCORES
# =========================================================
=======
# RISK SCORING
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c

def add_risk_scores(model, X_scaled, df):

    # Raw anomaly score
    scores = model.decision_function(
        X_scaled
    )

    # Invert:
    # lower = anomaly → higher risk
    scores_inverted = -scores

    # Normalize to [0, 1]
    min_score = scores_inverted.min()

    max_score = scores_inverted.max()

    risk_scores = (
        scores_inverted - min_score
    ) / (
        max_score - min_score
    )

    df["risk_score"] = risk_scores

    return df


def classify_risk(score):

    if score < 0.3:
        return "LOW"

    elif score < 0.7:
        return "MEDIUM"

    else:
        return "HIGH"


<<<<<<< HEAD
# =========================================================
# EXPLAINABILITY ENGINE
# =========================================================

def explain_risk(row):

    reasons = []

    risk_level = row["risk_level"]

    # -----------------------------------------------------
    # Timing entropy
    # -----------------------------------------------------

    if row["interval_entropy"] > 1.5:

        if risk_level == "HIGH":
            reasons.append(
                "Severe irregular timing behavior detected"
            )

        else:
            reasons.append(
                "Irregular packet timing observed"
            )

    # -----------------------------------------------------
    # Burst communication
    # -----------------------------------------------------

    if row["burst_ratio"] > 5:

        if risk_level == "HIGH":
            reasons.append(
                "Aggressive burst communication pattern identified"
            )

        else:
            reasons.append(
                "Burst communication behavior observed"
            )

    # -----------------------------------------------------
    # Packet transmission intensity
    # -----------------------------------------------------

    if row["packets_per_second"] > 500:

        if risk_level == "HIGH":
            reasons.append(
                "Extremely elevated packet transmission rate"
            )

        else:
            reasons.append(
                "Elevated packet transmission rate"
            )

    # -----------------------------------------------------
    # Packet size variance
    # -----------------------------------------------------

    if row["size_variance"] > 10000:

        if risk_level == "HIGH":
            reasons.append(
                "Significant packet size irregularity detected"
            )

        else:
            reasons.append(
                "Abnormal packet size variation detected"
            )

    # -----------------------------------------------------
    # Byte transfer intensity
    # -----------------------------------------------------

    if row["byte_rate"] > 100000:

        if risk_level == "HIGH":
            reasons.append(
                "Extremely high data transfer behavior observed"
            )

        else:
            reasons.append(
                "Unusually high data transfer rate"
            )

    # -----------------------------------------------------
    # Fallback
    # -----------------------------------------------------

    if not reasons:

        reasons.append(
            "Behavior within expected operational parameters"
        )

    return " | ".join(reasons)


# =========================================================
# SUGGESTED SECURITY ACTIONS
# =========================================================

def suggest_action(risk_level):

    if risk_level == "HIGH":

        return (
            "Immediate investigation recommended. "
            "Consider isolating session or blocking traffic."
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
# APPLY RISK LAYER
# =========================================================

=======
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
def add_risk_levels(df):

    df["risk_level"] = df[
        "risk_score"
    ].apply(classify_risk)

    return df


# PREDICTIONS

def predict(model, X_scaled, df):

    predictions = model.predict(
        X_scaled
    )

    # IsolationForest:
    #  1  -> normal
    # -1  -> anomaly

    df["prediction"] = pd.Series(
        predictions
    ).map({
        1: 0,
        -1: 1
    })

    return df


# EVALUATION

def evaluate(df):

    print("\n========== RESULTS ==========\n")

    print(
        pd.crosstab(
            df["label"],
            df["prediction"]
        )
    )

    print("\n=== RISK DISTRIBUTION ===")

    print(
<<<<<<< HEAD
        df["risk_level"]
        .value_counts()
    )

    print("\n=== SAMPLE RISK ANALYSIS ===")

    print(
        df[
            [
                "risk_score",
                "risk_level",
                "risk_reason",
                "suggested_action"
            ]
        ].head(5)
    )


# =========================================================
# SAVE RESULTS
# =========================================================

def save_results(df):

    df.to_csv(results_path, index=False)

    print(
        f"\n[SUCCESS] Results saved to {results_path}"
=======
        df["risk_level"].value_counts()
    )


# SAVE RESULTS

def save_results(df):

    df.to_csv(
        results_path,
        index=False
    )

    print(
        f"\n[SUCCESS] Results saved to: {results_path}"
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
    )


# MAIN PIPELINE

def main():

    print("\n[INFO] Loading dataset...")

    df = load_data()

    print("[INFO] Preparing features...")

    X, X_train = prepare_data(df)

<<<<<<< HEAD
    # Scale data
=======
    print("[INFO] Scaling data...")

>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
    X_scaled, X_train_scaled, scaler = scale_data(
        X,
        X_train
    )

<<<<<<< HEAD
    # Train model
    model = train_model(X_train_scaled)
=======
    print("[INFO] Training Isolation Forest...")

    model = train_model(
        X_train_scaled
    )

    print("[INFO] Running predictions...")
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c

    # Generate risk scores
    df = add_risk_scores(
        model,
        X_scaled,
        df
    )

<<<<<<< HEAD
    # Apply explainability layer
=======
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
    df = add_risk_levels(df)

    # Generate predictions
    df = predict(
        model,
        X_scaled,
        df
    )

<<<<<<< HEAD
    # Evaluate
    evaluate(df)

    # Save output
    save_results(df)


if __name__ == "__main__":
    main()
=======
    print("[INFO] Evaluating model...")

    evaluate(df)

    print("[INFO] Saving results...")

    save_results(df)

    print("\nModel pipeline completed successfully!")
>>>>>>> 1bf1b81939e3955bf084307584f24322728b109c
