import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# =========================================================
# LOAD DATA
# =========================================================

def load_data():
    df = pd.read_csv("../features/dataset.csv")
    return df


# =========================================================
# PREPARE FEATURES
# =========================================================

def prepare_data(df):

    # All usable features
    X = df.drop(columns=["label", "attack_type"])

    # Train ONLY on normal traffic
    X_train = (
        df[df["label"] == 0]
        .drop(columns=["label", "attack_type"])
    )

    return X, X_train


# =========================================================
# SCALE DATA
# =========================================================

def scale_data(X, X_train):

    scaler = StandardScaler()

    # Fit ONLY on training data
    X_train_scaled = scaler.fit_transform(X_train)

    # Transform complete dataset
    X_scaled = scaler.transform(X)

    return X_scaled, X_train_scaled, scaler


# =========================================================
# TRAIN MODEL
# =========================================================

def train_model(X_train_scaled):

    model = IsolationForest(
        contamination=0.2,
        random_state=42
    )

    model.fit(X_train_scaled)

    return model


# =========================================================
# RISK SCORE GENERATION
# =========================================================

def add_risk_scores(model, X_scaled, df):

    # Raw anomaly scores
    scores = model.decision_function(X_scaled)

    # Invert:
    # lower score = more anomalous
    scores_inverted = -scores

    # Normalize between 0 and 1
    min_score = scores_inverted.min()
    max_score = scores_inverted.max()

    risk_scores = (
        (scores_inverted - min_score)
        / (max_score - min_score)
    )

    df["risk_score"] = risk_scores

    return df


# =========================================================
# RISK CLASSIFICATION
# =========================================================

def classify_risk(score):

    if score < 0.3:
        return "LOW"

    elif score < 0.7:
        return "MEDIUM"

    else:
        return "HIGH"


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
            "Monitor behavior and log activity for "
            "further analysis."
        )

    else:

        return (
            "No immediate action required."
        )


# =========================================================
# APPLY RISK LAYER
# =========================================================

def add_risk_levels(df):

    # Risk category
    df["risk_level"] = (
        df["risk_score"]
        .apply(classify_risk)
    )

    # Behavioral explanations
    df["risk_reason"] = (
        df.apply(explain_risk, axis=1)
    )

    # Suggested security response
    df["suggested_action"] = (
        df["risk_level"]
        .apply(suggest_action)
    )

    return df


# =========================================================
# PREDICTIONS
# =========================================================

def predict(model, X_scaled, df):

    predictions = model.predict(X_scaled)

    # Convert:
    #  1  -> normal -> 0
    # -1 -> anomaly -> 1

    df["prediction"] = (
        pd.Series(predictions)
        .map({1: 0, -1: 1})
    )

    return df


# =========================================================
# EVALUATION
# =========================================================

def evaluate(df):

    print("\n=== RESULTS ===")

    print(
        pd.crosstab(
            df["label"],
            df["prediction"]
        )
    )

    print("\n=== RISK DISTRIBUTION ===")

    print(
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
# SAVE OUTPUT
# =========================================================

def save_results(df):

    df.to_csv("results.csv", index=False)

    print(
        "\n[SUCCESS] Results saved to results.csv"
    )


# =========================================================
# MAIN PIPELINE
# =========================================================

if __name__ == "__main__":

    # Load dataset
    df = load_data()

    # Prepare features
    X, X_train = prepare_data(df)

    # Scale
    X_scaled, X_train_scaled, scaler = scale_data(
        X,
        X_train
    )

    # Train
    model = train_model(X_train_scaled)

    # Risk scoring
    df = add_risk_scores(
        model,
        X_scaled,
        df
    )

    # Risk interpretation
    df = add_risk_levels(df)

    # Binary prediction
    df = predict(
        model,
        X_scaled,
        df
    )

    # Evaluation
    evaluate(df)

    # Save
    save_results(df)