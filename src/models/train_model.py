

# CONFIGURATION


FEATURE_DIR = "results"
RESULTS_DIR = "results"

DATASET_FILE = "dataset.csv"
RESULTS_FILE = "results.csv"

dataset_path = os.path.join(FEATURE_DIR, DATASET_FILE)

os.makedirs(RESULTS_DIR, exist_ok=True)

results_path = os.path.join(RESULTS_DIR, RESULTS_FILE)


# LOAD DATASET


# =========================================================
# LOAD DATA
# =========================================================

def load_data():

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"[ERROR] Dataset not found: {dataset_path}"
        )

    df = pd.read_csv(dataset_path)

    return df


# =========================================================
# PREPARE FEATURES
# =========================================================

# PREPARE FEATURES

def prepare_data(df):

    # All usable features

    # Full feature set
    X = df.drop(columns=["label", "attack_type"])

    # Train ONLY on normal traffic
    X_train = (
        df[df["label"] == 0]
        .drop(columns=["label", "attack_type"])
    )
    # Train ONLY on normal traffic
    X_train = df[
        df["label"] == 0
    ].drop(columns=["label", "attack_type"])

    return X, X_train


# =========================================================
# SCALE DATA
# =========================================================

# SCALE FEATURES

def scale_data(X, X_train):


    scaler = StandardScaler()

    # Fit ONLY on training data
    X_train_scaled = scaler.fit_transform(X_train)

    # Transform complete dataset
    X_scaled = scaler.transform(X)

    # Transform full dataset
    X_scaled = scaler.transform(X)

    return X_scaled, X_train_scaled, scaler


# =========================================================
# TRAIN MODEL
# =========================================================

# TRAIN ISOLATION FOREST

def train_model(X_train_scaled):


    model = IsolationForest(
    contamination=0.15,
    random_state=42
    )


    model.fit(X_train_scaled)


    return model


# =========================================================
# RISK SCORE GENERATION
# =========================================================
# PREDICTIONS

def add_risk_scores(model, X_scaled, df):

    # Raw anomaly scores

    # Raw anomaly score
    scores = model.decision_function(X_scaled)

    # Invert:
    # lower score = more anomalous
    # Invert (lower = anomaly → higher risk)
    scores_inverted = -scores

    # Normalize between 0 and 1
    # Normalize to [0, 1]
    min_score = scores_inverted.min()
    max_score = scores_inverted.max()

    risk_scores = (
        (scores_inverted - min_score)
        / (max_score - min_score)
    )
    risk_scores = (
        scores_inverted - min_score
    ) / (
        max_score - min_score
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


    df["risk_level"] = df["risk_score"].apply(
        classify_risk
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


# =========================================================
# EVALUATION
# =========================================================

# EVALUATION

def evaluate(df):

    print("\n=== RESULTS ===")

    print(
        pd.crosstab(
            df["label"],
            df["prediction"]
        )
    )

    print("\n========== RESULTS ==========\n")

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

    print(
        df["risk_level"].value_counts()
    )


# SAVE RESULTS

def save_results(df):

    df.to_csv("results.csv", index=False)

    print(
        "\n[SUCCESS] Results saved to results.csv"
    )

    df.to_csv(results_path, index=False)

    print(
        f"\n[SUCCESS] Results saved to: {results_path}"
    )


# =========================================================
# MAIN PIPELINE
# =========================================================

# MAIN PIPELINE

if __name__ == "__main__":

    # Load dataset

    print("\n[INFO] Loading dataset...")
    df = load_data()

    # Prepare features
    print("[INFO] Preparing features...")
    X, X_train = prepare_data(df)

    # Scale
    X_scaled, X_train_scaled, scaler = scale_data(
        X,
        X_train
    )
    print("[INFO] Scaling data...")
    X_scaled, X_train_scaled, scaler = scale_data(
        X,
        X_train
    )

    # Train
    print("[INFO] Training Isolation Forest...")
    model = train_model(X_train_scaled)

    # Risk scoring
    df = add_risk_scores(
        model,
        X_scaled,
        df
    )

    # Risk interpretation
    df = add_risk_levels(df)
print("[INFO] Running predictions...")

# Risk scoring
df = add_risk_scores(
    model,
    X_scaled,
    df
)

df = add_risk_levels(df)

    # Binary prediction
    df = predict(
        model,
        X_scaled,
        df
    )
# Binary prediction
df = predict(
    model,
    X_scaled,
    df
)
df = predict(model, X_scaled, df)

    # Evaluation
    evaluate(df)
print("[INFO] Evaluating model...")
evaluate(df)

    # Save
    save_results(df)
print("[INFO] Saving results...")
save_results(df)

print("\nModel pipeline completed successfully!")