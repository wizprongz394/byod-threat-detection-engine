import os
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# CONFIGURATION


FEATURE_DIR = "results"
RESULTS_DIR = "results"

DATASET_FILE = "dataset.csv"
RESULTS_FILE = "results.csv"

dataset_path = os.path.join(FEATURE_DIR, DATASET_FILE)

os.makedirs(RESULTS_DIR, exist_ok=True)

results_path = os.path.join(RESULTS_DIR, RESULTS_FILE)


# LOAD DATASET


def load_data():

    if not os.path.exists(dataset_path):
        raise FileNotFoundError(
            f"[ERROR] Dataset not found: {dataset_path}"
        )

    df = pd.read_csv(dataset_path)

    return df


# PREPARE FEATURES

def prepare_data(df):

    # Full feature set
    X = df.drop(columns=["label", "attack_type"])

    # Train ONLY on normal traffic
    X_train = df[
        df["label"] == 0
    ].drop(columns=["label", "attack_type"])

    return X, X_train


# SCALE FEATURES

def scale_data(X, X_train):

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(X_train)
    X_scaled = scaler.transform(X)

    # Transform full dataset
    X_scaled = scaler.transform(X)

    return X_scaled, X_train_scaled, scaler


# TRAIN ISOLATION FOREST

def train_model(X_train_scaled):

    model = IsolationForest(
    contamination=0.15,
    random_state=42
    )

    model.fit(X_train_scaled)

    return model

# PREDICTIONS

def add_risk_scores(model, X_scaled, df):

    # Raw anomaly score
    scores = model.decision_function(X_scaled)

    # Invert (lower = anomaly → higher risk)
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


def add_risk_levels(df):

    df["risk_level"] = df["risk_score"].apply(
        classify_risk
    )

    return df

def predict(model, X_scaled, df):

    predictions = model.predict(X_scaled)

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
        df["risk_level"].value_counts()
    )


# SAVE RESULTS

def save_results(df):

    df.to_csv(results_path, index=False)

    print(
        f"\n[SUCCESS] Results saved to: {results_path}"
    )


# MAIN PIPELINE

if __name__ == "__main__":

    print("\n[INFO] Loading dataset...")
    df = load_data()

    print("[INFO] Preparing features...")
    X, X_train = prepare_data(df)

    print("[INFO] Scaling data...")
    X_scaled, X_train_scaled, scaler = scale_data(
        X,
        X_train
    )

    print("[INFO] Training Isolation Forest...")
    model = train_model(X_train_scaled)
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
df = predict(model, X_scaled, df)

print("[INFO] Evaluating model...")
evaluate(df)

print("[INFO] Saving results...")
save_results(df)

print("\nModel pipeline completed successfully!")