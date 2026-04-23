import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def load_data():
    df = pd.read_csv("../features/dataset.csv")
    return df


def prepare_data(df):
    # Features only
    X = df.drop(columns=["label", "attack_type"])

    # Train ONLY on normal data
    X_train = df[df["label"] == 0].drop(columns=["label", "attack_type"])

    return X, X_train


def scale_data(X, X_train):
    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)
    X_train_scaled = scaler.fit_transform(X_train)

    return X_scaled, X_train_scaled, scaler


def train_model(X_train_scaled):
    model = IsolationForest(
        contamination=0.15,
        random_state=42
    )
    model.fit(X_train_scaled)
    return model


def predict(model, X_scaled, df):
    predictions = model.predict(X_scaled)

    # Convert:
    #  1 → normal → 0
    # -1 → anomaly → 1
    df["prediction"] = pd.Series(predictions).map({1: 0, -1: 1})

    return df


def evaluate(df):
    print("\n=== RESULTS ===")
    print(pd.crosstab(df["label"], df["prediction"]))


def save_results(df):
    df.to_csv("results.csv", index=False)
    print("\n[SUCCESS] Results saved to results.csv")


if __name__ == "__main__":
    df = load_data()

    X, X_train = prepare_data(df)

    X_scaled, X_train_scaled, scaler = scale_data(X, X_train)

    model = train_model(X_train_scaled)

    df = predict(model, X_scaled, df)

    evaluate(df)

    save_results(df)