import pandas as pd
from sklearn.ensemble import IsolationForest

# 🔹 Load dataset
df = pd.read_csv("../features/dataset.csv")
# 🔹 Drop non-numeric columns
X = df.drop(columns=["label", "attack_type"])

# 🔹 Train model
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(X)

# 🔹 Predict anomalies
df["prediction"] = model.predict(X)

# Convert:
#  1 → normal
# -1 → anomaly
df["prediction"] = df["prediction"].map({1: 0, -1: 1})

# 🔹 Compare results
print("\n=== RESULTS ===")
print(pd.crosstab(df["label"], df["prediction"]))

# 🔹 Save output
df.to_csv("results.csv", index=False)

print("\n[SUCCESS] Results saved to results.csv")