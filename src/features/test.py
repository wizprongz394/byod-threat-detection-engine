import pandas as pd

df = pd.read_csv("dataset.csv")

print("Shape:", df.shape)
print("\nLabel Distribution:\n", df["label"].value_counts())
print("\nAttack Types:\n", df["attack_type"].value_counts())
print("\nStats:\n", df.describe())
print("\nSample:\n", df.head(10))