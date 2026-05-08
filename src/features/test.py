import os
import pandas as pd

dataset_path = os.path.join(
    "results",
    "dataset.csv"
)

if not os.path.exists(dataset_path):
    raise FileNotFoundError(
        f"[ERROR] Dataset not found: {dataset_path}"
    )

df = pd.read_csv(dataset_path)

print("Shape:", df.shape)

print(
    "\nLabel Distribution:\n",
    df["label"].value_counts()
)

print(
    "\nAttack Types:\n",
    df["attack_type"].value_counts()
)

print(
    "\nStats:\n",
    df.describe()
)

print(
    "\nSample:\n",
    df.head(10)
)