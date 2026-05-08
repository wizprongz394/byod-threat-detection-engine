import pandas as pd


def load_results():

    df = pd.read_csv("results.csv")

    return df


def generate_summary(df):

    print("\n==============================")
    print(" BEHAVIORAL RISK REPORT ")
    print("==============================\n")

    print(f"Total Flows Analysed : {len(df)}")

    print("\nRisk Distribution:")

    print(
        df["risk_level"]
        .value_counts()
    )


def show_high_risk_flows(df):

    high_risk = (
        df[df["risk_level"] == "HIGH"]
        .sort_values(
            by="risk_score",
            ascending=False
        )
    )

    print("\n==============================")
    print(" HIGH RISK FLOWS ")
    print("==============================\n")

    if high_risk.empty:

        print("No HIGH risk flows detected.")
        return

    for idx, row in high_risk.head(10).iterrows():

        print(f"\nFlow Index : {idx}")

        print(
            f"Risk Score : "
            f"{row['risk_score']:.4f}"
        )

        print(
            f"Risk Level : "
            f"{row['risk_level']}"
        )

        print(
            f"Behavior Summary : "
            f"{row['risk_reason']}"
        )

        print(
            f"Suggested Action : "
            f"{row['suggested_action']}"
        )

        print("-" * 50)


def main():

    df = load_results()

    generate_summary(df)

    show_high_risk_flows(df)


if __name__ == "__main__":
    main()