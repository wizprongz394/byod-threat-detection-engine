import json
import os
from datetime import datetime

import pandas as pd


# =========================================================
# CONFIGURATION
# =========================================================

RESULTS_DIR = "../../results"

RESULTS_FILE = "results.csv"
THREAT_REPORT_FILE = "threat_report.json"

results_path = os.path.join(
    RESULTS_DIR,
    RESULTS_FILE
)

report_path = os.path.join(
    RESULTS_DIR,
    THREAT_REPORT_FILE
)


# =========================================================
# LOAD RESULTS
# =========================================================

def load_results():

    if not os.path.exists(results_path):

        raise FileNotFoundError(
            f"[ERROR] Results file not found: {results_path}"
        )

    df = pd.read_csv(results_path)

    return df


# =========================================================
# DETECTION CONFIDENCE
# =========================================================

def estimate_anomaly_strength(score):

    if score >= 0.85:
        return "HIGH"

    elif score >= 0.50:
        return "MEDIUM"

    else:
        return "LOW"


# =========================================================
# THREAT CATEGORY INFERENCE
# =========================================================

def infer_threat_category(behavior_summary):

    joined_summary = " ".join(
        behavior_summary
    ).lower()

    if (
        "burst" in joined_summary
        and "transfer" in joined_summary
    ):

        return "Potential Data Exfiltration"

    elif "timing" in joined_summary:

        return "Possible Beaconing Activity"

    elif "packet size" in joined_summary:

        return "Irregular Traffic Pattern"

    elif "transmission rate" in joined_summary:

        return "Traffic Spike Anomaly"

    else:

        return "General Behavioral Anomaly"


# =========================================================
# POLICY DECISION ENGINE
# =========================================================

def determine_policy_action(risk_level):

    if risk_level == "HIGH":

        return "ALERT"

    elif risk_level == "MEDIUM":

        return "MONITOR"

    else:

        return "IGNORE"


# =========================================================
# BUILD THREAT OBJECTS
# =========================================================

def build_threat_objects(df):

    threats = []

    for idx, row in df.iterrows():

        behavior_summary = (
            row["risk_reason"]
            .split(" | ")
        )

        threat_category = infer_threat_category(
            behavior_summary
        )

        threat = {

            # -------------------------------------------------
            # Flow Identification
            # -------------------------------------------------

            "flow_id": int(idx),

            # -------------------------------------------------
            # Risk Intelligence
            # -------------------------------------------------

            "risk_score": round(
                float(row["risk_score"]),
                4
            ),

            "risk_level": row["risk_level"],

            "anomaly_strength":
                estimate_anomaly_strength(
                    row["risk_score"]
                ),

            "prediction": int(
                row["prediction"]
            ),

            # -------------------------------------------------
            # Threat Interpretation
            # -------------------------------------------------

            "threat_category":
                threat_category,

            "behavior_summary":
                behavior_summary,

            # -------------------------------------------------
            # Policy & Response
            # -------------------------------------------------

            "policy_action":
                determine_policy_action(
                    row["risk_level"]
                ),

            "suggested_action":
                row["suggested_action"]
        }

        threats.append(threat)

    return threats


# =========================================================
# BUILD REPORT METADATA
# =========================================================

def build_metadata(df):

    metadata = {

        "generated_at":

            datetime.now()
            .strftime("%Y-%m-%d %H:%M:%S"),

        "total_flows":

            int(len(df)),

        "high_risk_flows":

            int(
                (df["risk_level"] == "HIGH")
                .sum()
            ),

        "medium_risk_flows":

            int(
                (df["risk_level"] == "MEDIUM")
                .sum()
            ),

        "low_risk_flows":

            int(
                (df["risk_level"] == "LOW")
                .sum()
            ),

        "detected_anomalies":

            int(
                (df["prediction"] == 1)
                .sum()
            )
    }

    return metadata


# =========================================================
# BUILD FINAL REPORT
# =========================================================

def build_report(df):

    report = {

        "metadata":
            build_metadata(df),

        "threats":
            build_threat_objects(df)
    }

    return report


# =========================================================
# SAVE REPORT
# =========================================================

def save_report(report):

    with open(report_path, "w") as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print(
        "\n[SUCCESS] Threat intelligence "
        f"report saved:\n{report_path}"
    )


# =========================================================
# DISPLAY SUMMARY
# =========================================================

def display_summary(report):

    metadata = report["metadata"]

    print("\n==============================")
    print(" THREAT INTELLIGENCE SUMMARY ")
    print("==============================")

    print(
        f"\nGenerated At : "
        f"{metadata['generated_at']}"
    )

    print(
        f"Total Flows : "
        f"{metadata['total_flows']}"
    )

    print(
        f"Detected Anomalies : "
        f"{metadata['detected_anomalies']}"
    )

    print(
        f"HIGH Risk Flows : "
        f"{metadata['high_risk_flows']}"
    )

    print(
        f"MEDIUM Risk Flows : "
        f"{metadata['medium_risk_flows']}"
    )

    print(
        f"LOW Risk Flows : "
        f"{metadata['low_risk_flows']}"
    )


# =========================================================
# MAIN
# =========================================================

def main():

    print(
        "\n=== GENERATING THREAT "
        "INTELLIGENCE REPORT ==="
    )

    df = load_results()

    report = build_report(df)

    save_report(report)

    display_summary(report)


if __name__ == "__main__":
    main()