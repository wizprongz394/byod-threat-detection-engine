import json
import os
import ast
from datetime import datetime

import pandas as pd


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "results"
)

RESULTS_FILE = "results.csv"

THREAT_REPORT_FILE = (
    "threat_report.json"
)

results_path = os.path.join(
    RESULTS_DIR,
    RESULTS_FILE
)

report_path = os.path.join(
    RESULTS_DIR,
    THREAT_REPORT_FILE
)

os.makedirs(
    RESULTS_DIR,
    exist_ok=True
)


# =========================================================
# LOAD RESULTS
# =========================================================

def load_results():

    if not os.path.exists(
        results_path
    ):

        raise FileNotFoundError(

            f"[ERROR] Results file "
            f"not found:\n{results_path}"
        )

    df = pd.read_csv(
        results_path
    )

    if len(df) == 0:

        raise ValueError(
            "[ERROR] Results file is empty."
        )

    print(
        f"\n[INFO] Results loaded:"
        f" {len(df)} rows"
    )

    return df


# =========================================================
# SAFE BEHAVIOR PARSER
# =========================================================

def parse_behavior_summary(value):

    # -----------------------------------------------------
    # ALREADY LIST
    # -----------------------------------------------------

    if isinstance(value, list):

        return value

    # -----------------------------------------------------
    # MISSING VALUE
    # -----------------------------------------------------

    if pd.isna(value):

        return [
            "No behavioral explanation available"
        ]

    # -----------------------------------------------------
    # STRINGIFIED LIST
    # -----------------------------------------------------

    try:

        parsed = ast.literal_eval(
            value
        )

        if isinstance(parsed, list):

            return parsed

    except Exception:

        pass

    # -----------------------------------------------------
    # FALLBACK
    # -----------------------------------------------------

    return [str(value)]


# =========================================================
# SAFE NUMERIC PARSER
# =========================================================

def safe_float(value, default=0.0):

    try:

        if pd.isna(value):

            return default

        return float(value)

    except Exception:

        return default


def safe_int(value, default=0):

    try:

        if pd.isna(value):

            return default

        return int(value)

    except Exception:

        return default


# =========================================================
# CONFIDENCE ESTIMATION
# =========================================================

def estimate_confidence(score):

    if score >= 0.85:

        return "HIGH"

    elif score >= 0.50:

        return "MEDIUM"

    else:

        return "LOW"


# =========================================================
# BUILD THREAT OBJECTS
# =========================================================

def build_threat_objects(df):

    threats = []

    for idx, row in df.iterrows():

        # -------------------------------------------------
        # SAFE VALUES
        # -------------------------------------------------

        risk_score = safe_float(
            row.get(
                "risk_score",
                0.0
            )
        )

        prediction = safe_int(
            row.get(
                "prediction",
                0
            )
        )

        behavior_summary = (
            parse_behavior_summary(

                row.get(
                    "behavior_summary",
                    []
                )
            )
        )

        # -------------------------------------------------
        # THREAT OBJECT
        # -------------------------------------------------

        threat = {

            # =============================================
            # NETWORK INTELLIGENCE
            # =============================================

            "source_ip": row.get(
                "source_ip",
                "UNKNOWN"
            ),

            "destination_ip": row.get(
                "destination_ip",
                "UNKNOWN"
            ),

            "source_port": safe_int(
                row.get(
                    "source_port",
                    0
                )
            ),

            "destination_port": safe_int(
                row.get(
                    "destination_port",
                    0
                )
            ),

            "protocol": row.get(
                "protocol",
                "UNKNOWN"
            ),

            # =============================================
            # THREAT INTELLIGENCE
            # =============================================

            "flow_id": int(idx),

            "prediction": prediction,

            "risk_score": round(
                risk_score,
                4
            ),

            "risk_level": row.get(
                "risk_level",
                "UNKNOWN"
            ),

            "anomaly_strength": row.get(

                "anomaly_strength",

                estimate_confidence(
                    risk_score
                )
            ),

            "threat_category": row.get(

                "threat_category",

                "General Behavioral "
                "Anomaly"
            ),

            "policy_action": row.get(

                "policy_action",

                "MONITOR"
            ),

            # =============================================
            # BEHAVIORAL INTELLIGENCE
            # =============================================

            "behavior_summary": (
                behavior_summary
            ),

            "suggested_action": row.get(

                "suggested_action",

                "Further investigation "
                "recommended."
            )
        }

        threats.append(
            threat
        )

    return threats


# =========================================================
# BUILD REPORT
# =========================================================

def build_report(df):

    # -----------------------------------------------------
    # SAFE COUNTS
    # -----------------------------------------------------

    total_flows = int(
        len(df)
    )

    anomalous_flows = int(

        (df["prediction"] == 1)
        .sum()

    ) if "prediction" in df else 0

    normal_flows = int(

        (df["prediction"] == 0)
        .sum()

    ) if "prediction" in df else 0

    high_risk = int(

        (df["risk_level"] == "HIGH")
        .sum()

    ) if "risk_level" in df else 0

    medium_risk = int(

        (df["risk_level"] == "MEDIUM")
        .sum()

    ) if "risk_level" in df else 0

    low_risk = int(

        (df["risk_level"] == "LOW")
        .sum()

    ) if "risk_level" in df else 0

    # -----------------------------------------------------
    # FINAL REPORT
    # -----------------------------------------------------

    report = {

        "metadata": {

            "generated_at": (

                datetime.now()
                .strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            ),

            "total_flows": (
                total_flows
            ),

            "normal_flows": (
                normal_flows
            ),

            "anomalous_flows": (
                anomalous_flows
            ),

            "high_risk_flows": (
                high_risk
            ),

            "medium_risk_flows": (
                medium_risk
            ),

            "low_risk_flows": (
                low_risk
            )
        },

        "threats": (
            build_threat_objects(df)
        )
    }

    return report


# =========================================================
# SAVE REPORT
# =========================================================

def save_report(report):

    # -----------------------------------------------------
    # EXISTING REPORT
    # -----------------------------------------------------

    if os.path.exists(
        report_path
    ):

        with open(
            report_path,
            "r"
        ) as f:

            existing_report = json.load(f)

        existing_threats = (
            existing_report.get(
                "threats",
                []
            )
        )

        new_threats = report.get(
            "threats",
            []
        )

        combined_threats = (

            existing_threats
            +
            new_threats
        )

        report["threats"] = (
            combined_threats
        )

        report["metadata"][
            "total_flows"
        ] = len(
            combined_threats
        )

    # -----------------------------------------------------
    # SAVE UPDATED REPORT
    # -----------------------------------------------------

    with open(
        report_path,
        "w"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    print(
        f"\n[SUCCESS] Threat report updated:"
        f"\n{report_path}"
    )


# =========================================================
# DISPLAY SUMMARY
# =========================================================

def display_summary(report):

    metadata = report[
        "metadata"
    ]

    print(
        "\n=== THREAT REPORT SUMMARY ==="
    )

    print(
        f"\nTotal Flows: "
        f"{metadata['total_flows']}"
    )

    print(
        f"Normal Flows: "
        f"{metadata['normal_flows']}"
    )

    print(
        f"Anomalous Flows: "
        f"{metadata['anomalous_flows']}"
    )

    print(
        f"\nHIGH Risk: "
        f"{metadata['high_risk_flows']}"
    )

    print(
        f"MEDIUM Risk: "
        f"{metadata['medium_risk_flows']}"
    )

    print(
        f"LOW Risk: "
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

    # -----------------------------------------------------
    # LOAD RESULTS
    # -----------------------------------------------------

    df = load_results()

    # -----------------------------------------------------
    # BUILD REPORT
    # -----------------------------------------------------

    report = build_report(
        df
    )

    # -----------------------------------------------------
    # SAVE REPORT
    # -----------------------------------------------------

    save_report(
        report
    )

    # -----------------------------------------------------
    # DISPLAY SUMMARY
    # -----------------------------------------------------

    display_summary(
        report
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()