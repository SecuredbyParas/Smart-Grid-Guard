"""
run_pipeline.py
Runs everything from the command line (no dashboard):
    python run_pipeline.py
"""
import pandas as pd

from src import config as cfg
from src import generate_data, detection, correlation, report


def load_data():
    if not (cfg.DATA_DIR / "telemetry.csv").exists():
        generate_data.main()
    tele = pd.read_csv(cfg.DATA_DIR / "telemetry.csv", parse_dates=["timestamp"])
    admin = pd.read_csv(cfg.DATA_DIR / "admin_events.csv", parse_dates=["timestamp"])
    assets = pd.read_csv(cfg.DATA_DIR / "assets.csv")
    return tele, admin, assets


def run(threshold=None):
    tele, admin, assets = load_data()
    scored = detection.add_scores(tele)
    scored = detection.isolation_forest_flags(scored)
    anomalies = detection.detect_telemetry(scored, threshold)
    admin_scored = detection.detect_admin(admin, assets)
    incidents = correlation.build_incidents(anomalies, admin_scored)
    return scored, anomalies, admin_scored, incidents, assets


def check_against_ground_truth(anomalies, incidents):
    """Did the detector find the scenarios I injected?"""
    truth = pd.read_csv(cfg.DATA_DIR / "ground_truth.csv", parse_dates=["start", "end"])
    print("\nChecking against injected scenarios:")
    for sc, grp in truth.groupby("scenario"):
        row = grp.iloc[0]
        found = incidents[(incidents["substation"] == row["substation"]) &
                          (incidents["end"] >= grp["start"].min()) &
                          (incidents["start"] <= grp["end"].max() + pd.Timedelta(hours=3))]
        status = "FOUND" if len(found) else "MISSED"
        print(f"  {sc}: {row['description']:<45} {status} {list(found['incident_id'])}")

    # false positives: anomalies not near any injected meter-event
    tele_truth = truth[truth["asset"].str.startswith("M-")]
    fp = 0
    for _, a in anomalies.iterrows():
        ok = ((tele_truth["asset"] == a["meter_id"]) & (tele_truth["start"] <= a["timestamp"]) &
              (tele_truth["end"] >= a["timestamp"])).any()
        fp += (not ok)
    print(f"  Abnormal readings outside injected scenarios (false alarms): {fp} "
          f"of {len(anomalies)}")


if __name__ == "__main__":
    scored, anomalies, admin_scored, incidents, assets = run()
    print(f"Anomalies: {len(anomalies)} | flagged admin events: {admin_scored['flagged'].sum()}")
    print(incidents[["incident_id", "severity", "kind", "substation", "start", "end", "affected_assets"]]
          .to_string(index=False))
    check_against_ground_truth(anomalies, incidents)
    path = report.save_report(incidents, anomalies, admin_scored)
    print(f"\nReport saved to {path}")
