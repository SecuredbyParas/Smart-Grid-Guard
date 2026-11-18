"""
detection.py
Step 2 and 3 of the project:
  - learn a baseline for each meter (what is "normal" for each hour of the day)
  - find abnormal telemetry readings (z-score + IsolationForest as a second opinion)
  - find suspicious admin events (simple scoring rules)
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from . import config as cfg

DEV_COLS = ["kwh_dev", "voltage_dev", "packets_dev", "latency_dev"]


# ------------------------------------------------------------------
# Baseline
# ------------------------------------------------------------------
def baseline_end():
    return pd.Timestamp(cfg.START_DATE) + pd.Timedelta(days=cfg.BASELINE_DAYS)


def add_scores(tele):
    """
    For every reading, compare it with what that SAME meter normally does at that
    SAME hour of day (calculated only from the baseline days), then turn the
    difference into a z-score.
    """
    df = tele.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["hour"] = df["timestamp"].dt.hour

    train = df[df["timestamp"] < baseline_end()]
    hour_avg = (train.groupby(["meter_id", "hour"])[["kwh", "voltage", "packets", "latency_ms"]]
                .mean().add_suffix("_base").reset_index())
    df = df.merge(hour_avg, on=["meter_id", "hour"], how="left")

    # kwh is compared as a ratio (so a drop at night is also visible), others as difference
    df["kwh_dev"] = df["kwh"] / df["kwh_base"] - 1
    df["voltage_dev"] = df["voltage"] - df["voltage_base"]
    df["packets_dev"] = df["packets"] - df["packets_base"]
    df["latency_dev"] = df["latency_ms"] - df["latency_ms_base"]

    # how much does each meter normally wobble? (std in the baseline period only)
    train = df[df["timestamp"] < baseline_end()]
    stds = train.groupby("meter_id")[DEV_COLS].std().add_suffix("_std").reset_index()
    df = df.merge(stds, on="meter_id", how="left")

    # The hourly average comes from only ~10 samples, so the in-sample std is a bit
    # too small for new data. Multiply by sqrt((1+1/n)/(1-1/n)) to compensate.
    n = cfg.BASELINE_DAYS
    fix = np.sqrt((1 + 1 / n) / (1 - 1 / n))
    for col in DEV_COLS:
        std = (df[col + "_std"] * fix).clip(lower=cfg.STD_FLOOR[col])
        df[col.replace("_dev", "_z")] = df[col] / std
    return df


def isolation_forest_flags(scored):
    """Second opinion: IsolationForest trained on the baseline days only."""
    z_cols = ["kwh_z", "voltage_z", "packets_z", "latency_z"]
    train = scored[scored["timestamp"] < baseline_end()]
    model = IsolationForest(n_estimators=100, contamination=0.005, random_state=cfg.SEED)
    model.fit(train[z_cols])
    scored = scored.copy()
    scored["ml_flag"] = model.predict(scored[z_cols]) == -1
    return scored


# ------------------------------------------------------------------
# Telemetry anomalies
# ------------------------------------------------------------------
METRIC_INFO = {
    # z column      -> (name shown to user, metric in raw data)
    "kwh_z":     ("Consumption", "kwh"),
    "voltage_z": ("Voltage deviation", "voltage"),
    "packets_z": ("Communication anomaly", "packets"),
    "latency_z": ("Communication anomaly", "latency_ms"),
}


def detect_telemetry(scored, threshold=None):
    """Return one row per abnormal reading."""
    if threshold is None:
        threshold = cfg.Z_THRESHOLD
    test = scored[scored["timestamp"] >= baseline_end()]
    found = []
    for zcol, (label, raw) in METRIC_INFO.items():
        hit = test[test[zcol].abs() > threshold]
        for _, r in hit.iterrows():
            atype = label
            if zcol == "kwh_z":
                atype = "Consumption drop" if r[zcol] < 0 else "Consumption spike"
            found.append(dict(timestamp=r["timestamp"], meter_id=r["meter_id"],
                              substation=r["substation"], anomaly_type=atype,
                              metric=raw, value=round(r[raw], 2),
                              expected=round(r[raw + "_base"], 2),
                              z_score=round(r[zcol], 1), ml_agrees=bool(r["ml_flag"])))
    cols = ["timestamp", "meter_id", "substation", "anomaly_type", "metric",
            "value", "expected", "z_score", "ml_agrees"]
    out = pd.DataFrame(found, columns=cols)
    return out.sort_values(["timestamp", "meter_id"]).reset_index(drop=True)


# ------------------------------------------------------------------
# Admin events
# ------------------------------------------------------------------
def is_off_hours(hour):
    return hour >= cfg.OFF_HOURS[0] or hour < cfg.OFF_HOURS[1]


def detect_admin(admin, assets):
    """
    Score each admin event with simple rules:
      +2 source IP is not in the internal network
      +1 happened in off hours
      +1 privileged action (firmware, config, new user)
      +2 part of a burst of failed logins by the same user
    Score >= ADMIN_FLAG_SCORE is flagged.
    """
    df = admin.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    sub_of = dict(zip(assets["asset_id"], assets["substation"]))
    df["substation"] = df["target"].map(sub_of)

    df["external_ip"] = ~df["source_ip"].str.startswith(cfg.TRUSTED_IP_PREFIX)
    df["off_hours"] = df["timestamp"].dt.hour.map(is_off_hours)
    df["privileged"] = df["action"].isin(cfg.PRIVILEGED_ACTIONS)

    # failed login burst: count failed logins by same user in the 30 min up to this event
    burst = []
    failed = df[df["action"] == "login_failed"]
    for _, row in df.iterrows():
        window = failed[(failed["user"] == row["user"]) &
                        (failed["timestamp"] <= row["timestamp"]) &
                        (failed["timestamp"] >= row["timestamp"] - pd.Timedelta(minutes=30))]
        burst.append(len(window) >= cfg.FAILED_LOGIN_BURST)
    df["failed_burst"] = burst
    # Only the events right after a burst count too (the attacker finally got in)

    df["risk_score"] = (2 * df["external_ip"] + 1 * df["off_hours"]
                        + 1 * df["privileged"] + 2 * df["failed_burst"])
    df["flagged"] = df["risk_score"] >= cfg.ADMIN_FLAG_SCORE

    def why(r):
        reasons = []
        if r["external_ip"]:
            reasons.append("external IP")
        if r["off_hours"]:
            reasons.append("off-hours")
        if r["privileged"]:
            reasons.append("privileged action")
        if r["failed_burst"]:
            reasons.append("failed-login burst")
        return ", ".join(reasons)
    df["reasons"] = df.apply(why, axis=1)
    return df
