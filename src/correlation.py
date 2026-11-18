"""
correlation.py
Step 4: correlate events across devices and locations.

Idea:
  1. group abnormal readings by substation (location) and by time -> telemetry incidents
  2. attach flagged admin events that happened in the same substation close in time
  3. admin alerts with no matching telemetry become their own (lower) incidents
  4. give each incident a severity score and an investigation recommendation
"""
import pandas as pd

from . import config as cfg

RECOMMENDATIONS = {
    "Consumption drop": "Send a technician to inspect meter seals / bypass. Compare with the feeder total to confirm loss.",
    "Consumption spike": "Check for faulty meter or unusual load. Validate against feeder measurements.",
    "Voltage deviation": "Check transformer tap settings and feeder load. If many meters are affected, treat as grid fault, not meter fault.",
    "Communication anomaly": "Isolate the affected meters from the network, capture traffic, and check the gateway they report to.",
}
ADMIN_RECOMMENDATION = ("Review the account used, reset its credentials, block the source IP, "
                        "and verify gateway configuration and firmware against the approved version.")
CORRELATED_RECOMMENDATION = ("Treat as possible cyber incident: contain the gateway first, "
                             "then roll back firmware/config to a known good state and preserve logs.")


def _group_in_time(times, gap_hours):
    """Take a sorted list of timestamps, return a group number for each (new group after a gap)."""
    groups, current, last = [], 0, None
    for t in times:
        if last is not None and (t - last) > pd.Timedelta(hours=gap_hours):
            current += 1
        groups.append(current)
        last = t
    return groups


def severity_level(score):
    if score >= 12:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def build_incidents(anomalies, admin_scored):
    flagged_admin = admin_scored[admin_scored["flagged"]].copy()
    incidents = []

    # ---- 1. telemetry incidents ----
    used_admin = set()
    for sub, grp in anomalies.groupby("substation"):
        grp = grp.sort_values("timestamp")
        grp = grp.assign(g=_group_in_time(list(grp["timestamp"]), cfg.INCIDENT_GAP_HOURS))
        for _, g in grp.groupby("g"):
            start, end = g["timestamp"].min(), g["timestamp"].max()
            window = pd.Timedelta(hours=cfg.ADMIN_WINDOW_HOURS)
            adm = flagged_admin[(flagged_admin["substation"] == sub) &
                                (flagged_admin["timestamp"] >= start - window) &
                                (flagged_admin["timestamp"] <= end + window)]
            used_admin.update(adm.index)

            types = sorted(g["anomaly_type"].unique())
            meters = sorted(g["meter_id"].unique())
            hours = (end - start).total_seconds() / 3600 + 1

            score = min(len(meters), 5) + 2 * len(types) + min(hours / 24, 4)
            if len(adm) > 0:
                score += 5                      # telemetry + admin = correlated
                if adm["privileged"].any():
                    score += 3
            kind = "Correlated (telemetry + admin)" if len(adm) else "Telemetry only"
            incidents.append(dict(
                substation=sub, start=start, end=end, kind=kind,
                anomaly_types=", ".join(types), n_meters=len(meters),
                affected_assets=", ".join(meters + [t for t in sorted(adm["target"].unique()) if t not in meters]),
                n_anomalies=len(g), n_admin_alerts=len(adm),
                admin_users=", ".join(sorted(adm["user"].unique())) if len(adm) else "",
                admin_ips=", ".join(sorted(adm["source_ip"].unique())) if len(adm) else "",
                score=round(score, 1),
                recommendation=(CORRELATED_RECOMMENDATION + " " if len(adm) else "")
                               + " ".join(RECOMMENDATIONS[t] for t in types if t in RECOMMENDATIONS),
            ))

    # ---- 2. admin-only incidents ----
    rest = flagged_admin[~flagged_admin.index.isin(used_admin)]
    for sub, grp in rest.groupby("substation"):
        grp = grp.sort_values("timestamp")
        grp = grp.assign(g=_group_in_time(list(grp["timestamp"]), cfg.INCIDENT_GAP_HOURS))
        for _, g in grp.groupby("g"):
            score = 2 + (3 if g["privileged"].any() else 0)
            incidents.append(dict(
                substation=sub, start=g["timestamp"].min(), end=g["timestamp"].max(),
                kind="Admin activity only", anomaly_types="Suspicious administrative activity",
                n_meters=0, affected_assets=", ".join(sorted(g["target"].unique())),
                n_anomalies=0, n_admin_alerts=len(g),
                admin_users=", ".join(sorted(g["user"].unique())),
                admin_ips=", ".join(sorted(g["source_ip"].unique())),
                score=score, recommendation=ADMIN_RECOMMENDATION))

    cols = ["incident_id", "severity", "score", "kind", "substation", "start", "end",
            "anomaly_types", "n_meters", "n_anomalies", "n_admin_alerts",
            "affected_assets", "admin_users", "admin_ips", "recommendation"]
    if not incidents:
        return pd.DataFrame(columns=cols)

    inc = pd.DataFrame(incidents).sort_values("score", ascending=False).reset_index(drop=True)
    inc["severity"] = inc["score"].map(severity_level)
    inc["incident_id"] = [f"INC-{i + 1:03d}" for i in range(len(inc))]
    return inc[cols]


def asset_status(assets, incidents):
    """Colour code for the asset map: affected / same-substation-as-incident / normal."""
    status = {a: "Normal" for a in assets["asset_id"]}
    for _, inc in incidents.iterrows():
        for a in assets[assets["substation"] == inc["substation"]]["asset_id"]:
            if status[a] == "Normal":
                status[a] = "In affected substation"
        for a in str(inc["affected_assets"]).split(", "):
            if a in status:
                status[a] = "Affected"
    out = assets.copy()
    out["status"] = out["asset_id"].map(status)
    return out
