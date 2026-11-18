"""
generate_data.py
Creates the synthetic telemetry used by the whole project.

Outputs (in /data):
  assets.csv         - substations, gateways and meters with x,y position for the map
  telemetry.csv      - hourly readings for every meter
  admin_events.csv   - administrative log (logins, config changes, ...)
  ground_truth.csv   - which anomalies I injected (only for checking my own detector)

NOTHING here is real data. Everything is made up with numpy random numbers.
"""
import numpy as np
import pandas as pd

from . import config as cfg


def gauss(x, mu, sigma):
    return np.exp(-((x - mu) ** 2) / (2 * sigma ** 2))


def make_assets():
    """Four substations in a square. Each has one gateway and 15 meters around it."""
    rng = np.random.default_rng(cfg.SEED)
    centres = [(2, 2), (8, 2), (2, 8), (8, 8)]
    rows = []
    meter_no = 1
    for s in range(cfg.N_SUBSTATIONS):
        ss_id = f"SS-0{s + 1}"
        cx, cy = centres[s]
        rows.append(dict(asset_id=ss_id, asset_type="substation", substation=ss_id, x=cx, y=cy))
        rows.append(dict(asset_id=f"GW-0{s + 1}", asset_type="gateway", substation=ss_id,
                         x=cx + 0.5, y=cy + 0.5))
        for _ in range(cfg.METERS_PER_SUBSTATION):
            angle = rng.uniform(0, 2 * np.pi)
            radius = rng.uniform(0.8, 2.2)
            rows.append(dict(asset_id=f"M-{meter_no:03d}", asset_type="meter", substation=ss_id,
                             x=cx + radius * np.cos(angle), y=cy + radius * np.sin(angle)))
            meter_no += 1
    return pd.DataFrame(rows)


def make_telemetry(assets):
    rng = np.random.default_rng(cfg.SEED + 1)
    times = pd.date_range(cfg.START_DATE, periods=cfg.DAYS * 24, freq="h")
    hours = times.hour.values
    # typical household shape: small morning peak, big evening peak
    profile = 0.6 + 0.4 * gauss(hours, 8, 2) + 0.9 * gauss(hours, 19, 2.5)

    meters = assets[assets.asset_type == "meter"]
    frames = []
    for _, m in meters.iterrows():
        base = rng.uniform(0.4, 2.5)  # every house uses a different amount
        n = len(times)
        frames.append(pd.DataFrame({
            "timestamp": times,
            "meter_id": m.asset_id,
            "substation": m.substation,
            "kwh": base * profile * (1 + rng.normal(0, 0.08, n)),
            "voltage": 230 + rng.normal(0, 1.2, n),
            "packets": 20 + rng.normal(0, 2, n),
            "latency_ms": 45 + rng.normal(0, 4, n),
            "firmware": "v2.1",
        }))
    return pd.concat(frames, ignore_index=True)


def inject_telemetry_scenarios(df):
    """Put the 'attacks' / faults into the last 4 days. Returns df and a ground truth list."""
    truth = []
    t = lambda day, hour: pd.Timestamp(cfg.START_DATE) + pd.Timedelta(days=day, hours=hour)

    # Scenario 1: possible meter tampering / energy theft on M-007 (reads ~92% too low)
    mask = (df.meter_id == "M-007") & (df.timestamp >= t(10, 0))
    df.loc[mask, "kwh"] *= 0.08
    truth.append(("S1", "Meter tampering / consumption drop", "M-007", "SS-01", t(10, 0), t(13, 23)))

    # Scenario 2: voltage sag over the whole of SS-02 for 4 hours
    mask = (df.substation == "SS-02") & (df.timestamp >= t(11, 14)) & (df.timestamp <= t(11, 17))
    df.loc[mask, "voltage"] -= 18
    for mid in df[df.substation == "SS-02"].meter_id.unique():
        truth.append(("S2", "Voltage sag on substation", mid, "SS-02", t(11, 14), t(11, 17)))

    # Scenario 3: three meters behind GW-03 start flooding traffic at night
    bad = ["M-033", "M-036", "M-040"]
    mask = df.meter_id.isin(bad) & (df.timestamp >= t(12, 2)) & (df.timestamp <= t(12, 5))
    df.loc[mask, "packets"] *= 12
    df.loc[mask, "latency_ms"] += 180
    for mid in bad:
        truth.append(("S3", "Communication anomaly after admin intrusion", mid, "SS-03", t(12, 2), t(12, 5)))

    return df, truth


def make_admin_events(assets):
    rng = np.random.default_rng(cfg.SEED + 2)
    users = ["op_ravi", "op_meera", "eng_sam"]
    normal_actions = ["login_success", "config_view", "meter_sync", "report_export"]
    gateways = assets[assets.asset_type == "gateway"].asset_id.tolist()
    base = pd.Timestamp(cfg.START_DATE)
    rows = []

    # normal working-hours activity: 3 events per day from the internal network
    for day in range(cfg.DAYS):
        for _ in range(3):
            ts = base + pd.Timedelta(days=day, hours=int(rng.integers(9, 17)),
                                     minutes=int(rng.integers(0, 60)))
            rows.append((ts, rng.choice(users), f"10.0.0.{rng.integers(10, 40)}",
                         rng.choice(normal_actions), rng.choice(gateways), "success"))

    # planned maintenance (should NOT be flagged): firmware update in the day, internal IP
    rows.append((base + pd.Timedelta(days=6, hours=11), "eng_sam", "10.0.0.21",
                 "firmware_update", "GW-02", "success"))

    # ---- Scenario 3: intrusion on GW-03 at night, from an outside address ----
    bad_ip = "203.0.113.45"   # documentation-only IP range, not a real host
    start = base + pd.Timedelta(days=12, hours=1, minutes=48)
    for i in range(6):
        rows.append((start + pd.Timedelta(minutes=2 * i), "svc_backup", bad_ip,
                     "login_failed", "GW-03", "failed"))
    rows.append((start + pd.Timedelta(minutes=15), "svc_backup", bad_ip, "login_success", "GW-03", "success"))
    rows.append((start + pd.Timedelta(minutes=18), "svc_backup", bad_ip, "config_change", "GW-03", "success"))
    rows.append((start + pd.Timedelta(minutes=21), "svc_backup", bad_ip, "create_user", "GW-03", "success"))
    rows.append((start + pd.Timedelta(minutes=24), "svc_backup", bad_ip, "firmware_update", "GW-03", "success"))
    rows.append((start + pd.Timedelta(minutes=27), "svc_backup", bad_ip, "firmware_update", "M-033", "success"))

    # ---- Scenario 4: a failed login attempt on GW-04, nothing else happens ----
    s4 = base + pd.Timedelta(days=13, hours=3, minutes=30)
    for i in range(3):
        rows.append((s4 + pd.Timedelta(minutes=3 * i), "admin", "198.51.100.9",
                     "login_failed", "GW-04", "failed"))

    df = pd.DataFrame(rows, columns=["timestamp", "user", "source_ip", "action", "target", "result"])
    return df.sort_values("timestamp").reset_index(drop=True)


def main():
    cfg.DATA_DIR.mkdir(exist_ok=True)
    assets = make_assets()
    tele = make_telemetry(assets)
    tele, truth = inject_telemetry_scenarios(tele)
    admin = make_admin_events(assets)

    base = pd.Timestamp(cfg.START_DATE)
    truth_df = pd.DataFrame(truth, columns=["scenario", "description", "asset", "substation", "start", "end"])
    extra = pd.DataFrame([
        ("S3", "Intrusion on gateway (admin events)", "GW-03", "SS-03",
         base + pd.Timedelta(days=12, hours=1, minutes=48), base + pd.Timedelta(days=12, hours=2, minutes=15)),
        ("S4", "Failed login attempts only", "GW-04", "SS-04",
         base + pd.Timedelta(days=13, hours=3, minutes=30), base + pd.Timedelta(days=13, hours=3, minutes=36)),
    ], columns=truth_df.columns)
    truth_df = pd.concat([truth_df, extra], ignore_index=True)

    assets.to_csv(cfg.DATA_DIR / "assets.csv", index=False)
    for col in ["kwh", "voltage", "packets", "latency_ms"]:
        tele[col] = tele[col].round(3)
    tele.to_csv(cfg.DATA_DIR / "telemetry.csv", index=False)
    admin.to_csv(cfg.DATA_DIR / "admin_events.csv", index=False)
    truth_df.to_csv(cfg.DATA_DIR / "ground_truth.csv", index=False)
    print(f"Created {len(tele)} telemetry rows, {len(admin)} admin events, {len(assets)} assets")


if __name__ == "__main__":
    main()
