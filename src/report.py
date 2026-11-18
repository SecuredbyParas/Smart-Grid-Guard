"""
report.py
Writes the incident report as a markdown file.
"""
import pandas as pd
from . import config as cfg


def make_report(incidents, anomalies, admin_scored):
    lines = []
    lines.append("# Smart Grid Threat Monitoring - Incident Report")
    lines.append("")
    lines.append(f"> **{cfg.DISCLAIMER}**")
    lines.append("")
    lines.append("## 1. Summary")
    lines.append("")
    lines.append(f"- Analysis period: {cfg.START_DATE} for {cfg.DAYS} days "
                 f"(first {cfg.BASELINE_DAYS} days used as baseline)")
    lines.append(f"- Abnormal telemetry readings found: **{len(anomalies)}**")
    lines.append(f"- Suspicious admin events flagged: **{int(admin_scored['flagged'].sum())}** "
                 f"out of {len(admin_scored)}")
    lines.append(f"- Incidents after correlation: **{len(incidents)}**")
    if len(incidents):
        counts = incidents["severity"].value_counts()
        lines.append("- By severity: " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    lines.append("")
    lines.append("| ID | Severity | Type | Substation | Start | End | Assets |")
    lines.append("|----|----------|------|-----------|-------|-----|--------|")
    for _, r in incidents.iterrows():
        lines.append(f"| {r.incident_id} | {r.severity} | {r.kind} | {r.substation} | "
                     f"{r.start:%Y-%m-%d %H:%M} | {r.end:%Y-%m-%d %H:%M} | {r.affected_assets} |")
    lines.append("")
    lines.append("## 2. Incident details")
    for _, r in incidents.iterrows():
        lines.append("")
        lines.append(f"### {r.incident_id} - {r.severity} - {r.anomaly_types}")
        lines.append("")
        lines.append(f"- **Location:** {r.substation}")
        lines.append(f"- **Time window:** {r.start:%Y-%m-%d %H:%M} to {r.end:%Y-%m-%d %H:%M}")
        lines.append(f"- **Category:** {r.kind}")
        lines.append(f"- **Affected assets:** {r.affected_assets}")
        lines.append(f"- **Abnormal readings:** {r.n_anomalies}  |  **Admin alerts:** {r.n_admin_alerts}")
        if r.admin_users:
            lines.append(f"- **Admin account(s):** {r.admin_users}  |  **Source IP(s):** {r.admin_ips}")
        lines.append(f"- **Investigation recommendation:** {r.recommendation}")

    lines.append("")
    lines.append("## 3. Limitations")
    lines.append("")
    lines.append("- All data is synthetic, so detection quality on real grids is unknown.")
    lines.append("- The baseline assumes the first days are clean. Real data may already contain attacks.")
    lines.append("- Fixed thresholds can raise false alarms around holidays, weather changes or new customers.")
    lines.append("- Severity scores are a simple hand-made formula, not a validated risk model.")
    lines.append("")
    return "\n".join(lines)


def save_report(incidents, anomalies, admin_scored):
    cfg.REPORT_DIR.mkdir(exist_ok=True)
    path = cfg.REPORT_DIR / "incident_report.md"
    path.write_text(make_report(incidents, anomalies, admin_scored), encoding="utf-8")
    return path
