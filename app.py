"""
app.py - Smart Power Grid Threat Monitoring dashboard
Run with:  streamlit run app.py
"""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import run_pipeline
from src import config as cfg
from src import correlation, report

st.set_page_config(page_title="Smart Grid Threat Monitor", layout="wide")

SEVERITY_COLOURS = {"Critical": "#b3261e", "High": "#e8710a", "Medium": "#d9a400", "Low": "#5f6b7a"}
STATUS_COLOURS = {"Normal": "#2e9e6b", "In affected substation": "#e8a317", "Affected": "#c62828"}


@st.cache_data(show_spinner="Running detection...")
def get_results(threshold):
    scored, anomalies, admin_scored, incidents, assets = run_pipeline.run(threshold)
    return scored, anomalies, admin_scored, incidents, assets


# ---------------- sidebar ----------------
st.sidebar.title("Controls")
threshold = st.sidebar.slider("Anomaly threshold (z-score)", 3.0, 8.0, float(cfg.Z_THRESHOLD), 0.5,
                              help="Lower = more sensitive but more false alarms.")
scored, anomalies, admin_scored, incidents, assets = get_results(threshold)
st.sidebar.markdown("---")
st.sidebar.info(cfg.DISCLAIMER)

# ---------------- header ----------------
st.title("Smart Power Grid Threat Monitoring")
st.caption("Synthetic telemetry from 60 smart meters, 4 gateways and 4 substations. " + cfg.DISCLAIMER)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Meters monitored", int((assets.asset_type == "meter").sum()))
c2.metric("Abnormal readings", len(anomalies))
c3.metric("Suspicious admin events", int(admin_scored["flagged"].sum()))
c4.metric("Incidents", len(incidents))

tab_over, tab_tele, tab_admin, tab_inc, tab_map, tab_rep, tab_about = st.tabs(
    ["Overview", "Telemetry", "Admin events", "Incidents", "Asset map", "Report", "About"])

# ---------------- overview ----------------
with tab_over:
    st.subheader("Abnormal readings over time")
    if len(anomalies):
        per_hour = anomalies.groupby([pd.Grouper(key="timestamp", freq="h"), "anomaly_type"]).size() \
                            .reset_index(name="count")
        fig = px.bar(per_hour, x="timestamp", y="count", color="anomaly_type",
                     labels={"timestamp": "Time", "count": "Abnormal readings", "anomaly_type": "Type"})
        st.plotly_chart(fig, width="stretch")
    else:
        st.success("No abnormal readings at this threshold.")

    st.subheader("Incidents by severity")
    if len(incidents):
        cols = st.columns(len(incidents))
        for col, (_, r) in zip(cols, incidents.iterrows()):
            col.markdown(f"**{r.incident_id}** - {r.severity}")
            col.caption(f"{r.substation}, {r.start:%d %b %H:%M}")
            col.write(r.anomaly_types)

# ---------------- telemetry ----------------
with tab_tele:
    st.subheader("Meter telemetry vs. baseline")
    left, right = st.columns(2)
    meter = left.selectbox("Meter", sorted(scored["meter_id"].unique()),
                           index=sorted(scored["meter_id"].unique()).index("M-033"))
    metric = right.selectbox("Metric", ["kwh", "voltage", "packets", "latency_ms"])
    m = scored[scored["meter_id"] == meter]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=m["timestamp"], y=m[metric], mode="lines", name="Actual"))
    fig.add_trace(go.Scatter(x=m["timestamp"], y=m[metric + "_base"], mode="lines",
                             name="Baseline (normal for this hour)", line=dict(dash="dot")))
    hits = anomalies[(anomalies["meter_id"] == meter) & (anomalies["metric"] == metric)]
    if len(hits):
        fig.add_trace(go.Scatter(x=hits["timestamp"], y=hits["value"], mode="markers", name="Flagged",
                                 marker=dict(color="red", size=8)))
    fig.add_vline(x=run_pipeline.detection.baseline_end(), line_dash="dash", line_color="grey",
                  annotation_text="end of baseline")
    st.plotly_chart(fig, width="stretch")

    st.subheader("All abnormal readings")
    st.dataframe(anomalies, width="stretch", hide_index=True)

# ---------------- admin ----------------
with tab_admin:
    st.subheader("Administrative events")
    only_flagged = st.checkbox("Show only flagged events", value=True)
    view = admin_scored[admin_scored["flagged"]] if only_flagged else admin_scored
    st.dataframe(view[["timestamp", "user", "source_ip", "action", "target", "substation",
                       "result", "risk_score", "flagged", "reasons"]],
                 width="stretch", hide_index=True)
    st.caption("Risk score: +2 external IP, +1 off-hours, +1 privileged action, +2 failed-login burst. "
               f"Flagged at {cfg.ADMIN_FLAG_SCORE} or more.")

# ---------------- incidents ----------------
with tab_inc:
    st.subheader("Correlated incidents")
    st.caption("Abnormal readings are grouped by substation and time, then matched with admin alerts "
               "in the same substation within a few hours.")
    for _, r in incidents.iterrows():
        with st.expander(f"{r.incident_id} | {r.severity} | {r.substation} | {r.anomaly_types}"):
            st.write(f"**Type:** {r.kind}")
            st.write(f"**Time:** {r.start:%Y-%m-%d %H:%M} to {r.end:%Y-%m-%d %H:%M}")
            st.write(f"**Affected assets:** {r.affected_assets}")
            if r.admin_users:
                st.write(f"**Admin account:** {r.admin_users} from {r.admin_ips}")
            st.write(f"**Score:** {r.score}")
            st.info(f"Recommendation: {r.recommendation}")
            if r.n_admin_alerts:
                ev = admin_scored[admin_scored["flagged"] & (admin_scored["substation"] == r.substation) &
                                  (admin_scored["timestamp"] >= r.start - pd.Timedelta(hours=cfg.ADMIN_WINDOW_HOURS)) &
                                  (admin_scored["timestamp"] <= r.end + pd.Timedelta(hours=cfg.ADMIN_WINDOW_HOURS))]
                st.dataframe(ev[["timestamp", "user", "source_ip", "action", "target", "reasons"]],
                             hide_index=True, width="stretch")

# ---------------- map ----------------
with tab_map:
    st.subheader("Asset map (schematic)")
    st.caption("Positions are made up for the simulation. Red = part of an incident, "
               "amber = same substation as an incident, green = normal.")
    amap = correlation.asset_status(assets, incidents)
    fig = go.Figure()
    # lines from each meter to its gateway
    gw = amap[amap.asset_type == "gateway"].set_index("substation")
    for _, a in amap[amap.asset_type == "meter"].iterrows():
        g = gw.loc[a.substation]
        fig.add_trace(go.Scatter(x=[a.x, g.x], y=[a.y, g.y], mode="lines", showlegend=False,
                                 line=dict(color="rgba(150,150,150,0.3)", width=1), hoverinfo="skip"))
    symbols = {"meter": "circle", "gateway": "square", "substation": "diamond"}
    sizes = {"meter": 9, "gateway": 14, "substation": 20}
    for status, colour in STATUS_COLOURS.items():
        for atype in ["meter", "gateway", "substation"]:
            d = amap[(amap.status == status) & (amap.asset_type == atype)]
            if len(d):
                fig.add_trace(go.Scatter(x=d.x, y=d.y, mode="markers", name=f"{status} ({atype})",
                                         text=d.asset_id, hovertemplate="%{text}<extra></extra>",
                                         marker=dict(color=colour, size=sizes[atype], symbol=symbols[atype],
                                                     line=dict(width=1, color="white"))))
    fig.update_layout(height=620, xaxis=dict(visible=False), yaxis=dict(visible=False, scaleanchor="x"))
    st.plotly_chart(fig, width="stretch")

# ---------------- report ----------------
with tab_rep:
    text = report.make_report(incidents, anomalies, admin_scored)
    st.download_button("Download incident report (.md)", text, file_name="incident_report.md")
    st.markdown(text)

# ---------------- about ----------------
with tab_about:
    st.subheader("How it works")
    st.markdown("""
1. **Ingest** - hourly smart-meter readings (kWh, voltage, packets, latency) and an admin event log.
2. **Baseline** - first 10 days give each meter a normal value for every hour of the day.
3. **Detect** - z-score on each reading, plus an IsolationForest as a second opinion.
   Admin events are scored with simple rules.
4. **Correlate** - group by substation and time, then link admin alerts to telemetry anomalies.
5. **Visualise** - this dashboard, the asset map and the incident report.
""")
    st.subheader("Limitations")
    st.markdown(open(cfg.ROOT / "docs" / "limitations.md", encoding="utf-8").read())
