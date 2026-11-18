# Smart Grid Threat Monitoring - Incident Report

> **SIMULATED DATA ONLY. This project does not connect to any real smart meter, utility network or SCADA system.**

## 1. Summary

- Analysis period: 2026-11-02 for 14 days (first 10 days used as baseline)
- Abnormal telemetry readings found: **180**
- Suspicious admin events flagged: **14** out of 57
- Incidents after correlation: **4**
- By severity: High: 2, Critical: 1, Low: 1

| ID | Severity | Type | Substation | Start | End | Assets |
|----|----------|------|-----------|-------|-----|--------|
| INC-001 | Critical | Correlated (telemetry + admin) | SS-03 | 2026-11-14 02:00 | 2026-11-14 05:00 | M-033, M-036, M-040, GW-03 |
| INC-002 | High | Telemetry only | SS-02 | 2026-11-13 14:00 | 2026-11-13 17:00 | M-016, M-017, M-018, M-019, M-020, M-021, M-022, M-023, M-024, M-025, M-026, M-027, M-028, M-029, M-030 |
| INC-003 | High | Telemetry only | SS-01 | 2026-11-12 00:00 | 2026-11-15 23:00 | M-007 |
| INC-004 | Low | Admin activity only | SS-04 | 2026-11-15 03:30 | 2026-11-15 03:36 | GW-04 |

## 2. Incident details

### INC-001 - Critical - Communication anomaly

- **Location:** SS-03
- **Time window:** 2026-11-14 02:00 to 2026-11-14 05:00
- **Category:** Correlated (telemetry + admin)
- **Affected assets:** M-033, M-036, M-040, GW-03
- **Abnormal readings:** 24  |  **Admin alerts:** 11
- **Admin account(s):** svc_backup  |  **Source IP(s):** 203.0.113.45
- **Investigation recommendation:** Treat as possible cyber incident: contain the gateway first, then roll back firmware/config to a known good state and preserve logs. Isolate the affected meters from the network, capture traffic, and check the gateway they report to.

### INC-002 - High - Voltage deviation

- **Location:** SS-02
- **Time window:** 2026-11-13 14:00 to 2026-11-13 17:00
- **Category:** Telemetry only
- **Affected assets:** M-016, M-017, M-018, M-019, M-020, M-021, M-022, M-023, M-024, M-025, M-026, M-027, M-028, M-029, M-030
- **Abnormal readings:** 60  |  **Admin alerts:** 0
- **Investigation recommendation:** Check transformer tap settings and feeder load. If many meters are affected, treat as grid fault, not meter fault.

### INC-003 - High - Consumption drop

- **Location:** SS-01
- **Time window:** 2026-11-12 00:00 to 2026-11-15 23:00
- **Category:** Telemetry only
- **Affected assets:** M-007
- **Abnormal readings:** 96  |  **Admin alerts:** 0
- **Investigation recommendation:** Send a technician to inspect meter seals / bypass. Compare with the feeder total to confirm loss.

### INC-004 - Low - Suspicious administrative activity

- **Location:** SS-04
- **Time window:** 2026-11-15 03:30 to 2026-11-15 03:36
- **Category:** Admin activity only
- **Affected assets:** GW-04
- **Abnormal readings:** 0  |  **Admin alerts:** 3
- **Admin account(s):** admin  |  **Source IP(s):** 198.51.100.9
- **Investigation recommendation:** Review the account used, reset its credentials, block the source IP, and verify gateway configuration and firmware against the approved version.

## 3. Limitations

- All data is synthetic, so detection quality on real grids is unknown.
- The baseline assumes the first days are clean. Real data may already contain attacks.
- Fixed thresholds can raise false alarms around holidays, weather changes or new customers.
- Severity scores are a simple hand-made formula, not a validated risk model.
