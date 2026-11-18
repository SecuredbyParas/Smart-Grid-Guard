"""
config.py
All the settings for the project are kept here so I don't have to hunt for
magic numbers in different files.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"

SEED = 42

# ---- synthetic grid size ----
START_DATE = "2026-11-02"      # a Monday
DAYS = 14                      # total days of telemetry
BASELINE_DAYS = 10             # first 10 days are "normal", used to learn baseline
N_SUBSTATIONS = 4
METERS_PER_SUBSTATION = 15     # 60 smart meters total

# ---- detection settings ----
Z_THRESHOLD = 5.0              # |z| above this = abnormal reading (4.0 gave a few false alarms)
INCIDENT_GAP_HOURS = 3         # anomalies closer than this are merged in one incident
ADMIN_WINDOW_HOURS = 3         # how close an admin alert must be to a telemetry anomaly

# minimum std values so that a very stable meter doesn't give crazy z-scores
STD_FLOOR = {
    "kwh_dev": 0.03,       # kwh is compared as a ratio to its normal value
    "voltage_dev": 0.5,
    "packets_dev": 1.0,
    "latency_dev": 2.0,
}

# ---- admin activity rules ----
TRUSTED_IP_PREFIX = "10."      # internal network
OFF_HOURS = (22, 6)            # 22:00 - 06:00 counts as off hours
PRIVILEGED_ACTIONS = {"firmware_update", "config_change", "create_user"}
FAILED_LOGIN_BURST = 5         # failed logins in 30 min -> suspicious
ADMIN_FLAG_SCORE = 3

DISCLAIMER = (
    "SIMULATED DATA ONLY. This project does not connect to any real smart "
    "meter, utility network or SCADA system."
)
