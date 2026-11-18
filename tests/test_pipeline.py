"""Small tests so I know the detector still works after I change something. Run: pytest"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import run_pipeline


def setup_module(module):
    module.scored, module.anomalies, module.admin, module.incidents, module.assets = run_pipeline.run()


def test_theft_meter_is_flagged():
    a = anomalies[(anomalies.meter_id == "M-007") & (anomalies.anomaly_type == "Consumption drop")]
    assert len(a) > 50


def test_voltage_sag_hits_whole_substation():
    v = anomalies[(anomalies.anomaly_type == "Voltage deviation") & (anomalies.substation == "SS-02")]
    assert v.meter_id.nunique() == 15


def test_planned_maintenance_not_flagged():
    row = admin[(admin.target == "GW-02") & (admin.action == "firmware_update")]
    assert not row.flagged.any()


def test_intrusion_is_correlated_and_critical():
    inc = incidents[incidents.substation == "SS-03"]
    assert len(inc) == 1
    assert inc.iloc[0].kind.startswith("Correlated")
    assert inc.iloc[0].severity == "Critical"


def test_no_false_alarms_on_clean_meters():
    clean = anomalies[~anomalies.meter_id.isin(["M-007", "M-033", "M-036", "M-040"]) &
                      (anomalies.substation != "SS-02")]
    assert len(clean) == 0
