"""Finite original-counter controls; no packets, timing waiver or author execution."""
from copy import deepcopy
import pytest
from qcsd_lab import buflo_handoff as handoff

def fixture():
    rows=[]
    for kind,late in (("full",7),("partial",11),("suppressed",19),("missed",999)):
        row={"direction":"outgoing","satisfaction":kind,"desired_udp_bytes":"600",
             "observed_udp_bytes":"600" if kind=="full" else "300" if kind=="partial" else "0",
             "lateness_us":str(late)}
        row.update({field:"0" for field in handoff._COMPOSITION_FIELDS});rows.append(row)
    d={"cs_buflo_scheduled_outgoing_cells":4,"cs_buflo_scheduled_incoming_cells":0,
       "cs_buflo_full_outgoing_cells":1,"cs_buflo_partial_outgoing_cells":1,
       "cs_buflo_suppressed_outgoing_cells":1,"cs_buflo_missed_outgoing_cells":1,
       "cs_buflo_missed_incoming_cells":0,"cs_buflo_desired_udp_bytes":2400,
       "cs_buflo_realized_udp_bytes":900,"cs_buflo_realized_incoming_credit_bytes":0,
       "cs_buflo_lateness_us_total":37,"cs_buflo_lateness_us_max":19}
    d.update({"cs_buflo_"+field:0 for field in handoff._COMPOSITION_FIELDS})
    return d,rows

def test_suppressed_lateness_counted_but_missed_lateness_not_counted():
    d,rows=fixture();handoff._validate_candidate_schedule_diagnostic_counts(d,rows,runtime_kind="cs_buflo")

@pytest.mark.parametrize("field,value",[("cs_buflo_lateness_us_total",18),("cs_buflo_lateness_us_max",11),
    ("cs_buflo_lateness_us_total",1036),("cs_buflo_realized_udp_bytes",901)])
def test_other_counter_mismatch_still_refuses(field,value):
    d,rows=fixture();d[field]=value
    with pytest.raises(ValueError,match="composition differs"):
        handoff._validate_candidate_schedule_diagnostic_counts(d,rows,runtime_kind="cs_buflo")

def test_lateness_integer_precision_keeps_uint64():
    d,rows=fixture();late=(1<<63)+29;rows[2]["lateness_us"]=str(late)
    d["cs_buflo_lateness_us_total"]=late+18;d["cs_buflo_lateness_us_max"]=late
    handoff._validate_candidate_schedule_diagnostic_counts(d,rows,runtime_kind="cs_buflo")

def test_original_partial_evidence_callback_still_required(monkeypatch,tmp_path):
    from qcsd_lab import capture_acceptance_policy as policy
    d,rows=fixture();calls=[]
    def refused(run,*,runner_directory,schedule_rows):
        calls.append((run,runner_directory,schedule_rows));raise ValueError("original partial guard refused")
    monkeypatch.setattr(policy,"validate_terminal_primary_partial_evidence",refused)
    with pytest.raises(ValueError,match="original partial guard refused"):
        handoff._validate_candidate_schedule_diagnostic_counts(d,rows,runtime_kind="cs_buflo",run={"fixture":True},runner_directory=tmp_path)
    assert len(calls)==1 and calls[0][1]==tmp_path and calls[0][2]==rows
