import json

import pytest

from qcsd_lab.capture_acceptance_policy import (
    FIELD, POLICY, buflo_incoming_release_window, incoming_release_window_from_policy,
    validate_buflo_preparation_policy, validate_buflo_source_binding,
)
from qcsd_lab.fidelity import _buflo_schedule_release_window, _incoming_credit_release_metrics


def marker():
    return {"schema_version": 1, "source": "bound-preparation-v1", "policy": POLICY,
            "incoming_release_window_us": 10_000, "period_us": 20_000,
            "cell_bytes": 1_200, "scientific_credit": False}


def run():
    return {"defense_start_monotonic_ns": 1_000_000,
            "primary_document_identity_policy": "variable-primary-document-body-v1",
            "application_response_policy": "completed-terminal-http-errors-v1",
            "defense_parameters": {"kind": "buflo"}, FIELD: marker()}


def prepared():
    return {"preparation": {FIELD: POLICY,
        "primary_document_identity_policy": "variable-primary-document-body-v1",
        "application_response_policy": "completed-terminal-http-errors-v1"}}


@pytest.mark.parametrize("delay_us,old_violations,new_violations", [
    (4999, 0, 0), (5000, 1, 0), (6099, 1, 0), (9999, 1, 0), (10000, 1, 1), (20000, 1, 1),
])
def test_explicit_incoming_window_preserves_old_measurements_and_half_open_boundaries(
    tmp_path, delay_us, old_violations, new_violations,
):
    path = tmp_path / "schedule.csv"
    rows = [{"direction": "incoming", "satisfaction": "satisfied", "target_time_us": "20000",
             "credit_advertised_at_us": str(1000 + 20000 + delay_us)}]
    (tmp_path / "run.json").write_text(json.dumps(run()))
    current = _incoming_credit_release_metrics(path, rows)
    assert current["incoming_credit_release_window_violations"] == new_violations
    assert current["incoming_credit_release_original_5000us_violations"] == old_violations
    assert current["incoming_credit_release_lateness_upper_bound_us_max"] == delay_us
    assert _buflo_schedule_release_window(current) == 10000
    legacy = run()
    legacy.pop(FIELD)
    (tmp_path / "run.json").write_text(json.dumps(legacy))
    old = _incoming_credit_release_metrics(path, rows)
    assert old["incoming_credit_release_window_violations"] == old_violations
    assert "incoming_credit_release_policy" not in old
    assert _buflo_schedule_release_window(old) == 5000


def test_pre_tick_credit_and_missing_timestamp_remain_failures(tmp_path):
    path = tmp_path / "schedule.csv"
    (tmp_path / "run.json").write_text(json.dumps(run()))
    metrics = _incoming_credit_release_metrics(path, [
        {"direction": "incoming", "satisfaction": "satisfied", "target_time_us": "20000",
         "credit_advertised_at_us": "20999"},
        {"direction": "incoming", "satisfaction": "satisfied", "target_time_us": "40000"},
    ])
    assert metrics["incoming_credit_release_window_violations"] == 2
    assert metrics["incoming_credit_release_original_5000us_violations"] == 2


@pytest.mark.parametrize("key,bad", [
    ("schema_version", True), ("incoming_release_window_us", 20000),
    ("period_us", 10000), ("cell_bytes", 600), ("scientific_credit", True),
    ("source", "unbound"), ("policy", "future-unknown"),
])
def test_unknown_or_widened_native_policy_is_rejected(key, bad):
    value = marker()
    value[key] = bad
    with pytest.raises(ValueError, match="invalid BufLO"):
        incoming_release_window_from_policy(value)


@pytest.mark.parametrize("value", [None, "", "unknown", True, {}])
def test_present_null_or_unknown_preparation_flag_is_not_legacy(value):
    source = prepared()["preparation"]
    source[FIELD] = value
    with pytest.raises(ValueError, match="explicit rapid"):
        validate_buflo_preparation_policy(source)


def test_native_policy_must_match_frozen_source_and_mode():
    validate_buflo_source_binding(prepared(), run())
    validate_buflo_source_binding({}, {})
    with pytest.raises(ValueError, match="matching prepared source"):
        validate_buflo_source_binding({}, run())
    native = run()
    native.pop(FIELD)
    with pytest.raises(ValueError, match="lacks its native"):
        validate_buflo_source_binding(prepared(), native)
    native = run()
    native["defense_parameters"]["kind"] = "tamaraw"
    with pytest.raises(ValueError, match="native rapid contract"):
        buflo_incoming_release_window(native)
    native.pop(FIELD)
    validate_buflo_source_binding(prepared(), native)


def test_changed_or_unbound_metric_window_cannot_change_admission():
    with pytest.raises(ValueError, match="lacks its explicit policy"):
        _buflo_schedule_release_window({"incoming_credit_release_window_us": 10000})
    metrics = {"incoming_credit_release_policy": marker(), "incoming_credit_release_window_us": 10000,
               "incoming_credit_release_original_5000us_violations": 2}
    assert _buflo_schedule_release_window(metrics) == 10000
    metrics["incoming_credit_release_window_us"] = 20000
    with pytest.raises(ValueError, match="differ from their policy"):
        _buflo_schedule_release_window(metrics)
