"""A clock retry discards failed evidence; it does not increase tolerance."""
from copy import deepcopy
import pytest
from qcsd_lab.resource_study import temporary_clock_failure

BASE = {"success": False, "resource_error": None, "runner_complete": True,
        "runner_binding_valid": True, "scheduler_runtime_evidence_valid": True,
        "runner_returncode": 0, "failure": {"stage": "capture", "details": [
        {"reason": "direct/runner reconciliation failed: direct/runner timestamp mismatch in clock epoch 0: 23569001ns exceeds 10000000ns"}]}}

def test_verified_clock_disturbance_is_retryable_without_credit():
    assert temporary_clock_failure(BASE)

def test_wrapper_clock_disturbance_is_also_discarded_and_retryable():
    value_map = deepcopy(BASE)
    value_map["failure"]["details"][0]["reason"] = (
        "direct/runner reconciliation failed: primary capture: wrapper realtime/monotonic elapsed difference exceeds 10 ms")
    assert temporary_clock_failure(value_map)

@pytest.mark.parametrize("field,value", [("success", True), ("resource_error", "incomplete response"),
    ("runner_complete", False), ("runner_binding_valid", False),
    ("scheduler_runtime_evidence_valid", False), ("runner_returncode", 1)])
def test_other_failed_prerequisites_do_not_trigger_clock_retry(field, value):
    value_map = deepcopy(BASE); value_map[field] = value
    assert not temporary_clock_failure(value_map)

def test_filter_crash_and_other_failures_are_not_clock_retries():
    value_map = deepcopy(BASE); value_map["failure"]["details"][0]["reason"] = "capture validation failed"
    assert not temporary_clock_failure(value_map)
    assert not temporary_clock_failure({})
