"""V3 inputs reuse original enrollment while declaring fresh runtime authority."""
from copy import deepcopy
from pathlib import Path

import pytest

from qcsd_lab import rapid_front_capture_amendment as front
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_front_capture_amendment import amended, planned, rolling_setup
from tests.test_rapid_lane_evidence import setup
from tools import rapid_rolling_capture as cli


@pytest.mark.parametrize("amended", [front.WINDOW_CAPTURE_POLICY], indirect=True)
def test_public_v3_amendment_plan_and_readiness_keep_original_application_and_enrollment(amended):
    a = amended
    before = {p: p.read_bytes() for p in (a.original, a.enrollment, a.f.root / "policy.json")}
    value = front.validate_amendment(a.declaration, enrollment=a.enrollment, runtime=a.runtime)
    assert lanes._load(a.declaration.read_bytes())["receipt_type"] == front.WINDOW_RECEIPT_TYPE
    assert value["contract"] == front.WINDOW_CONTRACT and value["capture_policy"] == front.WINDOW_CAPTURE_POLICY
    assert a.target.read_bytes() == a.original.read_bytes().replace(
        ('"' + front.ORIGINAL_POLICY + '"').encode(), ('"' + front.WINDOW_CAPTURE_POLICY + '"').encode(), 1)
    assert front._inventory(front._directory(a.original)) == front._inventory(front._directory(a.target))
    spec, sites, payload, lane = planned(a)
    assert payload["planned_trace_count"] == 320 and len(payload["lanes"]) == 80
    assert payload["bindings"]["cohort_sha256"] == lanes._sha(a.enrollment.read_bytes())
    assert sites[0].workload_sha256 == lanes._sha(a.target.read_bytes())
    from qcsd_lab import rapid_rolling_capture as rolling
    assert rolling.require_mode_readiness(spec, lane) == a.canary
    assert all(p.read_bytes() == raw for p, raw in before.items())


@pytest.mark.parametrize("amended", [front.WINDOW_CAPTURE_POLICY], indirect=True)
@pytest.mark.parametrize("mutation", ["receipt", "contract", "policy", "window-field", "resources", "application-bytes"])
def test_v3_closed_derivation_and_authority_cannot_be_relabelled(amended, mutation):
    a = amended
    wrapped = lanes._load(a.declaration.read_bytes())
    value = deepcopy(wrapped["payload"])
    if mutation == "receipt": wrapped["receipt_type"] = front.RECEIPT_TYPE
    elif mutation == "contract": value["contract"] = front.CONTRACT
    elif mutation == "policy": value["capture_policy"] = front.CAPTURE_POLICY
    elif mutation == "window-field": value["outgoing_release_window_us"] = 20000
    elif mutation == "resources":
        graph = lanes._load(a.target.read_bytes()); graph["resources"][0]["length"] = 1
        a.target.write_bytes(lanes._json(graph))
    else: (front._directory(a.target) / "headers.json").write_bytes(b'changed\n')
    if mutation in {"receipt", "contract", "policy", "window-field"}:
        a.declaration.write_bytes(admission._json(admission._bind(wrapped["receipt_type"], value)))
    with pytest.raises(ValueError): front.validate_amendment(a.declaration, enrollment=a.enrollment, runtime=a.runtime)


def test_invalid_capture_policy_is_rejected_before_any_publication(tmp_path):
    for invalid in (None, [], front.ORIGINAL_POLICY, "unknown"):
        with pytest.raises(ValueError, match="supported capture policy"):
            front.publish_amendment(tmp_path / "absent-enrollment", {}, tmp_path / "declaration", capture_policy=invalid)
        assert not (tmp_path / "declaration").exists()


def test_public_cli_has_explicit_v3_and_exact_v2_default():
    required = ["front-amendment", "--enrollment", "/enrollment", "--runtime-spec", "/runtime", "--output", "/declaration"]
    assert cli._parser().parse_args(required).capture_policy == front.CAPTURE_POLICY
    assert cli._parser().parse_args(required + ["--capture-policy", front.WINDOW_CAPTURE_POLICY]).capture_policy == front.WINDOW_CAPTURE_POLICY
    with pytest.raises(SystemExit): cli._parser().parse_args(required + ["--capture-policy", "unknown"])
