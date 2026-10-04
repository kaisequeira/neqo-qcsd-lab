"""The V4 capture-only amendment retains original classes and application bytes."""
from copy import deepcopy

import pytest

from qcsd_lab import rapid_front_capture_amendment as front, rapid_lane_evidence as lanes
from qcsd_lab import rapid_site_admission as admission
from tests.test_rapid_front_capture_amendment import amended, planned, rolling_setup
from tests.test_rapid_lane_evidence import setup
from tools import rapid_rolling_capture as cli


@pytest.mark.parametrize("amended", [front.RESERVE_CAPTURE_POLICY], indirect=True)
def test_v4_declaration_and_readiness_preserve_enrollment_full_graph_and_five_modes(amended):
    a = amended
    before = {path: path.read_bytes() for path in (a.original, a.enrollment, a.f.root / "policy.json")}
    value = front.validate_amendment(a.declaration, enrollment=a.enrollment, runtime=a.runtime)
    assert lanes._load(a.declaration.read_bytes())["receipt_type"] == front.RESERVE_RECEIPT_TYPE
    assert value["contract"] == front.RESERVE_CONTRACT
    assert (value["construction_window_us"], value["socket_window_us"], value["preparation_reserve_us"]) == (9000, 10000, 1000)
    assert value["formal_accepted_trace_count"] == 0 and value["scientific_credit"] is False
    assert a.target.read_bytes() == a.original.read_bytes().replace(
        ('"' + front.ORIGINAL_POLICY + '"').encode(), ('"' + front.RESERVE_CAPTURE_POLICY + '"').encode(), 1)
    assert front._inventory(front._directory(a.original)) == front._inventory(front._directory(a.target))
    spec, sites, payload, lane = planned(a)
    assert payload["planned_trace_count"] == 5 * 64 and len(payload["lanes"]) == 80
    assert len(sites) == 1 and sites[0].workload_sha256 == lanes._sha(a.target.read_bytes())
    from qcsd_lab import rapid_rolling_capture as rolling
    assert rolling.require_mode_readiness(spec, lane) == a.canary
    assert all(path.read_bytes() == raw for path, raw in before.items())


@pytest.mark.parametrize("amended", [front.RESERVE_CAPTURE_POLICY], indirect=True)
@pytest.mark.parametrize("mutation", ["receipt", "contract", "policy", "construction", "socket", "reserve", "bool", "resources", "evidence"])
def test_v4_amendment_cannot_relabel_old_authority_or_modify_the_application(amended, mutation):
    a = amended
    wrapper = lanes._load(a.declaration.read_bytes())
    value = deepcopy(wrapper["payload"])
    if mutation == "receipt": wrapper["receipt_type"] = front.WINDOW_RECEIPT_TYPE
    elif mutation == "contract": value["contract"] = front.WINDOW_CONTRACT
    elif mutation == "policy": value["capture_policy"] = front.WINDOW_CAPTURE_POLICY
    elif mutation == "construction": value["construction_window_us"] += 1
    elif mutation == "socket": value["socket_window_us"] += 1
    elif mutation == "reserve": value["preparation_reserve_us"] -= 1
    elif mutation == "bool": value["preparation_reserve_us"] = True
    elif mutation == "resources":
        graph = lanes._load(a.target.read_bytes()); graph["resources"].pop()
        a.target.write_bytes(lanes._json(graph))
    else: (front._directory(a.target) / "headers.json").write_bytes(b"modified\n")
    if mutation not in {"resources", "evidence"}:
        a.declaration.write_bytes(admission._json(admission._bind(wrapper["receipt_type"], value)))
    with pytest.raises(ValueError): front.validate_amendment(a.declaration, enrollment=a.enrollment, runtime=a.runtime)


def test_v4_cli_is_explicit_and_historical_default_is_preserved():
    required = ["front-amendment", "--enrollment", "/enrollment", "--runtime-spec", "/runtime", "--output", "/amendment"]
    assert cli._parser().parse_args(required).capture_policy == front.CAPTURE_POLICY
    assert cli._parser().parse_args(required + ["--capture-policy", front.RESERVE_CAPTURE_POLICY]).capture_policy == front.RESERVE_CAPTURE_POLICY
    with pytest.raises(SystemExit): cli._parser().parse_args(required + ["--capture-policy", "relax-all-deadlines"])
