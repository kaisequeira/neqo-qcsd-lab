"""Authenticated format conversion; no Native or physical acquisition."""
from copy import deepcopy
import json

import pytest

from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import supplied_static_graph as graph


@pytest.fixture
def bound(tmp_path):
    resources = [
        {"id": 0, "url": "https://primary.example/", "type": "Document",
         "headers": [["accept-language", "français"]], "depends_on": []},
        {"id": 1, "url": "https://auxiliary.example/asset", "type": "Image",
         "headers": [], "depends_on": [0]},
    ]
    original = tmp_path / "original.json"
    captured = tmp_path / "captured.json"
    original.write_bytes(graph.canonical_bytes({"resources": resources, "preparation": {"role": "original"}}))
    captured.write_bytes(graph.canonical_bytes({"resources": resources, "preparation": {"role": "derived"}}))
    row = {"original_manifest": rolling._ref(original), "capture_manifest": rolling._ref(captured),
           "resource_records_sha256": graph.digest(graph.canonical_bytes(resources))}
    amendment = {"workloads": [row]}
    facts = {"workload_sha256": row["capture_manifest"]["sha256"],
             "full_graph": {"resource_count": 2,
                            "resource_records_sha256": graph.digest(readiness._encoded(resources)),
                            "origins": ["https://auxiliary.example", "https://primary.example"]},
             "authority_source": {"original": "retained"}, "result_root": "/retained/result",
             "scientific_credit": False}
    return amendment, facts, original, captured


def test_two_encodings_convert_only_a_copy_of_authenticated_facts(bound):
    amendment, facts, _, _ = bound
    before = deepcopy(facts)
    assert facts["full_graph"]["resource_records_sha256"] != amendment["workloads"][0]["resource_records_sha256"]
    result = rolling._static_canary_facts(facts, amendment)
    assert facts == before
    assert result["full_graph"]["resource_records_sha256"] == amendment["workloads"][0]["resource_records_sha256"]
    assert {key: value for key, value in result.items() if key != "full_graph"} == {
        key: value for key, value in facts.items() if key != "full_graph"}
    assert result["full_graph"] is not facts["full_graph"]


@pytest.mark.parametrize("mutation", ["workload", "original-bytes", "capture-bytes", "derived-resources",
                                     "amendment-hash", "readiness-hash", "count", "origins",
                                     "partial-graph", "repeated-workload"])
def test_changed_bindings_records_or_complete_graph_are_rejected(bound, mutation):
    amendment, facts, original, captured = bound
    row = amendment["workloads"][0]
    if mutation == "workload":
        facts["workload_sha256"] = "0" * 64
    elif mutation == "original-bytes":
        original.write_bytes(original.read_bytes() + b" ")
    elif mutation == "capture-bytes":
        captured.write_bytes(captured.read_bytes() + b" ")
    elif mutation == "derived-resources":
        value = json.loads(captured.read_bytes())
        value["resources"].pop()
        captured.write_bytes(graph.canonical_bytes(value))
        row["capture_manifest"] = rolling._ref(captured)
        facts["workload_sha256"] = row["capture_manifest"]["sha256"]
    elif mutation == "amendment-hash":
        row["resource_records_sha256"] = "0" * 64
    elif mutation == "readiness-hash":
        facts["full_graph"]["resource_records_sha256"] = row["resource_records_sha256"]
    elif mutation == "count":
        facts["full_graph"]["resource_count"] = 1
    elif mutation == "origins":
        facts["full_graph"]["origins"].pop()
    elif mutation == "partial-graph":
        facts["full_graph"] = {"resource_records_sha256": facts["full_graph"]["resource_records_sha256"]}
    else:
        amendment["workloads"].append(deepcopy(row))
    with pytest.raises(ValueError):
        rolling._static_canary_facts(facts, amendment)
