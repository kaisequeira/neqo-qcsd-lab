"""HOST contract tests; synthetic formal authority is never measurement credit."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

from qcsd_lab import rapid_partial_lane as partial


def formal_report():
    """Controlled join fixture, not actual launch/runtime/qualification evidence."""
    lane = {"role": "formal", "study_version": 6, "block": 2, "shard": 2,
        "mode": "tamaraw-1200", "campaign_name": "synthetic-formal",
        "workload_ids": [f"site{i}" for i in range(2, 7)], "visits_per_workload": 4,
        "qualification_set": "synthetic-full-five", "generation": 1}
    sites = [{"workload_id": w, "candidate_id": f"candidate{i}", "workload_sha256": str(i) * 64,
        "qualification_set_manifest_sha256": "b" * 64} for i, w in enumerate(lane["workload_ids"], 2)]
    samples = []
    for row in sites:
        for visit in range(4):
            accepted = row["workload_id"] == "site2"
            failed = row["workload_id"] == "site3"
            sample_id = row["workload_id"] + "-" + str(visit)
            samples.append({"sample_id": sample_id, "workload_id": row["workload_id"], "visit": visit,
                "defense": lane["mode"], "request_policy": "as-defined", "eligible": accepted,
                "state": "accepted" if accepted else "failed" if failed else "planned",
                "path": "samples/" + sample_id, "attempts": 1 if accepted else 3 if failed else 0,
                "failure": {"type": "NativeTimeout"} if failed else None,
                "artifacts": {"samples/" + sample_id + "/run.json": "d" * 64} if accepted else {},
                "diagnostics": {"full_graph": True}})
    configuration = {"campaign_sha256": "c" * 64, "profile": "research-1200",
        "request_policies": ["as-defined"], "chaff_qualification_set": lane["qualification_set"],
        "chaff_qualification_set_manifest_sha256": "b" * 64,
        "defenses": [{"name": lane["mode"]}],
        "capture_limits": {"max_response_bytes": 16777216, "max_capture_bytes": 67108864,
                           "timeout_seconds": 180},
        "application_body_identity_policy": "complete-current-application-delivery-v1",
        "workloads": [{"id": s["workload_id"], "sha256": s["workload_sha256"], "visits": 4} for s in sites]}
    return {"lane": lane, "sites": sites, "intent": {"actuator": "run", "campaign_sha256": "c" * 64},
        "lineage": {"lab_commit": "a" * 40}, "spec": {"collection_image_digest": "sha256:" + "e" * 64},
        "experiment": {"name": lane["campaign_name"], "purpose": "evaluation", "status": "incomplete",
            "source": {"lab_dirty": False, "lab_commit": "a" * 40, "image_digest": "sha256:" + "e" * 64},
            "configuration": configuration, "samples": samples,
            "started_at": "2026-10-05T00:00:01+00:00", "completed_at": "2026-10-05T00:02:00+00:00",
            "summary": {"planned": 20, "accepted": 4, "failed": 4, "passed": False}},
        "accepted_samples": {s["sample_id"]: s["artifacts"] for s in samples if s["state"] == "accepted"},
        "result_root": "/synthetic/result", "result_seal": {"path": "/synthetic/result/evidence.sha256", "sha256": "f" * 64, "mode": 420}}


def test_partial_join_preserves_failed_aggregate_full_graph_epochs_and_slot_offsets():
    report = formal_report(); before = deepcopy(report)
    value = partial.accepted_subset(report)
    assert report == before
    assert value["aggregate_status"] == "incomplete" and value["aggregate_summary"]["passed"] is False
    assert value["lane_pass_claim"] is False and value["aggregate_formal_credit"] == 0
    assert value["accepted_count"] == 4 and len(value["remaining_samples"]) == 16
    assert [s["logical_visit"] for s in value["accepted_samples"]] == [4, 5, 6, 7]
    assert value["configuration"] == before["experiment"]["configuration"]
    assert [s["original_state"] for s in value["remaining_samples"][:4]] == ["failed"] * 4
    assert [s["attempts"] for s in value["remaining_samples"][:4]] == [3] * 4


@pytest.mark.parametrize("case", ["running", "complete", "all-pass", "changed-source", "dirty-source", "changed-image",
    "changed-campaign", "changed-graph", "trimmed-graph", "changed-mode", "changed-qualified-group",
    "duplicate-slot", "missing-slot", "running-slot", "moved-slot", "duplicate-sample", "missing-deep-accepted",
    "promoted-failure", "accepted-artifact-mutation", "ineligible", "parallel", "chunk-visits"])
def test_partial_join_refuses_contract_and_subset_mutations(case):
    r = formal_report(); e = r["experiment"]
    if case == "running": e["status"] = "running"
    elif case == "complete": e["status"] = "complete"
    elif case == "all-pass": e["summary"]["passed"] = True
    elif case == "changed-source": e["source"]["lab_commit"] = "d" * 40
    elif case == "dirty-source": e["source"]["lab_dirty"] = True
    elif case == "changed-image": e["source"]["image_digest"] = "sha256:" + "d" * 64
    elif case == "changed-campaign": e["configuration"]["campaign_sha256"] = "d" * 64
    elif case == "changed-graph": e["configuration"]["workloads"][0]["sha256"] = "d" * 64
    elif case == "trimmed-graph": e["configuration"]["workloads"].pop()
    elif case == "changed-mode": e["configuration"]["defenses"][0]["name"] = "undefended"
    elif case == "changed-qualified-group": e["configuration"]["chaff_qualification_set_manifest_sha256"] = "d" * 64
    elif case == "duplicate-slot": e["samples"][1]["visit"] = 0
    elif case == "missing-slot": e["samples"].pop()
    elif case == "running-slot": e["samples"][-1]["state"] = "running"
    elif case == "moved-slot": e["samples"][0]["workload_id"] = "site3"
    elif case == "duplicate-sample": e["samples"][1]["sample_id"] = e["samples"][0]["sample_id"]
    elif case == "missing-deep-accepted": r["accepted_samples"].pop(e["samples"][0]["sample_id"])
    elif case == "promoted-failure": e["samples"][4]["artifacts"] = {"fake": "d" * 64}
    elif case == "accepted-artifact-mutation": e["samples"][0]["artifacts"] = {"fake": "d" * 64}
    elif case == "ineligible": e["samples"][0]["eligible"] = False
    elif case == "parallel": r["intent"]["actuator"] = "parallel-formal-worker"
    elif case == "chunk-visits": r["lane"]["visits_per_workload"] = 16
    with pytest.raises(ValueError): partial.accepted_subset(r)


def original_fixture(tmp_path, report, *, effect=None):
    """Isolated controlled original API boundary; no real runtime/science claim."""
    root = tmp_path / "original"; package = root / "src/qcsd_lab"; package.mkdir(parents=True)
    evidence = tmp_path / "evidence"; evidence.mkdir()
    lane_dir = evidence / "lanes"; lane_dir.mkdir()
    result = tmp_path / "execution/results/synthetic-formal/run-001"; result.mkdir(parents=True)
    (result / "evidence.sha256").write_text("synthetic seal\n")
    intent = lane_dir / "intent.json"; intent.write_text(json.dumps(report["intent"]))
    for name in ("host-start.json", "host-process.json", "dns.json"):
        (lane_dir / name).write_text("{}")
    workload_root = tmp_path / "workloads"; workload_root.mkdir()
    for s in report["sites"]: (workload_root / (s["workload_id"] + ".json")).write_text("{}")
    spec = tmp_path / "spec.json"; spec.write_text("{}")
    report["result_root"] = str(result); report["result_seal"] = partial.reference(result / "evidence.sha256")
    (package / "__init__.py").write_text("")
    (package / "report.json").write_text(json.dumps(report))
    (package / "rapid_operation_facts.py").write_text(textwrap.dedent('''\
        from contextlib import nullcontext
        class OperationFacts:
            def begin_action(self): pass
            def scope(self): return nullcontext()
            def bind_capture(self, value): pass
            def check(self): pass
        '''))
    (package / "rapid_lane_evidence.py").write_text(textwrap.dedent(f'''\
        from dataclasses import dataclass
        from datetime import datetime
        from pathlib import Path
        from types import SimpleNamespace
        import hashlib,json
        R=json.loads(Path(__file__).with_name('report.json').read_text())
        def _read(p):return p.read_bytes()
        def _sha(raw):return hashlib.sha256(raw).hexdigest()
        class Spec:
            module_root=Path({str(root)!r})
            execution_root=Path({str(result.parents[2])!r})
            workload_root=Path({str(workload_root)!r})
            def serializable(self):return R['spec']
        def load_capture_spec(p): _read(p);return Spec()
        @dataclass
        class Lane:
            role:str;study_version:int;block:int;shard:int;mode:str;campaign_name:str;workload_ids:list;visits_per_workload:int;qualification_set:str;generation:int
        @dataclass
        class Site:
            workload_id:str;candidate_id:str;workload_sha256:str;qualification_set_manifest_sha256:str
        def _intent_and_lineage(spec,root,path,_context):
            _read(path);return R['intent'],R['lineage'],Lane(**R['lane']),[Site(**s) for s in R['sites']]
        def _validated_host_start(raw,intent_raw,campaign_name):return {{'command':['synthetic','run'],'started_at':'2026-10-05T00:00:00+00:00'}}
        def _verified_host_process(raw,root,intent_raw,campaign_name):
            return {{'start':{{}},'command':['synthetic','run'],'started_at':'2026-10-05T00:00:00+00:00','completed_at':'2026-10-05T00:03:00+00:00','returncode':1,'interruption':None}}
        def _object(root,ref):return b'{{}}'
        def _process_matches_lane(process,spec,name):return True
        def verify_dns_receipt(raw,name,workloads):return 'd'*64
        admission=SimpleNamespace(_utc=lambda s:datetime.fromisoformat(s))
        '''))
    body = textwrap.dedent('''\
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        def verify_result(root):
            # Actual isolated invocation, controlled original-proof body.
            with tempfile.TemporaryDirectory(prefix='partial-fixture-') as d:
                Path(d,'derived.txt').write_text('derived temporary endpoint replay')
            R=json.loads(Path(__file__).with_name('report.json').read_text())
            return SimpleNamespace(experiment=R['experiment'],accepted_samples=R['accepted_samples'])
        ''')
    if effect == "write": body = body.replace("# Actual isolated invocation, controlled original-proof body.", "Path(root,'forbidden.txt').write_text('mutation')")
    if effect == "network": body = body.replace("# Actual isolated invocation, controlled original-proof body.", "import socket; socket.socket().connect(('127.0.0.1', 1))")
    if effect == "docker": body = body.replace("# Actual isolated invocation, controlled original-proof body.", "import subprocess; subprocess.run(['docker','run','immutable-image'])")
    (package / "verification.py").write_text(body)
    source = {"root": str(root)}
    inputs = {"source_binding": {}, "spec": partial.reference(spec), "evidence_root": str(evidence),
              "intent": partial.reference(intent), "result": {"path": str(result), "seal": partial.reference(result / "evidence.sha256")}}
    return source, inputs


def test_isolated_original_call_preserves_report_and_derived_scratch_only(tmp_path):
    r = formal_report(); source, inputs = original_fixture(tmp_path, r)
    report, operation = partial._run_original(source, inputs, tmp_path / "audit")
    assert partial.accepted_subset(report)["accepted_count"] == 4
    assert set(operation) == {"started.json", "completed.json", "stdout.log", "stderr.log"}
    recorded, _ = partial._recorded_operation(source, inputs, operation)
    assert recorded == report
    assert (tmp_path / "audit/scratch").is_dir() and not list((tmp_path / "audit/scratch").iterdir())
    assert not (Path(inputs["result"]["path"]) / "forbidden.txt").exists()


@pytest.mark.parametrize("effect", ["write", "network", "docker"])
def test_original_child_cannot_write_evidence_or_execute_network_actuator(tmp_path, effect):
    source, inputs = original_fixture(tmp_path, formal_report(), effect=effect)
    with pytest.raises(ValueError, match="preserved raw audit"):
        partial._run_original(source, inputs, tmp_path / "audit")
    assert json.loads((tmp_path / "audit/completed.json").read_text())["returncode"] != 0
    assert not (Path(inputs["result"]["path"]) / "forbidden.txt").exists()


@pytest.mark.parametrize("case", ["bytes", "mode", "membership", "seal", "command", "raw-status", "chronology"])
def test_recorded_original_and_closing_fences_refuse_mutations(tmp_path, case):
    source, inputs = original_fixture(tmp_path, formal_report())
    report, operation = partial._run_original(source, inputs, tmp_path / "audit")
    if case in {"bytes", "mode"}:
        p = Path(inputs["intent"]["path"])
        p.write_text("changed") if case == "bytes" else p.chmod(0o600)
    elif case == "membership": (Path(inputs["result"]["path"]).parent / "unexpected").mkdir()
    elif case == "seal": Path(inputs["result"]["seal"]["path"]).write_text("changed seal")
    else:
        name = "started.json" if case == "command" else "completed.json"
        p = Path(operation[name]["path"]); v = json.loads(p.read_bytes())
        if case == "command": v["command"][-1] += "\n# changed"
        elif case == "raw-status": v["returncode"] = 1
        else: v["completed_at"] = "2000-01-01T00:00:00+00:00"
        p.write_bytes(partial.encoded(v)); operation[name] = partial.reference(p)
    with pytest.raises(ValueError): partial._recorded_operation(source, inputs, operation)


def test_live_unsealed_result_refuses_before_original_operation_or_receipt(tmp_path):
    result = tmp_path / "result"; result.mkdir()
    with pytest.raises(ValueError): partial.reference(result / "evidence.sha256")
    assert not (tmp_path / "audit").exists()


def test_unregistered_original_source_cannot_supply_a_new_validator(tmp_path):
    with pytest.raises(ValueError, match="not registered"):
        partial.source_snapshot(tmp_path, "a" * 40, "b" * 40)


def test_genuine_existing_deep_verifier_accepts_sealed_incomplete_generic_result(tmp_path):
    # Generic smoke fixture proves the unchanged API distinction, not TAM authority.
    from tests.test_verification import _make_result
    from qcsd_lab import verification
    root, experiment = _make_result(tmp_path, complete=False)
    verification.seal_result(root)
    original = (root / "experiment.json").read_bytes()
    verified = verification.verify_result(root)
    assert verified.experiment["status"] == "incomplete" and len(verified.accepted_samples) == 1
    assert original == (root / "experiment.json").read_bytes()
    raw = root / next(iter(next(iter(verified.accepted_samples.values()))))
    raw.write_bytes(raw.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="modified authoritative"): verification.verify_result(root)
