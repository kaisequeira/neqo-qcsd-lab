"""Original static three-mode HOST contracts; external runtime/120/canary fixtures.

Complete GET/raw preparation, admission, enrollment, public plans, capsule
dispatch and fences use real HOST code. Runtime closure, named qualification
and recorded image canary are explicit synthetic boundaries, not live evidence.
"""
from datetime import UTC, datetime
import copy
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_original_static_parallel_schedule as schedule
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as legacy
from qcsd_lab import rapid_runtime_epochs as epochs
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as preparation
from tests.test_supplied_static_get import actual_contract_fixture, load, write
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_supplied_static_capture_amendment import original, REPOSITORY
from tests.test_rapid_static_parallel_schedule import common_data_root
from tools import rapid_rolling_capture as cli


@pytest.fixture(params=["undefended", "tamaraw", "cs-buflo"])
def current(original, request, monkeypatch):
    a, mode = original, request.param
    old_source = Path(a.runtime["runtime_source_root"])
    current_source = old_source.with_name("current-source")
    shutil.copytree(old_source, current_source)
    a.runtime["runtime_source_root"] = str(current_source)
    for name, filename in (("source_manifest", "source.json"), ("client_binary", "client"),
                           ("base_launcher", "qcsd-lab")):
        a.runtime[name] = str(current_source / filename)
    metadata = load(current_source / "source.json")
    metadata.update(lab_commit="e" * 40, neqo_commit="c" * 40, neqo_pinned_commit="c" * 40)
    write(current_source / "source.json", metadata)
    (current_source / "client").write_bytes(b"synthetic distinct current client; no historical reuse\n")
    a.target.write_bytes(a.original.read_bytes())
    for relative in {*schedule.CONTROL_FILES, *(item[0] for item in lanes.TRAFFIC_FILES.values())}:
        path = current_source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((REPOSITORY / relative).read_bytes())
    sidecars = Path(a.runtime["campaign_dir"]).parent / "chaff-response-qualification-store/sets/current-original"
    sidecars.mkdir(parents=True)
    named = sidecars / "_qualification-set.json"
    write(named, {"external_qualification_primitive": "synthetic HOST-only named120 boundary"})
    source = {**metadata, "image_digest": a.runtime["collection_image_digest"]}
    write(sidecars / a.original.name, {
        "schema_version": schedule.qualification.RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION,
        "qualification_source": source, "qualification_image_digest": source["image_digest"],
        "implementation_receipt": {"sha256": "9" * 64,
            "neqo_qcsd_client": {"sha256": rolling._ref(current_source / "client")["sha256"]}}})
    qualifier = a.study / "current-original-qualifier.json"
    write(qualifier, {"schema_version": 1, "qualification_sets": [{"qualification_set": "current-original",
        "manifest": str(named), "sidecar_root": str(sidecars), "prefix_spec_root": None}]})
    canary_plan = a.study / "canary-plan.json"
    write(canary_plan, {"data_role": preparation.ROLE, "mode": mode})
    canary = {"plan": rolling._ref(canary_plan)}
    facts = {"authority_source": source, "client_sha256": rolling._ref(current_source / "client")["sha256"],
        "traffic_hashes": {key: digest for key, (_, digest) in lanes.TRAFFIC_FILES.items()},
        "workload_sha256": rolling._ref(a.original)["sha256"],
        "full_graph": {"resource_count": len(a.manifest["resources"]),
            "resource_records_sha256": readiness._sha(readiness._encoded(a.manifest["resources"])),
            "origins": sorted({rolling.origin(item["url"]).rstrip("/") for item in a.manifest["resources"]})}}
    calls = {"named120": 0, "canary": 0}
    def named120(value, **arguments):
        calls["named120"] += 1
        assert arguments["require_current_implementation"] is False
        assert arguments["expected_qualification_scope"] == "response-only"
        assert arguments["prefix_spec_root"] is None
    def canary_boundary(reference, *, runtime, mode):
        calls["canary"] += 1
        assert reference == canary and mode == request.param
        assert runtime == {key: a.runtime[key] for key in lanes.RUNTIME_KEYS}
        return facts
    monkeypatch.setattr(rolling, "validate_named_qualification_set_manifest", named120)
    monkeypatch.setattr(schedule.qualification, "validate_named_qualification_set_manifest", named120)
    monkeypatch.setattr(readiness, "validate_canary", canary_boundary)
    monkeypatch.setattr(readiness, "readiness_mount_roots", lambda *args, **kwargs: [a.study])
    a.monkeypatch.setattr(rolling.admission, "_now", lambda: datetime.now(UTC).isoformat())
    serial = a.study / "serial-plan.json"
    rolling.publish_plan(a.study, a.enrollment, qualifier, serial,
        readiness={mode: canary}, runtime_inputs=a.runtime)
    spec = rolling.capture_spec(a.study, a.enrollment, qualifier, serial)
    canonical = {"source": metadata, "collection_image_digest": spec.collection_image_digest,
        "installed_client_sha256": rolling._ref(spec.client_binary)["sha256"],
        "checks": {"collection": {"qualification_implementation_sha256": "9" * 64}},
        "verified_at": "2000-01-01T00:00:02Z"}
    path = a.study / "current-runtime/canonical-runtime.json"
    path.parent.mkdir()
    write(path, canonical)
    reference = rolling._ref(path)
    def reopen(ref, runtime, *, _inspector=False):
        assert _inspector is True
        assert ref == rolling._ref(path)
        value = load(path)
        if (runtime != a.runtime or value["source"] != load(spec.source_manifest)
            or value["collection_image_digest"] != spec.collection_image_digest
            or value["installed_client_sha256"] != rolling._ref(spec.client_binary)["sha256"]):
            raise ValueError("synthetic current closed-runtime identity changed")
        return value, {relative: (current_source / relative).read_bytes() for relative in schedule.CONTROL_FILES}
    monkeypatch.setattr(legacy, "reopen_runtime", reopen)
    return SimpleNamespace(a=a, spec=spec, canonical=reference, mode=mode, canary=canary,
        facts=facts, sidecars=sidecars, output=a.study / "original-static-schedule.json", calls=calls,
        old_source=old_source)


def capsule(c):
    return schedule.publish_schedule(c.spec, c.a.runtime, c.spec.qualification_spec,
        c.canonical, c.canonical, c.output, reason="prospective original-static same-setting HOST fixture")


def parallel(c, reference):
    output = c.a.study / "parallel-plan.json"
    rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, output,
        readiness={c.mode: c.canary}, runtime_inputs=c.a.runtime, scheduling=reference)
    return rolling.capture_spec(c.a.study, c.a.enrollment, c.spec.qualification_spec, output)


def test_each_original_static_mode_publishes_without_other_modes_or_amendments(current):
    c = current
    protected = {path: path.read_bytes() for path in (c.a.original, c.a.target, c.a.terminal,
        c.a.enrollment, c.a.study / "policy.json", c.a.get_root / "full-get-proof.json",
        c.a.get_root / "native/run.json", c.spec.plan_receipt)}
    reference = capsule(c)
    value = legacy.validate_schedule(reference, runtime=c.a.runtime)
    assert value["mode"] == c.mode and value["data_role"] == preparation.ROLE
    assert value["original_canonical"] == value["current_canonical"] == c.canonical
    assert value["qualified_inputs"]["workloads"][c.a.original.stem]["application_evidence"] is None
    spec = parallel(c, reference)
    sites, payload = rolling.verify_capture_plan(spec)
    assert payload["planned_trace_count"] == 320 and len(payload["lanes"]) == 80
    assert set(payload["readiness"]) == {c.mode}
    assert not {"static_capture_amendment", "front_capture_amendment", "buflo_duration_policy"} & payload.keys()
    lane = lanes._lane({"plan_payload": payload}, next(row["campaign_name"] for row in payload["lanes"] if row["mode"] == c.mode))
    assert rolling.require_mode_readiness(spec, lane) == c.canary
    roots = legacy.mount_roots(reference)
    assert c.a.get_root in roots and c.old_source in roots and spec.runtime_source_root in roots
    assert all(path.read_bytes() == before for path, before in protected.items())
    assert sites[0].workload_sha256 == rolling._ref(c.a.original)["sha256"]
    with pytest.raises(FileExistsError): capsule(c)
    with pytest.raises(ValueError, match="exact equal current"):
        legacy.validate_qualification_reuse({"sha256": "old"}, {"sha256": "current"}, reference,
            actual_image=spec.collection_image_digest)


def test_current_epoch_and_full_get_negative_fences(current):
    c = current
    mutations = ("old-runtime", "native", "client", "control", "traffic", "qualifier",
        "qualification-source", "qualification-image", "qualification-schema", "qualification-implementation",
        "graph", "get-raw", "canary-source", "canary-client", "canary-graph", "canary-workload")
    paths = [rolling._open_ref(c.canonical), c.spec.client_binary,
        c.spec.runtime_source_root / schedule.CONTROL_FILES[-1],
        c.spec.runtime_source_root / next(iter(lanes.TRAFFIC_FILES.values()))[0],
        c.spec.qualification_spec, c.sidecars / c.a.original.name, c.a.target,
        c.a.get_root / "native/packets.csv"]
    saved = {p: p.read_bytes() for p in paths}
    facts = copy.deepcopy(c.facts)
    for mutation in mutations:
        if mutation == "old-runtime":
            with pytest.raises(ValueError, match="one exact current"):
                schedule.publish_schedule(c.spec, c.a.runtime, c.spec.qualification_spec,
                    {"path": str(c.a.study / "absent-old-canonical.json"), "sha256": "e" * 64}, c.canonical,
                    c.output, reason="invalid historical substitution")
            continue
        if mutation == "native":
            value = load(paths[0]); value["source"]["neqo_commit"] = "e" * 40; write(paths[0], value)
        elif mutation == "client": c.spec.client_binary.write_bytes(b"changed client")
        elif mutation == "control": paths[2].write_bytes(b"changed control\n")
        elif mutation == "traffic": paths[3].write_bytes(b"changed fixed traffic\n")
        elif mutation == "qualifier": c.spec.qualification_spec.write_bytes(b"{}\n")
        elif mutation.startswith("qualification-"):
            value = load(c.sidecars / c.a.original.name)
            if mutation.endswith("source"): value["qualification_source"]["neqo_commit"] = "5" * 40
            elif mutation.endswith("image"): value["qualification_image_digest"] = "sha256:" + "e" * 64
            elif mutation.endswith("schema"): value["schema_version"] = 1
            else: value["implementation_receipt"]["sha256"] = "e" * 64
            write(c.sidecars / c.a.original.name, value)
        elif mutation == "graph":
            value = load(c.a.target); value["resources"].pop(); write(c.a.target, value)
        elif mutation == "get-raw": paths[-1].write_bytes(b"changed original raw GET\n")
        elif mutation == "canary-source": c.facts["authority_source"]["neqo_commit"] = "5" * 40
        elif mutation == "canary-client": c.facts["client_sha256"] = "e" * 64
        elif mutation == "canary-graph": c.facts["full_graph"]["resource_records_sha256"] = "e" * 64
        else: c.facts["workload_sha256"] = "e" * 64
        with pytest.raises((ValueError, OSError, KeyError, AssertionError)): capsule(c)
        assert not c.output.exists()
        for path, before in saved.items(): path.write_bytes(before)
        c.facts.clear(); c.facts.update(copy.deepcopy(facts))


def test_typed_capsule_cannot_change_mode_credit_or_import_amendment(current):
    c = current
    reference = capsule(c)
    original_bytes = c.output.read_bytes()
    value = load(c.output)
    for key, changed in (("mode", "front"), ("mode", "buflo"), ("scientific_credit", True),
                         ("data_role", "browser"), ("static_capture_amendment", {"path": "untrusted"})):
        forged = copy.deepcopy(value); forged[key] = changed
        write(c.output, forged)
        with pytest.raises(ValueError): legacy.validate_schedule(rolling._ref(c.output), runtime=c.a.runtime)
    c.output.write_bytes(original_bytes)
    assert legacy.validate_schedule(reference, runtime=c.a.runtime)["mode"] == c.mode
    with pytest.raises(ValueError, match="unchanged independently ready"):
        rolling.publish_plan(c.a.study, c.a.enrollment, c.spec.qualification_spec, c.a.study / "bad-plan.json",
            readiness={c.mode: c.canary, "front": c.canary}, runtime_inputs=c.a.runtime, scheduling=reference)


@pytest.mark.parametrize("current", ["tamaraw"], indirect=True)
def test_operation_local_original_static_fence_rejects_raw_modes_and_membership(current):
    c = current
    reference = capsule(c)
    value = load(c.output)
    context = operations.OperationFacts()
    context.bind_schedule(value)
    context.check()
    raw = c.a.get_root / "native/packets.csv"
    before = raw.read_bytes()
    raw.write_bytes(before + b"changed\n")
    with pytest.raises(ValueError): context.check()
    raw.write_bytes(before)
    context.check()
    old_mode = raw.stat().st_mode & 0o777
    raw.chmod(old_mode ^ 0o100)
    with pytest.raises(ValueError): context.check()
    raw.chmod(old_mode)
    added = raw.parent / "unexpected-evidence.txt"
    added.write_bytes(b"extra member\n")
    with pytest.raises(ValueError): context.check()
    added.unlink()
    context.check()


def test_cli_and_installed_hook_use_explicit_new_contract(current, monkeypatch):
    c = current
    parser = cli._parser()
    args = parser.parse_args(["original-static-scheduling", "--spec", "spec.json", "--runtime-spec", "runtime.json",
        "--qualification-spec", "qualification.json", "--original-canonical", "runtime-canonical.json",
        "--current-canonical", "runtime-canonical.json", "--output", "schedule.json", "--reason", "own current setting"])
    assert args.command == "original-static-scheduling"
    reference = capsule(c)
    monkeypatch.setenv(epochs.COMPATIBILITY_ENV, str(c.output))
    monkeypatch.setenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION", "untrusted")
    with pytest.raises(ValueError, match="cannot claim historical"):
        epochs.validate_qualification_reuse({}, {})
    monkeypatch.delenv("QCSD_RAPID_CAPTURE_CONTROL_INSTALLATION")
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", c.spec.collection_image_digest)
    seen = []
    monkeypatch.setattr(schedule, "validate_current_qualification", lambda old, new, ref, **kwargs: seen.append((old, new, ref, kwargs)))
    epochs.validate_qualification_reuse({"current": True}, {"current": True})
    assert seen[0][:3] == ({"current": True}, {"current": True}, reference)
    assert seen[0][3]["actual_image"] == c.spec.collection_image_digest
