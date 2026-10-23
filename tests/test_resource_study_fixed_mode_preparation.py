"""Cheap focused-preparation failure paths; no Native, Docker, or live GET.

The saved canonical is the real closed142 metadata. The small resource graph
below is synthetic guard input, never qualification evidence. Only the runtime
filesystem replay boundary is replaced in checked_input tests; every input,
source profile, fixed science, immutable FD, and frozen-manifest guard is real.
"""
from copy import deepcopy
from collections import Counter
from pathlib import Path
import hashlib
import json

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_fixed_mode_preparation as focused
from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_reader_compatibility as readers
from qcsd_lab import front_fixed_configuration as front
from qcsd_lab import tamaraw_fixed_configuration as tamaraw
from qcsd_lab import capture_acceptance_policy as policy


def immutable(path, value, *, raw=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    content = value if raw else inputs.canonical_json(value)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(content)
    path.chmod(0o444)
    return {"path":str(path), "sha256":hashlib.sha256(content).hexdigest()}


@pytest.fixture(params=("front", "tamaraw"))
def case(tmp_path, monkeypatch, request):
    tmp_path = tmp_path.resolve(strict=True)
    # Real canonical bytes keep their actual published SHA and image121 source.
    saved = Path(__file__).parent / "fixtures/native142_sdk121_canonical_runtime.json"
    raw = saved.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == focused.CANONICAL142_SHA256
    canonical = json.loads(raw)
    runtime = {"collection_image_digest":canonical["collection_image_digest"],
        "prepare_image_digest":canonical["prepare_image_digest"],
        "client_sha256":canonical["installed_client_sha256"], "platform":canonical["platform"],
        "native_commit":canonical["source"]["neqo_commit"], "source":canonical["source"],
        "canonical_sha256":focused.CANONICAL142_SHA256}
    assert runtime["source"]["lab_commit"] == "06225fa5638dc879171b4c43da6eb05843aafca5"
    root, oldroot = tmp_path / "fresh", tmp_path / "old"
    hostname = "example.org"
    urls = [f"https://{hostname}/asset-{i:02d}" for i in range(20)]
    manifest = inputs.native_manifest(hostname, urls, {url:2000 for url in urls})
    for resource in manifest["resources"]:
        resource["headers"] = [pair[:] for pair in native.REQUEST_HEADERS]
    manifest["resources"][0]["type"] = "Document"
    manifest_ref = immutable(oldroot / "resources.json", manifest)
    prepared = {"resources":deepcopy(manifest["resources"]), "preparation":{
        "primary_document_identity_policy":"variable-primary-document-body-v1",
        "application_response_policy":"completed-terminal-http-errors-v1",
        "qualified_chaff_origin_policy":"prepared-approved-origins-v1",
        policy.TERMINAL_PRIMARY_FIELD:policy.TERMINAL_PRIMARY_POLICY,
        policy.FRONT_FIELD:front.POLICY, policy.TAMARAW_FIELD:policy.TAMARAW_POLICY}}
    prepared_ref = immutable(oldroot / "prepared.json", prepared)
    mode = request.param
    fixed = front if mode == "front" else tamaraw
    policies = native.mode_policies()[mode]
    settings = {"profile":"research-1200", "request_policy":"as-defined",
        "max_response_bytes":native.MAX_RESPONSE_BYTES, "udp_payload_ceiling":1200,
        "policies":policies, "configuration_sha256":fixed.configuration_sha256(),
        "resolved_configuration":fixed.resolved_configuration(), "timeout_seconds":120,
        "capture_seconds":180}
    old = {"hostname":hostname, "urls":urls, "workload_sha256":manifest_ref["sha256"],
        "mode_settings":{mode:settings}, "mode_policies":{mode:policies},
        "paths":{"manifest":"resources.json", "prepared_workload":"prepared.json"},
        "files":{"resources.json":manifest_ref["sha256"], "prepared.json":prepared_ref["sha256"]},
        "scientific_credit":False}
    old_path = oldroot / "classes" / hostname / "enrollment.json"
    old_ref = immutable(old_path, old)
    canonical_ref = immutable(tmp_path / "canonical.json", raw, raw=True)
    source = cohorts.verifier_contract()
    value = {"record_type":focused.INPUT, "schema_version":1, "root":str(root),
        "parent":{"root":str(tmp_path/"parent"), "study_sha256":"a"*64, "head_sha256":"b"*64},
        "hostname":hostname, "mode":mode, "historical_root":str(oldroot),
        "historical_enrollment":old_ref, "runtime":runtime, "science":focused._science(old,mode),
        "source_contract":source, "canonical_runtime":canonical_ref,
        "resource_selection":{"path":str(tmp_path/"selection.json"),"sha256":"c"*64},
        "scientific_credit":False}
    calls = []
    def closed_runtime_boundary(path):
        calls.append(path)
        return deepcopy(runtime)
    monkeypatch.setattr(study, "runtime_identity", closed_runtime_boundary)
    path = tmp_path / "input.json"
    def publish():
        return immutable(path, value)
    return {"root":root,"old":old,"old_path":old_path,"input":value,"input_path":path,
        "runtime":runtime,"publish":publish,"runtime_calls":calls}


def test_exact_inputs_keep_image121_and_distinct_current_reader(case):
    ref = case["publish"]()
    checked = focused.checked_input(case["root"],case["runtime"],ref["path"],ref["sha256"])
    assert checked["input"]["source_contract"] == cohorts.verifier_contract()
    assert len(checked["input_observations"]) == 5
    assert len(case["runtime_calls"]) == 1
    focused._fence_inputs(checked)


def test_changed_reader_profile_refuses_before_runtime_or_native(case):
    case["input"]["source_contract"]["transitive_source_sha256"] = "0"*64
    ref = case["publish"]()
    with pytest.raises(ValueError, match="Source/parent scope"):
        focused.checked_input(case["root"],case["runtime"],ref["path"],ref["sha256"])
    assert case["runtime_calls"] == []


def test_full_runtime_client_mutation_refuses_before_runtime_or_native(case):
    case["input"]["runtime"] = deepcopy(case["runtime"])
    case["input"]["runtime"]["client_sha256"] = "0"*64
    ref = case["publish"]()
    with pytest.raises(ValueError, match="Source/parent scope"):
        focused.checked_input(case["root"],case["runtime"],ref["path"],ref["sha256"])
    assert case["runtime_calls"] == []


def test_rebound_bool_integer_science_cannot_pass_equality(case):
    # Rebind both old enrollment and new input hashes: type-safe fixed science
    # must independently refuse even if no hash mismatch remains.
    mode = case["input"]["mode"]
    case["old"]["mode_settings"][mode]["udp_payload_ceiling"] = 1200.0
    case["input"]["historical_enrollment"] = immutable(case["old_path"],case["old"])
    case["input"]["science"] = focused._science(case["old"],mode)
    ref = case["publish"]()
    with pytest.raises(ValueError, match="exact original fixed mode profile"):
        focused.checked_input(case["root"],case["runtime"],ref["path"],ref["sha256"])


def test_byteidentical_name_replacement_fails_whole_operation_fd_fence(case):
    ref = case["publish"]()
    checked = focused.checked_input(case["root"],case["runtime"],ref["path"],ref["sha256"])
    path = case["input_path"]
    replacement = path.with_name("replacement.json")
    immutable(replacement,path.read_bytes(),raw=True)
    replacement.replace(path)
    with pytest.raises(ValueError, match="FD/path changed"):
        focused._fence_inputs(checked)


def test_not_enrolled_result_never_becomes_positive_wrapper(case,monkeypatch):
    ref = case["publish"]()
    checked = focused.checked_input(case["root"],case["runtime"],ref["path"],ref["sha256"])
    monkeypatch.setattr(focused,"checked_input",lambda *args:checked)
    monkeypatch.setattr(study,"_retained_current_scope",lambda *args:{"fixture_parent":True})
    monkeypatch.setattr(study,"enroll",lambda *args,**kwargs:{"enrollment":[{
        "hostname":case["input"]["hostname"],"status":"not-enrolled","reason":"real validator refused"}]})
    with pytest.raises(ValueError,match="did not enroll its sole declared class"):
        focused.enroll_fixed_mode(case["root"],case["runtime"],input_path=ref["path"],
            input_sha256=ref["sha256"],backend=object())


def test_current178_preserves_historical_entries_and_only_original094_alias():
    current = cohorts.verifier_contract()
    qualified = readers.qualify_execution(current)
    assert current["transitive_source_files"] == 178
    assert len(qualified._supported_profiles) == 52
    # These two historical names already described the same exact Source094
    # contract before this change. Preserve that alias, and refuse any new one.
    exact094 = readers._encoded(readers.prior_exact094_execution_contract())
    assert exact094 == readers._encoded(readers.prior_native130_qpack_parser094_execution_contract())
    counts = Counter(qualified._supported_profiles)
    assert {value: count for value, count in counts.items() if count > 1} == {exact094: 2}
    old = readers.prior_exact123_execution_contract()
    assert old["transitive_source_files"] == 177
    assert old["transitive_source_sha256"] == "f96ce892edd7d41a0ff532cfff63d964aed5294a2aed5f055444b47d8152991e"
    distinct = [current, old, readers.prior_exact122_execution_contract(),
        readers.prior_exact121_execution_contract(), readers.prior_exact118003_execution_contract()]
    assert len({readers._encoded(profile) for profile in distinct}) == 5
    for profile in distinct:
        assert readers.require_supported(profile, qualified)
    assert readers.require_supported(old,qualified)
    changed = deepcopy(old);changed["transitive_source_sha256"] = "0"*64
    with pytest.raises(ValueError,match="unsupported or changed admission reader"):
        readers.require_supported(changed,qualified)
