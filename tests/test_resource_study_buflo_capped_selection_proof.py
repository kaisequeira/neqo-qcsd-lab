"""Four-field selection jobs plus a separate capped Native CLI; no live proof.

The real frozen pool/selection/job/input/workload fixture retains every
original selection check. Runtime tests control DNS, Docker authentication,
locking and the Native process boundary only; they prove argv/file metadata,
not installed bytes, real responses, physical custody or scientific credit.
"""
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path

import pytest

from qcsd_lab import resource_study_inputs as inputs
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab import resource_study_selection as selection
from tests.test_resource_study_selection import pool, prepared, put


CAP = 131072
DECLARATION = {"schema_version": 1,
    "record_type": "qcsd-resource-domain-buflo-capped-chaff-selection-v1",
    "selection_policy": "resource-domain-buflo-prepared-and-identity-body-cap-descending-prefix-v1",
    "cap_bytes": CAP}
JOB_KEYS = {"hostname", "urls", "output", "runtime"}


def test_original_four_field_selection_job_stays_valid(pool, tmp_path):
    root, enrollment, receipt = prepared(pool, tmp_path)
    path = root / enrollment["resource_selection"]["job_path"]
    before = path.read_bytes()
    assert set(json.loads(before)) == JOB_KEYS
    facts = selection.validate_selection_proof(root, enrollment, receipt)
    assert facts["selected_urls"] == enrollment["urls"] and len(facts["selected_urls"]) == 20
    assert facts["scientific_credit"] is False and path.read_bytes() == before
    assert "buflo_chaff_selection" not in enrollment


def test_capped_declaration_keeps_original_four_field_selection_proof(pool, tmp_path):
    root, enrollment, receipt = prepared(pool, tmp_path)
    enrollment["buflo_chaff_selection"] = deepcopy(DECLARATION)
    before = deepcopy((enrollment, receipt))
    path = root / enrollment["resource_selection"]["job_path"]
    assert set(json.loads(path.read_bytes())) == JOB_KEYS
    facts = selection.validate_selection_proof(root, enrollment, receipt)
    assert facts["selected_urls"] == enrollment["urls"] and facts["scientific_credit"] is False
    assert (enrollment, receipt) == before


@pytest.mark.parametrize("declared,key", [(False, "buflo_chaff_cap_bytes"),
    (True, "buflo_chaff_cap_bytes"), (True, "unreviewed")])
def test_extra_job_field_remains_refused_after_all_hashes_are_rebound(pool, tmp_path, declared, key):
    root, enrollment, receipt = prepared(pool, tmp_path)
    if declared: enrollment["buflo_chaff_selection"] = deepcopy(DECLARATION)
    binding = enrollment["resource_selection"]; relative = binding["job_path"]
    job = json.loads((root / relative).read_bytes()); job[key] = CAP
    digest = put(root / relative, job)
    binding["job_sha256"] = enrollment["files"][relative] = receipt["files"][relative] = digest
    with pytest.raises(ValueError, match="actual preparation job"):
        selection.validate_selection_proof(root, enrollment, receipt)


def runtime_prepare(tmp_path, monkeypatch, *, cap=CAP, declaration=DECLARATION):
    root = tmp_path / "study"; root.mkdir()
    bound = {"collection_image_digest": "sha256:" + "a" * 64}
    candidate = {"hostname": "assets.example.org", "urls": [
        "https://assets.example.org/resource-" + str(i) for i in range(20)]}
    observed = []
    monkeypatch.setattr(runtime, "public_ipv4", lambda _host: {"selected_ipv4": "8.8.8.8"})
    monkeypatch.setattr(runtime, "docker_lock", nullcontext)
    def checked(value):
        assert value is bound
    monkeypatch.setattr(runtime, "_runtime_check", checked)
    def docker(*argv, **kwargs):
        assert argv[0] == "run" and kwargs["timeout"] > 0
        job_path = Path(argv[argv.index("--job") + 1])
        job = json.loads(job_path.read_bytes())
        observed.append((argv, job))
        base = Path(job["output"]); base.mkdir()
        manifest = base / "resources.json"
        manifest.write_bytes(inputs.canonical_json({"resources": []}))
        result = {"hostname": candidate["hostname"], "urls": job["urls"],
            "workload_path": str(manifest), "workload_sha256": inputs.sha256_file(manifest),
            "paths": {"manifest": str(manifest)}, "files": {"resources.json": inputs.sha256_file(manifest)},
            "runtime": bound, "scientific_credit": False}
        if declaration is not None: result["buflo_chaff_selection"] = deepcopy(declaration)
        return json.dumps(result)
    monkeypatch.setattr(runtime, "_docker", docker)
    result = runtime.PreparationRuntime(root, bound).prepare(candidate, root / "enrollment-attempt",
                                                           buflo_chaff_cap_bytes=cap)
    assert len(observed) == 1
    return observed[0], result


def test_runtime_prepare_keeps_four_field_job_and_passes_separate_cap_cli(tmp_path, monkeypatch):
    (argv, job), result = runtime_prepare(tmp_path, monkeypatch)
    assert set(job) == JOB_KEYS
    assert argv[argv.index("_prepare"):] == ("_prepare", "--job", str(tmp_path / "study/enrollment-attempt/job.json"),
                                            "--buflo-chaff-cap-bytes", str(CAP))
    assert result["buflo_chaff_selection"] == DECLARATION and result["scientific_credit"] is False


def test_uncapped_runtime_keeps_original_job_and_native_argv(tmp_path, monkeypatch):
    (argv, job), result = runtime_prepare(tmp_path, monkeypatch, cap=None, declaration=None)
    assert set(job) == JOB_KEYS and "--buflo-chaff-cap-bytes" not in argv
    assert "buflo_chaff_selection" not in result


@pytest.mark.parametrize("case", ["missing", "wrong-cap", "boolean-cap", "boolean-schema", "wrong-record", "wrong-policy", "extra"])
def test_runtime_returned_declaration_must_match_requested_cap(tmp_path, monkeypatch, case):
    declared = deepcopy(DECLARATION)
    if case == "missing": declared = None
    elif case == "wrong-cap": declared["cap_bytes"] //= 2
    elif case == "boolean-cap": declared["cap_bytes"] = True
    elif case == "boolean-schema": declared["schema_version"] = True
    elif case == "wrong-record": declared["record_type"] = "unreviewed"
    elif case == "wrong-policy": declared["selection_policy"] = "unreviewed"
    else: declared["unreviewed"] = True
    with pytest.raises(ValueError):
        runtime_prepare(tmp_path, monkeypatch, declaration=declared)


def native_job(tmp_path):
    path = tmp_path / "job.json"
    value = {"hostname": "assets.example.org", "urls": ["https://assets.example.org/"],
             "output": str(tmp_path / "prepared"), "runtime": {"fixture": True}}
    path.write_bytes(inputs.canonical_json(value))
    return path, value


def native_boundary(monkeypatch):
    calls = []
    def called(**kwargs):
        calls.append(kwargs); return {"scientific_credit": False}
    for name in ("prepare_domain", "capture_session", "probe_urls"):
        monkeypatch.setattr(native, name, called)
    return calls


def test_native_prepare_accepts_separate_cap_and_forwards_it(tmp_path, monkeypatch, capsys):
    path, job = native_job(tmp_path); calls = native_boundary(monkeypatch)
    assert native.main(["_prepare", "--job", str(path), "--buflo-chaff-cap-bytes", str(CAP)]) == 0
    assert calls == [{**job, "buflo_chaff_cap_bytes": CAP}]
    assert json.loads(capsys.readouterr().out) == {"scientific_credit": False}
    assert json.loads(path.read_bytes()) == job and set(job) == JOB_KEYS


def test_uncapped_native_prepare_keeps_original_kwargs(tmp_path, monkeypatch, capsys):
    path, job = native_job(tmp_path); calls = native_boundary(monkeypatch)
    assert native.main(["_prepare", "--job", str(path)]) == 0
    assert calls == [job] and json.loads(capsys.readouterr().out) == {"scientific_credit": False}


@pytest.mark.parametrize("action", ["_capture", "_probe"])
def test_cap_cli_cannot_enter_another_native_action(tmp_path, monkeypatch, action):
    path, _ = native_job(tmp_path); calls = native_boundary(monkeypatch)
    with pytest.raises((ValueError, SystemExit)):
        native.main([action, "--job", str(path), "--buflo-chaff-cap-bytes", str(CAP)])
    assert calls == []


@pytest.mark.parametrize("value", ["0", "1199", "1048577", "131072.0", "True", "not-an-integer"])
def test_native_cap_cli_rejects_invalid_values_before_native_work(tmp_path, monkeypatch, value):
    path, _ = native_job(tmp_path); calls = native_boundary(monkeypatch)
    with pytest.raises((ValueError, SystemExit)):
        native.main(["_prepare", "--job", str(path), "--buflo-chaff-cap-bytes", value])
    assert calls == []


@pytest.mark.parametrize("explicit", [False, True])
def test_native_job_cannot_embed_or_duplicate_cap_authority(tmp_path, monkeypatch, explicit):
    path, job = native_job(tmp_path); job["buflo_chaff_cap_bytes"] = CAP
    path.write_bytes(inputs.canonical_json(job)); calls = native_boundary(monkeypatch)
    args = ["_prepare", "--job", str(path)]
    if explicit: args += ["--buflo-chaff-cap-bytes", str(CAP)]
    with pytest.raises((ValueError, SystemExit)):
        native.main(args)
    assert calls == []
