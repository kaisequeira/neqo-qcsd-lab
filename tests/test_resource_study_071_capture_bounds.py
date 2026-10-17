"""Offline Source071 timeout/role controls; mocked collection is never live proof."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from qcsd_lab import buflo_duration_budget as budget
from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_inputs import sha256_file


PARENT070_PRODUCER_FILES = {'resource_study.py': '75fc033a2c4d80dafba0d1e1e9b86cc9128a4af4f7abc1a3b4472b3c32c29047', 'resource_study_runtime.py': '984afdef4cd3e35b9c644dab791c14cd0aa96e6d0e740b52f8a06ea8ca0b34ec', 'resource_study_store.py': '9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb', 'resource_study_verify.py': '82f4bfafe4987f118bda6c3ba4b9cebe2a3a78414effbf198457df56020ba235', 'resource_study_inputs.py': '899b78d50063eea6c30140397b2342d900701d44aed8f1bfe9afb30abe9ffd2b', 'resource_study_storage.py': '20d4562f42461609c51c00f514eb22edebd8b123bb3824b3377a44b5f3a63db1', 'resource_study_supplements.py': '519b77d8f8305a8e77ad88f541f75a2e69845c8bdbb09a8192043f0a56042f2b', 'resource_study_epochs.py': '31ca54fd09cfc05c6ac94c1e11855638acfba8dd7d165cea0c7347beddebaf8e', 'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20', 'resource_study_audit.py': 'ee81e0506787a5414c6bcad438a02c7a468065890285542eba0b5e7f43b891c8', 'resource_study_cohorts.py': 'e7569bf189039339823ac5c81636e5a92a7429444a87427f0f6551ed6d8ae538', 'fidelity.py': '149fbf8049c359478f47427b2f5ae26252869454a24d00b0c6d8459abf533dd8', 'capture.py': 'c37a0444c62e77068891281fa72200bdc2c07192ee8e4e05a9832bfe1a681c99', 'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf', 'resource_study_integrity.py': '7ce3265d78ca7d88714e8018fe36b88a04b52276dd6fd07108fe9ec128af7b12', 'resource_study_selection.py': '6f06c6bef2953d6b480949281b4e889ad7412aca7f2e6bc3c500130234b0e99e', 'resource_study_lineage.py': '5f8633b96f5d6485cf785dd24d037c8933e074ceb03d268ff9ed04546ac444f4'}
EXPECTED071_RUNTIME_SHA256 = '868129929c305573017cbb7843bcb067222bab9a6b13e2ccb0e84258812913be'
# A synthetic image identifier keeps worker-schema tests offline. The source
# role is the genuine installed070 runtime, separate from current071 coordinator.
INSTALLED070_RUNTIME = {
    "collection_image_digest": "sha256:" + "7" * 64,
    "native_commit": "a2d1cedd1923543365532a769e195aba5576aae5",
    "client_sha256": "1" * 64,
    "source": {"lab_commit": "368c56eab15f11d2bee3069bb8f5ae48ec8ad00e"},
}


def duration_enrollment(policy):
    if policy is None:
        return {"preparation_dir": "prepared"}
    parameters = (budget.CADENCE64_1280_PARAMETERS
                  if policy == budget.CADENCE64_1280_POLICY else budget.CADENCE64_PARAMETERS)
    return {"preparation_dir": "prepared",
            "mode_policies": {"buflo": {"buflo_duration_policy": policy}},
            "mode_settings": {"buflo": {
                "parameters": deepcopy(parameters),
                **budget.capture_limits("buflo", {"timeout_seconds": 120, "capture_seconds": 180},
                                        policy=policy)}}}


def capture_fixture(runtime_type, tmp_path, monkeypatch):
    # Exercise the complete actual capture method without creating containers,
    # preparing workloads, accepting a session, or opening a history database.
    engine = runtime_type.__new__(runtime_type)
    engine.root = tmp_path / "root"
    engine.runtime = deepcopy(INSTALLED070_RUNTIME)
    engine.workers = [{"id": "owned-offline-worker", "helper": 3,
                       "partition_sha256": "2" * 64}]
    engine.class_routes = {"assets.example.org": {"environment": {"EXPLICIT_ROLE": "installed070"}}}
    engine.cell_roots = {"assets.example.org": tmp_path / "other-root"}
    attachment = {"record_type": "offline-attachment"}
    engine._activate = lambda index, hostname: attachment
    writes, calls = {}, []

    def put(path, value):
        writes[Path(path)] = deepcopy(value)

    def docker(*arguments, timeout=120):
        calls.append((list(arguments), timeout))
        return json.dumps({"success": False, "result": {"success": False},
                           "resource_error": "offline refusal remains uncredited",
                           "mode_policies": {}})

    monkeypatch.setattr(runtime, "_put", put)
    monkeypatch.setattr(runtime, "_docker", docker)
    attempt = {"hostname": "assets.example.org", "mode": "buflo",
               "path": "attempts/offline", "attempt_id": "a" * 32}
    return engine, attempt, writes, calls


@pytest.mark.parametrize("runtime_type", [runtime.CaptureRuntime, runtime.MultiRootCaptureRuntime])
def test_071_both_capture_calls_follow_enrolled_bound_and_keep_installed070_job(
        tmp_path, monkeypatch, runtime_type):
    engine, attempt, writes, calls = capture_fixture(runtime_type, tmp_path, monkeypatch)
    fixtures = [("buflo", None, 850), ("buflo", budget.CADENCE64_POLICY, 850),
                ("front", budget.CADENCE64_1280_POLICY, 850),
                ("buflo", budget.CADENCE64_1280_POLICY, 1490)]
    for mode, policy, expected in fixtures:
        attempt["mode"] = mode
        enrollment = duration_enrollment(policy)
        result = engine.capture(0, attempt, enrollment)
        arguments, actual_timeout = calls[-1]
        assert actual_timeout == expected
        assert type(actual_timeout) is int
        assert arguments[-8:-2] == ["/opt/qcsd-venv/bin/python3", "-I", "-B", "-m",
                                   "qcsd_lab.resource_study_native", "_capture"]
        assert arguments[-2] == "--job"
        job_path = Path(arguments[-1])
        job = writes[job_path]
        assert set(job) == {"hostname", "mode", "enrollment_dir", "attempt_dir", "seed", "runtime"}
        root = engine.cell_roots[attempt["hostname"]] if runtime_type is runtime.MultiRootCaptureRuntime else engine.root
        assert job_path == root / attempt["path"] / "job.json"
        assert job["enrollment_dir"] == str(root / "prepared")
        assert job["mode"] == mode and job["hostname"] == attempt["hostname"]
        assert job["seed"] == int(attempt["attempt_id"][:16], 16)
        assert job["runtime"] == INSTALLED070_RUNTIME
        assert result["success"] is False
        assert result["resource_error"] == "offline refusal remains uncredited"
    # Only the exact longer policy gains lifetime; old070 sends850 here and
    # therefore fails the final case without reaching any real Docker process.
    assert [timeout for _, timeout in calls] == [850, 850, 850, 1490]


def test_071_capture_bound_rejects_forged1280_tuple_settings_before_docker(tmp_path, monkeypatch):
    engine, attempt, _writes, calls = capture_fixture(runtime.CaptureRuntime, tmp_path, monkeypatch)
    original = duration_enrollment(budget.CADENCE64_1280_POLICY)
    mutations = []
    for key, value in (("timeout_seconds", 1321), ("capture_seconds", 1381),
                       ("capture_seconds", True)):
        forged = deepcopy(original)
        forged["mode_settings"]["buflo"][key] = value
        mutations.append(forged)
    forged = deepcopy(original)
    forged["mode_settings"]["buflo"]["parameters"]["max_events"] = 20001
    mutations.append(forged)
    forged = deepcopy(original)
    forged["mode_settings"]["buflo"]["parameters"][budget.PARAMETER_FIELD] = budget.CADENCE64_POLICY
    mutations.append(forged)
    for enrollment in mutations:
        with pytest.raises(ValueError):
            engine.capture(0, attempt, enrollment)
        assert not calls
    unknown = deepcopy(original)
    unknown["mode_policies"]["buflo"]["buflo_duration_policy"] = "unknown-policy"
    # The timeout helper grants no extension to unknown policy. Complete
    # enrollment/admission validation remains the original upstream authority.
    assert runtime._capture_call_timeout_seconds("buflo", unknown) == 850


def test_071_public_coordinator_producer_is_distinct_from_installed070_collector():
    producer = study.coordinator_provenance(resource_selection=True, class_selection=True)
    source = Path(study.__file__).parent
    actual = {name: sha256_file(source / name) for name in PARENT070_PRODUCER_FILES}
    assert producer == {"record_type": "qcsd-resource-study-host-code-v1", "files": actual,
                        "installed_native_and_sdk": "recorded separately in runtime"}
    assert len(actual) == 17
    assert actual["resource_study_runtime.py"] == EXPECTED071_RUNTIME_SHA256
    assert actual["resource_study_runtime.py"] != PARENT070_PRODUCER_FILES["resource_study_runtime.py"]
    assert actual["resource_study_cohorts.py"] != PARENT070_PRODUCER_FILES["resource_study_cohorts.py"]
    assert actual["resource_study.py"] != PARENT070_PRODUCER_FILES["resource_study.py"]
    assert {name for name in actual if actual[name] != PARENT070_PRODUCER_FILES[name]} == {
        "resource_study.py", "resource_study_runtime.py", "resource_study_cohorts.py"}
    # Worker native job reader/collector code is unchanged070. It does not
    # acquire the public coordinator's new071 producer identity by reuse.
    assert sha256_file(Path(native.__file__)) == "6565608516fad575b6f7065cf19aeb4959b2aff03b5233ebb1552102c9e363c0"
    assert "resource_study_native.py" not in producer["files"]
    assert INSTALLED070_RUNTIME["source"]["lab_commit"] == "368c56eab15f11d2bee3069bb8f5ae48ec8ad00e"
