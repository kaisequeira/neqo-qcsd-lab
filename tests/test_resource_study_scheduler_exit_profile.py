"""Source identity controls only; no admission, capture or historical raw replay."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from qcsd_lab import resource_study_reader_compatibility as compatibility

MONITOR_SHA256 = "8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf"
OLD_MONITOR_SHA256 = "bee4213504292059121871b94599a10b286f8776517e65c8022404fabe1555d0"
HELPER_SHA256 = "c7d4f5a9983b7f09f82f0279188136b287662adbf41a303630e8cc01eb582e93"
GRAPH_SHA256 = "bae215a4bb7ef5190c20329533a6ddb2a932396d9ed88bf161d745de8e683396"
CONTRACT_SHA256 = "2d9b7a5bfa67c024f15597b941be57c0b6c54532a69801213c7a2580fd95b180"


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False) + "\n").encode()


def _profile(files):
    return {"record_type": "qcsd-resource-domain-runtime-cohort-verifier-contract-v1",
        "schema_version": 1, "implementation": "resource-study-raw-v1",
        "files": {name: files[name] for name in compatibility.PRIMARY_FILES},
        "transitive_source_sha256": hashlib.sha256(_encoded(files)).hexdigest(),
        "transitive_source_files": len(files),
        "transitive_source_scope": "complete declared package-import closure; conservative dormant branches included"}


def _actual_files():
    root = Path(compatibility.__file__).resolve().parent
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in compatibility.execution_files()}


def _qualified():
    return compatibility.qualify_execution(_profile(_actual_files()))


def test_source051_binds_actual_monitor_helper_and_distinct_complete_graph():
    files = _actual_files()
    assert files == compatibility.execution_files()
    assert len(files) == 170
    assert files["process_scheduler.py"] == MONITOR_SHA256
    assert files[compatibility.HELPER_NAME] == HELPER_SHA256
    current = _profile(files)
    assert current["transitive_source_sha256"] == GRAPH_SHA256
    assert hashlib.sha256(_encoded(current)).hexdigest() == CONTRACT_SHA256
    assert compatibility.EXECUTION_KIND == "051"
    qualified = compatibility.qualify_execution(current)
    binding = compatibility.execution_binding(current, qualified)
    assert binding["record_type"] == "qcsd-resource-domain-017-018-019-045-051-reader-execution-binding-v1"
    assert binding["execution_reader"] == current
    assert binding["execution_reader_is_admission_reader"] is True
    assert binding["capture_scheduler_task_exit_race_monitor_changed"] is True
    assert binding["historical_receipts_requalified_by_compatibility"] is False
    assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0


def test_dated045_graph_keeps_its_original_monitor_and_helper():
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_ANALYSIS_EXECUTION_FILES)
    assert len(files) == 170
    assert files["process_scheduler.py"] == OLD_MONITOR_SHA256
    assert files[compatibility.HELPER_NAME] == "33fca2234bac94f484a0a917564f4e2ccbd83d0eb86bc74aa2fca9c941277d7a"
    assert hashlib.sha256(_encoded(files)).hexdigest() == "e94de1cf8c890f1e4f90ea8287d30c3c1ab9faa4b1dbcac1ed4c70f4b2cadce0"
    dated = _profile(files)
    assert dated == compatibility.prior_analysis_execution_contract()
    assert hashlib.sha256(_encoded(dated)).hexdigest() == "2bee8641e6cb774cab67e030b6672bf1a79144e8d94082ae83ada9d198fecbc1"
    assert {name for name, digest in _actual_files().items() if files[name] != digest} == {
        "process_scheduler.py", compatibility.HELPER_NAME}
    dated["files"].clear()
    assert len(compatibility.prior_analysis_execution_contract()["files"]) == 10


@pytest.mark.parametrize("version", ["017", "018", "019", "045"])
def test_exact_historical_profiles_remain_supported_without_current_identity_alias(version):
    factories = {"017": compatibility.legacy_contract,
        "018": compatibility.prior_execution_contract,
        "019": compatibility.prior_capture_execution_contract,
        "045": compatibility.prior_analysis_execution_contract}
    dated = factories[version]()
    original = _encoded(dated)
    qualified = _qualified()
    assert compatibility.require_supported(dated, qualified) is True
    assert compatibility.admission_contract(dated, qualified) == dated
    binding = compatibility.execution_binding(dated, qualified)
    assert binding["admission_reader"] == dated
    assert binding["admission_reader_preserved"] is True
    assert binding["execution_reader_is_admission_reader"] is False
    assert binding["execution_reader"]["files"]["process_scheduler.py"] == MONITOR_SHA256
    with pytest.raises(ValueError, match="Source051 execution reader"):
        compatibility.qualify_execution(dated)
    binding["admission_reader"]["files"].clear()
    assert _encoded(dated) == original


@pytest.mark.parametrize("change", ["monitor", "helper", "missing", "extra", "old-monitor"])
def test_unapproved_current_execution_hashes_or_surface_refused(change):
    files = _actual_files()
    if change == "monitor":
        files["process_scheduler.py"] = "0" * 64
    elif change == "helper":
        files[compatibility.HELPER_NAME] = "0" * 64
    elif change == "missing":
        files.pop("capture_session.py")
    elif change == "extra":
        files["operator_approved.py"] = "0" * 64
    else:
        files["process_scheduler.py"] = OLD_MONITOR_SHA256
    with pytest.raises(ValueError, match="Source051 execution reader"):
        compatibility.qualify_execution(_profile(files))


@pytest.mark.parametrize("change", ["monitor", "primary", "closure", "schema"])
def test_changed_dated045_profile_is_not_an_approved_historical_lookup(change):
    dated = deepcopy(compatibility.prior_analysis_execution_contract())
    if change == "monitor":
        dated["files"]["process_scheduler.py"] = MONITOR_SHA256
    elif change == "primary":
        dated["files"]["resource_study_verify.py"] = "0" * 64
    elif change == "closure":
        dated["transitive_source_sha256"] = GRAPH_SHA256
    else:
        dated["schema_version"] = True
    with pytest.raises(ValueError, match="admission reader"):
        compatibility.require_supported(dated, _qualified())
