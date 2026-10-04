"""The lifecycle ordering amendment preserves the two historical contracts."""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import subprocess
import zlib
from pathlib import Path

import pytest

from qcsd_lab import rapid_rolling_schedule as schedule


ROOT = Path(__file__).resolve().parents[1]
HELPER = schedule.MODULE_FILE
GUARDIAN = "tools/docker_lifecycle_lock_guardian.py"
PARALLEL = "src/qcsd_lab/rapid_parallel_capture.py"
CHANGED = {"qcsd-lab", HELPER, GUARDIAN, PARALLEL}
V2_FIXTURE = ROOT / "tests/fixtures/rapid_parallel_scheduling_v2.json.zlib.b85.txt"
V2_FIXTURE_SHA256 = "86fdebfa267f3b5a861992bae3d4776da18148b7ac04fb1592dd392a9fcb3aaf"
V2_SOURCE_COMMIT = "65794a16dc59615cfa46b5fbb4e2d9a13f97640a"


def retained_sources():
    """Reopen four immutable source blobs without Git history or a remote."""
    raw = V2_FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == V2_FIXTURE_SHA256
    value = json.loads(raw)
    assert value["schema_version"] == 1 and value["artifact_type"] == "qcsd-immutable-source-fixture"
    assert value["source_commit"] == V2_SOURCE_COMMIT and value["encoding"] == "zlib-base85"
    assert set(value["files"]) == CHANGED
    sources = {}
    for path, item in value["files"].items():
        source = zlib.decompress(base64.b85decode(item["encoded_source"]))
        assert len(source) == item["uncompressed_bytes"]
        assert hashlib.sha256(source).hexdigest() == item["sha256"]
        sources[path] = source
    assert hashlib.sha256(sources[HELPER]).hexdigest() == schedule.V2_HELPER_SHA256
    return sources


def retained(path):
    return retained_sources()[path]


def tracked_sources(root, prefix=""):
    names = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.split(b"\0")
    return {prefix + name.decode(): (root / name.decode()).read_bytes()
            for name in names if name and (root / name.decode()).is_file()}


@pytest.fixture(scope="module")
def sources():
    current = {**tracked_sources(ROOT), **tracked_sources(ROOT / "neqo-qcsd", "neqo-qcsd/")}
    before = {**current, **retained_sources()}
    after = {**current, **{path: (ROOT / path).read_bytes() for path in CHANGED}}
    assert schedule.evidence._sha(before[HELPER]) == schedule.V2_HELPER_SHA256
    return before, after


@pytest.fixture(scope="module")
def historical(tmp_path_factory):
    path = tmp_path_factory.mktemp("historical-validator") / "retained_v2.py"
    path.write_bytes(retained(HELPER))
    spec = importlib.util.spec_from_file_location("qcsd_lab._guardian_retained_v2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(old, new, *, contract=schedule.CONTRACT):
    return schedule.source_changes(old, new, client_sha256="a" * 64, contract=contract)


def test_four_actual_control_edits_preserve_complete_native_science_and_eight_acquisition_groups(sources):
    before, after = sources
    actual, unchanged = check(before, after), check(before, before)
    assert set(actual["changed_sources"]) == CHANGED
    assert actual["changed_sources"][GUARDIAN]["units"] == ["ready-timeout-diagnostic"]
    assert actual["changed_sources"][HELPER]["units"] == ["scheduling-v5-operation-local-verification-facts-authority"]
    assert {"lifecycle_inputs", "formal_entry_inputs", "main", "authority", "image_preflight",
            "initialize", "gate", "_require_result_birth", "verify_results",
            "verify_results_in_image"} == set(actual["changed_sources"][PARALLEL]["units"])
    assert len(actual["dependency_groups"]["native"]) > 1700
    assert len(actual["acquisition_source_groups"]) == 8
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert actual[key] == unchanged[key]


@pytest.mark.parametrize("contract", [schedule.CONTRACT_V1, schedule.CONTRACT_V2])
def test_historical_projection_results_remain_exact(sources, historical, contract):
    before, _ = sources
    changed = dict(before)
    tree = ast.parse(changed["src/qcsd_lab/rapid_formal_parallel.py"])
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_audit")
    node.body.insert(0, ast.parse("historical_control_probe = True").body[0])
    changed["src/qcsd_lab/rapid_formal_parallel.py"] = ast.unparse(tree).encode()
    expected = historical.source_changes(before, changed, client_sha256="a" * 64, contract=contract)
    assert check(before, changed, contract=contract) == expected


@pytest.mark.parametrize("contract", [schedule.CONTRACT_V1, schedule.CONTRACT_V2])
def test_old_contract_cannot_authorize_new_guardian_or_entry_helpers(sources, contract):
    before, after = sources
    for path in (GUARDIAN, PARALLEL):
        with pytest.raises(ValueError):
            check(before, {**before, path: after[path]}, contract=contract)


@pytest.mark.parametrize("mutation", ["ready-timeout", "recovery-timeout", "condition", "moved-print", "duplicate-print"])
def test_guardian_projection_does_not_allow_timeout_or_recovery_changes(sources, mutation):
    before, after = sources
    raw = after[GUARDIAN]
    diagnostic = b'                print("qcsd-lab Docker lifecycle guardian: initial READY handshake timed out before admission", file=sys.stderr)\n'
    if mutation == "ready-timeout":
        old = b"READY_TIMEOUT_SECONDS = 30.0"
        assert raw.count(old) == 1
        raw = raw.replace(old, b"READY_TIMEOUT_SECONDS = 300.0")
    elif mutation == "recovery-timeout":
        old = b"RECOVERY_IDLE_TIMEOUT_SECONDS = 360.0"
        assert raw.count(old) == 1
        raw = raw.replace(old, b"RECOVERY_IDLE_TIMEOUT_SECONDS = 3600.0")
    elif mutation == "condition":
        old = b"if now >= ready_deadline and not ready:"
        assert raw.count(old) == 1
        raw = raw.replace(old, b"if now >= ready_deadline and not ready and False:")
    elif mutation == "moved-print":
        assert raw.count(diagnostic) == 1
        original = diagnostic + b"                failed = True\n"
        assert raw.count(original) == 1
        raw = raw.replace(original, b"                failed = True\n" + diagnostic)
    else:
        assert raw.count(diagnostic) == 1
        raw = raw.replace(diagnostic, diagnostic + diagnostic)
    with pytest.raises(ValueError):
        check(before, {**after, GUARDIAN: raw})


@pytest.mark.parametrize("path", ["src/qcsd_lab/fidelity.py", "src/qcsd_lab/capture_session.py",
    "src/qcsd_lab/chaff_qualification.py", "src/qcsd_lab/cdp_targets.py",
    "config/defense-params/buflo-live.json", "neqo-qcsd/neqo-bin/src/qcsd/mod.rs"])
def test_lifecycle_scheduling_contract_rejects_scientific_source_changes(sources, path):
    before, after = sources
    suffix = b"\nUNREVIEWED_LIFECYCLE_STATE = True\n" if path.endswith(".py") else b"\n// unreviewed bytes\n"
    with pytest.raises(ValueError):
        check(before, {**after, path: after[path] + suffix})
