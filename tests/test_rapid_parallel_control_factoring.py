"""Real control-source projections and bounded operation-local reuse."""
from __future__ import annotations

import ast
import copy
import subprocess
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_rolling_schedule as schedule
from qcsd_lab import rapid_rolling_readiness as readiness
from tests.test_rapid_rolling_schedule_source import source_bytes
from tests.test_rapid_lane_evidence import setup as ordinary_setup
from tests.test_rapid_formal_parallel import formal_setup, _prepare


ROOT = Path(__file__).resolve().parents[1]
BASE = "7b47cb5b1d507f2b94bb493f7c724f1f86d2b460"
FRONT_BASE = "209bcf35d0e12bba8282a32ec66ae67a524ba7cc"


def retained(path, revision=BASE):
    return subprocess.run(["git", "show", f"{revision}:{path}"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def control_baseline():
    """Choose an explicit retained physics revision, never waive a byte edit."""
    paths = {"src/qcsd_lab/" + name + ".py"
             for names in readiness.DEPENDENCY_FILES.values() for name in names}
    paths.update(readiness.STATIC_MEASUREMENT_FILES - {"qcsd-lab"})
    for revision in (BASE, FRONT_BASE):
        if all(retained(path, revision) == (ROOT / path).read_bytes() for path in paths):
            return revision
    raise AssertionError("current scientific bytes match neither retained control baseline")


def test_actual_control_source_keeps_all_scientific_groups(source_bytes):
    baseline = control_baseline()
    old = {path: retained(path, baseline) if not path.startswith("neqo-qcsd/") else raw
           for path, raw in source_bytes.items()}
    old[schedule.MODULE_FILE] = retained(schedule.MODULE_FILE)
    new = {path: (ROOT / path).read_bytes() for path in old}
    comparison = schedule.source_changes(old, new, client_sha256="a" * 64)
    unchanged = schedule.source_changes(old, old, client_sha256="a" * 64)
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert comparison[key] == unchanged[key]
    assert comparison["changed_sources"][schedule.MODULE_FILE]["units"] == [
        "scheduling-v2-pre-birth-release-authority"]
    assert comparison["changed_sources"]["tools/rapid_parallel_capture.py"]["units"] == [
        "_host_authority", "declared-repository-import-bootstrap", "launch", "main"]


def test_historical_projection_is_byte_for_byte_legacy_result(source_bytes):
    old_helper = retained(schedule.MODULE_FILE)
    legacy = types.ModuleType("qcsd_lab._retained_scheduling_v1")
    legacy.__package__ = "qcsd_lab"
    legacy.__file__ = str(ROOT.parent.parent / "rapid-execution-rolling-parallel-v6-20261004" / schedule.MODULE_FILE)
    assert Path(legacy.__file__).read_bytes() == old_helper
    exec(compile(old_helper, legacy.__file__, "exec"), legacy.__dict__)
    new = {path: retained(path) if not path.startswith("neqo-qcsd/") else raw
           for path, raw in source_bytes.items()}
    new[schedule.MODULE_FILE] = old_helper
    expected = legacy.source_changes(source_bytes, new, client_sha256="b" * 64)
    actual = schedule.source_changes(source_bytes, new, client_sha256="b" * 64,
                                     contract=schedule.CONTRACT_V1)
    assert actual == expected
    assert schedule.V1_CONTROL_DEFINITIONS == legacy.CONTROL_DEFINITIONS
    assert schedule.NEW_FILES == legacy.NEW_FILES


@pytest.mark.parametrize("mutation", ["foreign_root", "after_import", "duplicate"])
def test_import_projection_rejects_different_bootstrap(source_bytes, mutation):
    path = "tools/rapid_parallel_capture.py"
    old = {**source_bytes, schedule.MODULE_FILE: retained(schedule.MODULE_FILE)}
    new = {**old, path: (ROOT / path).read_bytes(), schedule.MODULE_FILE: (ROOT / schedule.MODULE_FILE).read_bytes()}
    raw = new[path]
    bootstrap = b'_ROOT = Path(__file__).resolve().parents[1]\nsys.path.insert(0, str(_ROOT / "src"))\n'
    assert bootstrap in raw
    if mutation == "foreign_root":
        new[path] = raw.replace(b'_ROOT / "src"', b'Path("/foreign")')
    elif mutation == "after_import":
        new[path] = raw.replace(bootstrap, b"").replace(
            b"from qcsd_lab import rapid_parallel_capture as parallel\n",
            b"from qcsd_lab import rapid_parallel_capture as parallel\n" + bootstrap)
    else:
        new[path] = raw.replace(bootstrap, bootstrap + bootstrap)
    with pytest.raises(ValueError):
        schedule.source_changes(old, new, client_sha256="c" * 64)


def test_v1_does_not_gain_v2_release_units(source_bytes):
    path = "src/qcsd_lab/rapid_formal_parallel.py"
    old = {**source_bytes, schedule.MODULE_FILE: retained(schedule.MODULE_FILE)}
    new = {**old, path: (ROOT / path).read_bytes()}
    with pytest.raises(ValueError, match="outside named control"):
        schedule.source_changes(old, new, client_sha256="c" * 64, contract=schedule.CONTRACT_V1)


def test_operation_local_readiness_roots_are_not_persistent(tmp_path, monkeypatch):
    from qcsd_lab import rapid_rolling_capture as rolling
    capsule, intent, plan = (tmp_path / name for name in ("capsule.json", "intent.json", "plan.json"))
    formal.shared.put(capsule, {"closed": "fixture"})
    formal.shared.put(intent, {"same": "intent"})
    formal.ordinary._create(tmp_path, plan, formal.ordinary.PLAN_TYPE,
                            {"scheduling": rolling._ref(capsule)})
    spec = SimpleNamespace(plan_receipt=plan, serializable=lambda: {"same": "spec"})
    fact = (spec, tmp_path, intent, {}, {}, SimpleNamespace(study_version=6, campaign_name="lane"), ())
    calls = []
    monkeypatch.setattr(rolling, "readiness_roots", lambda *args: calls.append(1) or [tmp_path])
    first = formal.worker_environment({"installation": None}, 0, fact=fact)
    local = formal.worker_environment({"installation": None}, 0, fact=fact, _readiness_roots=[tmp_path])
    second = formal.worker_environment({"installation": None}, 0, fact=fact)
    assert first == local == second and calls == [1, 1]
    intent.write_bytes(b"changed actual intent")
    assert formal.worker_environment({"installation": None}, 0, fact=fact) != first
    assert calls == [1, 1, 1]


def test_real_pair_constructs_each_lineage_once_and_preserves_exact_output(formal_setup, monkeypatch):
    original = formal.ordinary._lineage_payload
    constructions = []
    def construct(*args, **kwargs):
        constructions.append(args[1].campaign_name)
        return original(*args, **kwargs)
    monkeypatch.setattr(formal.ordinary, "_lineage_payload", construct)
    batch = _prepare(formal_setup)
    assert constructions == [lane.campaign_name for lane in batch.lanes]
    for reference, lane in zip(batch.value["lane_intents"], batch.lanes, strict=True):
        path = Path(reference["path"])
        lineage = formal.ordinary._payload(path.parent / "lineage.json", formal.ordinary.LINEAGE_TYPE)
        expected = original(formal_setup.spec, lane, lineage["image_check"], formal_setup.root, None)
        assert lineage == expected
        assert not (path.parent / "complete.json").exists()


def test_shell_closes_preparation_and_transports_digest_before_birth():
    raw = (ROOT / "qcsd-lab").read_text()
    begin = raw.index('  parallel_prepared_sha256=""')
    end = raw.index('  parallel_retired=(0 0)', begin)
    region = raw[begin:end]
    assert region.index("prepare-release") < region.index("start_kernel_tx_public_router")
    assert region.index("prepare-release") < region.index("qcsd_run_detached_docker")
    assert '--prepared-sha256 "${parallel_prepared_sha256}"' in region
    assert '--label "org.qcsd.release-preparation-sha256=${parallel_prepared_sha256}"' in region
    assert region.index("actual-launch.json") < region.rindex("parallel_python release")
    gate = (ROOT / "src/qcsd_lab/rapid_parallel_capture.py").read_text()
    assert "time.monotonic() + 120" in gate
