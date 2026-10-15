"""Source024 controls retaining the Source020 immutable profile-byte cache.

These fixtures exercise reader identities and real SourceOperation boundaries.
They create no SQL database, admission, receipt or scientific credit. The
optional benchmark compares equivalent decisions and reports timings without
asserting a speed threshold or changing a production predicate.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from time import perf_counter_ns, process_time_ns

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility
from qcsd_lab.resource_study_inputs import canonical_json


def profiles():
    return (compatibility.legacy_contract(), compatibility.prior_execution_contract(),
        compatibility.prior_capture_execution_contract(), cohorts.verifier_contract())


def uncached_supported(admission, current):
    """Equivalent reference rebuilding all supported profile bytes per call."""
    return canonical_json(admission) in tuple(canonical_json(value) for value in (
        compatibility.legacy_contract(), compatibility.prior_execution_contract(),
        compatibility.prior_capture_execution_contract(), current))


def test_exact_source019_profile_is_preserved_as_a_distinct_supported_reader():
    old = compatibility.prior_capture_execution_contract()
    files = dict(compatibility.LEGACY_FILES)
    files.update(compatibility.PRIOR_CAPTURE_EXECUTION_FILES)
    assert compatibility.EXECUTION_KIND == "024"
    assert compatibility.PRIOR_CAPTURE_HEAD == "7c474b65caa44cb07c4a67f9b647a4fb8d44e355"
    assert len(files) == old["transitive_source_files"] == 170
    assert hashlib.sha256(canonical_json(files)).hexdigest() == old["transitive_source_sha256"]
    assert old["transitive_source_sha256"] == "335fc8497535ad3ea04dcbe8c66503265890b87dc9726d73f91d3f35dbea7d1c"
    assert hashlib.sha256(canonical_json(old)).hexdigest() == "0903a79cd1c64e09c81d912a872fb37a6301f98c564da9216db9a0d36ab0b9f8"
    current = cohorts.verifier_contract()
    assert current != old and current["files"] == old["files"]
    pair = compatibility.qualify_execution(current)
    assert compatibility.require_supported(old, pair) is True
    binding = compatibility.execution_binding(old, pair)
    assert binding["record_type"] == "qcsd-resource-domain-017-018-019-024-reader-execution-binding-v1"
    assert binding["admission_reader"] == old and binding["execution_reader"] == current
    assert binding["execution_reader_is_admission_reader"] is False
    old["files"].clear()
    assert len(compatibility.prior_capture_execution_contract()["files"]) == 10


@pytest.mark.parametrize("index", range(4))
def test_supported_profiles_match_the_uncached_reference_without_aliases(index):
    values = profiles()
    current, admission = values[-1], values[index]
    pair = compatibility.qualify_execution(current)
    original = canonical_json(admission)
    assert uncached_supported(admission, current) is True
    assert compatibility.require_supported(admission, pair) is True
    selected = compatibility.admission_contract(admission, pair)
    binding = compatibility.execution_binding(admission, pair)
    selected["files"].clear()
    binding["admission_reader"]["files"].clear()
    binding["execution_reader"]["files"].clear()
    assert canonical_json(admission) == original
    assert pair.contract() == current
    assert compatibility.require_supported(admission, pair) is True


@pytest.mark.parametrize("index", range(3))
def test_supported_historical_reader_cannot_alias_actual_source024_execution(index):
    with pytest.raises(ValueError, match="Source024 execution"):
        compatibility.qualify_execution(profiles()[index])


@pytest.mark.parametrize("change", ["primary", "closure", "count", "schema", "extra", "missing", "none", "nan"])
def test_cached_supported_bytes_preserve_malformed_and_unknown_refusals(change):
    current = cohorts.verifier_contract()
    value = compatibility.prior_capture_execution_contract()
    if change == "primary": value["files"]["fidelity.py"] = "0" * 64
    elif change == "closure": value["transitive_source_sha256"] = "0" * 64
    elif change == "count": value["transitive_source_files"] = 169
    elif change == "schema": value["schema_version"] = True
    elif change == "extra": value["operator_override"] = True
    elif change == "missing": del value["implementation"]
    elif change == "none": value = None
    else: value["schema_version"] = float("nan")
    pair = compatibility.qualify_execution(current)
    if change == "nan":
        with pytest.raises(ValueError): uncached_supported(value, current)
    else:
        assert uncached_supported(value, current) is False
    with pytest.raises(ValueError): compatibility.require_supported(value, pair)


def test_supported_profiles_are_constructed_once_per_qualified_object(monkeypatch):
    values = profiles()
    original = compatibility._profile
    constructions = []

    def observed(files):
        constructions.append(len(files))
        return original(files)

    monkeypatch.setattr(compatibility, "_profile", observed)
    pair = compatibility.qualify_execution(values[-1])
    assert constructions == [170, 169, 170, 170]
    before = tuple(constructions)
    for _ in range(20):
        for value in values:
            assert compatibility.require_supported(value, pair) is True
            assert compatibility.admission_contract(value, pair) == value
            assert compatibility.execution_binding(value, pair)["execution_reader"] == values[-1]
    assert tuple(constructions) == before
    another = compatibility.qualify_execution(values[-1])
    assert another is not pair and constructions == list(before) * 2


def test_cached_profiles_are_immutable_across_explicit_worker_threads():
    values = profiles()
    pair = compatibility.qualify_execution(values[-1])
    encoded_before = tuple(canonical_json(value) for value in values)

    def worker(index):
        value = values[index % 4]
        assert compatibility.require_supported(value, pair) is True
        selected = compatibility.admission_contract(value, pair)
        selected["files"].clear()
        current = pair.contract()
        current["files"].clear()
        bad = deepcopy(value)
        bad["transitive_source_sha256"] = "0" * 64
        with pytest.raises(ValueError): compatibility.require_supported(bad, pair)
        return compatibility.execution_binding(value, pair)

    with ThreadPoolExecutor(max_workers=4) as executor:
        bindings = list(executor.map(worker, range(32)))
    assert tuple(canonical_json(value) for value in values) == encoded_before
    assert all(value["execution_reader"] == values[-1] for value in bindings)
    assert pair.contract() == values[-1]


@pytest.mark.parametrize("name,restore", [(None, False),
    ("fidelity.py", False), ("fidelity.py", True),
    (compatibility.HELPER_NAME, False), (compatibility.HELPER_NAME, True)])
def test_real_source_operation_still_fences_cached_profiles_and_worker_handoff(tmp_path, monkeypatch, name, restore):
    # This marker opts a temporary, database-free fixture into the original
    # source scope. It is not a valid membership or admission and is never
    # passed to a membership/ledger/raw reader.
    base = tmp_path.resolve()
    root, source = base / "study", base / "source"
    root.mkdir(); source.mkdir()
    (root / cohorts.MARKER).write_bytes(b"source-scope-only fixture\n")
    original_source = Path(cohorts.__file__).parent
    for filename in cohorts.RAW_DEPENDENCIES:
        path = source / filename
        path.write_bytes((original_source / filename).read_bytes())
        path.chmod(0o644)
    monkeypatch.setattr(cohorts, "__file__", str(source / "resource_study_cohorts.py"))
    monkeypatch.setattr(compatibility, "__file__", str(source / compatibility.HELPER_NAME))

    def no_sql(*args, **kwargs):
        raise AssertionError("source-only fixture must not open SQL")

    monkeypatch.setattr(sqlite3, "connect", no_sql)
    hashed = []
    original_hash = cohorts.sha256_file

    def observed_hash(path):
        hashed.append(Path(path).name)
        return original_hash(path)

    monkeypatch.setattr(cohorts, "sha256_file", observed_hash)

    def bound_worker(auth):
        with cohorts.bind_source(auth):
            current = cohorts.verifier_contract()
            return compatibility.require_supported(compatibility.prior_capture_execution_contract(),
                compatibility.qualify_execution(current))

    if name is None:
        with cohorts.source_operation(root) as auth:
            with ThreadPoolExecutor(max_workers=1) as executor:
                assert executor.submit(bound_worker, auth).result(timeout=10) is True
        assert set(hashed) == set(cohorts.RAW_DEPENDENCIES)
        assert all(hashed.count(filename) == 2 for filename in cohorts.RAW_DEPENDENCIES)
    else:
        with pytest.raises(ValueError, match="Source"):
            with cohorts.source_operation(root) as auth:
                # Qualify before the controlled temporary-file mutation.
                pair = compatibility.qualify_execution(cohorts.verifier_contract())
                assert compatibility.require_supported(compatibility.legacy_contract(), pair) is True
                path = source / name
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n# controlled source mutation\n")
                if restore: path.write_bytes(raw)
                with ThreadPoolExecutor(max_workers=1) as executor:
                    with pytest.raises(ValueError, match="Source"):
                        executor.submit(bound_worker, auth).result(timeout=10)
    with pytest.raises(ValueError, match="closed"):
        with cohorts.bind_source(auth):
            cohorts.verifier_contract()
    assert not (root / "ledger.sqlite3").exists()


@pytest.mark.skipif(os.environ.get("QCSD_PROFILE_CACHE_BENCHMARK") != "1", reason="ROOT-only optional timing report")
def test_profile_cache_benchmark_reports_equivalent_decisions_without_timing_gate():
    values = profiles()
    pair = compatibility.qualify_execution(values[-1])
    bad = deepcopy(values[2]); bad["transitive_source_sha256"] = "0" * 64
    candidates = (*values, bad)
    iterations = 2000
    observations = {}
    for label in ("uncached", "cached"):
        wall, cpu = perf_counter_ns(), process_time_ns()
        accepted = 0
        for _ in range(iterations):
            for value in candidates:
                if label == "uncached":
                    accepted += uncached_supported(value, values[-1])
                else:
                    try: accepted += compatibility.require_supported(value, pair)
                    except ValueError: pass
        observations[label] = {"accepted": accepted,
            "cpu_ns": process_time_ns() - cpu, "wall_ns": perf_counter_ns() - wall}
    assert observations["uncached"]["accepted"] == observations["cached"]["accepted"] == iterations * 4
    print(json.dumps({"record_type": "qcsd-Source024-reader-profile-cache-benchmark-v1",
        "schema_version": 1, "calls_per_path": iterations * len(candidates),
        "observations": observations, "timing_threshold_enforced": False,
        "scientific_credit_added": 0}, sort_keys=True, allow_nan=False))
