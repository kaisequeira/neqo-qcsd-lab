"""Synthetic raw-contract checks; no actual HTTP, Native or scientific credit."""
from __future__ import annotations

import csv
import io
import shutil

import pytest

from tests.test_supplied_static_preparation import fixed_graph, POLICIES, seal
from tests.test_supplied_static_get import actual_contract_fixture, load, write, csv_bytes, reseal_outputs
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import supplied_static_preparation as prep
from qcsd_lab import supplied_static_admission as admission


def retained_producer(fixture):
    root, arguments, _ = fixture
    declaration = load(root / "declaration.json")
    declaration["producer_sources"] = dict(bootstrap.RETAINED_PRODUCER_SOURCES)
    write(root / "declaration.json", declaration)
    for child in (root, root / "bootstrap"):
        started = load(child / "native-started.json")
        started["declaration_sha256"] = graph.digest((root / "declaration.json").read_bytes())
        write(child / "native-started.json", started)
    return seal(root, **arguments)


def rejected_bootstrap(fixture):
    root, arguments, _ = fixture
    retained_producer(fixture)
    # The real failed bootstrap never began the full graph.
    for name in ("full-get-proof.json", "native-started.json", "native-completed.json",
                 "native.stdout.log", "native.stderr.log"):
        (root / name).unlink()
    shutil.rmtree(root / "native")
    child = root / "bootstrap"
    run = load(child / "native/run.json")
    run["completion_status"] = "partial"
    response = run["responses"][0]
    response.update(status=302, bytes=143, content_length=143,
                    body_sha256=graph.digest(b"x" * 143), outcome="failed")
    response["response_headers"] = [[":status", "302"], ["content-length", "143"],
                                    ["location", "https://other.example/"]]
    write(child / "native/run.json", run)
    rows = list(csv.DictReader(io.StringIO((child / "native/events.csv").read_text())))
    for row in rows:
        if row["event"] == "observation":
            detail = get._load(row["details"].encode())
            if detail["type"] == "resource_completed":
                detail["success"] = False
                row["details"] = graph.canonical_bytes(detail).decode().strip()
    (child / "native/events.csv").write_bytes(csv_bytes(list(rows[0]), rows))
    reseal_outputs(child)
    return root, arguments


def test_original_producer_map_and_proof_survive_verifier_change_without_refetch(fixed_graph, monkeypatch):
    root, arguments, context = fixed_graph
    original = retained_producer(fixed_graph)
    assert original["producer_sources"] != bootstrap.producer_sources()
    terminal = admission.admit(context, 1, root, policies=POLICIES)
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    def no_refetch(*args, **kwargs):
        raise AssertionError("verification must not execute a Native GET or resolve live DNS")
    monkeypatch.setattr(bootstrap, "_execute_step", no_refetch)
    monkeypatch.setattr(bootstrap.socket, "getaddrinfo", no_refetch)
    assert bootstrap.validate_proof(root, **arguments) == original
    assert prep.reopen_get(root, **arguments) == original
    assert admission.verify_terminal(terminal, context)["outcome"] == "admitted"
    assert original["producer_sources"] == dict(bootstrap.RETAINED_PRODUCER_SOURCES)
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("mutation", ["hash", "extra", "missing", "mixed", "proof", "raw"])
def test_known_producer_compatibility_never_accepts_changed_map_or_raw_or_proof(fixed_graph, mutation):
    root, arguments, _ = fixed_graph
    retained_producer(fixed_graph)
    if mutation == "proof":
        proof = load(root / "full-get-proof.json")
        proof["producer_sources"] = bootstrap.producer_sources()
        write(root / "full-get-proof.json", proof)
    elif mutation == "raw":
        (root / "native/packets.csv").write_bytes(b"changed raw packet body\n")
    else:
        declaration = load(root / "declaration.json")
        sources = declaration["producer_sources"]
        if mutation == "hash": sources["qcsd_lab.supplied_static_graph"] = "a" * 64
        elif mutation == "extra": sources["caller.arbitrary_legacy"] = "a" * 64
        elif mutation == "missing": sources.pop("qcsd_lab.prepare")
        else: sources["qcsd_lab.supplied_static_bootstrap_get"] = bootstrap.producer_sources()["qcsd_lab.supplied_static_bootstrap_get"]
        write(root / "declaration.json", declaration)
        for child in (root, root / "bootstrap"):
            started = load(child / "native-started.json")
            started["declaration_sha256"] = graph.digest((root / "declaration.json").read_bytes())
            write(child / "native-started.json", started)
    with pytest.raises(ValueError):
        bootstrap.validate_proof(root, **arguments)


def test_legacy_compatibility_requires_unchanged_protected_verifier_dependencies(fixed_graph, monkeypatch):
    root, arguments, _ = fixed_graph
    retained_producer(fixed_graph)
    current = bootstrap.producer_sources()
    current["qcsd_lab.supplied_static_preparation"] = "a" * 64
    monkeypatch.setattr(bootstrap, "producer_sources", lambda: current)
    with pytest.raises(ValueError, match="prospective"):
        bootstrap.validate_proof(root, **arguments)


def test_zero_exit_complete_redirect_has_only_operational_deferral(fixed_graph):
    root, arguments = rejected_bootstrap(fixed_graph)
    context = fixed_graph[2]
    failure = bootstrap.failure_proof(root, **arguments)
    assert failure["phase"] == "bootstrap" and failure["outcome"] == "operational-deferred"
    assert failure["scientific_credit"] is False and failure["formal_accepted_trace_count"] == 0
    assert load(root / "bootstrap/native-completed.json")["returncode"] == 0
    assert load(root / "declaration.json")["producer_sources"] == dict(bootstrap.RETAINED_PRODUCER_SOURCES)
    terminal = admission.record_get_deferral(context, 1, root)
    assert admission.verify_terminal(terminal, context)["admission"] is None
    assert admission.verify_terminal(terminal, context)["outcome"] == "operational-deferred"
    with pytest.raises((ValueError, FileNotFoundError)):
        admission.admit(context, 1, root, policies=POLICIES)


@pytest.mark.parametrize("mutation", ["200", "succeeded", "complete-run", "successful-observation",
                                      "missing-fin", "raw", "missing-output", "source-map"])
def test_zero_exit_deferral_requires_exact_nonpassing_complete_raw_contract(fixed_graph, mutation):
    root, arguments = rejected_bootstrap(fixed_graph)
    child = root / "bootstrap"
    if mutation in {"200", "succeeded", "complete-run"}:
        run = load(child / "native/run.json")
        if mutation == "200":
            run["responses"][0]["status"] = 200
            run["responses"][0]["response_headers"][0][1] = "200"
        elif mutation == "succeeded": run["responses"][0]["outcome"] = "succeeded"
        else: run["completion_status"] = "complete"
        write(child / "native/run.json", run)
        reseal_outputs(child)
    elif mutation in {"successful-observation", "missing-fin"}:
        rows = list(csv.DictReader(io.StringIO((child / "native/events.csv").read_text())))
        if mutation == "missing-fin": rows = [row for row in rows if "stream_finished" not in row["details"]]
        else:
            for row in rows:
                if row["event"] == "observation":
                    detail = get._load(row["details"].encode())
                    if detail["type"] == "resource_completed":
                        detail["success"] = True
                        row["details"] = graph.canonical_bytes(detail).decode().strip()
        (child / "native/events.csv").write_bytes(csv_bytes(list(rows[0]), rows))
        reseal_outputs(child)
    elif mutation == "raw": (child / "native/packets.csv").write_bytes(b"tampered\n")
    elif mutation == "missing-output":
        (child / "native/packets.csv").unlink()
        completed = load(child / "native-completed.json")
        completed["outputs"].pop("packets.csv")
        write(child / "native-completed.json", completed)
    else:
        declaration = load(root / "declaration.json")
        declaration["producer_sources"]["qcsd_lab.supplied_static_bootstrap_get"] = "a" * 64
        write(root / "declaration.json", declaration)
    with pytest.raises((ValueError, FileNotFoundError)):
        bootstrap.failure_proof(root, **arguments)


def test_successful_zero_exit_bootstrap_cannot_be_suppressed(fixed_graph):
    root, arguments, _ = fixed_graph
    (root / "native-started.json").unlink()
    with pytest.raises(ValueError):
        bootstrap.failure_proof(root, **arguments)


@pytest.mark.parametrize("mutation", ["paired-null", "half-null", "negative", "success-paired-null"])
def test_missing_terminal_receive_clock_is_allowed_only_for_bound_rejected_primary(fixed_graph, mutation):
    root, arguments = rejected_bootstrap(fixed_graph)
    child = root / "bootstrap"
    run = load(child / "native/run.json")
    lifecycle = run["endpoints"][0]["receive_lifecycle"]
    lifecycle["polling_stopped_at_elapsed_ns"] = None if mutation != "negative" else -1
    if mutation != "half-null":
        lifecycle["polling_stopped_at_unix_ns"] = None
    if mutation == "success-paired-null":
        run["completion_status"] = "complete"
        response = run["responses"][0]
        response.update(status=200, outcome="succeeded")
        response["response_headers"][0][1] = "200"
    write(child / "native/run.json", run)
    reseal_outputs(child)
    if mutation == "paired-null":
        assert bootstrap.failure_proof(root, **arguments)["outcome"] == "operational-deferred"
        with pytest.raises(ValueError):
            bootstrap._step(child, {**load(root / "declaration.json"),
                            "_raw_sha256": graph.digest((root / "declaration.json").read_bytes())},
                            load(child / "native-input.json"), policy=bootstrap.STRICT_POLICY, execution=child)
    else:
        with pytest.raises(ValueError):
            bootstrap.failure_proof(root, **arguments)


@pytest.mark.parametrize("phase", ["bootstrap", "full"])
@pytest.mark.parametrize("timed_out", [False, True])
def test_existing_native_nonzero_and_timeout_deferral_branches_remain(fixed_graph, phase, timed_out):
    root, arguments, _ = fixed_graph
    if phase == "bootstrap":
        (root / "native-started.json").unlink()
    child = root / "bootstrap" if phase == "bootstrap" else root
    completed = load(child / "native-completed.json")
    completed.update(returncode=None if timed_out else 1, timed_out=timed_out)
    write(child / "native-completed.json", completed)
    assert bootstrap.failure_proof(root, **arguments)["outcome"] == "operational-deferred"
