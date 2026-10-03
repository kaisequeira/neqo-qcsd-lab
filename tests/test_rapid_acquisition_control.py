"""Operator budgets conserve history and delegate actual decisions to frozen APIs."""
from copy import deepcopy
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_site_admission as admission
from tools import rapid_acquire
from tools import rapid_acquisition_control as control
from tests.test_rapid_site_admission import context, _amended_context, _root_logs


def test_one_page_budget_seals_exact_failure_and_discloses_unassessed_tail():
    event = {"kind": "failure", "ordinal": 0, "path": "actual-proof"}
    action, selected, audit = control.choose_step([event], 5, 1)
    assert action == "seal" and selected is event
    assert audit["visited_page_ordinals"] == [0]
    assert audit["unassessed_page_ordinals"] == [1, 2, 3, 4]


def test_resume_cannot_reset_budget_or_retry_previously_failed_ordinals():
    events = [{"kind": "failure", "ordinal": n} for n in (0, 1, 2)]
    action, selected, audit = control.choose_step(events, 5, 1)
    assert action == "seal" and selected["ordinal"] == 2
    assert audit["pre_existing_history_above_budget"] is True
    assert audit["unassessed_page_ordinals"] == [3, 4]
    assert control.choose_step(events, 5, 4)[:2] == ("probe-page", {"ordinal": 3})


@pytest.mark.parametrize("kind,expected", [("page", "screen-page"), ("screen", "prepare")])
def test_already_started_page_finishes_even_with_grandfathered_history(kind, expected):
    events = [{"kind": "failure", "ordinal": 0}, {"kind": kind, "ordinal": 1}]
    assert control.choose_step(events, 5, 1)[0] == expected


@pytest.mark.parametrize("eligible,budget,action", [(True, 2, "seal"), (False, 1, "seal"), (False, 2, "probe-page")])
def test_complete_graph_zero_cross_origin_uses_same_declared_budget(eligible, budget, action):
    assert control.choose_step([{"kind": "prepared", "ordinal": 0, "eligible": eligible}], 5, budget)[0] == action


@pytest.mark.parametrize("events,pages", [([{"kind": "blocked"}], 5), ([{"kind": "failure", "ordinal": True}], 5),
                                        ([{"kind": "failure", "ordinal": 5}], 5)])
def test_pending_generic_and_invalid_page_history_block(events, pages):
    with pytest.raises(ValueError):
        control.choose_step(events, pages, 1)


def test_verified_actual_navigation_failure_routes_to_existing_zero_credit_seal(context, tmp_path, monkeypatch):
    amended = _amended_context(context, tmp_path, revision=6)
    candidate = amended.candidates[0]
    roots = _root_logs(amended, tmp_path)
    registry = {"root_surveys": {"curated": [admission.import_evidence(amended.root, p) for p in roots], "fallback": []}}
    def fail(_self, _domain):
        raise RuntimeError("actual test backend navigation failure")
    monkeypatch.setattr(admission.ExistingAcquisitionBackend, "discover_navigation", fail)
    proof = rapid_acquire._page_action(amended, candidate["candidate_id"], SimpleNamespace(command="navigate"))
    plan = control.plan_action(admission, amended, registry, admission.acquisition_status(amended), 1)
    assert plan["action"] == "seal" and plan["live"] is False
    assert plan["arguments"][:2] == ["--attempt-failure", str(proof)]
    assert admission.acquisition_status(amended)["formal_trace_target"] == 16000
    terminal = admission.produce_site_terminal(amended, candidate_id=candidate["candidate_id"], root_surveys=roots, attempt_failure=proof)
    facts = admission.verify_site_terminal(terminal, amended)
    assert facts["outcome"] == "unsuccessful-live-attempt-screen-deferred" and facts["admission"] is None


def test_bound_registry_rejects_changed_bytes_and_reordered_prior_authority(context, tmp_path):
    amended = _amended_context(context, tmp_path, revision=6)
    refs = []
    for number in range(3):
        path = tmp_path / f"raw-root-{number}.json"
        path.write_bytes(admission._json({"raw": number}))
        refs.append(admission.import_evidence(amended.root, path))
    initial = {"schema_version": 1, "record_type": "private-frozen-v6-primary-document-policy-ordered-root-log-registry-v6",
        "created_at": control.now(), "provenance_sha256": amended.provenance_sha256,
        "selection_amendment_sha256": amended.selection_amendment_sha256, "previous_registry": None,
        "root_surveys": {"curated": refs[:2], "fallback": []}, "scientific_credit": False, "docker_executed": False}
    first = tmp_path / "first.json"; first.write_bytes(admission._json(initial)); digest = control.digest(first.read_bytes())
    assert control.load_registry(admission, amended, first, digest) == initial
    with pytest.raises(ValueError, match="bound input changed"):
        control.load_registry(admission, amended, first, "0" * 64)
    successor = deepcopy(initial); successor["previous_registry"] = {"path": str(first), "sha256": digest}
    successor["root_surveys"]["curated"] = [refs[1], refs[0], refs[2]]
    second = tmp_path / "second.json"; second.write_bytes(admission._json(successor))
    with pytest.raises(ValueError, match="reordered"):
        control.load_registry(admission, amended, second, control.digest(second.read_bytes()))


def test_actual_argv_logs_are_create_only_and_failed_child_keeps_completion(tmp_path, monkeypatch):
    directory = tmp_path / "action"; directory.mkdir()
    def child(argv, *, stdout, stderr, check):
        stdout.write(b"retained output"); stderr.write(b"actual failure")
        return subprocess.CompletedProcess(argv, 7)
    monkeypatch.setattr(control.subprocess, "run", child)
    with pytest.raises(RuntimeError, match="preserved logs"):
        control.execute(admission, ["checked-program", "arg"], directory)
    completed = admission._load((directory / "completed.json").read_bytes())
    assert completed["exit_code"] == 7 and completed["scientific_credit"] is False
    assert (directory / "stderr.log").read_bytes() == b"actual failure"
    with pytest.raises(FileExistsError):
        control.execute(admission, ["different-program"], directory)


def test_bootstrap_reopens_official_entrypoint_and_rejects_duplicate_environment(tmp_path):
    checkout, mounted, root = [tmp_path / name for name in ("checkout", "mounted", "context")]
    for path in (checkout, mounted):
        (path / "tools").mkdir(parents=True)
        (path / "tools/rapid_acquire.py").write_text("actual independently checked CLI\n")
    root.mkdir()
    context = SimpleNamespace(root=root, execution_binding={"admission_image_digest": "image@sha256:actual"}, mounted_module_hashes={})
    argv = ["docker", "run", "--name", "original", "-e", "QCSD_LAB_IMAGE_DIGEST=image@sha256:actual",
        "-e", "QCSD_LAB_ROOT=/runtime", "-v", f"{mounted}:/runtime:ro", "-v", f"{root}:/evidence:rw",
        "--entrypoint", "python3", "image@sha256:actual", "/runtime/tools/rapid_acquire.py"]
    assert control.verify_bootstrap(admission, context, checkout, argv) == ("/evidence", 3)
    changed_env = argv[:8] + ["-e", "QCSD_LAB_ROOT=/wrong"] + argv[8:]
    with pytest.raises(ValueError, match="source root differs"):
        control.verify_bootstrap(admission, context, checkout, changed_env)
    (mounted / "tools/rapid_acquire.py").write_text("different CLI\n")
    with pytest.raises(ValueError, match="mounted admission CLI differs"):
        control.verify_bootstrap(admission, context, checkout, argv)


def test_runtime_source_requires_declared_lab_native_and_gitlink(tmp_path, monkeypatch):
    lab, native = "a" * 40, "b" * 40
    context = SimpleNamespace(expected_runtime_source={"lab_commit": lab, "neqo_commit": native, "neqo_pinned_commit": native})
    calls = []
    monkeypatch.setattr(control, "clean_source", lambda path, commit: calls.append((path, commit)))
    monkeypatch.setattr(control, "git", lambda *args: f"160000 {native} 0\tneqo-qcsd\n".encode())
    control.verify_runtime_source(context, tmp_path, lab)
    assert calls == [(tmp_path / "neqo-qcsd", native)]
    with pytest.raises(ValueError, match="declared admission runtime"):
        control.verify_runtime_source(context, tmp_path, "c" * 40)
    monkeypatch.setattr(control, "git", lambda *args: f"160000 {'c' * 40} 0\tneqo-qcsd\n".encode())
    with pytest.raises(ValueError, match="Gitlink differs"):
        control.verify_runtime_source(context, tmp_path, lab)


def test_context_lock_rejects_peer_and_releases_without_replacing_inode(tmp_path):
    root = tmp_path / "context"; root.mkdir()
    with control.context_lock(root) as path:
        inode = path.stat().st_ino
        with pytest.raises(ValueError, match="another host coordinator"):
            with control.context_lock(root):
                pytest.fail("peer coordinator was admitted")
    with control.context_lock(root) as path:
        assert path.stat().st_ino == inode


def operator_args(tmp_path, label="operation", budget=1):
    return SimpleNamespace(operation_root=tmp_path / label, source_commit="a" * 40,
        operator_commit="b" * 40, coordinator_sha256="c" * 64,
        bootstrap=tmp_path / "bootstrap.json", bootstrap_sha256="d" * 64,
        root_registry=tmp_path / "registry.json", root_registry_sha256="e" * 64,
        page_budget=budget, max_actions=1, stop_at_admissions=1, stop_file=None, plan_only=False)


def test_operation_retains_budget_across_invocations_and_stops_before_actions(tmp_path, monkeypatch):
    root = tmp_path / "context"; root.mkdir()
    context = SimpleNamespace(root=root, provenance_sha256="f" * 64,
        profile_bytes=admission._json({"payload": {"cohort_contracts": [{"role": "final", "class_count": 50, "formal_sample_target": 16000}]}}))
    status = {"admitted_site_count": 0, "attempts": {}}
    reopen = lambda: (context, [], "/evidence", 4, {}, status)
    monkeypatch.setattr(control, "execute", lambda *args: pytest.fail("stop file launched an action"))
    stop = tmp_path / "stop"; stop.touch()
    args = operator_args(tmp_path); args.stop_file = stop
    with control.context_lock(root) as lock:
        assert control.run_operation(admission, args, tmp_path / "checkout", reopen, lock) == 0
    assert admission._load((args.operation_root / "stopped.json").read_bytes())["reason"] == "boundary-stop-file"
    resumed = operator_args(tmp_path, "resumed"); resumed.stop_file = stop
    with control.context_lock(root) as lock:
        assert control.run_operation(admission, resumed, tmp_path / "checkout", reopen, lock) == 0
    changed = operator_args(tmp_path, "changed", budget=2)
    with control.context_lock(root) as lock, pytest.raises(ValueError, match="retain its declared operator page budget"):
        control.run_operation(admission, changed, tmp_path / "checkout", reopen, lock)
    assert not changed.operation_root.exists()


def test_pending_operation_keeps_blocked_record_without_claiming_completion(tmp_path):
    root = tmp_path / "context"; root.mkdir()
    context = SimpleNamespace(root=root, provenance_sha256="f" * 64,
        profile_bytes=admission._json({"payload": {"cohort_contracts": [{"role": "final", "class_count": 50, "formal_sample_target": 16000}]}}))
    status = {"admitted_site_count": 0, "attempts": {"candidate": [{"state": "interrupted-or-pending"}]}}
    reopen = lambda: (context, [], "/evidence", 4, {}, status)
    args = operator_args(tmp_path)
    with control.context_lock(root) as lock, pytest.raises(ValueError, match="pending intent"):
        control.run_operation(admission, args, tmp_path / "checkout", reopen, lock)
    record = admission._load((args.operation_root / "blocked.json").read_bytes())
    assert record["exception_type"] == "ValueError" and record["scientific_credit"] is False
    assert not (args.operation_root / "stopped.json").exists()
    assert not list(args.operation_root.glob("action-*"))
