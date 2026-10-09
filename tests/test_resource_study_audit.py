"""Ordered pool/lifecycle controls and actual isolated public spawn refusals.

Positive ledger fixtures below use an explicitly controlled raw-proof boundary;
they are not captures or scientific passes. Actual child tests run the unchanged
verifier and must refuse those synthetic records.
"""
from concurrent.futures import Future, TimeoutError
from concurrent.futures.process import BrokenProcessPool
from contextlib import contextmanager
import json
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

import pytest

from qcsd_lab import resource_study_audit as audit
from qcsd_lab import resource_study as study
from qcsd_lab.resource_study_inputs import canonical_json
from .test_resource_study_epochs import (roots, admit, reserve, receipt, commit, mutate,
                                        epochs)


def tuple_json(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"


@pytest.fixture
def controlled_pool(monkeypatch):
    state = {"submitted": 0, "active": 0, "maximum": 0, "shutdown": [], "checked": [],
             "errors": {}, "change": None, "timeout_signal": False, "shutdown_signal": False,
             "broken": False}

    class ControlledFuture:
        def __init__(self, raw):
            self.receipt = json.loads(raw)
            self.done = False

        def result(self, timeout=None):
            assert timeout == 0.1
            if state["broken"]:raise BrokenProcessPool("controlled worker failure")
            if state["timeout_signal"]:
                state["timeout_signal"] = False
                signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                raise TimeoutError()
            if not self.done:
                self.done = True
                state["active"] -= 1
                state["checked"].append(self.receipt["ordinal"])
            result = {"facts": {"verified": True, "five_tuple": self.receipt["five_tuple"]},
                      "error": None, "identity": {**audit._identity(), "start_method": "spawn"},
                      "pid": os.getpid() + 1, "measurement": {"wall_ns": 100, "process_cpu_ns": 50}}
            if self.receipt["ordinal"] in state["errors"]:
                result.update(facts=None, error=state["errors"][self.receipt["ordinal"]])
            if state["change"]:
                state["change"](result)
            return result

    class ControlledExecutor:
        def __init__(self, *, max_workers, mp_context, initializer):
            assert mp_context.get_start_method() == "spawn"
            assert initializer is audit._initialize_worker
            state["workers"] = max_workers

        def submit(self, function, root, raw):
            assert function is audit._replay
            state["submitted"] += 1
            state["active"] += 1
            state["maximum"] = max(state["maximum"], state["active"])
            return ControlledFuture(raw)

        def shutdown(self, *, wait, cancel_futures):
            assert wait is cancel_futures is True
            if state["shutdown_signal"]:
                signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            state["active"] = 0
            state["shutdown"].append("all-started-proof-workers-joined")

    monkeypatch.setattr(audit, "ProcessPoolExecutor", ControlledExecutor)
    return state


def submit(pool, number):
    value = ["10.0.0.2", 30000 + number, "192.0.2.1", 443, 17]
    pool.submit("/synthetic-proof-root", canonical_json({"ordinal": number, "five_tuple": value}),
                tuple_json(value))


@pytest.mark.parametrize("workers", [0, -1, 33, True, None, 1.5, "2"])
def test_invalid_worker_limit_refuses_before_any_pool(workers):
    with pytest.raises(ValueError, match="integer from 1 to 32"):
        audit.ReceiptReplay(workers)


def test_bounded_submission_reduces_in_original_order_and_joins(controlled_pool, capsys):
    with audit.ReceiptReplay(2) as pool:
        for number in range(19):
            submit(pool, number)
            assert len(pool.pending) <= 4
    assert controlled_pool["maximum"] == 4
    assert controlled_pool["checked"] == list(range(19))
    assert controlled_pool["active"] == 0
    assert controlled_pool["shutdown"] == ["all-started-proof-workers-joined"]
    observation = json.loads(capsys.readouterr().err)
    assert observation["submitted_replays"] == observation["observed_replays"] == 19
    assert observation["unobserved_replays"] == 0 and observation["audit_completed"] is True


def test_earliest_raw_error_precedes_later_parent_metadata_error(controlled_pool):
    controlled_pool["errors"] = {0: ValueError("earliest raw proof"), 1: ValueError("later raw proof")}
    with pytest.raises(ValueError, match="earliest raw proof"):
        with audit.ReceiptReplay(2) as pool:
            submit(pool, 0);submit(pool, 1)
            raise ValueError("later parent metadata")
    assert controlled_pool["checked"] == [0]
    assert controlled_pool["active"] == 0


def test_parent_error_is_preserved_when_all_earlier_proofs_pass(controlled_pool):
    with pytest.raises(ValueError, match="parent metadata"):
        with audit.ReceiptReplay(2) as pool:
            submit(pool, 0);submit(pool, 1)
            raise ValueError("parent metadata")
    assert controlled_pool["checked"] == [0, 1]
    assert controlled_pool["active"] == 0


def test_first_reduced_error_cannot_be_replaced_by_a_later_error(controlled_pool):
    controlled_pool["errors"] = {0: ValueError("first failure"), 1: ValueError("second failure")}
    with pytest.raises(ValueError, match="first failure"):
        with audit.ReceiptReplay(2) as pool:
            for number in range(5):submit(pool, number)
    assert controlled_pool["checked"] == [0]


def test_real_futures_complete_out_of_order_but_preserve_serial_error():
    identity = {**audit._identity(), "start_method": "spawn"}
    def refusal(reason):
        return {"facts": None, "error": ValueError(reason), "identity": identity,
                "pid": os.getpid() + 1, "measurement": {"wall_ns": 100, "process_cpu_ns": 50}}
    first, later = Future(), Future()
    later.set_result(refusal("later failure completed first"))
    timer = threading.Timer(0.02, lambda: first.set_result(refusal("earliest failure completed later")))
    timer.start()
    try:
        with pytest.raises(ValueError, match="earliest failure completed later"):
            with audit.ReceiptReplay(2) as pool:
                pool.pending.extend([(first, "unused"), (later, "unused")])
    finally:timer.join()


def test_worker_crash_refuses_and_joins_all_children(controlled_pool):
    controlled_pool["broken"] = True
    with pytest.raises(RuntimeError, match="exited before full proof completion"):
        with audit.ReceiptReplay(2) as pool:
            submit(pool, 0);submit(pool, 1)
    assert controlled_pool["active"] == 0
    assert controlled_pool["shutdown"] == ["all-started-proof-workers-joined"]


@pytest.mark.parametrize("change,reason", [
    (lambda result: result["identity"].update(isolated=99), "interpreter authority"),
    (lambda result: result["identity"].update(start_method="fork"), "interpreter authority"),
    (lambda result: result.update(pid=os.getpid()), "interpreter authority"),
    (lambda result: result.update(facts={"verified": False}), "no verified facts"),
    (lambda result: result["facts"].update(five_tuple=["10.0.0.99", 30000, "192.0.2.1", 443, 17]), "deep epoch tuple"),
    (lambda result: result.update(error="fake error"), "malformed refusal"),
])
def test_foreign_worker_and_malformed_result_fail_closed(controlled_pool, change, reason):
    controlled_pool["change"] = change
    with pytest.raises((RuntimeError, ValueError), match=reason):
        with audit.ReceiptReplay(2) as pool:submit(pool, 0)
    assert controlled_pool["active"] == 0


@pytest.mark.parametrize("phase", ["timeout_signal", "shutdown_signal"])
def test_repeated_operator_signals_join_before_handler_restoration(controlled_pool, phase, capsys):
    original = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    controlled_pool[phase] = True
    with pytest.raises(audit.AuditInterrupted, match="all started workers joined"):
        with audit.ReceiptReplay(2) as pool:
            submit(pool, 0);submit(pool, 1)
    assert controlled_pool["active"] == 0
    assert controlled_pool["shutdown"] == ["all-started-proof-workers-joined"]
    assert {number: signal.getsignal(number) for number in original} == original
    observation = json.loads(capsys.readouterr().err)
    assert observation["audit_completed"] is False
    assert observation["unobserved_replays"] == (2 if phase == "timeout_signal" else 0)
    assert "joining is not proof credit" in observation["unobserved_scope"]


def accepted_parent(roots, monkeypatch, count=2):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    monkeypatch.setattr(epochs, "_pilot", lambda store, cell: None)
    for number in range(count):
        attempt = reserve(new)
        path = receipt(new, attempt, port=31000 + number)
        value = json.loads(path.read_bytes());value["ordinal"] = number
        mutate(path, canonical_json(value))
        commit(new, path)
    return parent, new


def test_parent_parallel_output_equals_serial_and_export_replays_every_receipt(
        roots, monkeypatch, controlled_pool, tmp_path):
    parent, new = accepted_parent(roots, monkeypatch, 7)
    monkeypatch.setattr(epochs, "verify_receipt", lambda root, value:
                        {"verified": True, "five_tuple": value["five_tuple"]})
    serial = epochs.status(parent.root, deep=True)
    parallel = epochs.status(parent.root, deep=True, verification_workers=2)
    assert canonical_json(serial) == canonical_json(parallel)
    assert parallel["scientific_credit"] is False and parallel["accepted_count"] == 7
    assert controlled_pool["submitted"] == 7
    exported = epochs.export_manifest(parent.root, tmp_path / "fresh.json", verification_workers=2)
    assert (tmp_path / "fresh.json").read_bytes() == canonical_json(serial)
    assert exported == serial and controlled_pool["submitted"] == 14


def test_join_happens_before_epoch_unlock_even_on_operator_stop(
        roots, monkeypatch, controlled_pool):
    parent, new = accepted_parent(roots, monkeypatch)
    original = epochs._lock
    @contextmanager
    def checked_lock(path):
        with original(path):
            try:yield
            finally:
                assert controlled_pool["active"] == 0
                assert controlled_pool["shutdown"] == ["all-started-proof-workers-joined"]
    monkeypatch.setattr(epochs, "_lock", checked_lock)
    controlled_pool["timeout_signal"] = True
    with pytest.raises(audit.AuditInterrupted):
        epochs.status(parent.root, deep=True, verification_workers=2)


def test_failed_parallel_export_never_creates_manifest(roots, monkeypatch, controlled_pool, tmp_path):
    parent, new = accepted_parent(roots, monkeypatch)
    controlled_pool["errors"][0] = ValueError("actual raw proof refused")
    path = tmp_path / "must-not-exist.json"
    with pytest.raises(ValueError, match="actual raw proof refused"):
        epochs.export_manifest(parent.root, path, verification_workers=2)
    assert not path.exists()


def test_default_serial_does_not_construct_pool_or_change_handlers(roots, monkeypatch):
    parent, new = accepted_parent(roots, monkeypatch)
    monkeypatch.setattr(epochs, "verify_receipt", lambda root, value:
                        {"verified": True, "five_tuple": value["five_tuple"]})
    monkeypatch.setattr(epochs, "ReceiptReplay", lambda *args:
                        (_ for _ in ()).throw(AssertionError("serial created a pool")))
    assert epochs.status(parent.root, deep=True)["accepted_count"] == 2


def test_actual_isolated_public_entrypoint_spawn_replays_and_preserves_serial_refusal(
        roots, monkeypatch, tmp_path):
    parent, new = accepted_parent(roots, monkeypatch)
    source = Path(epochs.__file__).resolve().parents[2]
    command = [sys.executable, "-I", "-B", str(source / "tools/resource_study.py"),
               "verify", "--root", str(parent.root), "--all"]
    serial = subprocess.run(command, capture_output=True, text=True, timeout=30)
    parallel = subprocess.run([*command, "--verification-workers", "2"],
                              capture_output=True, text=True, timeout=30)
    assert serial.returncode == parallel.returncode == 1
    assert json.loads(serial.stdout) == json.loads(parallel.stdout)
    assert json.loads(parallel.stdout)["reason"] == "session verification contract differs"
    execution = json.loads(parallel.stderr)
    assert execution["all_started_workers_joined"] is True
    assert execution["worker_authority"]["start_method"] == "spawn"
    assert execution["worker_authority"]["isolated"] == 1
    assert execution["worker_authority"]["dont_write_bytecode"] is True
    assert execution["processes"][0]["proof_process_cpu_ns"] > 0
    assert multiprocessing.active_children() == []


def test_actual_spawned_finite_work_is_joined_after_operator_signal(tmp_path):
    source = Path(epochs.__file__).resolve().parents[2]
    # A disposable finite sleep exercises real ProcessPoolExecutor shutdown,
    # not a fake future. It is not submitted through the scientific verifier.
    script = tmp_path / "finite-pool-stop.py"
    script.write_text("""import sys,os,signal,time,threading,multiprocessing
from pathlib import Path
sys.path.insert(0, SOURCE)
from qcsd_lab import resource_study_audit as audit
if __name__ == '__main__':
    timer=None
    started=time.monotonic()
    try:
        with audit.ReceiptReplay(2) as pool:
            pool.executor=audit.ProcessPoolExecutor(max_workers=2,
                mp_context=multiprocessing.get_context('spawn'),initializer=audit._initialize_worker)
            pool.pending.append((pool.executor.submit(time.sleep,0.3),'unused'))
            timer=threading.Timer(0.05,lambda:os.kill(os.getpid(),signal.SIGTERM));timer.start()
    except audit.AuditInterrupted:
        if timer is not None:timer.join()
        assert multiprocessing.active_children()==[]
        assert time.monotonic()-started>=0.3
        print('stopped-and-joined')
    else:raise AssertionError('operator stop did not refuse')
""".replace("SOURCE", repr(str(source / "src"))))
    process = subprocess.run([sys.executable, "-I", "-B", str(script)],
                             capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    assert process.stdout.strip() == "stopped-and-joined"
    assert json.loads(process.stderr)["all_started_workers_joined"] is True


def test_actual_spawned_worker_crash_closes_surviving_worker_without_hanging(tmp_path):
    source = Path(epochs.__file__).resolve().parents[2]
    script = tmp_path / "finite-pool-crash.py"
    script.write_text("""import sys,os,time,multiprocessing
from pathlib import Path
sys.path.insert(0, SOURCE)
from qcsd_lab import resource_study_audit as audit
def warm_worker(gate):
    Path(gate+'.worker-'+str(os.getpid())).write_text('ready')
    deadline=time.monotonic()+10
    while not Path(gate).exists():
        if time.monotonic()>deadline:raise RuntimeError('warmup gate absent')
        time.sleep(0.01)
    return os.getpid()
def survivor(ready,completed):
    Path(ready).write_text(str(time.monotonic()))
    time.sleep(10)
    Path(completed).write_text('normal-finite-completion')
def crash_after_survivor_ready(ready,crashed):
    deadline=time.monotonic()+10
    while not Path(ready).is_file():
        if time.monotonic()>deadline:raise RuntimeError('survivor readiness absent')
        time.sleep(0.01)
    Path(crashed).write_text('observed-survivor-ready')
    os._exit(17)
if __name__ == '__main__':
    ready=Path(__file__).with_suffix('.ready')
    completed=Path(__file__).with_suffix('.completed')
    crash_marker=Path(__file__).with_suffix('.crashed')
    gate=Path(__file__).with_suffix('.gate')
    try:
        with audit.ReceiptReplay(2) as pool:
            pool.executor=audit.ProcessPoolExecutor(max_workers=2,
                mp_context=multiprocessing.get_context('spawn'),initializer=audit._initialize_worker)
            warmups=[pool.executor.submit(warm_worker,str(gate)) for _ in range(2)]
            deadline=time.monotonic()+10
            while len(list(gate.parent.glob(gate.name+'.worker-*')))!=2:
                if time.monotonic()>deadline:raise RuntimeError('two worker warmup absent')
                time.sleep(0.01)
            gate.write_text('release')
            assert len({future.result(timeout=10) for future in warmups})==2
            surviving=pool.executor.submit(survivor,str(ready),str(completed))
            crashed=pool.executor.submit(crash_after_survivor_ready,str(ready),str(crash_marker))
            pool.pending.extend([(surviving,'unused'),(crashed,'unused')]);pool.submitted=2
    except RuntimeError as error:
        assert 'exited before full proof completion' in str(error)
        assert multiprocessing.active_children()==[]
        assert ready.is_file() and crash_marker.is_file() and not completed.exists()
        assert time.monotonic()-float(ready.read_text())<10
        print('crash-refused-and-joined')
    else:raise AssertionError('crashed pool did not refuse')
""".replace("SOURCE", repr(str(source / "src"))))
    process = subprocess.run([sys.executable, "-I", "-B", str(script)],
                             capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    assert process.stdout.strip() == "crash-refused-and-joined"
    observation = json.loads(process.stderr)
    assert observation["all_started_workers_joined"] is True
    assert observation["audit_completed"] is False
    assert observation["observed_replays"] == 0 and observation["unobserved_replays"] == 2


def test_worker_replays_exact_bytes_without_sqlite_or_store_calls(monkeypatch, tmp_path):
    import sqlite3
    from qcsd_lab.resource_study_store import StudyStore
    forbidden = lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("worker touched ledger"))
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(StudyStore, "__init__", forbidden)
    calls = []
    def verify(root, value):
        calls.append((root, value))
        return {"verified": True, "five_tuple": value["five_tuple"]}
    monkeypatch.setattr(audit.resource_study_verify, "verify_receipt", verify)
    raw = canonical_json({"five_tuple": ["10.0.0.2", 30000, "192.0.2.1", 443, 17], "opaque": "exact receipt"})
    result = audit._replay(str(tmp_path), raw)
    assert result["error"] is None
    assert calls == [(tmp_path, json.loads(raw))]


def test_public_cli_options_and_new_worker_module_provenance():
    for action in ("verify", "export"):
        options = [action, "--root", "/not-opened", "--verification-workers", "4"]
        if action == "export":options.extend(["--output", "/not-created"])
        assert study.parser().parse_args(options).verification_workers == 4
    assert "resource_study_audit.py" in study.coordinator_provenance()["files"]
