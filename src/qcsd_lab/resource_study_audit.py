"""Bounded, ordered raw receipt replay without ledger access or proof caching.

The parent owns every ledger/epoch decision. Spawned children only replay the
existing raw verifier on the exact immutable receipt bytes supplied by it.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from concurrent.futures.process import BrokenProcessPool
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sys
import threading
import time

from . import resource_study_verify

MAX_VERIFICATION_WORKERS = 32
_WORKER_IDENTITY = None


class AuditInterrupted(RuntimeError):
    """An operator requested a stop; all started proof workers were joined."""


def verification_workers(value):
    if type(value) is not int or not 1 <= value <= MAX_VERIFICATION_WORKERS:
        raise ValueError(f"verification workers must be an integer from 1 to {MAX_VERIFICATION_WORKERS}")
    return value


def _identity():
    paths = (Path(__file__).resolve(), Path(resource_study_verify.__file__).resolve())
    return {"python": str(Path(sys.executable).resolve()),
            "version": list(sys.version_info[:3]),
            "isolated": sys.flags.isolated, "dont_write_bytecode": sys.dont_write_bytecode,
            "affinity": sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None,
            "source": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}}


def _initialize_worker():
    global _WORKER_IDENTITY
    # The parent stops submission and joins finite, read-only proof work. A
    # process-group Ctrl-C must not strand a partially completed pool shutdown.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    # Operator TERM targets the coordinator PID. Keep child TERM conventional:
    # ProcessPoolExecutor needs it to close remaining workers on a broken pool.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    _WORKER_IDENTITY = _identity()
    _WORKER_IDENTITY["start_method"] = multiprocessing.get_start_method()


def _replay(root, raw):
    # No StudyStore or SQLite operation is permitted here. The parent has
    # already parsed these same bytes with its duplicate-field authority guard.
    started, cpu_started = time.monotonic_ns(), time.process_time_ns()
    receipt = json.loads(raw)
    try:
        facts = resource_study_verify.verify_receipt(Path(root), receipt)
        error = None
    except (OSError, ValueError, RuntimeError) as failure:
        facts, error = None, failure
    return {"facts": facts, "error": error, "identity": _WORKER_IDENTITY, "pid": os.getpid(),
            "measurement": {"wall_ns": time.monotonic_ns() - started,
                            "process_cpu_ns": time.process_time_ns() - cpu_started}}


class ReceiptReplay:
    """Join a bounded spawn pool before its enclosing epoch lock is released.

    A later parent metadata error cannot hide an earlier raw proof error.
    Results and failures are consumed in submission order, never completion
    order. This context is used only for explicit parallel deep parent audits.
    """

    def __init__(self, workers):
        self.workers = verification_workers(workers)
        self.limit = self.workers * 2
        self.pending = deque()
        self.executor = None
        self.previous_handlers = {}
        self.signals = []
        self.failure = None
        self.observations = {}
        self.submitted = 0
        self.expected_identity = _identity()
        self.expected_identity["start_method"] = "spawn"

    def _signal(self, number, frame):
        self.signals.append(number)

    def _check_stop(self):
        if self.signals:
            raise AuditInterrupted("raw receipt audit stopped by operator; all started workers joined")

    def __enter__(self):
        if threading.current_thread() is not threading.main_thread():
            raise ValueError("parallel receipt audit requires the main thread for graceful signal handling")
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                self.previous_handlers[sig] = signal.signal(sig, self._signal)
        except BaseException:
            self._restore_handlers()
            raise
        return self

    def _restore_handlers(self):
        for sig, handler in self.previous_handlers.items():
            signal.signal(sig, handler)
        self.previous_handlers.clear()

    def _complete_one(self):
        self._check_stop()
        future, expected_tuple = self.pending.popleft()
        try:
            while True:
                self._check_stop()
                try:
                    result = future.result(timeout=0.1)
                    break
                except TimeoutError:
                    continue
            if (not isinstance(result, dict) or set(result) != {"facts", "error", "identity", "pid", "measurement"}
                    or result["identity"] != self.expected_identity
                    or type(result["pid"]) is not int or result["pid"] <= 0
                    or result["pid"] == os.getpid()):
                raise RuntimeError("raw receipt worker code or interpreter authority differs")
            measurement = result["measurement"]
            if (not isinstance(measurement, dict) or set(measurement) != {"wall_ns", "process_cpu_ns"}
                    or any(type(value) is not int or value < 0 for value in measurement.values())):
                raise RuntimeError("raw receipt worker timing observation is malformed")
            observed = self.observations.setdefault(result["pid"], {"pid": result["pid"],
                "affinity": result["identity"]["affinity"], "proof_replays_completed": 0,
                "proof_wall_ns": 0, "proof_process_cpu_ns": 0})
            observed["proof_replays_completed"] += 1
            observed["proof_wall_ns"] += measurement["wall_ns"]
            observed["proof_process_cpu_ns"] += measurement["process_cpu_ns"]
            if result["error"] is not None:
                if not isinstance(result["error"], (OSError, ValueError, RuntimeError)) or result["facts"] is not None:
                    raise RuntimeError("raw receipt worker returned a malformed refusal")
                raise result["error"]
            facts = result["facts"]
            if not isinstance(facts, dict) or facts.get("verified") is not True:
                raise RuntimeError("raw receipt worker returned no verified facts")
            actual_tuple = json.dumps(facts.get("five_tuple"), sort_keys=True, indent=2, allow_nan=False) + "\n"
            if actual_tuple != expected_tuple:
                raise ValueError("deep epoch tuple differs from its accepted index")
        except BrokenProcessPool as error:
            self.failure = RuntimeError("raw receipt worker exited before full proof completion")
            raise self.failure from error
        except BaseException as error:
            self.failure = error
            raise

    def submit(self, root, raw, expected_tuple):
        self._check_stop()
        if len(self.pending) >= self.limit:
            self._complete_one()
        self._check_stop()
        if self.executor is None:
            self.executor = ProcessPoolExecutor(max_workers=self.workers,
                mp_context=multiprocessing.get_context("spawn"), initializer=_initialize_worker)
        try:
            future = self.executor.submit(_replay, str(root), raw)
        except BrokenProcessPool as error:
            # Earlier submitted proofs still take precedence in __exit__.
            raise RuntimeError("raw receipt worker exited before full proof completion") from error
        self.pending.append((future, expected_tuple))
        self.submitted += 1

    def __exit__(self, kind, error, traceback):
        earlier = None
        try:
            # An error already raised by ordered reduction is the earliest raw
            # failure. Otherwise drain earlier ordinals before a parent error.
            if self.failure is None and not isinstance(error, AuditInterrupted):
                try:
                    while self.pending:
                        self._complete_one()
                except BaseException as proof_error:
                    earlier = proof_error
        finally:
            try:
                if self.executor is not None:
                    # Queueing handlers remain installed throughout shutdown;
                    # workers ignore group Ctrl-C and finish current replay.
                    self.executor.shutdown(wait=True, cancel_futures=True)
                    observed = sum(value["proof_replays_completed"] for value in self.observations.values())
                    print(json.dumps({"record_type": "qcsd-resource-study-parallel-audit-execution-v1",
                        "worker_limit": self.workers, "pending_limit": self.limit,
                        "worker_authority": self.expected_identity,
                        "processes": [self.observations[pid] for pid in sorted(self.observations)],
                        "process_scope": "only workers whose replay result was observed",
                        "submitted_replays": self.submitted, "observed_replays": observed,
                        "unobserved_replays": self.submitted - observed,
                        "unobserved_scope": "may have completed, failed or been canceled; joining is not proof credit",
                        "audit_completed": error is None and earlier is None and self.failure is None and not self.signals,
                        "all_started_workers_joined": True, "operator_signals": self.signals,
                        "scope": "operational observations; scientific composition is unchanged"},
                        sort_keys=True, allow_nan=False), file=sys.stderr, flush=True)
            finally:
                self._restore_handlers()
        if earlier is not None:
            raise earlier from error
        self._check_stop()
        return False
