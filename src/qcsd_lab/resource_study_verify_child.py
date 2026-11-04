"""Bounded fresh-exec placement of the unchanged resource receipt reader.

Only the coordinator publishes files or owns Store/epoch/credit authority.
This module neither memoizes formal evidence nor replaces later whole proofs.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time

REQUEST = "qcsd-source106-readonly-new-receipt-request-v1"
RESPONSE = "qcsd-source106-readonly-new-receipt-result-v1"
INPUT_LIMIT = 16 * 1024**2
OUTPUT_LIMIT = 64 * 1024
MAX_FILES = 4096
SOURCE_LIMIT = 8 * 1024**2
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
           "st_size", "st_mtime_ns", "st_ctime_ns")


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _decode(raw, limit):
    _need(type(raw) is bytes and 0 < len(raw) <= limit, "bounded proof JSON required")
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "proof JSON repeats a field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite proof JSON")))
    _need(type(value) is dict, "proof JSON object required")
    return value


def _stamp(info):
    return [getattr(info, name) for name in _FIELDS]


def _canonical(path):
    path = Path(path)
    _need(path.is_absolute() and path.resolve(strict=True) == path
          and not any(item.is_symlink() for item in (path, *path.parents)),
          "canonical unlinked proof path required")
    return path


class _Files:
    """Hold fresh read-only descriptors; readers still perform original hashes."""
    def __init__(self, root, files, *, expected=None, hash_bytes=False):
        self.root = _canonical(root)
        self.handles = {}
        self.rows = {}
        try:
            _need(type(files) is dict and 0 < len(files) <= MAX_FILES,
                  "bounded complete proof file inventory required")
            for name, digest in sorted(files.items()):
                relative = PurePosixPath(name)
                _need(type(name) is str and str(relative) == name and not relative.is_absolute()
                      and relative.parts and ".." not in relative.parts and "\\" not in name
                      and type(digest) is str and _SHA.fullmatch(digest),
                      "exact proof file name and SHA required")
                path = _canonical(self.root / name)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                handle = os.fdopen(descriptor, "rb")
                self.handles[name] = handle
                info = os.fstat(handle.fileno())
                _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                      and _stamp(info) == _stamp(path.lstat()), "proof file FD identity differs")
                if hash_bytes:
                    raw = handle.read(SOURCE_LIMIT + 1)
                    _need(len(raw) == info.st_size and len(raw) <= SOURCE_LIMIT
                          and _digest(raw) == digest, "proof Source bytes differ")
                self.rows[name] = {"sha256": digest, "stamp": _stamp(info)}
            if expected is not None:
                _need(self.rows == expected, "proof fresh FD inventory differs")
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for name, handle in self.handles.items():
            expected = self.rows[name]["stamp"]
            _need(_stamp(os.fstat(handle.fileno())) == expected
                  and _stamp((self.root / name).lstat()) == expected
                  and _canonical(self.root / name) == self.root / name,
                  "proof source/raw FD or path changed")

    def close(self):
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            self.check()
        finally:
            self.close()


def _source_files():
    from .resource_study_reader_compatibility import execution_files
    return execution_files()


def _interpreter():
    # Keep the actual venv path (and therefore its dependency environment),
    # while independently binding its resolved executable bytes.
    path = Path(sys.executable).absolute()
    real = path.resolve(strict=True)
    _need(real.is_file(), "actual proof interpreter required")
    with real.open("rb") as handle:
        before = os.fstat(handle.fileno())
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
        _need(_stamp(before) == _stamp(os.fstat(handle.fileno())) == _stamp(real.lstat()),
              "proof interpreter FD changed")
    return {"path": str(path), "real_path": str(real), "sha256": digest,
            "stamp": _stamp(before), "prefix": sys.prefix}


def _birth(pid):
    path = Path("/proc") / str(pid)
    info = path.stat()
    fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "uid": info.st_uid, "gid": info.st_gid,
            "start_ticks": int(fields[19]), "pgid": int(fields[2]), "sid": int(fields[3])}


def _open_descriptors():
    result = []
    for name in os.listdir("/proc/self/fd"):
        try:
            os.fstat(int(name))
        except OSError:
            continue  # the closed descriptor used by listdir itself
        result.append(int(name))
    return sorted(result)


def _close_input_and_join(child):
    """A broken input pipe must never bypass the same child's terminal wait."""
    try:
        if child.stdin is not None and not child.stdin.closed:
            try:
                child.stdin.close()
            except BrokenPipeError:
                # The primary write/close failure still propagates from verify;
                # cleanup cannot lose the child while repeating that close.
                pass
    finally:
        child.wait()


def checked_request(value):
    keys = {"record_type", "schema_version", "root", "receipt", "receipt_sha256",
            "source_root", "source_files", "source_rows", "raw_rows", "interpreter",
            "affinity", "parent_pid", "attempt_id"}
    _need(type(value) is dict and set(value) == keys and value["record_type"] == REQUEST
          and type(value["schema_version"]) is int and value["schema_version"] == 1,
          "exact readonly proof request required")
    receipt = value["receipt"]
    _need(type(receipt) is dict and receipt.get("purpose") == "formal"
          and receipt.get("scientific_credit") is True and receipt.get("verified") is True
          and type(receipt.get("attempt_id")) is str
          and receipt["attempt_id"] == value["attempt_id"]
          and _digest(_encoded(receipt)) == value["receipt_sha256"],
          "proof exact new formal receipt/attempt binding differs")
    _need(type(value["affinity"]) is list and value["affinity"]
          and all(type(cpu) is int and cpu >= 0 for cpu in value["affinity"])
          and sorted(set(value["affinity"])) == value["affinity"]
          and type(value["parent_pid"]) is int and value["parent_pid"] > 0,
          "proof exact parent and auxiliary affinity required")
    _need(type(value["source_files"]) is dict and type(value["source_rows"]) is dict
          and set(value["source_files"]) == set(value["source_rows"])
          and type(value["raw_rows"]) is dict and set(value["raw_rows"]) == set(receipt.get("files", {})),
          "proof complete Source/raw request census required")
    return value


def checked_response(raw, request, *, request_sha256, birth, joined, returncode):
    _need(joined is True and type(returncode) is int and returncode == 0,
          "proof positive exact child exit and join required")
    value = _decode(raw, OUTPUT_LIMIT)
    keys = {"record_type", "schema_version", "request_sha256", "receipt_sha256", "root",
            "attempt_id", "source_rows_sha256", "raw_rows_sha256", "birth", "affinity",
            "initial_descriptors", "facts", "timing"}
    _need(set(value) == keys and value["record_type"] == RESPONSE
          and type(value["schema_version"]) is int and value["schema_version"] == 1
          and value["request_sha256"] == request_sha256
          and value["receipt_sha256"] == request["receipt_sha256"]
          and value["root"] == request["root"] and value["attempt_id"] == request["attempt_id"]
          and value["source_rows_sha256"] == _digest(_encoded(request["source_rows"]))
          and value["raw_rows_sha256"] == _digest(_encoded(request["raw_rows"]))
          and value["birth"] == birth and value["affinity"] == request["affinity"]
          and value["initial_descriptors"] == [0, 1, 2],
          "proof child input/Source/raw/process result binding differs")
    facts = value["facts"]
    _need(type(facts) is dict and facts.get("verified") is True
          and facts.get("responses") == 20 and facts.get("five_tuple") == request["receipt"]["five_tuple"]
          and facts.get("acceptance") == request["receipt"]["acceptance"],
          "proof independent facts differ from its exact receipt")
    timing = value["timing"]
    _need(type(timing) is dict and set(timing) == {"reader_wall_ns", "reader_cpu_ns", "child_wall_ns", "child_cpu_ns"}
          and all(type(item) is int and item >= 0 for item in timing.values())
          and timing["reader_wall_ns"] <= timing["child_wall_ns"]
          and timing["reader_cpu_ns"] <= timing["child_cpu_ns"], "proof measured timing differs")
    return facts, timing


@contextmanager
def measure_phase(target, name):
    wall, cpu = time.monotonic_ns(), time.thread_time_ns()
    try:
        yield
    finally:
        target[name] = {"wall_ns": time.monotonic_ns() - wall,
                        "thread_cpu_ns": time.thread_time_ns() - cpu}


class VerificationChildren:
    """Synchronous bounded placement; all mutable authority stays in parent."""
    def __init__(self, capacity=1):
        _need(type(capacity) is int and capacity in (1, 2), "proof child capacity must be1 or2")
        self.capacity = capacity
        self._slots = threading.BoundedSemaphore(capacity)
        self._lock = threading.Lock()
        self._active = {}
        self._closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        # No timeout releases custody or signals/restarts a verifier. Parent
        # executor threads synchronously join every child before this boundary.
        with self._lock:
            active = list(self._active.values())
        for child in active:
            child.wait()
        with self._lock:
            _need(not self._active, "proof children missing parent-owned positive join")
            self._closed = True

    def verify(self, root, receipt):
        queued = time.monotonic_ns()
        with self._slots:
            queue_ns = time.monotonic_ns() - queued
            with self._lock:
                _need(not self._closed, "closed proof child owner cannot be reused")
            affinity = sorted(os.sched_getaffinity(0))
            _need(0 < self.capacity <= len(affinity), "proof capacity exceeds actual auxiliary CPU mask")
            source_root = _canonical(Path(__file__).absolute().parent)
            files = _source_files()
            with _Files(source_root, files, hash_bytes=True) as source, _Files(root, receipt["files"]) as raw:
                request = checked_request({"record_type": REQUEST, "schema_version": 1,
                    "root": str(raw.root), "receipt": receipt, "receipt_sha256": _digest(_encoded(receipt)),
                    "source_root": str(source_root), "source_files": files, "source_rows": source.rows,
                    "raw_rows": raw.rows, "interpreter": _interpreter(), "affinity": affinity,
                    "parent_pid": os.getpid(), "attempt_id": receipt["attempt_id"]})
                payload = _encoded(request)
                _need(len(payload) <= INPUT_LIMIT, "proof request exceeds fixed input bound")
                request_sha = _digest(payload)
                entry = source_root / "resource_study_verify_child.py"
                argv = [sys.executable, "-I", "-B", str(entry), "--request-sha256", request_sha]
                started = time.monotonic_ns()
                with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
                    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=output, stderr=error,
                        cwd=source_root, close_fds=True, start_new_session=True,
                        env={"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
                    with self._lock:
                        self._active[child.pid] = child
                    joined = False
                    try:
                        # Child cannot read the request until this exact process
                        # birth/session is observed, preventing a quick-exit race.
                        birth = _birth(child.pid)
                        _need(birth["uid"] == os.getuid() and birth["gid"] == os.getgid()
                              and birth["pgid"] == birth["sid"] == child.pid,
                              "proof child birth/session owner differs")
                        child.stdin.write(payload)
                        child.stdin.close()
                        returncode = child.wait()
                        joined = True
                        output.seek(0); result = output.read(OUTPUT_LIMIT + 1)
                        error.seek(0); errors = error.read(OUTPUT_LIMIT + 1)
                        _need(len(errors) <= OUTPUT_LIMIT, "proof child stderr exceeds fixed bound")
                        _need(returncode == 0, "readonly proof child refused: " + errors.decode(errors="replace")[:4096])
                        facts, timing = checked_response(result, request, request_sha256=request_sha,
                            birth=birth, joined=joined, returncode=returncode)
                        source.check(); raw.check()
                        _need(_interpreter() == request["interpreter"], "proof interpreter changed")
                        return facts, {**timing, "queue_wall_ns": queue_ns,
                            "exec_through_response_wall_ns": time.monotonic_ns() - started,
                            "capacity": self.capacity, "child_birth": birth,
                            "auxiliary_cpus": affinity, "request_sha256": request_sha,
                            "child_returncode": returncode, "child_joined": True}
                    finally:
                        try:
                            _close_input_and_join(child)
                        finally:
                            # An unobserved exit remains owned by __exit__.
                            # Never drop a live child or signal/relaunch it.
                            if child.returncode is not None:
                                with self._lock:
                                    self._active.pop(child.pid)


def child_main():
    started, cpu_started = time.monotonic_ns(), time.process_time_ns()
    _need(sys.flags.isolated and sys.dont_write_bytecode, "isolated no-bytecode proof interpreter required")
    _need(len(sys.argv) == 3 and sys.argv[1] == "--request-sha256" and _SHA.fullmatch(sys.argv[2]),
          "exact bound readonly proof entry required")
    initial = _open_descriptors()
    _need(initial == [0, 1, 2], "proof child inherited unrelated descriptors")
    payload = sys.stdin.buffer.read(INPUT_LIMIT + 1)
    _need(_digest(payload) == sys.argv[2], "proof input SHA differs")
    request = checked_request(_decode(payload, INPUT_LIMIT))
    _need(_encoded(request) == payload, "proof input canonical JSON differs")
    source_root = _canonical(Path(__file__).absolute().parent)
    _need(str(source_root) == request["source_root"] and _source_files() == request["source_files"]
          and _interpreter() == request["interpreter"] and os.getppid() == request["parent_pid"]
          and sorted(os.sched_getaffinity(0)) == request["affinity"],
          "proof exact Source/interpreter/parent/affinity differs")
    birth = _birth(os.getpid())
    _need(birth["uid"] == os.getuid() and birth["gid"] == os.getgid()
          and birth["pgid"] == birth["sid"] == os.getpid(), "proof own process identity differs")
    with _Files(source_root, request["source_files"], expected=request["source_rows"], hash_bytes=True) as source, \
            _Files(request["root"], request["receipt"]["files"], expected=request["raw_rows"]) as raw:
        from .resource_study_verify import verify_receipt
        wall, cpu = time.monotonic_ns(), time.process_time_ns()
        facts = verify_receipt(raw.root, request["receipt"])
        timing = {"reader_wall_ns": time.monotonic_ns() - wall,
                  "reader_cpu_ns": time.process_time_ns() - cpu}
        source.check(); raw.check()
    _need(_source_files() == request["source_files"] and _interpreter() == request["interpreter"],
          "proof final Source/interpreter differs")
    timing.update(child_wall_ns=time.monotonic_ns() - started, child_cpu_ns=time.process_time_ns() - cpu_started)
    response = {"record_type": RESPONSE, "schema_version": 1, "request_sha256": sys.argv[2],
        "receipt_sha256": request["receipt_sha256"], "root": request["root"], "attempt_id": request["attempt_id"],
        "source_rows_sha256": _digest(_encoded(request["source_rows"])),
        "raw_rows_sha256": _digest(_encoded(request["raw_rows"])), "birth": birth,
        "affinity": request["affinity"], "initial_descriptors": initial, "facts": facts, "timing": timing}
    encoded = _encoded(response)
    _need(len(encoded) <= OUTPUT_LIMIT, "proof output exceeds fixed bound")
    sys.stdout.buffer.write(encoded); sys.stdout.buffer.flush()


if __name__ == "__main__":
    # A direct isolated file entry intentionally imports no CLI/Store/runtime.
    # Package location is derived from the exact entry itself, never caller data.
    sys.path.insert(0, str(Path(__file__).absolute().parents[1]))
    __package__ = "qcsd_lab"
    try:
        child_main()
    except BaseException as failure:
        sys.stderr.write((type(failure).__name__ + ": " + str(failure))[:4096] + "\n")
        raise SystemExit(1)
