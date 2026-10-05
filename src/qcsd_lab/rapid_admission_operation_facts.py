"""One action's observations and first proofs for ordered static accounting.

The original first validators remain the authority. This private memo exists
only in an explicit action, retains no receipt or cross-action authority, and
freshly closes file bytes, modes and observed directory membership before a
publication and before success. Core002 and all GET producers stay unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
import contextvars
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from .rapid_operation_facts import OperationFacts, current_context

ACTION_TYPE = "qcsd-operation-owned-ordered-static-accounting-v1"
_ACTIVE = contextvars.ContextVar("qcsd_static_accounting_action", default=None)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _path(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("accounting dependency requires an absolute nonlinked path")
    return path


def _directory(path):
    path = _path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("accounting membership requires a directory")
    members = {}
    for item in sorted(path.iterdir()):
        mode = item.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("accounting dependency has linked or special membership")
        members[item.name] = {"kind": stat.S_IFMT(mode), "mode": stat.S_IMODE(mode)}
    return {"mode": stat.S_IMODE(info.st_mode), "members": members}


class _Action:
    def __init__(self, context):
        self.context = context
        self.busy = False
        self.directories = {}

    @contextmanager
    def observing(self):
        previous = self.busy
        self.busy = True
        try:
            yield
        finally:
            self.busy = previous

    def file(self, path):
        path = _path(path)
        with self.observing():
            if path not in self.context._files:
                return self.context.watch_file(path)
        return None

    def tree(self, path):
        with self.observing():
            self.context.watch_tree(_path(path))

    def directory(self, path):
        path = _path(path)
        with self.observing():
            if path not in self.directories:
                self.directories[path] = _directory(path)

    def references(self, value):
        if isinstance(value, dict):
            if set(value) in ({"path", "sha256"}, {"path", "sha256", "mode"}):
                self.file(value["path"])
            else:
                for child in value.values():
                    self.references(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self.references(child)

    def close(self):
        with self.observing():
            self.context.check()
            for path, observed in self.directories.items():
                if _directory(path) != observed:
                    raise ValueError("accounting dependency membership or mode changed")


def _observe(event, args):
    owner = _ACTIVE.get()
    if owner is None or owner.busy:
        return
    if event == "open":
        path, _, flags = args
        if not isinstance(path, (str, bytes)) or flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            return
        path = Path(os.fsdecode(path)).absolute()
        # Interpreter/environment reads are not evidence. Executing Lab module
        # files are separately bound below even if installed under sys.prefix.
        if any(path.is_relative_to(Path(root)) for root in (sys.prefix, sys.base_prefix, "/proc", "/sys", "/dev")):
            return
        with owner.observing():
            if path.exists() and stat.S_ISREG(path.lstat().st_mode):
                owner.file(path)
    elif event in {"os.listdir", "os.scandir"} and isinstance(args[0], (str, bytes)):
        path = Path(os.fsdecode(args[0])).absolute()
        if any(path.is_relative_to(Path(root)) for root in (sys.prefix, sys.base_prefix, "/proc", "/sys", "/dev")):
            return
        owner.directory(path)


sys.addaudithook(_observe)


@contextmanager
def action():
    """Own or borrow the current transaction; close before returning success."""
    previous = _ACTIVE.get()
    if previous is not None:
        yield previous.context
        return
    context = current_context()
    if context is None:
        context = OperationFacts()
        context.begin_action()
    owner = _Action(context)
    # Bind all already executing Lab modules before any memo or first proof.
    with owner.observing():
        for name, module in tuple(sys.modules.items()):
            filename = getattr(module, "__file__", None)
            if name.startswith("qcsd_lab") and filename and Path(filename).suffix == ".py":
                owner.file(Path(filename).absolute())
    token = _ACTIVE.set(owner)
    try:
        with context.scope():
            yield context
            owner.close()
    finally:
        _ACTIVE.reset(token)


def before_publication():
    owner = _ACTIVE.get()
    if owner is not None:
        owner.close()


def load_context(root, seen, original):
    owner = _ACTIVE.get()
    if owner is None:
        return original(root, _seen=seen)
    root = Path(root).absolute()
    # Keep the historical cycle refusal ahead of the memo lookup.
    if root in seen:
        raise ValueError("static context successor contains a cycle")
    for name in ("provenance.json", "profile.json", "source-list.json", "candidate-order.json"):
        owner.file(root / name)
    key = (ACTION_TYPE, "static-context", str(root))
    if owner.context.has(key):
        return owner.context.get(key)
    return owner.context.remember(key, original(root, _seen=seen))


def verify_terminal(path, context, original):
    owner = _ACTIVE.get()
    if owner is None:
        return original(path, context)
    path = Path(path).absolute()
    raw = owner.file(path)
    if raw is None:
        # The first proof only parses already observed bytes; subsequent memo
        # hits do not rehash the full raw graph before the final fresh fence.
        raw = path.read_bytes()
    from . import supplied_static_admission as static
    value = static.receipts._unpack(raw, static.TERMINAL_TYPE)
    owner.references(value)
    if value.get("get_evidence_root") is not None:
        owner.tree(value["get_evidence_root"])
    identity = _digest({"provenance": context.provenance, "candidates": context.candidates,
                        "source_sha256": hashlib.sha256(context.source_bytes).hexdigest()})
    key = (ACTION_TYPE, "static-terminal", str(path), str(context.root), identity)
    if owner.context.has(key):
        return owner.context.get(key)
    return owner.context.remember(key, original(path, context))

