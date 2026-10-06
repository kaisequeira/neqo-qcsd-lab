"""One-command reader facts; no persistent authority or original-module edits."""
from contextvars import ContextVar
from contextlib import contextmanager
from copy import deepcopy
from functools import wraps
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
from types import FunctionType, ModuleType

CURRENT = ContextVar('whole_graph_command_facts', default=None)


def file_state(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('linked dependency')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('regular dependency required')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('dependency changed while opening')
        raw = stream.read()
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
            before.st_mode) != (after.st_dev, after.st_ino, after.st_size,
                                after.st_mtime_ns, after.st_mode):
        raise ValueError('dependency changed while reading')
    return raw, (hashlib.sha256(raw).hexdigest(), stat.S_IMODE(after.st_mode))


def tree_state(root):
    root = Path(root).absolute()
    if not root.is_dir() or any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('unlinked dependency directory required')
    result = {'.': ['directory', stat.S_IMODE(root.stat().st_mode)]}
    for p in sorted(root.rglob('*')):
        info = p.lstat()
        if p.is_symlink() or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError('unsupported dependency tree member')
        result[str(p.relative_to(root))] = ['directory' if p.is_dir() else 'file',
                                          stat.S_IMODE(info.st_mode)]
        if len(result) > 16384:
            raise ValueError('dependency tree exceeds declared observation bound')
    return result


class Facts:
    def __init__(self):
        self.files = {}
        self.trees = {}
        self.values = {}
        self.readers = {}
        self.modules = []
        self.building = set()

    def read(self, path):
        path = Path(path).absolute()
        raw, state = file_state(path)
        prior = self.files.get(path)
        if prior is not None and prior != state:
            raise ValueError('observed dependency bytes/full mode changed')
        self.files[path] = state
        return raw

    def watch_tree(self, root):
        root = Path(root).absolute()
        state = tree_state(root)
        if root in self.trees and self.trees[root] != state:
            raise ValueError('observed tree membership/full mode changed')
        self.trees[root] = state

    def check(self):
        for path, expected in self.files.items():
            if file_state(path)[1] != expected:
                raise ValueError('observed dependency bytes/full mode changed')
        for root, expected in self.trees.items():
            if tree_state(root) != expected:
                raise ValueError('observed tree membership/full mode changed')

    def fact(self, key, build):
        if key in self.values:
            self.check()
            return deepcopy(self.values[key])
        if key in self.building:
            raise ValueError('recursive reader dependency cycle')
        self.building.add(key)
        try:
            value = build()
            self.values[key] = deepcopy(value)
            return deepcopy(value)
        finally:
            self.building.remove(key)

    def reader(self, path, digest=None):
        path = Path(path).absolute()
        raw = self.read(path)
        identity = (str(path), hashlib.sha256(raw).hexdigest(), self.files[path][1])
        if digest is not None and identity[1] != digest:
            raise ValueError('pinned reader changed')
        if identity in self.readers:
            return self.readers[identity]
        name = '_command_reader_' + identity[1] + '_' + str(len(self.readers))
        spec = importlib.util.spec_from_file_location(name + '_original', path)
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        fork = ModuleType(name)
        namespace = fork.__dict__
        namespace.update(original.__dict__)
        namespace['__name__'] = name
        for key, value in original.__dict__.items():
            if isinstance(value, FunctionType) and value.__globals__ is original.__dict__:
                namespace[key] = FunctionType(value.__code__, namespace, key,
                    value.__defaults__, value.__closure__)
                namespace[key].__kwdefaults__ = value.__kwdefaults__
        namespace['read'] = lambda p: self.read(p)
        producer = namespace.get('_producer')
        if producer is not None:
            def child(value):
                module = producer(value)
                if module is fork:
                    return fork
                return self.reader(module.__file__)
            namespace['_producer'] = child
        for label in ('_check_plan' if '_check_plan' in namespace else 'check_plan',
                      'verify_input', '_history_batch'):
            function = namespace.get(label)
            if function is None:
                continue
            def wrapper(*args, _function=function, _label=label, **kwargs):
                # Raw path and the executing reader identity are reopened on
                # every hit. All transitive observations close before return.
                primary = Path(args[0]).absolute()
                if _label == '_check_plan' and len(args) > 1 and primary in args[1]:
                    raise ValueError('catalogue declaration lineage contains a cycle')
                primary_raw = self.read(primary)
                extra = ('' if _label == '_check_plan' else
                         repr(args[1:]) + repr(sorted(kwargs.items())))
                key = (identity, _label, str(primary),
                    hashlib.sha256(primary_raw).hexdigest(), self.files[primary][1], extra)
                return self.fact(key, lambda: _function(*args, **kwargs))
            namespace[label] = wrapper
        sys.modules[name] = fork
        self.modules.append(name)
        self.readers[identity] = fork
        # Revalidate the reader after observation; no validation/registration
        # swap can grant authority to different bytes.
        if self.read(path) != raw:
            raise ValueError('reader changed during registration')
        return fork


@contextmanager
def action():
    existing = CURRENT.get()
    if existing is not None:
        yield existing
        return
    facts = Facts()
    token = CURRENT.set(facts)
    try:
        yield facts
        facts.check()
    finally:
        CURRENT.reset(token)
        for name in facts.modules:
            sys.modules.pop(name, None)


def current():
    value = CURRENT.get()
    if value is None:
        raise ValueError('an explicit one-command action scope is required')
    return value
