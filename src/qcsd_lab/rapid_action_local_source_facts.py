"""Reuse authenticated Source and dependency selectors in one owning action.

Results never survive OperationFacts.begin_action. Original validators still run
on the first read; every registered byte, mode and membership is closed by the
unchanged ownership and pre-effect fences.
"""
from functools import wraps
import hashlib
from pathlib import Path
import subprocess

from .rapid_operation_facts import current_context


def _key(function, reference):
    from . import rapid_fixed_condition_target as fixed
    if isinstance(reference, dict) and set(reference) == {'path', 'sha256', 'mode'}:
        fixed._open(reference)
    readers = fixed._sources()
    # Include the helper and selector's executing module, beyond the old roles.
    readers = {**readers, 'memo': fixed.reference(Path(__file__)),
               'selector': fixed.reference(Path(function.__code__.co_filename))}
    if readers['memo']['sha256'] != fixed._ACTION_LOCAL_SOURCE_FACTS_SHA256:
        raise ValueError('action-local Source helper differs from its reviewed bytes')
    return ('action-local-authenticated-selection', function.__module__, function.__name__,
            fixed._digest(reference), fixed._digest(readers))


def _reference(context, reference):
    raw = context.watch_file(Path(reference['path']))
    if (hashlib.sha256(raw).hexdigest() != reference['sha256']
            or Path(reference['path']).stat().st_mode & 0o7777 != reference['mode']):
        raise ValueError('memoized Source dependency bytes or full mode changed')


def _bind_source(context, source):
    binding = source['binding']
    references = [*source['files'].values(), *binding['read_dependencies'],
                  *binding['runtime_operation'].values(), binding['canonical'],
                  *binding['reader_sources'].values()]
    # Overlay bindings expose both original module and actual runtime closures.
    if 'overlay_registration' in source:
        references.extend(source['overlay_registration']['read_dependencies'])
    observed = {}
    for reference in references:
        old = observed.get(reference['path'])
        if old is not None and old != reference:
            raise ValueError('memoized Source dependency aliases disagree')
        observed[reference['path']] = reference
    for reference in observed.values():
        _reference(context, reference)
    for row in binding['directory_dependencies']:
        context.watch_directory(Path(row['path']), expected=row)
    releases = {}
    for release in (source, binding['release']):
        value = {key: release[key] for key in ('root', 'lab_head', 'native_head', 'files')}
        previous = releases.get(value['root'])
        if previous is not None and previous != value:
            raise ValueError('memoized Source release aliases disagree')
        releases[value['root']] = value
    for root_name, release in sorted(releases.items()):
        root = Path(root_name)
        # Source files are individually bound above. Complete import membership
        # closes the original unbound-Python check without scanning unrelated
        # untracked results elsewhere in a retained release.
        for name in ('src', 'tools'):
            context.watch_tree(root / name)
        # Git may be an independent directory or an original submodule gitfile.
        # Fence both actual Git metadata stores; no HEAD/index/stat shortcut.
        for checkout in (root, root / 'neqo-qcsd'):
            gitfile = checkout / '.git'
            if gitfile.is_file():
                context.watch_file(gitfile)
            command = ['git', '-C', str(checkout), 'rev-parse', '--absolute-git-dir', '--git-common-dir']
            paths = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env={'GIT_OPTIONAL_LOCKS': '0'}).stdout.decode().splitlines()
            if len(paths) != 2:
                raise ValueError('memoized Source Git metadata roles changed')
            for name in paths:
                path = Path(name)
                context.watch_tree(path if path.is_absolute() else checkout / path)
        # Tie the first Git-tree observations to the exact original release,
        # including a move between the initial reader and memo registration.
        from . import rapid_chunk_partial_lane as dynamic
        if dynamic.release_snapshot(root, release['lab_head'], release['native_head']) != release:
            raise ValueError('memoized Source release changed before registration')


def source(function):
    """Memoize only a fully validated installed Source binding."""
    @wraps(function)
    def run(reference):
        context = current_context()
        if context is None:
            return function(reference)
        key = _key(function, reference)
        if context.has(key):
            return context.get(key)
        result = function(reference)
        _bind_source(context, result)
        context.remember(key, result)
        return result
    return run


def selection(function):
    """Memoize a dependency projection after its original validators register it."""
    @wraps(function)
    def run(reference):
        context = current_context()
        if context is None:
            return function(reference)
        key = _key(function, reference)
        if context.has(key):
            return context.get(key)
        result = function(reference)
        context.remember(key, result)
        return result
    return run
