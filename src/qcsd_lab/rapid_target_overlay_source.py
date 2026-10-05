"""Separately authenticated measurement code and installed capture runtime.

This role authorizes the original complete-lane reader to execute a reviewed
clean module release. It never declares that module release installed in the
measurement image. The existing installed-equality and partial roles stay exact.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from . import rapid_chunk_partial_lane as dynamic
from . import rapid_epoch_corpus as epoch
from . import rapid_fixed_condition_target as target
from .rapid_operation_facts import current_context

SOURCE_TYPE = 'qcsd-fixed-target-reviewed-module-overlay-and-installed-runtime-v1'
CONTRACT = 'original-complete-lane-module-overlay-separate-installed-runtime-v1'
PUBLICATION_KEYS = {'actual_measured_runtime_source_unchanged', 'actual_runtime_rebuilt',
    'base_lab_commit', 'clean_reader_overlay', 'formal_credit_added', 'lab_commit',
    'native_commit', 'published_branches', 'review', 'source_closure'}


def _sources():
    return {name: target.reference(path) for name, path in {
        'overlay': Path(__file__), 'target': Path(target.__file__),
        'dynamic_runtime_reader': Path(dynamic.__file__),
        'original_epoch_reader': Path(epoch.__file__),
    }.items()}


def _digest_reference(value):
    target._keys(value, {'path', 'sha256'}, 'overlay publication digest reference')
    observed = target.reference(value['path'])
    if observed['sha256'] != value['sha256']:
        raise ValueError('overlay publication dependency bytes changed')
    return observed


def _inventory_reference(value):
    target._keys(value, {'path', 'sha256', 'mode', 'size'}, 'overlay inventory reference')
    observed = {key: value[key] for key in ('path', 'sha256', 'mode')}
    path = target._open(observed)
    if type(value['size']) is not int or value['size'] != path.stat().st_size:
        raise ValueError('overlay inventory dependency size changed')
    return observed


def _publication(publication, release):
    """Authenticate the publication/review, then compare relocated full files."""
    raw = json.loads(target._open(publication).read_bytes())
    target._keys(raw, PUBLICATION_KEYS, 'actual reviewed module-overlay publication')
    if (raw['actual_measured_runtime_source_unchanged'] is not True
            or raw['actual_runtime_rebuilt'] is not False
            or type(raw['formal_credit_added']) is not int or raw['formal_credit_added'] != 0
            or raw['lab_commit'] != release['lab_head']
            or raw['native_commit'] != release['native_head']
            or raw['clean_reader_overlay'] != release['root']
            or not isinstance(raw['base_lab_commit'], str)
            or dynamic.HEAD.fullmatch(raw['base_lab_commit']) is None
            or raw['published_branches'] != ['main', 'desktop-portability-2026-09-26']):
        raise ValueError('overlay publication does not retain separate actual runtime and module labels')
    closure_ref = _digest_reference(raw['source_closure'])
    review_ref = _digest_reference(raw['review'])
    closure = json.loads(target._open(closure_ref).read_bytes())
    review = json.loads(target._open(review_ref).read_bytes())
    review_closure = _inventory_reference(review['closure'])
    if (review.get('outcome') != 'no-concrete-blocker' or review_closure != closure_ref
            or review.get('source_root') != closure.get('source_root')
            or closure.get('native_head') != release['native_head']
            or closure.get('native_unchanged') is not True
            or closure.get('source_before_after_unchanged') is not True):
        raise ValueError('overlay publication lacks its exact reviewed unchanged Source closure')
    inventory_ref = _inventory_reference(closure['source_inventory'])
    inventory = json.loads(target._open(inventory_ref).read_bytes())
    target._keys(inventory, {'source_root', 'files'}, 'overlay publication full Source inventory')
    if inventory['source_root'] != closure['source_root'] or not isinstance(inventory['files'], dict):
        raise ValueError('overlay publication inventory lost its author Source identity')
    files = {}
    for name, value in inventory['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name:
            raise ValueError('overlay publication inventory has an escaping name')
        target._keys(value, {'path', 'sha256', 'mode', 'size'}, 'overlay publication inventory member')
        if (value['path'] != str(Path(inventory['source_root']) / name)
                or type(value['mode']) is not int or type(value['size']) is not int or value['size'] < 0):
            raise ValueError('overlay publication inventory member changed identity or mode schema')
        files[name] = {key: value[key] for key in ('sha256', 'mode')}
    expected = {name: {key: ref[key] for key in ('sha256', 'mode')}
                for name, ref in release['files'].items()}
    if files != expected or closure.get('source_file_count') != len(expected):
        raise ValueError('clean overlay differs from its reviewed complete Source files or modes')
    return [publication, closure_ref, review_ref, inventory_ref]


def _module_directories(root):
    # Shallow import membership is watched; these are immutable Source trees,
    # never result/output parents. Full file bytes/modes are independently bound.
    directories = []
    for base in (Path(root) / 'src', Path(root) / 'tools'):
        directories.append(epoch._directory(base))
        for path in sorted(base.rglob('*')):
            if path.is_dir() and '__pycache__' not in path.parts:
                directories.append(epoch._directory(path))
    return directories


def _derive(module_release, publication, runtime_binding):
    # Only the executing trusted runtime reader decides installation validity.
    # The proposed measurement module is never imported for that decision.
    runtime = dynamic._source(runtime_binding)
    if current_context() is not None:
        for relative in ('src', 'tools'):
            current_context().watch_tree(Path(module_release['root']) / relative)
    release = dynamic.release_snapshot(module_release['root'], module_release['lab_head'], module_release['native_head'])
    if release != module_release:
        raise ValueError('measurement module release moved after its declaration')
    module_native = {name: {key: ref[key] for key in ('sha256', 'mode')}
        for name, ref in release['files'].items() if name.startswith('neqo-qcsd/')}
    runtime_native = {name: {key: ref[key] for key in ('sha256', 'mode')}
        for name, ref in runtime['files'].items() if name.startswith('neqo-qcsd/')}
    if (release['native_head'] != runtime['native_head'] or not module_native
            or module_native != runtime_native):
        raise ValueError('overlay module and trusted installed runtime changed Native complement')
    publication_dependencies = _publication(publication, release)
    hashes = {name: ref['sha256'] for name, ref in release['files'].items()
        if Path(name).parent.as_posix() in ('src/qcsd_lab', 'tools') and name.endswith('.py')}
    if not hashes:
        raise ValueError('overlay module lacks its exact original Python authority map')
    runtime_dependencies = dynamic._input_closure(runtime, runtime_binding,
        {'read_dependencies': [], 'directory_dependencies': []}, {})
    dependencies = target._dependency_union(runtime_dependencies,
        {'read_dependencies': [*release['files'].values(), *publication_dependencies, *_sources().values()],
         'directory_dependencies': _module_directories(release['root'])})
    return runtime, {'contract': CONTRACT, 'module_release': release,
        'module_publication': publication, 'publication_dependencies': publication_dependencies,
        'runtime_source_binding': runtime_binding,
        'runtime_identity': runtime['binding']['runtime_identity'],
        'module_overlay_hashes': hashes, 'sources': _sources(),
        'module_installed_claim': False, 'scientific_credit': False, **dependencies}


@target._owned
def bind_source(*, module_root, module_publication, runtime_source_binding, output):
    publication = json.loads(target._open(module_publication).read_bytes())
    target._keys(publication, PUBLICATION_KEYS, 'module-overlay publication')
    release = dynamic.release_snapshot(module_root, publication['lab_commit'], publication['native_commit'])
    runtime, value = _derive(release, module_publication, runtime_source_binding)
    destination = Path(output).absolute()
    for root in (Path(release['root']), Path(runtime['root']), dynamic._consumer_root()):
        if destination.is_relative_to(root):
            raise ValueError('overlay registration cannot enter executing or measured Source')
    value['published_at'] = datetime.now(timezone.utc).isoformat()
    # Recheck the full Git/Source/import closure before creating authority.
    if _derive(release, module_publication, runtime_source_binding)[1] != {k: v for k, v in value.items() if k != 'published_at'}:
        raise ValueError('overlay module or runtime changed before registration')
    return target._write(destination, SOURCE_TYPE, value,
        value['read_dependencies'], value['directory_dependencies'])


@target._owned
def _source(reference):
    value = target._document(reference, SOURCE_TYPE)
    target._keys(value, {'contract', 'module_release', 'module_publication', 'publication_dependencies',
        'runtime_source_binding', 'runtime_identity', 'module_overlay_hashes', 'sources',
        'module_installed_claim', 'scientific_credit', 'read_dependencies', 'directory_dependencies',
        'published_at'}, 'separate overlay/runtime registration')
    runtime, derived = _derive(value['module_release'], value['module_publication'], value['runtime_source_binding'])
    if (not target._typed_equal(derived, {k: v for k, v in value.items() if k != 'published_at'})
            or not target._time(runtime['binding']['published_at']) <= target._time(value['published_at']) <= datetime.now(timezone.utc)):
        raise ValueError('overlay registration differs from original runtime or reviewed module authority')
    # Preserve the actual runtime's existing ABI for the dependency selector.
    # These inherited runtime fields are never relabelled to module release.
    binding = {**runtime['binding'], 'read_dependencies': value['read_dependencies'],
        'directory_dependencies': value['directory_dependencies']}
    return {**value['module_release'], 'binding': binding, 'overlay_registration': value,
            'runtime_root': runtime['root']}


def validate_lane(source, lane):
    registration = source['overlay_registration']
    runtime = source['binding']['runtime']
    identity = source['binding']['runtime_identity']
    spec = lane['spec']
    if (lane['overlay_source_hashes'] != registration['module_overlay_hashes']
            or spec['module_root'] != source['root']
            or spec['runtime_source_root'] != source['runtime_root']
            or lane['runtime_source_root'] != source['runtime_root']
            or lane['measurement_source'] != {**identity['source'], 'image_digest': identity['collection_image_digest']}
            or spec['collection_image_digest'] != identity['collection_image_digest']):
        raise ValueError('original lane changed separate overlay or installed runtime authority')
    for role in ('source_manifest', 'client_binary', 'base_launcher', 'host_launcher'):
        measured = target.reference(spec[role]); installed = target.reference(runtime[role])
        if any(measured[key] != installed[key] for key in ('sha256', 'mode')):
            raise ValueError('original overlay lane runtime copy bytes or mode changed')
    if target.reference(spec['client_binary'])['sha256'] != identity['client_sha256']:
        raise ValueError('original overlay lane client differs from trusted runtime')


def input_closure(source, source_binding, report, operation):
    dependencies = dynamic._input_closure(source, source_binding, report, operation)
    return target._dependency_union(dependencies)
