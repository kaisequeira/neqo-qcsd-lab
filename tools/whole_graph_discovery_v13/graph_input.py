"""Portable, prospective canonical-homepage whole-graph discovery.

Only ``discover`` makes network/browser calls. Declarations and verification
are create-only or read-only HOST operations and confer no scientific credit.
The actual installed browser identity remains separate from this operator.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, fields
from datetime import datetime, timezone
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
SOURCE_ROOT = HERE.parents[1]
sys.path.insert(0, str(SOURCE_ROOT / 'src'))
_spec = importlib.util.spec_from_file_location('_qcsd_canonical_homepage_v13', HERE / 'canonical_homepage.py')
homepage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(homepage)
from qcsd_lab import class_acquisition as acquisition
from qcsd_lab import class_catalogue as catalogue
from qcsd_lab import discover as browser
from qcsd_lab import discovery_evidence as evidence
from qcsd_lab import manifest as native_manifest
from qcsd_lab import supplied_static_admission as static
from qcsd_lab import supplied_static_graph as static_graph
from qcsd_lab import util
from qcsd_lab import whole_graph_input as intake

PLAN_TYPE = 'qcsd-external-canonical-homepage-whole-graph-catalogue-plan-v13'
INPUT_TYPE = 'qcsd-external-browser-whole-graph-input-v13'
CONTRACT = 'prospectively-resolved-canonical-homepage-complete-occurrence-graph-input-only-v13'
BATCH_TYPE = 'qcsd-complete-v13-ordered-discovery-batch-v1'
SELECTION = 'next-unseen-frozen-catalogue-order-before-measurement-v13'
ZERO = homepage.ZERO
MAX_BATCH = 5
DAEMON = 'unix:///var/run/docker.sock'
RECORDER_SHA = '7e7653fe26a89ecc512a2b17b37438f6af6f3c97ea4f95ee77ea995e27594af7'
OUTER = {'setup_seconds': 240, 'discovery_seconds': 180, 'cleanup_seconds': 30,
         'term_seconds': 450, 'kill_after_seconds': 15, 'maximum_recorded_seconds': 470,
         'docker_host': DAEMON}
LIMITS = {'candidate_deadline_seconds': 180, 'backend_navigation_timeout_ms': 60000,
          'max_origin_passes': 8, 'max_approved_origins': 32}
PLAN_KEYS = {'schema_version', 'artifact_type', 'contract', 'declared_at', 'selection_policy',
    'catalogue', 'catalogue_payload_sha256', 'original_prefix', 'previous_plan', 'previous_batch',
    'reserved_candidates', 'source', 'browser_image', 'source_metadata', 'producer_sources',
    'canonical_homepage_policy', 'candidates', 'passive_render_contract', 'executor_uid_gid', 'outer_budget', *LIMITS, *ZERO}
INPUT_KEYS = {'schema_version', 'artifact_type', 'contract', 'plan', 'original_prefix', 'candidate', 'runtime',
    'canonical_homepage', 'final_source_url', 'navigation_seed_origins', 'passes', 'final_discovery',
    'native_manifest', 'resource_graph_sha256', 'approved_origin_union', 'observed_origins', 'completed_at',
    'elapsed_ns', 'resource_count', 'all_occurrences_and_edges_retained', 'discovery_safe_headers_retained',
    'http3_get_performed', 'browser_qualification_claim', 'challenge_absence_claim', 'response_stability_claim',
    'admission_state', 'attempt_inventory', 'host_validation', *ZERO}
FAILURE_KEYS = {'schema_version', 'artifact_type', 'contract', 'plan', 'candidate', 'runtime', 'completed_at',
    'elapsed_ns', 'error_type', 'message', 'traceback', 'exception_evidence', 'exception_evidence_sha256',
    'completed_passes', 'completed_canonical_homepage', 'failure_stage', 'outcome', 'attempt_inventory', 'host_validation', *ZERO}
FAILURE_TYPE = 'qcsd-canonical-homepage-whole-graph-operational-failure-v13'
require = homepage.require
reference = homepage.reference
reopen = homepage.reopen
load = homepage.load
create = homepage.create
now = homepage.now
utc = homepage.instant


def zero(value):
    return isinstance(value, dict) and all(type(value.get(k)) is type(v) and value[k] == v for k, v in ZERO.items())


def digest(value):
    return intake.discovery_digest(value)


def sources():
    return {name: reference(HERE / name) for name in ('graph_input.py', 'operator.py', 'canonical_homepage.py')}


def source_modules():
    for module in (acquisition, catalogue, browser, evidence, native_manifest, static, static_graph, util, intake):
        require(Path(module.__file__).absolute().parent == SOURCE_ROOT / 'src/qcsd_lab',
                'V13 imported a different operator Source')


def regular_directory(path):
    path = Path(path).absolute()
    require(path.is_dir() and not any(p.is_symlink() for p in (path, *path.parents)), 'bound directory changed type/link')
    return path


def fresh_directory(path, protected):
    path = Path(path).absolute(); regular_directory(path.parent)
    require(not path.exists() and not path.is_symlink(), 'create-only namespace already claimed')
    for item in protected:
        boundary = Path(item).absolute()
        require(path != boundary and not path.is_relative_to(boundary) and not boundary.is_relative_to(path),
                'new namespace overlaps immutable authority')
    path.mkdir(mode=0o700)
    return path


def _git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'}).stdout


def source_snapshot(root):
    root = regular_directory(root)
    require(not _git(root, 'status', '--porcelain', '--untracked-files=no', '--ignore-submodules=untracked').strip(),
            'V13 requires a clean frozen operator checkout')
    result = {'root': str(root), 'lab_commit': _git(root, 'rev-parse', 'HEAD').decode().strip(), 'gitlinks': {}, 'files': {}}
    for item in _git(root, 'ls-files', '--stage', '-z').split(b'\0'):
        if not item:
            continue
        prefix, name = item.split(b'\t', 1); mode, commit, stage = prefix.decode().split(); name = name.decode()
        require(stage == '0' and not Path(name).is_absolute() and '..' not in Path(name).parts, 'operator index is unresolved')
        if mode == '160000':
            require(_git(root / name, 'rev-parse', 'HEAD').decode().strip() == commit
                    and not _git(root / name, 'status', '--porcelain', '--untracked-files=no').strip(), 'Native Gitlink is dirty or moved')
            result['gitlinks'][name] = commit
        else:
            require(mode in ('100644', '100755'), 'operator Source includes unsupported file type')
            ref = reference(root / name)
            result['files'][name] = {'sha256': ref['sha256'], 'mode': ref['mode']}
    verify_snapshot(result)
    require(all(str(HERE / name).startswith(str(root) + '/') and str((HERE / name).relative_to(root)) in result['files']
                for name in sources()), 'V13 producer is not tracked in its frozen operator Source')
    return result


def verify_snapshot(value):
    require(isinstance(value, dict) and set(value) == {'root', 'lab_commit', 'gitlinks', 'files'}
            and re.fullmatch('[0-9a-f]{40}', value['lab_commit']) and set(value['gitlinks']) == {'neqo-qcsd'}
            and re.fullmatch('[0-9a-f]{40}', value['gitlinks']['neqo-qcsd']) and value['files'], 'operator Source identity changed')
    root = regular_directory(value['root'])
    for relative, expected in value['files'].items():
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
                and set(expected) == {'sha256', 'mode'}, 'operator Source inventory escapes root')
        actual = reference(root / relative)
        require({k: actual[k] for k in ('sha256', 'mode')} == expected, 'frozen operator Source bytes/full mode changed')


def validate_metadata(raw, image):
    value = json.loads(raw)
    require(isinstance(value, dict) and set(value) == util.SOURCE_METADATA_KEYS
            and value['image_digest'] in (None, image) and value['lab_dirty'] is False and value['neqo_dirty'] is False
            and value['lab_patch_sha256'] in (None, homepage.digest(b''))
            and value['neqo_patch_sha256'] in (None, homepage.digest(b''))
            and re.fullmatch('[0-9a-f]{40}', value['lab_commit'])
            and re.fullmatch('[0-9a-f]{40}', value['neqo_commit'])
            and value['neqo_pinned_commit'] == value['neqo_commit'], 'actual browser metadata is not a clean declared image')
    return value


def retained_runtime(plan, raw):
    expected = reopen(plan['source_metadata']).read_bytes()
    require(raw == expected, 'actual browser metadata bytes differ from declared export')
    return {'image_digest': plan['browser_image'], 'source_metadata': validate_metadata(raw, plan['browser_image']),
        'installed_metadata_sha256': homepage.digest(raw),
        'execution_role': 'actual-browser-image-canonical-homepage-graph-input-only-v13',
        'external_operator_source': {'lab_commit': plan['source']['lab_commit'], 'gitlinks': plan['source']['gitlinks'],
            'producer_sources': plan['producer_sources'], 'installed_image_source_changed': False}}


def actual_runtime(plan):
    require(os.environ.get('QCSD_LAB_IMAGE_DIGEST') == plan['browser_image']
            and os.environ.get('QCSD_LAB_SOURCE_METADATA') == str(util.DEFAULT_SOURCE_METADATA),
            'physical discovery must run inside the declared browser image')
    return retained_runtime(plan, util.DEFAULT_SOURCE_METADATA.read_bytes())


def original_prefix(value):
    require(isinstance(value, dict) and set(value) == {'role', 'context', 'source_list', 'candidate_order', 'profile',
            'candidate_count', 'candidates', 'domains', *ZERO}
            and value['role'] == 'original-source-and-order-binding-only-no-admission-credit-v1' and zero(value),
            'original static prefix role changed')
    context = load(reopen(value['context']))
    require(set(context) == {'schema_version', 'receipt_type', 'payload', 'payload_sha256'}
            and context['schema_version'] == 1 and context['receipt_type'] == 'qcsd-static-fixed-resource-acquisition-v1'
            and context['payload_sha256'] == homepage.digest((json.dumps(context['payload'], sort_keys=True,
                indent=2, allow_nan=False) + '\n').encode()), 'original context payload changed')
    payload = context['payload']
    for key in ('source_list', 'candidate_order', 'profile'):
        reopen(value[key])
        require(payload[key] == {k: value[key][k] for k in ('path', 'sha256')}, 'original prefix input changed')
    raw = reopen(value['source_list']).read_bytes()
    require(payload['source_sha256'] == value['source_list']['sha256'], 'original prefix source digest changed')
    rows = static_graph._source(raw, value['source_list']['sha256'])
    candidates = static._candidate_rows(raw, value['source_list']['sha256'], load(reopen(value['candidate_order'])))
    require(value['candidates'] == list(candidates) == payload['candidates'] and value['candidate_count'] == len(candidates)
            and value['domains'] == [row['crUX_domain'] for row in rows] and payload['scientific_credit'] is False,
            'original candidate identities/order changed')


def select_candidates(rows, prefix, reserved, count):
    require(type(count) is int and 1 <= count <= MAX_BATCH, 'candidate batch must contain 1..5 identities')
    identities, domains = set(), set(prefix['domains'])
    for candidate in reserved:
        require(candidate['candidate_id'] not in identities and candidate['domain'] not in domains,
                'prior declarations repeat a reserved identity')
        identities.add(candidate['candidate_id']); domains.add(candidate['domain'])
    eligible = [(position, row) for position, row in enumerate(rows, 1)
                if row['candidate_id'] not in identities and row['domain'] not in domains]
    require(len(eligible) >= count, 'frozen catalogue lacks enough unseen identities')
    return [{'catalogue_position': position, **{key: row[key] for key in ('candidate_id', 'domain', 'rank', 'stratum')},
             'source_url': 'https://' + row['domain'] + '/'} for position, row in eligible[:count]]


def legacy_predecessor(previous, batch):
    """Reopen V12 with its genuine separate interpreter, never mixed imports."""
    previous_path = reopen(previous)
    value = intake.load_plan(previous_path)
    require(value['schema_version'] == 12, 'initial V13 predecessor must be genuine V12')
    operator = intake._producer(value)
    action = reopen(value['action_local_sources']['action_facts.py'])
    producer = reopen(value['producer_sources']['graph_input.py'])
    require(action.parent == producer.parent == operator.parent, 'historical V12 program layout changed')
    script = """import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
import action_facts
with action_facts.action():
    graph=action_facts.current().reader(Path(sys.argv[2]),sys.argv[3])
    declaration=graph.check_plan(Path(sys.argv[4]))
    graph.verify_batch(Path(sys.argv[5]),declaration)
"""
    subprocess.run([sys.executable, '-I', '-B', '-c', script, str(producer.parent), str(producer),
        value['producer_sources']['graph_input.py']['sha256'], str(previous_path), str(reopen(batch))],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return value


def predecessor(previous, batch, memo, seen):
    previous_path = reopen(previous)
    value = load(previous_path)
    if value.get('schema_version') == 13:
        value = _check_plan(previous_path, memo, seen)
        verify_batch(reopen(batch), value)
        return value
    key = ('legacy', previous['path'], previous['sha256'], previous['mode'], batch['path'], batch['sha256'], batch['mode'])
    if key not in memo:
        memo[key] = legacy_predecessor(previous, batch)
    return memo[key]


def static_plan(path):
    """Local typed/source/input checks; historical HOST validation is separate."""
    path = Path(path).absolute(); reference(path)
    value = load(path)
    require(isinstance(value, dict) and set(value) == PLAN_KEYS and type(value['schema_version']) is int
            and value['schema_version'] == 13 and value['artifact_type'] == PLAN_TYPE and value['contract'] == CONTRACT
            and value['selection_policy'] == SELECTION and value['producer_sources'] == sources()
            and all(ref['mode'] == '0644' for ref in value['producer_sources'].values())
            and homepage.canonical(value['canonical_homepage_policy']) == homepage.canonical(homepage.POLICY)
            and homepage.canonical(value['outer_budget']) == homepage.canonical(OUTER)
            and re.fullmatch('[0-9]+:[0-9]+', value['executor_uid_gid'])
            and all(type(value[key]) is int and value[key] == expected for key, expected in LIMITS.items())
            and value['passive_render_contract'] == evidence.passive_render_contract() and zero(value), 'V13 declaration policy changed')
    source_modules(); verify_snapshot(value['source'])
    require(Path(value['source']['root']) == SOURCE_ROOT, 'declaration uses another operator checkout')
    for name, ref in sources().items():
        require(value['source']['files'].get(str((HERE / name).relative_to(SOURCE_ROOT)))
                == {k: ref[k] for k in ('sha256', 'mode')}, 'producer is outside frozen operator Source inventory')
    original_prefix(value['original_prefix'])
    receipt, rows = catalogue.load_candidate_catalogue_receipt(reopen(value['catalogue']))
    rows = [row.as_dict() for row in rows]
    require(rows == receipt['payload']['candidates'] and value['catalogue_payload_sha256'] == receipt['payload_sha256'],
            'catalogue complete candidate order changed')
    validate_metadata(reopen(value['source_metadata']).read_bytes(), value['browser_image'])
    require(re.fullmatch('sha256:[0-9a-f]{64}', value['browser_image']), 'browser image must be immutable digest')
    return value, rows


def _check_plan(path, memo, seen):
    path = Path(path).absolute(); ref = reference(path)
    key = (str(path), ref['sha256'], ref['mode'])
    require(path not in seen, 'declaration ancestry cycles')
    if key in memo:
        return memo[key]
    value, rows = static_plan(path)
    previous = predecessor(value['previous_plan'], value['previous_batch'], memo, seen | {path})
    reserved = deepcopy(previous['reserved_candidates']) + deepcopy(previous['candidates'])
    require(value['original_prefix'] == previous['original_prefix'] and value['catalogue'] == previous['catalogue']
            and value['browser_image'] == previous['browser_image'] and value['source_metadata'] == previous['source_metadata']
            and value['reserved_candidates'] == reserved
            and value['candidates'] == select_candidates(rows, value['original_prefix'], reserved, len(value['candidates']))
            and utc(load(reopen(value['previous_batch']))['closed_at']) <= utc(value['declared_at']) <= datetime.now(timezone.utc),
            'V13 changed reserved prefix, frozen selection, browser identity or chronology')
    memo[key] = value
    return value


def check_plan(path):
    return _check_plan(path, {}, frozenset())


def declare_next(previous_plan, previous_batch, count, output):
    previous_ref, batch_ref = reference(previous_plan), reference(previous_batch)
    memo = {}; previous = predecessor(previous_ref, batch_ref, memo, frozenset())
    source = source_snapshot(SOURCE_ROOT)
    receipt, rows = catalogue.load_candidate_catalogue_receipt(reopen(previous['catalogue']))
    rows = [row.as_dict() for row in rows]
    reserved = deepcopy(previous['reserved_candidates']) + deepcopy(previous['candidates'])
    value = {'schema_version': 13, 'artifact_type': PLAN_TYPE, 'contract': CONTRACT, 'declared_at': now(),
        'selection_policy': SELECTION, 'catalogue': previous['catalogue'], 'catalogue_payload_sha256': receipt['payload_sha256'],
        'original_prefix': deepcopy(previous['original_prefix']), 'previous_plan': previous_ref, 'previous_batch': batch_ref,
        'reserved_candidates': reserved, 'source': source, 'browser_image': previous['browser_image'],
        'source_metadata': previous['source_metadata'], 'producer_sources': sources(), 'canonical_homepage_policy': homepage.POLICY,
        'executor_uid_gid': f'{os.getuid()}:{os.getgid()}', 'outer_budget': OUTER,
        'candidates': select_candidates(rows, previous['original_prefix'], reserved, count),
        'passive_render_contract': evidence.passive_render_contract(), **LIMITS, **ZERO}
    authority = dependency_fence(value)
    root = fresh_directory(output, [SOURCE_ROOT, Path(previous_plan).parent, Path(previous_batch).parent,
        *(Path(ref['path']).parent for ref in authority['files'])])
    verify_fence(authority)
    create(root / 'plan.json', value)
    _check_plan(root / 'plan.json', memo, frozenset())
    return root / 'plan.json'


def tree(root, *, excluded=()):
    root = regular_directory(root)
    result = {'root': str(root), 'directories': {'.': f'{stat.S_IMODE(root.stat().st_mode):04o}'}, 'files': {}}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'attempt tree includes link')
        name = str(path.relative_to(root))
        if path.is_dir():
            result['directories'][name] = f'{stat.S_IMODE(path.stat().st_mode):04o}'
        elif path.is_file():
            if name not in excluded:
                result['files'][name] = reference(path)
        else:
            raise ValueError('attempt tree includes nonregular object')
        require(len(result['files']) + len(result['directories']) <= 256, 'attempt exceeds finite raw inventory')
    return result


def verify_tree(value, *, excluded=()):
    require(isinstance(value, dict) and set(value) == {'root', 'directories', 'files'}
            and value == tree(value['root'], excluded=excluded), 'closed attempt membership/bytes/full modes changed')


def dependency_fence(plan):
    """Close transitive immutable references, including original failed trees."""
    files, directories, seen = {}, {}, set()
    def walk(value):
        if isinstance(value, dict):
            if set(value) == {'path', 'sha256', 'mode'}:
                path = reopen(value); files[str(path)] = value
                if path.suffix == '.json' and path not in seen:
                    seen.add(path); walk(load(path))
            elif set(value) == {'path', 'sha256'} and isinstance(value['path'], str):
                path = Path(value['path']).absolute(); ref = reference(path)
                require(ref['sha256'] == value['sha256'], 'historical raw reference changed')
                files[str(path)] = ref
                if path.suffix == '.json' and path not in seen:
                    seen.add(path); walk(load(path))
            if set(value) == {'root', 'lab_commit', 'gitlinks', 'files'}:
                verify_snapshot(value)
                for name in value['files']:
                    ref = reference(Path(value['root']) / name); files[ref['path']] = ref
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
        require(len(files) <= 20000 and len(seen) <= 2000, 'declaration exceeds finite dependency transport')
    walk(plan)
    # A predecessor batch's full Root-recorded raw inventory is authority, even
    # where a historical closure used named operation prefixes rather than refs.
    previous = reopen(plan['previous_batch']).parent
    previous_tree = tree_unbounded(previous)
    for ref in previous_tree['files'].values():
        files[ref['path']] = ref
    directories[str(previous)] = previous_tree['directories']
    return {'files': sorted(files.values(), key=lambda ref: ref['path']), 'trees': directories}


def tree_unbounded(root):
    root = regular_directory(root)
    result = {'root': str(root), 'directories': {'.': f'{stat.S_IMODE(root.stat().st_mode):04o}'}, 'files': {}}
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'historical batch contains a link')
        name = str(path.relative_to(root))
        if path.is_dir():
            result['directories'][name] = f'{stat.S_IMODE(path.stat().st_mode):04o}'
        elif path.is_file():
            result['files'][name] = reference(path)
        else:
            raise ValueError('historical batch contains a nonregular object')
        require(len(result['files']) + len(result['directories']) <= 20000, 'historical batch exceeds finite transport')
    return result


def verify_fence(value):
    for ref in value['files']:
        reopen(ref)
    for root, expected in value['trees'].items():
        actual = tree_unbounded(root)
        require(actual['directories'] == expected
                and set(actual['files']) == {str(Path(ref['path']).relative_to(root)) for ref in value['files']
                    if Path(ref['path']).is_relative_to(root)}, 'historical batch membership/full modes changed')


def transport_roots(plan):
    fence = dependency_fence(plan)
    roots = {SOURCE_ROOT, *(Path(ref['path']).parent for ref in fence['files']), *(Path(root) for root in fence['trees'])}
    return sorted(root for root in roots if not any(root != other and root.is_relative_to(other) for other in roots))


def validate_discovery(value):
    require(isinstance(value, dict) and set(value) == {field.name for field in fields(browser.DiscoveryResult)}
            and value['passive_render_contract'] == evidence.passive_render_contract()
            and value['passive_render_contract_sha256'] == evidence.PASSIVE_RENDER_CONTRACT_SHA256
            and value['render_observation_sha256'] == evidence.evidence_sha256(value['render_observation'])
            and value['discovery_event_audit_sha256'] == evidence.evidence_sha256(value['discovery_event_audit']),
            'browser whole-graph evidence/render policy changed')
    result = intake.project({'approved_origin_union': value['approved_origins'],
        'resource_graph_sha256': digest(value['resources']), 'resource_count': len(value['resources'])},
        {'resources': deepcopy(value['resources'])})
    evidence.verify_discovery_event_audit(value['discovery_event_audit'], render_observation=value['render_observation'],
        resources=value['resources'], exclusions=value['exclusions'], approved_origins=value['approved_origins'],
        observed_request_count=value['observed_request_count'], expected_root_document_url=value['source_url'],
        expected_final_document_url=value['final_url'], expected_observed_origins=value['observed_origins'])
    return result


def discover(plan_path, index, output, host_validation):
    """Root-only physical execution; no Native GET, fitting or admission."""
    plan_path = Path(plan_path).absolute(); plan = physical_plan(plan_path, host_validation)
    require(type(index) is int and 1 <= index <= len(plan['candidates']), 'candidate index leaves declaration')
    authority = dependency_fence(plan); runtime = actual_runtime(plan)
    validation_ref = reference(host_validation)
    root = fresh_directory(output, [SOURCE_ROOT, plan_path.parent,
        Path(host_validation).absolute().parent, *(Path(ref['path']).parent for ref in authority['files'])])
    plan_ref = reference(plan_path); candidate = plan['candidates'][index - 1]
    begun_ns = time.monotonic_ns()
    create(root / 'started.json', {'schema_version': 1, 'plan': plan_ref, 'candidate': candidate,
        'runtime': runtime, 'started_at': now(), **ZERO})
    metadata = util.DEFAULT_SOURCE_METADATA.read_bytes()
    fd = os.open(root / 'image-source-metadata.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(metadata); stream.flush(); os.fsync(stream.fileno())
    passes, canonical_ref = [], None
    stage = 'canonical-homepage-resolution'
    class ObservedBackend:
        def discover(self, url, approved):
            ordinal = len(passes) + 1; prefix = f'pass-{ordinal:02d}'; start_ns = time.monotonic_ns()
            begin = create(root / (prefix + '-started.json'), {'ordinal': ordinal, 'source_url': url,
                'approved_origins': list(approved), 'started_at': now(), 'runtime': actual_runtime(plan), **ZERO})
            pins = acquisition.public_origin_ip_pins(approved)
            result = browser.discover_page(url, allow_origins=list(approved),
                timeout_ms=plan['backend_navigation_timeout_ms'], origin_ip_pins=pins)
            raw = asdict(result); result_ref = create(root / (prefix + '-result.json'), raw)
            validate_discovery(raw)
            end = create(root / (prefix + '-completed.json'), {'ordinal': ordinal, 'started': begin,
                'result': result_ref, 'completed_at': now(), 'elapsed_ns': time.monotonic_ns() - start_ns,
                'runtime': actual_runtime(plan), 'successful_graph_input_pass': True, **ZERO})
            passes.append({'started': begin, 'result': result_ref, 'completed': end})
            return result
    try:
        verify_fence(authority)
        with homepage.deadline(plan['candidate_deadline_seconds']):
            canonical_ref, canonical_value = homepage.resolve(root / 'canonical-homepage', candidate=candidate, plan=plan_ref)
            source_url = canonical_value['final_url']; seeds = [browser.origin(source_url)]
            stage = 'complete-occurrence-convergence'
            approved, result = acquisition._converge_origins(ObservedBackend(), source_url, seed_origins=seeds)
            raw = asdict(result); manifest = validate_discovery(raw)
            require(raw['source_url'] == source_url and approved == raw['approved_origins'], 'final graph changed declared canonical URL')
            stage = 'graph-input-finalization'
            manifest_ref = create(root / 'native-input.json', manifest)
            require(actual_runtime(plan) == runtime, 'browser runtime changed during discovery')
            verify_snapshot(plan['source']); verify_fence(authority)
            envelope = {'schema_version': 13, 'artifact_type': INPUT_TYPE, 'contract': CONTRACT, 'plan': plan_ref,
                'original_prefix': plan['original_prefix'], 'candidate': candidate, 'runtime': runtime,
                'canonical_homepage': canonical_ref, 'final_source_url': source_url, 'navigation_seed_origins': seeds,
                'passes': passes, 'final_discovery': passes[-1]['result'], 'native_manifest': manifest_ref,
                'resource_graph_sha256': digest(raw['resources']), 'approved_origin_union': approved,
                'observed_origins': raw['observed_origins'], 'completed_at': now(), 'elapsed_ns': time.monotonic_ns() - begun_ns,
                'resource_count': len(manifest['resources']), 'all_occurrences_and_edges_retained': True,
                'discovery_safe_headers_retained': True, 'http3_get_performed': False, 'browser_qualification_claim': False,
                'challenge_absence_claim': False, 'response_stability_claim': False,
                'admission_state': 'unqualified-graph-input-only', 'attempt_inventory': tree(root),
                'host_validation': validation_ref, **ZERO}
            create(root / 'whole-graph-input.json', envelope)
    except Exception as error:
        require(not (root / 'whole-graph-input.json').exists(), 'closed successful graph cannot become a failure')
        retained = deepcopy(getattr(error, 'evidence', None))
        require(retained is None or isinstance(retained, dict), 'actual exception evidence is not a mapping')
        create(root / 'failed.json', {'schema_version': 13, 'artifact_type': FAILURE_TYPE, 'contract': CONTRACT,
            'plan': plan_ref, 'candidate': candidate, 'runtime': runtime, 'completed_at': now(),
            'elapsed_ns': time.monotonic_ns() - begun_ns, 'error_type': type(error).__name__, 'message': str(error),
            'traceback': traceback.format_exc(), 'exception_evidence': retained, 'exception_evidence_sha256': digest(retained),
            'completed_passes': passes, 'completed_canonical_homepage': canonical_ref, 'failure_stage': stage,
            'outcome': 'operational-discovery-failure-no-admission', 'attempt_inventory': tree(root),
            'host_validation': validation_ref, **ZERO})
        return 1
    return 0


def attempt_start(path, value, plan):
    root = path.parent
    started = load(root / 'started.json'); raw = (root / 'image-source-metadata.json').read_bytes()
    runtime = retained_runtime(plan, raw)
    require(set(started) == {'schema_version', 'plan', 'candidate', 'runtime', 'started_at', *ZERO}
            and type(started['schema_version']) is int and started['schema_version'] == 1
            and started['plan'] == value['plan'] and started['candidate'] == value['candidate']
            and started['runtime'] == runtime == value['runtime'] and zero(started)
            and value['candidate'] in plan['candidates']
            and utc(plan['declared_at']) <= utc(started['started_at']) <= utc(value['completed_at']) <= datetime.now(timezone.utc)
            and reference(root / 'started.json')['mode'] == reference(root / 'image-source-metadata.json')['mode'] == '0600',
            'actual attempt start/runtime/chronology changed')
    return runtime, utc(started['started_at'])


def verify_passes(records, *, root, source_url, runtime, plan, last_time, require_converged):
    require(isinstance(records, list) and len(records) <= plan['max_origin_passes']
            and (records or not require_converged), 'complete graph lacks finite pass evidence')
    approved, results, converged = {browser.origin(source_url)}, [], False
    for ordinal, refs in enumerate(records, 1):
        require(isinstance(refs, dict) and set(refs) == {'started', 'result', 'completed'} and not converged,
                'graph pass roles changed or continued after convergence')
        documents = {}
        for key, ref in refs.items():
            path = reopen(ref)
            require(path == root / f'pass-{ordinal:02d}-{key}.json' and ref['mode'] == '0600', 'graph raw pass escaped namespace/full mode')
            documents[key] = load(path)
        begin, result, end = (documents[key] for key in ('started', 'result', 'completed'))
        require(set(begin) == {'ordinal', 'source_url', 'approved_origins', 'started_at', 'runtime', *ZERO}
                and set(end) == {'ordinal', 'started', 'result', 'completed_at', 'elapsed_ns', 'runtime',
                    'successful_graph_input_pass', *ZERO}
                and type(begin['ordinal']) is int and begin['ordinal'] == end['ordinal'] == ordinal
                and begin['source_url'] == result['source_url'] == source_url
                and begin['approved_origins'] == result['approved_origins'] == sorted(approved)
                and begin['runtime'] == end['runtime'] == runtime and zero(begin) and zero(end)
                and end['started'] == refs['started'] and end['result'] == refs['result']
                and end['successful_graph_input_pass'] is True and type(end['elapsed_ns']) is int and end['elapsed_ns'] > 0
                and last_time <= utc(begin['started_at']) <= utc(end['completed_at']), 'graph pass identity/chronology changed')
        validate_discovery(result)
        expandable = result['expandable_origins']
        require(isinstance(expandable, list) and expandable == sorted(set(expandable))
                and all(browser.origin(origin) == origin for origin in expandable)
                and set(expandable) <= {browser.origin(origin) for origin in result['observed_origins']},
                'graph omitted its observed expandable-origin ledger')
        expanded = approved | set(expandable)
        require(len(expanded) <= plan['max_approved_origins'], 'graph origin union exceeds stock finite limits')
        converged = expanded == approved; approved = expanded; last_time = utc(end['completed_at']); results.append(result)
    if require_converged:
        require(converged, 'final graph pass has not converged')
        class RecordedBackend:
            index = 0
            def discover(self, url, expected_approved):
                require(self.index < len(results), 'retained passes ended before stock convergence')
                row = results[self.index]; self.index += 1
                require(row['source_url'] == url and row['approved_origins'] == list(expected_approved), 'stock replay input changed')
                return browser.DiscoveryResult(**row)
        replay = RecordedBackend()
        replay_approved, replay_final = acquisition._converge_origins(replay, source_url, seed_origins=[browser.origin(source_url)])
        require(replay.index == len(results) and replay_approved == sorted(approved) and asdict(replay_final) == results[-1],
                'retained graph changes stock convergence output')
    return sorted(approved), results, last_time


def verify_input(path, *, _plan=None):
    path = Path(path).absolute(); ref = reference(path); value = load(path)
    require(path.name == 'whole-graph-input.json' and ref['mode'] == '0600' and isinstance(value, dict)
            and set(value) == INPUT_KEYS and type(value['schema_version']) is int and value['schema_version'] == 13
            and value['artifact_type'] == INPUT_TYPE and value['contract'] == CONTRACT and zero(value)
            and value['all_occurrences_and_edges_retained'] is True and value['discovery_safe_headers_retained'] is True
            and all(value[key] is False for key in ('http3_get_performed', 'browser_qualification_claim',
                'challenge_absence_claim', 'response_stability_claim'))
            and value['admission_state'] == 'unqualified-graph-input-only' and type(value['elapsed_ns']) is int
            and value['elapsed_ns'] > 0 and not path.with_name('failed.json').exists(), 'graph input changed its zero-credit role')
    plan = physical_plan(reopen(value['plan']), reopen(value['host_validation'])) if _plan is None else _plan
    require(load(reopen(value['plan'])) == plan, 'graph declaration changed from the verified batch plan')
    verify_tree(value['attempt_inventory'], excluded=('whole-graph-input.json',))
    require(value['attempt_inventory']['root'] == str(path.parent) and value['original_prefix'] == plan['original_prefix'],
            'graph attempt/prefix namespace changed')
    runtime, last_time = attempt_start(path, value, plan)
    verify_host_validation(reopen(value['host_validation']), reopen(value['plan']), plan)
    require(utc(load(reopen(value['host_validation']))['closed_at']) <= last_time, 'browser predates complete HOST validation')
    canonical_path = reopen(value['canonical_homepage'])
    require(canonical_path == path.parent / 'canonical-homepage/canonical-homepage.json', 'canonical declaration leaves original attempt')
    declaration = homepage.verify(canonical_path, candidate=value['candidate'], plan=value['plan'])
    require(last_time <= utc(declaration['started_at']) and value['final_source_url'] == declaration['final_url']
            and value['navigation_seed_origins'] == [browser.origin(declaration['final_url'])], 'graph changed prospective URL/seed chronology')
    approved, results, last_time = verify_passes(value['passes'], root=path.parent, source_url=declaration['final_url'],
        runtime=runtime, plan=plan, last_time=utc(declaration['declared_at']), require_converged=True)
    final = results[-1]; manifest_path = reopen(value['native_manifest'])
    expected_files = {'started.json', 'image-source-metadata.json', 'native-input.json',
                      str(canonical_path.relative_to(path.parent))}
    for hop in declaration['hops']:
        expected_files.update(str(reopen(ref).relative_to(path.parent)) for ref in hop.values())
    for refs in value['passes']:
        expected_files.update(str(reopen(ref).relative_to(path.parent)) for ref in refs.values())
    require(set(value['attempt_inventory']['files']) == expected_files, 'successful graph retained an unaccounted raw file')
    require(manifest_path == path.parent / 'native-input.json' and value['native_manifest']['mode'] == '0600'
            and load(manifest_path) == validate_discovery(final) and value['final_discovery'] == value['passes'][-1]['result']
            and value['approved_origin_union'] == approved and value['observed_origins'] == final['observed_origins']
            and value['resource_graph_sha256'] == digest(final['resources']) and type(value['resource_count']) is int
            and value['resource_count'] == len(final['resources']) and last_time <= utc(value['completed_at']),
            'complete graph final binding pruned or rewrote original occurrences/edges')
    verify_snapshot(plan['source']); verify_tree(value['attempt_inventory'], excluded=('whole-graph-input.json',)); reopen(ref)
    return {'input_ref': ref, 'resource_count': value['resource_count'], 'pass_count': len(results),
            'approved_origin_count': len(approved), **ZERO}


def verify_failure(path, *, _plan=None):
    path = Path(path).absolute(); ref = reference(path); value = load(path)
    require(path.name == 'failed.json' and ref['mode'] == '0600' and isinstance(value, dict) and set(value) == FAILURE_KEYS
            and type(value['schema_version']) is int and value['schema_version'] == 13 and value['artifact_type'] == FAILURE_TYPE
            and value['contract'] == CONTRACT and zero(value) and value['outcome'] == 'operational-discovery-failure-no-admission'
            and value['failure_stage'] in ('canonical-homepage-resolution', 'complete-occurrence-convergence', 'graph-input-finalization')
            and type(value['elapsed_ns']) is int and value['elapsed_ns'] > 0
            and all(isinstance(value[key], str) and value[key] for key in ('error_type', 'traceback'))
            and isinstance(value['message'], str) and (value['exception_evidence'] is None or isinstance(value['exception_evidence'], dict))
            and value['exception_evidence_sha256'] == digest(value['exception_evidence'])
            and not path.with_name('whole-graph-input.json').exists(), 'closed successful graph cannot become a zero-credit failure')
    plan = physical_plan(reopen(value['plan']), reopen(value['host_validation'])) if _plan is None else _plan
    require(load(reopen(value['plan'])) == plan, 'failure declaration changed from the verified batch plan')
    verify_tree(value['attempt_inventory'], excluded=('failed.json',))
    require(value['attempt_inventory']['root'] == str(path.parent), 'failure closed a different raw attempt')
    runtime, last_time = attempt_start(path, value, plan)
    verify_host_validation(reopen(value['host_validation']), reopen(value['plan']), plan)
    require(utc(load(reopen(value['host_validation']))['closed_at']) <= last_time, 'failed attempt predates complete HOST validation')
    canonical_ref = value['completed_canonical_homepage']
    if canonical_ref is None:
        require(value['failure_stage'] == 'canonical-homepage-resolution' and value['completed_passes'] == []
                and not (path.parent / 'canonical-homepage/canonical-homepage.json').exists()
                and not any(name.startswith('pass-') or name == 'native-input.json' for name in value['attempt_inventory']['files']),
                'incomplete resolution gained a successful canonical declaration or graph')
        homepage.verify_partial(path.parent / 'canonical-homepage', candidate=value['candidate'], plan=value['plan'],
            not_before=last_time, not_after=utc(value['completed_at']))
    else:
        canonical_path = reopen(canonical_ref)
        require(canonical_path == path.parent / 'canonical-homepage/canonical-homepage.json'
                and value['failure_stage'] != 'canonical-homepage-resolution', 'failure changed completed canonical role')
        declaration = homepage.verify(canonical_path, candidate=value['candidate'], plan=value['plan'])
        require(last_time <= utc(declaration['started_at']), 'failure canonical chronology changed')
        approved, results, last_time = verify_passes(value['completed_passes'], root=path.parent, source_url=declaration['final_url'],
            runtime=runtime, plan=plan, last_time=utc(declaration['declared_at']), require_converged=False)
        partial_ordinal = len(value['completed_passes']) + 1
        named = {f'pass-{ordinal:02d}-{key}.json' for ordinal in range(1, partial_ordinal)
                 for key in ('started', 'result', 'completed')}
        leftovers = {name for name in value['attempt_inventory']['files'] if name.startswith('pass-')} - named
        expected_start, expected_result = (f'pass-{partial_ordinal:02d}-{key}.json' for key in ('started', 'result'))
        require(leftovers in (set(), {expected_start}, {expected_start, expected_result})
                and (not leftovers or partial_ordinal <= plan['max_origin_passes']), 'failure altered its finite incomplete graph prefix')
        if leftovers:
            begin = load(path.parent / expected_start)
            require(set(begin) == {'ordinal', 'source_url', 'approved_origins', 'started_at', 'runtime', *ZERO}
                    and type(begin['ordinal']) is int and begin['ordinal'] == partial_ordinal
                    and begin['source_url'] == declaration['final_url'] and begin['approved_origins'] == approved
                    and begin['runtime'] == runtime and zero(begin)
                    and last_time <= utc(begin['started_at']) <= utc(value['completed_at']), 'incomplete actual graph command changed')
            if expected_result in leftovers:
                raw = load(path.parent / expected_result)
                require(isinstance(raw, dict) and set(raw) == {field.name for field in fields(browser.DiscoveryResult)}
                        and raw['source_url'] == begin['source_url'] and raw['approved_origins'] == approved,
                        'incomplete raw graph changed its original request identity')
    require(last_time <= utc(value['completed_at']), 'failure terminal predates retained completed work')
    verify_snapshot(plan['source']); verify_tree(value['attempt_inventory'], excluded=('failed.json',)); reopen(ref)
    return {'failure_ref': ref, 'failure_stage': value['failure_stage'], **ZERO}


def operation(prefix, expected_code, *, command):
    prefix = Path(prefix).absolute()
    refs = {role: reference(Path(str(prefix) + suffix)) for role, suffix in (
        ('started', '-started.json'), ('completed', '-completed.json'), ('stdout', '.stdout.log'), ('stderr', '.stderr.log'))}
    started, completed = (load(reopen(refs[key])) for key in ('started', 'completed'))
    require(started['command'] == command and type(completed['returncode']) is int
            and completed['returncode'] == expected_code and completed['stdout_sha256'] == refs['stdout']['sha256']
            and completed['stderr_sha256'] == refs['stderr']['sha256']
            and utc(started['started_at']) <= utc(completed['completed_at']) <= datetime.now(timezone.utc),
            'actual operation command/terminal/raw log identity changed')
    return refs, started, completed


def command(plan, plan_path, root, local, container_prefix, host_validation):
    require(type(local) is int and 1 <= local <= len(plan['candidates'])
            and isinstance(container_prefix, str) and re.fullmatch('[a-z0-9][a-z0-9-]{2,80}', container_prefix),
            'bounded local mapping/container identity required')
    validation = load(Path(host_validation).absolute())
    roots = set(transport_roots(plan)) | {Path(plan_path).absolute().parent, Path(host_validation).absolute().parent,
        reopen(validation['recorder']).parent}
    roots = sorted(path for path in roots if not any(path != other and path.is_relative_to(other) for other in roots))
    attempts = Path(root).absolute() / 'attempts'
    require(not any(attempts.is_relative_to(path) or path.is_relative_to(attempts) for path in roots),
            'writable attempts overlap immutable authority')
    argv = ['timeout', '--signal=TERM', '--kill-after=15s', '450s', 'docker', '--host', DAEMON,
        'run', '--rm', '--init', '--name', f'{container_prefix}-{local:03d}', '--network', 'bridge',
        '--user', plan['executor_uid_gid'], '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
        '--env', 'QCSD_LAB_IMAGE_DIGEST=' + plan['browser_image'],
        '--env', 'QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json',
        '--env', 'QCSD_PUBLIC_ORIGIN_ONLY=1', '--env', 'PYTHONDONTWRITEBYTECODE=1']
    for path in roots:
        require(path.is_absolute() and not any(character in str(path) for character in (':', '\n', '\r', '\0')),
                'immutable transport contains a delimiter')
        argv += ['--volume', f'{path}:{path}:ro']
    return argv + ['--volume', f'{attempts}:{attempts}:rw', '--workdir', str(SOURCE_ROOT),
        '--entrypoint', '/opt/qcsd-venv/bin/python3', plan['browser_image'], '-I', '-B', str(HERE / 'operator.py'),
        'discover', '--plan', str(Path(plan_path).absolute()), '--candidate-index', str(local),
        '--output', str(attempts / f'candidate-{local:06d}'), '--host-validation', str(Path(host_validation).absolute())]


def recorder(path):
    path = Path(path).absolute()
    require(reference(path)['sha256'] == RECORDER_SHA and reference(path)['mode'] == '0644', 'original Root recorder changed')
    spec = importlib.util.spec_from_file_location('_qcsd_original_v13_root_recorder', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def recorded(record, root, step, argv):
    try:
        record.recorded_run(argv, root / 'operations', step, cwd=root)
    except RuntimeError:
        pass
    completed = load(root / 'operations' / (step + '-completed.json'))
    code = completed['returncode']; operation(root / 'operations' / step, code, command=argv)
    return code


def actors(record, root, step):
    argv = ['docker', '--host', DAEMON, 'ps', '--format', '{{.ID}} {{.Names}}']
    require(recorded(record, root, step, argv) == 0
            and not (root / 'operations' / (step + '.stdout.log')).read_bytes().strip()
            and not (root / 'operations' / (step + '.stderr.log')).read_bytes().strip(),
            'physical actors reserve the discovery boundary')


def bind_host_validation(plan_path, root, record, recorder_path):
    """Record the full HOST check once, before claiming a browser actor."""
    plan_path = Path(plan_path).absolute()
    argv = [sys.executable, '-I', '-B', str(HERE / 'operator.py'), 'check', '--plan', str(plan_path)]
    require(recorded(record, root, 'host-plan-check', argv) == 0, 'complete HOST declaration verification refused')
    plan, _ = static_plan(plan_path)
    refs, _, _ = operation(root / 'operations/host-plan-check', 0, command=argv)
    value = {'schema_version': 1, 'artifact_type': 'qcsd-complete-v13-host-plan-validation-v1',
        'plan': reference(plan_path), 'producer_sources': sources(), 'recorder': reference(recorder_path),
        'verify_interpreter': str(Path(sys.executable).absolute()), 'check_operation': refs,
        'dependency_fence': dependency_fence(plan), 'closed_at': now(), **ZERO}
    output = root / 'operations/host-plan-validation.json'; create(output, value)
    verify_host_validation(output, plan_path, plan)
    return output


def verify_host_validation(path, plan_path, plan):
    path = Path(path).absolute(); value = load(path)
    require(reference(path)['mode'] == '0600' and isinstance(value, dict)
            and set(value) == {'schema_version', 'artifact_type', 'plan', 'producer_sources', 'recorder',
                'verify_interpreter', 'check_operation', 'dependency_fence', 'closed_at', *ZERO}
            and type(value['schema_version']) is int and value['schema_version'] == 1
            and value['artifact_type'] == 'qcsd-complete-v13-host-plan-validation-v1'
            and value['plan'] == reference(plan_path) and value['producer_sources'] == plan['producer_sources']
            and value['recorder']['sha256'] == RECORDER_SHA and value['recorder']['mode'] == '0644'
            and Path(value['verify_interpreter']).is_absolute() and zero(value), 'HOST prebirth validation identity changed')
    reopen(value['recorder'])
    command = [value['verify_interpreter'], '-I', '-B', str(HERE / 'operator.py'), 'check', '--plan', str(Path(plan_path).absolute())]
    refs, _, end = operation(path.parent / 'host-plan-check', 0, command=command)
    require(value['check_operation'] == refs and all(ref['mode'] == '0644' for ref in refs.values()),
            'HOST original operation/raw full modes changed')
    summary = load(reopen(refs['stdout']))
    require(isinstance(summary, dict) and set(summary) == {'status', 'action', 'candidate_count', *ZERO}
            and summary['status'] == 'closed' and summary['action'] == 'check' and zero(summary)
            and type(summary['candidate_count']) is int and summary['candidate_count'] == len(plan['candidates'])
            and utc(end['completed_at']) <= utc(value['closed_at']) <= datetime.now(timezone.utc),
            'HOST public declaration check did not genuinely close before browser birth')
    require(value['dependency_fence'] == dependency_fence(plan), 'HOST complete immutable dependency membership changed')
    verify_fence(value['dependency_fence'])
    return value


def physical_plan(plan_path, host_validation):
    plan, _ = static_plan(plan_path)
    verify_host_validation(host_validation, plan_path, plan)
    return plan


def validate(plan_path, output, recorder_path):
    plan_path = Path(plan_path).absolute(); plan, _ = static_plan(plan_path)
    authority = dependency_fence(plan); record = recorder(recorder_path)
    root = fresh_directory(output, [SOURCE_ROOT, plan_path.parent, *(Path(ref['path']).parent for ref in authority['files'])])
    (root / 'operations').mkdir(mode=0o700)
    return bind_host_validation(plan_path, root, record, recorder_path)


def run(plan_path, plan_sha256, output, container_prefix, recorder_path):
    """Root-only five-or-fewer serial candidates; preserve unexpected failures."""
    plan_path = Path(plan_path).absolute()
    require(reference(plan_path)['sha256'] == plan_sha256, 'reviewed prospective plan bytes changed')
    plan, _ = static_plan(plan_path); authority = dependency_fence(plan); record = recorder(recorder_path)
    root = fresh_directory(output, [SOURCE_ROOT, plan_path.parent, *(Path(ref['path']).parent for ref in authority['files'])])
    (root / 'operations').mkdir(mode=0o700); (root / 'attempts').mkdir(mode=0o700)
    validation = bind_host_validation(plan_path, root, record, recorder_path)
    create(root / 'inputs.json', {'plan': reference(plan_path), 'producer_sources': sources(),
        'recorder': reference(recorder_path), 'verify_interpreter': str(Path(sys.executable).absolute()),
        'host_validation': reference(validation), 'container_prefix': container_prefix,
        'candidate_ids': [row['candidate_id'] for row in plan['candidates']], **ZERO})
    rows = []
    for local, candidate in enumerate(plan['candidates'], 1):
        verify_fence(authority); require(reference(plan_path)['sha256'] == plan_sha256, 'declared plan changed')
        actors(record, root, f'candidate-{local:06d}-before-actors')
        argv = command(plan, plan_path, root, local, container_prefix, validation)
        verify_fence(authority)
        code = recorded(record, root, f'candidate-{local:06d}-discover', argv)
        attempt = root / 'attempts' / f'candidate-{local:06d}'
        require(code in (0, 1), 'unexpected outer status leaves a pending reservation; preserve original attempt')
        action, key, evidence_path = ('verify-input', '--input', attempt / 'whole-graph-input.json') if code == 0 else (
            'verify-failure', '--failure', attempt / 'failed.json')
        verification = [sys.executable, '-I', '-B', str(HERE / 'operator.py'), action, key, str(evidence_path)]
        require(recorded(record, root, f'candidate-{local:06d}-{action}', verification) == 0,
                'public verification refused original graph or failure')
        verify_fence(authority); actors(record, root, f'candidate-{local:06d}-after-actors')
        row = {'local_index': local, 'candidate': candidate, 'discovery_returncode': code,
               'evidence': reference(evidence_path), **ZERO}
        create(root / f'candidate-{local:06d}-closed.json', row); rows.append(row)
    result = {'schema_version': 1, 'artifact_type': BATCH_TYPE, 'plan': reference(plan_path),
              'candidates': rows, 'closed_at': now(), **ZERO}
    verify_fence(authority); create(root / 'batch-closed.json', result)
    verify_batch(root / 'batch-closed.json', plan)
    return root / 'batch-closed.json'


def verify_batch(path, plan):
    path = Path(path).absolute(); value = load(path)
    require(isinstance(value, dict) and set(value) == {'artifact_type', 'schema_version', 'plan', 'candidates', 'closed_at', *ZERO}
            and value['artifact_type'] == BATCH_TYPE and type(value['schema_version']) is int and value['schema_version'] == 1
            and load(reopen(value['plan'])) == plan and zero(value) and isinstance(value['candidates'], list)
            and len(value['candidates']) == len(plan['candidates']), 'V13 full ordered batch changed its declaration/zero credit')
    root = path.parent; inputs = load(root / 'inputs.json')
    require(set(inputs) == {'plan', 'producer_sources', 'recorder', 'verify_interpreter', 'host_validation', 'container_prefix', 'candidate_ids', *ZERO}
            and inputs['plan'] == value['plan'] and inputs['producer_sources'] == plan['producer_sources']
            and inputs['recorder']['sha256'] == RECORDER_SHA and inputs['recorder']['mode'] == '0644'
            and Path(inputs['verify_interpreter']).is_absolute() and zero(inputs)
            and inputs['candidate_ids'] == [row['candidate_id'] for row in plan['candidates']], 'V13 batch Root controller identity changed')
    reopen(inputs['recorder'])
    validation = reopen(inputs['host_validation']); verify_host_validation(validation, reopen(value['plan']), plan)
    last_time = utc(plan['declared_at'])
    for local, (candidate, row) in enumerate(zip(plan['candidates'], value['candidates']), 1):
        require(isinstance(row, dict) and set(row) == {'local_index', 'candidate', 'evidence', 'discovery_returncode', *ZERO}
                and type(row['local_index']) is int and row['local_index'] == local and row['candidate'] == candidate
                and type(row['discovery_returncode']) is int and row['discovery_returncode'] in (0, 1) and zero(row),
                'V13 ordered batch changed candidate/returncode')
        require(row == load(root / f'candidate-{local:06d}-closed.json'), 'original Root candidate closure changed')
        actor_command = ['docker', '--host', DAEMON, 'ps', '--format', '{{.ID}} {{.Names}}']
        before, before_start, before_end = operation(root / 'operations' / f'candidate-{local:06d}-before-actors',
            0, command=actor_command)
        require(not reopen(before['stdout']).read_bytes().strip() and not reopen(before['stderr']).read_bytes().strip()
                and last_time <= utc(before_start['started_at']), 'actual actor-absence boundary missing')
        discover_refs, discover_start, discover_end = operation(root / 'operations' / f'candidate-{local:06d}-discover',
            row['discovery_returncode'], command=command(plan, reopen(value['plan']), root, local, inputs['container_prefix'], validation))
        require(utc(before_end['completed_at']) <= utc(discover_start['started_at'])
                and 0 < discover_end['elapsed_seconds'] <= OUTER['maximum_recorded_seconds'], 'actual discovery outer bound changed')
        evidence_path = reopen(row['evidence']); retained = load(evidence_path)
        inner_start = load(evidence_path.parent / 'started.json')
        require(evidence_path.parent == root / 'attempts' / f'candidate-{local:06d}'
                and retained['plan'] == value['plan'] and retained['candidate'] == candidate
                and retained['host_validation'] == inputs['host_validation']
                and utc(discover_start['started_at']) <= utc(inner_start['started_at']) <= utc(retained['completed_at'])
                    <= utc(discover_end['completed_at'])
                and (utc(inner_start['started_at']) - utc(discover_start['started_at'])).total_seconds() <= OUTER['setup_seconds'],
                'V13 batch changed original attempt identity/order/setup chronology')
        if row['discovery_returncode'] == 0:
            verify_input(evidence_path, _plan=plan)
            action, key = 'verify-input', '--input'
        else:
            verify_failure(evidence_path, _plan=plan)
            action, key = 'verify-failure', '--failure'
        verify_refs, verify_start, verify_end = operation(root / 'operations' / f'candidate-{local:06d}-{action}',
            0, command=[inputs['verify_interpreter'], '-I', '-B', str(HERE / 'operator.py'), action, key, str(evidence_path)])
        after, after_start, after_end = operation(root / 'operations' / f'candidate-{local:06d}-after-actors', 0, command=actor_command)
        require(utc(discover_end['completed_at']) <= utc(verify_start['started_at']) <= utc(verify_end['completed_at'])
                    <= utc(after_start['started_at']) and not reopen(after['stdout']).read_bytes().strip()
                and not reopen(after['stderr']).read_bytes().strip(), 'public verification or terminal actor boundary changed')
        last_time = utc(after_end['completed_at'])
    require(last_time <= utc(value['closed_at']) <= datetime.now(timezone.utc), 'batch closed before complete ordered attempts')
    return value
