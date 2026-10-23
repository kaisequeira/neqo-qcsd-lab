"""Focused ordinary preparation for one fixed FRONT or Tamaraw cell.

This prospective consumer preserves the original preparation/readiness and
ownpilot contracts. It skips URL discovery because the exact admitted twenty
are already frozen. It runs one strict twenty-resource GET and the original
three qualifications of the deterministic selected chaff resource. It does
not run a defense during preparation or grant formal recording credit.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

from .resource_study_store import StudyStore
from .util import load_json, sha256_file

INPUT = 'qcsd-resource-domain-focused-fixed-mode-preparation-input-v1'
RESULT = 'qcsd-resource-domain-focused-fixed-mode-preparation-result-v1'
MODES = ('front', 'tamaraw')
NATIVE142 = 'f64210a47fcd81b9ec75a076e892b4cf4d87e987'
CANONICAL142_SHA256 = '4fd41d2f41bc1f2359be4b1b17a7ef6b61620034aef12fbc570b48c3abdbe4e9'


def _selected_mode(value):
    if value not in MODES:
        raise ValueError('focused ordinary preparation supports only fixed FRONT or Tamaraw')
    return value


def _read(path, digest=None, *, observations=None):
    from .resource_study_native import retained_mode_read
    return retained_mode_read(Path(path), digest, observations=observations)


def _same(a, b):
    from .resource_study_inputs import canonical_json
    return canonical_json(a) == canonical_json(b)


def _fence_inputs(checked):
    for item in checked['input_observations'].values():
        path = item[0]
        info = path.lstat()
        current = (path, info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_nlink, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if current != item or any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('focused fixed-mode immutable input FD/path changed across operation')


def _fixed_science_preflight(science, prepared, mode):
    from . import resource_study_native as n
    from . import front_fixed_configuration as front, tamaraw_fixed_configuration as tamaraw
    module = front if mode == 'front' else tamaraw
    policies = n.mode_policies()[mode]
    expected = {'profile':'research-1200', 'request_policy':'as-defined',
        'max_response_bytes':n.MAX_RESPONSE_BYTES, 'udp_payload_ceiling':1200,
        'policies':policies, 'configuration_sha256':module.configuration_sha256(),
        'resolved_configuration':module.resolved_configuration(),
        'timeout_seconds':120, 'capture_seconds':180}
    if not _same(science['settings'], expected) or not _same(science['policies'], policies):
        raise ValueError('focused preparation requires the exact original fixed mode profile')
    module.validate_prepared(prepared)


def _science(enrollment, mode):
    return {'hostname': enrollment['hostname'], 'urls': enrollment['urls'],
        'workload_sha256': enrollment['workload_sha256'],
        'settings': enrollment['mode_settings'][mode],
        'policies': enrollment['mode_policies'][mode]}


def _replay_qualified_assets(base, enrollment):
    """Use the existing complete generic three-receipt asset validator.

    Its historical BuFLO parameter projection is a finite launch-byte check;
    it executes no defense and grants no mode readiness or capture credit.
    FRONT/Tamaraw science is separately compared in full by the caller.
    """
    from . import resource_study_native as n
    if ('buflo_chaff_selection' in enrollment
            or 'buflo_small_response_aggregate_selection' in enrollment):
        raise ValueError('fixed F/T preparation requires original generic schema-three chaff')
    return n._retained_old_assets(Path(base), enrollment, _science(enrollment, 'buflo'))


def checked_input(root, runtime, input_path, input_sha256):
    from . import resource_study_native as n
    from .resource_study_cohorts import verifier_contract
    observed = {}
    raw = _read(input_path, input_sha256, observations=observed)
    value = json.loads(raw)
    fields = {'record_type', 'schema_version', 'root', 'parent', 'hostname', 'mode',
        'historical_root', 'historical_enrollment', 'runtime', 'science',
        'source_contract', 'canonical_runtime', 'resource_selection', 'scientific_credit'}
    if (type(value) is not dict or set(value) != fields or value['record_type'] != INPUT
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['root'] != str(Path(root).absolute()) or value['scientific_credit'] is not False
            or not _same(value['runtime'], n._retained_runtime(runtime))
            or not _same(value['source_contract'], verifier_contract())
            or type(value['parent']) is not dict
            or set(value['parent']) != {'root', 'study_sha256', 'head_sha256'}):
        raise ValueError('focused preparation changes explicit root/runtime/Source/parent scope')
    mode = _selected_mode(value['mode'])
    if (runtime['native_commit'] != NATIVE142 or runtime['source']['neqo_commit'] != NATIVE142
            or runtime['canonical_sha256'] != CANONICAL142_SHA256):
        raise ValueError('focused F/T preparation requires the genuine existing Native142 full runtime')
    canonical_path, canonical_sha = n._retained_ref(value['canonical_runtime'])
    n.retained_mode_read(canonical_path, canonical_sha, canonical_runtime=True, observations=observed)
    if canonical_sha != runtime['canonical_sha256']:
        raise ValueError('focused preparation canonical reference differs from the full runtime')
    from .resource_study import runtime_identity
    if not _same(runtime_identity(canonical_path), runtime):
        raise ValueError('focused preparation runtime was not fully authenticated')
    old_root = Path(value['historical_root'])
    old_path, old_sha = n._retained_ref(value['historical_enrollment'])
    if (not old_root.is_absolute() or old_root == Path(root).absolute()
            or old_path != old_root / 'classes' / value['hostname'] / 'enrollment.json'):
        raise ValueError('focused preparation historical reference is not its enrolled original class')
    old = json.loads(_read(old_path, old_sha, observations=observed))
    if (old.get('hostname') != value['hostname'] or old.get('scientific_credit') is not False
            or not _same(value['science'], _science(old, mode))
            or len(old['urls']) != len(set(old['urls'])) or len(old['urls']) != 20):
        raise ValueError('focused preparation changed its original same-host twenty or fixed mode science')
    manifest_relative = n._retained_relative(old['paths']['manifest'])
    manifest_sha = old['files'][manifest_relative]
    manifest_raw = _read(old_root / manifest_relative, manifest_sha, observations=observed)
    if manifest_sha != old['workload_sha256']:
        raise ValueError('historical class workload reference changed')
    from .resource_study_selection import validate_frozen_application_manifest_bytes
    validate_frozen_application_manifest_bytes(manifest_raw, value['hostname'], old['urls'])
    prepared_relative = n._retained_relative(old['paths']['prepared_workload'])
    prepared = json.loads(_read(old_root / prepared_relative, old['files'][prepared_relative], observations=observed))
    if not _same(prepared['resources'], json.loads(manifest_raw)['resources']):
        raise ValueError('historical prepared application changed its exact frozen graph')
    _fixed_science_preflight(value['science'], prepared, mode)
    _fence_inputs({'input_observations':observed})
    return {'input': value, 'input_raw': raw, 'input_sha256': input_sha256, 'input_observations':observed,
        'historical': old, 'manifest': {'path': str(old_root / manifest_relative), 'sha256': manifest_sha},
        'historical_prepared': prepared}


def enroll_fixed_mode(root, runtime, *, input_path, input_sha256, backend=None):
    """Original ordinary enrollment, with a focused real preparation backend."""
    from . import resource_study as study, resource_study_cohorts as c
    from . import resource_study_native as n
    root = Path(root).absolute()
    from .resource_study_lineage import INCLUDED
    checked = checked_input(root, runtime, input_path, input_sha256)
    value = checked['input']
    with study._retained_source_operation():
        context = study._retained_current_scope(StudyStore(root), checked)
        if backend is None:
            backend = FocusedFixedModePreparationRuntime(root, runtime, checked)
        selection_path, selection_sha = n._retained_ref(value['resource_selection'])
        try:
            frozen_options = ({} if value['hostname'] == INCLUDED else {
                'frozen_application_manifest': Path(checked['manifest']['path']),
                'frozen_application_manifest_sha256': checked['manifest']['sha256']})
            result = study.enroll(root, runtime, [value['hostname']], backend=backend,
                resource_selection=selection_path, resource_selection_sha256=selection_sha,
                **frozen_options)
            rows = result.get('enrollment')
            if (type(rows) is not list or len(rows) != 1
                    or rows[0].get('hostname') != value['hostname']
                    or rows[0].get('status') != 'enrolled'):
                raise ValueError('focused preparation did not enroll its sole declared class: ' + str(rows))
            if not _same(c._input_context(root, StudyStore(root).plan())[0], context):
                raise ValueError('parent input context changed during focused fixed-mode preparation')
            _read(input_path, input_sha256)
            return {'record_type': RESULT, 'schema_version': 1, 'hostname': value['hostname'],
                'mode': value['mode'], 'status':'enrolled', 'runtime': runtime, 'preparation': result,
                'historical_qualification_reexecuted': False,
                'declared_fresh_operation_bound': 'one strict original20 GET plus original three deterministic selected-response qualifications',
                'full_mode_physics_case_not_run_by_preparation': True,
                'own_pilot_required_before_formal': True, 'scientific_credit': False}
        finally:
            _fence_inputs(checked)


class FocusedFixedModePreparationRuntime:
    """The immutable image supplies Native142; the read-only consumer is distinct."""
    def __init__(self, root, runtime, checked):
        self.root, self.runtime, self.checked = Path(root).absolute(), runtime, checked

    def prepare(self, candidate, output, *, frozen_application_manifest=None):
        from . import resource_study_runtime as r
        from .resource_study_selection import read_frozen_application_manifest
        from .resource_study_cohorts import INPUT_CONTEXT, verifier_contract
        value = self.checked['input']
        mode = _selected_mode(value['mode'])
        if (candidate['hostname'] != value['hostname'] or candidate['urls'] != value['science']['urls']
                or not _same(self.runtime, value['runtime']) or not _same(verifier_contract(), value['source_contract'])):
            raise ValueError('focused runtime/backend changed its immutable declared case')
        from .resource_study_lineage import INCLUDED
        literal_reserve = value['hostname'] == INCLUDED
        if literal_reserve:
            if frozen_application_manifest is not None:
                raise ValueError('literal reserve keeps its original selection reader')
            from .resource_study_selection import validate_frozen_application_manifest_bytes
            frozen_raw = _read(self.checked['manifest']['path'], self.checked['manifest']['sha256'])
            validate_frozen_application_manifest_bytes(frozen_raw, candidate['hostname'], candidate['urls'])
        else:
            frozen_raw, _ = read_frozen_application_manifest(self.root, candidate['hostname'],
                candidate['urls'], frozen_application_manifest)
        if hashlib.sha256(frozen_raw).hexdigest() != value['science']['workload_sha256']:
            raise ValueError('focused preparation manifest is not the original frozen class')
        output.mkdir(parents=True, exist_ok=False)
        if literal_reserve:
            from .resource_study_store import _create
            frozen_path = output / 'literal-reserve-application-manifest.json'
            _create(frozen_path, frozen_raw)
        else:
            frozen_path = self.root / frozen_application_manifest['manifest_path']
        dns = r.public_ipv4(candidate['hostname'])
        r._put(output / 'dns.json', dns)
        consumer = Path(__file__).resolve(strict=True).parents[2]
        job = {'record_type': INPUT, 'hostname': value['hostname'], 'mode': mode,
            'urls': value['science']['urls'], 'output': str(output / 'prepared'),
            'runtime': self.runtime, 'science': value['science'],
            'frozen_manifest': str(frozen_path),
            'frozen_manifest_sha256': hashlib.sha256(frozen_raw).hexdigest(),
            'historical_prepared': self.checked['historical_prepared'],
            'consumer_checkout': str(consumer), 'source_contract': value['source_contract'],
            'scientific_credit': False}
        if literal_reserve:
            job['literal_reserve'] = True
        # Preserve the exact original four-field preparation-job schema used
        # by validate_selection_proof. The distinct external-consumer job is
        # also retained and hash-bound in the enrollment, never aliased to it.
        r._put(output / 'job.json', {'hostname':job['hostname'], 'urls':job['urls'],
            'output':job['output'], 'runtime':job['runtime']})
        r._put(output / 'focused-job.json', job)
        bootstrap = ('import sys;sys.path.insert(0,' + repr(str(consumer / 'src')) + ');'
            'from qcsd_lab.resource_study_fixed_mode_preparation import native_main;native_main(sys.argv[1])')
        with r.docker_lock():
            r._runtime_check(self.runtime)
            raw = r._docker('run', '--rm', '--network', 'bridge', '--user', f'{os.getuid()}:{os.getgid()}',
                '--cap-drop', 'ALL', '--env', 'QCSD_LAB_ROOT=/runtime-src',
                '--env', 'QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json',
                '--security-opt', 'no-new-privileges', '--add-host', candidate['hostname'] + ':' + dns['selected_ipv4'],
                '--mount', f'type=bind,src={self.root},dst={self.root}',
                '--mount', f'type=bind,src={consumer},dst={consumer},readonly',
                '--entrypoint', '/opt/qcsd-venv/bin/python3', self.runtime['collection_image_digest'],
                '-I', '-B', '-c', bootstrap, str(output / 'focused-job.json'), timeout=600)
        r._put(output / 'result.json', json.loads(raw.splitlines()[-1]))
        enrollment = load_json(output / 'result.json')
        base = output / 'prepared'
        if (not _same(enrollment['runtime'], self.runtime) or not _same(_science(enrollment, mode), value['science'])
                or enrollment['mode_readiness'] != {m: m == mode for m in ('undefended','front','tamaraw','buflo','cs-buflo')}
                or Path(enrollment['workload_path']).read_bytes() != frozen_raw):
            raise ValueError('focused Native result changed the declared mode/resources/runtime')
        for path in base.rglob('*'):
            if path.is_symlink():
                raise ValueError('focused Native preparation created a linked artifact')
            if path.is_file():
                path.chmod(0o444)
        native = load_json(base / 'enrollment.json')
        _replay_qualified_assets(base, native)
        if not literal_reserve:
            enrollment['frozen_application_manifest'] = dict(frozen_application_manifest)
        enrollment['workload_path'] = Path(enrollment['workload_path']).relative_to(self.root).as_posix()
        enrollment['paths'] = {key: Path(path).relative_to(self.root).as_posix() if path else None
            for key,path in enrollment['paths'].items()}
        enrollment['preparation_dir'] = base.relative_to(self.root).as_posix()
        enrollment['files'] = {(base / relative).relative_to(self.root).as_posix(): digest
            for relative,digest in enrollment['files'].items()}
        enrollment['files'][(output / 'dns.json').relative_to(self.root).as_posix()] = sha256_file(output / 'dns.json')
        enrollment['files'][(output / 'focused-job.json').relative_to(self.root).as_posix()] = sha256_file(output / 'focused-job.json')
        if literal_reserve:
            enrollment['files'][frozen_path.relative_to(self.root).as_posix()] = hashlib.sha256(frozen_raw).hexdigest()
        else:
            enrollment['files'][frozen_application_manifest['manifest_path']] = frozen_application_manifest['manifest_sha256']
            enrollment['files'][INPUT_CONTEXT] = frozen_application_manifest['context_sha256']
        enrollment['source_occurrences'] = candidate.get('source_occurrences', [])
        for relative in enrollment['files']:
            (self.root / relative).chmod(0o444)
        return enrollment


def native_main(job_path):
    """Four genuine unshaped operations; installed immutable Native is unchanged."""
    from . import resource_study_native as n
    from .resource_study_cohorts import verifier_contract
    from .resource_study_selection import (validate_frozen_application_manifest_bytes,
        frozen_application_manifest_declaration)
    job = load_json(Path(job_path))
    fields = {'record_type','hostname','mode','urls','output','runtime','science','frozen_manifest',
        'frozen_manifest_sha256','historical_prepared','consumer_checkout','source_contract','scientific_credit'}
    if type(job) is dict and job.get('literal_reserve') is True:
        fields.add('literal_reserve')
    if (type(job) is not dict or set(job) != fields or job['record_type'] != INPUT
            or job['scientific_credit'] is not False
            or job['consumer_checkout'] != str(Path(__file__).resolve(strict=True).parents[2])
            or not _same(job['source_contract'], verifier_contract())):
        raise ValueError('focused Native adapter has a foreign consumer or job')
    from .resource_study_lineage import INCLUDED
    literal_reserve = job.get('literal_reserve') is True
    if literal_reserve != (job['hostname'] == INCLUDED):
        raise ValueError('focused literal-reserve job differs from its original hostname')
    mode = _selected_mode(job['mode'])
    runtime = n._retained_runtime(job['runtime'])
    if runtime['native_commit'] != NATIVE142 or runtime['canonical_sha256'] != CANONICAL142_SHA256:
        raise ValueError('focused Native job changed its actual immutable runtime')
    executable, bound = n._runtime(runtime, n.DEFAULT_CLIENT)
    frozen_raw = _read(job['frozen_manifest'], job['frozen_manifest_sha256'])
    manifest = validate_frozen_application_manifest_bytes(frozen_raw, job['hostname'], job['urls'])
    if job['science']['workload_sha256'] != job['frozen_manifest_sha256']:
        raise ValueError('focused Native job changed the exact frozen workload')
    _fixed_science_preflight(job['science'], job['historical_prepared'], mode)
    root = n._new_directory(job['output'])
    actual_dir = n._new_directory(root / 'preparation-get')
    _, responses = n._checked_operation(actual_dir, manifest, client=executable, runtime=bound,
        client_sha256=bound['client_sha256'], timeout=120, max_response_bytes=n.MAX_RESPONSE_BYTES)
    prepared = deepcopy(job['historical_prepared'])
    if not _same(prepared['resources'], manifest['resources']):
        raise ValueError('focused preparation changed frozen application resource bytes')
    preparation = prepared['preparation']
    preparation.update(runtime=bound,
        expected_responses=[{k:r[k] for k in ('resource_id','status','bytes','body_sha256')} for r in responses],
        actual_preparation_run='preparation-get/native/run.json',
        actual_preparation_run_sha256=sha256_file(actual_dir / 'native/run.json'))
    if literal_reserve:
        if 'frozen_application_manifest' in preparation:
            raise ValueError('literal reserve cannot inherit retained49 manifest authority')
    else:
        preparation['frozen_application_manifest'] = frozen_application_manifest_declaration(job['frozen_manifest_sha256'])
    _fixed_science_preflight(job['science'], prepared, mode)
    paths = {'manifest': n._write(root / 'resources.json', frozen_raw, raw=True),
        'prepared_workload': n._write(root / 'prepared-workload.json', prepared),
        'expected_responses': n._write(root / 'expected-responses.json', {'responses':preparation['expected_responses']}),
        **n._parameter_bundle(root)}
    qualified = n._qualify(paths['prepared_workload'], manifest['resources'], responses,
        n._new_directory(root / 'qualification'), executable, bound)
    if qualified['error'] is not None:
        raise ValueError('focused selected-resource qualification failed; original evidence retained: ' + qualified['error'])
    paths['chaff_core'] = n._write(root / 'chaff-core.json', qualified['core'])
    paths['chaff_manifest'] = n._write(root / 'chaff-manifest.json', qualified['manifest'])
    enrollment = {'schema_version':1,'role':n.ROLE,'hostname':job['hostname'],'urls':job['urls'],
        'workload_path':'resources.json','workload_sha256':sha256_file(paths['manifest']),
        'paths':{k:p.relative_to(root).as_posix() for k,p in paths.items()},'files':n._files(root),
        'runtime':bound,'mode_policies':n.mode_policies(),'mode_settings':n._mode_settings(paths),
        'mode_readiness':{m:m==mode for m in n.MODES},'qualification_error':None,'scientific_credit':False}
    if not _same(_science(enrollment,mode), job['science']):
        raise ValueError('focused preparation changed the approved fixed mode profile')
    enrollment_path = n._write(root / 'enrollment.json', enrollment)
    result = {**enrollment, 'workload_path':str(paths['manifest']),
        'paths':{**{k:str(p) for k,p in paths.items()},'enrollment':str(enrollment_path)},
        'files':n._files(root),'enrollment_sha256':sha256_file(enrollment_path)}
    print(json.dumps(result,sort_keys=True,allow_nan=False))
