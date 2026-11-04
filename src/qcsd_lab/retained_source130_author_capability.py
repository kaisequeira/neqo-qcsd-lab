"""Source-stable Source130 author proof validator; explicit external binding only.

This coordinator module never supplies a replacement worker or qualifies a
trace. The caller binds a sealed proof in its job/core/enrollment; code never embeds per-input data.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat

AUTHOR_TEMPLATE_SHA = '6569644fad11e611a966cf8ffd5a4fd8073814183c4b0d0de1710dc3c26e083c'
SCOPE_SHA = '099d55d187eccd948598fc02b292f47bba06f4cd1254fc91f7c40facc83d6ef6'
MANIFEST_SHA = '5034be68ca8e2e8655e3c6bc24d069ce84c4e0f3502f400626dba30ec95b72e8'
HOST_PACKAGE = '/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009'
COMMAND_PREFIX = [HOST_PACKAGE + '/setup/limactl', '--tty=false', 'shell', '--workdir',
    '/home/joshkai', 'neqo-study', '/usr/bin/nice', '-n', '19', '/usr/bin/taskset', '-c', '23',
    '/usr/bin/python3', '-I', '-B', '-c']


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(reference, limit=4 * 1024**2):
    need(type(reference) is dict and set(reference) == {'path', 'sha256'}
         and type(reference['path']) is str and type(reference['sha256']) is str,
         'exact immutable reference required')
    path = Path(reference['path'])
    need(path.is_absolute() and path.resolve(strict=True) == path
         and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical capability path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 503 and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o444 and 0 <= before.st_size <= limit,
             'sealed bounded owned capability file required')
        with os.fdopen(os.dup(fd), 'rb') as handle:
            raw = handle.read(limit + 1)
        need(len(raw) == before.st_size and digest(raw) == reference['sha256']
             and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()), 'capability file changed')
        return raw
    finally:
        os.close(fd)


def verify_capability(row, value, input_sha256, expected_execution):
    observed = {}
    root = Path(value['root'])
    def get(reference, limit=4 * 1024**2):
        need(Path(reference['path']).is_relative_to(root), 'external author proof escaped its mounted study root')
        raw = read(reference, limit)
        observed[reference['path']] = reference['sha256']
        return raw
    need(type(row) is dict and set(row) == {'author_source', 'job', 'input', 'result', 'request', 'stdout', 'stderr'},
         'complete genuine author recorder pins required')
    need(row['input']['sha256'] == input_sha256, 'capability input SHA differs')
    author_raw = get(row['author_source'])
    need(author_raw.count(b'\nREADY = True\n') == 1
         and digest(author_raw.replace(b'\nREADY = True\n', b'\nREADY = False\n', 1)) == AUTHOR_TEMPLATE_SHA,
         'author is not exact reviewed READY-only derivative')
    job_raw = get(row['job']); job = json.loads(job_raw)
    command = [*COMMAND_PREFIX, author_raw.decode(), base64.b64encode(job_raw).decode(), digest(job_raw)]
    result_raw = get(row['result']); result = json.loads(result_raw)
    request_raw = get(row['request']); request = json.loads(request_raw)
    stdout = get(row['stdout']); stderr = get(row['stderr'])
    need(type(result) is dict and set(result) == {'schema_version', 'command', 'cwd', 'scientific_credit',
         'started_at', 'ended_at', 'elapsed_seconds', 'returncode', 'files'}
         and type(result['schema_version']) is int and result['schema_version'] == 1
         and type(result['returncode']) is int and result['returncode'] == 0
         and result['command'] == command and result['cwd'] == HOST_PACKAGE
         and result['scientific_credit'] is False and type(result['elapsed_seconds']) in (int, float)
         and result['elapsed_seconds'] >= 0, 'genuine successful exact author command required')
    need(request == {k: result[k] for k in ('schema_version', 'command', 'cwd', 'scientific_credit', 'started_at')},
         'author request/result join changed')
    need(result['files'] == {'request.json': {'sha256': digest(request_raw), 'size_bytes': len(request_raw)},
         'stdout.log': {'sha256': digest(stdout), 'size_bytes': len(stdout)},
         'stderr.log': {'sha256': digest(stderr), 'size_bytes': len(stderr)}}
         and stderr == b'' and len(stdout.splitlines()) == 1, 'closed author log joins required')
    # Byte authentication precedes executing only the known module's pure helpers.
    module = {'__name__': '_reviewed_source130_author_capability', '__file__': row['author_source']['path']}
    exec(compile(author_raw, row['author_source']['path'], 'exec'), module)
    need(module['encoded'](job) == job_raw and job['manifest']['sha256'] == MANIFEST_SHA,
         'canonical external author scope/job and original manifest required')
    scope = json.loads(get(job['scope'])); snapshot = json.loads(get(job['snapshot'])); context = json.loads(get(job['context']))
    module['validate_job_scope'](job, scope, snapshot, context)
    declaration = json.loads(get(job['runtime_declaration']))
    module['validate_runtime_evidence'](declaration, scope, lambda reference: json.loads(get(reference)), get)
    require_isolated_role_producer(declaration['role_source_contract'],expected_execution)
    manifest = json.loads(get(job['manifest']))
    need(manifest['execution_contract'] == scope['original_contract'] and manifest['file_count'] == 187
         and len(manifest['files']) == 187, 'literal genuine original source contract required')
    report = json.loads(stdout)
    expected_input = module['make_input'](job, scope, snapshot, context, value['resource_selection'], declaration)
    input_raw = get(row['input'])
    need(json.loads(input_raw) == value == expected_input and digest(input_raw) == input_sha256,
         'actual authored retained input changed')
    need(report == {'record_type': 'original-source130-retained-input-author-result-v2', 'passed': True,
         'runtime_declaration': job['runtime_declaration'], 'runtime': declaration['runtime'],
         'canonical_runtime': declaration['canonical_runtime'],
         'job_sha256': digest(job_raw), 'hostname': job['hostname'], 'root': scope['root'], 'head': scope['head'],
         'input': row['input'], 'resource_selection': value['resource_selection'],
         'original_contract': scope['original_contract'], 'source_manifest_sha256': MANIFEST_SHA,
         'source_files_checked': 187, 'original_input_validator_passed': True,
         'historical_qualification_reexecuted': False, 'readiness_run': False, 'installed_runtime_checked': False,
         'current_sql_checked': False, 'scientific_credit_added': 0}, 'author result is incomplete or foreign')
    # The unchanged native validator authenticates selection semantics and frozen
    # historical assets. This independent file join also rejects report-only data.
    selected = json.loads(get(value['resource_selection']))
    need(selected.get('hostname') == value['hostname'] and selected.get('urls') == value['science']['urls']
         and selected.get('scientific_credit') is False, 'actual twenty-resource selection changed')
    return observed



def validate(value, input_sha256, proof_reference):
    from . import resource_study_reader_compatibility as reader
    from .resource_study_cohorts import verifier_contract
    if type(value) is not dict or value.get('source_contract') != reader.prior_exact130_execution_contract():
        return False
    need(type(proof_reference) is dict and set(proof_reference) == {'path','sha256'}
         and Path(proof_reference['path']).is_relative_to(Path(value['root'])),
         'explicit sealed Source130 author proof within owning study required')
    proof = json.loads(read(proof_reference))
    need(type(proof) is dict and set(proof) == {'record_type','schema_version','input_sha256','author_record'}
         and proof['record_type'] == 'source130-genuine-author-proof-v2'
         and type(proof['schema_version']) is int and proof['schema_version'] == 2
         and proof['input_sha256'] == input_sha256, 'exact external author proof/input binding required')
    observed = verify_capability(proof['author_record'], value, input_sha256, verifier_contract())
    observed[proof_reference['path']] = proof_reference['sha256']
    return {'proof': proof_reference, 'files': [{'path':path,'sha256':sha} for path,sha in sorted(observed.items())]}


TYPED_ROLE_RUNTIME='qcsd-isolated-lane-role-runtime-v1'
ROLE_PROBE_SHA='2f2aab6ff767a561beffa04f35b3d455e181545b0573ed871c8d4ff8121e308f'

def load_ref(reference):
    return json.loads(read(reference))

def _canonical_discriminator(path):
    path=Path(path).absolute()
    need(path.is_absolute() and path.resolve(strict=True)==path
         and not any(p.is_symlink()for p in(path,*path.parents)),'canonical runtime path required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid==503 and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)in(0o444,0o644) and 0<before.st_size<=4*1024**2,
             'bounded owned canonical discriminator required')
        with os.fdopen(os.dup(fd),'rb')as handle:raw=handle.read(4*1024**2+1)
        need(len(raw)==before.st_size and stamp(before)==stamp(os.fstat(fd))==stamp(path.lstat()),'canonical discriminator changed')
        return raw
    finally:os.close(fd)

def typed_runtime_or_none(path,expected_canonical_sha256=None,*,raw=None):
    path=Path(path).absolute()
    raw=_canonical_discriminator(path)if raw is None else raw
    value=json.loads(raw)
    if type(value)is not dict or value.get('record_type')!=TYPED_ROLE_RUNTIME:
        return None
    need(type(expected_canonical_sha256)is str and len(expected_canonical_sha256)==64,
         'typed role runtime requires independently supplied canonical SHA')
    canonical_ref={'path':str(path),'sha256':expected_canonical_sha256}
    need(read(canonical_ref)==raw,'typed canonical bytes/SHA changed')
    fields={'record_type','schema_version','source','platform','collection_image_digest','prepare_image_digest',
            'installed_client_sha256','installed_byte_verification_completed','native_compilation_executed',
            'image_build_proof','scientific_credit'}
    need(set(value)==fields and type(value['schema_version'])is int and value['schema_version']==1
         and value['installed_byte_verification_completed']is True and value['native_compilation_executed']is False
         and value['scientific_credit']is False and type(value['source'])is dict,
         'typed role canonical requires exact verified-build schema')
    runtime={'collection_image_digest':value['collection_image_digest'],'prepare_image_digest':value['prepare_image_digest'],
        'client_sha256':value['installed_client_sha256'],'platform':value['platform'],
        'native_commit':value['source']['neqo_commit'],'source':value['source'],
        'canonical_sha256':expected_canonical_sha256}
    proof=load_ref(value['image_build_proof'])
    from .resource_study_cohorts import verifier_contract
    from . import resource_study_reader_compatibility as reader
    qualified=reader.qualify_execution(verifier_contract())
    reader.require_supported(proof['role_source_contract'],qualified)
    # The actual complete installed SDK is part of the known role probe. No
    # unknown current image can inherit a historical source-profile label.
    require_isolated_role_producer(proof['role_source_contract'],qualified.contract())
    declaration={'record_type':'source130-genuine-role-runtime-declaration-v1','schema_version':1,
        'runtime':runtime,'canonical_runtime':canonical_ref,'role_source_contract':proof['role_source_contract'],
        'image_build_proof':value['image_build_proof'],'scientific_credit':False}
    validate_runtime_evidence(declaration,{'runtime':runtime},load_ref,read)
    return runtime


def ref(value):
    need(type(value) is dict and set(value) == {'path', 'sha256'} and type(value['path']) is str
         and type(value['sha256']) is str and len(value['sha256']) == 64
         and all(c in '0123456789abcdef' for c in value['sha256']), 'exact path/hash reference required')
    return value['path'], value['sha256']

def validate_runtime_declaration(declaration, scope):
    fields = {'record_type','schema_version','runtime','canonical_runtime','role_source_contract','image_build_proof','scientific_credit'}
    need(type(declaration) is dict and set(declaration) == fields
         and declaration['record_type'] == 'source130-genuine-role-runtime-declaration-v1'
         and type(declaration['schema_version']) is int and declaration['schema_version'] == 1
         and declaration['scientific_credit'] is False, 'exact external actual-runtime declaration required')
    runtime = declaration['runtime']; old = scope['runtime']
    need(type(runtime) is dict and set(runtime) == set(old)
         and all(runtime[k] == old[k] for k in ('client_sha256','native_commit','platform'))
         and type(runtime['source']) is dict
         and all(runtime['source'].get(k) == old['source'][k] for k in ('neqo_commit','neqo_dirty','neqo_patch_sha256')),
         'new role images must preserve exact Native157 client/Native/platform')
    ref(declaration['canonical_runtime']); ref(declaration['image_build_proof'])
    need(runtime['canonical_sha256'] == declaration['canonical_runtime']['sha256']
         and type(declaration['role_source_contract']) is dict
         and declaration['role_source_contract'].get('transitive_source_files') == 194,
         'new actual canonical and complete194 installed SDK required')
    return runtime

def validate_runtime_evidence(declaration, scope, read_ref=load_ref, read_bytes=None):
    if read_bytes is None:
        read_bytes = read
    runtime = validate_runtime_declaration(declaration, scope)
    canonical_value = read_ref(declaration['canonical_runtime'])
    need(canonical_value.get('installed_client_sha256') == runtime['client_sha256']
         and all(canonical_value.get(k) == runtime[k] for k in ('platform','collection_image_digest','prepare_image_digest','source')),
         'actual canonical bytes differ from declared complete runtime')
    proof = read_ref(declaration['image_build_proof'])
    fields = {'record_type','schema_version','built','installed_sdk_verified','installed_client_verified',
              'collection_image_digest','prepare_image_digest','client_sha256','native_commit','platform',
              'role_source_contract','source','recorder_refs','scientific_credit','sdk_inventory_sha256','probe_source_ref'}
    need(type(proof) is dict and set(proof) == fields
         and proof['record_type'] == 'qcsd-isolated-lane-role-images-installed-verification-v1'
         and type(proof['schema_version']) is int and proof['schema_version'] == 1
         and proof['built'] is True and proof['installed_sdk_verified'] is True and proof['installed_client_verified'] is True
         and proof['scientific_credit'] is False
         and all(proof[k] == runtime[k] for k in ('collection_image_digest','prepare_image_digest','client_sha256','native_commit','platform','source'))
         and proof['role_source_contract'] == declaration['role_source_contract']
         and type(proof['recorder_refs']) is list and proof['recorder_refs'],
         'genuine completed installed-image verification required; source-only context is not proof')
    probe_raw=read_bytes(proof['probe_source_ref'])
    need(proof['probe_source_ref']['sha256']==ROLE_PROBE_SHA and digest(probe_raw)==ROLE_PROBE_SHA,
         'known installed-role probe source required before interpreting its output')
    probe_count=0
    for reference in proof['recorder_refs']:
        ref(reference)
        result = read_ref(reference)
        need(type(result) is dict and result.get('schema_version') == 1
             and type(result.get('returncode')) is int and result['returncode'] == 0
             and result.get('scientific_credit') is False and type(result.get('ended_at')) is str
             and type(result.get('started_at')) is str and type(result.get('command')) is list
             and result['command'] and type(result.get('files')) is dict
             and set(result['files']) == {'request.json','stdout.log','stderr.log'}, 'closed real build recorder required')
        logs = {}
        for name, item in result['files'].items():
            need(type(item) is dict and set(item) == {'sha256','size_bytes'}
                 and type(item['size_bytes']) is int and item['size_bytes'] >= 0, 'build recorder file row differs')
            logs[name] = read_bytes({'path': str(Path(reference['path']).parent / name), 'sha256': item['sha256']})
            need(len(logs[name]) == item['size_bytes'], 'build recorder file size differs')
        need(json.loads(logs['request.json']) == {key: result[key] for key in
             ('schema_version','command','cwd','scientific_credit','started_at')}, 'build recorder request/result differs')
        command=result['command']
        prefix=[HOST_PACKAGE+'/setup/limactl','--tty=false','shell','--workdir','/home/joshkai','neqo-study',
                '/usr/bin/python3','-I','-B','-c',probe_raw.decode()]
        if command[:len(prefix)]!=prefix:
            continue
        need(len(command)==len(prefix)+2 and result['cwd']==HOST_PACKAGE and logs['stderr.log']==b''
             and len(logs['stdout.log'].splitlines())==1, 'exact known probe command/logs required')
        raw_job=base64.b64decode(command[-2],validate=True);job=json.loads(raw_job)
        compact=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        need(compact(job)==raw_job and digest(raw_job)==command[-1], 'known probe job SHA/bytes differ')
        expected_job_fields={'record_type','schema_version','roles','platform','client_sha256','source','sdk_files','role_source_contract'}
        need(type(job)is dict and set(job)==expected_job_fields
             and job['record_type']=='qcsd-isolated-lane-installed-role-probe-job-v1'
             and type(job['schema_version'])is int and job['schema_version']==1
             and job['roles']=={'collection':runtime['collection_image_digest'],'prepare':runtime['prepare_image_digest']}
             and len(set(job['roles'].values()))==2
             and all(job[key]==runtime[key]for key in ('platform','client_sha256','source'))
             and job['role_source_contract']==declaration['role_source_contract']
             and type(job['sdk_files'])is dict and len(job['sdk_files'])==194
             and digest(compact(job['sdk_files']))==proof['sdk_inventory_sha256'], 'known probe role/SDK/runtime job differs')
        sdk={}
        for name,sha in job['sdk_files'].items():
            need(name.startswith('src/qcsd_lab/') and name.count('/')==2 and name.endswith('.py'), 'known probe SDK path differs')
            ref({'path':name,'sha256':sha});sdk[name.split('/')[-1]]=sha
        contract=declaration['role_source_contract']
        need(len(sdk)==194 and contract['files']=={name:sdk[name]for name in contract['files']}
             and digest(compact(sdk)+b'\n')==contract['transitive_source_sha256'], 'probe inventory and full source contract differ')
        observed=json.loads(logs['stdout.log'])
        need(type(observed)is dict and type(observed.get('roles'))is list and len(observed['roles'])==2,
             'known probe requires two actual installed role results')
        receipts={};dependency_sources=None
        for role_row in observed['roles']:
            receipt=role_row.get('python_runtime_receipt')
            keys={'schema_version','artifact_type','domain','source','source_files','installed_modules',
                  'installed_tools','installed_entrypoint','payload_sha256'}
            need(type(receipt)is dict and set(receipt)==keys and type(receipt['schema_version'])is int
                 and receipt['schema_version']==2 and receipt['artifact_type']=='qcsd-python-runtime-implementation'
                 and receipt['domain']=='qcsd-python-runtime-implementation-v2' and receipt['source']==runtime['source']
                 and set(receipt['source_files'])==set(job['sdk_files'])|{'tools/build_class_catalogue.py','tools/browser_egress_qualification.py','.dockerignore','Dockerfile','pyproject.toml','uv.lock'}
                 and all(receipt['source_files'][name]==sha for name,sha in job['sdk_files'].items())
                 and set(receipt['installed_modules'])==set(job['sdk_files'])
                 and all(receipt['installed_modules'][name]['sha256']==sha for name,sha in job['sdk_files'].items())
                 and receipt['payload_sha256']==digest(receipt['domain'].encode()+b'\0'+compact({key:value for key,value in receipt.items()if key!='payload_sha256'})),
                 'known probe runtime receipt does not bind exact refreshed SDK/source')
            dependencies={name:receipt['source_files'][name]for name in ('.dockerignore','Dockerfile','pyproject.toml','uv.lock')}
            need(all(type(sha)is str and len(sha)==64 and all(ch in '0123456789abcdef'for ch in sha)for sha in dependencies.values()),
                 'runtime receipt base dependency hashes are malformed')
            need(dependency_sources is None or dependencies==dependency_sources,'role receipts disagree on actual base dependency source hashes')
            dependency_sources=dependencies
            need(role_row.get('role')not in receipts,'known probe repeats role')
            receipts[role_row['role']]=receipt
        roles=[{'record_type':'qcsd-isolated-lane-installed-role-probe-v1','role':role,'image_digest':image,
                'platform':runtime['platform'],'client_sha256':runtime['client_sha256'],'source':runtime['source'],
                'sdk_files':job['sdk_files'],'sdk_inventory_sha256':proof['sdk_inventory_sha256'],
                'role_source_contract':contract,'qualify_execution':{'passed':True,'contract':contract},
                'python_runtime_receipt':receipts.get(role)}
               for role,image in sorted(job['roles'].items())]
        need(observed=={'record_type':'qcsd-isolated-lane-installed-role-probe-result-v1',
             'schema_version':1,'job':job,'job_sha256':digest(raw_job),'roles':roles,'passed':True,'scientific_credit':False},
             'known probe did not verify both exact installed roles/client/source/SDK')
        probe_count+=1
    need(probe_count==1 and len(proof['recorder_refs'])>=2, 'one genuine known probe plus genuine build recorder required')
    return proof


def require_isolated_role_producer(actual,execution):
    from . import resource_study_reader_compatibility as reader
    qualified=reader.qualify_execution(execution)
    reader.require_supported(actual,qualified)
    if actual not in (qualified.contract(),reader.prior_exact_isolated_sdk7_execution_contract(),reader.prior_exact_isolated_sdk8_execution_contract(),reader.prior_exact_isolated_sdk9_execution_contract(),reader.prior_exact_isolated_sdk10_execution_contract()):
        raise ValueError('isolated role runtime requires exact current or immutable SDK7/8 producer')
    return True
