"""Root-only V9 continuation; every action has fresh roots and raw operations."""
from pathlib import Path
import importlib.util
import json
import os
import re
import sys

import action_facts
import graph_input as graph

HERE = Path(__file__).absolute().parent
RECORDER_SHA = '7e7653fe26a89ecc512a2b17b37438f6af6f3c97ea4f95ee77ea995e27594af7'


def command(plan, plan_path, root, local, container_prefix):
    if (type(local) is not int or not 1 <= local <= len(plan['candidates'])
            or not re.fullmatch('[a-z0-9][a-z0-9-]{2,80}', container_prefix)):
        raise ValueError('bounded local mapping/container identity required')
    roots = sorted(set(graph.transport_roots(plan)) | {Path(plan_path).parent})
    attempts = Path(root) / 'attempts'
    if any(attempts.is_relative_to(p) or p.is_relative_to(attempts) for p in roots):
        raise ValueError('writable attempts overlap immutable inputs')
    argv = ['timeout','--signal=TERM','--kill-after=15s','450s','docker','--host',graph.DAEMON,
        'run','--rm','--init','--name',f'{container_prefix}-{local:03d}','--network','bridge',
        '--user',plan['executor_uid_gid'],'--security-opt','no-new-privileges','--cap-drop','ALL',
        '--env','QCSD_LAB_IMAGE_DIGEST='+plan['browser_image'],
        '--env','QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json',
        '--env','QCSD_PUBLIC_ORIGIN_ONLY=1','--env','PYTHONDONTWRITEBYTECODE=1']
    for path in roots:
        if not path.is_absolute() or any(c in str(path) for c in (':','\n','\r','\0')):
            raise ValueError('immutable mount has a delimiter')
        argv += ['--volume',f'{path}:{path}:ro']
    output = attempts / f'candidate-{local:06d}'
    return argv + ['--volume',f'{attempts}:{attempts}:rw','--workdir',plan['source']['root'],
        '--entrypoint','/opt/qcsd-venv/bin/python3',plan['browser_image'],'-I','-B',
        str(HERE/'operator.py'),'discover','--plan',str(plan_path),'--candidate-index',str(local),
        '--output',str(output)]


def actual(recorder, root, step, argv):
    try:
        recorder.recorded_run(argv, root/'operations', step, cwd=root)
    except RuntimeError:
        pass
    completed = graph.load(graph.read(root/'operations'/(step+'-completed.json')))
    graph.operation(root/'operations'/step, completed['returncode'], expected_command=argv)
    return completed['returncode']


def actors(recorder, root, label):
    argv=['docker','--host',graph.DAEMON,'ps','--format','{{.ID}} {{.Names}}']
    if actual(recorder,root,label,argv) != 0 or graph.read(root/'operations'/(label+'.stdout.log')).strip():
        raise ValueError('physical actors reserve the boundary')


def recorder(path):
    path=Path(path).absolute()
    if graph.reference(path)['sha256'] != RECORDER_SHA:
        raise ValueError('exact original recorder required')
    spec=importlib.util.spec_from_file_location('original_v9_recorder',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def failed(plan, plan_path, attempt, candidate, operation_prefix):
    """Retain the original complete typed-failure reader and its raw guards."""
    original = action_facts.current().reader(graph.ORIGINAL.parent /
        'supplemental-generic-v8-root-controller-authoring-20261006-001/driver.py',
        graph.ORIGINAL_CONTROLLER)
    return original.failed(graph.reader(), plan, plan_path, attempt, candidate, operation_prefix)


def run(plan_path, plan_sha256, output, container_prefix, recorder_path):
    plan_path=Path(plan_path).absolute()
    if (not re.fullmatch('[0-9a-f]{64}',plan_sha256)
            or graph.reference(plan_path)['sha256']!=plan_sha256):
        raise ValueError('reviewed prospective declaration bytes changed')
    plan=graph.check_plan(plan_path)
    record=recorder(recorder_path)
    action_facts.current().check()
    root=graph.reader().fresh_directory(Path(output),[*graph.transport_roots(plan),plan_path.parent])
    (root/'operations').mkdir(mode=0o700);(root/'attempts').mkdir(mode=0o700)
    record.json_create(root/'inputs.json',{'plan':graph.reference(plan_path),
        'controller':graph.reference(__file__),'producer_sources':graph.sources(),
        'verify_interpreter':str(Path(sys.executable).absolute()),
        'container_prefix':container_prefix,'original_candidate_indices':plan['original_candidate_indices'],
        'candidate_ids':[r['candidate_id'] for r in plan['candidates']],**graph.ZERO})
    rows=[]
    for local,candidate in enumerate(plan['candidates'],1):
        if graph.check_plan(plan_path)!=plan:
            raise ValueError('declared plan changed')
        action_facts.current().check()
        actors(record,root,f'candidate-{local:06d}-before-actors')
        argv=command(plan,plan_path,root,local,container_prefix)
        action_facts.current().check()
        code=actual(record,root,f'candidate-{local:06d}-discover',argv)
        attempt=root/'attempts'/f'candidate-{local:06d}'
        if code==0:
            verify=[sys.executable,'-I','-B',str(HERE/'operator.py'),'verify-input','--input',str(attempt/'whole-graph-input.json')]
            if actual(record,root,f'candidate-{local:06d}-verify-input',verify)!=0:
                raise ValueError('public complete graph verification failed')
            evidence=graph.reference(attempt/'whole-graph-input.json')
        elif code==1 and (attempt/'failed.json').is_file():
            evidence=failed(plan,plan_path,attempt,candidate,
                root/'operations'/f'candidate-{local:06d}-discover')
        else:
            raise ValueError('unexpected status retains a pending reservation; no synthetic terminal')
        action_facts.current().check()
        actors(record,root,f'candidate-{local:06d}-after-actors')
        row={'local_index':local,'original_candidate_index':plan['original_candidate_indices'][local-1],
            'candidate':candidate,'discovery_returncode':code,'evidence':evidence,**graph.ZERO}
        record.json_create(root/f'candidate-{local:06d}-closed.json',row);rows.append(row)
    result={'schema_version':1,'artifact_type':'qcsd-complete-v9-ordered-discovery-batch-v1',
        'plan':graph.reference(plan_path),'candidates':rows,'closed_at':graph.now(),
        'retained_interruption':plan['retained_interruption'],
        'original_v8_batch_complete_claimed':False,'prior_outcomes_reclassified':False,**graph.ZERO}
    action_facts.current().check();record.json_create(root/'batch-closed.json',result)
    verify_batch(root/'batch-closed.json',plan)
    return root/'batch-closed.json'


def verify_batch(path, plan):
    value=graph.load(graph.read(path));root=Path(path).parent
    inputs=graph.load(graph.read(root/'inputs.json'))
    plan_path=graph.reopen(value['plan'])[0]
    if (value.get('artifact_type')!='qcsd-complete-v9-ordered-discovery-batch-v1'
            or value.get('schema_version')!=1 or value['retained_interruption']!=plan['retained_interruption']
            or value.get('original_v8_batch_complete_claimed') is not False
            or value.get('prior_outcomes_reclassified') is not False
            or inputs['plan']!=value['plan'] or inputs['controller']!=graph.reference(__file__)
            or inputs['producer_sources']!=graph.sources()
            or not Path(inputs['verify_interpreter']).is_absolute()
            or inputs['candidate_ids']!=[r['candidate_id'] for r in plan['candidates']]
            or len(value['candidates'])!=len(plan['candidates'])
            or not graph.reader().zero_credit(value)):
        raise ValueError('V9 full ordered batch/controller/zero credit differs')
    previous=graph.utc(plan['declared_at'])
    for local,(candidate,row) in enumerate(zip(plan['candidates'],value['candidates']),1):
        if (row['local_index']!=local or row['original_candidate_index']!=plan['original_candidate_indices'][local-1]
                or row['candidate']!=candidate or type(row['discovery_returncode']) is not int
                or row['discovery_returncode'] not in (0,1) or not graph.reader().zero_credit(row)
                or row!=graph.load(graph.read(root/f'candidate-{local:06d}-closed.json'))):
            raise ValueError('ordered original/local candidate mapping or credit changed')
        before,bs,be=graph.operation(root/'operations'/f'candidate-{local:06d}-before-actors',0,
            expected_command=['docker','--host',graph.DAEMON,'ps','--format','{{.ID}} {{.Names}}'])
        if (graph.read(before['stdout']['path']).strip() or graph.read(before['stderr']['path']).strip()
                or not previous<=graph.utc(bs['started_at'])):
            raise ValueError('candidate has no serial actor absence boundary')
        op,start,end=graph.operation(root/'operations'/f'candidate-{local:06d}-discover',row['discovery_returncode'],
            expected_command=command(plan,plan_path,root,local,inputs['container_prefix']))
        if not 0<end['elapsed_seconds']<=graph.OUTER['maximum_recorded_seconds']:
            raise ValueError('prospective setup-aware outer bound changed')
        attempt=root/'attempts'/f'candidate-{local:06d}'
        inner=graph.load(graph.read(attempt/'started.json'))
        metadata=graph.read(attempt/'image-source-metadata.json')
        runtime=graph.reader()._retained_runtime(plan,metadata)
        evidence_path=graph.reopen(row['evidence'])[0]
        evidence=graph.load(graph.read(evidence_path))
        if (inner['plan']!=value['plan'] or inner['candidate']!=candidate or inner['runtime']!=runtime
                or not graph.reader().zero_credit(inner)
                or graph.load(metadata)!=graph.load(graph.reopen(plan['source_metadata'])[1])
                or not graph.utc(be['completed_at'])<=graph.utc(start['started_at'])<=graph.utc(inner['started_at'])
                    <=graph.utc(evidence['completed_at'])<=graph.utc(end['completed_at'])):
            raise ValueError('actual new attempt identity/runtime/chronology changed')
        if (graph.utc(inner['started_at'])-graph.utc(start['started_at'])).total_seconds()>graph.OUTER['setup_seconds']:
            raise ValueError('declared prospective setup bound exceeded')
        if row['discovery_returncode']==0:
            if evidence_path!=attempt/'whole-graph-input.json' or (attempt/'failed.json').exists():
                raise ValueError('successful graph evidence conflicts with failure')
            graph.verify_input(evidence_path)
            _,vs,ve=graph.operation(root/'operations'/f'candidate-{local:06d}-verify-input',0,
                expected_command=[inputs['verify_interpreter'],'-I','-B',str(HERE/'operator.py'),'verify-input','--input',str(evidence_path)])
            if graph.utc(vs['started_at'])<graph.utc(end['completed_at']):
                raise ValueError('verification predates actual discovery terminal')
            previous=graph.utc(ve['completed_at'])
        else:
            if (evidence_path!=attempt/'failed.json' or (attempt/'whole-graph-input.json').exists()
                    or evidence['plan']!=value['plan'] or evidence['candidate']!=candidate
                    or evidence['outcome']!='operational-discovery-failure-no-admission'
                    or not graph.reader().zero_credit(evidence)):
                raise ValueError('real producer failure required; interruption is not failure')
            if failed(plan,plan_path,attempt,candidate,
                    root/'operations'/f'candidate-{local:06d}-discover') != row['evidence']:
                raise ValueError('original typed failure evidence changed')
            previous=graph.utc(end['completed_at'])
        after,ab,ae=graph.operation(root/'operations'/f'candidate-{local:06d}-after-actors',0,
            expected_command=['docker','--host',graph.DAEMON,'ps','--format','{{.ID}} {{.Names}}'])
        if (graph.read(after['stdout']['path']).strip() or graph.read(after['stderr']['path']).strip()
                or not previous<=graph.utc(ab['started_at'])):
            raise ValueError('actual terminal actor absence required')
        previous=graph.utc(ae['completed_at'])
    if not previous<=graph.utc(value['closed_at'])<=graph.utc(graph.now()):
        raise ValueError('batch closure chronology differs')
    action_facts.current().check()
    return value
