"""Individual accepted traces from an incomplete released slot-chunk lane.

The measurement release executes the unchanged original deep proof program.
This additive role binds its actual installed runtime and complete Git Source;
it never executes capture, completes a lane, or relabels older receipts.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from . import rapid_partial_lane as original
from .rapid_partial_lane import (_path, reference, reopen, encoded, _write,
    _document, _git, _timestamp, _close_dependencies)
from .util import durable_create

SOURCE_TYPE = "qcsd-chunk-partial-lane-installed-release-source-v1"
SOURCE_V2_TYPE = "qcsd-chunk-partial-lane-portable-installed-release-source-v2"
TYPE = "qcsd-original-deep-verified-individual-traces-from-incomplete-chunk-v1"
CONTRACT = "released-original-accepted-chunk-traces-incomplete-aggregate-no-lane-pass-v1"
LAYOUT = "remaining-slot-chunk-v1"
FOUR_TYPE = "qcsd-original-deep-verified-individual-traces-from-dynamic-four-visit-lane-v1"
FOUR_CONTRACT = "released-original-accepted-four-visit-traces-incomplete-aggregate-no-lane-pass-v1"
FOUR_LAYOUT = "original-serial-v6-four-visit-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
RUNTIME_KEYS = {"runtime_source_root", "module_root", "base_launcher", "host_launcher",
    "source_manifest", "client_binary", "collection_image_digest"}
# The original program including its public deep validator is byte-exact.
_PROGRAM = original._PROGRAM


def release_snapshot(root, lab_head, native_head):
    """The original verifier must be a complete unchanged paired Git release."""
    root = _path(root, directory=True)
    if any(not isinstance(x, str) or HEAD.fullmatch(x) is None for x in (lab_head, native_head)):
        raise ValueError("partial lane Source requires exact release heads")
    files = {}
    for checkout, prefix, head in ((root, "", lab_head), (root / "neqo-qcsd", "neqo-qcsd/", native_head)):
        if _git(checkout, "rev-parse", "HEAD").decode().strip() != head:
            raise ValueError("original verifier Source release moved")
        tree = {}; index = {}; rows = []
        for row in _git(checkout, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
            if row:
                meta, name = row.split(b"\t"); mode, _, blob = meta.decode().split()
                tree[name.decode()] = (mode, blob)
        for row in _git(checkout, "ls-files", "-s", "-z").split(b"\0"):
            if not row: continue
            meta, raw_name = row.split(b"\t"); mode, blob, stage = meta.decode().split(); name = raw_name.decode()
            if stage != "0" or Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError("original Source has conflicted or escaping membership")
            index[name] = (mode, blob)
            if mode == "160000":
                if prefix or name != "neqo-qcsd" or blob != native_head:
                    raise ValueError("original verifier Native Gitlink changed")
                continue
            if mode not in {"100644", "100755"} or tree.get(name) != (mode, blob):
                raise ValueError("original verifier Source index differs from release")
            rows.append((name, mode, blob))
        if tree != index:
            raise ValueError("original verifier Source membership differs from release")
        raw = _git(checkout, "cat-file", "--batch", input="".join(x[2] + "\n" for x in rows).encode()); offset = 0
        for name, mode, blob in rows:
            end = raw.index(b"\n", offset); actual, kind, size = raw[offset:end].decode().split()
            body = raw[end + 1:end + 1 + int(size)]; offset = end + int(size) + 2
            ref = reference(checkout / name)
            if (actual != blob or kind != "blob" or ref["sha256"] != hashlib.sha256(body).hexdigest()
                    or ref["mode"] != int(mode[-3:], 8)):
                raise ValueError("original verifier Source bytes or mode differ from release")
            files[prefix + name] = ref
        if offset != len(raw): raise ValueError("original Source Git stream has trailing data")
    if not any(p.startswith("neqo-qcsd/") for p in files):
        raise ValueError("original verifier requires its full Native release")
    for directory in (root / "src", root / "tools"):
        for p in directory.rglob("*.py"):
            if "__pycache__" not in p.parts and p.relative_to(root).as_posix() not in files:
                raise ValueError("original verifier acquired an unbound importable file")
    return {"root": str(root), "lab_head": lab_head, "native_head": native_head, "files": files}


def portable_release_snapshot(root, lab_head, native_head, installed_root):
    """Bind Git bytes and both exact, separately observed permission roles."""
    root = _path(root, directory=True)
    installed_root = _path(installed_root, directory=True)
    if any(not isinstance(x, str) or HEAD.fullmatch(x) is None for x in (lab_head, native_head)):
        raise ValueError('portable Source requires exact release heads')
    files = {}; installed_files = {}; mode_pairs = {}
    for checkout, prefix, head in ((root, '', lab_head), (root / 'neqo-qcsd', 'neqo-qcsd/', native_head)):
        if _git(checkout, 'rev-parse', 'HEAD').decode().strip() != head:
            raise ValueError('portable Source release moved')
        tree = {}; index = {}; rows = []
        for row in _git(checkout, 'ls-tree', '-r', '-z', 'HEAD').split(b'\0'):
            if row:
                meta, name = row.split(b'\t'); mode, _, blob = meta.decode().split()
                tree[name.decode()] = (mode, blob)
        for row in _git(checkout, 'ls-files', '-s', '-z').split(b'\0'):
            if not row: continue
            meta, raw_name = row.split(b'\t'); mode, blob, stage = meta.decode().split(); name = raw_name.decode()
            if stage != '0' or Path(name).is_absolute() or '..' in Path(name).parts:
                raise ValueError('portable Source has conflicted or escaping membership')
            index[name] = (mode, blob)
            if mode == '160000':
                if prefix or name != 'neqo-qcsd' or blob != native_head:
                    raise ValueError('portable Native Gitlink changed')
                continue
            if mode not in {'100644', '100755'} or tree.get(name) != (mode, blob):
                raise ValueError('portable Source index differs from release')
            rows.append((name, mode, blob))
        if tree != index:
            raise ValueError('portable Source membership differs from release')
        raw = _git(checkout, 'cat-file', '--batch', input=''.join(x[2] + '\n' for x in rows).encode()); offset = 0
        for name, mode, blob in rows:
            end = raw.index(b'\n', offset); actual, kind, size = raw[offset:end].decode().split()
            body = raw[end + 1:end + 1 + int(size)]; offset = end + int(size) + 2
            ref = reference(checkout / name)
            allowed = {0o600, 0o644} if mode == '100644' else {0o755}
            if (actual != blob or kind != 'blob' or ref['sha256'] != hashlib.sha256(body).hexdigest()
                    or ref['mode'] not in allowed):
                raise ValueError('portable Source bytes or observed mode differ from its Git release')
            relative = prefix + name
            installed = reference(installed_root / relative)
            installed_allowed = {0o644, 0o664} if mode == '100644' else {0o755, 0o775}
            if (installed['sha256'] != ref['sha256'] or installed['mode'] not in installed_allowed):
                raise ValueError('portable installed Source bytes or executable-class mode differ from Git')
            files[relative] = ref
            installed_files[relative] = installed
            mode_pairs[relative] = {'git_mode': mode, 'observed_mode': ref['mode'],
                                    'installed_mode': installed['mode']}
        if offset != len(raw): raise ValueError('portable Source Git stream has trailing data')
    if not any(p.startswith('neqo-qcsd/') for p in files):
        raise ValueError('portable Source requires its full Native release')
    for directory in (root / 'src', root / 'tools'):
        for p in directory.rglob('*.py'):
            if '__pycache__' not in p.parts and p.relative_to(root).as_posix() not in files:
                raise ValueError('portable Source acquired an unbound importable file')
    return {'root': str(root), 'lab_head': lab_head, 'native_head': native_head,
            'files': files, 'installed_files': installed_files, 'mode_pairs': mode_pairs}

def accepted_subset(report):
    """Join a genuine original deep result to its entire originally planned lane."""
    e, lane, intent, lineage, spec = (report[k] for k in ("experiment", "lane", "intent", "lineage", "spec"))
    config, summary, source = (e[k] for k in ("configuration", "summary", "source"))
    from .rapid_slot_chunks import checked_lane
    checked_lane(lane)
    visits = lane["visits_per_workload"]
    count = len(lane["workload_ids"]) * visits
    if (lane["role"] != "formal" or lane["study_version"] != 6 or not 1 <= visits <= 16
            or type(lane["block"]) is not int or not 1 <= lane["block"] <= 64
            or intent["actuator"] != "run" or e["status"] != "incomplete" or summary["passed"] is not False
            or e["name"] != lane["campaign_name"] or e["purpose"] != "evaluation"
            or config["campaign_sha256"] != intent["campaign_sha256"] or config["profile"] != "research-1200"
            or config["request_policies"] != ["as-defined"] or config["chaff_qualification_set"] != lane["qualification_set"]
            or source["lab_dirty"] is not False or source["lab_commit"] != lineage["lab_commit"]
            or source["image_digest"] != spec["collection_image_digest"]):
        raise ValueError("partial lane changes original incomplete formal contract")
    sites = {s["workload_id"]: s for s in report["sites"] if s["workload_id"] in lane["workload_ids"]}
    if set(sites) != set(lane["workload_ids"]): raise ValueError("partial lane site graph membership changed")
    expected_workloads = {name: (s["workload_sha256"], visits) for name, s in sites.items()}
    observed = {s["id"]: (s["sha256"], s["visits"]) for s in config["workloads"]}
    if len(config["workloads"]) != len(sites) or observed != expected_workloads:
        raise ValueError("partial lane changed a full workload graph or visit count")
    if len(config["defenses"]) != 1 or config["defenses"][0]["name"] != lane["mode"]:
        raise ValueError("partial lane changed its defense mode")
    if lane["qualification_set"] is not None:
        hashes = {s["qualification_set_manifest_sha256"] for s in sites.values()}
        if len(hashes) != 1 or config["chaff_qualification_set_manifest_sha256"] not in hashes:
            raise ValueError("partial lane changed the full qualification group")
    samples = e["samples"]
    expected = {(name, visit, lane["mode"]) for name in lane["workload_ids"] for visit in range(visits)}
    slots = [(s["workload_id"], s["visit"], s["defense"]) for s in samples]
    if (len(samples) != count or len(set(slots)) != count or set(slots) != expected
            or len({s["sample_id"] for s in samples}) != count
            or any(type(s["visit"]) is not int or s["request_policy"] != "as-defined"
                   or s["state"] not in {"accepted", "failed", "planned"} for s in samples)):
        raise ValueError("partial lane has moved, duplicate, absent or running slots")
    accepted = [s for s in samples if s["state"] == "accepted"]
    if (not 0 < len(accepted) < count or summary["planned"] != count or summary["accepted"] != len(accepted)
            or summary["failed"] != sum(s["state"] == "failed" for s in samples)
            or any(s["eligible"] is not True for s in accepted)
            or set(report["accepted_samples"]) != {s["sample_id"] for s in accepted}):
        raise ValueError("partial lane deep accepted subset differs from original checkpoint")
    rows, remaining = [], []
    for s in samples:
        slot = {"candidate_id": sites[s["workload_id"]]["candidate_id"], "workload_id": s["workload_id"],
                "workload_sha256": sites[s["workload_id"]]["workload_sha256"], "mode": lane["mode"],
                "logical_visit": lane["slot_start"] + s["visit"], "actual_local_visit": s["visit"],
                "sample_id": s["sample_id"], "original_state": s["state"]}
        if s["state"] == "accepted":
            if s["artifacts"] != report["accepted_samples"][s["sample_id"]] or not s["artifacts"]:
                raise ValueError("partial lane lost original accepted raw artifacts")
            rows.append({**slot, "path": s["path"], "artifacts": s["artifacts"], "diagnostics": s["diagnostics"]})
        else:
            if s["artifacts"]: raise ValueError("partial lane attempts to promote nonaccepted artifacts")
            remaining.append({**slot, "attempts": s["attempts"], "failure": s["failure"]})
    return {"registered_layout": LAYOUT, "chunk_plan": report["chunk_bindings"]["plan"],
        "slot_policy": report["chunk_bindings"]["policy"], "slot_start": lane["slot_start"],
        "slot_count": visits, "aggregate_status": e["status"], "aggregate_summary": summary, "configuration": config,
        "measurement_source": source, "lane": lane, "spec": spec, "intent": intent,
        "lineage": lineage, "result_root": report["result_root"], "result_seal": report["result_seal"],
        "accepted_count": len(rows), "accepted_samples": rows, "remaining_samples": remaining,
        "lane_pass_claim": False, "aggregate_formal_credit": 0,
        "individual_trace_authority": "original-collector-accepted-and-original-deep-verified-v1"}


def _legacy_lane(value):
    from . import rapid_capture_plan as plan
    from .rapid_rolling_capture import _keys
    _keys(value, set(plan.Lane.__dataclass_fields__), 'dynamic original four-visit lane')
    if not isinstance(value['workload_ids'], (list, tuple)):
        raise ValueError('dynamic original lane requires its ordered workload list')
    lane = plan.Lane(**{k: tuple(v) if k == 'workload_ids' else v for k,v in value.items()})
    if (lane.role != 'formal' or type(lane.study_version) is not int or lane.study_version != 6
            or type(lane.block) is not int or not 1 <= lane.block <= 16
            or type(lane.shard) is not int or not 1 <= lane.shard <= 50
            or lane.mode not in plan.MODES or type(lane.visits_per_workload) is not int or lane.visits_per_workload != 4
            or type(lane.generation) is not int or not 1 <= lane.generation <= plan.MAX_LANE_GENERATION
            or not 1 <= len(lane.workload_ids) <= 5 or len(set(lane.workload_ids)) != len(lane.workload_ids)
            or any(not isinstance(v,str) or plan.IDENTIFIER_RE.fullmatch(v) is None for v in lane.workload_ids)
            or (lane.qualification_set is None) != (lane.mode == 'undefended')
            or lane.qualification_set is not None and (not isinstance(lane.qualification_set,str)
                or plan.IDENTIFIER_RE.fullmatch(lane.qualification_set) is None)
            or lane.campaign_name != plan._campaign_name(lane.role,lane.block,lane.shard,lane.mode,lane.generation,6)):
        raise ValueError('dynamic original lane changed its four-visit identity, offsets or mode')
    return lane


def four_accepted_subset(report):
    """Exact historical acceptance with a distinct dynamic four-visit role."""
    lane = _legacy_lane(report['lane'])
    return {**original.accepted_subset(report), 'registered_layout': FOUR_LAYOUT,
        'original_four_visit_plan': report['four_bindings']['plan'],
        'slot_start': (lane.block-1)*4, 'slot_count': 4}


def partial_subset(report):
    return accepted_subset(report) if 'lane_layout' in report['lane'] else four_accepted_subset(report)


def _kind(layout):
    if layout == LAYOUT: return TYPE, CONTRACT
    if layout == FOUR_LAYOUT: return FOUR_TYPE, FOUR_CONTRACT
    raise ValueError('dynamic partial receipt has an unregistered lane layout')


def _four_binding(report):
    from .rapid_lane_evidence import plan_payload
    lane = _legacy_lane(report['lane'])
    plan = reference(report['spec']['plan_receipt'])
    payload = plan_payload(reopen(plan).read_bytes())
    if (any(k in payload for k in ('lane_layout','slot_chunk_policy'))
            or payload != report['lineage']['image_check']['proof']['plan_payload']):
        raise ValueError('dynamic four-visit plan differs from the original executed authority')
    matching = [r for r in payload['lanes'] if r.get('campaign_name') == lane.campaign_name]
    if (len(matching) != 1 or encoded({k:v for k,v in matching[0].items() if k != 'campaign_sha256'}) != encoded(report['lane'])
            or plan not in report['read_dependencies']):
        raise ValueError('dynamic four-visit proof lost its exact original plan lane')
    return {**report, 'four_bindings': {'plan': plan}}

# Reuse the exact read-only observer/import prefix with the TRUSTED executing
# consumer Source. A proposed measurement release cannot approve itself. The
# original deep body remains _PROGRAM and imports only its authenticated release.
_RUNTIME_PROGRAM = _PROGRAM.split('facts=OperationFacts();facts.begin_action()', 1)[0] + r'''
from qcsd_lab.rapid_rolling_schedule import reopen_runtime
canonical,sources=reopen_runtime({'path':q['canonical']['path'],'sha256':q['canonical']['sha256']},q['runtime'],_inspector=True)
source=canonical['source']
files={name:{'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE((Path(q['runtime']['runtime_source_root'])/name).stat().st_mode)} for name,raw in sources.items()}
report={'source':source,'collection_image_digest':canonical['collection_image_digest'],
'client_sha256':canonical['installed_client_sha256'],'source_files':files,
'base_launcher':record(q['runtime']['base_launcher']),'host_launcher':record(q['runtime']['host_launcher'])}
for p,v in list(watched.items()):record(p)
for p,v in list(directories.items()):directory(p)
report['read_dependencies']=list(watched.values());report['directory_dependencies']=list(directories.values())
print(json.dumps(report,sort_keys=True,allow_nan=False))
'''


def _consumer_root():
    return _path(Path(__file__).absolute().parents[2], directory=True)


def _reader_sources():
    from . import rapid_slot_chunks, util, rapid_rolling_schedule, rapid_capture_plan
    return {module.__name__: reference(Path(module.__file__).absolute())
            for module in (sys.modules[__name__], original, rapid_slot_chunks, util, rapid_rolling_schedule, rapid_capture_plan)}


def _runtime_request(release, canonical, runtime, audit):
    reopen(canonical)
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_KEYS:
        raise ValueError('chunk partial binding requires the seven exact runtime roles')
    for key in ('runtime_source_root', 'module_root'):
        _path(runtime[key], directory=True)
    for key in ('base_launcher', 'host_launcher', 'source_manifest', 'client_binary'):
        _path(runtime[key])
    if (not isinstance(runtime['collection_image_digest'], str)
            or re.fullmatch(r'sha256:[0-9a-f]{64}', runtime['collection_image_digest']) is None):
        raise ValueError('chunk partial runtime image is not immutable')
    return {'source_root': str(_consumer_root()), 'canonical': canonical,
            'runtime': runtime, 'scratch_root': str(Path(audit) / 'scratch')}


def _compatible_reader_sources(producer):
    """Authenticate original reader locations without changing their identity."""
    from . import rapid_fixed_condition_target as target
    current = _reader_sources()
    if not isinstance(producer, dict) or set(producer) != set(current):
        raise ValueError('chunk partial reader unit set changed')
    package = Path(producer[__name__]['path']).parent
    if package.name != 'qcsd_lab' or package.parent.name != 'src':
        raise ValueError('chunk partial original reader lacks its explicit Source package')
    for name, expected in current.items():
        ref = producer[name]
        if (set(ref) != {'path', 'sha256', 'mode'}
                or Path(ref['path']) != package / (name.rsplit('.', 1)[-1] + '.py')):
            raise ValueError('chunk partial original reader locations are inconsistent')
        if name == __name__:
            target._compatible_code_ref('dynamic', ref, expected)
        elif name == 'qcsd_lab.rapid_rolling_schedule':
            if (reference(ref['path']) != ref or reference(expected['path']) != expected
                    or ref['mode'] != expected['mode'] or ref['sha256'] != expected['sha256'] and
                    target._parallel_schedule_source_projection(Path(ref['path']).read_bytes()) !=
                    target._parallel_schedule_source_projection(Path(expected['path']).read_bytes())):
                raise ValueError('chunk partial scheduling reader changed protected code or full modes')
        elif (reference(ref['path']) != ref or reference(expected['path']) != expected
                or any(ref[key] != expected[key] for key in ('sha256', 'mode'))):
            raise ValueError('chunk partial original/current reader code bytes or full modes changed')
    return str(package.parent.parent)


def _runtime_operation(release, canonical, runtime, operation, *, reader_sources=None):
    if set(operation) != {'started.json', 'completed.json', 'stdout.log', 'stderr.log'}:
        raise ValueError('chunk partial runtime operation lacks its four records')
    paths = {name: reopen(ref) for name, ref in operation.items()}
    if len({p.parent for p in paths.values()}) != 1 or any(p.name != k for k, p in paths.items()):
        raise ValueError('chunk partial runtime operation records moved')
    started = json.loads(paths['started.json'].read_bytes())
    completed = json.loads(paths['completed.json'].read_bytes())
    readers = _reader_sources() if reader_sources is None else reader_sources
    expected_request = _runtime_request(release, canonical, runtime, paths['started.json'].parent)
    expected_request['source_root'] = _compatible_reader_sources(readers)
    command = started.get('command')
    interpreter = started.get('interpreter')
    if (not isinstance(command, list) or len(command) != 5 or not isinstance(command[0], str)
            or not Path(command[0]).is_absolute() or not isinstance(interpreter, dict)
            or set(interpreter) != {'path', 'sha256', 'mode'}
            or reference(Path(command[0]).resolve(strict=True)) != interpreter):
        raise ValueError('chunk partial original runtime interpreter changed')
    if (set(started) != {'command', 'request', 'reader_sources', 'interpreter', 'started_at'}
            or started['command'] != [command[0], '-I', '-B', '-c', _RUNTIME_PROGRAM]
            or started['request'] != expected_request
            or started['reader_sources'] != readers
            or set(completed) != {'returncode', 'completed_at', 'stdout_sha256', 'stderr_sha256'}
            or type(completed['returncode']) is not int or completed['returncode'] != 0
            or any(completed[k + '_sha256'] != operation[k + '.log']['sha256'] for k in ('stdout', 'stderr'))
            or not _timestamp(started['started_at']) <= _timestamp(completed['completed_at']) <= datetime.now(timezone.utc)):
        raise ValueError('chunk partial recorded installation proof changed')
    report = json.loads(paths['stdout.log'].read_bytes())
    if set(report) != {'source', 'collection_image_digest', 'client_sha256', 'source_files',
                       'base_launcher', 'host_launcher', 'read_dependencies', 'directory_dependencies'}:
        raise ValueError('chunk partial installation proof has another schema')
    expected = {name: {key: ref[key] for key in ('sha256', 'mode')} for name, ref in release['files'].items()}
    source = report['source']
    empty = hashlib.sha256(b'').hexdigest()
    if (report['source_files'] != expected or source.get('lab_commit') != release['lab_head']
            or source.get('neqo_commit') != release['native_head'] or source.get('neqo_pinned_commit') != release['native_head']
            or source.get('lab_dirty') is not False or source.get('neqo_dirty') is not False
            or source.get('lab_patch_sha256') != empty or source.get('neqo_patch_sha256') != empty
            or report['collection_image_digest'] != runtime['collection_image_digest']
            or report['client_sha256'] != reference(runtime['client_binary'])['sha256']
            or any(reference(runtime[key])['sha256'] != release['files']['qcsd-lab']['sha256']
                   or reference(runtime[key])['mode'] != release['files']['qcsd-lab']['mode']
                   for key in ('base_launcher', 'host_launcher'))):
        raise ValueError('chunk partial installed Source, client or launcher differs from its Git release')
    _close_dependencies(report)
    return report, completed


def _run_runtime(release, canonical, runtime, audit_root):
    audit = Path(audit_root).absolute(); _path(audit.parent, directory=True)
    protected = [Path(release['root']), _consumer_root(), Path(canonical['path']).parent,
                 Path(runtime['runtime_source_root']), Path(runtime['source_manifest']).parent]
    if any(audit.is_relative_to(p) or p.is_relative_to(audit) for p in protected):
        raise ValueError('chunk partial installation audit must be disjoint and fresh')
    request = _runtime_request(release, canonical, runtime, audit)
    audit.mkdir(mode=0o755, exist_ok=False); (audit / 'scratch').mkdir(mode=0o700, exist_ok=False)
    command = [sys.executable, '-I', '-B', '-c', _RUNTIME_PROGRAM]
    started = {'command': command, 'request': request, 'reader_sources': _reader_sources(),
               'interpreter': reference(Path(sys.executable).resolve()), 'started_at': datetime.now(timezone.utc).isoformat()}
    durable_create(audit / 'started.json', encoded(started))
    env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH' and not k.startswith(('QCSD_', 'GIT_', 'PYTHON'))}
    env['GIT_OPTIONAL_LOCKS'] = '0'
    result = subprocess.run(command, input=encoded(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, check=False)
    durable_create(audit / 'stdout.log', result.stdout); durable_create(audit / 'stderr.log', result.stderr)
    completed = {'returncode': result.returncode, 'completed_at': datetime.now(timezone.utc).isoformat(),
                 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
    durable_create(audit / 'completed.json', encoded(completed))
    if result.returncode != 0:
        raise ValueError('original installed runtime reopening refused; raw installation audit retained')
    operation = {name: reference(audit / name) for name in ('started.json', 'completed.json', 'stdout.log', 'stderr.log')}
    report, _ = _runtime_operation(release, canonical, runtime, operation)
    return report, operation


def _portable_installed_release(release):
    """Compare image files with Git modes while retaining measured full modes."""
    if (not isinstance(release, dict)
            or set(release) != {'root', 'lab_head', 'native_head', 'files', 'installed_files', 'mode_pairs'}
            or not isinstance(release['files'], dict) or not isinstance(release['installed_files'], dict)
            or not isinstance(release['mode_pairs'], dict)
            or set(release['files']) != set(release['mode_pairs'])
            or set(release['files']) != set(release['installed_files'])):
        raise ValueError('portable Source permission contract has another schema')
    installed = {}
    for name, ref in release['files'].items():
        pair = release['mode_pairs'][name]
        installed_ref = release['installed_files'][name]
        if (not isinstance(pair, dict)
                or set(pair) != {'git_mode', 'observed_mode', 'installed_mode'}
                or not isinstance(ref, dict) or set(ref) != {'path', 'sha256', 'mode'}
                or not isinstance(installed_ref, dict) or set(installed_ref) != {'path', 'sha256', 'mode'}
                or pair['observed_mode'] != ref['mode']
                or pair['installed_mode'] != installed_ref['mode']
                or installed_ref['sha256'] != ref['sha256']):
            raise ValueError('portable Source permission pair changed')
        git_mode = pair['git_mode']
        if (git_mode == '100644' and (ref['mode'] not in (0o600, 0o644)
                or installed_ref['mode'] not in (0o644, 0o664))
                or git_mode == '100755' and (ref['mode'] != 0o755
                or installed_ref['mode'] not in (0o755, 0o775))
                or git_mode not in ('100644', '100755')):
            raise ValueError('portable Source has an unauthorized permission pair')
        installed[name] = installed_ref
    return {**release, 'files': installed}


def _portable_runtime_roles(canonical, runtime):
    """Keep the installed permission role on the actual frozen image context."""
    installed_root = reopen(canonical).parent / 'image-context' / 'source'
    if (not isinstance(runtime, dict) or set(runtime) != RUNTIME_KEYS
            or _path(runtime['runtime_source_root'], directory=True) != _path(installed_root, directory=True)
            or _path(runtime['module_root'], directory=True) != installed_root):
        raise ValueError('portable installation Source must be its actual image context')


def _run_portable_runtime(release, canonical, runtime, audit_root):
    _portable_runtime_roles(canonical, runtime)
    audit = Path(audit_root).absolute(); _path(audit.parent, directory=True)
    protected = [Path(release['root']), _consumer_root(), Path(canonical['path']).parent,
                 Path(runtime['runtime_source_root']), Path(runtime['source_manifest']).parent]
    if any(audit.is_relative_to(p) or p.is_relative_to(audit) for p in protected):
        raise ValueError('portable installation audit must be disjoint and fresh')
    request = _runtime_request(release, canonical, runtime, audit)
    audit.mkdir(mode=0o755, exist_ok=False); (audit / 'scratch').mkdir(mode=0o700, exist_ok=False)
    command = [sys.executable, '-I', '-B', '-c', _RUNTIME_PROGRAM]
    started = {'command': command, 'request': request, 'reader_sources': _reader_sources(),
               'interpreter': reference(Path(sys.executable).resolve()), 'started_at': datetime.now(timezone.utc).isoformat()}
    durable_create(audit / 'started.json', encoded(started))
    env = {k: v for k, v in os.environ.items() if k != 'PYTHONPATH' and not k.startswith(('QCSD_', 'GIT_', 'PYTHON'))}
    env['GIT_OPTIONAL_LOCKS'] = '0'
    result = subprocess.run(command, input=encoded(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, check=False)
    durable_create(audit / 'stdout.log', result.stdout); durable_create(audit / 'stderr.log', result.stderr)
    completed = {'returncode': result.returncode, 'completed_at': datetime.now(timezone.utc).isoformat(),
                 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(), 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}
    durable_create(audit / 'completed.json', encoded(completed))
    if result.returncode != 0:
        raise ValueError('portable installed runtime reopening refused; raw installation audit retained')
    operation = {name: reference(audit / name) for name in ('started.json', 'completed.json', 'stdout.log', 'stderr.log')}
    report, _ = _runtime_operation(_portable_installed_release(release), canonical, runtime, operation)
    return report, operation


def bind_portable_source(*, root, canonical, runtime, audit_root, output):
    """Bind separate measured and installed file modes under one clean Git pair."""
    raw = json.loads(reopen(canonical).read_bytes())
    metadata = raw.get('source', {})
    _portable_runtime_roles(canonical, runtime)
    release = portable_release_snapshot(root, metadata.get('lab_commit'), metadata.get('neqo_commit'),
        runtime['runtime_source_root'])
    readers = _reader_sources()
    report, operation = _run_portable_runtime(release, canonical, runtime, audit_root)
    target = Path(output).absolute()
    if any(target.is_relative_to(p) for p in (Path(release['root']), Path(audit_root), Path(canonical['path']).parent)):
        raise ValueError('portable Source binding must be outside original authority')
    if portable_release_snapshot(root, release['lab_head'], release['native_head'],
            runtime['runtime_source_root']) != release or _reader_sources() != readers:
        raise ValueError('portable release or executing reader changed before binding')
    _close_dependencies(report)
    return _write(target, SOURCE_V2_TYPE, {'release': release, 'canonical': canonical, 'runtime': runtime,
        'runtime_identity': {key: report[key] for key in ('source', 'collection_image_digest', 'client_sha256')},
        'runtime_operation': operation, 'read_dependencies': report['read_dependencies'],
        'directory_dependencies': report['directory_dependencies'], 'reader_sources': readers,
        'published_at': datetime.now(timezone.utc).isoformat()})


def bind_source(*, root, canonical, runtime, audit_root, output):
    """Bind an actual installed clean release; no release-head allowlist cycle."""
    raw = json.loads(reopen(canonical).read_bytes())
    metadata = raw.get('source', {})
    release = release_snapshot(root, metadata.get('lab_commit'), metadata.get('neqo_commit'))
    readers = _reader_sources()
    report, operation = _run_runtime(release, canonical, runtime, audit_root)
    target = Path(output).absolute()
    if any(target.is_relative_to(p) for p in (Path(release['root']), Path(audit_root), Path(canonical['path']).parent)):
        raise ValueError('chunk partial Source binding must be outside original authority')
    if release_snapshot(root, release['lab_head'], release['native_head']) != release or _reader_sources() != readers:
        raise ValueError('chunk partial release or executing reader changed before binding')
    _close_dependencies(report)
    return _write(target, SOURCE_TYPE, {'release': release, 'canonical': canonical, 'runtime': runtime,
        'runtime_identity': {key: report[key] for key in ('source', 'collection_image_digest', 'client_sha256')},
        'runtime_operation': operation, 'read_dependencies': report['read_dependencies'],
        'directory_dependencies': report['directory_dependencies'], 'reader_sources': readers,
        'published_at': datetime.now(timezone.utc).isoformat()})


def _source(ref):
    if json.loads(reopen(ref).read_bytes()).get('artifact_type') == SOURCE_V2_TYPE:
        return _portable_source(ref)
    value = _document(ref, SOURCE_TYPE)
    if set(value) != {'release', 'canonical', 'runtime', 'runtime_identity', 'runtime_operation',
                     'read_dependencies', 'directory_dependencies', 'reader_sources', 'published_at'}:
        raise ValueError('chunk partial Source binding has another schema')
    release = value['release']
    if (set(release) != {'root', 'lab_head', 'native_head', 'files'}
            or release_snapshot(release['root'], release['lab_head'], release['native_head']) != release
            or not _compatible_reader_sources(value['reader_sources'])):
        raise ValueError('chunk partial original or executing Source changed')
    report, completed = _runtime_operation(release, value['canonical'], value['runtime'], value['runtime_operation'],
        reader_sources=value['reader_sources'])
    if (value['runtime_identity'] != {key: report[key] for key in ('source', 'collection_image_digest', 'client_sha256')}
            or value['read_dependencies'] != report['read_dependencies']
            or value['directory_dependencies'] != report['directory_dependencies']
            or not _timestamp(completed['completed_at']) <= _timestamp(value['published_at']) <= datetime.now(timezone.utc)):
        raise ValueError('chunk partial Source binding differs from its actual installation proof')
    _close_dependencies(value)
    return {**release, 'binding': value}


def _portable_source(ref):
    value = _document(ref, SOURCE_V2_TYPE)
    if set(value) != {'release', 'canonical', 'runtime', 'runtime_identity', 'runtime_operation',
                      'read_dependencies', 'directory_dependencies', 'reader_sources', 'published_at'}:
        raise ValueError('portable Source binding has another schema')
    release = value['release']
    _portable_runtime_roles(value['canonical'], value['runtime'])
    if (not isinstance(release, dict)
            or set(release) != {'root', 'lab_head', 'native_head', 'files', 'installed_files', 'mode_pairs'}
            or portable_release_snapshot(release['root'], release['lab_head'], release['native_head'],
                value['runtime']['runtime_source_root']) != release
            or not _compatible_reader_sources(value['reader_sources'])):
        raise ValueError('portable original or executing Source changed')
    report, completed = _runtime_operation(_portable_installed_release(release), value['canonical'],
        value['runtime'], value['runtime_operation'], reader_sources=value['reader_sources'])
    if (value['runtime_identity'] != {key: report[key] for key in ('source', 'collection_image_digest', 'client_sha256')}
            or value['read_dependencies'] != report['read_dependencies']
            or value['directory_dependencies'] != report['directory_dependencies']
            or not _timestamp(completed['completed_at']) <= _timestamp(value['published_at']) <= datetime.now(timezone.utc)):
        raise ValueError('portable Source binding differs from its actual installation proof')
    _close_dependencies(value)
    return {**release, 'binding': value}


def _measurement_binding(report, source):
    identity = source['binding']['runtime_identity']
    spec, intent = report['spec'], report['intent']
    if (report['experiment']['source'] != {**identity['source'], 'image_digest': identity['collection_image_digest']}
            or spec['module_root'] != source['root']
            or spec['collection_image_digest'] != identity['collection_image_digest']
            or intent['runtime_identity']['runtime_source'] != identity['source']
            or intent['runtime_identity']['collection_image_digest'] != identity['collection_image_digest']
            or intent['runtime_identity']['client_sha256'] != identity['client_sha256']):
        raise ValueError('chunk partial measurement Source or image differs from its actual installed release')
    runtime = source['binding']['runtime']
    for key in ('source_manifest', 'client_binary', 'base_launcher', 'host_launcher'):
        a, b = reference(spec[key]), reference(runtime[key])
        if any(a[field] != b[field] for field in ('sha256', 'mode')):
            raise ValueError('chunk partial measurement runtime copy bytes or mode changed')
    if 'lane_layout' not in report['lane']:
        return _four_binding(report)
    from .rapid_slot_chunks import checked_lane, LAYOUT as CHUNK_LAYOUT
    from .rapid_lane_evidence import plan_payload
    from .rapid_site_admission import _unpack
    from .rapid_slot_chunks import POLICY_TYPE
    lane = checked_lane(report['lane'])
    plan = reference(spec['plan_receipt'])
    payload = plan_payload(reopen(plan).read_bytes())
    if (payload.get('lane_layout') != CHUNK_LAYOUT
            or payload != report['lineage']['image_check']['proof']['plan_payload']):
        raise ValueError('chunk partial plan differs from original executed chunk authority')
    from . import rapid_epoch_target_parallel_schedule as epoch_workers
    if epoch_workers.is_payload(payload):
        return epoch_workers.require_partial_binding(report)
    if 'target_chunk_policy' in payload:
        from .rapid_target_chunks import require_partial_binding
        return require_partial_binding(report)
    if 'epoch_target_chunk_policy' in payload:
        from .rapid_epoch_target_chunks import require_partial_binding
        return require_partial_binding(report)
    policy_ref = payload.get('slot_chunk_policy')
    if not isinstance(policy_ref, dict) or set(policy_ref) != {'path', 'sha256'}:
        raise ValueError('chunk partial slot policy has another schema')
    policy = reference(policy_ref['path'])
    if policy['sha256'] != policy_ref['sha256'] or policy['sha256'] != lane.slot_policy_sha256:
        raise ValueError('chunk partial lane changed its authenticated slot policy')
    _unpack(reopen(policy).read_bytes(), POLICY_TYPE)
    for ref in (plan, policy):
        if ref not in report['read_dependencies']:
            raise ValueError('chunk partial original proof did not observe its plan and policy bytes')
    return {**report, 'chunk_bindings': {'plan': plan, 'policy': policy}}


def _recorded_operation(source, inputs, operation):
    report, completed = original._recorded_operation(source, inputs, operation)
    return _measurement_binding(report, source), completed


def _run_original(source, inputs, audit_root):
    report, operation = original._run_original(source, inputs, audit_root)
    return _measurement_binding(report, source), operation


def _input_closure(source, source_binding, report, operation):
    """Expose the complete authenticated Source/runtime and own deep read set."""
    binding = source['binding']
    files = {}; directories = {}
    refs = (list(report['read_dependencies']) + list(binding['read_dependencies'])
            + list(source['files'].values()) + list(binding['reader_sources'].values())
            + list(binding['runtime_operation'].values()) + list(operation.values())
            + [binding['canonical'], source_binding])
    for ref in refs:
        if ref['path'] in files and files[ref['path']] != ref:
            raise ValueError('chunk partial authenticated dependency aliases disagree')
        files[ref['path']] = ref
    for row in report['directory_dependencies'] + binding['directory_dependencies']:
        if row['path'] in directories and directories[row['path']] != row:
            raise ValueError('chunk partial authenticated directory aliases disagree')
        directories[row['path']] = row
    return {'read_dependencies': [files[k] for k in sorted(files)],
            'directory_dependencies': [directories[k] for k in sorted(directories)]}


def declare(*, source_binding, spec, evidence_root, intent, result, audit_root, output):
    source = _source(source_binding)
    result = _path(result, directory=True)
    inputs = {'source_binding': source_binding, 'spec': reference(spec), 'evidence_root': str(_path(evidence_root, directory=True)),
              'intent': reference(intent), 'result': {'path': str(result), 'seal': reference(result / 'evidence.sha256')}}
    readers = _reader_sources()
    report, operation = _run_original(source, inputs, audit_root)
    facts = partial_subset(report)
    dependencies = _input_closure(source, source_binding, report, operation)
    _close_dependencies(dependencies)
    if _source(source_binding) != source or _reader_sources() != readers:
        raise ValueError('chunk partial original or executing Source changed before publication')
    target = Path(output).absolute()
    if any(target.is_relative_to(Path(p)) for p in (source['root'], inputs['evidence_root'], str(result), str(Path(intent).parent), str(audit_root))):
        raise ValueError('chunk partial receipt must remain outside original Source and evidence')
    kind, contract = _kind(facts['registered_layout'])
    return _write(target, kind, {'contract': contract, 'inputs': inputs, 'reader_sources': readers,
        'deep_operation': operation, **dependencies, **facts,
        'published_at': datetime.now(timezone.utc).isoformat()})


def verify(receipt, *, audit_root):
    raw = json.loads(reopen(receipt).read_bytes())
    if raw.get('artifact_type') not in (TYPE, FOUR_TYPE):
        raise ValueError('dynamic partial receipt has another artifact role')
    value = _document(receipt, raw['artifact_type'])
    kind, contract = _kind(value['registered_layout'])
    if (raw['artifact_type'] != kind or value['contract'] != contract
            or value['lane_pass_claim'] is not False or value['aggregate_formal_credit'] != 0
            or value['reader_sources'] != _reader_sources()):
        raise ValueError('chunk partial receipt changed its explicit incomplete chunk contract')
    source = _source(value['inputs']['source_binding'])
    recorded, completed = _recorded_operation(source, value['inputs'], value['deep_operation'])
    recorded_facts = partial_subset(recorded)
    recorded_inputs = _input_closure(source, value['inputs']['source_binding'], recorded, value['deep_operation'])
    if (any(value.get(k) != v for k, v in recorded_facts.items())
            or value['read_dependencies'] != recorded_inputs['read_dependencies']
            or value['directory_dependencies'] != recorded_inputs['directory_dependencies']
            or not _timestamp(completed['completed_at']) <= _timestamp(value['published_at']) <= datetime.now(timezone.utc)):
        raise ValueError('chunk partial receipt differs from recorded original deep authority')
    _close_dependencies(value)
    report, operation = _run_original(source, value['inputs'], audit_root)
    facts = partial_subset(report)
    if any(value.get(k) != v for k, v in facts.items()):
        raise ValueError('chunk partial receipt differs from independent original deep reopening')
    dependencies = _input_closure(source, value['inputs']['source_binding'], report, operation)
    _close_dependencies(dependencies)
    if _source(value['inputs']['source_binding']) != source or _reader_sources() != value['reader_sources']:
        raise ValueError('chunk partial Source changed during independent verification')
    return {'accepted_count': facts['accepted_count'], 'registered_layout': facts['registered_layout'],
        'slot_start': facts['slot_start'], 'slot_count': facts['slot_count'],
        'aggregate_status': facts['aggregate_status'], 'lane_pass_claim': False,
        'aggregate_formal_credit': 0, 'fresh_deep_operation': operation,
        **dependencies}
