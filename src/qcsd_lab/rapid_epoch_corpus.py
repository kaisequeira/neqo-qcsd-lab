"""Final cross-epoch reader; original validators and measurement labels stay exact.

Source bindings and read-only audit reports grant no capture credit. The final
manifest requires fifty distinct admitted sites and every setting/slot exactly
once. Each original lane is reopened once by its own Source interpreter.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextvars import ContextVar
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping

from .util import durable_create

SOURCE_TYPE = "qcsd-original-epoch-corpus-reader-source-v1"
AUDIT_TYPE = "qcsd-read-only-original-epoch-corpus-audit-v1"
CORPUS_TYPE = "qcsd-complete-fifty-site-five-setting-sixty-four-slot-epoch-corpus-v1"
CONTRACT = "original-validators-source-labels-and-exact-16000-logical-slots-v1"
PARTIAL_AUDIT_TYPE = "qcsd-read-only-original-epoch-corpus-with-verified-partial-traces-audit-v1"
PARTIAL_CORPUS_TYPE = "qcsd-complete-fifty-site-five-setting-sixty-four-slot-partial-epoch-corpus-v1"
PARTIAL_CONTRACT = "original-accepted-deep-verified-individual-slots-incomplete-aggregates-preserved-v1"
MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
TARGET = 16000
# The declared study retains these already accepted traces. A future study
# needs its own prospective contract; this reader cannot reset this anchor.
RETAINED_PROGRESS_SHA256 = "eb409d9f05347840804bcb0a26882e1a8825f4c7ff8909536b88a6f8321dbc48"
SHA = re.compile(r"[0-9a-f]{64}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
_PARTIAL_OBSERVATIONS = ContextVar("qcsd_partial_corpus_observations", default=None)


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _path(value: str | Path, *, directory=False) -> Path:
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts or any(c in str(path) for c in "\0\r\n")
            or any(p.is_symlink() for p in (path, *path.parents))):
        raise ValueError("epoch reader needs original absolute nonlinked paths")
    mode = path.lstat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise ValueError("epoch reader input has an unsupported file type")
    return path


def reference(path: Path) -> dict[str, Any]:
    path = _path(path)
    before = path.lstat()
    raw = path.read_bytes()
    after = path.lstat()
    fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if fields(before) != fields(after):
        raise ValueError("epoch reader input changed while observed")
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "mode": stat.S_IMODE(before.st_mode)}


def _directory(path: Path) -> dict:
    path = _path(path, directory=True)
    return {"path": str(path), "mode": stat.S_IMODE(path.stat().st_mode),
            "members": {child.name: {"kind": stat.S_IFMT(child.lstat().st_mode), "mode": stat.S_IMODE(child.lstat().st_mode)}
                        for child in sorted(path.iterdir())}}


def _sync_directory(path: Path) -> None:
    descriptor = os.open(_path(path, directory=True), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def reopen(value: Mapping[str, Any]) -> Path:
    if (not isinstance(value, dict) or set(value) not in ({"path", "sha256"}, {"path", "sha256", "mode"})
            or not isinstance(value.get("sha256"), str) or SHA.fullmatch(value["sha256"]) is None
            or "mode" in value and (type(value["mode"]) is not int or not 0 <= value["mode"] <= 0o7777)):
        raise ValueError("epoch reader reference schema differs")
    path = _path(value["path"])
    actual = reference(path)
    if any(actual[key] != item for key, item in value.items()):
        raise ValueError("epoch reader reference bytes or mode changed")
    return path


def _document(value: Mapping[str, Any], kind: str) -> dict:
    data = json.loads(reopen(value).read_bytes())
    if (not isinstance(data, dict) or set(data) != {"schema_version", "artifact_type", "payload", "payload_sha256"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["artifact_type"] != kind
            or data["payload_sha256"] != hashlib.sha256(_json(data["payload"])).hexdigest()):
        raise ValueError("epoch reader artifact schema or payload digest differs")
    return data["payload"]


def _write(path: Path, kind: str, payload: dict) -> dict:
    path = path.absolute()
    if (".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)) or path.exists()
            or any(c in str(path) for c in "\0\r\n")):
        raise ValueError("epoch reader output must be create-only and nonlinked")
    _path(path.parent, directory=True)
    durable_create(path, _json({"schema_version": 1, "artifact_type": kind, "payload": payload,
                               "payload_sha256": hashlib.sha256(_json(payload)).hexdigest()}))
    return reference(path)


def _git(root: Path, *args: str, input=None) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], input=input, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}).stdout


def source_snapshot(root: Path, lab_head: str, native_head: str) -> dict:
    """Authenticate complete tracked membership against immutable Git blobs."""
    root = _path(root, directory=True)
    if not isinstance(lab_head, str) or HEAD.fullmatch(lab_head) is None or not isinstance(native_head, str) or HEAD.fullmatch(native_head) is None:
        raise ValueError("epoch Source needs exact Lab and Native Git heads")
    files = {}
    for checkout, prefix, expected in [(root, "", lab_head), (root / "neqo-qcsd", "neqo-qcsd/", native_head)]:
        _path(checkout, directory=True)
        if _git(checkout, "rev-parse", "HEAD").decode().strip() != expected:
            raise ValueError("epoch Source checkout moved from its bound head")
        released = {}
        for entry in _git(checkout, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
            if entry:
                metadata, relative = entry.split(b"\t")
                mode, kind, blob = metadata.decode().split()
                released[relative.decode()] = (mode, blob)
        indexed = {}
        rows = []
        for entry in _git(checkout, "ls-files", "-s", "-z").split(b"\0"):
            if not entry:
                continue
            metadata, relative = entry.split(b"\t")
            mode, blob, stage = metadata.decode().split()
            name = relative.decode()
            indexed[name] = (mode, blob)
            if stage != "0" or ".." in Path(name).parts or Path(name).is_absolute():
                raise ValueError("epoch Source has conflicted or unsafe membership")
            if mode == "160000":
                if prefix or name != "neqo-qcsd" or blob != native_head:
                    raise ValueError("epoch Source changed its Native Gitlink")
                continue
            if mode not in {"100644", "100755"}:
                raise ValueError("epoch Source contains a linked or unsupported member")
            # HEAD membership, not a modified index, is the release authority.
            if released.get(name) != (mode, blob):
                raise ValueError("epoch Source index changed from its release")
            rows.append((name, mode, blob))
        if indexed != released:
            raise ValueError("epoch Source inventory omitted or added a release member")
        raw = _git(checkout, "cat-file", "--batch", input="".join(blob + "\n" for _, _, blob in rows).encode())
        offset = 0
        for name, mode, blob in rows:
            end = raw.index(b"\n", offset)
            actual, kind, length = raw[offset:end].decode().split()
            offset = end + 1
            body = raw[offset:offset + int(length)]
            offset += int(length) + 1
            observed = reference(checkout / name)
            if (actual != blob or kind != "blob" or observed["sha256"] != hashlib.sha256(body).hexdigest()
                    or observed["mode"] != int(mode[-3:], 8)):
                raise ValueError("epoch Source bytes or mode differ from their release")
            files[prefix + name] = {**observed, "git_blob_sha1": blob}
        if offset != len(raw):
            raise ValueError("epoch Source Git inventory has trailing data")
    if not files or not any(name.startswith("neqo-qcsd/") for name in files):
        raise ValueError("epoch Source requires the complete paired Native checkout")
    for directory in (root / "src", root / "tools"):
        if directory.exists():
            for path in directory.rglob("*.py"):
                if "__pycache__" not in path.parts and str(path.relative_to(root)) not in files:
                    raise ValueError("epoch Source acquired an unbound importable member")
    return {"root": str(root), "lab_head": lab_head, "native_head": native_head, "files": files}


def bind_source(root: Path, lab_head: str, native_head: str, output: Path) -> dict:
    value = source_snapshot(root, lab_head, native_head)
    if source_snapshot(root, lab_head, native_head) != value:
        raise ValueError("epoch Source changed before binding")
    return _write(output, SOURCE_TYPE, {**value, "scientific_credit": False})


def _source(ref: Mapping[str, Any]) -> dict:
    value = _document(ref, SOURCE_TYPE)
    if set(value) != {"root", "lab_head", "native_head", "files", "scientific_credit"} or value["scientific_credit"] is not False:
        raise ValueError("epoch Source binding has an unknown role")
    current = source_snapshot(Path(value["root"]), value["lab_head"], value["native_head"])
    if any(value[key] != item for key, item in current.items()):
        raise ValueError("epoch Source release inventory changed")
    return value


# The observer fences actual reads without changing any historical predicate.
# This child never invokes a Docker/Native actuator or changes a receipt.
_PROGRAM = r'''
import hashlib,json,os,stat,sys
from pathlib import Path
request=json.load(sys.stdin)
root=Path(request['source_root'])
sys.pycache_prefix=os.path.join(os.devnull,'qcsd-read-only-epoch-corpus')
sys.path.insert(0,str(root/'src'))
watched={}; directories={}; observing=False
def record(path):
    global observing
    if observing: return
    observing=True
    try:
        path=Path(path).absolute()
        if any(path.is_relative_to(Path(p)) for p in [sys.prefix,sys.base_prefix,'/proc','/sys','/dev']): return
        if any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('epoch validator read linked evidence')
        before=path.lstat()
        if not stat.S_ISREG(before.st_mode): return
        raw=path.read_bytes(); after=path.lstat()
        fields=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        if fields(before)!=fields(after): raise ValueError('epoch validator read changed evidence')
        value={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(before.st_mode)}
        if str(path) in watched and watched[str(path)]!=value: raise ValueError('epoch validator dependency changed')
        watched[str(path)]=value
    finally: observing=False
def record_directory(path):
    global observing
    if observing: return
    observing=True
    try:
        path=Path(path).absolute()
        if any(path.is_relative_to(Path(p)) for p in [sys.prefix,sys.base_prefix,'/proc','/sys','/dev']): return
        if any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('epoch validator listed linked evidence')
        if not path.is_dir(): return
        value={'path':str(path),'mode':stat.S_IMODE(path.stat().st_mode),'members':{p.name:{'kind':stat.S_IFMT(p.lstat().st_mode),'mode':stat.S_IMODE(p.lstat().st_mode)} for p in sorted(path.iterdir())}}
        if str(path) in directories and directories[str(path)]!=value: raise ValueError('epoch validator directory membership changed')
        directories[str(path)]=value
    finally: observing=False
def hook(event,args):
    if event=='open' and not observing:
        path,mode,flags=args
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND): raise ValueError('epoch validator attempted a write')
        if isinstance(path,(str,bytes)): record(os.fsdecode(path))
    elif event in {'os.listdir','os.scandir'} and not observing:
        if isinstance(args[0],(str,bytes)): record_directory(os.fsdecode(args[0]))
    elif event=='subprocess.Popen':
        executable,argv,*rest=args
        if Path(executable).name!='git': raise ValueError('epoch validator attempted an actuator subprocess')
        command=list(argv)[1:]
        if command[:1]==['-C']: command=command[2:]
        if (not command or command[0] not in {'rev-parse','status','diff','ls-files','show','cat-file'} or any(arg.startswith(('--output','--ext-diff','--textconv','--filters')) for arg in command)): raise ValueError('epoch validator attempted a non-read-only subprocess')
    elif event in {'os.remove','os.rename','os.mkdir','os.rmdir','os.chmod','os.chown','os.symlink','os.link'}:
        raise ValueError('epoch validator attempted a filesystem mutation')
    elif event in {'os.system','os.exec','os.posix_spawn','socket.connect','socket.connect_ex','socket.bind'}:
        raise ValueError('epoch validator attempted a network or actuator effect')
sys.addaudithook(hook)
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_lane_evidence as lanes
try:
    from qcsd_lab.rapid_operation_facts import OperationFacts
except ImportError:
    from contextlib import nullcontext
    facts=None; scope=nullcontext()
else:
    facts=OperationFacts(); facts.begin_action(); scope=facts.scope()
def graph_identity(path):
    value=json.loads(Path(path).read_bytes())
    preparation=value['preparation']
    rows=value['resources']
    # Encoding does not reorder, collapse repeated requests or project headers.
    return hashlib.sha256(json.dumps({'resources':rows,'primary_resource_id':value.get('primary_resource_id',preparation.get('primary_resource_id')),'final_url':preparation['final_url'],'approved_origins':preparation.get('approved_origins')},sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def original_reference(ref):
    # Authenticate the complete mode-bearing object before the unchanged
    # original API receives its historical two-field reference shape.
    if isinstance(ref,dict) and set(ref)=={'path','sha256','mode'}:
        if (not isinstance(ref['path'],str) or not Path(ref['path']).is_absolute()
            or '..' in Path(ref['path']).parts or type(ref['mode']) is not int or not 0<=ref['mode']<=0o7777):
            raise ValueError('epoch original reference mode or path schema differs')
        record(ref['path'])
        if watched.get(ref['path'])!=ref:
            raise ValueError('epoch original reference bytes or mode changed')
        return rolling._open_ref({key:ref[key] for key in ('path','sha256')})
    return rolling._open_ref(ref)
def class_rows(path):
    batch,classes,policy=rolling._verify_enrollment(Path(path))
    result=[]
    for row in classes:
        if 'prepared_workload' in row:
            original=original_reference(row['prepared_workload'])
        else:
            # An additive seed keeps its original static row shape. Resolve
            # its already authenticated direct input, including through a
            # per-class policy's immutable seed-policy chain.
            original_policy=policy; seen=set()
            while True:
                inputs=original_policy.get('seed_inputs',{})
                if row['candidate_id'] in inputs:
                    from qcsd_lab import rapid_additive_static_enrollment as additive
                    from qcsd_lab import rapid_selected_capture_input as selected
                    data,_=additive.input_metadata(inputs[row['candidate_id']])
                    if (data['candidate_id']!=row['candidate_id'] or data['workload_id']!=row['workload_id']
                            or data['canonical_sites']!=row['canonical_sites']):
                        raise ValueError('epoch membership replaced a retained selected seed')
                    original=selected.reopen(data['original_manifest'])
                    break
                if 'seed_policy' not in original_policy:
                    context=rolling._context_for_policy(original_policy,Path(row['admission_root']))
                    original,_=rolling._prepared_workload(context,original_reference(row['terminal']))
                    break
                seed=original_reference(original_policy['seed_policy'])
                if str(seed) in seen: raise ValueError('epoch membership has cyclic seed policy ancestry')
                seen.add(str(seed))
                raw=seed.read_bytes(); envelope=json.loads(raw)
                original_policy=rolling.admission._unpack(raw,envelope['receipt_type'])
        result.append({**row,'capture_limits':row.get('capture_limits',policy['capture_limits']),'original_graph_sha256':graph_identity(original)})
    return result
with scope:
    membership=class_rows(request['enrollment']) if request.get('enrollment') else None
    result=[]
    for ref in request['closures']:
        # The original API accepts its original two-key hash reference. The
        # parent has already reopened the optional mode-bearing wrapper and
        # retains that exact reference in the new audit.
        spec,receipt,facts_value,lane,sites=rolling._reopen_lane_check({key:ref[key] for key in ('path','sha256')})
        if str(spec.module_root)!=str(root): raise ValueError('epoch validator module Source moved')
        if lane.role!='formal' or lane.study_version!=6: raise ValueError('epoch validator promoted a diagnostic')
        classes=class_rows(spec.cohort)
        by_workload={row['workload_id']:row for row in classes}
        if getattr(lane,'lane_layout',None) is None:
            if lane.visits_per_workload!=4 or not 1<=lane.block<=16: raise ValueError('legacy slot count changed')
            slots=list(range((lane.block-1)*4,lane.block*4)); layout='original-four-visit-block-v6'
        else:
            from qcsd_lab import rapid_slot_chunks as chunks
            if not isinstance(lane,chunks.ChunkLane): raise ValueError('unknown explicit slot layout')
            from dataclasses import asdict
            chunks.checked_lane(asdict(lane))
            slots=list(range(lane.slot_start,lane.slot_start+lane.visits_per_workload)); layout=chunks.LAYOUT
        value=json.loads(Path(ref['path']).read_bytes())['payload']
        experiment_path=Path(facts_value['result_root'])/'experiment.json'
        experiment=json.loads(experiment_path.read_bytes())
        samples=experiment['samples']
        expected={(workload,lane.mode,visit) for workload in lane.workload_ids for visit in range(lane.visits_per_workload)}
        actual={(item['workload_id'],item['defense'],item['visit']) for item in samples}
        if (experiment['status']!='complete' or experiment['name']!=lane.campaign_name or len(samples)!=lane.sample_count or actual!=expected or any(item['state']!='accepted' or type(item['visit']) is not int for item in samples)):
            raise ValueError('epoch validator lost exact complete local sample mapping')
        site_ids={site.workload_id:site.candidate_id for site in sites}
        identities=[]
        for sample in samples:
            row=by_workload[sample['workload_id']]
            if site_ids[sample['workload_id']]!=row['candidate_id']: raise ValueError('epoch lane changed candidate membership')
            identities.append({'candidate_id':row['candidate_id'],'class_index':row['class_index'],'workload_id':row['workload_id'],'original_graph_sha256':row['original_graph_sha256'],'mode':lane.mode,'visit':slots[sample['visit']],'actual_local_visit':sample['visit'],'sample_id':sample['id'] if 'id' in sample else sample['sample_id']})
        intent_path=Path(receipt).parent/'intent.json'
        intent=json.loads(intent_path.read_bytes())['payload']
        lineage=lanes._payload(rolling.admission._child(Path(value['root']),intent['lineage']),lanes.LINEAGE_TYPE)
        proof=lineage['image_check']['proof']
        result.append({'closure':ref,'receipt':rolling._ref(receipt),'spec':spec.serializable(),'facts':facts_value,'logical_lane':lane.logical_name,'campaign_name':lane.campaign_name,'mode':lane.mode,'workload_ids':list(lane.workload_ids),'layout':layout,'logical_slots':slots,'samples':identities,'measurement_source':proof['runtime_source'],'overlay_source_hashes':proof['overlay_source_hashes'],'runtime_source_root':str(spec.runtime_source_root),'source_manifest':rolling._ref(spec.source_manifest),'client_binary':rolling._ref(spec.client_binary),'profile':rolling._ref(spec.execution_root/lanes.STUDY_PROFILE_FILE),'campaign':rolling._ref(Path(facts_value['result_root'])/'inputs'/'campaign.yml'),'configuration':experiment['configuration'],'enrollment':rolling._ref(spec.cohort)})
    if facts is not None: facts.check()
for path,previous in list(watched.items()):
    record(path)
    if watched[path]!=previous: raise ValueError('epoch validator closing fence changed')
for path,previous in list(directories.items()):
    record_directory(path)
    if directories[path]!=previous: raise ValueError('epoch validator closing membership fence changed')
print(json.dumps({'membership':membership,'lanes':result,'read_dependencies':list(watched.values()),'directory_dependencies':list(directories.values()),'read_only':True},sort_keys=True,allow_nan=False))
'''


def _run_epoch(source: dict, enrollment: Path | None, closures: list[dict], directory: Path) -> dict:
    request = {"source_root": source["root"], "enrollment": None if enrollment is None else str(enrollment), "closures": closures}
    command = [sys.executable, "-I", "-B", "-c", _PROGRAM]
    directory.mkdir(mode=0o700)
    _sync_directory(directory.parent)
    started = {"command": command, "request": request, "started_at": datetime.now(timezone.utc).isoformat()}
    durable_create(directory / "started.json", _json(started))
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("QCSD_", "GIT_CONFIG_")) and key not in {"PYTHONPATH", "PYTHONSTARTUP", "GIT_EXTERNAL_DIFF"}}
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        process = subprocess.run(command, input=_json(request), stdout=stdout, stderr=stderr, env=environment, cwd=source["root"])
        for stream in (stdout, stderr):
            stream.flush(); os.fsync(stream.fileno())
    completed = {**started, "completed_at": datetime.now(timezone.utc).isoformat(), "returncode": process.returncode,
                 "stdout": reference(directory / "stdout.log"), "stderr": reference(directory / "stderr.log")}
    durable_create(directory / "completed.json", _json(completed))
    if process.returncode != 0:
        raise ValueError("original epoch reader failed; raw operation is retained")
    report = json.loads((directory / "stdout.log").read_bytes())
    if set(report) != {"membership", "lanes", "read_dependencies", "directory_dependencies", "read_only"} or report["read_only"] is not True:
        raise ValueError("original epoch reader returned an unknown role")
    for value in report["read_dependencies"]:
        reopen(value)
    for value in report["directory_dependencies"]:
        if _directory(Path(value["path"])) != value:
            raise ValueError("original epoch reader's complete directory membership changed")
    return {"report": report, "started": reference(directory / "started.json"), "completed": reference(directory / "completed.json")}


def _classes(rows: list[dict], *, final: bool) -> dict[str, dict]:
    if not isinstance(rows, list) or not 1 <= len(rows) <= 50 or final and len(rows) != 50:
        raise ValueError("final corpus requires exactly fifty authenticated classes")
    seen_sites, result, workloads = set(), {}, set()
    for index, row in enumerate(rows, 1):
        aliases = row.get("canonical_sites")
        if aliases is None:
            from urllib.parse import urlsplit
            host = urlsplit(row["primary_origin"]).hostname
            aliases = [host]
        from .rapid_additive_static_enrollment import _canonical_host
        aliases = [_canonical_host(item) for item in aliases]
        if (type(row["class_index"]) is not int or row["class_index"] != index
                or not aliases or len(aliases) != len(set(aliases)) or seen_sites.intersection(aliases)
                or row["candidate_id"] in result or row["workload_id"] in workloads
                or SHA.fullmatch(row["original_graph_sha256"]) is None):
            raise ValueError("final corpus renumbers or duplicates an admitted candidate/site/workload")
        result[row["candidate_id"]] = row
        seen_sites.update(aliases); workloads.add(row["workload_id"])
    return result


def coverage(classes: list[dict], lane_reports: list[dict], *, require_complete=True) -> dict:
    known = _classes(classes, final=require_complete)
    expected = {(row["class_index"], mode, visit) for row in classes for mode in MODES for visit in range(64)}
    observed, samples, lane_ids, totals = set(), set(), set(), 0
    for row in lane_reports:
        lane_key = (row["spec"]["data_root"], row["logical_lane"])
        if (lane_key in lane_ids or row["facts"].get("scientific_credit") is not True
                or type(row["facts"].get("host_returncode")) is not int or row["facts"]["host_returncode"] != 0):
            raise ValueError("final corpus repeats a lane or promotes an unclosed/failed lane")
        lane_ids.add(lane_key)
        local_slots = row["logical_slots"]
        if (not local_slots or any(type(value) is not int or not 0 <= value < 64 for value in local_slots)
                or local_slots != list(range(local_slots[0], local_slots[0] + len(local_slots)))
                or row["layout"] not in {"original-four-visit-block-v6", "explicit-logical-offset-bounded-sixteen-visit-chunks-v1"}
                or row["layout"] == "original-four-visit-block-v6" and (len(local_slots) != 4 or local_slots[0] % 4)
                or row["layout"] != "original-four-visit-block-v6" and not 1 <= len(local_slots) <= 16):
            raise ValueError("final corpus changed registered logical slot offsets")
        ids = row["workload_ids"]
        if (row["mode"] not in MODES or not 1 <= len(ids) <= 5 or len(ids) != len(set(ids))
                or len(row["samples"]) != len(ids) * len(local_slots)
                or {(item["workload_id"], item["mode"], item["actual_local_visit"]) for item in row["samples"]}
                    != {(workload, row["mode"], local) for workload in ids for local in range(len(local_slots))}):
            raise ValueError("final corpus changed its complete workload/setting/local-visit group")
        for sample in row["samples"]:
            original = known.get(sample["candidate_id"])
            local = sample["actual_local_visit"]
            if (original is None or type(sample["class_index"]) is not int or sample["class_index"] != original["class_index"]
                    or sample["workload_id"] != original["workload_id"] or sample["original_graph_sha256"] != original["original_graph_sha256"]
                    or type(local) is not int or not 0 <= local < len(local_slots) or sample["visit"] != local_slots[local]
                    or type(sample["visit"]) is not int or sample["mode"] not in MODES):
                raise ValueError("final corpus moved a sample or replaced its admitted full graph")
            if any(row["configuration"]["limits"][key] != original["capture_limits"][key]
                   for key in ("max_response_bytes", "capture_megabytes")):
                raise ValueError("final corpus changed a class's declared response/recording budgets")
            slot = sample["class_index"], sample["mode"], sample["visit"]
            sample_key = row["facts"]["result_root"], sample["sample_id"]
            if slot not in expected or slot in observed or sample_key in samples:
                raise ValueError("final corpus duplicates or invents a logical/sample slot across epochs")
            observed.add(slot); samples.add(sample_key)
        if type(row["facts"]["accepted"]) is not int or row["facts"]["accepted"] != len(row["samples"]):
            raise ValueError("final corpus changed an original accepted count")
        totals += row["facts"]["accepted"]
    complete = observed == expected and len(classes) == 50 and totals == TARGET
    if require_complete and not complete:
        raise ValueError("final corpus has holes; exactly fifty by five by sixty-four is required")
    return {"accepted": totals, "complete": complete, "missing_slots": len(expected - observed),
            "class_count": len(classes), "lane_count": len(lane_reports), "scientific_credit": complete}


def partial_coverage(classes: list[dict], lane_reports: list[dict], partial_rows: list[dict],
                     *, require_complete=True) -> dict:
    """Combine individual proof rows without converting failed lanes to passes.

    Public audit/publication accepts these rows only through the authenticated
    partial-progress validator. This reducer grants no standalone receipt.
    """
    known = _classes(classes, final=require_complete)
    original = coverage(classes, lane_reports, require_complete=False)
    expected = {(row["class_index"], mode, visit) for row in classes for mode in MODES for visit in range(64)}
    observed = {(sample["class_index"], sample["mode"], sample["visit"])
                for lane in lane_reports for sample in lane["samples"]}
    samples = {(lane["facts"]["result_root"], sample["sample_id"])
               for lane in lane_reports for sample in lane["samples"]}
    complete_results = {lane["facts"]["result_root"] for lane in lane_reports}
    partial_results = set()
    for row in partial_rows:
        cls = known.get(row.get("candidate_id"))
        block, local, logical = (row.get(key) for key in ("registered_block", "actual_local_visit", "logical_visit"))
        if (cls is None or type(row.get("class_index")) is not int or row["class_index"] != cls["class_index"]
                or row.get("workload_id") != cls["workload_id"]
                or row.get("original_graph_sha256") != cls["original_graph_sha256"]
                or row.get("mode") not in MODES
                or type(block) is not int or not 1 <= block <= 16
                or type(local) is not int or not 0 <= local < 4
                or type(logical) is not int or logical != (block - 1) * 4 + local
                or row.get("original_state") != "accepted"
                or row.get("individual_trace_authority") != "original-collector-accepted-and-original-deep-verified-v1"
                or row.get("aggregate_status") != "incomplete" or row.get("lane_pass_claim") is not False
                or type(row.get("aggregate_formal_credit")) is not int or row["aggregate_formal_credit"] != 0
                or type(row.get("host_returncode")) is not int or row["host_returncode"] != 1):
            raise ValueError("partial corpus changes original accepted trace or incomplete aggregate authority")
        caps = row.get("capture_limits")
        if (not isinstance(caps, dict) or any(type(caps.get(key)) is not int or caps[key] != cls["capture_limits"][key]
                for key in ("max_response_bytes", "capture_megabytes"))):
            raise ValueError("partial corpus changes a class's declared response/recording budgets")
        result, sample_id = row.get("result_root"), row.get("sample_id")
        artifacts, receipt = row.get("artifacts"), row.get("partial_receipt")
        if (not isinstance(result, str) or not Path(result).is_absolute()
                or not isinstance(sample_id, str) or not sample_id
                or not isinstance(artifacts, dict) or not artifacts
                or not isinstance(receipt, dict) or set(receipt) not in ({"path", "sha256"}, {"path", "sha256", "mode"})
                or not isinstance(receipt.get("path"), str) or not Path(receipt["path"]).is_absolute()
                or not isinstance(receipt.get("sha256"), str) or SHA.fullmatch(receipt["sha256"]) is None
                or result in complete_results):
            raise ValueError("partial corpus lost original raw artifacts or mixes incomplete and complete lane labels")
        slot = row["class_index"], row["mode"], logical
        sample_key = result, sample_id
        if slot not in expected or slot in observed or sample_key in samples:
            raise ValueError("partial corpus duplicates or invents a logical/sample slot across epochs")
        observed.add(slot); samples.add(sample_key); partial_results.add(result)
    total = original["accepted"] + len(partial_rows)
    complete = len(classes) == 50 and observed == expected and total == TARGET
    if require_complete and not complete:
        raise ValueError("partial corpus has holes; exactly fifty by five by sixty-four is required")
    return {"accepted": total, "complete": complete, "missing_slots": len(expected - observed),
            "class_count": len(classes), "complete_lane_count": len(lane_reports),
            "incomplete_lane_count": len(partial_results), "accepted_individual_partial_traces": len(partial_rows),
            "scientific_credit": complete, "incomplete_aggregate_labels_preserved": True}


def _prior(progress_refs: list[dict], reports: list[dict], classes: list[dict]) -> list[dict]:
    """Keep genuine previously accepted lanes/slots, without awarding new credit."""
    if not progress_refs:
        raise ValueError("final epoch audit must retain the genuine prior accepted-slot progress")
    known = _classes(classes, final=False)
    by_closure = {(row["closure"]["path"], row["closure"]["sha256"]): row for row in reports}
    dependencies = []
    for ref in progress_refs:
        path = reopen(ref)
        value = json.loads(path.read_bytes())
        closed_at = datetime.fromisoformat(value["closed_at"])
        if (value.get("artifact_type") not in {"root-reopened-rolling-static-scientific-progress", "root-reopened-remaining-slot-chunk-scientific-progress-v1"}
                or value.get("actual_installed_deep_reopened") is not True
                or value.get("measurement_epochs_preserve_original_source_and_runtime_labels") is not True
                or type(value.get("final_target")) is not int or value["final_target"] != TARGET
                or type(value.get("formal_accepted_trace_count")) is not int or not 1 <= value["formal_accepted_trace_count"] <= TARGET
                or not isinstance(value.get("lanes"), list) or not value["lanes"]
                or closed_at.tzinfo is None or closed_at.utcoffset().total_seconds() != 0 or closed_at > datetime.now(timezone.utc)):
            raise ValueError("prior corpus progress lost its genuine installed deep role")
        declared, declared_rows, derived, lane_refs, accepted = set(), {}, set(), set(), 0
        for sample in value["accepted_formal_slots"]:
            basic = {"candidate_id", "class_index", "mode", "visit"}
            block = {"actual_local_visit", "registered_block", "campaign_name"}
            key = (sample["class_index"], sample["mode"], sample["visit"])
            if (set(sample) not in (basic, basic | block) or type(sample["class_index"]) is not int or type(sample["visit"]) is not int
                    or not 0 <= sample["visit"] < 64 or sample["mode"] not in MODES
                    or known.get(sample["candidate_id"], {}).get("class_index") != sample["class_index"] or key in declared):
                raise ValueError("prior corpus progress moved or duplicated an accepted slot")
            if block <= set(sample) and (type(sample["registered_block"]) is not int or not 1 <= sample["registered_block"] <= 16
                    or type(sample["actual_local_visit"]) is not int or not 0 <= sample["actual_local_visit"] < 4
                    or sample["visit"] != (sample["registered_block"] - 1) * 4 + sample["actual_local_visit"]):
                raise ValueError("prior corpus progress confused registered and raw local slots")
            declared.add(key)
            declared_rows[key] = sample
        for lane in value["lanes"]:
            if set(lane) != {"accepted", "complete_reference", "lane_closure_reference"}:
                raise ValueError("prior corpus progress changed a physical lane reference")
            closure = lane["lane_closure_reference"]
            key = closure["path"], closure["sha256"]
            report = by_closure.get(key)
            if (report is None or key in lane_refs or type(lane["accepted"]) is not int
                    or lane["accepted"] != report["facts"]["accepted"]
                    or any(report["receipt"][field] != lane["complete_reference"][field] for field in ("path", "sha256"))
                    or datetime.fromisoformat(report["facts"]["completed_at"]) > closed_at):
                raise ValueError("final corpus omitted or replaced a genuinely accepted prior lane")
            lane_refs.add(key); accepted += lane["accepted"]
            for sample in report["samples"]:
                slot = sample["class_index"], sample["mode"], sample["visit"]
                if slot in derived:
                    raise ValueError("prior corpus progress repeats a physical logical slot")
                derived.add(slot)
                declared_row = declared_rows.get(slot)
                if declared_row is not None and "campaign_name" in declared_row and declared_row["campaign_name"] != report["campaign_name"]:
                    raise ValueError("prior corpus progress changed its registered campaign")
            dependencies.extend([reference(reopen(closure)), reference(reopen(lane["complete_reference"]))])
        if declared != derived or accepted != value["formal_accepted_trace_count"] or len(declared) != accepted:
            raise ValueError("prior corpus counter differs from its original deep-closed lanes")
        dependencies.append(reference(path))
    return dependencies


def audit(final_enrollment: dict, membership_source: dict, epoch_sources: list[dict], closures: list[dict],
          prior_progress: list[dict], output_root: Path) -> dict:
    """Create an engineering audit using unchanged original Source per epoch."""
    if not any(ref.get("sha256") == RETAINED_PROGRESS_SHA256 for ref in prior_progress):
        raise ValueError("epoch audit must retain the exact declared SCI36 progress anchor")
    output_root = output_root.absolute()
    if output_root.exists() or output_root.is_symlink() or any(p.is_symlink() for p in output_root.parents):
        raise ValueError("epoch audit namespace is already claimed or linked")
    _path(output_root.parent, directory=True)
    enrollment = reopen(final_enrollment)
    bindings = [membership_source, *epoch_sources]
    sources = {}
    for ref in bindings:
        value = _source(ref)
        if value["root"] in sources and sources[value["root"]][0] != ref:
            raise ValueError("epoch audit supplied conflicting Source authority")
        sources[value["root"]] = (ref, value)
    membership_root = _source(membership_source)["root"]
    grouped = {name: [] for name in sources}
    if not closures or len({(item["path"], item["sha256"]) for item in closures}) != len(closures):
        raise ValueError("epoch audit requires unique genuine closed lane references")
    for ref in closures:
        value = json.loads(reopen(ref).read_bytes())
        payload = value.get("payload", {})
        source_root = payload.get("spec", {}).get("module_root")
        if source_root not in sources:
            raise ValueError("epoch audit lacks the original lane module Source")
        grouped[source_root].append(ref)
    output_root.mkdir(mode=0o700)
    _sync_directory(output_root.parent)
    reports, operations, classes = [], [], None
    dependencies = [reference(reopen(value)) for value in [final_enrollment, *bindings, *closures]]
    directory_dependencies = {}
    for index, (name, (ref, source)) in enumerate(sources.items(), 1):
        if not grouped[name] and name != membership_root:
            continue
        result = _run_epoch(source, enrollment if name == membership_root else None, grouped[name], output_root / f"epoch-{index:04d}")
        if name == membership_root:
            classes = result["report"]["membership"]
        reports.extend(result["report"]["lanes"])
        dependencies.extend(result["report"]["read_dependencies"])
        for value in result["report"]["directory_dependencies"]:
            path = value["path"]
            if path in directory_dependencies and directory_dependencies[path] != value:
                raise ValueError("epoch audit raw directory membership changed across Sources")
            directory_dependencies[path] = value
        operations.append({"source": ref, "started": result["started"], "completed": result["completed"]})
        if _source(ref) != source:
            raise ValueError("original epoch Source changed during isolated validation")
    for row in reports:
        runtime = sources.get(row["runtime_source_root"])
        module = sources[row["spec"]["module_root"]][1]
        label = row["measurement_source"]
        if (runtime is None or label.get("lab_dirty") is not False or label.get("neqo_dirty") is not False
                or label.get("lab_commit") != runtime[1]["lab_head"] or label.get("neqo_commit") != runtime[1]["native_head"]
                or label.get("neqo_pinned_commit") != runtime[1]["native_head"]
                or any(module["files"].get(name, {}).get("sha256") != digest for name, digest in row["overlay_source_hashes"].items())):
            raise ValueError("epoch audit changed original release/measurement/overlay Source authority")
    facts = coverage(classes, reports, require_complete=False)
    dependencies.extend(_prior(prior_progress, reports, classes))
    for ref, source in sources.values():
        if _source(ref) != source:
            raise ValueError("original release Source changed before audit publication")
    for value in directory_dependencies.values():
        if _directory(Path(value["path"])) != value:
            raise ValueError("original raw directory membership changed before audit publication")
    unique = {}
    for value in dependencies:
        path = str(reopen(value))
        actual = reference(Path(path))
        if path in unique and unique[path] != actual:
            raise ValueError("epoch audit dependency changed across original Sources")
        unique[path] = actual
    payload = {"contract": CONTRACT, "final_enrollment": final_enrollment, "membership_source": membership_source,
               "epoch_sources": epoch_sources, "closures": closures, "classes": classes, "lanes": reports,
               "prior_progress": prior_progress,
               "operations": operations, "read_dependencies": list(unique.values()), "facts": facts,
               "directory_dependencies": list(directory_dependencies.values()),
               "reader_source": reference(Path(__file__)), "scientific_credit": False,
               "measurement_equivalence_claimed": False, "closed_at": datetime.now(timezone.utc).isoformat()}
    return _write(output_root / "audit.json", AUDIT_TYPE, payload)


def _close_original_dependencies(expected: list[dict], directories: dict[str, dict],
                                 recorded: list[dict], recorded_directories: list[dict]) -> None:
    """Rebuild coverage from original outputs, then reopen every observed byte."""
    by_path = {}
    for ref in expected:
        actual = reference(reopen(ref))
        if actual["path"] in by_path and by_path[actual["path"]] != actual:
            raise ValueError("final epoch audit's original dependency observations differ")
        by_path[actual["path"]] = actual
    if recorded != list(by_path.values()) or recorded_directories != list(directories.values()):
        raise ValueError("final epoch audit omitted or substituted its original raw dependency closure")
    for ref in recorded:
        reopen(ref)
    for ref in recorded_directories:
        if _directory(Path(ref["path"])) != ref:
            raise ValueError("final epoch audit raw directory membership changed before publication")


def _operation_request(started: dict, source_ref: dict, sources: dict, membership_source: dict,
                       final_enrollment: dict) -> dict:
    """Bind a retained interpreter request to its declared original Source."""
    source = sources.get((source_ref["path"], source_ref["sha256"]))
    request = started.get("request")
    if (source is None or set(started) != {"command", "request", "started_at"}
            or not isinstance(request, dict) or set(request) != {"source_root", "enrollment", "closures"}
            or request["source_root"] != source["root"] or not isinstance(request["closures"], list)
            or not request["closures"] and request["enrollment"] is None):
        raise ValueError("final epoch operation substituted its original Source/request")
    expected = final_enrollment["path"] if source_ref == membership_source else None
    if request["enrollment"] != expected:
        raise ValueError("final epoch operation substituted its original membership Source")
    return request


def _reopen_audit(audit_ref: dict, *, require_complete=True) -> tuple[dict, dict]:
    value = _document(audit_ref, AUDIT_TYPE)
    fields = {"contract", "final_enrollment", "membership_source", "epoch_sources", "closures", "prior_progress",
              "classes", "lanes", "operations", "read_dependencies", "directory_dependencies", "facts",
              "reader_source", "scientific_credit", "measurement_equivalence_claimed", "closed_at"}
    if set(value) != fields:
        raise ValueError("final epoch audit has missing or unknown authority fields")
    if not any(ref.get("sha256") == RETAINED_PROGRESS_SHA256 for ref in value["prior_progress"]):
        raise ValueError("final epoch audit omitted the exact declared SCI36 progress anchor")
    if (value.get("contract") != CONTRACT or value.get("scientific_credit") is not False
            or value.get("measurement_equivalence_claimed") is not False or value.get("reader_source") != reference(Path(__file__))):
        raise ValueError("final epoch manifest needs this exact closed read-only audit")
    sources = {}
    for ref in [value["membership_source"], *value["epoch_sources"]]:
        sources[(ref["path"], ref["sha256"])] = _source(ref)
    for ref in value["read_dependencies"]:
        reopen(ref)
    for ref in value["directory_dependencies"]:
        if _directory(Path(ref["path"])) != ref:
            raise ValueError("final epoch audit raw directory membership changed")
    facts = coverage(value["classes"], value["lanes"], require_complete=require_complete)
    # Reopen original operation raw outputs and require exact audit report rows.
    original_lanes, original_classes = [], None
    expected_dependencies = [reference(reopen(ref)) for ref in [value["final_enrollment"], value["membership_source"], *value["epoch_sources"], *value["closures"]]]
    expected_directories = {}
    requests = []
    for operation in value["operations"]:
        if set(operation) != {"source", "started", "completed"}:
            raise ValueError("final epoch operation lost its original bound record fields")
        started = json.loads(reopen(operation["started"]).read_bytes())
        completed = json.loads(reopen(operation["completed"]).read_bytes())
        request = _operation_request(started, operation["source"], sources,
                                     value["membership_source"], value["final_enrollment"])
        if (set(completed) != set(started) | {"completed_at", "returncode", "stdout", "stderr"}
                or type(completed["returncode"]) is not int or completed["returncode"] != 0
                or any(completed[key] != started[key] for key in started) or started["command"] != [sys.executable, "-I", "-B", "-c", _PROGRAM]
                or datetime.fromisoformat(completed["completed_at"]) < datetime.fromisoformat(started["started_at"])):
            raise ValueError("final epoch audit has an unclosed or substituted original validator operation")
        report = json.loads(reopen(completed["stdout"]).read_bytes()); reopen(completed["stderr"])
        if report["read_only"] is not True:
            raise ValueError("final epoch audit changed its read-only role")
        original_lanes.extend(report["lanes"])
        expected_dependencies.extend(report["read_dependencies"])
        for ref in report["directory_dependencies"]:
            if ref["path"] in expected_directories and expected_directories[ref["path"]] != ref:
                raise ValueError("final epoch audit's original directory observations differ")
            expected_directories[ref["path"]] = ref
        if any(row["spec"]["module_root"] != request["source_root"] for row in report["lanes"]):
            raise ValueError("final epoch operation changed the original lane module Source")
        requests.append(request)
        if report["membership"] is not None:
            if original_classes is not None:
                raise ValueError("final epoch audit repeats its membership authority")
            original_classes = report["membership"]
    if original_lanes != value["lanes"] or original_classes != value["classes"]:
        raise ValueError("final epoch audit substituted original read-only output")
    requested = [ref for request in requests for ref in request["closures"]]
    if requested != [row["closure"] for row in original_lanes] or sorted((ref["path"], ref["sha256"]) for ref in requested) != sorted((ref["path"], ref["sha256"]) for ref in value["closures"]):
        raise ValueError("final epoch audit substituted original requested closures")
    expected_dependencies.extend(_prior(value["prior_progress"], original_lanes, original_classes))
    _close_original_dependencies(expected_dependencies, expected_directories,
                                 value["read_dependencies"], value["directory_dependencies"])
    return value, facts


def publish(audit_ref: dict, output: Path) -> dict:
    value, facts = _reopen_audit(audit_ref)
    return _write(output, CORPUS_TYPE, {"contract": CONTRACT, "audit": audit_ref, "classes": value["classes"],
                   "lanes": value["lanes"], **facts, "measurement_equivalence_claimed": False,
                   "closed_at": datetime.now(timezone.utc).isoformat()})


def _partial_owned(function):
    """One fresh or borrowed owner for the new typed route only."""
    @wraps(function)
    def run(*args, **kwargs):
        from .rapid_operation_facts import OperationFacts, current_context
        context = current_context()
        if context is None:
            context = OperationFacts(); context.begin_action()
        token = _PARTIAL_OBSERVATIONS.set({"files": {}, "directories": {}, "context": context})
        try:
            with context.scope():
                _partial_reference(Path(__file__).absolute())
                value = function(*args, **kwargs)
                _partial_close()
                return value
        finally:
            _PARTIAL_OBSERVATIONS.reset(token)
    return run


def _partial_reference(value: Path | dict) -> dict:
    """Observe each dependency once; the owner freshly closes every byte."""
    expected = value if isinstance(value, dict) else None
    if expected is not None:
        if (set(expected) not in ({"path", "sha256"}, {"path", "sha256", "mode"})
                or not isinstance(expected.get("sha256"), str) or SHA.fullmatch(expected["sha256"]) is None
                or "mode" in expected and (type(expected["mode"]) is not int or not 0 <= expected["mode"] <= 0o7777)):
            raise ValueError("partial corpus dependency reference schema differs")
    path = _path(expected["path"] if expected is not None else value)
    state = _PARTIAL_OBSERVATIONS.get()
    if state is None:
        actual = reference(path)
    elif str(path) in state["files"]:
        actual = state["files"][str(path)]
    else:
        before = path.lstat()
        raw = state["context"].watch_file(path)
        after = path.lstat()
        fields = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if fields(before) != fields(after):
            raise ValueError("partial corpus dependency changed while observed")
        actual = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "mode": stat.S_IMODE(before.st_mode)}
        state["files"][str(path)] = actual
    if expected is not None and any(actual[key] != item for key, item in expected.items()):
        raise ValueError("partial corpus dependency bytes or mode changed")
    return dict(actual)


def _partial_directory(value: dict) -> dict:
    path = _path(value["path"], directory=True)
    state = _PARTIAL_OBSERVATIONS.get()
    current = None if state is None else state["directories"].get(str(path))
    if current is None:
        current = _directory(path)
        if state is not None:
            state["directories"][str(path)] = current
    if current != value:
        raise ValueError("partial corpus changed original raw directory membership")
    return current


def _partial_close() -> None:
    from . import rapid_partial_progress as progress
    state = _PARTIAL_OBSERVATIONS.get()
    if state is None:
        raise ValueError("partial corpus publication lacks its owning operation")
    for value in state["directories"].values():
        if _directory(Path(value["path"])) != value:
            raise ValueError("partial corpus raw directory membership changed before publication")
    progress.close_operation(state["context"])


def _partial_inputs(progress_refs: list[dict]) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Use the explicit typed join; no current reader reinterprets an old lane."""
    from . import rapid_partial_progress as progress
    from . import rapid_partial_lane as partial
    if (not progress_refs or len({(ref["path"], ref["sha256"]) for ref in progress_refs}) != len(progress_refs)):
        raise ValueError("partial corpus requires unique typed partial-progress references")
    state = _PARTIAL_OBSERVATIONS.get()
    if state is None:
        raise ValueError("partial corpus inputs require an owning operation")
    executing = [_partial_reference(Path(progress.__file__).absolute()), _partial_reference(Path(partial.__file__).absolute())]
    rows, values, files, directories = [], [], list(executing), {}
    receipts = {}
    for ref in progress_refs:
        files.append(_partial_reference(ref))
        value, dependencies = progress.read_inputs(ref)
        accepted = value.get("individual_slots") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or not isinstance(accepted, list) or not accepted
                or any(not isinstance(row, dict) for row in accepted)
                or not isinstance(dependencies, set) or any(not isinstance(path, Path) for path in dependencies)):
            raise ValueError("partial corpus received another typed progress API")
        values.append(value)
        for row in accepted:
            receipt = row.get("partial_receipt")
            if not isinstance(receipt, dict):
                raise ValueError("partial corpus omitted an original partial receipt")
            actual = _partial_reference(receipt)
            if actual["path"] in receipts and receipts[actual["path"]] != actual:
                raise ValueError("partial corpus replaced a partial receipt across joins")
            receipts[actual["path"]] = actual
        rows.extend(accepted)
        observed = progress.observed_inputs(dependencies, state["context"])
        if {item["path"] for item in observed} != {str(path) for path in dependencies}:
            raise ValueError("partial corpus omitted an authenticated input observation")
        for item in observed:
            path = str(_path(item["path"]))
            if path in state["files"] and state["files"][path] != item:
                raise ValueError("partial corpus changed an authenticated dependency observation")
            state["files"][path] = dict(item)
        files.extend(observed)
        for item in value["directory_dependencies"]:
            if item["path"] in directories and directories[item["path"]] != item:
                raise ValueError("partial corpus changed original raw directory observations")
            directories[item["path"]] = _partial_directory(item)
    files.extend(receipts.values())
    unique = {}
    for ref in files:
        actual = _partial_reference(ref)
        if actual["path"] in unique and unique[actual["path"]] != actual:
            raise ValueError("partial corpus changed a recorded read dependency")
        unique[actual["path"]] = actual
    return rows, values, list(unique.values()), list(directories.values())


def _combined_dependencies(base: dict, base_ref: dict, files: list[dict], directories: list[dict]) -> tuple[list[dict], list[dict]]:
    unique, members = {}, {}
    for ref in [base_ref, *base["read_dependencies"], *files]:
        actual = _partial_reference(ref)
        if actual["path"] in unique and unique[actual["path"]] != actual:
            raise ValueError("partial corpus changed raw bytes or modes across proof epochs")
        unique[actual["path"]] = actual
    for ref in [*base["directory_dependencies"], *directories]:
        if ref["path"] in members and members[ref["path"]] != ref:
            raise ValueError("partial corpus changed original raw membership across proof epochs")
        members[ref["path"]] = _partial_directory(ref)
    return list(unique.values()), list(members.values())


@_partial_owned
def audit_with_partials(final_enrollment: dict, membership_source: dict, epoch_sources: list[dict],
                        closures: list[dict], prior_progress: list[dict], partial_progress: list[dict],
                        output_root: Path) -> dict:
    """Keep SCI36/original complete lanes and genuine partial proofs separate."""
    if not partial_progress:
        raise ValueError("partial corpus audit needs an explicit partial-progress authority")
    if not any(ref.get("sha256") == RETAINED_PROGRESS_SHA256 for ref in prior_progress):
        raise ValueError("partial corpus audit must retain the exact declared SCI36 progress anchor")
    reader = reference(Path(__file__).absolute())
    root = output_root.absolute()
    if root.exists() or root.is_symlink() or any(p.is_symlink() for p in root.parents):
        raise ValueError("partial corpus audit namespace is already claimed or linked")
    _path(root.parent, directory=True)
    root.mkdir(mode=0o700); _sync_directory(root.parent)
    base_ref = audit(final_enrollment, membership_source, epoch_sources, closures, prior_progress, root / "complete-lanes")
    base, _ = _reopen_audit(base_ref, require_complete=False)
    rows, values, files, directories = _partial_inputs(partial_progress)
    facts = partial_coverage(base["classes"], base["lanes"], rows, require_complete=False)
    files, directories = _combined_dependencies(base, base_ref, files, directories)
    if reader != reference(Path(__file__).absolute()):
        raise ValueError("partial corpus executing Source changed before publication")
    payload = {"contract": PARTIAL_CONTRACT, "complete_audit": base_ref, "partial_progress": partial_progress,
        "partial_progress_values": values, "accepted_partial_rows": rows, "read_dependencies": files,
        "directory_dependencies": directories, "facts": facts, "reader_source": reader,
        "scientific_credit": False, "measurement_equivalence_claimed": False,
        "closed_at": datetime.now(timezone.utc).isoformat()}
    _partial_close()
    return _write(root / "audit.json", PARTIAL_AUDIT_TYPE, payload)


@_partial_owned
def publish_with_partials(audit_ref: dict, output: Path) -> dict:
    _partial_reference(audit_ref)
    value = _document(audit_ref, PARTIAL_AUDIT_TYPE)
    fields = {"contract", "complete_audit", "partial_progress", "partial_progress_values", "accepted_partial_rows",
        "read_dependencies", "directory_dependencies", "facts", "reader_source", "scientific_credit",
        "measurement_equivalence_claimed", "closed_at"}
    if (set(value) != fields or value["contract"] != PARTIAL_CONTRACT or value["scientific_credit"] is not False
            or value["measurement_equivalence_claimed"] is not False
            or value["reader_source"] != reference(Path(__file__).absolute())):
        raise ValueError("partial corpus publication needs this exact closed typed audit")
    base, _ = _reopen_audit(value["complete_audit"], require_complete=False)
    rows, progress_values, files, directories = _partial_inputs(value["partial_progress"])
    if rows != value["accepted_partial_rows"] or progress_values != value["partial_progress_values"]:
        raise ValueError("partial corpus substituted original independently verified partial output")
    audit_facts = partial_coverage(base["classes"], base["lanes"], rows, require_complete=False)
    if audit_facts != value["facts"]:
        raise ValueError("partial corpus changed its original accepted-slot arithmetic")
    facts = partial_coverage(base["classes"], base["lanes"], rows)
    files, directories = _combined_dependencies(base, value["complete_audit"], files, directories)
    if files != value["read_dependencies"] or directories != value["directory_dependencies"]:
        raise ValueError("partial corpus omitted or substituted its original raw dependency closure")
    if value["reader_source"] != reference(Path(__file__).absolute()):
        raise ValueError("partial corpus executing Source changed before final publication")
    _partial_close()
    return _write(output, PARTIAL_CORPUS_TYPE, {"contract": PARTIAL_CONTRACT, "audit": audit_ref,
        "classes": base["classes"], "complete_lanes": base["lanes"], "partial_progress": value["partial_progress"],
        "accepted_partial_rows": rows, **facts, "measurement_equivalence_claimed": False,
        "closed_at": datetime.now(timezone.utc).isoformat()})
