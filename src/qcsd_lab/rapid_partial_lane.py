"""Separate individual-trace authority for a terminal, incomplete original lane.

The original release performs every deep/launch/DNS predicate. This reader never
completes a lane, changes a sample state, repairs a result, or executes capture.
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
from typing import Any

from .util import durable_create

SOURCE_TYPE = "qcsd-partial-lane-original-release-source-v1"
TYPE = "qcsd-original-deep-verified-individual-traces-from-incomplete-lane-v1"
CONTRACT = "original-accepted-traces-retained-incomplete-aggregate-no-lane-pass-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
# This additive contract initially recognizes the actual V17 measurement epoch.
# A caller cannot supply a different clean Git repository as a proof authority.
ORIGINAL_RELEASES = {"86cd8c78cf16447e6add3d10ffa02f6167505276":
                     "c24da2afeec2944a67c48b38eba957dcd543728d"}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _path(value, *, directory=False):
    p = Path(value)
    if (not p.is_absolute() or ".." in p.parts or any(c in str(p) for c in "\0\r\n")
            or any(q.is_symlink() for q in (p, *p.parents))):
        raise ValueError("partial lane needs an original absolute nonlinked path")
    if not (p.is_dir() if directory else p.is_file()):
        raise ValueError("partial lane input has the wrong type")
    return p


def reference(path):
    p = _path(path)
    a = p.stat(); raw = p.read_bytes(); b = p.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if identity(a) != identity(b):
        raise ValueError("partial lane dependency changed while read")
    return {"path": str(p), "sha256": hashlib.sha256(raw).hexdigest(), "mode": stat.S_IMODE(a.st_mode)}


def reopen(ref):
    if (not isinstance(ref, dict) or set(ref) != {"path", "sha256", "mode"}
            or not isinstance(ref["sha256"], str) or SHA.fullmatch(ref["sha256"]) is None
            or type(ref["mode"]) is not int):
        raise ValueError("partial lane reference has another schema")
    p = _path(ref["path"])
    if reference(p) != ref:
        raise ValueError("partial lane dependency bytes or mode changed")
    return p


def _write(path, kind, payload):
    p = Path(path).absolute()
    _path(p.parent, directory=True)
    if p.exists() or any(q.is_symlink() for q in (p, *p.parents)):
        raise FileExistsError("partial lane output must be create only")
    durable_create(p, encoded({"schema_version": 1, "artifact_type": kind, "payload": payload,
        "payload_sha256": hashlib.sha256(encoded(payload)).hexdigest()}))
    return reference(p)


def _document(ref, kind):
    value = json.loads(reopen(ref).read_bytes())
    if (not isinstance(value, dict) or set(value) != {"schema_version", "artifact_type", "payload", "payload_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["artifact_type"] != kind
            or value["payload_sha256"] != hashlib.sha256(encoded(value["payload"])).hexdigest()):
        raise ValueError("partial lane artifact type or digest changed")
    return value["payload"]


def _git(root, *args, input=None):
    return subprocess.run(["git", "-C", str(root), *args], input=input, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"}).stdout


def source_snapshot(root, lab_head, native_head):
    """The original verifier must be a complete unchanged paired Git release."""
    root = _path(root, directory=True)
    if any(not isinstance(x, str) or HEAD.fullmatch(x) is None for x in (lab_head, native_head)):
        raise ValueError("partial lane Source requires exact release heads")
    if ORIGINAL_RELEASES.get(lab_head) != native_head:
        raise ValueError("partial lane original verifier release is not registered")
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


def bind_source(root, lab_head, native_head, output):
    value = source_snapshot(root, lab_head, native_head)
    if source_snapshot(root, lab_head, native_head) != value:
        raise ValueError("original Source changed before publication")
    return _write(output, SOURCE_TYPE, value)


def _source(ref):
    value = _document(ref, SOURCE_TYPE)
    if set(value) != {"root", "lab_head", "native_head", "files"}:
        raise ValueError("partial lane Source binding has another schema")
    if source_snapshot(Path(value["root"]), value["lab_head"], value["native_head"]) != value:
        raise ValueError("original verifier differs from bound complete release")
    return value


def _timestamp(value):
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if t.tzinfo is None: raise ValueError("partial lane chronology lacks timezone")
    return t.astimezone(timezone.utc)


def accepted_subset(report):
    """Join a genuine original deep result to its entire originally planned lane."""
    e, lane, intent, lineage, spec = (report[k] for k in ("experiment", "lane", "intent", "lineage", "spec"))
    config, summary, source = (e[k] for k in ("configuration", "summary", "source"))
    count = len(lane["workload_ids"]) * lane["visits_per_workload"]
    if (lane["role"] != "formal" or lane["study_version"] != 6 or lane["visits_per_workload"] != 4
            or type(lane["block"]) is not int or not 1 <= lane["block"] <= 16
            or intent["actuator"] != "run" or e["status"] != "incomplete" or summary["passed"] is not False
            or e["name"] != lane["campaign_name"] or e["purpose"] != "evaluation"
            or config["campaign_sha256"] != intent["campaign_sha256"] or config["profile"] != "research-1200"
            or config["request_policies"] != ["as-defined"] or config["chaff_qualification_set"] != lane["qualification_set"]
            or source["lab_dirty"] is not False or source["lab_commit"] != lineage["lab_commit"]
            or source["image_digest"] != spec["collection_image_digest"]):
        raise ValueError("partial lane changes original incomplete formal contract")
    sites = {s["workload_id"]: s for s in report["sites"] if s["workload_id"] in lane["workload_ids"]}
    if set(sites) != set(lane["workload_ids"]): raise ValueError("partial lane site graph membership changed")
    expected_workloads = {name: (s["workload_sha256"], 4) for name, s in sites.items()}
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
    expected = {(name, visit, lane["mode"]) for name in lane["workload_ids"] for visit in range(4)}
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
                "logical_visit": (lane["block"] - 1) * 4 + s["visit"], "actual_local_visit": s["visit"],
                "sample_id": s["sample_id"], "original_state": s["state"]}
        if s["state"] == "accepted":
            if s["artifacts"] != report["accepted_samples"][s["sample_id"]] or not s["artifacts"]:
                raise ValueError("partial lane lost original accepted raw artifacts")
            rows.append({**slot, "path": s["path"], "artifacts": s["artifacts"], "diagnostics": s["diagnostics"]})
        else:
            if s["artifacts"]: raise ValueError("partial lane attempts to promote nonaccepted artifacts")
            remaining.append({**slot, "attempts": s["attempts"], "failure": s["failure"]})
    return {"aggregate_status": e["status"], "aggregate_summary": summary, "configuration": config,
        "measurement_source": source, "lane": lane, "spec": spec, "intent": intent,
        "lineage": lineage, "result_root": report["result_root"], "result_seal": report["result_seal"],
        "accepted_count": len(rows), "accepted_samples": rows, "remaining_samples": remaining,
        "lane_pass_claim": False, "aggregate_formal_credit": 0,
        "individual_trace_authority": "original-collector-accepted-and-original-deep-verified-v1"}


# An isolated interpreter imports ONLY the bound original Source. The observer
# prohibits effects and fences actual bytes/modes/listed membership; it never
# replaces a historical validator or its predicates.
_PROGRAM = r'''
import hashlib,json,os,stat,sys
from pathlib import Path
from dataclasses import asdict
q=json.load(sys.stdin); root=Path(q['source_root']); sys.path.insert(0,str(root/'src'))
scratch=Path(q['scratch_root']); os.environ['TMPDIR']=str(scratch)
watched={}; directories={}; observing=False
def record(p):
    global observing
    if observing:return
    observing=True
    try:
        p=Path(p).absolute()
        if p.is_relative_to(scratch) or any(p.is_relative_to(Path(x)) for x in (sys.prefix,sys.base_prefix,'/proc','/sys','/dev')):return
        if any(x.is_symlink() for x in (p,*p.parents)):raise ValueError('original reader opened linked evidence')
        if not p.is_file():return
        a=p.stat(); raw=p.read_bytes(); b=p.stat()
        fields=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if fields(a)!=fields(b):raise ValueError('original dependency changed while read')
        value={'path':str(p),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(a.st_mode)}
        if str(p) in watched and watched[str(p)]!=value:raise ValueError('original dependency changed')
        watched[str(p)]=value
    finally:observing=False
def directory(p):
    global observing
    if observing:return
    observing=True
    try:
        p=Path(p).absolute()
        if p.is_relative_to(scratch) or any(p.is_relative_to(Path(x)) for x in (sys.prefix,sys.base_prefix,'/proc','/sys','/dev')):return
        if any(x.is_symlink() for x in (p,*p.parents)):raise ValueError('original reader listed linked evidence')
        if not p.is_dir():return
        value={'path':str(p),'mode':stat.S_IMODE(p.stat().st_mode),'members':{x.name:{'kind':stat.S_IFMT(x.lstat().st_mode),'mode':stat.S_IMODE(x.lstat().st_mode)} for x in sorted(p.iterdir())}}
        if str(p) in directories and directories[str(p)]!=value:raise ValueError('original directory membership changed')
        directories[str(p)]=value
    finally:observing=False
def mutation_path(event,args):
    p=Path(os.fsdecode(args[0]))
    index=2 if event in {'os.mkdir','os.chmod'} else 1
    fd=args[index] if len(args)>index else -1
    if not p.is_absolute() and isinstance(fd,int) and fd!=-1:p=Path(os.readlink('/proc/self/fd/'+str(fd)))/p
    return p.absolute()
def hook(event,args):
    if event=='open' and not observing:
        p,mode,flags=args
        if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            if not isinstance(p,(str,bytes)) or not Path(os.fsdecode(p)).absolute().is_relative_to(scratch):raise ValueError('original reader attempted evidence write')
            return
        if isinstance(p,(str,bytes)):record(os.fsdecode(p))
    elif event in {'os.listdir','os.scandir'} and not observing:
        if isinstance(args[0],(str,bytes)):directory(os.fsdecode(args[0]))
    elif event=='subprocess.Popen':
        executable,argv,*_=args; name=Path(executable).name; command=list(argv)[1:]
        if name=='git':
            if command[:1]==['-C']:command=command[2:]
            if not command or command[0] not in {'rev-parse','status','diff','ls-files','show','cat-file'} or any(x.startswith(('--output','--ext-diff','--textconv','--filters')) for x in command):raise ValueError('original reader attempted mutable Git')
        elif name=='tshark':
            if '-r' not in command or any(x in command for x in ('-i','-w','--capture','--export-objects')):raise ValueError('original reader attempted live or mutable packet operation')
        else:raise ValueError('original deep endpoint proof needs local TShark; offline image execution belongs to Root')
    elif event in {'os.remove','os.mkdir','os.rmdir','os.chmod'}:
        if not isinstance(args[0],(str,bytes)) or not mutation_path(event,args).is_relative_to(scratch):raise ValueError('original reader attempted evidence mutation')
    elif event in {'os.rename','os.chown','os.symlink','os.link','os.system','os.exec','os.posix_spawn','socket.connect','socket.connect_ex','socket.bind'}:
        raise ValueError('original reader attempted filesystem/network effect')
sys.addaudithook(hook)
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import verification
from qcsd_lab.rapid_operation_facts import OperationFacts
facts=OperationFacts();facts.begin_action()
with facts.scope():
    spec=lanes.load_capture_spec(Path(q['spec'])); study=Path(q['evidence_root']); intent_path=Path(q['intent']); result=Path(q['result'])
    if spec.module_root!=root:raise ValueError('partial verifier module Source differs')
    facts.bind_capture(spec)
    intent,lineage,lane,sites=lanes._intent_and_lineage(spec,study,intent_path,_context=facts)
    intent_raw=lanes._read(intent_path); d=intent_path.parent
    process=lanes._verified_host_process(lanes._read(d/'host-process.json'),study,intent_raw,lane.campaign_name)
    start=lanes._validated_host_start(lanes._read(d/'host-start.json'),intent_raw,campaign_name=lane.campaign_name)
    if (intent['actuator']!='run' or process['interruption'] is not None or type(process['returncode']) is not int or process['returncode']!=1 or not lanes._process_matches_lane(process,spec,lane.campaign_name)
        or lanes._object(study,process['start'])!=lanes._read(d/'host-start.json') or any(process[k]!=start[k] for k in ('command','started_at'))):raise ValueError('partial lane has no matching terminal serial failed host')
    namespace=spec.execution_root/'results'/lane.campaign_name
    children=[x for x in namespace.iterdir() if x.is_dir()]
    if len(children)!=1 or children[0]!=result or result.parent!=namespace:raise ValueError('partial result leaves original unique lane namespace')
    workloads={s.workload_id:lanes._read(spec.workload_root/(s.workload_id+'.json')) for s in sites if s.workload_id in lane.workload_ids}
    dns_sha=lanes.verify_dns_receipt(lanes._read(d/'dns.json'),lane.campaign_name,workloads)
    # All original accepted/failure/fidelity/endpoint proof bodies run unchanged.
    verified=verification.verify_result(result)
    e=verified.experiment
    if not lanes.admission._utc(process['started_at'])<=lanes.admission._utc(e['started_at'])<=lanes.admission._utc(e['completed_at'])<=lanes.admission._utc(process['completed_at']):raise ValueError('partial result chronology leaves actual host execution')
    facts.check()
    report={'spec':spec.serializable(),'intent':intent,'lineage':lineage,'lane':asdict(lane),'sites':[asdict(s) for s in sites],
      'experiment':e,'accepted_samples':verified.accepted_samples,'result_root':str(result),'result_seal':{'path':str(result/'evidence.sha256'),'sha256':lanes._sha(lanes._read(result/'evidence.sha256')),'mode':stat.S_IMODE((result/'evidence.sha256').stat().st_mode)},'dns_sha256':dns_sha}
for p,v in list(watched.items()):record(p)
for p,v in list(directories.items()):directory(p)
report['read_dependencies']=list(watched.values());report['directory_dependencies']=list(directories.values())
print(json.dumps(report,sort_keys=True,allow_nan=False))
'''


def _close_dependencies(report):
    for ref in report["read_dependencies"]: reopen(ref)
    for row in report["directory_dependencies"]:
        p = _path(row["path"], directory=True)
        current = {"path": str(p), "mode": stat.S_IMODE(p.stat().st_mode),
            "members": {x.name: {"kind": stat.S_IFMT(x.lstat().st_mode), "mode": stat.S_IMODE(x.lstat().st_mode)}
                        for x in sorted(p.iterdir())}}
        if row != current: raise ValueError("partial lane original dependency membership changed")


def _request(source, inputs):
    if set(inputs) != {"source_binding", "spec", "evidence_root", "intent", "result"}:
        raise ValueError("partial lane original inputs have another schema")
    if set(inputs["result"]) != {"path", "seal"}:
        raise ValueError("partial lane result binding has another schema")
    result = _path(inputs["result"]["path"], directory=True)
    seal = reopen(inputs["result"]["seal"])
    if seal != result / "evidence.sha256":
        raise ValueError("partial lane result seal moved")
    return {"source_root": source["root"], "evidence_root": str(_path(inputs["evidence_root"], directory=True)),
        **{k: str(reopen(inputs[k])) for k in ("spec", "intent")}, "result": str(result)}


def _recorded_operation(source, inputs, operation):
    if set(operation) != {"started.json", "completed.json", "stdout.log", "stderr.log"}:
        raise ValueError("partial lane deep operation lost its four authentic records")
    paths = {name: reopen(ref) for name, ref in operation.items()}
    if len({p.parent for p in paths.values()}) != 1 or any(p.name != name for name, p in paths.items()):
        raise ValueError("partial lane deep operation records moved")
    started = json.loads(paths["started.json"].read_bytes())
    completed = json.loads(paths["completed.json"].read_bytes())
    if (set(started) != {"command", "request", "reader", "interpreter", "started_at"}
            or started["command"] != [sys.executable, "-I", "-B", "-c", _PROGRAM]
            or started["request"] != {**_request(source, inputs), "scratch_root": str(paths["started.json"].parent / "scratch")}
            or started["reader"] != reference(Path(__file__).absolute())
            or started["interpreter"] != reference(Path(sys.executable).resolve())
            or set(completed) != {"returncode", "completed_at", "stdout_sha256", "stderr_sha256"}
            or type(completed["returncode"]) is not int or completed["returncode"] != 0
            or completed["stdout_sha256"] != operation["stdout.log"]["sha256"]
            or completed["stderr_sha256"] != operation["stderr.log"]["sha256"]
            or not _timestamp(started["started_at"]) <= _timestamp(completed["completed_at"]) <= datetime.now(timezone.utc)):
        raise ValueError("partial lane recorded original deep invocation changed")
    report = json.loads(paths["stdout.log"].read_bytes())
    if report["result_root"] != inputs["result"]["path"] or report["result_seal"] != inputs["result"]["seal"]:
        raise ValueError("partial lane original deep operation opened another result")
    _close_dependencies(report)
    return report, completed


def _run_original(source, inputs, audit_root):
    """Record an actual read-only original verifier invocation, including failures."""
    audit = Path(audit_root).absolute(); _path(audit.parent, directory=True)
    protected = [Path(source["root"]), Path(inputs["evidence_root"]), Path(inputs["result"]["path"]), Path(inputs["intent"]["path"]).parent]
    if any(audit.is_relative_to(p) or p.is_relative_to(audit) for p in protected):
        raise ValueError("partial lane audit must use a disjoint fresh namespace")
    audit.mkdir(mode=0o755, exist_ok=False)
    (audit / "scratch").mkdir(mode=0o700, exist_ok=False)
    request = {**_request(source, inputs), "scratch_root": str(audit / "scratch")}
    command = [sys.executable, "-I", "-B", "-c", _PROGRAM]
    started = {"command": command, "request": request, "reader": reference(Path(__file__).absolute()),
               "interpreter": reference(Path(sys.executable).resolve()),
               "started_at": datetime.now(timezone.utc).isoformat()}
    durable_create(audit / "started.json", encoded(started))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith(("QCSD_", "GIT_", "PYTHON"))}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(command, input=encoded(request), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    durable_create(audit / "stdout.log", result.stdout); durable_create(audit / "stderr.log", result.stderr)
    completed = {"returncode": result.returncode, "completed_at": datetime.now(timezone.utc).isoformat(),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(), "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
    durable_create(audit / "completed.json", encoded(completed))
    if result.returncode != 0:
        raise ValueError("original partial-lane reopening refused; preserved raw audit has the cause")
    operation = {name: reference(audit / name) for name in ("started.json", "completed.json", "stdout.log", "stderr.log")}
    report, _ = _recorded_operation(source, inputs, operation)
    return report, operation


def declare(*, source_binding, spec, evidence_root, intent, result, audit_root, output):
    source = _source(source_binding)
    result = _path(result, directory=True)
    # A live checkpoint cannot be snapshotted as a partial authority.
    inputs = {"source_binding": source_binding, "spec": reference(spec), "evidence_root": str(_path(evidence_root, directory=True)),
        "intent": reference(intent), "result": {"path": str(result), "seal": reference(result / "evidence.sha256")}}
    reader = reference(Path(__file__).absolute())
    report, operation = _run_original(source, inputs, audit_root)
    facts = accepted_subset(report)
    _close_dependencies(report)
    if _source(source_binding) != source or reference(Path(__file__).absolute()) != reader:
        raise ValueError("original or executing reader Source changed before publication")
    target = Path(output).absolute()
    if any(target.is_relative_to(Path(x)) for x in (source["root"], inputs["evidence_root"], str(result), str(Path(intent).parent), str(audit_root))):
        raise ValueError("partial receipt must be outside original Source and evidence")
    payload = {"contract": CONTRACT, "inputs": inputs, "reader": reader, "deep_operation": operation,
        "read_dependencies": report["read_dependencies"], "directory_dependencies": report["directory_dependencies"],
        **facts, "published_at": datetime.now(timezone.utc).isoformat()}
    return _write(target, TYPE, payload)


def verify(receipt, *, audit_root):
    value = _document(receipt, TYPE)
    if value["contract"] != CONTRACT or value["lane_pass_claim"] is not False or value["aggregate_formal_credit"] != 0:
        raise ValueError("partial receipt changed its separate incomplete-lane contract")
    if value["reader"] != reference(Path(__file__).absolute()):
        raise ValueError("partial receipt requires its exact executing reader Source")
    source = _source(value["inputs"]["source_binding"])
    recorded, completed = _recorded_operation(source, value["inputs"], value["deep_operation"])
    recorded_facts = accepted_subset(recorded)
    if any(value.get(k) != v for k, v in recorded_facts.items()) or _timestamp(value["published_at"]) < _timestamp(completed["completed_at"]):
        raise ValueError("partial receipt differs from its recorded original deep proof")
    _close_dependencies(value)
    report, operation = _run_original(source, value["inputs"], audit_root)
    facts = accepted_subset(report)
    if any(value.get(k) != v for k, v in facts.items()):
        raise ValueError("partial receipt differs from freshly reopened original accepted subset")
    _close_dependencies(report)
    if _source(value["inputs"]["source_binding"]) != source:
        raise ValueError("original Source changed during partial verification")
    return {"accepted_count": facts["accepted_count"], "aggregate_status": facts["aggregate_status"],
        "lane_pass_claim": False, "aggregate_formal_credit": 0, "fresh_deep_operation": operation}
