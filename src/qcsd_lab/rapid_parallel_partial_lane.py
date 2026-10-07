"""Prospective individual traces from terminal incomplete PARALLEL workers.

The immutable measurement release owns the unchanged full deep predicates.
This separately published reader records a new parallel-partial role and never
writes a capture, retires a session, completes a lane, or changes a sample.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys

from . import rapid_partial_lane as original
from . import rapid_chunk_partial_lane as measurement
from .rapid_partial_lane import (_path, reference, reopen, encoded, _write,
    _document, _timestamp, _close_dependencies)
from .util import durable_create

TYPE = "qcsd-original-deep-verified-individual-traces-from-incomplete-parallel-chunk-v1"
CONTRACT = "actual-parallel-worker-original-accepted-traces-incomplete-aggregate-v1"
LAYOUT = "actual-parallel-workers-remaining-slot-chunk-v1"
READER_SOURCE_TYPE = "qcsd-prospective-parallel-partial-read-only-source-v2"
READER_SOURCE_CONTRACT = "full-paired-git-prospective-reader-exact-observed-modes-v1"
_READER_HEAD = re.compile(r"[0-9a-f]{40}\Z")
_READER_MODULE_ROLES = {
    "src/qcsd_lab/rapid_parallel_partial_lane.py": "prospective-parallel-partial-reader",
    "src/qcsd_lab/rapid_partial_lane.py": "unchanged-original-full-deep-proof-program",
    "src/qcsd_lab/rapid_chunk_partial_lane.py": "unchanged-measurement-source-authenticator",
    "src/qcsd_lab/rapid_fixed_condition_target.py": "prospective-fixed-target-dispatch-adapter",
    "tools/rapid_parallel_partial_lane.py": "prospective-reader-public-entrypoint",
}
ACTUATOR = "parallel-formal-worker"

# These two anchored adaptations define a NEW proof program. They do not
# modify or masquerade as the original serial _PROGRAM or its receipts.
_SERIAL_GUARD = "if (intent['actuator']!='run' or process['interruption']"
_PARALLEL_GUARD = "if (intent['actuator']!='parallel-formal-worker' or process.get('actuator')!='parallel-formal-worker' or process['interruption']"
_DEEP_SEAM = "    e=verified.experiment\n"
_PARALLEL_PROOF = r'''
    e=verified.experiment
    from qcsd_lab import rapid_formal_parallel as formal
    from qcsd_lab import rapid_parallel_capture as shared
    formal.require_batch_closure(process)
    authority=process['_authority_value']
    if len(authority['lane_intents'])!=2 or len(authority['lane_specs'])!=2:
        raise ValueError('parallel partial requires its exact original two-worker authority')
    peer_records=[]
    for index,ref in enumerate(authority['lane_intents']):
        peer_path=formal._reference(ref)
        peer_raw=lanes._read(peer_path)
        peer_intent=lanes._host_intent(peer_raw)
        peer=lanes._verified_host_process(lanes._read(peer_path.parent/'host-process.json'),study,peer_raw,peer_intent['campaign_name'])
        peer_spec=lanes.load_capture_spec(formal._reference(authority['lane_specs'][index]))
        if (peer.get('actuator')!='parallel-formal-worker' or peer['worker_index']!=index
            or peer['authority']!=process['authority'] or peer['batch_root']!=process['batch_root']
            or peer['interruption'] is not None or type(peer['returncode']) is not int
            or not lanes._process_matches_lane(peer,peer_spec,peer_intent['campaign_name'])):
            raise ValueError('parallel partial lacks both actual terminal retired workers')
        peer_records.append({'worker_index':index,'campaign_name':peer_intent['campaign_name'],
            'host_process_path':str(peer_path.parent/'host-process.json'),
            'returncode':peer['returncode'],'completed_at':peer['completed_at'],'retirement':peer['retirement']})
    partition_path=Path(process['batch_root'])/f"lane-{process['worker_index']+1}"/'gate/host-partition.json'
    partition=shared.load(partition_path)
    # FULL original result was deep verified above. This in-memory projection
    # is only input to the additional original accepted-sample peer predicate.
    accepted=[sample for sample in e['samples'] if sample['state']=='accepted']
    if set(verified.accepted_samples)!={sample['sample_id'] for sample in accepted}:
        raise ValueError('parallel partial peer projection differs from full original deep accepted set')
    shared.verify_peer_sample_bindings({'samples':accepted},partition)
    record(partition_path)
    authority_path=formal._reference(process['authority']);record(authority_path)
    parallel_binding={'actuator':'parallel-formal-worker','authority':watched[str(authority_path.absolute())],
        'batch_root':process['batch_root'],'worker_index':process['worker_index'],
        'partition':watched[str(partition_path.absolute())],'peer_processes':peer_records,
        'peer_proof_scope':'original-deep-accepted-subset-after-unchanged-full-result-verification-v1',
        'global_session_retirement_pass_claim':False}
'''
_REPORT_SEAM = "'dns_sha256':dns_sha}"
_REPORT_ADD = "'dns_sha256':dns_sha,'parallel_binding':parallel_binding,'offline_endpoint_operations':offline_endpoint_operations}"
_GIT_READ_SEAM = "{'rev-parse','status','diff','ls-files','show','cat-file'}"
_GIT_READ_ADD = "{'rev-parse','status','diff','ls-files','ls-tree','show','cat-file'}"
_DOCKER_SEAM = "        else:raise ValueError('original deep endpoint proof needs local TShark; offline image execution belongs to Root')"
_DOCKER_FENCE = r'''
        elif name=='docker':
            if q.get('root_offline_endpoint_replay') is not True:
                raise ValueError('offline endpoint replay requires explicit Root transport authorization')
            verifier=Path(q['endpoint_verifier']['path'])
            result_root=Path(q['result'])
            module_source=Path(q['source_root'])/'src'
            replay=sys.modules.get('qcsd_lab.verification')
            if replay is None or Path(replay.__file__).absolute()!=verifier:
                raise ValueError('offline replay uses another original Source verifier')
            record(verifier)
            if watched[str(verifier)]!=q['endpoint_verifier']:
                raise ValueError('offline replay verifier bytes or full mode changed')
            image=q['collection_image_digest']
            expected=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
                '--security-opt','no-new-privileges','--user',f'{os.getuid()}:{os.getgid()}',
                '--tmpfs','/tmp:rw,nosuid,nodev,noexec','--volume',f'{result_root}:{result_root}:ro',
                '--volume',f'{module_source}:{module_source}:ro','--entrypoint',
                '/opt/qcsd-venv/bin/python3',image,'-I','-B','-c',replay._ENDPOINT_REPLAY_SCRIPT,
                str(result_root),str(module_source),image,q['endpoint_verifier']['sha256']]
            if list(argv)!=expected:
                raise ValueError('parallel partial permits only original immutable offline endpoint replay argv')
        else:raise ValueError('parallel partial attempted an unregistered subprocess effect')
'''
_IMPORT_SEAM = "from qcsd_lab import verification\n"
_OBSERVED_IMPORT = r'''
from qcsd_lab import verification
offline_endpoint_operations=[]
_original_endpoint_transport=getattr(verification,'run',None)
def _observe_endpoint_transport(command,*args,**kwargs):
    # Observe exact raw return values without replacing any replay predicate.
    execution=_original_endpoint_transport(command,*args,**kwargs)
    if command and Path(command[0]).name=='docker':
        offline_endpoint_operations.append({'command':command,'returncode':execution.returncode,
            'stdout':execution.stdout,'stderr':execution.stderr,
            'role':'original-immutable-offline-endpoint-replay-transport-v1'})
    return execution
if _original_endpoint_transport is not None:
    verification.run=_observe_endpoint_transport
'''

def proof_program():
    program = original._PROGRAM
    for before, after in ((_SERIAL_GUARD, _PARALLEL_GUARD),
            (_DEEP_SEAM, _PARALLEL_PROOF), (_REPORT_SEAM, _REPORT_ADD),
            (_GIT_READ_SEAM, _GIT_READ_ADD), (_DOCKER_SEAM, _DOCKER_FENCE),
            (_IMPORT_SEAM, _OBSERVED_IMPORT)):
        if program.count(before) != 1:
            raise ValueError("parallel partial original proof seam differs")
        program = program.replace(before, after, 1)
    return program.replace("terminal serial failed host", "terminal parallel failed worker")

_PROGRAM = proof_program()

def _reader_sources():
    return {module.__name__: reference(Path(module.__file__).absolute())
            for module in (sys.modules[__name__], original, measurement)}

def reader_source_snapshot(root, lab_head, native_head):
    """Authenticate this independent reader's complete paired Git bytes and modes.

    Git records an executable class, not full permissions. Private 0600 files
    remain private and bind their exact observed full mode. This is a new reader
    contract; it neither calls nor changes measurement.release_snapshot.
    """
    root = _path(root, directory=True)
    if any(not isinstance(x, str) or _READER_HEAD.fullmatch(x) is None
            for x in (lab_head, native_head)):
        raise ValueError("prospective reader Source requires exact paired Git heads")
    files = {}; mode_pairs = {}
    for checkout, prefix, head in ((root, "", lab_head),
            (root / "neqo-qcsd", "neqo-qcsd/", native_head)):
        if original._git(checkout, "rev-parse", "HEAD").decode().strip() != head:
            raise ValueError("prospective reader Source head moved")
        if original._git(checkout, "status", "--porcelain=v1", "--untracked-files=all"):
            raise ValueError("prospective reader Source is not a clean complete Git checkout")
        tree = {}; index = {}; rows = []
        for row in original._git(checkout, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
            if not row: continue
            meta, raw_name = row.split(b"\t"); mode, kind, blob = meta.decode().split()
            name = raw_name.decode()
            if (not name or Path(name).is_absolute() or ".." in Path(name).parts
                    or any(c in name for c in "\0\r\n") or name in tree
                    or kind != ("commit" if mode == "160000" else "blob")):
                raise ValueError("prospective reader Source has invalid tree membership")
            tree[name] = (mode, blob)
        for row in original._git(checkout, "ls-files", "-s", "-z").split(b"\0"):
            if not row: continue
            meta, raw_name = row.split(b"\t"); mode, blob, stage = meta.decode().split()
            name = raw_name.decode()
            if (stage != "0" or not name or Path(name).is_absolute() or ".." in Path(name).parts
                    or any(c in name for c in "\0\r\n") or name in index):
                raise ValueError("prospective reader Source has conflicted or invalid index membership")
            index[name] = (mode, blob)
            if mode == "160000":
                if prefix or name != "neqo-qcsd" or blob != native_head:
                    raise ValueError("prospective reader Native Gitlink differs")
                continue
            if mode not in {"100644", "100755"} or tree.get(name) != (mode, blob):
                raise ValueError("prospective reader Source index differs from its committed tree")
            rows.append((name, mode, blob))
        if tree != index or (not prefix and tree.get("neqo-qcsd") != ("160000", native_head)):
            raise ValueError("prospective reader complete Source membership or Native Gitlink differs")
        raw = original._git(checkout, "cat-file", "--batch",
            input="".join(blob + "\n" for _, _, blob in rows).encode())
        offset = 0
        for name, mode, blob in rows:
            end = raw.index(b"\n", offset)
            actual, kind, size = raw[offset:end].decode().split(); size = int(size)
            body = raw[end + 1:end + 1 + size]
            if (size < 0 or len(body) != size or raw[end + 1 + size:end + 2 + size] != b"\n"):
                raise ValueError("prospective reader Git blob stream is incomplete")
            offset = end + size + 2
            value = reference(checkout / name)
            allowed = {0o600, 0o644} if mode == "100644" else {0o755}
            if (actual != blob or kind != "blob" or value["sha256"] != hashlib.sha256(body).hexdigest()
                    or value["mode"] not in allowed):
                raise ValueError("prospective reader Source bytes or observed full mode differ: " + prefix + name)
            relative = prefix + name
            files[relative] = value
            mode_pairs[relative] = {"git_mode":mode, "observed_full_mode":value["mode"]}
        if offset != len(raw):
            raise ValueError("prospective reader Git blob stream has trailing data")
        if (original._git(checkout, "rev-parse", "HEAD").decode().strip() != head
                or original._git(checkout, "status", "--porcelain=v1", "--untracked-files=all")):
            raise ValueError("prospective reader Source changed during its snapshot")
    if not any(name.startswith("neqo-qcsd/") for name in files):
        raise ValueError("prospective reader Source lacks its full Native checkout")
    for directory in (root / "src", root / "tools"):
        for path in directory.rglob("*.py"):
            if "__pycache__" not in path.parts and path.relative_to(root).as_posix() not in files:
                raise ValueError("prospective reader acquired an unbound importable file")
    if not set(_READER_MODULE_ROLES) <= set(files):
        raise ValueError("prospective reader Source lacks a registered module role")
    roles = {name:{"role":role, "reference":files[name]}
        for name, role in _READER_MODULE_ROLES.items()}
    return {"contract":READER_SOURCE_CONTRACT, "root":str(root),
        "lab_head":lab_head, "native_head":native_head, "files":files,
        "mode_pairs":mode_pairs, "module_roles":roles}


def _reader_module_closure(snapshot):
    root = Path(snapshot["root"])
    sources = _reader_sources()
    for value in sources.values():
        path = Path(value["path"])
        if not path.is_relative_to(root) or snapshot["files"].get(path.relative_to(root).as_posix()) != value:
            raise ValueError("prospective reader loaded an unbound module outside its own Source")
    return sources


def bind_reader(*, root, lab_head, native_head, output):
    root = _path(root, directory=True)
    if root != Path(__file__).absolute().parents[2]:
        raise ValueError("parallel partial consumer must bind its actual executing checkout")
    snapshot = reader_source_snapshot(root, lab_head, native_head)
    sources = _reader_module_closure(snapshot)
    target = Path(output).absolute()
    if target.is_relative_to(root):
        raise ValueError("parallel partial reader binding must remain outside the reader Source")
    return _write(target, READER_SOURCE_TYPE, {"reader_source":snapshot,
        "reader_sources":sources, "role":"prospective-read-only-verifier-not-measurement-runtime-v1",
        "published_at":datetime.now(timezone.utc).isoformat()})

def _reader(binding):
    value = _document(binding, READER_SOURCE_TYPE)
    if set(value) != {"reader_source","reader_sources","role","published_at"}:
        raise ValueError("parallel partial reader Source binding schema differs")
    snapshot=value["reader_source"]
    if (value["role"]!="prospective-read-only-verifier-not-measurement-runtime-v1"
            or value["reader_sources"]!=_reader_module_closure(snapshot)
            or Path(snapshot["root"])!=Path(__file__).absolute().parents[2]
            or reader_source_snapshot(snapshot["root"],snapshot["lab_head"],snapshot["native_head"])!=snapshot):
        raise ValueError("parallel partial executing reader differs from its frozen full Git Source")
    if not _timestamp(value["published_at"])<=datetime.now(timezone.utc):
        raise ValueError("parallel partial reader Source publication chronology differs")
    return value

def _accepted_subset(report):
    e, lane, intent, lineage, spec = (report[k] for k in ("experiment", "lane", "intent", "lineage", "spec"))
    config, summary, source = (e[k] for k in ("configuration", "summary", "source"))
    from .rapid_slot_chunks import checked_lane
    checked_lane(lane)
    visits = lane["visits_per_workload"]
    count = len(lane["workload_ids"]) * visits
    if (lane["role"] != "formal" or lane["study_version"] != 6 or not 1 <= visits <= 16
            or type(lane["block"]) is not int or not 1 <= lane["block"] <= 64
            or intent["actuator"] != "parallel-formal-worker" or e["status"] != "incomplete" or summary["passed"] is not False
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


def accepted_subset(report):
    facts=_accepted_subset(report)
    binding=report.get("parallel_binding")
    expected={"actuator","authority","batch_root","worker_index","partition","peer_processes",
        "peer_proof_scope","global_session_retirement_pass_claim"}
    if (not isinstance(binding,dict) or set(binding)!=expected
            or binding["actuator"]!=ACTUATOR or type(binding["worker_index"]) is not int
            or binding["worker_index"] not in (0,1)
            or binding["global_session_retirement_pass_claim"] is not False
            or binding["peer_proof_scope"]!="original-deep-accepted-subset-after-unchanged-full-result-verification-v1"
            or len(binding["peer_processes"])!=2
            or [r["worker_index"] for r in binding["peer_processes"]]!=[0,1]
            or any(type(r["returncode"]) is not int for r in binding["peer_processes"])
            or binding["peer_processes"][binding["worker_index"]]["returncode"]!=1
            or binding["authority"] not in report["read_dependencies"]
            or binding["partition"] not in report["read_dependencies"]):
        raise ValueError("parallel partial accepted subset lost actual peer/terminal authority")
    return {**facts,"actuator":ACTUATOR,"parallel_binding":binding,
        "global_session_retirement_pass_claim":False,
        **({"image_metadata_join":report["image_metadata_join"]} if "image_metadata_join" in report else {})}

def _request(source,inputs):
    if set(inputs)!={"source_binding","reader_binding","spec","evidence_root","intent","result",
            "root_offline_endpoint_replay"} or type(inputs["root_offline_endpoint_replay"]) is not bool:
        raise ValueError("parallel partial original inputs have another schema")
    _reader(inputs["reader_binding"])
    original_ref = source["files"]["src/qcsd_lab/rapid_partial_lane.py"]
    current_ref = reference(Path(original.__file__).absolute())
    if any(original_ref[key] != current_ref[key] for key in ("sha256", "mode")):
        raise ValueError("parallel partial consumer changed the original measurement proof program")
    original_inputs={k:v for k,v in inputs.items() if k not in ("reader_binding","root_offline_endpoint_replay")}
    return {**original._request(source,original_inputs),
        "reader_binding":inputs["reader_binding"],
        "root_offline_endpoint_replay":inputs["root_offline_endpoint_replay"],
        "collection_image_digest":source["binding"]["runtime_identity"]["collection_image_digest"],
        "endpoint_verifier":source["files"]["src/qcsd_lab/verification.py"]}

def _measurement_binding(report, source):
    """Join unadorned installed export metadata to the authenticated capture image.

    The immutable source binding and full original report remain untouched.
    Only a separate, explicitly recorded in-memory identity projection is
    passed to the unchanged original measurement join. Every original root,
    image, client, source, runtime-copy and chunk-authority guard still runs.
    """
    if "image_metadata_join" in report:
        raise ValueError("parallel partial raw original report contains an unregistered image join")
    identity = source["binding"]["runtime_identity"]
    exported = identity["source"]
    captured = report["intent"]["runtime_identity"]["runtime_source"]
    if captured == exported:
        return measurement._measurement_binding(report, source)
    image = identity["collection_image_digest"]
    expected = {**exported, "image_digest":image}
    if ("image_digest" not in exported or exported["image_digest"] is not None
            or captured != expected or report["experiment"]["source"] != expected):
        raise ValueError("parallel partial installed-export/capture image identity join differs")
    projected = {**source, "binding":{**source["binding"], "runtime_identity":{
        **identity, "source":expected}}}
    joined = measurement._measurement_binding(report, projected)
    return {**joined, "image_metadata_join":{
        "contract":"unadorned-installed-export-to-authenticated-capture-image-metadata-v1",
        "installed_export_source":dict(exported), "captured_source":dict(captured),
        "collection_image_digest":image,
        "canonical":source["binding"]["canonical"],
        "source_manifest":reference(source["binding"]["runtime"]["source_manifest"]),
        "projection_scope":"in-memory-installed-source-identity-image-field-only",
        "original_report_rewritten":False, "source_binding_rewritten":False}}


def _recorded_operation(source,inputs,operation):
    if set(operation)!={"started.json","completed.json","stdout.log","stderr.log"}:
        raise ValueError("parallel partial deep operation lost its four original records")
    paths={name:reopen(ref) for name,ref in operation.items()}
    if len({p.parent for p in paths.values()})!=1 or any(p.name!=n for n,p in paths.items()):
        raise ValueError("parallel partial recorded deep operation moved")
    started=json.loads(paths["started.json"].read_bytes())
    completed=json.loads(paths["completed.json"].read_bytes())
    if (set(started)!={"command","request","reader_sources","interpreter","started_at"}
            or started["command"]!=[sys.executable,"-I","-B","-c",_PROGRAM]
            or started["request"]!={**_request(source,inputs),"scratch_root":str(paths["started.json"].parent/"scratch")}
            or started["reader_sources"]!=_reader_sources()
            or started["interpreter"]!=reference(Path(sys.executable).resolve())
            or set(completed)!={"returncode","completed_at","stdout_sha256","stderr_sha256"}
            or type(completed["returncode"]) is not int or completed["returncode"]!=0
            or completed["stdout_sha256"]!=operation["stdout.log"]["sha256"]
            or completed["stderr_sha256"]!=operation["stderr.log"]["sha256"]
            or not _timestamp(started["started_at"])<=_timestamp(completed["completed_at"])<=datetime.now(timezone.utc)):
        raise ValueError("parallel partial recorded original full deep invocation changed")
    report=json.loads(paths["stdout.log"].read_bytes())
    if report["result_root"]!=inputs["result"]["path"] or report["result_seal"]!=inputs["result"]["seal"]:
        raise ValueError("parallel partial deep operation opened another result")
    _close_dependencies(report)
    return _measurement_binding(report,source),completed

def _run_original(source,inputs,audit_root):
    audit=Path(audit_root).absolute();_path(audit.parent,directory=True)
    protected=[Path(source["root"]),Path(inputs["evidence_root"]),Path(inputs["result"]["path"]),
        Path(inputs["intent"]["path"]).parent,Path(__file__).absolute().parents[2]]
    if any(audit.is_relative_to(p) or p.is_relative_to(audit) for p in protected):
        raise ValueError("parallel partial audit needs a disjoint fresh namespace")
    request={**_request(source,inputs),"scratch_root":str(audit/"scratch")}
    audit.mkdir(mode=0o755,exist_ok=False);(audit/"scratch").mkdir(mode=0o700,exist_ok=False)
    command=[sys.executable,"-I","-B","-c",_PROGRAM]
    started={"command":command,"request":request,"reader_sources":_reader_sources(),
        "interpreter":reference(Path(sys.executable).resolve()),"started_at":datetime.now(timezone.utc).isoformat()}
    durable_create(audit/"started.json",encoded(started))
    env={k:v for k,v in os.environ.items() if k!="PYTHONPATH" and not k.startswith(("QCSD_","GIT_","PYTHON"))}
    env["GIT_OPTIONAL_LOCKS"]="0"
    result=subprocess.run(command,input=encoded(request),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,check=False)
    durable_create(audit/"stdout.log",result.stdout);durable_create(audit/"stderr.log",result.stderr)
    completed={"returncode":result.returncode,"completed_at":datetime.now(timezone.utc).isoformat(),
        "stdout_sha256":hashlib.sha256(result.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(result.stderr).hexdigest()}
    durable_create(audit/"completed.json",encoded(completed))
    if result.returncode:
        raise ValueError("parallel partial unchanged full deep reopening refused; preserve raw audit cause")
    operation={name:reference(audit/name) for name in ("started.json","completed.json","stdout.log","stderr.log")}
    report,_=_recorded_operation(source,inputs,operation)
    return report,operation

def _input_closure(source,inputs,report,operation):
    closure=measurement._input_closure(source,inputs["source_binding"],report,operation)
    reader=_reader(inputs["reader_binding"])
    files={ref["path"]:ref for ref in closure["read_dependencies"]}
    for ref in [inputs["reader_binding"],*_reader_sources().values(),*reader["reader_source"]["files"].values()]:
        if ref["path"] in files and files[ref["path"]]!=ref:
            raise ValueError("parallel partial reader dependency alias disagrees")
        files[ref["path"]]=ref
    return {**closure,"read_dependencies":[files[p] for p in sorted(files)]}

def declare(*,source_binding,reader_binding,spec,evidence_root,intent,result,audit_root,output,
        root_offline_endpoint_replay=False):
    source=measurement._source(source_binding);_reader(reader_binding)
    result=_path(result,directory=True)
    inputs={"source_binding":source_binding,"reader_binding":reader_binding,"spec":reference(spec),
        "evidence_root":str(_path(evidence_root,directory=True)),"intent":reference(intent),
        "result":{"path":str(result),"seal":reference(result/"evidence.sha256")},
        "root_offline_endpoint_replay":root_offline_endpoint_replay}
    readers=_reader_sources();report,operation=_run_original(source,inputs,audit_root)
    facts=accepted_subset(report);dependencies=_input_closure(source,inputs,report,operation)
    _close_dependencies(dependencies)
    target=Path(output).absolute()
    if any(target.is_relative_to(Path(p)) for p in (source["root"],inputs["evidence_root"],
            str(result),str(Path(intent).parent),str(audit_root),str(Path(__file__).absolute().parents[2]))):
        raise ValueError("parallel partial receipt must stay outside original Source and evidence")
    if measurement._source(source_binding)!=source or _reader_sources()!=readers:
        raise ValueError("parallel partial Source changed before publication")
    return _write(target,TYPE,{"contract":CONTRACT,"inputs":inputs,"reader_sources":readers,
        "deep_operation":operation,**dependencies,**facts,"published_at":datetime.now(timezone.utc).isoformat()})

def _recorded_receipt(receipt):
    value=_document(receipt,TYPE)
    if (value["contract"]!=CONTRACT or value["registered_layout"]!=LAYOUT
            or value["lane_pass_claim"] is not False or type(value["aggregate_formal_credit"]) is not int
            or value["aggregate_formal_credit"]!=0 or value["reader_sources"]!=_reader_sources()):
        raise ValueError("parallel partial receipt changed its separate actual parallel role")
    source=measurement._source(value["inputs"]["source_binding"])
    report,completed=_recorded_operation(source,value["inputs"],value["deep_operation"])
    facts=accepted_subset(report);dependencies=_input_closure(source,value["inputs"],report,value["deep_operation"])
    from .rapid_fixed_condition_target import _typed_equal
    if (any(not _typed_equal(value.get(k),v) for k,v in facts.items())
            or any(not _typed_equal(value.get(k),v) for k,v in dependencies.items())
            or not _timestamp(completed["completed_at"])<=_timestamp(value["published_at"])<=datetime.now(timezone.utc)):
        raise ValueError("parallel partial receipt differs from full original deep authority")
    _close_dependencies(dependencies)
    return value,source,report,facts,dependencies

def verify(receipt,*,audit_root):
    value,source,old,old_facts,_=_recorded_receipt(receipt)
    report,operation=_run_original(source,value["inputs"],audit_root)
    facts=accepted_subset(report)
    from .rapid_fixed_condition_target import _typed_equal
    if not _typed_equal(facts,old_facts):
        raise ValueError("parallel partial independent original full deep reopening differs")
    dependencies=_input_closure(source,value["inputs"],report,operation);_close_dependencies(dependencies)
    if measurement._source(value["inputs"]["source_binding"])!=source:
        raise ValueError("parallel partial measurement Source changed during independent proof")
    return {k:facts[k] for k in ("accepted_count","registered_layout","slot_start","slot_count",
        "aggregate_status","lane_pass_claim","aggregate_formal_credit")} | {
        "fresh_deep_operation":operation,**dependencies}

def target_operation(operation):
    from . import rapid_fixed_condition_target as target
    target._keys(operation,{"receipt","verification"},"target original parallel-partial proof")
    value,source,first,first_facts,first_dependencies=_recorded_receipt(operation["receipt"])
    verified=operation["verification"]
    target._keys(verified,{"accepted_count","registered_layout","slot_start","slot_count","aggregate_status",
        "lane_pass_claim","aggregate_formal_credit","fresh_deep_operation","read_dependencies","directory_dependencies"},
        "target independent parallel-partial verification")
    second,end=_recorded_operation(source,value["inputs"],verified["fresh_deep_operation"])
    second_facts=accepted_subset(second);second_dependencies=_input_closure(source,value["inputs"],second,verified["fresh_deep_operation"])
    start=json.loads(reopen(verified["fresh_deep_operation"]["started.json"]).read_bytes())
    if (not target._typed_equal(first_facts,second_facts)
            or value["deep_operation"]==verified["fresh_deep_operation"]
            or not _timestamp(value["published_at"])<=_timestamp(start["started_at"])<=_timestamp(end["completed_at"])
            or any(not target._typed_equal(verified[k],second_facts[k]) for k in
                ("accepted_count","registered_layout","slot_start","slot_count","aggregate_status","lane_pass_claim","aggregate_formal_credit"))
            or any(not target._typed_equal(verified[k],v) for k,v in second_dependencies.items())):
        raise ValueError("parallel partial target lacks separate unchanged original full deep verification")
    dependencies=target._dependency_union(first_dependencies,second_dependencies,
        {"read_dependencies":[operation["receipt"]],"directory_dependencies":[]})
    source["binding_reference"]=value["inputs"]["source_binding"]
    return source,second,second_facts,dependencies,end["completed_at"]
