"""Selected complete GET inputs under the prospective per-class budget role.

The original budget authority is audited once, with its actual Source retained.
Consumers independently reconstruct the selected ordinary bootstrap/full GET;
they do not replay an unrelated acquisition prefix for every capture. Plain
selected V1 inputs keep their original verifier, receipt and preparation bytes.
"""
from __future__ import annotations

from copy import deepcopy
import math
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Mapping

from . import rapid_selected_capture_input as plain
from . import rapid_additive_static_enrollment as old_ledger
from . import rapid_operation_facts as facts
from . import rapid_lane_evidence as lanes
from . import rapid_site_admission as receipts
from . import supplied_static_budget_successor as budget
from . import supplied_static_get as get
from . import supplied_static_graph as graph
from . import supplied_static_preparation as original

ROLE = "selected-complete-graph-per-class-budget-capture-input-v1"
RECEIPT_TYPE = "qcsd-selected-complete-graph-per-class-budget-input-v1"
AUDIT_TYPE = "qcsd-selected-budget-original-authority-audit-v1"
CONTRACT = "selected-budget-own-complete-bootstrap-get-with-original-authority-audit-v1"
FIELD = "selected_budget_input_evidence"
FIELDS = plain.FIELDS | {"budget_terminal", "underlying_manifest", "budget_context"}
ORIGINAL_CORE_INVENTORY_SHA256 = "e20951f884196b5ec1eed6f6634462c980976e3dfbc626fd50a25f18b8c9a809"
LEGACY_SELECTED_SOURCE_SHA256 = "d4bbea3459cccf36217fa9897fbef4a51f73b3690151ef8aec883344e84145ca"
V3_SELECTED_SOURCE_SHA256 = "9e13ebe6eb79f066b2d96e9fc1cb90056584d4ba02f203ec8d8b42da95c57cf7"
V3_HOST_INVENTORY_SHA256 = "e6a77370e1ae219e97cf4147c239a29e46cf56df519ce9a0781ea97779c271ff"
V3_HOST_AUTHORITY_SHA256 = "54263b4d1da96c4b22ee7be5401cd51d2e6336c78f69673b2661d2f28abb91c3"
V3_ADMISSION_SOURCE_SHA256 = "f3ebf10f0d75944c18c73699efeb4f6d6f637e3dd87f8f84b4e20695706fab35"
V3_DEFERRAL_SOURCE_SHA256 = "4ba46dbe73cf6ada368b41fb0bafaec03a3db62ddaf30de6b2225e7f4802d283"


def is_selected(value: Any) -> bool:
    return isinstance(value, Mapping) and value.get("data_role") == ROLE


def is_input(path: Path) -> bool:
    return get._load(get._read(path)).get("receipt_type") == RECEIPT_TYPE


def _modules():
    return (*plain._direct_modules(), budget, __import__(__name__, fromlist=["_"]))


def direct_sources() -> dict[str, str]:
    return {module.__name__: graph.digest(get._read(Path(module.__file__))) for module in _modules()}


_AUDIT_PROGRAM = r'''
import json,sys
from pathlib import Path
root=Path(sys.argv[1]);sys.path[:0]=[str(root/"src"),str(root)]
from qcsd_lab import supplied_static_budget_successor as b
from qcsd_lab import supplied_static_preparation as p
from qcsd_lab import supplied_static_graph as g
context=b.load_context(Path(sys.argv[2]));terminal=Path(sys.argv[3])
facts=b.verify_terminal(terminal,context)
if facts["outcome"]!="admitted":raise ValueError("selected budget input needs an admitted full GET")
path,manifest=b.prepared_workload(context,terminal)
candidate=next(row for row in context.candidates if row["candidate_id"]==facts["candidate_id"])
print(json.dumps({"candidate":candidate,"manifest":p.reference(path),"terminal":p.reference(terminal),
 "context":p.reference(context.root/"provenance.json"),"capture_limits":manifest["preparation"][b.FIELD]["capture_limits"],
 "facts":facts,"scientific_credit":False},sort_keys=True))
'''

# The historical subprocess program above remains literal and unchanged for
# every existing selection audit.  This successor changes only its Source
# authority: the v3 HOST reader can authenticate q083's typed zero-credit
# preparation deferral before reading a later actually admitted terminal.
_AUDIT_PROGRAM_V3 = _AUDIT_PROGRAM.replace(
    'from qcsd_lab import supplied_static_budget_successor as b',
    'from qcsd_lab import supplied_static_completed_get_deferral as typed\n'
    'if typed.REASON!="actual-complete-native-get-preparation-no-successful-secondary":'
    'raise ValueError("v3 typed deferral Source changed")\n'
    'from qcsd_lab import supplied_static_budget_successor as b')

# Retain both historical programs byte for byte. The successor binds the
# reviewed full HOST Source and accounting authority before any prefix reopen.
# Its action closes fresh observations before the process returns success.
_AUDIT_PROGRAM_V3_SCOPED = (
    _AUDIT_PROGRAM_V3.split('context=b.load_context', 1)[0] + r'''
import importlib.util
from qcsd_lab import rapid_admission_operation_facts as observed
from qcsd_lab import supplied_static_bootstrap_get as bootstrap
spec=importlib.util.spec_from_file_location("selected_budget_host_accounting",root/"tools/rapid_static_accounting.py")
tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)
with observed.action() as action:
    files=tool.bind_source(action,Path(sys.argv[4]),sys.argv[5])
    with bootstrap.host_accounting_scope(action,Path(sys.argv[6]),sys.argv[7]):
''' + '\n'.join('        ' + line for line in (
        'context=b.load_context' + _AUDIT_PROGRAM_V3.split('context=b.load_context', 1)[1]).splitlines()) + r'''
    if set(files)!=tool._names():raise ValueError("selected v3 audit HOST Source membership changed")
''')


def _v3_inventory(source_root: Path, inventory: Mapping[str, Any], authority: Mapping[str, Any], *, full: bool) -> dict:
    """Reopen the independently closed v3 HOST reader without replacing Core002."""
    path = plain.reopen(inventory)
    authority_path = plain.reopen(authority)
    if inventory['sha256'] != V3_HOST_INVENTORY_SHA256 or authority['sha256'] != V3_HOST_AUTHORITY_SHA256:
        raise ValueError('selected v3 audit requires the reviewed typed HOST inventory and authority')
    value = get._load(get._read(path))
    record = get._load(get._read(authority_path))
    source_root = source_root.absolute()
    files = value.get('files')
    if (not isinstance(files, dict) or len(files) != 2656
            or value.get('source_root') != str(source_root)
            or record.get('artifact_type') != 'qcsd-host-accounting-complete-get-preparation-deferral-authority-v3'
            or record.get('schema_version') != 3 or record.get('source_root') != str(source_root)
            or record.get('source_inventory') != dict(inventory)
            or record.get('original_inventory', {}).get('sha256') != ORIGINAL_CORE_INVENTORY_SHA256
            or record.get('preparation_deferral_policy') !=
                'host-authenticated-original-complete-get-zero-successful-nonempty-secondary-no-credit-v1'):
        raise ValueError('selected v3 audit lost its complete original and typed HOST authority')
    exact = {
        'supplied_static_admission.py': V3_ADMISSION_SOURCE_SHA256,
        'supplied_static_completed_get_deferral.py': V3_DEFERRAL_SOURCE_SHA256,
        'supplied_static_budget_successor.py': graph.digest(get._read(Path(budget.__file__))),
        'supplied_static_preparation.py': graph.digest(get._read(Path(original.__file__))),
        'supplied_static_get.py': graph.digest(get._read(Path(get.__file__))),
        'supplied_static_graph.py': graph.digest(get._read(Path(graph.__file__))),
    }
    for name, expected in exact.items():
        relative = 'src/qcsd_lab/' + name
        ref = files.get(relative)
        if (not isinstance(ref, dict) or ref.get('sha256') != expected
                or ref.get('mode') != 0o644 or full and graph.digest(get._read(source_root / relative)) != expected):
            raise ValueError('selected v3 audit changed an original or typed admission validator')
    for key, expected in (('preparation_deferral_source', V3_DEFERRAL_SOURCE_SHA256),):
        member = record.get(key)
        if (not isinstance(member, dict) or member.get('sha256') != expected
                or member.get('path') != str(source_root / 'src/qcsd_lab/supplied_static_completed_get_deferral.py')
                or full and plain.reopen(member) != source_root / 'src/qcsd_lab/supplied_static_completed_get_deferral.py'):
            raise ValueError('selected v3 typed source is not the authenticated authority file')
    if full:
        source_root = lanes._regular_directory(source_root)
        members = set()
        for prefix in ('', 'neqo-qcsd/'):
            directory = source_root / prefix
            for arguments in (('ls-files', '-z'), ('ls-files', '--others', '--exclude-standard', '-z')):
                result = subprocess.run(['git', '-C', str(directory), *arguments], check=True, capture_output=True)
                members.update(prefix + name.decode() for name in result.stdout.split(b'\0')
                               if name and name != b'neqo-qcsd')
        if members != set(files):
            raise ValueError('selected v3 audit full HOST Source membership changed')
        for relative, item in files.items():
            member = Path(relative)
            if (member.is_absolute() or '..' in member.parts or not isinstance(item, dict)
                    or set(item) != {'sha256', 'mode'}):
                raise ValueError('selected v3 inventory member escapes its checkout')
            candidate = source_root / member
            if (candidate.is_symlink() or not candidate.is_file()
                    or graph.digest(get._read(candidate)) != item['sha256']
                    or candidate.stat().st_mode & 0o7777 != item['mode']):
                raise ValueError('selected v3 audit full HOST Source bytes or mode changed')
    return value


def _inventory(source_root: Path, inventory: Mapping[str, Any], *, full: bool) -> dict:
    path = plain.reopen(inventory)
    if inventory["sha256"] != ORIGINAL_CORE_INVENTORY_SHA256:
        raise ValueError("budget audit requires the independently closed original Core002 inventory")
    value = get._load(get._read(path))
    files = value.get("current")
    if not isinstance(files, dict) or len(files) != 2485:
        raise ValueError("budget audit requires a full explicit original Source inventory")
    source_root = source_root.absolute()
    if full:
        source_root = lanes._regular_directory(source_root)
    if value["author_root"] != str(source_root):
        raise ValueError("budget audit Source is not its approved original inventory checkout")
    for relative, ref in files.items():
        member = Path(relative)
        if member.is_absolute() or ".." in member.parts:
            raise ValueError("budget audit Source inventory escapes its original checkout")
        bound = plain.reopen({**ref, "mode": int(ref["mode"], 8)}) if full else Path(ref["path"])
        if bound != source_root / member:
            raise ValueError("budget audit Source inventory belongs to another original checkout")
    for module in (budget, original, get, graph):
        key = "src/qcsd_lab/" + module.__name__.rsplit(".", 1)[1] + ".py"
        ref = files.get(key)
        if ref is None or ref["sha256"] != graph.digest(get._read(Path(module.__file__))):
            raise ValueError("budget audit changes an original budget/GET validator")
    if full:
        # Check the complete approved Source membership, including prospective
        # untracked author files and the separately tracked Native submodule.
        members = set()
        for prefix in ("", "neqo-qcsd/"):
            directory = source_root / prefix
            for args in (("ls-files", "-z"), ("ls-files", "--others", "--exclude-standard", "-z")):
                result = subprocess.run(["git", "-C", str(directory), *args], check=True, capture_output=True)
                members.update(prefix + name.decode() for name in result.stdout.split(b"\0") if name and name != b"neqo-qcsd")
        if members != set(files):
            raise ValueError("budget audit original Source membership differs from its approved full inventory")
    return value


def audit_budget(output: Path, *, source_root: Path, source_inventory: Mapping[str, Any],
                 context: Path, terminal: Path, host_authority: Mapping[str, Any] | None = None) -> Path:
    """Create an immutable original-authority operation, granting zero credit."""
    source_root = source_root.absolute()
    auditor = (_inventory if host_authority is None else
               lambda root, inventory, *, full: _v3_inventory(root, inventory, host_authority, full=full))
    program = _AUDIT_PROGRAM if host_authority is None else _AUDIT_PROGRAM_V3_SCOPED
    before_inventory = auditor(source_root, source_inventory, full=True)
    command = [sys.executable, "-I", "-B", "-c", program,
               str(source_root), str(context.absolute()), str(terminal.absolute())]
    if host_authority is not None:
        command.extend([source_inventory['path'], source_inventory['sha256'],
                        host_authority['path'], host_authority['sha256']])
    output = output.absolute()
    get.util.require_disjoint_path(output, [source_root, context, terminal], label="budget selection audit")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    started = {"schema_version": 1, "command": command, "started_at": receipts._now(),
        "source_inventory": dict(source_inventory), "context": plain.reference(context / "provenance.json"),
        "terminal": plain.reference(terminal)}
    if host_authority is not None:
        started['host_authority'] = dict(host_authority)
    receipts.durable_create(output / "audit-started.json", graph.canonical_bytes(started))
    before = time.monotonic()
    result = subprocess.run(command, check=False, capture_output=True)
    for name, raw in (("audit.stdout.log", result.stdout), ("audit.stderr.log", result.stderr)):
        receipts.durable_create(output / name, raw)
    completed = {"schema_version": 1, "returncode": result.returncode,
        "elapsed_seconds": time.monotonic() - before, "completed_at": receipts._now(),
        "started": plain.reference(output / "audit-started.json"),
        "stdout": plain.reference(output / "audit.stdout.log"), "stderr": plain.reference(output / "audit.stderr.log")}
    receipts.durable_create(output / "audit-completed.json", graph.canonical_bytes(completed))
    if result.returncode != 0:
        raise ValueError("original budget authority audit failed; raw attempts remain")
    if auditor(source_root, source_inventory, full=True) != before_inventory:
        raise ValueError("original budget audit Source changed during its operation")
    payload = {"contract": CONTRACT, "source_root": str(source_root), "source_inventory": dict(source_inventory),
        "program_sha256": graph.digest(program.encode()), "result": get._load(result.stdout),
        "started": plain.reference(output / "audit-started.json"), "completed": plain.reference(output / "audit-completed.json"),
        "stdout": plain.reference(output / "audit.stdout.log"), "stderr": plain.reference(output / "audit.stderr.log"),
        "published_at": receipts._now(), "scientific_credit": False}
    if host_authority is not None:
        payload['host_authority'] = dict(host_authority)
    path = output / "selection-audit.json"
    receipts.durable_create(path, graph.canonical_bytes(receipts._bind(AUDIT_TYPE, payload)))
    read_audit(path)
    return path


def read_audit(path: Path) -> dict:
    value = receipts._unpack(get._read(path), AUDIT_TYPE)
    v3 = 'host_authority' in value
    programs = (_AUDIT_PROGRAM_V3, _AUDIT_PROGRAM_V3_SCOPED) if v3 else (_AUDIT_PROGRAM,)
    program = next((item for item in programs if graph.digest(item.encode()) == value.get('program_sha256')), None)
    if program is None:
        raise ValueError('budget audit program is outside the retained or scoped authority')
    scoped = program == _AUDIT_PROGRAM_V3_SCOPED
    fields = {"contract", "source_root", "source_inventory", "program_sha256", "result", "started",
        "completed", "stdout", "stderr", "published_at", "scientific_credit"}
    get._exact(value, fields | ({'host_authority'} if v3 else set()), "budget selection audit")
    started = get._load(get._read(plain.reopen(value["started"])))
    completed = get._load(get._read(plain.reopen(value["completed"])))
    stdout = get._read(plain.reopen(value["stdout"]))
    plain.reopen(value["stderr"])
    row = get._exact(value["result"], {"candidate", "manifest", "terminal", "context", "capture_limits", "facts",
        "scientific_credit"}, "budget audited class")
    if (value["contract"] != CONTRACT or value["scientific_credit"] is not False or row["scientific_credit"] is not False
            or value["program_sha256"] != graph.digest(program.encode())
            or not isinstance(started.get("command"), list) or len(started["command"]) != (12 if scoped else 8)
            or not Path(started["command"][0]).is_absolute()
            or started["command"][1:6] != ["-I", "-B", "-c", program, value["source_root"]]
            or started["command"][6] != str(Path(started["context"]["path"]).parent)
            or started["command"][7] != started["terminal"]["path"]
            or (scoped and started['command'][8:] != [value['source_inventory']['path'], value['source_inventory']['sha256'],
                                                       value['host_authority']['path'], value['host_authority']['sha256']])
            or started.get("schema_version") != 1 or type(started["schema_version"]) is not int
            or completed.get("schema_version") != 1 or type(completed["schema_version"]) is not int
            or started["source_inventory"] != value["source_inventory"]
            or (v3 and started.get('host_authority') != value['host_authority'])
            or (not v3 and 'host_authority' in started)
            or completed["started"] != value["started"] or completed["stdout"] != value["stdout"]
            or completed["stderr"] != value["stderr"] or type(completed["returncode"]) is not int or completed["returncode"] != 0
            or type(completed["elapsed_seconds"]) not in (int, float) or not math.isfinite(completed["elapsed_seconds"])
            or completed["elapsed_seconds"] <= 0 or get._load(stdout) != row
            or not get._time(started["started_at"]) < get._time(completed["completed_at"]) <= get._time(value["published_at"]) <= get._time(receipts._now())
            or row["facts"].get("outcome") != "admitted" or row["facts"].get("candidate_id") != row["candidate"]["candidate_id"]
            or row["capture_limits"] != budget.static.capture_limits(budget.RESPONSE_BYTES, budget.RECORDING_MEGABYTES)
            or row["context"] != {key: started["context"][key] for key in ("path", "sha256")}
            or row["terminal"] != {key: started["terminal"][key] for key in ("path", "sha256")}):
        raise ValueError("budget audit changes its command, original Source, complete admission, caps or raw closure")
    # The completed operation binds the full original inventory; per-trace
    # membership reads retain that artifact without replaying its Source tree.
    if v3:
        _v3_inventory(Path(value['source_root']), value['source_inventory'], value['host_authority'], full=False)
    else:
        _inventory(Path(value["source_root"]), value["source_inventory"], full=False)
    for key in ("context", "terminal"):
        plain.reopen(started[key])
    for key in ("manifest", "context", "terminal"):
        original.open_reference(row[key])
    return value


def input_metadata(ref: Mapping[str, Any]) -> tuple[dict, dict]:
    value = receipts._unpack(get._read(plain.reopen(ref)), RECEIPT_TYPE)
    get._exact(value, FIELDS, "selected budget input")
    audited = read_audit(plain.reopen(value["selection_audit"]))
    row = audited["result"]
    manifest = get._load(get._read(plain.reopen(value["original_manifest"])))
    if (value["contract"] != CONTRACT or value["original_role"] != budget.ROLE
            or value["scientific_credit"] is not False or type(value["formal_accepted_trace_count"]) is not int
            or value["formal_accepted_trace_count"] != 0 or not budget.is_budget(manifest["preparation"])
            or row["manifest"] != {key: value["original_manifest"][key] for key in ("path", "sha256")}
            or value["candidate_id"] != row["candidate"]["candidate_id"]
            or value["workload_id"] != plain.reopen(value["original_manifest"]).stem
            or value["canonical_sites"] != old_ledger._aliases(row["candidate"], manifest)
            or value["capture_limits"] != row["capture_limits"]
            or value["budget_terminal"] != {**row["terminal"], "mode": plain.reference(original.open_reference(row["terminal"]))["mode"]}
            or value["budget_context"] != {**row["context"], "mode": plain.reference(original.open_reference(row["context"]))["mode"]}
            or not get._time(audited["published_at"]) <= get._time(value["declared_at"]) <= get._time(receipts._now())):
        raise ValueError("selected budget input replaces its original class, caps, role or chronology")
    return value, row


def _underlying(value: dict, manifest: dict) -> dict:
    evidence = manifest["preparation"].get(budget.FIELD)
    get._exact(evidence, {"schema_version", "record_type", "context", "position", "original_terminal", "original_manifest",
        "proof", "capture_limits"}, "selected original budget evidence")
    underlying = get._load(get._read(plain.reopen(value["underlying_manifest"])))
    terminal = receipts._unpack(get._read(plain.reopen(value["budget_terminal"])), budget.TERMINAL_TYPE)
    context = receipts._unpack(get._read(plain.reopen(value["budget_context"])), budget.CONTEXT_TYPE)
    if (type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1 or evidence["record_type"] != budget.EVIDENCE_TYPE
            or evidence["original_manifest"] != {key: value["underlying_manifest"][key] for key in ("path", "sha256")}
            or evidence["context"] != {key: value["budget_context"][key] for key in ("path", "sha256")}
            or evidence["capture_limits"] != value["capture_limits"] or context["capture_limits"] != value["capture_limits"]
            or terminal["prepared_workload"] != {key: value["original_manifest"][key] for key in ("path", "sha256")}
            or terminal["outcome"] != "admitted" or terminal["candidate_id"] != value["candidate_id"]
            or terminal["context"] != evidence["context"] or terminal["position"] != evidence["position"]
            or terminal["original_terminal"] != evidence["original_terminal"] or terminal["capture_limits"] != value["capture_limits"]
            or not budget.refs.zero(terminal) or not original.is_static(underlying["preparation"])
            or evidence["proof"] != {key: value["proof"][key] for key in ("path", "sha256")}
            or budget._wrap(underlying, evidence) != manifest):
        raise ValueError("selected budget receipt changes its genuine budget wrapper or original complete graph")
    return underlying


def _validate_input_uncached(path: Path) -> tuple[dict, dict, dict]:
    value, _ = input_metadata(plain.reference(path))
    expected = direct_sources()
    legacy = {**expected, __name__: LEGACY_SELECTED_SOURCE_SHA256}
    v3 = {**expected, __name__: V3_SELECTED_SOURCE_SHA256}
    if value['direct_validator_sources'] not in (expected, legacy, v3):
        raise ValueError('selected budget direct verifier Source changed')
    if (value['direct_validator_sources'] == legacy
            and 'host_authority' in read_audit(plain.reopen(value['selection_audit']))):
        raise ValueError('v3 typed audit cannot claim the historical selected verifier')
    if (value['direct_validator_sources'] == v3
            and read_audit(plain.reopen(value['selection_audit']))['program_sha256'] ==
                graph.digest(_AUDIT_PROGRAM_V3_SCOPED.encode())):
        raise ValueError('scoped v3 audit cannot claim the earlier unscoped selected verifier')
    plain._bound_validator_files(value)
    manifest = get._load(get._read(plain.reopen(value["original_manifest"])))
    underlying = _underlying(value, manifest)
    proof = plain._raw_selected_proof({**value, "original_role": original.ROLE}, underlying)
    return value, manifest, proof


def _input_dependencies(path: Path, context) -> tuple[set[Path], set[Path]]:
    """Observe only the selected input's declared metadata and complete GET."""
    raw = context.watch_file(path)
    key = ("selected-budget-input-dependencies", str(path.absolute()), graph.digest(raw))
    if context.has(key):
        return context.get(key)
    for module in _modules():
        context.watch_file(Path(module.__file__))
    context.watch_file(Path(facts.__file__))
    value = receipts._unpack(raw, RECEIPT_TYPE)
    get._exact(value, FIELDS, "selected budget input")
    files = {path.absolute()}

    def follow(ref):
        # Register exact bytes before either reference reader authenticates
        # them; the closing operation fence detects modes and membership too.
        target = context._reference(ref)
        if "mode" in ref:
            plain.reopen(ref)
        else:
            original.open_reference(ref)
        files.add(target)
        return target

    for name in ("selection_audit", "original_manifest", "underlying_manifest", "proof",
                 "budget_terminal", "budget_context"):
        follow(value[name])
    for ref in value["direct_validator_files"].values():
        follow(ref)
    files.update(Path(module.__file__).absolute() for module in _modules())
    audit_path = follow(value["selection_audit"])
    audit = receipts._unpack(context.watch_file(audit_path), AUDIT_TYPE)
    for name in ("started", "completed", "stdout", "stderr", "source_inventory") + (
            ("host_authority",) if "host_authority" in audit else ()):
        follow(audit[name])
    started = get._load(context.watch_file(Path(audit["started"]["path"])))
    for name in ("context", "terminal"):
        follow(started[name])
    for name in ("manifest", "context", "terminal"):
        follow(audit["result"][name])
    if value["namespace"] is not None:
        for name in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"):
            follow(value["namespace"][name])
    trees = {Path(value["raw_root"]).absolute()}
    for tree in trees:
        context.watch_tree(tree)
    return context.remember(key, (files, trees))


def validate_input(path: Path) -> tuple[dict, dict, dict]:
    """Reuse one genuine selected proof only within its active operation."""
    context = facts.current_context()
    if context is None:
        return _validate_input_uncached(path)
    raw = context.watch_file(path)
    key = ("selected-budget-input", str(path.absolute()), graph.digest(raw))
    if context.has(key):
        return context.get(key)
    _input_dependencies(path, context)
    result = _validate_input_uncached(path)
    context.check()
    return context.remember(key, result)


def publish_input(output: Path, *, audit: Path, candidate_id: str) -> Path:
    audited = read_audit(audit)
    row = audited["result"]
    if row["candidate"]["candidate_id"] != candidate_id:
        raise ValueError("budget input selects another audited candidate")
    path = original.open_reference(row["manifest"])
    manifest = get._load(get._read(path))
    wrapper = manifest["preparation"][budget.FIELD]
    underlying_path = original.open_reference(wrapper["original_manifest"])
    underlying = get._load(get._read(underlying_path))
    evidence = underlying["preparation"]["static_get_evidence"]
    root = Path(evidence["root"])
    declaration = get._load(get._read(root / "declaration.json"))
    value = {"contract": CONTRACT, "original_manifest": plain.reference(path), "original_role": budget.ROLE,
        "candidate_id": candidate_id, "workload_id": path.stem, "canonical_sites": old_ledger._aliases(row["candidate"], manifest),
        "selection_audit": plain.reference(audit), "raw_root": str(root), "raw_inventory": facts._tree(root),
        "proof": plain.reference(original.open_reference(evidence["proof"])), "declaration": declaration,
        "namespace": evidence["namespace"], "neutral": get._load(get._read(root / "neutral-input.json")),
        "approved_origins": underlying["preparation"]["approved_origins"], "capture_limits": row["capture_limits"],
        "measurement_runtime": evidence["runtime_binding"], "recorded_producer_sources": declaration["producer_sources"],
        "direct_validator_sources": direct_sources(), "direct_validator_files": {module.__name__: plain.reference(Path(module.__file__)) for module in _modules()},
        "declared_at": receipts._now(), "scientific_credit": False, "formal_accepted_trace_count": 0,
        "budget_terminal": plain.reference(original.open_reference(row["terminal"])),
        "budget_context": plain.reference(original.open_reference(row["context"])), "underlying_manifest": plain.reference(underlying_path)}
    _underlying(value, manifest)
    plain._raw_selected_proof({**value, "original_role": original.ROLE}, underlying)
    get.util.require_disjoint_path(output.absolute(), [root, path, underlying_path, audit], label="selected budget input")
    receipts.durable_create(output, graph.canonical_bytes(receipts._bind(RECEIPT_TYPE, value)))
    return output


def prepare_input(path: Path, output: Path) -> Path:
    _, manifest, _ = validate_input(path)
    get.util.require_disjoint_path(output.absolute(), [path, plain.reopen(receipts._unpack(get._read(path), RECEIPT_TYPE)["original_manifest"])], label="selected budget manifest")
    prepared = deepcopy(manifest)
    prepared["preparation"].update(data_role=ROLE, **{FIELD: {"schema_version": 1, "record_type": RECEIPT_TYPE, "receipt": plain.reference(path)}})
    receipts.durable_create(output, graph.canonical_bytes(prepared))
    return output


def validate_preparation(value: Mapping[str, Any], resources: list[dict]) -> dict:
    if not is_selected(value):
        raise ValueError("selected budget preparation role is absent")
    evidence = get._exact(value.get(FIELD), {"schema_version", "record_type", "receipt"}, "selected budget evidence")
    if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1 or evidence["record_type"] != RECEIPT_TYPE:
        raise ValueError("selected budget evidence has another authority")
    _, manifest, proof = validate_input(plain.reopen(evidence["receipt"]))
    expected = deepcopy(manifest)
    expected["preparation"].update(data_role=ROLE, **{FIELD: dict(evidence)})
    if expected != {"preparation": dict(value), "resources": resources}:
        raise ValueError("selected budget capture changes its complete original graph or policies")
    return proof


def preparation_inputs(value: Mapping[str, Any], resources: list[dict]) -> tuple[set[Path], set[Path]]:
    validate_preparation(value, resources)
    path = plain.reopen(value[FIELD]["receipt"])
    context = facts.current_context()
    if context is not None:
        return _input_dependencies(path, context)
    payload = receipts._unpack(get._read(path), RECEIPT_TYPE)
    audit_path = plain.reopen(payload["selection_audit"])
    audit = read_audit(audit_path)
    files = {path, audit_path, *(plain.reopen(payload[key]) for key in
        ("original_manifest", "underlying_manifest", "proof", "budget_terminal", "budget_context")),
        *(plain.reopen(audit[key]) for key in ("started", "completed", "stdout", "stderr", "source_inventory"))}
    files.update(plain._bound_validator_files(payload))
    files.update(Path(module.__file__).absolute() for module in _modules())
    if payload["namespace"] is not None:
        files.update(original.open_reference(payload["namespace"][key]) for key in
            ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
    return files, {Path(payload["raw_root"])}


def preparation_roots(value: Mapping[str, Any], resources: list[dict]) -> list[Path]:
    files, trees = preparation_inputs(value, resources)
    payload = receipts._unpack(get._read(plain.reopen(value[FIELD]["receipt"])), RECEIPT_TYPE)
    files.difference_update({Path(module.__file__).absolute() for module in _modules()} - plain._bound_validator_files(payload))
    return sorted(trees | {path.parent for path in files})
