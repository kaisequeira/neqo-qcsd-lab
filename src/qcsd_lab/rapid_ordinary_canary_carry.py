"""An explicit ordinary authority over a separately labelled measured canary.

The original successful canary is read by its authenticated frozen reader.
The current trusted reader authenticates both installed runtimes. This type
never states that the old sample ran the new Source or image, authorizes a
defended setting, or changes any original evidence or scientific counter.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from datetime import datetime, timezone

from . import rapid_lane_evidence as lanes
from . import rapid_rolling_readiness as ready
from . import rapid_rolling_schedule as schedule
from . import rapid_rolling_capture as rolling
from . import rapid_undefended_capture as ordinary
from . import rapid_epoch_corpus as epoch
from . import rapid_partial_lane as observer
from . import rapid_selected_capture_input as selected
from .rapid_operation_facts import OperationFacts, current_context

TYPE = "qcsd-current-ordinary-measured-canary-control-carry-v1"
CONTRACT = "original-successful-ordinary-canary-distinct-current-control-authority-v1"
ORIGINAL_HEAD = "9e5dd93eda4419bc56795c443cc67bc89f201fa0"
ORIGINAL_CANONICAL = "ca2084e6fa183d8edc46fc720d845376352294fce4b8838decf86e8783f0d3be"
INDIVIDUAL_EVIDENCE_SHA256 = "1aca09fad12067ae257140cd93a7172188d44a6d059684427d41dadd406451b3"
INDIVIDUAL_POLICY_TYPE = "qcsd-ordinary-native-label-distinct-full-manifest-primary-authority-v1"
REFERENCE_KEYS = {"schema_version", "artifact_type", "carry"}
FILES = ("rapid_ordinary_canary_carry.py", "rapid_rolling_readiness.py",
         "rapid_operation_facts.py", "rapid_undefended_capture.py",
         "rapid_ordinary_parallel_schedule.py", "rapid_rolling_schedule.py",
         "rapid_epoch_corpus.py", "rapid_partial_lane.py")
# Populated with exact reviewed original/current module pairs. Every other
# protected file, full Native complement, launcher and traffic file stays exact.
MODE_SAFE_PAIRS = {'src/qcsd_lab/capture_acceptance_policy.py': {'original_sha256': '31dbeb9d01ab2a58b1478969388de558262c7a52768b202eb08f1cf801306466', 'current_sha256': '7eb599484082c59798e92466b5a56f267f772a98900975bcc41957d6b381e262', 'units': {'terminal_primary_capture_cell_size': {'original': '5be553b0df13292a6ecdfb32ff5502937b79e5c616d47274d9b28803975474fa', 'current': 'f2da333df343989865a021b83e5a5b4704460ea854aa5b6a3617917ecd245b04'}, 'validate_terminal_primary_partial_evidence': {'original': 'b2e214cf6630d1a704b6b39ab5bb14d533d8b16edc25937f1f9b3cdd2973e437', 'current': '0ba1fbb59f038fc3943cc572580685e24eda4e177ebff9a588e0aeff42b18c0e'}, 'validate_terminal_primary_source_binding': {'original': '978fcb819c57690b1be38776f6c5a5815b4a6234a064587838f9bb34fd31750a', 'current': '28b73cb3bd42288623de1c89a657dd19e00e92a33f19c20409c8e7c87338639e'}}}, 'src/qcsd_lab/capture_session.py': {'original_sha256': 'cfe41199ddd256b468cda729fb444f3ded3d040bc1cdded420fe5aa01b570d7b', 'current_sha256': '818501d472a2df4875d645023a7dfe87d0973f7a8ce162ff4c38b013769c6ae7', 'units': {'_client_command': {'original': '31bebfd8071a020bf42ab821f620fece312cccdfd38c9ed7786876bb33a10a49', 'current': 'bb9379d9d3700d3450aa537187eaa1d9315da9c07fe1f7621cc42d772473ca01'}, '_validate_run_binding': {'original': '06dc4855e4d2ee226f96bc6d79c9f527af8bebc250ce3ac1f6786e5b3894645c', 'current': '7f7de598c74ae08b1977d3a815eec87546586085d937dac4fc74336a290d1f45'}}}, 'src/qcsd_lab/experiment.py': {'original_sha256': 'ed1f1e4cc1776930bbeab61b4ff2c784959127e80db97c6315a6e46aa3b2ee7c', 'current_sha256': 'd9272511f2f16c6bdc979d80d01a0798a48461708aaa11dc39b145472d549b44', 'units': {'_OPTIONAL_CONFIGURATION_KEYS': {'original': 'c62a06cdabd8bcce03d704ad5b1788c0c11f4af216b79e40bba9a11808e683dd', 'current': '853a5ddbf83f5d1bf904ef8f25b05ca73352f6e1b702810d2ef4a47557581a29'}, '_validate_configuration': {'original': 'c2eb51ff7ea5df62d2eda332de1658e2cfe61b760efb795b39126d27393aa37e', 'current': '6e1f0a0df01be3ce3e10c019985598d6cdd26b779f1824455ecfcd2e15257de9'}}}, 'src/qcsd_lab/fidelity.py': {'original_sha256': 'a5d07f41f6cfe0648f2ad1d6e766562338d20de09dc0042472dbb7fa9e9af579', 'current_sha256': 'ae953aea2597de72f4e96d7dac057e7652f9ce0a0872b2591db0a93f13eb1130', 'units': {'_schedule_realization_metrics': {'original': '8764d598328bcc63e664558152bd3dfb5718d9820c2682e49c4374f179cbcc9a', 'current': '2329ef339615c4a636a77ca38ca519e4d18bcd032871efcbaad455bdacb20ae7'}, '_schedule_realization_metrics_from_path': {'original': '499f22c2b977c6b4f52cebb06cee2bc47aa4dd28245e8ad18189e64f1085df8c', 'current': '46782c7401314b376b7a77425093241a7e4afa0368cd96746f4dcb5ee8d3e68e'}, '_terminal_primary_partial_metrics': {'original': '9b3465f14d29944fc261c1a8a8b3b4a2a7d884e02e4411b8bef99d1245856353', 'current': '78d8ed64eac9c5b178152311bfea1b17934c3af219fd0beeca1833ad2adda1e9'}}}, 'src/qcsd_lab/orchestrator.py': {'original_sha256': 'c6ae54337ba2e40347ee6d6bc6b95daa54c424bcd4fb4ae5194de8fcad5e73ce', 'current_sha256': '6b7417052e27a7f35953b4ff363c9d93acaeb75adeeb35d3258f5ede6e925e6b', 'units': {'Campaign': {'original': '9565d304c870676f8f51e7893b3f79dfa00f230b7226072176b32b4c3e22e7d6', 'current': '07875e0122a265a924193f6c4b4ed8ed4d02b7d861638f894d1ebdf2236813ae'}, 'LEGACY_CAMPAIGN_KEYS': {'original': '46b2c7ccfe7197d17649449436c0d984271d56cbe7062755ad0c9e81f6d91d4f', 'current': 'f8939f1f0f617d6597ecbeaf2c0b7b69af03a7684a770d820ce8cf60ff84f2d6'}, '_RunContext': {'original': '0d6b4f4fefdc0e05909d200242cc5fc7c4a38009792df30ccd65ba50ed800ac1', 'current': 'c9f97f423c9c122b437e3f23a30473765a7a828b48488444aa8c8cdfaee926a0'}, '_compare_group': {'original': '10e4ef24b1134833c9936fa13a83288fb79e454fdfb8305b5c9401a3c6610039', 'current': 'd2d7157564b2ed13ccbf286cadd9b213c309c06768a786cf9df89115ab985737'}, '_execute': {'original': 'bf239d4224e2cea41cd685c8d1b68eb4c6b8f3e38a93fcc73d77e058d1c1b5a8', 'current': '6d7659e51724a010f9d6f5c33e7236b8c554d7fb2dc7830913b8ed54f4b34286'}, '_frozen_configuration': {'original': 'c7c0385bd579dc9a9f0b861745b3722386ec60ad2025d194128713edbfc722b1', 'current': 'c1d6b0bde60a9ed0da07b5194ff08d52380e327f18e59e60d8ea7b89d86a48c7'}, '_intrinsic_fidelity_failure': {'original': '61cb43daa1b76e0a2297c387fe4a88094091727204f31228e1b2b378c3c83488', 'current': '28bb74eeb87f3ec0f4d4dbf0996780438c3d1688fa370414784d6f5c6cfeeea3'}, '_load_campaign': {'original': '74756a906fa6cd2893672e63cdbdfff3dd7d101d4670118873165e78eb92e691', 'current': '0467f75be95843143a569f5e14608a2818277f420a45f68e0b668da5686fafe1'}, '_materialize_inputs': {'original': '14c24d2811df1019da8f4dcb91080b47bc51cb50b7914c68b60aacd2e5df7126', 'current': '2c9a05a0ad6bb24aa00680abb7fee4da9c2b1115741c91bb33ca3e91df517ac0'}, '_recover_completed_attempt': {'original': '845bfe4c61b938fa066b0445617925f1cdd75464f90d0d41c904adbe651c10cd', 'current': '9a94c8245d2c3cc68d1742853886d45cfb6a31587b44b27141b7c9028741870e'}}}, 'src/qcsd_lab/verification.py': {'original_sha256': '765a3765fb77e3e8ae40ab327c2487bb525a14d03d54a9d2f752a8ce4e75a593', 'current_sha256': '5aac78e1ce65b21141d82186983e58f1f2b23631208ff2f4e058a38679bb7aef', 'units': {'_validate_policy_application_responses': {'original': '7c34aca1bb00721657941d50eb8290d9680c170206f01e117b4e2430efd5bc7e', 'current': '1fe2232127feca8a02fe923662b0f2018722a8fea15d39903e4b4863b76a2649'}}}}
TAMARAW_MODULE_SHA256 = "50ce06e201a6e93f1039be3352d2ef9743e75aa07536da54441ae7c1157a7117"
KEYS = {"schema_version", "artifact_type", "contract", "original_canary",
    "original_runtime", "original_canonical", "current_runtime", "current_canonical",
    "current_input", "original_operation", "original_facts", "authority_source",
    "authority_workload_sha256", "graph_bindings", "capture_limits", "body_policy",
    "dependency_groups", "mode_safe_units", "consumer_sources", "published_at",
    "reason", "scientific_credit", "formal_accepted_trace_count", "individual_evidence",
    "individual_primary_authority"}


def _read(path):
    context = current_context()
    return lanes._read(Path(path)) if context is None else context.watch_file(Path(path))


def reference(path):
    path = Path(path).absolute()
    _read(path)
    return selected.reference(path)


def _open(ref):
    # Register before authentication, including the complete permission mode.
    _read(Path(ref["path"]))
    return selected.reopen(ref)


def _sources():
    return {name: reference(Path(__file__).parent / name) for name in FILES}


def _units(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            key = node.name
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            key = ",".join(sorted(n.id for target in targets for n in ast.walk(target)
                                  if isinstance(n, ast.Name)))
        else:
            key = ast.dump(node, include_attributes=False)
        if key in result:
            raise ValueError("ordinary carry projection repeats a top-level code unit")
        result[key] = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
    return result


def protected_groups(original_root, current_root, original_inventory, current_inventory):
    """Only the exact reviewed TAM branches can differ for an ordinary run."""
    old, _ = ready._groups(original_root, original_inventory)
    new, _ = ready._groups(current_root, current_inventory)
    changed = {}
    for group in old:
        if set(old[group]) != set(new[group]):
            raise ValueError("ordinary carry changes a protected dependency membership")
        for name in old[group]:
            if ":" in name:
                if old[group][name] != new[group][name]:
                    raise ValueError("ordinary carry changes a protected launcher or preparation unit")
                continue
            a, b = Path(original_root) / name, Path(current_root) / name
            if stat.S_IMODE(a.stat().st_mode) != stat.S_IMODE(b.stat().st_mode):
                raise ValueError("ordinary carry changes a protected full permission mode")
            if old[group][name] == new[group][name]:
                continue
            pair = MODE_SAFE_PAIRS.get(name)
            before, after = _read(a), _read(b)
            if (pair is None or ready._sha(before) != pair["original_sha256"]
                    or ready._sha(after) != pair["current_sha256"]):
                raise ValueError("ordinary carry changes executable request, collector or acceptance code")
            left, right = _units(before), _units(after)
            delta = {key: {"original": left.get(key), "current": right.get(key)}
                     for key in sorted(set(left) | set(right)) if left.get(key) != right.get(key)}
            if delta != pair["units"]:
                raise ValueError("ordinary carry differs from its exact reviewed ordinary-mode code proof")
            changed[name] = delta
            new[group][name] = old[group][name]
    # The inherited shell projector is intentionally stricter in this role.
    if _read(Path(original_root) / "qcsd-lab") != _read(Path(current_root) / "qcsd-lab"):
        raise ValueError("ordinary carry changes the executable launcher")
    if old != new:
        raise ValueError("ordinary carry changes protected scientific dependencies")
    if ready._sha(_read(Path(current_root) / "src/qcsd_lab/tamaraw_fixed_configuration.py")) != TAMARAW_MODULE_SHA256:
        raise ValueError("ordinary carry changes the reviewed mode selector")
    return {name: {"files": len(entries), "sha256": ready._sha(ready._encoded(entries))}
            for name, entries in old.items()}, changed


def _bind_runtime(canonical_ref, runtime):
    context = current_context()
    rolling._keys(runtime, lanes.RUNTIME_KEYS, "ordinary carry runtime")
    memo_key = (TYPE, "installed-runtime", ready._sha(ready._encoded(canonical_ref)),
           ready._sha(ready._encoded(runtime)), ready._sha(ready._encoded(_sources())))
    if context is not None and context.has(memo_key):
        context.check()
        return context.get(memo_key)
    pending, seen = [canonical_ref], set()
    while pending:
        ref = pending.pop(); path = _open(ref)
        if path in seen:
            raise ValueError("ordinary carry runtime ancestry contains a cycle")
        seen.add(path)
        if context is not None:
            context.watch_tree(path.parent)
        value = lanes._load(_read(path))
        for key in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record", "closure_recipe"):
            if key in value:
                _read(Path(value[key]["path"]))
                rolling._open_ref(value[key])
        if value.get("original_canonical") is not None:
            pending.append(reference(rolling._open_ref(value["original_canonical"])))
    for key in ("runtime_source_root", "module_root"):
        if context is not None:
            context.watch_tree(Path(runtime[key]), ignore_git=True)
    for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        _read(runtime[key])
    canonical, source_files = schedule.reopen_runtime(
        {"path": canonical_ref["path"], "sha256": canonical_ref["sha256"]}, runtime, _inspector=True)
    result = canonical, source_files
    return context.remember(memo_key, result) if context is not None else result


def _runtime_dependency_roots(canonical_ref):
    pending, seen, roots = [canonical_ref], set(), set()
    while pending:
        path = _open(pending.pop())
        if path in seen:
            raise ValueError("ordinary carry runtime root ancestry contains a cycle")
        seen.add(path); roots.add(path.parent)
        value = lanes._load(_read(path))
        for name in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record", "closure_recipe"):
            if name in value:
                _read(Path(value[name]["path"]))
                roots.add(rolling._open_ref(value[name]).parent)
        if value.get("original_canonical") is not None:
            pending.append(reference(rolling._open_ref(value["original_canonical"])))
    return roots


_PROGRAM = observer._PROGRAM.split("facts=OperationFacts();facts.begin_action()", 1)[0] + r'''
from qcsd_lab import rapid_ordinary_group_canary as group
facts=OperationFacts();facts.begin_action()
with facts.scope():
    value=group.validate(q['reference'],runtime=q['runtime'],mode='undefended')
    roots=[str(p) for p in group.roots(q['reference'],runtime=q['runtime'],mode='undefended')]
    facts.check()
for p,v in list(watched.items()):record(p)
for p,v in list(directories.items()):directory(p)
print(json.dumps({'facts':value,'roots':roots,'read_dependencies':list(watched.values()),
 'directory_dependencies':list(directories.values())},sort_keys=True,allow_nan=False))
'''


def _request(reference_value, runtime, audit):
    return {"source_root": runtime["module_root"], "reference": reference_value,
            "runtime": runtime, "scratch_root": str(Path(audit) / "scratch")}


def _close_report(report):
    for ref in report["read_dependencies"]:
        _open(ref)
    context = current_context()
    for row in report["directory_dependencies"]:
        if epoch._directory(Path(row["path"])) != row:
            raise ValueError("ordinary carry original raw membership or directory mode changed")
        if context is not None:
            context.watch_directory(Path(row["path"]), expected=row)


def close_operation(context=None):
    context = context or current_context()
    if context is not None:
        context.check()


def _recorded_operation(reference_value, runtime, operation):
    rolling._keys(operation, {"started.json", "completed.json", "stdout.log", "stderr.log"}, "ordinary carry original reader operation")
    paths = {name: _open(ref) for name, ref in operation.items()}
    if len({p.parent for p in paths.values()}) != 1 or any(p.name != name for name, p in paths.items()):
        raise ValueError("ordinary carry original reader raw namespace changed")
    start = lanes._load(_read(paths["started.json"])); end = lanes._load(_read(paths["completed.json"]))
    command = start.get("command")
    plan = lanes._load(_read(Path(reference_value["plan"]["path"])))
    expected_interpreter = reference(Path(plan["host_python"]).resolve(strict=True))
    if (set(start) != {"command", "request", "interpreter", "started_at"}
            or not isinstance(command, list) or len(command) != 5
            or command[1:] != ["-I", "-B", "-c", _PROGRAM]
            or not isinstance(command[0], str) or not Path(command[0]).is_absolute()
            or reference(Path(start["command"][0]).resolve(strict=True)) != start["interpreter"]
            or start["interpreter"] != expected_interpreter
            or start["request"] != _request(reference_value, runtime, paths["started.json"].parent)
            or set(end) != {"returncode", "completed_at", "stdout_sha256", "stderr_sha256"}
            or type(end["returncode"]) is not int or end["returncode"] != 0
            or any(end[key + "_sha256"] != operation[key + ".log"]["sha256"] for key in ("stdout", "stderr"))
            or not ready._timestamp(start["started_at"]) <= ready._timestamp(end["completed_at"]) <= datetime.now(timezone.utc)):
        raise ValueError("ordinary carry original reader operation or interpreter changed")
    report = lanes._load(_read(paths["stdout.log"]))
    rolling._keys(report, {"facts", "roots", "read_dependencies", "directory_dependencies"}, "ordinary carry original report")
    _close_report(report)
    return report, end


def _run_original(reference_value, runtime, audit_root):
    audit = Path(audit_root).absolute()
    lanes._regular_directory(audit.parent)
    roots = [Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root")]
    roots.append(Path(reference_value["plan"]["path"]).parent)
    if any(audit.is_relative_to(root) or root.is_relative_to(audit) for root in roots):
        raise ValueError("ordinary carry original proof requires a fresh disjoint namespace")
    audit.mkdir(mode=0o755, exist_ok=False); (audit / "scratch").mkdir(mode=0o700, exist_ok=False)
    command = [sys.executable, "-I", "-B", "-c", _PROGRAM]
    plan = lanes._load(_read(Path(reference_value["plan"]["path"])))
    if reference(Path(sys.executable).resolve(strict=True)) != reference(Path(plan["host_python"]).resolve(strict=True)):
        raise ValueError("ordinary carry original reader must use the registered original host Python binary")
    started = {"command": command, "request": _request(reference_value, runtime, audit),
        "interpreter": reference(Path(sys.executable).resolve(strict=True)),
        "started_at": datetime.now(timezone.utc).isoformat()}
    lanes.admission.durable_create(audit / "started.json", ready._encoded(started))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH" and not k.startswith(("QCSD_", "GIT_", "PYTHON"))}
    env["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(command, input=ready._encoded(started["request"]),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
    lanes.admission.durable_create(audit / "stdout.log", result.stdout)
    lanes.admission.durable_create(audit / "stderr.log", result.stderr)
    lanes.admission.durable_create(audit / "completed.json", ready._encoded({"returncode": result.returncode,
        "completed_at": datetime.now(timezone.utc).isoformat(), "stdout_sha256": ready._sha(result.stdout),
        "stderr_sha256": ready._sha(result.stderr)}))
    if result.returncode != 0:
        raise ValueError("ordinary carry original reader refused; actual raw operation retained")
    operation = {name: reference(audit / name) for name in ("started.json", "completed.json", "stdout.log", "stderr.log")}
    return _recorded_operation(reference_value, runtime, operation)[0], operation


def _registered_original(original_canary, original_runtime, original_canonical):
    if (set(original_canary) != ready.REFERENCE_KEYS | {"artifact_type", "reader_sources"}
            or type(original_canary.get("schema_version")) is not int or original_canary.get("schema_version") != 5
            or original_canary.get("artifact_type") != "qcsd-current-ordinary-successful-group-canary-v1"
            or original_canonical.get("sha256") != ORIGINAL_CANONICAL):
        raise ValueError("ordinary carry needs its exact registered successful ordinary measurement")
    old_canonical, old_files = _bind_runtime(original_canonical, original_runtime)
    if old_canonical["source"]["lab_commit"] != ORIGINAL_HEAD:
        raise ValueError("ordinary carry original frozen reader is not the registered installed release")
    source_root = Path(original_runtime["module_root"])
    for name, digest in original_canary["reader_sources"].items():
        if ready._sha(old_files["src/qcsd_lab/" + name]) != digest:
            raise ValueError("ordinary carry original canary reader differs from its trusted installation")
    return old_canonical, old_files


def _derive(original_canary, original_runtime, original_canonical, current_input,
            current_canonical, original_operation, individual_evidence=None):
    old_canonical, old_files = _registered_original(original_canary, original_runtime, original_canonical)
    source_root = Path(original_runtime["module_root"])
    report, completion = _recorded_operation(original_canary, original_runtime, original_operation)
    original = report["facts"]
    input_path = _open(current_input); input_value = lanes._load(_read(input_path))
    runtime_full = rolling._runtime(input_value["runtime"])
    runtime = {key: runtime_full[key] for key in lanes.RUNTIME_KEYS}
    current, current_files = _bind_runtime(current_canonical, runtime)
    executing = Path(__file__).absolute().parents[2]
    if current_context() is not None:
        current_context().watch_tree(executing, ignore_git=True)
    if ready._inventory(executing) != ready._inventory(Path(runtime["runtime_source_root"])):
        raise ValueError("ordinary carry executing consumer differs from the current full installed Source")
    sites = ordinary.validate_inputs(input_path, enrollment=rolling._open_ref(input_value["enrollment"]),
        runtime=runtime_full, require_current=True)
    value = input_value
    client = ready._sha(_read(runtime["client_binary"]))
    if (original.get("mode") != "undefended" or original.get("recorded_image_deep_reopened") is not True
            or client != original["client_sha256"] or client != current["installed_client_sha256"]
            or current["source"]["neqo_commit"] != old_canonical["source"]["neqo_commit"]
            or any(key in original for key in ("tamaraw_configuration_policy", "qualification_delivery_compatibility"))):
        raise ValueError("ordinary carry changed Native client, measurement mode or qualification policy")
    old_plan = lanes._load(_read(original_canary["plan"]["path"]))
    old_renewal = lanes._load(_read(rolling._open_ref(old_plan["ordinary_renewal"])))
    new_renewal = lanes._load(_read(rolling._open_ref(value["renewal"])))
    if ready._encoded(value["capture_limits"]) != ready._encoded(old_plan["capture_limits"]) or len(old_renewal["rows"]) != len(sites):
        raise ValueError("ordinary carry changes the full measured capture caps or cohort")
    bindings = []
    for old, new, site in zip(old_renewal["rows"], new_renewal["rows"], sites):
        keys = ("candidate_id", "class_index", "workload_id", "original_manifest")
        if any(ready._encoded(old[k]) != ready._encoded(new[k]) for k in keys) or new["workload_id"] != site.workload_id:
            raise ValueError("ordinary carry changes exact original cohort identity or order")
        a = lanes._load(_read(_open(old["current_manifest"]))); b = lanes._load(_read(_open(new["current_manifest"])))
        from .application_response_policy import application_response_policy, primary_document_identity_policy
        if (ready._encoded(a["resources"]) != ready._encoded(b["resources"]) or application_response_policy(a) != application_response_policy(b)
                or primary_document_identity_policy(a) != primary_document_identity_policy(b)
                or any(a["preparation"][k] != b["preparation"][k] for k in ("max_response_bytes", "timeout_seconds"))):
            raise ValueError("ordinary carry changes a complete resource graph, response policy or caps")
        bindings.append({**{k: old[k] for k in keys}, "measured_manifest": old["current_manifest"],
            "authority_manifest": new["current_manifest"], "resources_sha256": ready._sha(ready._encoded(a["resources"]))})
    result = Path(original["result_root"])
    experiment = lanes._load(_read(result / "experiment.json")); config = experiment["configuration"]
    if (_measured_caps(config["limits"]) != _measured_caps(value["capture_limits"]) or config["profile"] != "research-1200"
            or len(config["defenses"]) != 1 or config["defenses"][0]["kind"] != "none"
            or config["defenses"][0]["baseline"] is not True
            or any(key.startswith("tamaraw_configuration") for key in config)
            or len(experiment["samples"]) != 1 or experiment["samples"][0]["request_policy"] != "as-defined"):
        raise ValueError("ordinary carry changes fixed request, ordinary configuration or measured caps")
    from .application_response_policy import application_body_identity_policy
    body = application_body_identity_policy(config)
    if body != application_body_identity_policy(original) or body != application_body_identity_policy(old_plan):
        raise ValueError("ordinary carry changes the original full-body policy")
    traffic = {key: ready._sha(_read(Path(runtime["execution_root"]) / name))
               for key, (name, _) in lanes.TRAFFIC_FILES.items()}
    if traffic != original["traffic_hashes"]:
        raise ValueError("ordinary carry changes actual fixed traffic parameters")
    groups, changed = protected_groups(source_root, Path(runtime["runtime_source_root"]),
        ready._inventory(source_root), ready._inventory(Path(runtime["runtime_source_root"])))
    individual = (None if individual_evidence is None else _individual_policy_authority(
        individual_evidence, bindings, value["capture_limits"], experiment, result, old_canonical, original_runtime))
    return {"current_runtime": runtime, "original_facts": original,
        "authority_source": {**current["source"], "image_digest": current["collection_image_digest"]},
        "authority_workload_sha256": sites[0].workload_sha256, "graph_bindings": bindings,
        "capture_limits": value["capture_limits"], "body_policy": body,
        "dependency_groups": groups, "mode_safe_units": changed, "consumer_sources": _sources(),
        "individual_primary_authority": individual}, completion


def _individual_policy_authority(evidence, bindings, caps, canary_experiment, canary_root, canonical, original_runtime):
    """Distinct Native reported label and Lab policy; no old deep replay."""
    if evidence.get("sha256") != INDIVIDUAL_EVIDENCE_SHA256:
        raise ValueError("ordinary individual authority needs its registered genuine independently verified batch")
    retained = []
    def bound(ref):
        # Old Root records have strict two-field references; observe full mode
        # before delegating to that unchanged reader.
        if set(ref) == {"path", "sha256", "mode"}:
            path = _open(ref)
        else:
            _read(Path(ref["path"])); path = rolling._open_ref(ref)
        full = reference(path); retained.append(full)
        return lanes._load(_read(path))
    value = bound(evidence)
    if (value.get("artifact_type") != "qcsd-root-independently-verified-current-ordinary-batch-v1"
            or value.get("mode") != "undefended" or value.get("classes") != [r["class_index"] for r in bindings]
            or any(type(value.get(k)) is not int or value[k] != expected for k, expected in
                (("independently_verified_trace_count",20),("eligible_trace_count",20),("failed_trace_count",0)))
            or value.get("module_source_commit") != ORIGINAL_HEAD or value.get("runtime_source_commit") != ORIGINAL_HEAD
            or value.get("native_commit") != canonical["source"]["neqo_commit"]
            or value.get("collection_image_digest") != canonical["collection_image_digest"]):
        raise ValueError("ordinary individual authority changed its genuine source, runtime, cohort or verified count")
    for name in ("launch", "verify"):
        completed = bound(value["actual_operations"][name]["completed"])
        if type(completed.get("returncode")) is not int or completed["returncode"] != 0:
            raise ValueError("ordinary individual authority lacks successful original operations")
    complete = lanes.admission._unpack(ready._encoded(bound(value["completed_lane"])), lanes.COMPLETE_TYPE)
    proof = lanes.admission._unpack(ready._encoded(bound(value["independent_proof"])), 'qcsd-rapid-v6-installed-lane-deep-check')
    result_root = Path(value["experiment"]["path"]).parent
    if (type(complete.get("accepted")) is not int or complete["accepted"] != 20
            or type(complete.get("host_returncode")) is not int or complete["host_returncode"] != 0
            or complete.get("collection_image_digest") != canonical["collection_image_digest"]
            or complete.get("lab_commit") != ORIGINAL_HEAD
            or proof.get("complete") is not False or proof.get("receipt") != value["completed_lane"]
            or proof.get("target") != value["completed_lane"]["path"]
            or proof.get("facts") != {**complete,"result_root":str(result_root)}
            or any(proof["spec"].get(k) != original_runtime[k] for k in lanes.RUNTIME_KEYS)
            or Path(proof["spec"]["execution_root"]) / "results" / complete["result_relpath"] != result_root):
        raise ValueError("ordinary individual authority lost its exact complete lane, independent proof or runtime binding")
    for name in ("started", "completed"):
        record = bound(proof[name])
        if name == "completed" and (type(record.get("returncode")) is not int or record["returncode"] != 0):
            raise ValueError("ordinary individual authority lacks its successful independent inner proof")
    seal_ref = reference(result_root / 'evidence.sha256')
    if seal_ref['sha256'] != complete['result_seal_sha256']:
        raise ValueError('ordinary individual authority changed its original complete result seal')
    retained.append(seal_ref)
    checksums = {}
    for line in _read(result_root / 'evidence.sha256').decode('utf-8').splitlines():
        digest, separator, relative = line.partition('  ')
        path = Path(relative)
        if (not separator or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest)
                or not relative or path.is_absolute() or path.as_posix() != relative
                or any(part in ('.', '..') for part in relative.split('/')) or relative in checksums):
            raise ValueError('ordinary individual authority has a malformed or duplicate result seal entry')
        checksums[relative] = digest
    def result_metadata(ref):
        path = Path(ref['path'])
        if not path.is_relative_to(result_root) or checksums.get(path.relative_to(result_root).as_posix()) != ref['sha256']:
            raise ValueError('ordinary individual metadata differs from its original complete result seal')
        return bound(ref)
    experiment = result_metadata(value["experiment"]); configuration = experiment["configuration"]
    measured_caps, authority_caps = lanes._load(_measured_caps(configuration["limits"])), lanes._load(_measured_caps(caps))
    if (type(measured_caps.get("max_attempts")) is not int or measured_caps["max_attempts"] != 3
            or type(authority_caps.get("max_attempts")) is not int or authority_caps["max_attempts"] != 1
            or {k:v for k,v in measured_caps.items() if k != "max_attempts"} !=
               {k:v for k,v in authority_caps.items() if k != "max_attempts"}
            or configuration["profile"] != canary_experiment["configuration"]["profile"]
            or configuration["defenses"] != canary_experiment["configuration"]["defenses"]
            or configuration["request_policies"] != ["as-defined"]):
        raise ValueError("ordinary individual evidence changed request, defense, profile or caps")
    from .application_response_policy import (application_body_identity_policy, application_response_policy,
        primary_document_identity_policy, EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY, VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
    if application_body_identity_policy(configuration) != application_body_identity_policy(canary_experiment["configuration"]):
        raise ValueError("ordinary individual evidence changed full-body acceptance")
    from .verification import resolved_sample_directory
    first = canary_experiment["samples"][0]
    canary_run = bound(reference(resolved_sample_directory(canary_root, first) / "neqo/run.json"))
    if (canary_run.get("primary_document_identity_policy") != EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
            or canary_run.get('application_workload_source_hash_sha256') is not None):
        raise ValueError("ordinary grouped practice changed its actual Native primary label")
    root = Path(value["experiment"]["path"]).parent
    workloads = {w["id"]:w for w in configuration["workloads"]}
    rows = {r["workload_id"]:r for r in bindings}
    observed, policies = set(), {}
    for sample in experiment["samples"]:
        name = sample["workload_id"]
        if (name not in rows or sample["state"] != "accepted" or sample.get("eligible") is not True
                or sample["defense"] != "undefended" or sample["request_policy"] != "as-defined"
                or type(sample["visit"]) is not int or not 0 <= sample["visit"] < 4
                or (name,sample["visit"]) in observed):
            raise ValueError("ordinary individual evidence changed its accepted sample identities")
        observed.add((name,sample["visit"]))
        manifest_ref = reference(ready._child(root,workloads[name]["manifest"]))
        if manifest_ref["sha256"] != workloads[name]["sha256"]:
            raise ValueError("ordinary individual evidence changed its configured frozen manifest bytes")
        manifest = result_metadata(manifest_ref)
        original_manifest = bound(rows[name]["measured_manifest"])
        current_manifest = bound(rows[name]["authority_manifest"])
        if (ready._encoded(manifest["resources"]) != ready._encoded(original_manifest["resources"])
                or any(primary_document_identity_policy(m) != VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
                       for m in (manifest,original_manifest,current_manifest))):
            raise ValueError("ordinary individual evidence changed an entire graph or authenticated Lab primary policy")
        run = result_metadata(reference(resolved_sample_directory(root,sample) / "neqo/run.json"))
        if (run.get("resolved_configuration") != canary_run.get("resolved_configuration")
                or run.get("primary_document_identity_policy") != EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
                or run.get("application_response_policy") != application_response_policy(manifest)
                or run.get("application_workload_source_hash_sha256") is not None):
            raise ValueError("ordinary individual evidence changed Native configuration, request or reported policies")
        policies[name] = {"candidate_id":rows[name]["candidate_id"], "workload_id":name,
            "authority_manifest":rows[name]["authority_manifest"],
            "lab_primary_policy":VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY}
    if observed != {(name,visit) for name in rows for visit in range(4)}:
        raise ValueError("ordinary individual evidence omitted a current full graph or verified visit")
    return {"artifact_type":INDIVIDUAL_POLICY_TYPE, "supporting_original_batch":evidence,
        "measured_native_primary_policy":EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY,
        "individual_manifests":[policies[r["workload_id"]] for r in bindings],
        "original_individual_capture_limits":configuration["limits"], "current_authority_capture_limits":caps,
        "references":list({r["path"]:r for r in retained}.values()),
        "original_verified_sample_count":20, "scientific_credit":False}


def _measured_caps(value):
    """Account for the original serializer's two floating time fields only."""
    import math
    result = dict(value)
    for name in ("settle_seconds", "per_origin_cooldown_seconds"):
        if type(result.get(name)) not in (int, float) or not math.isfinite(result[name]):
            raise ValueError("ordinary carry measured time cap is not a finite numeric value")
        result[name] = float(result[name])
    return ready._encoded(result)


def _owned(function):
    def action(*args, **kwargs):
        context = current_context(); owned = context is None
        context = OperationFacts() if owned else context
        if owned: context.begin_action()
        with context.scope():
            result = function(*args, **kwargs)
            if owned: close_operation(context)
            return result
    return action


@_owned
def publish(*, original_canary, original_runtime, original_canonical, current_input,
            current_canonical, audit_root, output, reason, individual_evidence=None):
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("ordinary carry needs an explicit prospective reason")
    _registered_original(original_canary, original_runtime, original_canonical)
    _, operation = _run_original(original_canary, original_runtime, audit_root)
    derived, completed = _derive(original_canary, original_runtime, original_canonical,
        current_input, current_canonical, operation, individual_evidence)
    output = Path(output).absolute(); lanes._regular_directory(output.parent)
    protected = [Path(original_runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root")]
    protected += [Path(derived["current_runtime"][key]) for key in ("runtime_source_root", "module_root", "execution_root")]
    protected.append(Path(audit_root))
    if any(output.is_relative_to(root) for root in protected):
        raise ValueError("ordinary carry publication must stay outside frozen measurement and authority roots")
    value = {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT,
        "original_canary": original_canary, "original_runtime": original_runtime,
        "original_canonical": original_canonical, "current_input": current_input,
        "current_canonical": current_canonical, "original_operation": operation,
        "individual_evidence":individual_evidence, **derived,
        "published_at": datetime.now(timezone.utc).isoformat(), "reason": reason.strip(),
        "scientific_credit": False, "formal_accepted_trace_count": 0}
    close_operation()
    lanes.admission.durable_create(output, ready._encoded(value))
    return {"schema_version": 6, "artifact_type": TYPE, "carry": reference(output)}


def bind_dependencies(value, runtime, context):
    rolling._keys(value, REFERENCE_KEYS, "ordinary carry canary reference")
    path = _open(value["carry"]); stored = lanes._load(_read(path))
    key = (TYPE, value["carry"]["sha256"], value["carry"]["mode"])
    if key in context._bindings: return
    for name in FILES: _read(Path(__file__).parent / name)
    context.bind_canary(stored["original_canary"], stored["original_runtime"])
    _bind_runtime(stored["original_canonical"], stored["original_runtime"])
    _bind_runtime(stored["current_canonical"], stored["current_runtime"])
    _open(stored["current_input"])
    report, _ = _recorded_operation(stored["original_canary"], stored["original_runtime"], stored["original_operation"])
    _close_report(report)
    context._bindings.add(key)


@_owned
def validate(value, *, runtime, mode):
    if (set(value) != REFERENCE_KEYS or type(value["schema_version"]) is not int
            or value["schema_version"] != 6 or value["artifact_type"] != TYPE or mode != "undefended"):
        raise ValueError("ordinary carry authorizes only its explicit ordinary typed route")
    bind_dependencies(value, runtime, current_context())
    stored = lanes._load(_read(_open(value["carry"])))
    rolling._keys(stored, KEYS, "ordinary canary carry")
    if (stored["artifact_type"] != TYPE or stored["contract"] != CONTRACT
            or type(stored["schema_version"]) is not int or stored["schema_version"] != 1
            or stored["scientific_credit"] is not False
            or type(stored["formal_accepted_trace_count"]) is not int or stored["formal_accepted_trace_count"] != 0
            or stored["current_runtime"] != runtime):
        raise ValueError("ordinary carry changed exact current authority or zero-credit scope")
    key = (TYPE, ready._sha(ready._encoded(value)), ready._sha(ready._encoded(runtime)))
    if current_context().has(key): return current_context().get(key)
    derived, completion = _derive(stored["original_canary"], stored["original_runtime"],
        stored["original_canonical"], stored["current_input"], stored["current_canonical"], stored["original_operation"],
        stored["individual_evidence"])
    if any(ready._encoded(stored[key]) != ready._encoded(item) for key, item in derived.items()):
        raise ValueError("ordinary carry differs from authenticated measurement and current control facts")
    if not ready._timestamp(completion["completed_at"]) <= ready._timestamp(stored["published_at"]) <= datetime.now(timezone.utc):
        raise ValueError("ordinary carry publication precedes its original reader or is future dated")
    result = {**derived["original_facts"], "authority_source": derived["authority_source"],
        "authority_workload_sha256": derived["authority_workload_sha256"],
        "ordinary_canary_carry": TYPE, "ordinary_carry_capture_limits": derived["capture_limits"],
        "ordinary_individual_primary_authority": derived["individual_primary_authority"],
        "ordinary_carry_current_input": stored["current_input"],
        "ordinary_carry_sites": [{"candidate_id": row["candidate_id"], "workload_id": row["workload_id"],
            "workload_sha256": row["authority_manifest"]["sha256"]} for row in derived["graph_bindings"]],
        "source_equivalence_sha256": value["carry"]["sha256"],
        "source_equivalence_published_at": stored["published_at"]}
    close_operation()
    return current_context().remember(key, result)


def require_current_plan(facts, spec, payload, sites):
    if (facts.get("ordinary_canary_carry") != TYPE
            or facts.get("ordinary_carry_current_input") != reference(spec.qualification_spec)
            or ready._encoded(facts.get("ordinary_carry_capture_limits")) != ready._encoded(payload.get("capture_limits"))
            or facts.get("ordinary_carry_sites") != [{"candidate_id": site.candidate_id,
                "workload_id": site.workload_id, "workload_sha256": site.workload_sha256} for site in sites]):
        raise ValueError("ordinary carry differs from this exact current input, ordered full cohort or capture caps")


def _interpreter_dependency_roots(command, interpreter):
    """Preserve an authenticated HOST alias chain in an installed reader."""
    path = Path(command)
    if not path.is_absolute() or reference(path.resolve(strict=True)) != interpreter:
        raise ValueError("ordinary carry interpreter transport differs from its registered binary")
    pending, seen, result = [path, Path(interpreter["path"])], set(), set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        result.add(current.parent)
        for entry in (current, *current.parents):
            if entry.is_symlink():
                result.add(entry.parent)
                target = entry.readlink()
                pending.append(target if target.is_absolute() else entry.parent / target)
    result.add(path.resolve(strict=True).parent)
    return result


@_owned
def roots(value, *, runtime, mode):
    validate(value, runtime=runtime, mode=mode)
    stored = lanes._load(_read(_open(value["carry"])))
    report, _ = _recorded_operation(stored["original_canary"], stored["original_runtime"], stored["original_operation"])
    result = {Path(value["carry"]["path"]).parent, Path(stored["current_input"]["path"]).parent,
        *map(Path, report["roots"])}
    start = lanes._load(_read(_open(stored["original_operation"]["started.json"])))
    plan = lanes._load(_read(Path(stored["original_canary"]["plan"]["path"])))
    for command in (start["command"][0], plan["host_python"]):
        result.update(_interpreter_dependency_roots(command, start["interpreter"]))
    for operation_ref in stored["original_operation"].values(): result.add(Path(operation_ref["path"]).parent)
    for role, canonical in ((stored["original_runtime"], stored["original_canonical"]),
                            (runtime, stored["current_canonical"])):
        result.update(_runtime_dependency_roots(canonical))
        result.add(Path(canonical["path"]).parent)
        result.update(Path(role[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
        result.update(Path(role[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    result.update(Path(ref["path"]).parent for ref in report["read_dependencies"])
    if stored["individual_primary_authority"] is not None:
        result.update(Path(ref["path"]).parent for ref in stored["individual_primary_authority"]["references"])
    result.update(Path(row["path"]) for row in report["directory_dependencies"])
    retained = sorted(root for root in result if not any(root != other and root.is_relative_to(other) for other in result))
    for root in retained:
        lanes._regular_directory(root)
        if any(c in str(root) for c in ("\n", "\r", "\0", ":")):
            raise ValueError("ordinary carry requires safe read-only transport roots")
    return retained
