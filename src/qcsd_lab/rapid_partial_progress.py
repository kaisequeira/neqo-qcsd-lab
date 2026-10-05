"""Join independently proved individual slots without completing a failed lane.

Both original public operations and both unchanged original deep invocations
are required. Reading this artifact executes neither capture nor a deep reader.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
import math
from pathlib import Path
import re
import stat

from . import rapid_partial_lane as original
from . import rapid_rolling_capture as rolling
from . import rapid_capture_plan as plan
from . import rapid_additive_static_enrollment as additive

TYPE = "qcsd-original-individual-slot-partial-progress-join-v1"
CONTRACT = "retained-failed-aggregate-original-declare-and-independent-deep-verify-v1"
FINAL_TARGET = 16000
READER_SHA256 = "0c32fde26a13c4602a88b314ca4deb73d47c4f89b769ec6a5e527ebce7bcf4c4"
TOOL_SHA256 = "11399466dd1b1f2d052cded70c1fb4cc2e2db291fb77b8efda5e568bc0184497"
# The first supported original epoch is an exact registered paired Git release.
# Image-domain interpreter labels belong to that immutable original image.
OFFLINE_TYPE = "qcsd-original-release-offline-image-partial-public-operation-v1"
REGISTERED_IMAGES = {"86cd8c78cf16447e6add3d10ffa02f6167505276": {
    "image": "sha256:0960f076e02ce24f3d0b9449e6487649c2e6a1e286946936cd5500c5c39165a0",
    "client": "fdb8bdab61bf9a4e728ee3826139de6230ee7aa00c4ec0349240ce6414992525",
    "source_export": "b2d7532ae22d0f99f61708faaf9006df4e2317acaafcd781f045b6e5fd1dd0e4",
    # This belongs to the immutable image ABI, not the consumer HOST filesystem.
    "interpreter": {"path": "/usr/bin/python3.11", "mode": 0o755,
        "sha256": "6d972cf21be56fe3c947ab6ba257ff8d08c342dd2714442986791bd9a6dfabfe"},
    "entrypoint": "/opt/qcsd-venv/bin/python3",
}}
CONTROL_MODULES = ("rapid_partial_progress", "rapid_partial_lane", "rapid_slot_chunks",
                   "rapid_rolling_capture", "rapid_additive_static_enrollment")


def _owned(function):
    @wraps(function)
    def run(*args, **kwargs):
        from .rapid_operation_facts import OperationFacts, current_context
        context = current_context()
        if context is None:
            context = OperationFacts(); context.begin_action()
        with context.scope():
            for ref in _control_sources().values(): _open(ref)
            value = function(*args, **kwargs)
            close_operation(context)
            return value
    return run


def _observe(ref, *, need_raw=False):
    if not isinstance(ref, dict) or set(ref) not in ({"path", "sha256"}, {"path", "sha256", "mode"}):
        raise ValueError("partial progress reference has another schema")
    p = original._path(ref["path"])
    from .rapid_operation_facts import current_context
    context = current_context()
    key = ("partial-progress-authenticated-ref", ref["path"], ref["sha256"], ref.get("mode"))
    if context is not None and context.has(key) and not need_raw:
        return p, None
    raw = context.watch_file(p) if context is not None else p.read_bytes()
    if (hashlib.sha256(raw).hexdigest() != ref["sha256"] or "mode" in ref and
            (type(ref["mode"]) is not int or stat.S_IMODE(p.stat().st_mode) != ref["mode"])):
        raise ValueError("partial progress dependency bytes or mode changed")
    if context is not None and not context.has(key): context.remember(key, True)
    return p, raw


def _open(ref):
    return _observe(ref)[0]


def _json(ref):
    from .rapid_operation_facts import current_context
    context = current_context()
    key = ("partial-progress-json", ref["path"], ref["sha256"], ref.get("mode"))
    if context is not None and context.has(key): return context.get(key)
    value = json.loads(_observe(ref, need_raw=True)[1])
    if context is not None: context.remember(key, value)
    return value


def _document(ref, kind):
    value = _json(ref)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "artifact_type", "payload", "payload_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["artifact_type"] != kind
            or value["payload_sha256"] != hashlib.sha256(original.encoded(value["payload"])).hexdigest()):
        raise ValueError("partial progress artifact type or payload digest changed")
    return value["payload"]


def _sources():
    from importlib import import_module
    return {name: original.reference(Path(import_module("qcsd_lab." + name).__file__).absolute())["sha256"]
            for name in CONTROL_MODULES}


def _control_sources():
    from importlib import import_module
    return {name: original.reference(Path(import_module("qcsd_lab." + name).__file__).absolute())
            for name in CONTROL_MODULES}


def _source(ref):
    value = _document(ref, original.SOURCE_TYPE)
    if (set(value) != {"root", "lab_head", "native_head", "files"}
            or original.ORIGINAL_RELEASES.get(value["lab_head"]) != value["native_head"]):
        raise ValueError("partial progress requires its registered complete original release inventory")
    _open(ref)
    root = Path(value["root"])
    for name, member in value["files"].items():
        if (Path(name).is_absolute() or ".." in Path(name).parts
                or Path(member["path"]) != root / name):
            raise ValueError("partial original Source member moved")
        _open(member)
    from .rapid_operation_facts import current_context
    context = current_context()
    key = ("partial-progress-original-release", ref["path"], ref["sha256"], READER_SHA256)
    if context is None or not context.has(key):
        for directory in (root / "src", root / "tools"):
            directories = [directory, *(p for p in directory.rglob("*") if p.is_dir())]
            _close({"read_dependencies": [], "directory_dependencies": [
                {"path": str(p), "mode": stat.S_IMODE(p.stat().st_mode),
                 "members": {x.name: {"kind": stat.S_IFMT(x.lstat().st_mode),
                     "mode": stat.S_IMODE(x.lstat().st_mode)} for x in sorted(p.iterdir())}}
                for p in directories]})
        for checkout in (root, root / "neqo-qcsd"):
            git = checkout / ".git"
            if git.is_file():
                _open(original.reference(git))
                raw = git.read_text().strip()
                if not raw.startswith("gitdir: "): raise ValueError("original Source Git directory changed")
                git = (checkout / raw.removeprefix("gitdir: ")).absolute()
            elif git.is_dir():
                pass
            if git.is_dir() and context is not None:
                context.watch_tree(git)
        if _release_source(ref) != value:
            raise ValueError("partial original Source differs from registered complete Git release")
        if context is not None: context.remember(key, True)
    return value


def _release_source(ref):
    # The unchanged full original validator authenticates every Git member at
    # first use; callers cannot register an arbitrary self-consistent inventory.
    return original._source(ref)


def _directory(row):
    p = original._path(row["path"], directory=True)
    current = {"path": str(p), "mode": stat.S_IMODE(p.stat().st_mode),
        "members": {x.name: {"kind": stat.S_IFMT(x.lstat().st_mode), "mode": stat.S_IMODE(x.lstat().st_mode)}
                    for x in sorted(p.iterdir())}}
    if current != row: raise ValueError("partial original shallow directory membership changed")


def _close(report):
    for ref in report["read_dependencies"]: _open(ref)
    from .rapid_operation_facts import current_context
    context = current_context()
    for row in report["directory_dependencies"]:
        key = ("partial-progress-directory", row["path"])
        if context is not None and context.has(key):
            if context.get(key) != row: raise ValueError("partial directory observations disagree")
        else:
            _directory(row)
            if context is not None:
                context.remember(key, row)
                context._bindings.add(key)


def close_operation(context=None):
    """Fresh bytes/modes and exact shallow memberships before effects/success."""
    from .rapid_operation_facts import current_context
    context = context or current_context()
    if context is None: return
    for key in context._bindings:
        if key[0] == "partial-progress-directory": _directory(context.get(key))
    context.check()


def _offline(authority, tool, source):
    if (not isinstance(authority, dict) or set(authority) != {"artifact_type", "runtime", "root_inputs"}
            or authority["artifact_type"] != OFFLINE_TYPE):
        raise ValueError("offline partial operation has another typed authority")
    runtime, inputs = _json(authority["runtime"]), _json(authority["root_inputs"])
    image = REGISTERED_IMAGES[source["lab_head"]]
    export = {"path": runtime["source_manifest"], "sha256": runtime["exported_source_manifest_sha256"]}
    exported = _json(export)
    if (runtime["collection_image_digest"] != image["image"]
            or runtime["installed_client_sha256"] != image["client"]
            or export["sha256"] != image["source_export"] or exported != runtime["source"]
            or runtime["installed_byte_verification_completed"] is not True
            or runtime["scientific_credit"] is not False
            or runtime["source"]["lab_commit"] != source["lab_head"]
            or runtime["source"]["neqo_commit"] != source["native_head"]
            or runtime["source"]["lab_dirty"] is not False or runtime["source"]["neqo_dirty"] is not False
            or inputs["original_source"] != source["root"] or inputs["original_lab"] != source["lab_head"]
            or inputs["original_native"] != source["native_head"] or inputs["original_image"] != image["image"]
            or type(inputs["formal_credit_added"]) is not int or inputs["formal_credit_added"] != 0
            or inputs["aggregate_lane_pass_claim"] is not False):
        raise ValueError("offline partial image, Source, client or input authority changed")
    for key in ("driver", "reader_closure", "reader_review"): _open(inputs[key])
    root = original._path(Path(authority["root_inputs"]["path"]).parent, directory=True)
    workspace = Path(source["root"]).parent
    if (not root.is_relative_to(workspace) or root == workspace
            or not Path(tool["path"]).is_relative_to(workspace)):
        raise ValueError("offline proof namespaces leave their authenticated workspace")
    return image, root, workspace, inputs


def _deep(source, inputs, operation, reader, interpreter):
    """Location-explicit replay of the pinned reader's recorded-only predicate."""
    if set(operation) != {"started.json", "completed.json", "stdout.log", "stderr.log"}:
        raise ValueError("partial progress needs all four original deep records")
    paths = {name: _open(ref) for name, ref in operation.items()}
    if len({p.parent for p in paths.values()}) != 1 or any(p.name != name for name, p in paths.items()):
        raise ValueError("original deep records moved")
    start, end = (_json(operation[name]) for name in ("started.json", "completed.json"))
    expected_request = {**original._request(source, inputs), "scratch_root": str(paths["started.json"].parent / "scratch")}
    if (set(start) != {"command", "request", "reader", "interpreter", "started_at"}
            or start["command"] != [interpreter["command"], "-I", "-B", "-c", original._PROGRAM]
            or start["request"] != expected_request or start["reader"] != reader
            or start["interpreter"] != interpreter["reference"]
            or set(end) != {"returncode", "completed_at", "stdout_sha256", "stderr_sha256"}
            or type(end["returncode"]) is not int or end["returncode"] != 0
            or end["stdout_sha256"] != operation["stdout.log"]["sha256"]
            or end["stderr_sha256"] != operation["stderr.log"]["sha256"]
            or not original._timestamp(start["started_at"]) <= original._timestamp(end["completed_at"])
                <= datetime.now(timezone.utc)):
        raise ValueError("original deep command, Source, status or chronology changed")
    report = _json(operation["stdout.log"])
    if report["result_root"] != inputs["result"]["path"] or report["result_seal"] != inputs["result"]["seal"]:
        raise ValueError("original deep proof opened another result")
    _close(report)
    return report, start, end


def _outer(operation, action, arguments, tool, offline=None, source=None):
    """Authenticate genuine recorder records and the exact public CLI action."""
    if set(operation) != {"started", "completed", "stdout", "stderr"}:
        raise ValueError("partial progress needs actual public operation raw records")
    paths = {key: _open(ref) for key, ref in operation.items()}
    if len({p.parent for p in paths.values()}) != 1:
        raise ValueError("partial public records moved")
    prefix = paths["started"].name.removesuffix("-started.json")
    if any(paths[k].name != prefix + suffix for k, suffix in
           (("started", "-started.json"), ("completed", "-completed.json"),
            ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))):
        raise ValueError("partial public record basenames changed")
    start, end = _json(operation["started"]), _json(operation["completed"])
    argv = start.get("command")
    image_interpreter = None
    if isinstance(argv, list) and argv[:2] == ["docker", "run"]:
        if offline is None or source is None:
            raise ValueError("offline image action needs explicit authenticated authority")
        image, root, workspace, _ = _offline(offline, tool, source)
        if len(argv) < 27 or re.fullmatch(r"[1-9][0-9]*:[0-9]+", argv[11]) is None:
            raise ValueError("offline original proof needs exact nonroot sandbox user")
        prefix_argv = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", argv[11],
            "--volume", f"{workspace}:{workspace}:ro", "--volume", f"{root}:{root}:rw",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=268435456", "--workdir", str(workspace),
            "--entrypoint", image["entrypoint"], image["image"], "-I", "-B", tool["path"], action]
        if (argv[:27] != prefix_argv or paths["started"].parent != root / "operations"
                or not Path(arguments["--audit-root"]).is_relative_to(root)
                or any(not Path(v).is_relative_to(workspace) for v in arguments.values())
                or action == "declare" and not Path(arguments["--output"]).is_relative_to(root)):
            raise ValueError("offline public proof changed image, readonly mounts or owned output")
        image_interpreter = {"command": image["entrypoint"], "reference": image["interpreter"],
                             "domain": "immutable-original-image", "image": image["image"]}
        argv = [image["entrypoint"], "-I", "-B", tool["path"], action, *argv[27:]]
    elif offline is not None:
        raise ValueError("offline authority cannot relabel a HOST public proof")
    if (not isinstance(argv, list) or len(argv) != 5 + 2 * len(arguments)
            or argv[1:5] != ["-I", "-B", tool["path"], action]
            or len(set(argv[5::2])) != len(arguments)
            or dict(zip(argv[5::2], argv[6::2])) != arguments
            or type(end.get("returncode")) is not int or end["returncode"] != 0
            or end.get("invocation_error") is not None
            or end.get("stdout_sha256") != operation["stdout"]["sha256"]
            or end.get("stderr_sha256") != operation["stderr"]["sha256"]
            or not isinstance(end.get("elapsed_seconds"), (int, float))
            or isinstance(end["elapsed_seconds"], bool) or not math.isfinite(end["elapsed_seconds"])
            or end["elapsed_seconds"] < 0
            or not original._timestamp(start["started_at"]) <= original._timestamp(end["completed_at"])
                <= datetime.now(timezone.utc)):
        raise ValueError("partial public command, status, raw logs or chronology changed")
    output = _json(operation["stdout"])
    if set(output) != {"operation", "status", "result"} or output["operation"] != action or output["status"] != "closed":
        raise ValueError("partial public operation did not actually close")
    if image_interpreter is not None: return output["result"], image_interpreter, start, end
    executable = original.reference(Path(argv[0]).resolve())
    _open(executable)
    return output["result"], {"command": argv[0], "reference": executable}, start, end


def _portion(row):
    if set(row) not in ({"receipt", "tool", "declare", "verify"},
                       {"receipt", "tool", "declare", "verify", "offline_image"}):
        raise ValueError("partial join needs receipt and separate original declare/verify operations")
    receipt, tool = row["receipt"], row["tool"]
    value = _document(receipt, original.TYPE)
    reader = value["reader"]; _open(reader); _open(tool)
    if (reader["sha256"] != READER_SHA256 or tool["sha256"] != TOOL_SHA256
            or Path(reader["path"]) != Path(tool["path"]).parents[1] / "src/qcsd_lab/rapid_partial_lane.py"
            or hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest() != READER_SHA256
            or value["contract"] != original.CONTRACT or value["lane_pass_claim"] is not False
            or type(value["aggregate_formal_credit"]) is not int or value["aggregate_formal_credit"] != 0):
        raise ValueError("partial join changed its original reader or failed aggregate authority")
    source = _source(value["inputs"]["source_binding"])
    inputs = value["inputs"]
    declare_start = _json(row["declare"]["started"])
    verify_start = _json(row["verify"]["started"])
    # Audit destinations are retained original CLI inputs, then independently
    # matched to the corresponding original inner operation directories.
    def audit_path(command):
        if not isinstance(command, list) or command.count("--audit-root") != 1:
            raise ValueError("partial public action lost its original audit namespace")
        return command[command.index("--audit-root") + 1]
    args = {"--source-binding": inputs["source_binding"]["path"], "--spec": inputs["spec"]["path"],
            "--evidence-root": inputs["evidence_root"], "--intent": inputs["intent"]["path"],
            "--result": inputs["result"]["path"], "--audit-root": audit_path(declare_start["command"]),
            "--output": receipt["path"]}
    offline = row.get("offline_image")
    declared, interpreter, ds, de = _outer(row["declare"], "declare", args, tool, offline, source)
    if declared != receipt:
        raise ValueError("partial declare output did not publish this exact receipt")
    verified, second_interpreter, vs, ve = _outer(row["verify"], "verify", {
        "--receipt": receipt["path"], "--audit-root": audit_path(verify_start["command"])}, tool, offline, source)
    if (interpreter != second_interpreter or set(verified) != {"accepted_count", "aggregate_status",
            "lane_pass_claim", "aggregate_formal_credit", "fresh_deep_operation"}
            or type(verified["accepted_count"]) is not int
            or type(verified["aggregate_formal_credit"]) is not int
            or verified["lane_pass_claim"] is not False
            or original._timestamp(de["completed_at"]) > original._timestamp(vs["started_at"])):
        raise ValueError("partial verification is not a separate subsequent original public proof")
    first, fs, fe = _deep(source, inputs, value["deep_operation"], reader, interpreter)
    second, ss, se = _deep(source, inputs, verified["fresh_deep_operation"], reader, interpreter)
    if (args["--audit-root"] != str(Path(value["deep_operation"]["started.json"]["path"]).parent)
            or audit_path(verify_start["command"]) != str(Path(verified["fresh_deep_operation"]["started.json"]["path"]).parent)
            or value["deep_operation"] == verified["fresh_deep_operation"]
            or not original._timestamp(ds["started_at"]) <= original._timestamp(fs["started_at"])
                <= original._timestamp(fe["completed_at"]) <= original._timestamp(value["published_at"])
                <= original._timestamp(de["completed_at"])
            or not original._timestamp(vs["started_at"]) <= original._timestamp(ss["started_at"])
                <= original._timestamp(se["completed_at"]) <= original._timestamp(ve["completed_at"])):
        raise ValueError("partial original/independent deep namespaces or chronology changed")
    facts = original.accepted_subset(first)
    if offline is not None and _offline(offline, tool, source)[3]["intended_lane"] != facts["lane"]["campaign_name"]:
        raise ValueError("offline original proof plan names another lane")
    if (facts != original.accepted_subset(second) or any(value.get(k) != v for k, v in facts.items())
            or any(verified[k] != facts[k] for k in verified if k != "fresh_deep_operation")
            or value["read_dependencies"] != first["read_dependencies"]
            or value["directory_dependencies"] != first["directory_dependencies"]
            or facts["measurement_source"]["lab_commit"] != source["lab_head"]):
        raise ValueError("partial accepted slots differ from either unchanged original deep proof")
    _close(value)
    return facts, first, second, ve["completed_at"]


def graph_identity(path):
    value = _json(original.reference(path)); prep = value["preparation"]
    return hashlib.sha256(json.dumps({"resources": value["resources"],
        "primary_resource_id": value.get("primary_resource_id", prep.get("primary_resource_id")),
        "final_url": prep["final_url"], "approved_origins": prep.get("approved_origins")},
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _class_rows(enrollment):
    _, classes, policy = rolling._verify_enrollment(_open(enrollment))
    result = []
    for row in classes:
        if "prepared_workload" in row:
            manifest = _open(row["prepared_workload"])
        else:
            original_policy = policy; seen = set()
            while True:
                refs = original_policy.get("seed_inputs", {})
                if row["candidate_id"] in refs:
                    from . import rapid_selected_capture_input as selected
                    data, _ = additive.input_metadata(refs[row["candidate_id"]])
                    if any(data[k] != row[k] for k in ("candidate_id", "workload_id", "canonical_sites")):
                        raise ValueError("partial class membership replaced a retained seed")
                    manifest = selected.reopen(data["original_manifest"]); break
                if "seed_policy" not in original_policy:
                    context = rolling._context_for_policy(original_policy, Path(row["admission_root"]))
                    manifest, _ = rolling._prepared_workload(context, _open(row["terminal"])); break
                seed = _open(original_policy["seed_policy"])
                if str(seed) in seen: raise ValueError("partial class policy ancestry is cyclic")
                seen.add(str(seed)); raw = seed.read_bytes(); document = json.loads(raw)
                original_policy = rolling.admission._unpack(raw, document["receipt_type"])
        manifest_ref = original.reference(manifest); _open(manifest_ref)
        result.append({**row, "capture_limits": row.get("capture_limits", policy["capture_limits"]),
                       "original_manifest": manifest_ref, "original_graph_sha256": graph_identity(manifest)})
    return result


def _rows(classes, portions):
    by_candidate = {r["candidate_id"]: r for r in classes}; rows = []; seen = set()
    if (len(by_candidate) != len(classes) or len({r["class_index"] for r in classes}) != len(classes)
            or len({r["workload_id"] for r in classes}) != len(classes)):
        raise ValueError("partial membership repeats a class, candidate or workload")
    for portion, facts in portions:
        measured_limits = facts["configuration"]["limits"]
        for sample in facts["accepted_samples"]:
            member = by_candidate.get(sample["candidate_id"])
            if (member is None or member["workload_id"] != sample["workload_id"]
                    or member["original_manifest"]["sha256"] != sample["workload_sha256"]
                    or set(member["capture_limits"]) != set(measured_limits)
                    or any(member["capture_limits"][k] != measured_limits[k]
                           for k in measured_limits if k != "max_attempts")
                    or sample["mode"] not in plan.MODES):
                raise ValueError("partial slot changes its enrolled original graph, caps or mode")
            key = (member["class_index"], sample["mode"], sample["logical_visit"])
            trace = (facts["result_root"], sample["sample_id"])
            if key in seen or trace in seen: raise ValueError("partial join repeats a logical slot or physical sample")
            seen.update((key, trace))
            rows.append({**sample, "class_index": member["class_index"],
                "original_graph_sha256": member["original_graph_sha256"], "result_root": facts["result_root"],
                "configuration": facts["configuration"], "measurement_source": facts["measurement_source"],
                "capture_limits": measured_limits, "partial_receipt": portion["receipt"],
                "source_binding": _document(portion["receipt"], original.TYPE)["inputs"]["source_binding"],
                "registered_block": facts["lane"]["block"], "campaign_name": facts["lane"]["campaign_name"],
                "original_state": "accepted", "host_returncode": 1, "aggregate_status": "incomplete",
                "lane_pass_claim": False, "aggregate_formal_credit": 0,
                "individual_trace_authority": facts["individual_trace_authority"]})
    return rows


def _derive(prior, enrollment, portions, control_sources=None):
    from . import rapid_slot_chunks as chunks
    classes = _class_rows(enrollment)
    old, slots, files = chunks.prior_progress(prior, classes)
    all_facts, reports, closed = [], [], [old["closed_at"]]
    for portion in portions:
        facts, first, second, completed = _portion(portion)
        all_facts.append((portion, facts)); reports.extend((first, second)); closed.append(completed)
    if not all_facts: raise ValueError("partial progress join requires at least one independently verified partial lane")
    rows = _rows(classes, all_facts)
    new = {(r["class_index"], r["mode"], r["logical_visit"]) for r in rows}
    if slots & new: raise ValueError("partial progress duplicates a previously accepted slot")
    accepted = old["accepted_formal_slots"] + [{"candidate_id": r["candidate_id"],
        "class_index": r["class_index"], "mode": r["mode"], "visit": r["logical_visit"]} for r in rows]
    controls = _control_sources() if control_sources is None else control_sources
    if set(controls) != set(CONTROL_MODULES) or any(controls[k]["sha256"] != _sources()[k] for k in controls):
        raise ValueError("partial progress control authority changed")
    for ref in controls.values(): _open(ref)
    value = {"contract": CONTRACT, "prior_progress": prior, "enrollment": enrollment,
        "classes": classes, "partials": portions, "partial_lanes": [facts for _, facts in all_facts],
        "individual_slots": rows, "formal_accepted_trace_count": len(accepted),
        "accepted_formal_slots": accepted, "retained_prior_trace_count": len(slots),
        "individual_trace_count": len(rows), "aggregate_formal_credit": 0, "lane_pass_claim": False,
        "aggregate_status": "incomplete", "final_target": FINAL_TARGET,
        "historical_browser_traces_excluded": old["historical_browser_traces_excluded"],
        "actual_installed_deep_reopened": True,
        "measurement_epochs_preserve_original_source_and_runtime_labels": True,
        "closed_at": max(closed, key=original._timestamp),
        "read_dependencies": [r for report in reports for r in report["read_dependencies"]],
        "directory_dependencies": [r for report in reports for r in report["directory_dependencies"]],
        "sources": _sources(), "control_sources": controls}
    additive._progress(value, classes)
    for path in files: _open(original.reference(path))
    return value, files


@_owned
def publish(*, prior_progress, enrollment, partials, output):
    value, _ = _derive(prior_progress, enrollment, partials)
    _close(value)
    value["published_at"] = datetime.now(timezone.utc).isoformat()
    from .rapid_operation_facts import current_context
    close_operation(current_context())
    return original._write(output, TYPE, value)


def _validated(ref, classes=None):
    value = _document(ref, TYPE)
    if value["sources"] != _sources(): raise ValueError("partial progress executing control Source changed")
    derived, prior_files = _derive(value["prior_progress"], value["enrollment"], value["partials"], value["control_sources"])
    if (set(value) != set(derived) | {"published_at"}
            or any(value[k] != v for k, v in derived.items())
            or original._timestamp(value["published_at"]) < original._timestamp(value["closed_at"])):
        raise ValueError("partial progress differs from its retained original proofs and slot mapping")
    if classes is not None:
        expected = {r["candidate_id"]: r for r in classes}
        if any(r["candidate_id"] not in expected or any(expected[r["candidate_id"]].get(k) != r[k]
               for k in ("class_index", "workload_id")) for r in value["classes"]):
            raise ValueError("partial progress was moved to another enrollment identity")
    _close(value)
    return value, prior_files


@_owned
def validate(ref, classes=None):
    return _validated(ref, classes)[0]


def accepted_slots(ref):
    return validate(ref)["individual_slots"]


def _input_files(ref, value, prior_files):
    result = {_open(ref)}
    def walk(item):
        if isinstance(item, dict):
            if set(item) in ({"path", "sha256"}, {"path", "sha256", "mode"}): result.add(_open(item))
            else:
                for child in item.values(): walk(child)
        elif isinstance(item, list):
            for child in item: walk(child)
    walk(value)
    result.update(prior_files)
    for portion in value["partials"]:
        payload = _document(portion["receipt"], original.TYPE)
        verified = _json(portion["verify"]["stdout"])["result"]
        walk(payload); walk(verified)
        for operation in (payload["deep_operation"], verified["fresh_deep_operation"]):
            started = _json(operation["started.json"])
            for key, item in started.items():
                if key != "interpreter" or "offline_image" not in portion: walk(item)
        if "offline_image" in portion:
            authority = portion["offline_image"]
            runtime = _json(authority["runtime"])
            walk(_json(authority["root_inputs"]))
            result.add(_open({"path": runtime["source_manifest"],
                              "sha256": runtime["exported_source_manifest_sha256"]}))
        binding = payload["inputs"]["source_binding"]
        result.update(_open(r) for r in _source(binding)["files"].values())
    return result


@_owned
def read_inputs(ref, classes=None):
    """Authenticate once for callers needing both rows and transport inputs."""
    value, prior_files = _validated(ref, classes)
    return value, _input_files(ref, value, prior_files)


def input_files(ref):
    return read_inputs(ref)[1]


def observed_inputs(files, context=None):
    """Export already authenticated file refs within their owning action.

    These snapshots acquire no independent authority. The caller must invoke
    close_operation before publication and success while this action is active.
    """
    from .rapid_operation_facts import current_context
    context = context or current_context()
    if context is None: raise ValueError("partial input snapshots need their owning action")
    result = []
    for path in sorted({Path(p).absolute() for p in files}):
        if path not in context._files:
            raise ValueError("partial input has no authenticated action observation")
        result.append({"path": str(path), **context._files[path]})
    return result
