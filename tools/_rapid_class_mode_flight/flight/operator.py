#!/usr/bin/env python3
"""Create-only full-graph flights for 1–5 original enrolled classes and one mode.

Root alone launches physical actions. Compatible current response-only evidence
may be reused; each mode retains its own complete canary and independent deep.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FIRST_HELPER = HERE.parent / "rapid-v6-first-site-operator-20261004-001/operator.py"
FIRST_HELPER_SHA = "f50d4781cde87ee78d6d5ee6efa85ebf586d680068ec9569342fb16df111b8f1"
RECORDER = HERE.parent / "application-response-policy-runtime-20261003-001/runtime_recipe.py"
RECORDER_SHA = "7e7653fe26a89ecc512a2b17b37438f6af6f3c97ea4f95ee77ea995e27594af7"
MODES = ("undefended", "front", "tamaraw", "buflo", "cs-buflo")
AMENDED_MODES = ("front", "buflo")
PUBLIC_CLI_BOOTSTRAP = ("import runpy,sys;sys.path.insert(0,sys.argv.pop(1));"
                        "runpy.run_path(sys.argv.pop(1),run_name='__main__')")
ZERO = {"scientific_credit": False, "site_credit": 0,
        "study_pilot_accepted_trace_count": 0, "formal_accepted_trace_count": 0}


def now():
    return datetime.now(timezone.utc).isoformat()


def read(path):
    path = Path(path).absolute()
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("required regular unlinked input is absent")
    return path.read_bytes()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def ref(path):
    return {"path": str(Path(path).absolute()), "sha256": digest(read(path))}


def checked(value):
    if set(value) != {"path", "sha256"} or not Path(value["path"]).is_absolute():
        raise ValueError("immutable file reference differs")
    raw = read(value["path"])
    if digest(raw) != value["sha256"]:
        raise ValueError("bound input bytes changed")
    return raw


def create(path, raw):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def module(path, expected, name):
    if digest(read(path)) != expected:
        raise ValueError("immutable helper changed")
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def graph(manifest):
    rows = manifest["resources"]
    return {"resource_count": len(rows), "resource_records_sha256": digest(encode(rows)),
            "origins": sorted({f'{urlsplit(r["url"]).scheme}://{urlsplit(r["url"]).netloc}' for r in rows})}


def static_roots(manifest):
    from qcsd_lab.static_evidence_transport import manifest_roots
    from qcsd_lab import supplied_static_capture_amendment as amendment
    roots = [str(root) for root in manifest_roots(manifest)]
    from qcsd_lab import supplied_static_preparation as preparation
    if preparation.is_static(manifest.get("preparation")):
        from qcsd_lab import supplied_static_admission as static
        from qcsd_lab.static_evidence_transport import _path
        proof = preparation.validate_static_preparation(manifest["preparation"], manifest["resources"])
        context = static.load_context(preparation.open_reference(proof["context"]).parent)
        inherited_roots = set()
        # Reopening the selected graph also validates every sealed inherited
        # prefix. Include complete raw GET/deferral trees and recorded outer
        # files; later mutable context attempts are not dependencies here.
        while True:
            inherited_roots.add(_path(context.root, directory=True))
            for reference in context.provenance["inherited_terminals"]:
                terminal = preparation.open_reference(reference)
                static.verify_terminal(terminal, context)
                record = static.receipts._unpack(read(terminal), static.TERMINAL_TYPE)
                inherited_roots.add(_path(terminal.parent, directory=True))
                if record["get_evidence_root"] is not None:
                    inherited_roots.add(_path(Path(record["get_evidence_root"]), directory=True))
                if record["namespace"] is not None:
                    inherited_roots.update(_path(preparation.open_reference(record["namespace"][key]).parent, directory=True)
                        for key in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
            if context.provenance["parent_context"] is None:
                break
            context = static.load_context(preparation.open_reference(context.provenance["parent_context"]).parent)
        roots = sorted(set(roots) | {str(root) for root in inherited_roots})
    if amendment.is_amended(manifest.get("preparation")):
        # The public validator above authenticates this whole chain. Fail on
        # HOST before Docker if an older producer omitted its original policy
        # runtime from the exact public transport calculation.
        declaration = json.loads(checked(manifest["preparation"][amendment.FIELD]))["payload"]
        enrollment = json.loads(checked(declaration["enrollment"]))["payload"]
        policy_ref = enrollment["policy"]
        policy = json.loads(checked(policy_ref))["payload"]
        required = {Path(policy_ref["path"]).parent}
        required.update(Path(policy["runtime"][key]) for key in
                        ("runtime_source_root", "module_root", "execution_root"))
        required.update(Path(policy[key]["path"]).parent
                        for key in ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"))
        if any(not any(path == Path(root) or path.is_relative_to(Path(root)) for root in roots)
               for path in required):
            raise ValueError("public static transport omits original enrolled policy runtime authority")
    # Match the public deep validator's canonical minimal mount set. Prefix
    # terminal directories are already covered by their authenticated context.
    return sorted(root for root in set(roots)
                  if not any(root != parent and Path(root).is_relative_to(Path(parent)) for parent in roots))


def host_imports(clean):
    sys.path[:0] = [str(Path(clean) / "src"), str(clean)]


def checked_runtime(args):
    first = module(FIRST_HELPER, FIRST_HELPER_SHA, "bound_first_site_helper")
    reference, canonical, clean = first.checked_runtime(SimpleNamespace(
        runtime_build_root=args.runtime_build_root, clean_runtime_root=args.clean_runtime_root,
        canonical_sha256=args.canonical_sha256, expected_lab_commit=args.expected_lab_commit))
    if (re.fullmatch(r"[0-9a-f]{40}", args.expected_native_commit) is None
        or canonical["source"]["neqo_commit"] != args.expected_native_commit):
        raise ValueError("new amended site requires the exact actual installed Native commit")
    return reference, canonical, clean



def typed_original(manifest):
    """Reopen a new role without changing any original GET authority."""
    from qcsd_lab import supplied_static_budget_successor as budget
    from qcsd_lab import whole_graph_supplement as whole
    declared = manifest["preparation"]
    if budget.is_budget(declared):
        return budget.validate_preparation(declared, manifest["resources"])
    if whole.is_whole(declared):
        return whole.validate_preparation(declared, manifest["resources"])
    raise ValueError("unknown prospective flight original data role")

def typed_selected_inputs(batch, policy, rows, contexts):
    """Only explicit complete-GET contexts may select the new role branch."""
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import supplied_static_preparation as preparation
    from qcsd_lab import supplied_static_budget_successor as budget
    from qcsd_lab import static_budget_capture as capture
    from qcsd_lab import whole_graph_supplement as whole
    if any(not isinstance(context, (budget.Context, capture.Context, whole.Context)) for context in contexts):
        raise ValueError("one typed flight requires authenticated budget or whole-graph contexts")
    bindings, manifests, roots = [], [], set()
    for row, context in zip(rows, contexts):
        terminal = rolling._open_ref(row["terminal"])
        original, manifest = rolling._prepared_workload(context, terminal)
        if preparation.is_static(manifest["preparation"]):
            preparation.validate_static_preparation(manifest["preparation"], manifest["resources"])
        else:
            typed_original(manifest)
        if row["workload_id"] != original.stem:
            raise ValueError("enrollment workload identity differs from its admitted original")
        identity = rolling._admission_identity(context)
        bindings.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"],
            "admission_root": str(context.root), "terminal": ref(terminal),
            "original_workload": ref(original), "workload_id": original.stem,
            "full_graph": graph(manifest), "selection_sha256": identity["profile_sha256"]})
        manifests.append(manifest)
        roots.update(static_roots(manifest))
    if len({row["workload_id"] for row in bindings}) != len(rows):
        raise ValueError("flight class workload identities repeat")
    limits = capture.selected_capture_limits(manifests, policy["capture_limits"])
    return batch, policy, bindings, manifests, sorted(roots), {**limits, "max_attempts": 1}

def typed_manifest_limits(manifest):
    """Use only dependencies already authenticated by public manifest roots."""
    from qcsd_lab import supplied_static_budget_successor as budget
    from qcsd_lab import whole_graph_supplement as whole
    from qcsd_lab import supplied_static_preparation as preparation
    from qcsd_lab import supplied_static_admission as static
    declared = manifest["preparation"]
    if budget.is_budget(declared):
        budget.validate_preparation(declared, manifest["resources"])
        return dict(declared[budget.FIELD]["capture_limits"])
    if whole.is_whole(declared):
        proof = whole.validate_preparation(declared, manifest["resources"])
        context = whole.load_context(preparation.open_reference(proof["context"]).parent)
        return whole.context_limits(context)
    if preparation.is_static(declared):
        proof = preparation.validate_static_preparation(declared, manifest["resources"])
        context = static.load_context(preparation.open_reference(proof["context"]).parent)
        return static.context_limits(context)
    raise ValueError("unknown original role cannot select a flight budget")

def typed_canary_limits(manifests, policy, mode, selected_policy):
    from qcsd_lab import static_budget_capture as capture
    from qcsd_lab import buflo_duration_budget as duration
    limits = [typed_manifest_limits(manifest) for manifest in manifests]
    if not limits or any(value != limits[0] for value in limits[1:]):
        raise ValueError("typed flight requires homogeneous authenticated class budgets")
    declared = capture.selected_capture_limits(manifests,
        limits[0] if policy is None else policy["capture_limits"])
    if declared != limits[0]:
        raise ValueError("enrolled policy differs from the authenticated original class budgets")
    return duration.capture_limits(mode, {**declared, "max_attempts": 1}, policy=selected_policy)


def selected_inputs(enrollment, study):
    """Authenticate the current declared batch, preserving each original graph."""
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import supplied_static_admission as static
    from qcsd_lab import supplied_static_preparation as preparation
    batch, all_classes, policy = rolling._verify_enrollment(Path(enrollment).absolute())
    count = len(batch["selected_candidate_ids"])
    if (not 1 <= count <= 5 or policy["contract"] != rolling.STATIC_CONTRACT
        or rolling._open_ref(batch["policy"]).parent != Path(study).absolute()):
        raise ValueError("flight requires this exact original-static enrolled batch of 1–5 classes")
    rows = all_classes[-count:]
    if [row["candidate_id"] for row in rows] != batch["selected_candidate_ids"]:
        raise ValueError("enrolled current class order differs")
    selected_contexts = [rolling._context_for_policy(policy, Path(row["admission_root"])) for row in rows]
    if any(not isinstance(context, static.Context) for context in selected_contexts):
        return typed_selected_inputs(batch, policy, rows, selected_contexts)
    bindings, manifests, roots, contexts = [], [], set(), []
    for row, context in zip(rows, selected_contexts):
        terminal = rolling._open_ref(row["terminal"])
        original, manifest = static.prepared_workload(context, terminal)
        if manifest["preparation"].get("data_role") != preparation.ROLE:
            raise ValueError("supplemental/browser roles require their own explicit flight recipe")
        if row["workload_id"] != original.stem:
            raise ValueError("enrollment workload identity differs from its admitted original")
        bindings.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"],
            "admission_root": str(context.root), "terminal": ref(terminal),
            "original_workload": ref(original), "workload_id": original.stem,
            "full_graph": graph(manifest), "selection_sha256": context.provenance["profile"]["sha256"]})
        manifests.append(manifest)
        roots.update(static_roots(manifest))
        contexts.append(context)
    if len({row["workload_id"] for row in bindings}) != count:
        raise ValueError("flight class workload identities repeat")
    limits = [{**static.context_limits(context), "max_attempts": 1} for context in contexts]
    if any(value != limits[0] for value in limits[1:]):
        raise ValueError("one flight requires identical declared physical limits")
    return batch, policy, bindings, manifests, sorted(roots), limits[0]


def current_sidecar(sidecar, canonical, *, workload_id, workload_sha256):
    """Equal current authority only: no historical runtime/Source projection."""
    expected_source = {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
    receipt = sidecar.get("implementation_receipt", {})
    if (sidecar.get("workload_id") != workload_id
        or sidecar.get("base_manifest", {}).get("sha256") != workload_sha256
        or sidecar.get("qualification_source") != expected_source
        or sidecar.get("qualification_image_digest") != canonical["collection_image_digest"]
        or receipt.get("sha256") != canonical["checks"]["collection"]["qualification_implementation_sha256"]
        or receipt.get("neqo_qcsd_client", {}).get("sha256") != canonical["installed_client_sha256"]):
        raise ValueError("response evidence changed current Source/image/client/implementation/workload")


def reuse_input(path, bindings, canonical, workload_root):
    from qcsd_lab.chaff_qualification import load_named_qualification_set
    path = Path(path).absolute()
    named = load_named_qualification_set(path, workload_root=Path(workload_root),
        expected_workload_ids=[row["workload_id"] for row in bindings],
        expected_qualification_scope="response-only", require_current_implementation=False)
    value = json.loads(read(path))
    from qcsd_lab.chaff_qualification import RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
    if value["qualification_sidecar_schema_version"] != RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION:
        raise ValueError("reuse requires actual response-only v2 epoch evidence")
    sidecars = {}
    for row in bindings:
        sidecar_path = path.parent / (row["workload_id"] + ".json")
        current_sidecar(json.loads(read(sidecar_path)), canonical,
            workload_id=row["workload_id"], workload_sha256=row["original_workload"]["sha256"])
        sidecars[row["workload_id"]] = ref(sidecar_path)
    return {"manifest": ref(path), "manifest_sha256": named.manifest_sha256, "sidecars": sidecars}


def group_roots(manifests):
    return sorted({root for manifest in manifests for root in static_roots(manifest)})

def checked_setup(args):
    raw = read(args.setup)
    if digest(raw) != args.setup_sha256:
        raise ValueError("prospective setup changed")
    setup = json.loads(raw)
    output = Path(args.setup).absolute().parent
    if (setup["recipe"] != ref(__file__) or setup["mode"] not in MODES
        or output != Path(setup["output"]) or output / "setup.json" != args.setup.absolute()):
        raise ValueError("setup is not owned by this immutable namespace")
    canonical_ref, canonical, clean = checked_runtime(SimpleNamespace(
        runtime_build_root=Path(setup["runtime_build_root"]),
        clean_runtime_root=Path(setup["clean_runtime_root"]),
        canonical_sha256=setup["canonical_runtime_sha256"],
        expected_lab_commit=setup["expected_lab_commit"],
        expected_native_commit=setup["expected_native_commit"]))
    if (canonical != setup["canonical_runtime"]
        or checked(setup["canonical_runtime_reference"]) != checked(canonical_ref)
        or read(output / "canonical-runtime.json") != checked(canonical_ref)):
        raise ValueError("setup actual runtime changed")
    host_imports(clean)
    from qcsd_lab import rapid_rolling_capture as rolling
    runtime = rolling.load_runtime(Path(setup["runtime_spec"]["path"]))
    checked(setup["runtime_spec"])
    _, policy, bindings, manifests, roots, limits = selected_inputs(
        setup["enrollment"]["path"], setup["study_root"])
    checked(setup["enrollment"])
    if (bindings != setup["selected_classes"] or roots != setup["original_roots"]
        or limits != setup["original_limits"] or runtime["data_root"] != policy["runtime"]["data_root"]):
        raise ValueError("setup original enrollment, complete graphs, roots or limits changed")
    for row in bindings:
        if read(output / "lineage/originals" / (row["workload_id"] + ".json")) != checked(row["original_workload"]):
            raise ValueError("original immutable manifest copy changed")
    for relative, record in json.loads(read(output / "source-inventory.json")).items():
        for base in (clean, Path(setup["execution_root"])):
            source = base / relative
            if digest(read(source)) != record["sha256"] or bool(source.stat().st_mode & 0o111) != record["executable"]:
                raise ValueError("setup complete Source inventory or executable mode changed")
    if digest(read(output / "source-inventory.json")) != canonical["source_inventory_sha256"]:
        raise ValueError("setup Source inventory changed")
    checked(setup["amendment_commands"])
    if setup["reuse"] is not None:
        expected = reuse_input(setup["reuse"]["manifest"]["path"], bindings, canonical,
                               Path(setup["execution_root"]) / "config/workloads")
        if expected != setup["reuse"]:
            raise ValueError("reuse input changed after declaration")
        for workload_id, record in setup["reuse"]["sidecars"].items():
            if read(Path(setup["execution_root"]) / "config/flight-reuse" / (workload_id + ".json")) != checked(record):
                raise ValueError("copied current response qualification changed")
    return setup, output, clean, runtime, bindings, manifests

def stage(args):
    """HOST-only create-only export; physical actions are separately invoked."""
    if (re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.name) is None
        or type(args.campaign_seed) is not int or not 0 <= args.campaign_seed < 2**64):
        raise ValueError("safe lowercase name and unsigned 64-bit seed required")
    canonical_ref, canonical, clean = checked_runtime(args)
    host_imports(clean)
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import capture_acceptance_policy as capture
    from qcsd_lab.buflo_duration_budget import POLICY
    enrollment = args.enrollment.absolute()
    _, policy, bindings, manifests, roots, limits = selected_inputs(enrollment, args.study_root)
    output, study = args.output.absolute(), args.study_root.absolute()
    data = Path(policy["runtime"]["data_root"])
    protected = [clean, args.runtime_build_root.absolute(), study, HERE,
                 *(Path(row["admission_root"]) for row in bindings), *(Path(root) for root in roots)]
    reuse_manifest = getattr(args, "reuse_qualification", None)
    if reuse_manifest is not None:
        if args.mode in AMENDED_MODES:
            raise ValueError("prospective amended preparations require fresh post-declaration response epochs")
        protected.append(reuse_manifest.absolute().parent)
    if (not data.is_dir() or not output.is_relative_to(data) or output.exists()
        or any(path.is_symlink() for path in (output, *output.parents))
        or any(output.is_relative_to(path) or path.is_relative_to(output) for path in protected)):
        raise ValueError("fresh flight namespace must be absent and disjoint from immutable inputs")
    amendment = study / (args.name + "-capture-amendment.json") if args.mode in AMENDED_MODES else None
    if amendment is not None:
        declaration = amendment.with_name(amendment.stem + "-declaration.json")
        if any(path.exists() or path.is_symlink() for path in (amendment, declaration)):
            raise ValueError("prospective amendment names are create-only")
    output.mkdir(parents=True, mode=0o700)
    execution = output / "execution-root"
    shutil.copytree(args.runtime_build_root / "image-context/source", execution)
    for path in execution.rglob("*"):
        if path.is_file():
            path.chmod(path.stat().st_mode & 0o755)
    for row in bindings:
        original = checked(row["original_workload"])
        target = execution / "config/workloads" / (row["workload_id"] + ".json")
        if target.exists() or target.is_symlink():
            raise ValueError("export already contains an enrolled flight workload")
        create(output / "lineage/originals" / target.name, original)
        if amendment is None:
            create(target, original)
    create(output / "lineage/original-manifest.json", checked(bindings[0]["original_workload"]))
    create(output / "lineage/original-enrollment.json", read(enrollment))
    for name in ("logs", "dns-receipts", "plans"):
        (output / name).mkdir(mode=0o700)
    create(output / "canonical-runtime.json", checked(canonical_ref))
    create(output / "source-inventory.json", read(args.runtime_build_root / "source-inventory.json"))
    runtime = {"data_root": str(data), "runtime_source_root": str(clean), "module_root": str(clean),
        "execution_root": str(execution), "workload_root": str(execution / "config/workloads"),
        "campaign_dir": str(execution / "config/campaigns"),
        "source_manifest": str(args.runtime_build_root.absolute() / "runtime-export/source.json"),
        "client_binary": str(args.runtime_build_root.absolute() / "runtime-export/neqo-qcsd-client"),
        "base_launcher": str(clean / "qcsd-lab"), "host_launcher": str(execution / "qcsd-lab"),
        "collection_image_digest": canonical["collection_image_digest"], "execution_generation": args.name}
    runtime_path = output / "runtime-spec.json"
    create(runtime_path, encode({"schema_version": 1, "artifact_type": rolling.RUNTIME_TYPE, "inputs": runtime}))
    rolling.load_runtime(runtime_path)
    prefix = [str(args.python.absolute()), "-I", "-B", "-c", PUBLIC_CLI_BOOTSTRAP,
              str(clean / "src"), str(clean / "tools/rapid_rolling_capture.py")]
    command = None
    if amendment is not None:
        command = prefix + ["static-amendment", "--enrollment", str(enrollment),
                            "--runtime-spec", str(runtime_path), "--output", str(amendment)]
        if args.mode == "front":
            command += ["--front-policy", capture.FRONT_RESERVE_POLICY]
        else:
            command += ["--buflo-policy", capture.BUFLO_KERNEL_PREPARATION_POLICY,
                        "--buflo-duration-policy", POLICY]
    create(output / "amendment-commands.json", encode({"amend": command}))
    reuse = None
    if reuse_manifest is not None:
        reuse = reuse_input(reuse_manifest, bindings, canonical, execution / "config/workloads")
        for workload_id, record in reuse["sidecars"].items():
            create(execution / "config/flight-reuse" / (workload_id + ".json"), checked(record))
    setup = {"schema_version": 1, "purpose": "prospective-full-static-1-to-5-setting-flight-setup", **ZERO,
        "recipe": ref(__file__), "output": str(output), "name": args.name, "mode": args.mode,
        "campaign_seed": args.campaign_seed, "host_python": str(args.python.absolute()),
        "expected_lab_commit": args.expected_lab_commit, "expected_native_commit": args.expected_native_commit,
        "runtime_build_root": str(args.runtime_build_root.absolute()), "clean_runtime_root": str(clean),
        "execution_root": str(execution), "canonical_runtime": canonical,
        "canonical_runtime_sha256": args.canonical_sha256, "canonical_runtime_reference": canonical_ref,
        "runtime_spec": ref(runtime_path), "study_root": str(study), "enrollment": ref(enrollment),
        "selected_classes": bindings, "original_roots": roots, "original_limits": limits,
        "amendment_path": None if amendment is None else str(amendment), "reuse": reuse,
        "amendment_commands": ref(output / "amendment-commands.json")}
    create(output / "setup.json", encode(setup))
    return {"setup": ref(output / "setup.json"), "commands": ref(output / "amendment-commands.json"),
            "class_count": len(bindings), "physical_actions_performed": False, **ZERO}

def amend(args):
    setup, output, clean, _, bindings, _ = checked_setup(args)
    if setup["mode"] not in AMENDED_MODES:
        raise ValueError("original-static settings have no prospective amendment step")
    command = json.loads(checked(setup["amendment_commands"]))["amend"]
    amendment = Path(setup["amendment_path"])
    declaration = amendment.with_name(amendment.stem + "-declaration.json")
    targets = [Path(setup["execution_root"]) / "config/workloads" / (row["workload_id"] + ".json") for row in bindings]
    if any(path.exists() or path.is_symlink() for path in (*targets, amendment, declaration)):
        raise ValueError("preserve attempted amendment; stage a new successor")
    recorder = module(RECORDER, RECORDER_SHA, "group_flight_recorder")
    recorder.recorded_run(command, output / "logs", "amend", cwd=clean)

def finalize(args):
    setup, output, clean, runtime, bindings, originals = checked_setup(args)
    from qcsd_lab import supplied_static_capture_amendment as adapter
    from qcsd_lab import rapid_capture_traffic as traffic
    from qcsd_lab import buflo_duration_budget as budget
    from qcsd_lab.rapid_capture_plan import PARAMETER_REFERENCES
    from qcsd_lab.orchestrator import _stable_seed
    mode, authority = setup["mode"], None
    manifests, current = [], []
    if mode in AMENDED_MODES:
        command = json.loads(checked(setup["amendment_commands"]))["amend"]
        require_operation(output, "amend", command)
        amendment = Path(setup["amendment_path"])
        authority = adapter.validate_amendment(amendment,
            enrollment=Path(setup["enrollment"]["path"]), runtime=runtime)
        if authority["modes"] != [mode] or len(authority["workloads"]) != len(bindings):
            raise ValueError("public amendment must authorize this exact group and setting")
        by_candidate = {row["candidate_id"]: row for row in authority["workloads"]}
        if set(by_candidate) != {row["candidate_id"] for row in bindings}:
            raise ValueError("amendment class identities changed")
    for binding, original in zip(bindings, originals):
        copied = Path(runtime["workload_root"]) / (binding["workload_id"] + ".json")
        manifest_raw = read(copied)
        manifest = json.loads(manifest_raw)
        if authority is not None:
            row = by_candidate[binding["candidate_id"]]
            if row["capture_manifest"] != ref(copied):
                raise ValueError("amendment derived manifest path or bytes changed")
            adapter.validate_preparation(manifest["preparation"], manifest["resources"])
        elif manifest_raw != checked(binding["original_workload"]):
            raise ValueError("plain static mode changed its exact original manifest")
        if manifest["resources"] != original["resources"] or graph(manifest) != binding["full_graph"]:
            raise ValueError("flight must preserve all occurrences, dependencies, headers and origins")
        manifests.append(manifest)
        current.append({**binding, "capture_manifest": ref(copied)})
    selected_policy = None if authority is None else authority.get(traffic.FIELD)
    limits = budget.capture_limits(mode, setup["original_limits"], policy=selected_policy)
    if (mode == "buflo" and selected_policy != budget.POLICY
        or mode != "buflo" and selected_policy is not None):
        raise ValueError("setting changed its prospective traffic policy")
    canary, manifest = current[0], manifests[0]
    copied = Path(canary["capture_manifest"]["path"])
    qualification_set, group_set = setup["name"] + "-canary", setup["name"] + "-group"
    name = "rapid-curated-tranco50-v2-diagnostic-v12-" + setup["name"] + "-" + mode
    defense = {"name": mode, "kind": "none" if mode == "undefended" else mode}
    if mode == "buflo":
        defense["parameters"] = "../defense-params/buflo-duration200.json"
    elif mode in PARAMETER_REFERENCES:
        defense["parameters"] = PARAMETER_REFERENCES[mode]
    campaign = {"schema": 1, "name": name, "purpose": "smoke", "seed": setup["campaign_seed"],
        "profile": "research-1200", "workloads": {canary["workload_id"]: 1},
        "request_policies": ["as-defined"], "defenses": [defense], "limits": limits}
    if mode != "undefended":
        campaign["chaff_qualification_set"] = qualification_set
    import yaml
    execution = Path(setup["execution_root"])
    relative = "config/campaigns/" + name + ".yml"
    raw = yaml.safe_dump(campaign, sort_keys=False, width=100).encode()
    create(execution / relative, raw)
    run_argv = ["env", "QCSD_LAB_COLLECTION_IMAGE=" + setup["canonical_runtime"]["collection_image_digest"],
        f"QCSD_RAPID_IMAGE_SOURCE_QCSD={clean / 'qcsd-lab'}",
        f"QCSD_RAPID_DNS_RECEIPT_PATH={output / 'dns-receipts' / (mode + '.json')}",
        str(execution / "qcsd-lab"), "run", str(execution / relative)]
    campaigns = [{"mode": mode, "name": name, "visits": 1, "limits": limits,
        "campaign_relative": relative, "campaign_sha256": digest(raw), "run_argv": run_argv,
        "sample_seed": _stable_seed("sample-seed", setup["campaign_seed"], canary["workload_id"], "as-defined", 0, mode)}]
    named = "chaff-response-qualification-store/sets/" + group_set
    qspec = execution / "config/rolling-static-qualification-spec.json"
    create(qspec, encode({"schema_version": 1, "qualification_sets": [{"qualification_set": group_set,
        "manifest": named + "/_qualification-set.json", "sidecar_root": named, "prefix_spec_root": None}]}))
    plan = {"schema_version": 1, "purpose": "private-static-full-1-to-5-setting-canary", **ZERO,
        "name": setup["name"], "data_role": manifest["preparation"]["data_role"],
        "recipe_sha256": digest(read(__file__)), "host_python": setup["host_python"],
        "helper_sha256": FIRST_HELPER_SHA, "helper_path": str(FIRST_HELPER),
        "clean_runtime_root": str(clean), "execution_root": str(execution),
        "expected_lab_commit": setup["expected_lab_commit"], "expected_native_commit": setup["expected_native_commit"],
        "canonical_runtime": setup["canonical_runtime"], "canonical_runtime_sha256": setup["canonical_runtime_sha256"],
        "selection_sha256": canary["selection_sha256"],
        "selection_role": "prospective-static-admission-profile", "acquisition_root": canary["admission_root"],
        "original_terminal": canary["terminal"], "original_workload": canary["original_workload"],
        "original_workload_sha256": canary["original_workload"]["sha256"],
        "workload_sha256": canary["capture_manifest"]["sha256"], "workload_id": canary["workload_id"],
        "workload_relative": copied.relative_to(execution).as_posix(),
        "qualification_set": qualification_set, "group_qualification_set": group_set,
        "selected_classes": current, "full_graph": canary["full_graph"],
        "traffic_hashes": traffic.expected(selected_policy),
        "static_preparation_roots": static_roots(manifest), "group_preparation_roots": group_roots(manifests),
        "capture_limits": limits, "campaigns": campaigns, "reuse": setup["reuse"],
        "study_root": setup["study_root"], "enrollment": setup["enrollment"]}
    if authority is not None:
        plan["static_capture_amendment"] = ref(Path(setup["amendment_path"]))
    if selected_policy is not None:
        plan[traffic.FIELD] = selected_policy
    create(output / "plan.json", encode(plan))
    prefix = [setup["host_python"], "-I", "-B", "-c", PUBLIC_CLI_BOOTSTRAP,
              str(clean / "src"), str(clean / "tools/rapid_rolling_capture.py")]
    commands = {"preamble": image_argv(plan, output, "preamble-image"),
                "qualify": image_argv(plan, output, "qualify-image"),
                "preflight": image_argv(plan, output, "preflight-image", "--mode", mode)}
    commands["plan"] = prefix + ["plan", "--evidence-root", setup["study_root"],
        "--enrollment", setup["enrollment"]["path"], "--qualification-spec", str(qspec),
        "--readiness", str(output / "readiness.json"), "--runtime-spec", str(output / "runtime-spec.json"),
        "--output", str(output / "plans/g01.json"), "--spec-output", str(output / "plans/g01-spec.json")]
    if authority is not None:
        commands["plan"] += ["--static-capture-amendment", setup["amendment_path"]]
    create(output / "commands.json", encode(commands))
    staged = {"recipe": ref(__file__), "setup": ref(output / "setup.json"), "plan": ref(output / "plan.json"),
        "runtime_spec": ref(output / "runtime-spec.json"), "qualification_spec": ref(qspec),
        "canonical_runtime": setup["canonical_runtime_reference"], "commands": ref(output / "commands.json"), **ZERO}
    if authority is not None:
        staged["static_capture_amendment"] = plan["static_capture_amendment"]
    create(output / "staged.json", encode(staged))
    return {"staged": ref(output / "staged.json"), "plan": ref(output / "plan.json"),
            "commands": ref(output / "commands.json"), "class_count": len(bindings),
            "physical_actions_performed": False, **ZERO}

def image_argv(plan, output, action, *extra):
    network = "bridge" if action == "qualify-image" and plan["reuse"] is None else "none"
    argv = ["docker", "run", "--rm", "--name", f'qcsd-v12-{plan["name"]}-{action}',
        "--network", network, "--user", f"{os.getuid()}:{os.getgid()}",
        "--security-opt", "no-new-privileges", "--cap-drop", "ALL",
        "--env", "QCSD_LAB_IMAGE_DIGEST=" + plan["canonical_runtime"]["collection_image_digest"],
        "--env", "QCSD_LAB_ROOT=/lab", "--env", "QCSD_LAB_SOURCE_METADATA=/usr/share/qcsd-lab/source.json",
        "--env", "QCSD_PUBLIC_ORIGIN_ONLY=1", "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--volume", f'{plan["clean_runtime_root"]}:/runtime-src:ro',
        "--volume", f'{plan["execution_root"]}:/lab:' + ("rw" if action == "qualify-image" else "ro"),
        "--volume", f"{output}:/diagnostic:rw", "--volume", f"{Path(__file__).absolute()}:/recipe.py:ro",
        "--volume", f'{plan["helper_path"]}:/helpers.py:ro']
    roots = plan["static_preparation_roots"] if action == "verify-image" else plan["group_preparation_roots"]
    for root in roots:
        argv += ["--volume", f"{root}:{root}:ro"]
    return argv + ["--workdir", "/lab", "--entrypoint", "/opt/qcsd-venv/bin/python3",
        plan["canonical_runtime"]["collection_image_digest"], "-I", "-B", "/recipe.py", action,
        "--plan", "/diagnostic/plan.json", "--plan-sha256", digest(read(output / "plan.json")), *extra]


def checked_plan(args, *, image=False):
    raw = read(args.plan)
    if digest(raw) != args.plan_sha256:
        raise ValueError("first-site plan changed")
    plan = json.loads(raw)
    output = Path("/diagnostic") if image else Path(args.plan).absolute().parent
    clean = Path("/runtime-src") if image else Path(plan["clean_runtime_root"])
    execution = Path("/lab") if image else Path(plan["execution_root"])
    if (plan["recipe_sha256"] != digest(read(__file__)) or plan["helper_sha256"] != FIRST_HELPER_SHA
        or re.fullmatch(r"[0-9a-f]{40}", str(plan["expected_lab_commit"])) is None
        or re.fullmatch(r"[0-9a-f]{40}", str(plan["expected_native_commit"])) is None):
        raise ValueError("first-site recipe or frozen Source differs")
    canonical_raw = read(output / "canonical-runtime.json")
    canonical = json.loads(canonical_raw)
    if (canonical != plan["canonical_runtime"] or digest(canonical_raw) != plan["canonical_runtime_sha256"]
        or canonical["source"]["lab_commit"] != plan["expected_lab_commit"]
        or canonical["source"]["neqo_commit"] != plan["expected_native_commit"]):
        raise ValueError("actual canonical runtime differs")
    inventory_raw = read(output / "source-inventory.json")
    if digest(inventory_raw) != canonical["source_inventory_sha256"]:
        raise ValueError("complete Source inventory changed")
    for relative, record in json.loads(inventory_raw).items():
        for base in (clean, execution):
            path = base / relative
            if digest(read(path)) != record["sha256"] or bool(path.stat().st_mode & 0o111) != record["executable"]:
                raise ValueError("complete mounted Source bytes or modes changed")
    if not image:
        host_imports(clean)

    from qcsd_lab import supplied_static_capture_amendment as adapter
    from qcsd_lab import rapid_capture_traffic as traffic
    from qcsd_lab import supplied_static_preparation as preparation
    original = read(output / "lineage/original-manifest.json")
    manifest_raw = read(execution / plan["workload_relative"])
    manifest = json.loads(manifest_raw)
    [campaign] = plan["campaigns"]
    mode = campaign["mode"]
    if mode not in MODES:
        raise ValueError("unknown flight setting")
    amended = "static_capture_amendment" in plan
    if amended != (mode in AMENDED_MODES) or not 1 <= len(plan["selected_classes"]) <= 5:
        raise ValueError("wrong setting amendment or class count")
    selected_policy = traffic.canary_policy(plan, mode)
    runtime = json.loads(read(output / "runtime-spec.json"))["inputs"]
    authority = None
    if amended:
        authority = adapter._closed(Path(plan["static_capture_amendment"]["path"]))
        checked(plan["static_capture_amendment"])
        adapter.validate_preparation(manifest["preparation"], manifest["resources"])
        if (authority["runtime"] != runtime or authority["declaration"] != manifest["preparation"][adapter.FIELD]
            or plan["enrollment"] != json.loads(checked(authority["declaration"]))["payload"]["enrollment"]
            or authority["modes"] != [mode] or authority.get(traffic.FIELD) != selected_policy):
            raise ValueError("canary amendment changed the current runtime, enrollment or setting")
    else:
        if manifest_raw != original or selected_policy is not None:
            raise ValueError("plain mode changed its original manifest or authority")
        if manifest["preparation"]["data_role"] != preparation.ROLE:
            typed_original(manifest)
    if (digest(original) != plan["original_workload_sha256"]
        or manifest["resources"] != json.loads(original)["resources"]
        or digest(manifest_raw) != plan["workload_sha256"] or graph(manifest) != plan["full_graph"]
        or plan["data_role"] != manifest["preparation"]["data_role"]
        or static_roots(manifest) != plan["static_preparation_roots"]):
        raise ValueError("canary complete original graph or transport changed")
    if digest(read(output / "lineage/original-enrollment.json")) != plan["enrollment"]["sha256"]:
        raise ValueError("enrollment lineage changed")
    if not image:
        checked(plan["enrollment"])
        _, checked_policy, expected, originals, _, _ = selected_inputs(plan["enrollment"]["path"], plan["study_root"])
        recorded = [{key: value for key, value in row.items() if key != "capture_manifest"} for row in plan["selected_classes"]]
        if expected != recorded:
            raise ValueError("selected original classes changed")
    local_manifests = []
    for row in plan["selected_classes"]:
        path = execution / "config/workloads" / (row["workload_id"] + ".json")
        local_raw = read(path)
        local = json.loads(local_raw)
        original_raw = read(output / "lineage/originals" / path.name)
        if (digest(original_raw) != row["original_workload"]["sha256"]
            or digest(local_raw) != row["capture_manifest"]["sha256"]
            or local["resources"] != json.loads(original_raw)["resources"]
            or graph(local) != row["full_graph"]):
            raise ValueError("selected complete graph bytes or occurrence identity changed")
        if authority is None and local_raw != original_raw:
            raise ValueError("plain group manifest changed")
        if authority is None and local["preparation"]["data_role"] != preparation.ROLE:
            typed_original(local)
        if authority is not None:
            matching = [item for item in authority["workloads"] if item["candidate_id"] == row["candidate_id"]]
            if len(matching) != 1 or matching[0]["capture_manifest"] != row["capture_manifest"]:
                raise ValueError("group amendment derived manifest binding changed")
        local_manifests.append(local)
    if authority is None and any(local["preparation"]["data_role"] != preparation.ROLE for local in local_manifests):
        expected_limits = typed_canary_limits(local_manifests, None if image else checked_policy, mode, selected_policy)
        if plan["capture_limits"] != expected_limits or campaign["limits"] != expected_limits:
            raise ValueError("typed canary changed its authenticated response or recording limits")
    if (not image or args.command != "verify-image") and group_roots(local_manifests) != plan["group_preparation_roots"]:
        raise ValueError("full selected group transport changed")
    if plan["reuse"] is not None:
        if amended:
            raise ValueError("amended epochs cannot be relabeled as reused")
        for row in plan["selected_classes"]:
            record = plan["reuse"]["sidecars"].get(row["workload_id"])
            if record is None:
                raise ValueError("reuse omitted selected class")
            copied = execution / "config/flight-reuse" / (row["workload_id"] + ".json")
            raw_reuse = read(copied)
            if digest(raw_reuse) != record["sha256"]:
                raise ValueError("copied reused sidecar changed")
            current_sidecar(json.loads(raw_reuse), canonical, workload_id=row["workload_id"],
                            workload_sha256=row["capture_manifest"]["sha256"])
    if digest(read("/helpers.py" if image else plan["helper_path"])) != FIRST_HELPER_SHA:
        raise ValueError("immutable HOST/runtime helper changed")
    if image:
        from qcsd_lab.chaff_qualification import implementation_receipt
        from qcsd_lab.runtime_provenance import validate_runtime_receipt
        from qcsd_lab.util import source_metadata
        expected = canonical["checks"]["collection"]
        if (json.loads(read("/usr/share/qcsd-lab/source.json")) != canonical["source"]
            or source_metadata() != {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
            or digest(read("/usr/local/bin/neqo-qcsd-client")) != canonical["installed_client_sha256"]
            or os.environ.get("QCSD_LAB_IMAGE_DIGEST") != canonical["collection_image_digest"]
            or implementation_receipt(executed_image=True)["sha256"] != expected["qualification_implementation_sha256"]
            or validate_runtime_receipt()["payload_sha256"] != expected["python_runtime_payload_sha256"]):
            raise ValueError("current installed Source/client/qualification implementation differs")
    return plan, output, execution


def image_action(args):
    plan, output, execution = checked_plan(args, image=True)
    if args.command == "preamble-image":
        from qcsd_lab.manifest import validate_manifest, validate_research_preparation
        from qcsd_lab import capture_acceptance_policy as capture
        for row in plan["selected_classes"]:
            manifest = json.loads(read(execution / "config/workloads" / (row["workload_id"] + ".json")))
            validate_manifest(manifest)
            validate_research_preparation(manifest, workload_id=row["workload_id"])
        [campaign] = plan["campaigns"]
        mode = campaign["mode"]
        for row in plan["selected_classes"]:
            preparation = json.loads(read(execution / "config/workloads" / (row["workload_id"] + ".json")))["preparation"]
            capture.validate_front_preparation_policy(preparation)
            capture.validate_buflo_kernel_preparation_policy(preparation)
        if mode == "buflo":
            from qcsd_lab.buflo_duration_budget import PARAMETER_PATH
            from qcsd_lab.parameters import validate_parameter_artifact
            validate_parameter_artifact(execution / PARAMETER_PATH, expected_kind="buflo",
                allow_study_candidate=True, expected_qcsd_profile="research-1200",
                expected_udp_payload_ceiling=1200)
        create(output / "preamble-complete.json", encode({"completed_at": now(),
            "plan_sha256": args.plan_sha256, "mode": mode, "installed_source_and_client_checked": True,
            "manifest_schema_checked": True, "qualification_performed": False,
            "capture_performed": False, **ZERO}))
        return
    if args.command == "qualify-image":
        from qcsd_lab.chaff_qualification import (qualify_response_chaff_v2, publish_named_qualification_set,
            RESPONSE_ONLY_QUALIFICATION_SCOPE, RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION)

        workload_ids = [row["workload_id"] for row in plan["selected_classes"]]
        if plan["reuse"] is None:
            sidecars = execution / "config/static-response-sidecars" / plan["group_qualification_set"]
            sidecars.mkdir(parents=True, exist_ok=False)
            for workload_id in workload_ids:
                qualify_response_chaff_v2(workload_id, qualification_root=sidecars,
                    workload_root=execution / "config/workloads")
        else:
            sidecars = execution / "config/flight-reuse"
        store = execution / "config/chaff-response-qualification-store/sets"
        store.mkdir(parents=True, exist_ok=True)
        group = publish_named_qualification_set(workload_ids,
            qualification_set=plan["group_qualification_set"],
            qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
            workload_root=execution / "config/workloads", sidecar_root=sidecars, publication_root=store,
            qualification_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION)
        named = publish_named_qualification_set([plan["workload_id"]],
            qualification_set=plan["qualification_set"],
            qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
            workload_root=execution / "config/workloads", sidecar_root=sidecars, publication_root=store,
            qualification_sidecar_schema_version=RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION)
        create(output / "qualification-complete.json", encode({"completed_at": now(),
            "plan_sha256": args.plan_sha256, "workload_id": plan["workload_id"],
            "workload_sha256": plan["workload_sha256"],
            "sidecar_sha256": digest(read(sidecars / (plan["workload_id"] + ".json"))),
            "named_manifest_sha256": named.manifest_sha256, "qualification_set": named.qualification_set,
            "group_manifest_sha256": group.manifest_sha256, "group_qualification_set": group.qualification_set,
            "workload_ids": workload_ids, "reused_same_current_evidence": plan["reuse"] is not None, **ZERO}))
        return
    from qcsd_lab.orchestrator import preflight_campaign
    selected = plan["campaigns"] if args.mode is None else [c for c in plan["campaigns"] if c["mode"] == args.mode]
    if not selected:
        raise ValueError("preflight setting is absent")
    if args.command == "preflight-image":
        for campaign in selected:
            result = preflight_campaign(execution / campaign["campaign_relative"])
            if (result["sample_count"] != 1 or result["purpose"] != "smoke"
                or result["defenses"] != [campaign["mode"]]
                or [row["id"] for row in result["workloads"]] != [plan["workload_id"]]):
                raise ValueError("installed preflight changed the exact full single visit")
            if campaign["mode"] != "undefended":
                q = json.loads(read(output / "qualification-complete.json"))
                if result["chaff_qualification_set_manifest_sha256"] != q["named_manifest_sha256"]:
                    raise ValueError("installed preflight did not use this actual named120 qualification")
            create(output / (campaign["mode"] + "-preflight-complete.json"), encode({
                "plan_sha256": args.plan_sha256, "check": result, **ZERO}))
        return
    [campaign] = selected
    mode = campaign["mode"]
    from qcsd_lab.verification import verify_result
    from qcsd_lab.rapid_lane_evidence import verify_dns_receipt
    from qcsd_lab.application_response_policy import validate_application_responses, application_response_identity_signature
    from qcsd_lab.capture_acceptance_policy import validate_terminal_primary_source_binding
    result_root = args.result.resolve(strict=True)
    if result_root.parent != execution / "results" / campaign["name"] or args.result.is_symlink():
        raise ValueError("result is outside its actual single canary parent")
    verified = verify_result(result_root)
    experiment = verified.experiment
    config = experiment["configuration"]
    [workload], [defense], [sample] = config["workloads"], config["defenses"], experiment["samples"]
    if (experiment["status"] != "complete" or experiment["summary"]["passed"] is not True
        or experiment["name"] != campaign["name"] or experiment["purpose"] != "smoke"
        or len(verified.accepted_samples) != 1 or experiment["source"] != {**plan["canonical_runtime"]["source"],
            "image_digest": plan["canonical_runtime"]["collection_image_digest"]}
        or config["campaign_sha256"] != campaign["campaign_sha256"] or config["limits"] != campaign["limits"]
        or workload["id"] != plan["workload_id"] or workload["sha256"] != plan["workload_sha256"]
        or workload["visits"] != 1 or defense["name"] != mode or sample["seed"] != campaign["sample_seed"]):
        raise ValueError("amended deep did not complete the full graph single visit")
    manifest = json.loads(read(result_root / workload["manifest"]))
    run = json.loads(read(result_root / sample["path"] / "neqo/run.json"))
    if run["seed"] != campaign["sample_seed"] or graph(manifest) != plan["full_graph"]:
        raise ValueError("amended Native seed or whole graph changed")
    response = validate_application_responses(manifest, run)
    validate_terminal_primary_source_binding(manifest, run, runner_directory=result_root / sample["path"] / "neqo")
    if sorted(str(row["origin"]).rstrip("/") for row in run["endpoints"]) != plan["full_graph"]["origins"]:
        raise ValueError("Native omitted a supplied origin")
    identity = application_response_identity_signature(manifest, response["response_signature"])
    dns_sha = verify_dns_receipt(read(output / "dns-receipts" / (mode + ".json")), campaign["name"],
        {plan["workload_id"]: read(result_root / workload["manifest"])})
    create(output / (mode + "-deep-verification.json"), encode({**verified.as_dict(), **ZERO,
        "completed_at": now(), "mode": mode, "source": plan["canonical_runtime"]["source"],
        "plan_sha256": args.plan_sha256, "canonical_runtime_sha256": plan["canonical_runtime_sha256"],
        "selection_sha256": plan["selection_sha256"], "workload_sha256": plan["workload_sha256"],
        "experiment_sha256": digest(read(result_root / "experiment.json")),
        "evidence_index_sha256": digest(read(result_root / "evidence.sha256")), "dns_receipt_sha256": dns_sha,
        "response_identity_sha256": digest(encode(identity)), "full_graph": plan["full_graph"]}))


def readiness(args):
    plan, output, _ = checked_plan(args)
    from qcsd_lab.rapid_rolling_readiness import validate_canary
    from qcsd_lab.rapid_lane_evidence import RUNTIME_KEYS
    runtime = json.loads(read(output / "runtime-spec.json"))["inputs"]
    references = {}
    if args.modes != [plan["campaigns"][0]["mode"]]:
        raise ValueError("readiness must contain only this separately amended setting")
    for mode in args.modes:
        reference = {"schema_version": 1, "plan": ref(output / "plan.json"),
                     "deep_receipt": ref(output / (mode + "-deep-verification.json"))}
        for operation in ("capture", "deep"):
            reference[operation] = {key: ref(output / "logs" / (mode + "-" + operation + suffix))
                for key, suffix in (("started", "-started.json"), ("completed", "-completed.json"),
                                    ("stdout", ".stdout.log"), ("stderr", ".stderr.log"))}
        validate_canary(reference, runtime={key: runtime[key] for key in RUNTIME_KEYS}, mode=mode)
        references[mode] = reference
    destination = args.output.absolute() if args.output is not None else output / "readiness.json"
    if destination.parent != output or any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError("readiness output must be a fresh direct file in this canary namespace")
    create(destination, encode(references))
    return {"readiness": ref(destination), **ZERO}


def require_operation(output, name, command, *, allow_failure=False):
    started = json.loads(read(output / "logs" / (name + "-started.json")))
    completed = json.loads(read(output / "logs" / (name + "-completed.json")))
    if (started["command"] != command or type(completed["returncode"]) is not int
        or (not allow_failure and completed["returncode"] != 0)
        or completed["stdout_sha256"] != digest(read(output / "logs" / (name + ".stdout.log")))
        or completed["stderr_sha256"] != digest(read(output / "logs" / (name + ".stderr.log")))
        or datetime.fromisoformat(started["started_at"]) > datetime.fromisoformat(completed["completed_at"])):
        raise ValueError("actual prerequisite operation failed or changed")


def run(args):
    """Root-only action: each real process keeps a separate actual raw closure."""
    plan, output, execution = checked_plan(args)
    staged = json.loads(read(output / "staged.json"))
    if checked(staged["plan"]) != read(args.plan) or checked(staged["recipe"]) != read(__file__):
        raise ValueError("Root dispatcher changed its immutable stage or recipe")
    commands = json.loads(checked(staged["commands"]))
    recorder = module(RECORDER, RECORDER_SHA, "amended_first_site_recorder")
    [campaign] = plan["campaigns"]
    mode = campaign["mode"]
    if args.step == "qualify":
        require_operation(output, "preamble", commands["preamble"])
        if json.loads(read(output / "preamble-complete.json"))["plan_sha256"] != args.plan_sha256:
            raise ValueError("actual installed preamble belongs to another plan")
    if args.step == "preflight":
        require_operation(output, "qualify", commands["qualify"])
    if args.step == "plan":
        checked(ref(output / "readiness.json"))
    if args.step in {"capture", "deep"}:
        require_operation(output, "preflight", commands["preflight"])
        receipt = json.loads(read(output / (mode + "-preflight-complete.json")))
        if receipt["plan_sha256"] != args.plan_sha256:
            raise ValueError("actual preflight belongs to another frozen plan")
        parent = execution / "results" / campaign["name"]
        if args.step == "capture":
            if parent.exists() or parent.is_symlink():
                raise ValueError("preserve attempted canary; stage a fresh successor for retry")
            command, name = campaign["run_argv"], mode + "-capture"
        else:
            require_operation(output, mode + "-capture", campaign["run_argv"], allow_failure=True)
            children = list(parent.iterdir()) if parent.exists() else []
            if len(children) != 1 or not children[0].is_dir() or children[0].is_symlink():
                raise ValueError("actual capture lacks exactly one direct result child")
            command = image_argv(plan, output, "verify-image", "--mode", mode,
                "--result", f'/lab/results/{campaign["name"]}/{children[0].name}')
            name = mode + "-deep"
    else:
        command, name = commands[args.step], args.step
    old_python = os.environ.get("QCSD_PARALLEL_HOST_PYTHON")
    os.environ["QCSD_PARALLEL_HOST_PYTHON"] = plan["host_python"]
    try:
        recorder.recorded_run(command, output / "logs", name,
                              cwd=Path(plan["clean_runtime_root"]) if args.step == "plan" else None)
    finally:
        if old_python is None:
            os.environ.pop("QCSD_PARALLEL_HOST_PYTHON", None)
        else:
            os.environ["QCSD_PARALLEL_HOST_PYTHON"] = old_python


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    item = commands.add_parser("stage")
    for option in ("runtime-build-root", "clean-runtime-root",
                   "study-root", "enrollment", "output", "python"):
        item.add_argument("--" + option, type=Path, required=True)
    item.add_argument("--canonical-sha256", required=True)
    item.add_argument("--expected-lab-commit", required=True)
    item.add_argument("--expected-native-commit", required=True)
    item.add_argument("--name", required=True)
    item.add_argument("--campaign-seed", type=int, required=True)
    item.add_argument("--mode", choices=MODES, required=True)
    item.add_argument("--reuse-qualification", type=Path,
                      help="exact current original-group named response-only v2 manifest")
    for name in ("amend", "finalize"):
        item = commands.add_parser(name)
        item.add_argument("--setup", type=Path, required=True)
        item.add_argument("--setup-sha256", required=True)
    for name in ("preamble-image", "qualify-image", "preflight-image", "verify-image", "readiness", "run"):
        item = commands.add_parser(name)
        item.add_argument("--plan", type=Path, required=True)
        item.add_argument("--plan-sha256", required=True)
        if name == "readiness":
            item.add_argument("--modes", nargs="+", choices=MODES, required=True)
            item.add_argument("--output", type=Path)
        elif name == "run":
            item.add_argument("--step", choices=("preamble", "qualify", "preflight", "capture", "deep", "plan"),
                              required=True)
        else:
            item.add_argument("--mode", choices=MODES, required=name == "verify-image")
            if name == "verify-image":
                item.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    dispatch = {"stage": stage, "amend": amend, "finalize": finalize, "readiness": readiness, "run": run}
    result = dispatch.get(args.command, image_action)(args)
    if result is not None:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
