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
CLI_BUFLO_POLICIES = ("rapid-v6-fixed-200s-duration-budget-v1",
                      "rapid-v7-fixed-64ms-640s-duration-budget-v1")
CLI_FRONT_POLICY = "rapid-v7-front-450-600-sigma1-4-incoming10000us-padding-10pct-window10000us-reserve1000us-v5"
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
    """Bind one authenticated SDK; never relabel an already imported package."""
    clean = Path(clean).absolute()
    package = clean / "src/qcsd_lab"
    read(package / "__init__.py")
    for name, loaded in tuple(sys.modules.items()):
        if name != "qcsd_lab" and not name.startswith("qcsd_lab."):
            continue
        origin = getattr(loaded, "__file__", None)
        if origin is None:
            raise ValueError("already imported qcsd SDK has no authenticated module source")
        origin = Path(origin).absolute()
        if (not origin.is_relative_to(package)
                or name == "qcsd_lab" and origin != package / "__init__.py"):
            raise ValueError("already imported qcsd SDK belongs to another source root")
        read(origin)
        paths = getattr(loaded, "__path__", None)
        if paths is not None and tuple(Path(item).absolute() for item in paths) != (origin.parent,):
            raise ValueError("already imported qcsd SDK has another package search path")
    sys.path[:0] = [str(clean / "src"), str(clean)]


def checked_runtime(args):
    first = module(FIRST_HELPER, FIRST_HELPER_SHA, "bound_first_site_helper")
    reference, canonical, clean = first.checked_runtime(SimpleNamespace(
        runtime_build_root=args.runtime_build_root, clean_runtime_root=args.clean_runtime_root,
        canonical_sha256=args.canonical_sha256, expected_lab_commit=args.expected_lab_commit))
    if (re.fullmatch(r"[0-9a-f]{40}", args.expected_native_commit) is None
        or canonical["source"]["neqo_commit"] != args.expected_native_commit):
        raise ValueError("new amended site requires the exact actual installed Native commit")
    return reference, canonical, clean



def _bind_host_sdk(args):
    """Authenticate HOST runtime metadata before importing its owning SDK."""
    if args.command == "stage":
        _, _, clean = checked_runtime(args)
    elif args.command in {"amend", "finalize"}:
        raw = read(args.setup)
        if digest(raw) != args.setup_sha256:
            raise ValueError("prospective setup changed")
        setup = json.loads(raw)
        output = args.setup.absolute().parent
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
    elif args.command in {"readiness", "run"}:
        raw = read(args.plan)
        if digest(raw) != args.plan_sha256:
            raise ValueError("first-site plan changed")
        plan = json.loads(raw)
        if (plan["recipe_sha256"] != digest(read(__file__)) or plan["helper_sha256"] != FIRST_HELPER_SHA
                or re.fullmatch(r"[0-9a-f]{40}", str(plan["expected_lab_commit"])) is None
                or re.fullmatch(r"[0-9a-f]{40}", str(plan["expected_native_commit"])) is None):
            raise ValueError("first-site recipe or frozen Source differs")
        canonical_raw = read(args.plan.absolute().parent / "canonical-runtime.json")
        canonical = json.loads(canonical_raw)
        if (canonical != plan["canonical_runtime"] or digest(canonical_raw) != plan["canonical_runtime_sha256"]
                or canonical["source"]["lab_commit"] != plan["expected_lab_commit"]
                or canonical["source"]["neqo_commit"] != plan["expected_native_commit"]):
            raise ValueError("actual canonical runtime differs")
        source_manifest = Path(canonical["source_manifest"])
        build = source_manifest.parent.parent
        if (not build.is_absolute() or source_manifest != build / "runtime-export/source.json"
                or canonical["client_binary"] != str(build / "runtime-export/neqo-qcsd-client")):
            raise ValueError("canonical HOST runtime export location differs")
        _, actual, clean = checked_runtime(SimpleNamespace(
            runtime_build_root=build, clean_runtime_root=Path(plan["clean_runtime_root"]),
            canonical_sha256=plan["canonical_runtime_sha256"],
            expected_lab_commit=plan["expected_lab_commit"],
            expected_native_commit=plan["expected_native_commit"]))
        if actual != canonical:
            raise ValueError("plan actual runtime changed before SDK binding")
    else:
        raise ValueError("HOST SDK binding cannot replace an installed image SDK")
    host_imports(clean)
    return clean


def typed_original(manifest):
    """Reopen a new role without changing any original GET authority."""
    from qcsd_lab import rapid_selected_budget_input as selected_budget
    if selected_budget.is_selected(manifest.get("preparation")):
        return selected_budget.validate_preparation(manifest["preparation"], manifest["resources"])
    from qcsd_lab import rapid_selected_capture_input as selected
    if selected.is_selected(manifest.get("preparation")):
        return selected.validate_preparation(manifest["preparation"], manifest["resources"])
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
    from qcsd_lab import rapid_selected_budget_input as selected_budget
    if selected_budget.is_selected(manifest.get("preparation")):
        selected_budget.validate_preparation(manifest["preparation"], manifest["resources"])
        value, _, _ = selected_budget.validate_input(selected_budget.plain.reopen(
            manifest["preparation"][selected_budget.FIELD]["receipt"]))
        return dict(value["capture_limits"])
    from qcsd_lab import per_class_selected_capture_amendment as per_class_amendment
    if per_class_amendment.is_amended(manifest.get("preparation")):
        per_class_amendment.validate_preparation(manifest["preparation"], manifest["resources"])
        declaration = per_class_amendment._declaration(per_class_amendment.rolling._open_ref(
            manifest["preparation"][per_class_amendment.old.FIELD]))
        return dict(declaration["capture_limits"])
    from qcsd_lab import rapid_selected_capture_input as selected
    from qcsd_lab import selected_capture_amendment as selected_amendment
    if selected_amendment.is_amended(manifest.get("preparation")):
        selected_amendment.validate_preparation(manifest["preparation"], manifest["resources"])
        declaration = selected_amendment._declaration(selected_amendment.rolling._open_ref(
            manifest["preparation"][selected_amendment.old.FIELD]))
        return dict(declaration["capture_limits"])
    if selected.is_selected(manifest.get("preparation")):
        selected.validate_preparation(manifest["preparation"], manifest["resources"])
        value, _, _ = selected.validate_input(selected.reopen(manifest["preparation"]["selected_input_evidence"]["receipt"]))
        return dict(value["capture_limits"])
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
    from qcsd_lab import rapid_per_class_selected_input as per_class_input
    from qcsd_lab import per_class_selected_capture_amendment as per_class_amendment
    from qcsd_lab import rapid_per_class_selected_enrollment as per_class
    if all(per_class_amendment.is_amended(manifest.get("preparation")) for manifest in manifests):
        declarations = [per_class_amendment._declaration(per_class_amendment.rolling._open_ref(
            manifest["preparation"][per_class_amendment.old.FIELD])) for manifest in manifests]
        if (mode not in AMENDED_MODES or any(row["modes"] != [mode] for row in declarations)
                or any(row.get("buflo_duration_policy") != selected_policy for row in declarations)):
            raise ValueError("per-class amended canary changed its fixed setting")
        declared = limits[0]
        if policy is not None and policy["contract"] != per_class.CONTRACT:
            raise ValueError("per-class canary imported another policy authority")
        return duration.capture_limits(mode, {**declared, "max_attempts": 1}, policy=selected_policy)
    if all(per_class_input.is_selected(manifest.get("preparation")) for manifest in manifests) and (
            policy is not None and policy["contract"] == per_class.CONTRACT
            or any(per_class_input.budget.is_selected(manifest.get("preparation")) for manifest in manifests)):
        if mode not in {"undefended", "tamaraw", "cs-buflo"} or selected_policy is not None:
            raise ValueError("per-class FRONT/BuFLO require their explicit typed amendment")
        return duration.capture_limits(mode, {**limits[0], "max_attempts": 1}, policy=selected_policy)
    from qcsd_lab.rapid_selected_capture_input import is_selected
    from qcsd_lab import selected_capture_amendment as selected_amendment
    if all(selected_amendment.is_amended(manifest.get("preparation")) for manifest in manifests):
        declarations = [selected_amendment._declaration(selected_amendment.rolling._open_ref(
            manifest["preparation"][selected_amendment.old.FIELD])) for manifest in manifests]
        if (mode not in AMENDED_MODES or any(row["modes"] != [mode] for row in declarations)
            or any(row.get("buflo_duration_policy") != selected_policy for row in declarations)):
            raise ValueError("selected canary requires its exact prospective fixed setting")
        declared = limits[0]
        if policy is not None and declared != policy["capture_limits"]:
            raise ValueError("selected amended graph limits differ from its enrollment")
    elif all(is_selected(manifest.get("preparation")) for manifest in manifests):
        if mode not in {"undefended", "tamaraw", "cs-buflo"} or selected_policy is not None:
            raise ValueError("selected FRONT and BuFLO need their separate prospective fixed policy authority")
        declared = limits[0]
        if policy is not None and declared != policy["capture_limits"]:
            raise ValueError("selected graph limits differ from its prospective enrollment policy")
    else:
        declared = capture.selected_capture_limits(manifests,
            limits[0] if policy is None else policy["capture_limits"])
    if declared != limits[0]:
        raise ValueError("enrolled policy differs from the authenticated original class budgets")
    return duration.capture_limits(mode, {**declared, "max_attempts": 1}, policy=selected_policy)


def selected_inputs(enrollment, study, *, class_indices=None, enrolled_subgroup=None, **kwargs):
    from qcsd_lab import rapid_enrolled_subgroup as subgroup
    from qcsd_lab import rapid_rolling_capture as rolling
    if class_indices is None and enrolled_subgroup is None:
        return _selected_inputs(enrollment, study, **kwargs)
    if kwargs.get("ordinary_renewal") is not None:
        raise ValueError("subgroup selection requires its own qualified flight, not ordinary-only renewal")
    batch, classes, _ = rolling._verify_enrollment(Path(enrollment).absolute())
    if enrolled_subgroup is None:
        enrolled_subgroup = subgroup.declare(Path(enrollment).absolute(), batch, classes, class_indices)
    rows = subgroup.validate(enrolled_subgroup, Path(enrollment).absolute(), batch, classes)
    if class_indices is not None and list(class_indices) != enrolled_subgroup["class_indices"]:
        raise ValueError("subgroup command and retained authority differ")
    batch, policy, bindings, manifests, roots, limits = _selected_inputs(enrollment, study, **kwargs)
    from qcsd_lab import selected_capture_amendment as metadata
    from qcsd_lab import rapid_additive_static_enrollment as additive
    from qcsd_lab import rapid_per_class_selected_enrollment as per_class
    if policy["contract"] == per_class.CONTRACT:
        from qcsd_lab import per_class_selected_capture_amendment as metadata
    elif policy["contract"] != additive.CONTRACT:
        raise ValueError("subgroup flight currently requires its selected-input enrollment authority")
    files, trees = metadata.metadata_inputs(Path(enrollment).absolute(), batch, classes, policy)
    roots = sorted(set(roots) | {str(path.parent) for path in files} | {str(path) for path in trees})
    chosen = {row["candidate_id"] for row in rows}
    pairs = [(binding, manifest) for binding, manifest in zip(bindings, manifests)
             if binding["candidate_id"] in chosen]
    if [binding["candidate_id"] for binding, _ in pairs] != [row["candidate_id"] for row in rows]:
        raise ValueError("subgroup full manifests differ from authenticated class identities")
    return batch, policy, [binding for binding, _ in pairs], [manifest for _, manifest in pairs], roots, limits


def _selected_inputs(enrollment, study, *, prospective_amendment=False, ordinary_renewal=None,
                    selected_input_renewal=None, runtime=None, mode=None, tamaraw_configuration_policy=None):
    """Authenticate the current declared batch, preserving each original graph."""
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import supplied_static_admission as static
    from qcsd_lab import supplied_static_preparation as preparation
    if selected_input_renewal is not None:
        if ordinary_renewal is not None or prospective_amendment:
            raise ValueError("defended selected renewal has its own mode authority")
        from qcsd_lab import rapid_selected_input_renewal as renewed
        checked(selected_input_renewal)
        result = renewed.flight_inputs(Path(selected_input_renewal["path"]), Path(enrollment).absolute(),
            Path(study), runtime=runtime, mode=mode, tamaraw_configuration_policy=tamaraw_configuration_policy)
        batch, policy, bindings, manifests, roots, limits = result
        for row, manifest in zip(bindings, manifests):
            row["full_graph"] = graph(manifest)
        return batch, policy, bindings, manifests, roots, limits
    if ordinary_renewal is not None:
        if prospective_amendment:
            raise ValueError("ordinary renewal cannot authorize amended modes")
        from qcsd_lab import rapid_undefended_capture as ordinary
        checked(ordinary_renewal)
        result = ordinary.flight_inputs(Path(ordinary_renewal["path"]), Path(enrollment).absolute(), Path(study))
        batch, policy, bindings, manifests, roots, limits = result
        for row, manifest in zip(bindings, manifests):
            row["full_graph"] = graph(manifest)
        return batch, policy, bindings, manifests, roots, limits
    batch, all_classes, policy = rolling._verify_enrollment(Path(enrollment).absolute())
    from qcsd_lab import rapid_additive_static_enrollment as additive
    from qcsd_lab import rapid_per_class_selected_enrollment as per_class
    if policy["contract"] == per_class.CONTRACT:
        return additive_selected_inputs(enrollment, study, batch, all_classes, policy,
            prospective_amendment=prospective_amendment)
    if policy["contract"] == additive.CONTRACT:
        return additive_selected_inputs(enrollment, study, batch, all_classes, policy,
                                        prospective_amendment=prospective_amendment)
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


def additive_selected_inputs(enrollment, study, batch, all_classes, policy, *, prospective_amendment=False):
    """Select only this new batch's direct receipts without acquisition history."""
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import rapid_selected_capture_input as selected
    from qcsd_lab import rapid_per_class_selected_enrollment as per_class
    per_class_policy = policy["contract"] == per_class.CONTRACT
    if per_class_policy:
        from qcsd_lab import rapid_per_class_selected_input as selected
    count = len(batch["selected_candidate_ids"])
    if not 1 <= count <= 5 or rolling._open_ref(batch["policy"]).parent != Path(study).absolute():
        raise ValueError("selected flight belongs to another prospective study or class count")
    rows = all_classes[-count:]
    bindings, manifests, roots = [], [], set()
    if prospective_amendment:
        from qcsd_lab import selected_capture_amendment as selected_amendment
        if per_class_policy:
            from qcsd_lab import per_class_selected_capture_amendment as selected_amendment
        files, trees = selected_amendment.metadata_inputs(Path(enrollment).absolute(), batch, all_classes, policy)
        roots.update(trees | {path.parent for path in files})
        roots.add(Path(policy["runtime"]["execution_root"]))
    for row in rows:
        original = selected.reopen(row["prepared_workload"])
        manifest = json.loads(read(original))
        if prospective_amendment:
            selected_amendment._original(row)
        else:
            selected.validate_preparation(manifest["preparation"], manifest["resources"])
        if original.stem != row["workload_id"]:
            raise ValueError("selected flight changed its immutable class/workload mapping")
        bindings.append({"candidate_id": row["candidate_id"], "class_index": row["class_index"],
            "admission_root": row["admission_root"], "terminal": ref(rolling._open_ref(row["terminal"])),
            "original_workload": ref(original), "workload_id": row["workload_id"],
            "full_graph": graph(manifest), "selection_sha256": policy["admission_identity"]["profile_sha256"]})
        manifests.append(manifest)
        if not prospective_amendment:
            roots.update(static_roots(manifest))
    if [row["candidate_id"] for row in bindings] != batch["selected_candidate_ids"]:
        raise ValueError("selected flight reorders its append-only class membership")
    limits = per_class.select_classes(batch, all_classes, policy)[1] if per_class_policy else policy["capture_limits"]
    return batch, policy, bindings, manifests, [str(root) for root in sorted(roots)], {**limits, "max_attempts": 1}


def current_sidecar(sidecar, canonical, *, workload_id, workload_sha256,
                    delivery_compatibility=None, body_policy=None):
    """Exact current evidence, or explicit qualification-only producer/consumer reuse."""
    if delivery_compatibility is not None:
        from qcsd_lab.qualification_control_authority import validate_sidecar
        validate_sidecar(sidecar, canonical, workload_id=workload_id, workload_sha256=workload_sha256,
            reference=delivery_compatibility, body_policy=body_policy)
        return
    expected_source = {**canonical["source"], "image_digest": canonical["collection_image_digest"]}
    receipt = sidecar.get("implementation_receipt", {})
    if (sidecar.get("workload_id") != workload_id
        or sidecar.get("base_manifest", {}).get("sha256") != workload_sha256
        or sidecar.get("qualification_source") != expected_source
        or sidecar.get("qualification_image_digest") != canonical["collection_image_digest"]
        or receipt.get("sha256") != canonical["checks"]["collection"]["qualification_implementation_sha256"]
        or receipt.get("neqo_qcsd_client", {}).get("sha256") != canonical["installed_client_sha256"]):
        raise ValueError("response evidence changed current Source/image/client/implementation/workload")


def reuse_input(path, bindings, canonical, workload_root, *, delivery_compatibility=None, body_policy=None):
    from qcsd_lab.response_budget_qualification import load_named_qualification_set, NAMED_ARTIFACT_TYPE, SIDECAR_SCHEMA_VERSION
    path = Path(path).absolute()
    named = load_named_qualification_set(path, workload_root=Path(workload_root),
        expected_workload_ids=[row["workload_id"] for row in bindings],
        expected_qualification_scope="response-only", require_current_implementation=False)
    value = json.loads(read(path))
    from qcsd_lab.chaff_qualification import RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
    expected_version = SIDECAR_SCHEMA_VERSION if value["artifact_type"] == NAMED_ARTIFACT_TYPE else RESPONSE_ONLY_SIDECAR_V2_SCHEMA_VERSION
    if value["qualification_sidecar_schema_version"] != expected_version:
        raise ValueError("reuse requires actual response-only v2 epoch evidence")
    sidecars = {}
    for row in bindings:
        sidecar_path = path.parent / (row["workload_id"] + ".json")
        current_sidecar(json.loads(read(sidecar_path)), canonical,
            workload_id=row["workload_id"], workload_sha256=row["original_workload"]["sha256"],
            delivery_compatibility=delivery_compatibility, body_policy=body_policy)
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
    from qcsd_lab.application_response_policy import application_body_identity_policy
    body_policy = application_body_identity_policy(setup)
    from qcsd_lab import rapid_ael_fifteen_qualification as ael
    from qcsd_lab import rapid_capture_traffic as traffic
    if "buflo_duration_policy" in setup:
        selected = traffic.policy(setup["buflo_duration_policy"])
        if (selected is None or setup["mode"] != "buflo"
            or selected == traffic.budget.CADENCE64_POLICY and body_policy != "complete-current-application-delivery-v1"):
            raise ValueError("setup changed its explicit prospective BuFLO condition")
    from qcsd_lab import front_fixed_configuration as front
    selected_front = front.policy(setup)
    if selected_front is not None:
        if (setup["mode"] != "front" or setup["reuse"] is not None
            or body_policy != "complete-current-application-delivery-v1"
            or "qualification_delivery_compatibility" in setup or "buflo_duration_policy" in setup):
            raise ValueError("setup changed its explicit prospective FRONT condition")
        from qcsd_lab.rapid_rolling_capture import load_runtime
        front.validate_source_artifacts(load_runtime(output / "runtime-spec.json"))
    ael.validate_scope(setup, setup["mode"])
    from qcsd_lab.tamaraw_fixed_configuration import policy as fixed_tamaraw_policy
    fixed_tamaraw = fixed_tamaraw_policy(setup)
    if fixed_tamaraw is not None and (setup["mode"] != "tamaraw" or setup["reuse"] is not None
            or setup.get("qualification_delivery_compatibility") is not None
            or body_policy != "complete-current-application-delivery-v1"):
        raise ValueError("fixed Tamaraw setup changed its current single-setting condition")
    witness = setup.get("qualification_delivery_compatibility")
    if "qualification_delivery_compatibility" in setup and witness is None:
        raise ValueError("explicit setup qualification delivery witness cannot be null")
    if witness is not None:
        from qcsd_lab.qualification_control_authority import validate
        validate(witness, body_policy=body_policy, canonical=canonical)
        if read(output / "qualification-delivery-compatibility.json") != checked(witness):
            raise ValueError("staged qualification delivery witness changed")
    if "ordinary_renewal" in setup and (setup["mode"] != "undefended" or setup["reuse"] is not None
            or witness is not None):
        raise ValueError("ordinary renewal setup requires only its unqualified ordinary setting")
    if "selected_input_renewal" in setup and (setup["reuse"] is not None or witness is not None
            or "ordinary_renewal" in setup or body_policy != "complete-current-application-delivery-v1"):
        raise ValueError("defended selected renewal requires its own fresh current qualification")
    from qcsd_lab import rapid_rolling_capture as rolling
    runtime = rolling.load_runtime(Path(setup["runtime_spec"]["path"]))
    checked(setup["runtime_spec"])
    _, policy, bindings, manifests, roots, limits = selected_inputs(
        setup["enrollment"]["path"], setup["study_root"], prospective_amendment=setup["mode"] in AMENDED_MODES,
        ordinary_renewal=setup.get("ordinary_renewal"), selected_input_renewal=setup.get("selected_input_renewal"),
        runtime=runtime, mode=setup["mode"], tamaraw_configuration_policy=setup.get("tamaraw_configuration_policy"),
        enrolled_subgroup=setup.get("enrolled_subgroup"))
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
                               Path(setup["execution_root"]) / "config/workloads",
                               delivery_compatibility=witness, body_policy=body_policy)
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
    from qcsd_lab.application_response_policy import validate_application_body_identity_policy
    requested_body_policy = getattr(args, "application_body_identity_policy", None)
    body_policy = validate_application_body_identity_policy(requested_body_policy)
    from qcsd_lab import rapid_ael_fifteen_qualification as ael
    response_policy = ael.validate_scope({ael.FIELD: args.response_qualification_policy,
        "reuse": getattr(args, "reuse_qualification", None),
        "qualification_delivery_compatibility": getattr(args, "qualification_delivery_compatibility", None),
        **({"ordinary_renewal": True} if getattr(args, "ordinary_renewal", None) is not None else {})}, args.mode) if getattr(args, "response_qualification_policy", None) is not None else None
    from qcsd_lab.tamaraw_fixed_configuration import validate_policy as validate_fixed_tamaraw_policy
    fixed_tamaraw = validate_fixed_tamaraw_policy(getattr(args, "tamaraw_configuration_policy", None))
    from qcsd_lab.front_fixed_configuration import validate_policy as validate_fixed_front_policy
    fixed_front = validate_fixed_front_policy(getattr(args, "front_configuration_policy", None))
    if fixed_front is not None and (args.mode != "front" or fixed_tamaraw is not None
            or body_policy != "complete-current-application-delivery-v1"
            or getattr(args, "qualification_delivery_compatibility", None) is not None
            or getattr(args, "reuse_qualification", None) is not None):
        raise ValueError("fixed FRONT V5 flight requires its own current whole-group qualification")
    if fixed_tamaraw is not None and (args.mode != "tamaraw"
            or body_policy != "complete-current-application-delivery-v1"
            or getattr(args, "qualification_delivery_compatibility", None) is not None
            or getattr(args, "reuse_qualification", None) is not None):
        raise ValueError("fixed Tamaraw flight requires its own fresh current response qualification")
    witness_path = getattr(args, "qualification_delivery_compatibility", None)
    witness = None if witness_path is None else ref(witness_path)
    if witness is not None:
        from qcsd_lab.qualification_control_authority import validate
        validate(witness, body_policy=body_policy, canonical=canonical)
    from qcsd_lab import rapid_rolling_capture as rolling
    from qcsd_lab import capture_acceptance_policy as capture
    from qcsd_lab.buflo_duration_budget import POLICY, CADENCE64_POLICY
    from qcsd_lab.rapid_capture_traffic import policy as duration_policy
    requested_duration = getattr(args, "buflo_duration_policy", None)
    selected_duration = duration_policy(requested_duration)
    if selected_duration is not None and args.mode != "buflo":
        raise ValueError("explicit BuFLO duration choice requires only the BuFLO setting")
    if selected_duration == CADENCE64_POLICY and body_policy != "complete-current-application-delivery-v1":
        raise ValueError("prospective 64 ms BuFLO requires complete current application delivery")
    enrollment = args.enrollment.absolute()
    renewal_path = getattr(args, "ordinary_renewal", None)
    renewal = None if renewal_path is None else ref(renewal_path)
    renew_selected = getattr(args, "renew_selected_inputs", False)
    if renew_selected:
        from qcsd_lab.rapid_selected_input_renewal import _condition
        _condition(args.mode, fixed_tamaraw)
        if (renewal is not None or witness is not None or getattr(args, "reuse_qualification", None) is not None
                or body_policy != "complete-current-application-delivery-v1"):
            raise ValueError("defended selected renewal needs fresh qualification and complete current delivery")
    if renewal is not None and (args.mode != "undefended" or witness is not None
            or getattr(args, "reuse_qualification", None) is not None):
        raise ValueError("ordinary renewal requires only its unqualified undefended setting")
    _, policy, bindings, manifests, roots, limits = selected_inputs(enrollment, args.study_root,
        prospective_amendment=args.mode in AMENDED_MODES or renew_selected, ordinary_renewal=renewal,
        class_indices=getattr(args, "class_indices", None))
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
    if witness is not None:
        create(output / "qualification-delivery-compatibility.json", checked(witness))
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
        create(output / ("lineage/admission-originals" if renew_selected else "lineage/originals") / target.name, original)
        if amendment is None and not renew_selected:
            create(target, original)
    if not renew_selected:
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
    defended_renewal = None
    if renew_selected:
        from qcsd_lab import rapid_selected_input_renewal as renewed
        renewed_path = output / "current-selected-inputs.json"
        renewed.publish(enrollment, runtime, renewed_path, mode=args.mode,
                        tamaraw_configuration_policy=fixed_tamaraw)
        defended_renewal = ref(renewed_path)
        _, policy, bindings, manifests, roots, limits = selected_inputs(enrollment, study,
            selected_input_renewal=defended_renewal, runtime=runtime, mode=args.mode,
            tamaraw_configuration_policy=fixed_tamaraw, class_indices=getattr(args, "class_indices", None))
        for row in bindings:
            create(output / "lineage/originals" / (row["workload_id"] + ".json"), checked(row["original_workload"]))
        create(output / "lineage/original-manifest.json", checked(bindings[0]["original_workload"]))
    prefix = [str(args.python.absolute()), "-I", "-B", "-c", PUBLIC_CLI_BOOTSTRAP,
              str(clean / "src"), str(clean / "tools/rapid_rolling_capture.py")]
    command = None
    if amendment is not None:
        command = prefix + ["static-amendment", "--enrollment", str(enrollment),
                            "--runtime-spec", str(runtime_path), "--output", str(amendment)]
        if args.mode == "front":
            command += ["--front-policy", fixed_front or capture.FRONT_RESERVE_POLICY]
        else:
            duration = selected_duration or POLICY
            preparation = (capture.CADENCE64_KERNEL_PREPARATION_POLICY if duration == CADENCE64_POLICY
                           else capture.BUFLO_KERNEL_PREPARATION_POLICY)
            command += ["--buflo-policy", preparation, "--buflo-duration-policy", duration]
    create(output / "amendment-commands.json", encode({"amend": command}))
    reuse = None
    if reuse_manifest is not None:
        reuse = reuse_input(reuse_manifest, bindings, canonical, execution / "config/workloads",
                            delivery_compatibility=witness, body_policy=body_policy)
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
    if getattr(args, "class_indices", None) is not None:
        from qcsd_lab import rapid_enrolled_subgroup as subgroup
        batch, classes, _ = rolling._verify_enrollment(enrollment)
        setup[subgroup.FIELD] = subgroup.declare(enrollment, batch, classes, args.class_indices)
    if requested_duration is not None:
        setup["buflo_duration_policy"] = selected_duration
    if requested_body_policy is not None:
        setup["application_body_identity_policy"] = body_policy
    if response_policy is not None:
        setup[ael.FIELD] = response_policy
    if fixed_front is not None:
        setup["front_configuration_policy"] = fixed_front
    if fixed_tamaraw is not None:
        setup["tamaraw_configuration_policy"] = fixed_tamaraw
    if witness is not None:
        setup["qualification_delivery_compatibility"] = witness
    if renewal is not None:
        setup["ordinary_renewal"] = renewal
    if defended_renewal is not None:
        setup["selected_input_renewal"] = defended_renewal
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
        if authority["modes"] != [mode] or ("enrolled_subgroup" not in setup and len(authority["workloads"]) != len(bindings)):
            raise ValueError("public amendment must authorize this exact group and setting")
        by_candidate = {row["candidate_id"]: row for row in authority["workloads"]}
        if (not {row["candidate_id"] for row in bindings} <= set(by_candidate)
            or "enrolled_subgroup" not in setup and set(by_candidate) != {row["candidate_id"] for row in bindings}):
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
    from qcsd_lab import rapid_ael_fifteen_qualification as ael
    response_policy = ael.validate_scope(setup, mode)
    if response_policy is not None:
        for row, current_manifest in zip(current, manifests):
            ael.selection(current_manifest, row["workload_id"])
    selected_policy = None if authority is None else authority.get(traffic.FIELD)
    limits = budget.capture_limits(mode, setup["original_limits"], policy=selected_policy)
    if (mode == "buflo" and selected_policy != setup.get(traffic.FIELD, budget.POLICY)
        or mode != "buflo" and selected_policy is not None):
        raise ValueError("setting changed its prospective traffic policy")
    canary, manifest = current[0], manifests[0]
    copied = Path(canary["capture_manifest"]["path"])
    qualification_set, group_set = setup["name"] + "-canary", setup["name"] + "-group"
    name = "rapid-curated-tranco50-v2-diagnostic-v12-" + setup["name"] + "-" + mode
    defense = {"name": mode, "kind": "none" if mode == "undefended" else mode}
    if mode == "buflo":
        defense["parameters"] = "../defense-params/" + Path(traffic.parameter_files(selected_policy)[0][0]).name
    elif mode in PARAMETER_REFERENCES:
        defense["parameters"] = PARAMETER_REFERENCES[mode]
    campaign = {"schema": 1, "name": name, "purpose": "smoke", "seed": setup["campaign_seed"],
        "profile": "research-1200", "workloads": {canary["workload_id"]: 1},
        "request_policies": ["as-defined"], "defenses": [defense], "limits": limits}
    if mode != "undefended":
        campaign["chaff_qualification_set"] = qualification_set
    from qcsd_lab.application_response_policy import application_body_identity_policy
    body_policy = application_body_identity_policy(setup)
    if "application_body_identity_policy" in setup:
        campaign["application_body_identity_policy"] = body_policy
    from qcsd_lab.tamaraw_fixed_configuration import policy as fixed_tamaraw_policy
    fixed_tamaraw = fixed_tamaraw_policy(setup)
    if fixed_tamaraw is not None:
        if mode != "tamaraw" or setup["reuse"] is not None or "qualification_delivery_compatibility" in setup:
            raise ValueError("fixed Tamaraw setup changed its prospective current condition")
        campaign["tamaraw_configuration_policy"] = fixed_tamaraw
    from qcsd_lab.front_fixed_configuration import policy as fixed_front_policy
    fixed_front = fixed_front_policy(setup)
    if fixed_front is not None:
        if (mode != "front" or setup["reuse"] is not None or "qualification_delivery_compatibility" in setup
            or authority is None or authority["policies"].get("front_capture_policy") != fixed_front):
            raise ValueError("fixed FRONT setup changed its prospective amendment/condition")
        campaign["front_configuration_policy"] = fixed_front
    if "qualification_delivery_compatibility" in setup:
        campaign["qualification_delivery_compatibility"] = setup["qualification_delivery_compatibility"]
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
        "traffic_hashes": {key: expected for key, (_, expected)
            in traffic.files(selected_policy, front_selected=fixed_front).items()},
        "static_preparation_roots": static_roots(manifest), "group_preparation_roots": group_roots(manifests),
        "capture_limits": limits, "campaigns": campaigns, "reuse": setup["reuse"],
        "study_root": setup["study_root"], "enrollment": setup["enrollment"]}
    if "enrolled_subgroup" in setup:
        plan["enrolled_subgroup"] = setup["enrolled_subgroup"]
    if "application_body_identity_policy" in setup:
        plan["application_body_identity_policy"] = body_policy
    if response_policy is not None:
        plan[ael.FIELD] = response_policy
    if fixed_front is not None:
        plan["front_configuration_policy"] = fixed_front
    if fixed_tamaraw is not None:
        plan["tamaraw_configuration_policy"] = fixed_tamaraw
    if "qualification_delivery_compatibility" in setup:
        plan["qualification_delivery_compatibility"] = setup["qualification_delivery_compatibility"]
    if authority is not None:
        plan["static_capture_amendment"] = ref(Path(setup["amendment_path"]))
    if selected_policy is not None:
        plan[traffic.FIELD] = selected_policy
    if "ordinary_renewal" in setup:
        plan["ordinary_renewal"] = setup["ordinary_renewal"]
    if "selected_input_renewal" in setup:
        plan["selected_input_renewal"] = setup["selected_input_renewal"]
    create(output / "plan.json", encode(plan))
    prefix = [setup["host_python"], "-I", "-B", "-c", PUBLIC_CLI_BOOTSTRAP,
              str(clean / "src"), str(clean / "tools/rapid_rolling_capture.py")]
    commands = {"preamble": image_argv(plan, output, "preamble-image"),
                "preflight": image_argv(plan, output, "preflight-image", "--mode", mode)}
    if "ordinary_renewal" not in setup:
        commands["qualify"] = image_argv(plan, output, "qualify-image")
    commands["plan"] = prefix + ["plan", "--evidence-root", setup["study_root"],
        "--enrollment", setup["enrollment"]["path"], "--qualification-spec", str(qspec),
        "--readiness", str(output / "readiness.json"), "--runtime-spec", str(output / "runtime-spec.json"),
        "--output", str(output / "plans/g01.json"), "--spec-output", str(output / "plans/g01-spec.json")]
    if "enrolled_subgroup" in setup:
        commands["plan"] += ["--class-indices", *map(str, setup["enrolled_subgroup"]["class_indices"])]
    if authority is not None:
        commands["plan"] += ["--static-capture-amendment", setup["amendment_path"]]
    if "application_body_identity_policy" in setup:
        commands["plan"] += ["--application-body-identity-policy", body_policy]
    if fixed_front is not None:
        commands["plan"] += ["--front-configuration-policy", fixed_front]
    if fixed_tamaraw is not None:
        commands["plan"] += ["--tamaraw-configuration-policy", fixed_tamaraw]
    if "selected_input_renewal" in setup:
        commands["plan"] += ["--selected-input-renewal", setup["selected_input_renewal"]["path"]]
    if "qualification_delivery_compatibility" in setup:
        commands["plan"] += ["--qualification-delivery-compatibility", setup["qualification_delivery_compatibility"]["path"]]
    if "ordinary_renewal" in setup:
        ordinary_prefix = [setup["host_python"], "-I", "-B", "-c", PUBLIC_CLI_BOOTSTRAP,
            str(clean / "src"), str(clean / "tools/rapid_undefended_capture.py")]
        ordinary_input = output / "ordinary-input.json"
        commands["inputs"] = ordinary_prefix + ["inputs", "--enrollment", setup["enrollment"]["path"],
            "--runtime-spec", str(output / "runtime-spec.json"), "--ordinary-renewal", setup["ordinary_renewal"]["path"],
            "--output", str(ordinary_input)]
        commands["plan"] = ordinary_prefix + ["plan", "--enrollment", setup["enrollment"]["path"],
            "--runtime-spec", str(output / "runtime-spec.json"), "--ordinary-input", str(ordinary_input),
            "--ordinary-readiness", str(output / "readiness.json"), "--output", str(output / "plans/g01.json"),
            "--spec-output", str(output / "plans/g01-spec.json")]
        if "application_body_identity_policy" in setup:
            commands["plan"] += ["--application-body-identity-policy", body_policy]
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
    if action == "qualify-image" and plan["reuse"] is not None:
        reuse_manifest = plan["reuse"]["manifest"]
        checked(reuse_manifest)
        reuse_path = str(Path(reuse_manifest["path"]).absolute())
        if any(char in reuse_path for char in ("\n", "\r", "\0", ":")):
            raise ValueError("reuse manifest requires a canonical same-absolute RO file mount")
        argv += ["--volume", f"{reuse_path}:{reuse_path}:ro"]
    roots = plan["static_preparation_roots"] if action == "verify-image" else plan["group_preparation_roots"]
    if "selected_input_renewal" in plan:
        from qcsd_lab import rapid_selected_input_renewal as renewed
        runtime = json.loads(read(output / "runtime-spec.json"))["inputs"]
        renewed_roots = renewed.flight_inputs(Path(plan[renewed.FIELD]["path"]), Path(plan["enrollment"]["path"]),
            Path(plan["study_root"]), runtime=runtime, mode=plan["campaigns"][0]["mode"],
            tamaraw_configuration_policy=plan.get("tamaraw_configuration_policy"))[4]
        roots = sorted(set(roots) | set(renewed_roots))
    if "ordinary_renewal" in plan:
        if plan["campaigns"][0]["mode"] != "undefended" or plan["reuse"] is not None or action == "qualify-image":
            raise ValueError("ordinary renewal has no padding qualification operation")
        checked(plan["ordinary_renewal"])
        renewal_path = str(Path(plan["ordinary_renewal"]["path"]).absolute())
        if any(char in renewal_path for char in ("\n", "\r", "\0", ":")):
            raise ValueError("ordinary renewal requires a canonical read-only file mount")
        argv += ["--volume", f"{renewal_path}:{renewal_path}:ro"]
        if action == "verify-image":
            roots = plan["group_preparation_roots"]
            original_recipe = Path(plan["clean_runtime_root"]) / "tools/_rapid_class_mode_flight/flight/operator.py"
            if digest(read(original_recipe)) != plan["recipe_sha256"]:
                raise ValueError("ordinary verifier must retain its exact original recipe bytes")
            index = argv.index(f"{Path(__file__).absolute()}:/recipe.py:ro")
            argv[index] = f"{original_recipe}:/recipe.py:ro"
    if "enrolled_subgroup" in plan:
        from qcsd_lab import rapid_enrolled_subgroup as subgroup
        roots = sorted(set(roots) | {str(path) for path in subgroup.input_roots(
            plan["enrollment"], plan[subgroup.FIELD])})
    if "qualification_delivery_compatibility" in plan:
        from qcsd_lab.application_response_policy import application_body_identity_policy
        from qcsd_lab.qualification_control_authority import roots as witness_roots
        roots = sorted(set(roots) | {str(path) for path in witness_roots(plan["qualification_delivery_compatibility"],
                       body_policy=application_body_identity_policy(plan))})
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
    from qcsd_lab.application_response_policy import application_body_identity_policy
    body_policy = application_body_identity_policy(plan)
    from qcsd_lab.tamaraw_fixed_configuration import policy as fixed_tamaraw_policy
    fixed_tamaraw = fixed_tamaraw_policy(plan)
    if fixed_tamaraw is not None:
        import yaml
        configured = yaml.safe_load(read(execution / campaign["campaign_relative"]))
        if (mode != "tamaraw" or plan["reuse"] is not None or "qualification_delivery_compatibility" in plan
            or fixed_tamaraw_policy(configured) != fixed_tamaraw
            or body_policy != "complete-current-application-delivery-v1"):
            raise ValueError("canary plan changed its fixed Tamaraw condition")
    from qcsd_lab import front_fixed_configuration as front
    fixed_front = front.policy(plan)
    if fixed_front is not None:
        import yaml
        configured = yaml.safe_load(read(execution / campaign["campaign_relative"]))
        if (mode != "front" or plan["reuse"] is not None
            or "qualification_delivery_compatibility" in plan
            or front.policy(configured) != fixed_front
            or body_policy != "complete-current-application-delivery-v1"
            or traffic.canary_policy(plan, mode) is not None):
            raise ValueError("canary plan changed its fixed FRONT V5 configuration authority")
        front.validate_prepared(manifest)
        for root in (clean, execution):
            for relative, expected in ((front.CONFIGURATION_PATH, front.CONFIGURATION_SHA256),
                                       (front.PROVENANCE_PATH, front.PROVENANCE_SHA256)):
                artifact = root / relative
                if artifact.stat().st_mode & 0o7777 != 0o644 or digest(read(artifact)) != expected:
                    raise ValueError("canary FRONT configuration/provenance bytes or full mode changed")
    witness = plan.get("qualification_delivery_compatibility")
    if "qualification_delivery_compatibility" in plan and witness is None:
        raise ValueError("explicit canary qualification delivery witness cannot be null")
    if witness is not None:
        from qcsd_lab.qualification_control_authority import validate
        validate(witness, body_policy=body_policy, canonical=canonical)
        if read(output / "qualification-delivery-compatibility.json") != checked(witness):
            raise ValueError("canary qualification delivery witness changed")
    if "application_body_identity_policy" in plan:
        import yaml
        campaign_raw = read(execution / campaign["campaign_relative"])
        if (digest(campaign_raw) != campaign["campaign_sha256"]
            or application_body_identity_policy(yaml.safe_load(campaign_raw)) != body_policy
            or yaml.safe_load(campaign_raw).get("qualification_delivery_compatibility") != witness):
            raise ValueError("canary campaign changed its prospectively declared application body policy")
    if mode not in MODES:
        raise ValueError("unknown flight setting")
    from qcsd_lab import rapid_ael_fifteen_qualification as ael
    response_policy = ael.validate_scope(plan, mode)
    if "ordinary_renewal" in plan:
        if mode != "undefended" or plan["reuse"] is not None or witness is not None:
            raise ValueError("ordinary renewal cannot authorize another setting or reused padding")
        checked(plan["ordinary_renewal"])
        if not image:
            from qcsd_lab.rapid_undefended_capture import validate_renewal
            validate_renewal(Path(plan["ordinary_renewal"]["path"]), Path(plan["enrollment"]["path"]))
    amended = "static_capture_amendment" in plan
    if amended != (mode in AMENDED_MODES) or not 1 <= len(plan["selected_classes"]) <= 5:
        raise ValueError("wrong setting amendment or class count")
    selected_policy = traffic.canary_policy(plan, mode)
    runtime = json.loads(read(output / "runtime-spec.json"))["inputs"]
    if "selected_input_renewal" in plan:
        from qcsd_lab import rapid_selected_input_renewal as renewed
        if (amended or "ordinary_renewal" in plan or plan["reuse"] is not None or witness is not None
                or body_policy != "complete-current-application-delivery-v1"):
            raise ValueError("defended renewed canary cannot import another setting or reused qualification")
        renewed.validate(renewed.rolling._open_ref(plan[renewed.FIELD]),
            enrollment=Path(plan["enrollment"]["path"]), runtime=runtime, mode=mode,
            tamaraw_configuration_policy=plan.get("tamaraw_configuration_policy"))
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
        _, checked_policy, expected, originals, _, _ = selected_inputs(plan["enrollment"]["path"], plan["study_root"],
            prospective_amendment=amended, ordinary_renewal=plan.get("ordinary_renewal"),
            selected_input_renewal=plan.get("selected_input_renewal"), runtime=runtime, mode=mode,
            tamaraw_configuration_policy=plan.get("tamaraw_configuration_policy"),
            enrolled_subgroup=plan.get("enrolled_subgroup"))
        recorded = [{key: value for key, value in row.items() if key != "capture_manifest"} for row in plan["selected_classes"]]
        if expected != recorded:
            raise ValueError("selected original classes changed")
    if "enrolled_subgroup" in plan:
        from qcsd_lab import rapid_enrolled_subgroup as subgroup
        from qcsd_lab import rapid_rolling_capture as rolling
        batch, classes, _ = rolling._verify_enrollment(Path(plan["enrollment"]["path"]))
        rows = subgroup.validate(plan[subgroup.FIELD], Path(plan["enrollment"]["path"]), batch, classes)
        if [(row["class_index"], row["candidate_id"], row["workload_id"]) for row in rows] != [
                (row["class_index"], row["candidate_id"], row["workload_id"]) for row in plan["selected_classes"]]:
            raise ValueError("subgroup image plan changed its exact class identities")
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
    if response_policy is not None:
        for row, current_manifest in zip(plan["selected_classes"], local_manifests):
            ael.selection(current_manifest, row["workload_id"])
    from qcsd_lab import selected_capture_amendment as selected_amendment
    if (authority is None and any(local["preparation"]["data_role"] != preparation.ROLE for local in local_manifests)
        or authority is not None and authority["contract"] == selected_amendment.CONTRACT):
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
                            workload_sha256=row["capture_manifest"]["sha256"],
                            delivery_compatibility=witness, body_policy=body_policy)
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
    if "ordinary_renewal" in plan and args.command == "qualify-image":
        raise ValueError("ordinary renewal has no padding qualification operation")
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
            from qcsd_lab import rapid_capture_traffic as traffic
            from qcsd_lab.parameters import validate_parameter_artifact
            parameter_path = traffic.parameter_files(traffic.canary_policy(plan, mode))[0][0]
            validate_parameter_artifact(execution / parameter_path, expected_kind="buflo",
                allow_study_candidate=True, expected_qcsd_profile="research-1200",
                expected_udp_payload_ceiling=1200)
        create(output / "preamble-complete.json", encode({"completed_at": now(),
            "plan_sha256": args.plan_sha256, "mode": mode, "installed_source_and_client_checked": True,
            "manifest_schema_checked": True, "qualification_performed": False,
            "capture_performed": False, **ZERO}))
        return
    if args.command == "qualify-image":
        from qcsd_lab.chaff_qualification import RESPONSE_ONLY_QUALIFICATION_SCOPE
        from qcsd_lab.response_budget_qualification import qualify_response_chaff_v2, SIDECAR_SCHEMA_VERSION
        from qcsd_lab.qualification_control_authority import publish_named_qualification_set
        from qcsd_lab.application_response_policy import application_body_identity_policy
        delivery = {"delivery_compatibility": plan.get("qualification_delivery_compatibility"),
                    "body_policy": application_body_identity_policy(plan)}

        workload_ids = [row["workload_id"] for row in plan["selected_classes"]]
        from qcsd_lab import rapid_ael_fifteen_qualification as ael
        response_policy = ael.validate_scope(plan, plan["campaigns"][0]["mode"]) if ael.FIELD in plan else None
        if plan["reuse"] is None:
            sidecars = execution / "config/static-response-sidecars" / plan["group_qualification_set"]
            sidecars.mkdir(parents=True, exist_ok=False)
            for workload_id in workload_ids:
                if response_policy is not None:
                    ael.qualify(workload_id, qualification_root=sidecars,
                        workload_root=execution / "config/workloads",
                        timeout_seconds=plan["capture_limits"]["timeout_seconds"])
                else:
                    qualify_response_chaff_v2(workload_id, qualification_root=sidecars,
                        workload_root=execution / "config/workloads",
                        timeout_seconds=plan["capture_limits"]["timeout_seconds"],
                        max_response_bytes=plan["capture_limits"]["max_response_bytes"])
        else:
            sidecars = execution / "config/flight-reuse"
        schema_version = (SIDECAR_SCHEMA_VERSION if plan["reuse"] is None else
            json.loads(read(Path(plan["reuse"]["manifest"]["path"]))) ["qualification_sidecar_schema_version"])
        if response_policy is not None:
            schema_version = ael.original.RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION
        store = execution / "config/chaff-response-qualification-store/sets"
        store.mkdir(parents=True, exist_ok=True)
        group = publish_named_qualification_set(workload_ids,
            **delivery,
            qualification_set=plan["group_qualification_set"],
            qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
            workload_root=execution / "config/workloads", sidecar_root=sidecars, publication_root=store,
            qualification_sidecar_schema_version=schema_version)
        named = publish_named_qualification_set([plan["workload_id"]],
            **delivery,
            qualification_set=plan["qualification_set"],
            qualification_scope=RESPONSE_ONLY_QUALIFICATION_SCOPE,
            workload_root=execution / "config/workloads", sidecar_root=sidecars, publication_root=store,
            qualification_sidecar_schema_version=schema_version)
        if response_policy is not None:
            ael.publish_prerequisite(group, workload_root=execution / "config/workloads")
            ael.publish_prerequisite(named, workload_root=execution / "config/workloads")
        create(output / "qualification-complete.json", encode({"completed_at": now(),
            "plan_sha256": args.plan_sha256, "workload_id": plan["workload_id"],
            "workload_sha256": plan["workload_sha256"],
            "sidecar_sha256": digest(read(sidecars / (plan["workload_id"] + ".json"))),
            "named_manifest_sha256": named.manifest_sha256, "qualification_set": named.qualification_set,
            "group_manifest_sha256": group.manifest_sha256, "group_qualification_set": group.qualification_set,
            "workload_ids": workload_ids, "reused_same_current_evidence": plan["reuse"] is not None,
            **({"response_qualification_prerequisite": ael.record()} if response_policy is not None else {}), **ZERO}))
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
    from qcsd_lab.application_response_policy import application_body_identity_policy
    body_policy = application_body_identity_policy(plan)
    if application_body_identity_policy(config) != body_policy:
        raise ValueError("actual canary configuration differs from its declared application body policy")
    if config.get("qualification_delivery_compatibility") != plan.get("qualification_delivery_compatibility"):
        raise ValueError("actual canary changed its declared qualification delivery witness")
    response = validate_application_responses(manifest, run, body_identity_policy=body_policy)
    from qcsd_lab.tamaraw_fixed_configuration import policy as fixed_tamaraw_policy, configuration_sha256
    fixed_tamaraw = fixed_tamaraw_policy(plan)
    if fixed_tamaraw_policy(config) != fixed_tamaraw:
        raise ValueError("actual canary changed its fixed Tamaraw condition")
    from qcsd_lab.front_fixed_configuration import policy as fixed_front_policy, validate_run as validate_fixed_front_run, configuration_sha256 as front_configuration_sha256
    fixed_front = fixed_front_policy(plan)
    if fixed_front_policy(config) != fixed_front:
        raise ValueError("actual canary changed its fixed FRONT condition")
    validate_fixed_front_run(run, selected_policy=fixed_front)
    validate_terminal_primary_source_binding(manifest, run, runner_directory=result_root / sample["path"] / "neqo",
        tamaraw_configuration_policy=fixed_tamaraw)
    if sorted(str(row["origin"]).rstrip("/") for row in run["endpoints"]) != plan["full_graph"]["origins"]:
        raise ValueError("Native omitted a supplied origin")
    identity = application_response_identity_signature(manifest, response["response_signature"], body_identity_policy=body_policy)
    dns_sha = verify_dns_receipt(read(output / "dns-receipts" / (mode + ".json")), campaign["name"],
        {plan["workload_id"]: read(result_root / workload["manifest"])})
    deep_receipt = {**verified.as_dict(), **ZERO,
        "completed_at": now(), "mode": mode, "source": plan["canonical_runtime"]["source"],
        "plan_sha256": args.plan_sha256, "canonical_runtime_sha256": plan["canonical_runtime_sha256"],
        "selection_sha256": plan["selection_sha256"], "workload_sha256": plan["workload_sha256"],
        "experiment_sha256": digest(read(result_root / "experiment.json")),
        "evidence_index_sha256": digest(read(result_root / "evidence.sha256")), "dns_receipt_sha256": dns_sha,
        "response_identity_sha256": digest(encode(identity)), "full_graph": plan["full_graph"]}
    if "application_body_identity_policy" in plan:
        deep_receipt["application_body_identity_policy"] = body_policy
        deep_receipt["content_equality_across_visits_claimed"] = False
    if fixed_front is not None:
        deep_receipt.update(front_configuration_policy=fixed_front,
                            front_configuration_sha256=front_configuration_sha256())
    if fixed_tamaraw is not None:
        deep_receipt.update(tamaraw_configuration_policy=fixed_tamaraw,
                            tamaraw_configuration_sha256=configuration_sha256())
    if "qualification_delivery_compatibility" in plan:
        deep_receipt["qualification_delivery_compatibility"] = plan["qualification_delivery_compatibility"]
    create(output / (mode + "-deep-verification.json"), encode(deep_receipt))


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
        if "ordinary_renewal" in plan:
            from qcsd_lab.rapid_ordinary_group_canary import reference as group_reference
            reference = group_reference(reference)
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
    ordinary = "ordinary_renewal" in plan
    if ordinary and args.step == "qualify":
        raise ValueError("ordinary renewal has no padding qualification operation")
    if args.step == "inputs" and not ordinary:
        raise ValueError("ordinary input action requires the explicit ordinary renewal contract")
    if args.step == "qualify":
        require_operation(output, "preamble", commands["preamble"])
        if json.loads(read(output / "preamble-complete.json"))["plan_sha256"] != args.plan_sha256:
            raise ValueError("actual installed preamble belongs to another plan")
    if args.step == "preflight":
        if ordinary:
            require_operation(output, "preamble", commands["preamble"])
            if json.loads(read(output / "preamble-complete.json"))["plan_sha256"] != args.plan_sha256:
                raise ValueError("actual installed preamble belongs to another plan")
        else:
            require_operation(output, "qualify", commands["qualify"])
    if args.step == "plan":
        checked(ref(output / "readiness.json"))
        if ordinary:
            require_operation(output, "inputs", commands["inputs"])
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
    item.add_argument("--front-configuration-policy", choices=(CLI_FRONT_POLICY,),
                      help="explicit prospective lighter FRONT V5; default retains V4")
    item.add_argument("--buflo-duration-policy", choices=CLI_BUFLO_POLICIES,
                      help="explicit prospective BuFLO cadence/event budget; default retains the fixed20ms/200s flight")
    item.add_argument("--class-indices", type=int, nargs="+",
                      help="ordered current-batch subgroup with fresh qualification and canary")
    item.add_argument("--ordinary-renewal", type=Path)
    item.add_argument("--renew-selected-inputs", action="store_true",
                      help="revalidate the same retained full selected GET for fresh TAM8192 or CS-BuFLO qualification")
    item.add_argument("--reuse-qualification", type=Path,
                      help="exact current original-group named response-only v2 manifest")
    item.add_argument("--application-body-identity-policy", choices=("exact-prepared-application-body-v1", "complete-current-application-delivery-v1"),
                      help="prospectively verify complete current delivery without claiming frozen body equality")
    item.add_argument("--qualification-delivery-compatibility", type=Path,
                      help="authenticated original response-producer/current complete-delivery consumer witness")
    item.add_argument("--tamaraw-configuration-policy", choices=("rapid-tamaraw-initial8192-owned-bootstrap-v1",),
                      help="prospective fixed 8192-byte initial credit on all controlled TAM request streams")
    item.add_argument("--response-qualification-policy", choices=("ael-equals-identity-three-by-five-stable-wire-response-v1",),
                      help="fresh fifteen-completion schema3 AEL prerequisite with exact identity header projection")
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
            item.add_argument("--step", choices=("preamble", "qualify", "preflight", "capture", "deep", "inputs", "plan"),
                              required=True)
        else:
            item.add_argument("--mode", choices=MODES, required=name == "verify-image")
            if name == "verify-image":
                item.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    dispatch = {"stage": stage, "amend": amend, "finalize": finalize, "readiness": readiness, "run": run}
    if args.command in dispatch:
        _bind_host_sdk(args)
    from qcsd_lab.rapid_operation_facts import OperationFacts, current_context
    context = current_context()
    owned = context is None
    if owned:
        context = OperationFacts()
    with context.scope():
        result = dispatch.get(args.command, image_action)(args)
        if owned:
            context.check()
    if result is not None:
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
