"""Explicit, short-lived facts for one public capture control operation.

A context deduplicates validation within its owning operation. It is never a
receipt, persistent cache, lifecycle authority or replacement for an actual
installed check. Callers recheck every registered raw dependency and complete
immutable tree before effects and after waiting for ownership locks.
"""
from __future__ import annotations

import copy
import contextvars
import hashlib
import json
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any


_ACTIVE_OPERATION = contextvars.ContextVar("qcsd_capture_operation_facts", default=None)


def current_context():
    """Compatibility hooks see facts only within the owning installed action."""
    return _ACTIVE_OPERATION.get()


def _raw(path: Path) -> bytes:
    path = Path(path).absolute()
    if (not path.is_file() or any(item.is_symlink() for item in (path, *path.parents))):
        raise ValueError(f"operation dependency is not a regular unlinked file: {path}")
    return path.read_bytes()


def _file(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _raw(path)
    return raw, {"sha256": hashlib.sha256(raw).hexdigest(), "mode": stat.S_IMODE(path.stat().st_mode)}


def _tree(path: Path, *, ignore_git=False) -> dict[str, dict[str, Any]]:
    path = Path(path).absolute()
    if not path.is_dir() or any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError(f"operation dependency is not a regular unlinked directory: {path}")
    result = {".": {"kind": "directory", "mode": stat.S_IMODE(path.stat().st_mode)}}
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path)
        if ignore_git and ".git" in relative.parts:
            continue
        if item.is_symlink():
            raise ValueError("operation dependency tree contains a link")
        if item.is_dir():
            result[relative.as_posix()] = {"kind": "directory", "mode": stat.S_IMODE(item.stat().st_mode)}
        elif item.is_file():
            result[relative.as_posix()] = {"kind": "file",
                "sha256": hashlib.sha256(item.read_bytes()).hexdigest(), "mode": stat.S_IMODE(item.stat().st_mode)}
        else:
            raise ValueError("operation dependency tree contains a special file")
    return result


class OperationFacts:
    """Private facts and raw dependency observations owned by one action."""

    def __init__(self):
        self._facts: dict[Any, Any] = {}
        self._files: dict[Path, dict[str, Any]] = {}
        self._trees: dict[tuple[Path, bool], dict[str, dict[str, Any]]] = {}
        self._bindings: set[tuple[str, str]] = set()
        self._absent: set[Path] = set()

    def begin_action(self) -> None:
        """A public action never inherits another action's semantic memo."""
        self._facts.clear()
        self._bindings.clear()

    @contextmanager
    def scope(self):
        """Bridge a legacy hook signature without retaining facts on exit."""
        token = _ACTIVE_OPERATION.set(self)
        try:
            yield self
        finally:
            _ACTIVE_OPERATION.reset(token)

    def has(self, key) -> bool:
        return key in self._facts

    def get(self, key):
        return copy.deepcopy(self._facts[key])

    def remember(self, key, value):
        if key in self._facts:
            raise ValueError("operation attempted to replace validated facts")
        self._facts[key] = copy.deepcopy(value)
        return value

    def watch_file(self, path: Path) -> bytes:
        path = Path(path).absolute()
        raw, observation = _file(path)
        if path in self._files and self._files[path] != observation:
            raise ValueError("operation dependency changed during validation")
        self._files[path] = observation
        return raw

    def watch_tree(self, path: Path, *, ignore_git=False) -> dict[str, dict[str, Any]]:
        path = Path(path).absolute()
        key = (path, ignore_git)
        if key not in self._trees:
            self._trees[key] = _tree(path, ignore_git=ignore_git)
        return copy.deepcopy(self._trees[key])

    def check(self) -> None:
        """Reopen bytes, permission modes and complete membership, never stat alone."""
        for path, observation in self._files.items():
            if _file(path)[1] != observation:
                raise ValueError("operation dependency bytes or mode changed")
        for (path, ignore_git), observation in self._trees.items():
            if _tree(path, ignore_git=ignore_git) != observation:
                raise ValueError("operation dependency tree bytes, mode or membership changed")
        if any(path.exists() or path.is_symlink() for path in self._absent):
            raise ValueError("operation dependency acquired previously absent membership")

    def watch_optional_tree(self, path: Path) -> None:
        path = Path(path).absolute()
        if path.exists() or path.is_symlink():
            self.watch_tree(path)
        else:
            self._absent.add(path)

    def _reference(self, reference) -> Path:
        path = Path(reference["path"]).absolute()
        if hashlib.sha256(self.watch_file(path)).hexdigest() != reference["sha256"]:
            raise ValueError("operation dependency reference changed")
        return path

    def _enrollment(self, path: Path, seen=None) -> None:
        seen = set() if seen is None else seen
        path = Path(path).absolute()
        if path in seen:
            raise ValueError("operation enrollment dependency contains a cycle")
        seen.add(path)
        from . import rapid_additive_static_enrollment as additive
        if json.loads(self.watch_file(path)).get("receipt_type") == additive.ENROLLMENT_TYPE:
            for dependency in additive.membership_inputs(path):
                self.watch_file(dependency)
            return
        value = json.loads(self.watch_file(path)).get("payload", {})
        admission_root = Path(value["admission_root"])
        self._references(value, admission_root)
        for key in ("policy", "admission_provenance"):
            if key in value:
                target = self._reference(value[key])
                document = json.loads(self.watch_file(target))
                self._references(document, target.parent)
                if key == "policy":
                    initial = Path(document["payload"]["initial_admission_root"])
                    self._references(json.loads(self.watch_file(initial / "provenance.json")), initial)
        self._references(json.loads(self.watch_file(admission_root / "provenance.json")), admission_root)
        if value.get("parent") is not None:
            self._enrollment(self._reference(value["parent"]), seen)
        for row in value.get("decisions", []):
            self.watch_tree(self._reference(row["terminal"]).parent)

    def _references(self, item, root: Path, seen=None) -> None:
        """Follow authenticated lab receipt references, never webpage bodies."""
        seen = set() if seen is None else seen
        if isinstance(item, dict):
            if item.get("artifact_type") == "qcsd-chaff-qualification-implementation":
                # Installed paths belong to the collection image namespace.
                # Their actual source/client counterparts are registered by
                # bind_capture and checked by the unchanged image validators.
                return
            if set(item) == {"path", "sha256"}:
                path = Path(item["path"])
                path = path if path.is_absolute() else root / path
                path = self._reference({"path": str(path), "sha256": item["sha256"]})
                if path in seen:
                    return
                seen.add(path)
                try:
                    document = json.loads(self.watch_file(path))
                except (ValueError, UnicodeError, TypeError):
                    return
                if (isinstance(document, dict) and isinstance(document.get("receipt_type"), str)
                    and document["receipt_type"].startswith("qcsd-")):
                    document_root = root
                    if document["receipt_type"] == "qcsd-rapid-v6-immutable-enrollment-batch":
                        document_root = Path(document["payload"]["admission_root"])
                    self._references(document, document_root, seen)
            else:
                for child in item.values():
                    self._references(child, root, seen)
        elif isinstance(item, list):
            for child in item:
                self._references(child, root, seen)

    def bind_capture(self, spec) -> None:
        from .rapid_lane_evidence import STUDY_PROFILE_FILE
        from .rapid_capture_traffic import plan_files
        key = ("capture", json.dumps(spec.serializable(), sort_keys=True))
        if key in self._bindings:
            return
        for name in ("cohort", "qualification_spec", "plan_receipt", "source_manifest",
                     "client_binary", "base_launcher", "host_launcher"):
            self.watch_file(getattr(spec, name))
        self.watch_tree(spec.runtime_source_root, ignore_git=True)
        self.watch_tree(spec.module_root, ignore_git=True)
        self.watch_file(spec.execution_root / STUDY_PROFILE_FILE)
        plan = json.loads(self.watch_file(spec.plan_receipt)).get("payload", {})
        self._references(plan, spec.data_root)
        for relative, _ in plan_files(plan).values():
            self.watch_file(spec.execution_root / relative)
        if plan.get("study_version") == 6:
            for lane in plan.get("lanes", []):
                self.watch_file(spec.campaign_dir / (lane["campaign_name"] + ".yml"))
            self._enrollment(spec.cohort)
        qualifier = json.loads(self.watch_file(spec.qualification_spec))
        for row in qualifier.get("qualification_sets", []):
            for name in ("manifest", "sidecar_root"):
                path = Path(row[name])
                path = path if path.is_absolute() else spec.qualification_spec.parent / path
                if name == "manifest":
                    self.watch_file(path)
                else:
                    self.watch_tree(path)
        for site in plan.get("sites", []):
            path = spec.workload_root / (site["workload_id"] + ".json")
            self.watch_file(path)
            self.watch_optional_tree(path.with_name(site["workload_id"] + "-application-response-evidence"))
            if "data_role" in plan:
                from .supplied_static_preparation import ROLE, is_static
                from .supplied_static_capture_amendment import is_amended
                from .whole_graph_supplement import is_whole
                from .supplied_static_budget_successor import is_budget
                preparation = json.loads(self.watch_file(path)).get("preparation")
                if plan["data_role"] != ROLE or not (is_static(preparation) or is_amended(preparation) or is_whole(preparation) or is_budget(preparation)):
                    raise ValueError("operation workload changed its declared static data role")
                for evidence_root in self._workload_evidence_trees(path):
                    self.watch_tree(evidence_root)
        self._bindings.add(key)

    def bind_schedule(self, capsule) -> None:
        from .rapid_lane_evidence import CaptureSpec, PATH_KEYS, TRAFFIC_FILES, STUDY_PROFILE_FILE
        key = ("schedule", json.dumps(capsule, sort_keys=True))
        if key in self._bindings:
            return
        base = CaptureSpec(**{name: Path(value) if name in PATH_KEYS else value
                              for name, value in capsule["base_spec"].items()})
        self.bind_capture(base)
        self.watch_tree(Path(capsule["runtime"]["runtime_source_root"]), ignore_git=True)
        self.watch_tree(Path(capsule["runtime"]["module_root"]), ignore_git=True)
        self.watch_file(Path(capsule["runtime"]["execution_root"]) / STUDY_PROFILE_FILE)
        for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
            self.watch_file(Path(capsule["runtime"][name]))
        for relative, _ in TRAFFIC_FILES.values():
            self.watch_file(Path(capsule["runtime"]["execution_root"]) / relative)
        for lane in json.loads(self.watch_file(base.plan_receipt))["payload"]["lanes"]:
            self.watch_file(Path(capsule["runtime"]["campaign_dir"]) / (lane["campaign_name"] + ".yml"))
        self.watch_file(Path(capsule["qualification_spec"]["path"]))
        pending = [capsule["original_canonical"], capsule["current_canonical"]]
        seen = set()
        while pending:
            reference = pending.pop()
            path = self._reference(reference)
            if path in seen:
                continue
            seen.add(path)
            canonical = json.loads(self.watch_file(path))
            self.watch_tree(path.parent)
            for name in ("client_reuse_recipe", "client_reuse_proof", "original_native_build_record"):
                if name in canonical:
                    self._reference(canonical[name])
            if canonical.get("original_canonical") is not None:
                pending.append(canonical["original_canonical"])
        # Both original/current qualified graphs and sidecar inventories remain
        # dependencies even if their already validated semantic facts match.
        qualification_path = self._reference(capsule["qualification_spec"])
        qualifier = json.loads(self.watch_file(qualification_path))
        for row in qualifier["qualification_sets"]:
            for name in ("manifest", "sidecar_root"):
                path = Path(row[name])
                path = path if path.is_absolute() else qualification_path.parent / path
                self.watch_file(path) if name == "manifest" else self.watch_tree(path)
        for site in json.loads(self.watch_file(base.plan_receipt))["payload"]["sites"]:
            path = Path(capsule["runtime"]["workload_root"]) / (site["workload_id"] + ".json")
            self.watch_file(path)
            from .rapid_static_parallel_schedule import CAPSULE_TYPE as STATIC_CAPSULE_TYPE
            from .rapid_original_static_parallel_schedule import CAPSULE_TYPE as ORIGINAL_STATIC_CAPSULE_TYPE
            if capsule.get("artifact_type") in {STATIC_CAPSULE_TYPE, ORIGINAL_STATIC_CAPSULE_TYPE}:
                self._references(json.loads(self.watch_file(path)), path.parent)
            else:
                self.watch_tree(path.with_name(site["workload_id"] + "-application-response-evidence"))
        self._bindings.add(key)

    def bind_canary(self, reference, runtime=None) -> None:
        from .rapid_capture_traffic import canary_files
        plan = self._reference(reference["plan"])
        # A canary transport parent can also contain the execution's future
        # parallel outputs. Its exact plan, inventory and raw operation refs
        # are immutable files; the completed result is the closed raw tree.
        self._references(reference, plan.parent)
        for name in ("deep_receipt", "source_equivalence"):
            if name in reference:
                self._reference(reference[name])
        for operation in ("capture", "deep"):
            for value in reference[operation].values():
                self._reference(value)
        canary = json.loads(self.watch_file(plan))
        selected_traffic = canary_files(canary)
        execution = Path(canary["execution_root"])
        for campaign in canary.get("campaigns", []):
            self.watch_file(execution / campaign["campaign_relative"])
        if "workload_id" in canary:
            name = canary["workload_id"]
            self.watch_file(execution / "config/workloads" / (name + ".json"))
            self.watch_optional_tree(execution / "config/workloads" / (name + "-application-response-evidence"))
        if "qualification_set" in canary:
            self.watch_optional_tree(execution / "config/chaff-response-qualification-store/sets" / canary["qualification_set"])
        # Recipes and helpers are external read-only mounts, not necessarily
        # members of either Source inventory or the canary receipt directory.
        deep_start = json.loads(self.watch_file(self._reference(reference["deep"]["started"])))
        command = deep_start.get("command", [])
        for index, item in enumerate(command):
            if item == "--volume":
                mount = command[index + 1]
                for suffix in (":/recipe.py:ro", ":/helpers.py:ro"):
                    if mount.endswith(suffix):
                        self.watch_file(Path(mount.removesuffix(suffix)))
        if runtime is not None:
            for name in ("runtime_source_root", "module_root"):
                self.watch_tree(Path(runtime[name]), ignore_git=True)
            for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
                self.watch_file(Path(runtime[name]))
            for relative, _ in selected_traffic.values():
                self.watch_file(Path(runtime["execution_root"]) / relative)
                self.watch_file(execution / relative)
        inventory = json.loads(self.watch_file(plan.parent / "source-inventory.json"))
        self.watch_tree(Path(canary["clean_runtime_root"]), ignore_git=True)
        for name in inventory:
            self.watch_file(Path(canary["execution_root"]) / name)
        deep = json.loads(self.watch_file(Path(reference["deep_receipt"]["path"])))
        result = Path(canary["execution_root"]) / "results" / Path(deep["root"]).relative_to("/lab/results")
        self.watch_tree(result)
        if reference.get("source_equivalence") is not None:
            capsule = json.loads(self.watch_file(self._reference(reference["source_equivalence"])))
            self._references(capsule, plan.parent)
            for role in (capsule["original_runtime"], capsule["current_runtime"]):
                for name in ("runtime_source_root", "module_root"):
                    self.watch_tree(Path(role[name]), ignore_git=True)
                for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
                    self.watch_file(Path(role[name]))
                for relative, _ in selected_traffic.values():
                    self.watch_file(Path(role["execution_root"]) / relative)

    def content_key(self, files=(), trees=(), *, include_modes=True):
        values = []
        for path in files:
            raw = self.watch_file(Path(path))
            values.append(("file", hashlib.sha256(raw).hexdigest()))
        for path in trees:
            inventory = self.watch_tree(Path(path))
            if not include_modes:
                inventory = {name: {key: value for key, value in record.items() if key != "mode"}
                             for name, record in inventory.items()}
            values.append(("tree", json.dumps(inventory, sort_keys=True)))
        return tuple(values)

    def validate_canary(self, reference, runtime, mode, validator):
        self.bind_canary(reference, runtime)
        key = ("validated-canary", json.dumps(reference, sort_keys=True),
               json.dumps(runtime, sort_keys=True), mode)
        if self.has(key):
            return self.get(key)
        return self.remember(key, validator(reference, runtime=runtime, mode=mode))

    def validate_named_qualification(self, manifest, validator, **arguments):
        """Reuse only the identical fully checked named graph in this action."""
        root = Path(arguments["workload_root"])
        names = arguments["expected_workload_ids"]
        content = self.content_key([root / (name + ".json") for name in names],
            [Path(arguments["sidecar_root"]),
             *(tree for name in names for tree in self._workload_evidence_trees(root / (name + ".json")))],
            include_modes=False)
        semantic = {key: value for key, value in arguments.items()
                    if key not in {"workload_root", "sidecar_root"}}
        key = ("named-qualification", json.dumps(manifest, sort_keys=True),
               json.dumps(semantic, sort_keys=True), content)
        if self.has(key):
            return self.get(key)
        return self.remember(key, validator(manifest, **arguments))

    def _workload_evidence_trees(self, path: Path) -> list[Path]:
        """Bind the explicitly declared preparation role's actual raw evidence."""
        raw = self.watch_file(path)
        manifest = json.loads(raw)
        preparation = manifest.get("preparation")
        if isinstance(preparation, dict) and "data_role" in preparation:
            from . import rapid_selected_capture_input as selected
            if selected.is_selected(preparation):
                files, trees = selected.preparation_inputs(preparation, manifest["resources"])
                for dependency in files:
                    self.watch_file(dependency)
                return sorted(trees)
            from .supplied_static_preparation import is_static, preparation_roots
            from . import supplied_static_capture_amendment as amendment
            from .supplied_static_capture_amendment import is_amended
            from .whole_graph_supplement import is_whole, preparation_inputs as whole_inputs
            from .whole_graph_capture_amendment import is_amended as is_whole_amended, preparation_inputs as amended_whole_inputs
            from .supplied_static_budget_successor import is_budget
            from .static_budget_capture import preparation_inputs as budget_inputs
            from .static_budget_capture_amendment import is_amended as is_budget_amended, preparation_inputs as amended_budget_inputs
            if is_budget(preparation) or is_budget_amended(preparation):
                files, trees = (budget_inputs if is_budget(preparation) else amended_budget_inputs)(preparation)
                for dependency in files:
                    self.watch_file(dependency)
                return sorted(trees)
            if is_whole(preparation) or is_whole_amended(preparation):
                files, trees = (whole_inputs if is_whole(preparation) else amended_whole_inputs)(preparation)
                for dependency in files:
                    self.watch_file(dependency)
                return sorted(trees)
            if is_amended(preparation):
                key = ("amended-immutable-inputs-v3", hashlib.sha256(raw).hexdigest())
                if self.has(key):
                    return self.get(key)
                # Docker mount parents also contain later capture outputs.
                # Bind the authenticated immutable input closure, not the
                # transport parent's mutable image-check/objects membership.
                declaration_path = self._reference(preparation[amendment.FIELD])
                amendment.validate_preparation(preparation, manifest["resources"])
                declaration = amendment._declaration(declaration_path)
                self._references(declaration, declaration_path.parent)
                receipt_path = Path(declaration["receipt_path"])
                self._references(json.loads(self.watch_file(receipt_path)), receipt_path.parent)
                enrollment = self._reference(declaration["enrollment"])
                self._enrollment(enrollment)
                from . import rapid_rolling_capture as rolling
                from . import rapid_static_parallel_schedule as scheduling
                from .rapid_capture_traffic import FIELD, files
                _, _, policy = rolling._verify_enrollment(enrollment)
                for runtime, selected_traffic in ((declaration["runtime"], declaration.get(FIELD)),
                                                  (policy["runtime"], None)):
                    for name in ("runtime_source_root", "module_root"):
                        self.watch_tree(Path(runtime[name]), ignore_git=True)
                    for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
                        self.watch_file(Path(runtime[name]))
                    for relative, _ in files(selected_traffic).values():
                        self.watch_file(Path(runtime["execution_root"]) / relative)
                _, trees = scheduling.terminal_inputs(enrollment, _context=self)
                return self.remember(key, sorted(trees))
            if not is_static(preparation):
                raise ValueError("operation workload has an unknown preparation data role")
            return preparation_roots(preparation)
        return [path.with_name(path.stem + "-application-response-evidence")]
