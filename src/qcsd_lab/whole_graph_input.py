"""Reopen a separately produced browser occurrence graph, without granting GET credit.

The external discovery producer is an immutable, separately executed authority.
It is reopened in a fresh interpreter so its historical imports cannot be mixed
with the installed GET/capture verifier. No browser or network command is used.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any

from . import supplied_static_get as get
from . import supplied_static_graph as graph

INPUT_TYPE = "qcsd-external-browser-whole-graph-input-v1"
PLAN_TYPE = "qcsd-external-whole-graph-discovery-plan-v1"
CONTRACT = "catalogue-homepage-complete-occurrence-graph-input-only-v1"
PRODUCERS = {
    "graph_input.py": "9477be712eaaa8bf4af5d1e39922516ee37cd9e608a875bd772e85a11363d0dc",
    "operator.py": "b5826b33a9c4f109764997bcb92979bb940cdf750cf09f411aac9369d03c3c68",
}
SEEDED_PLAN_TYPE = "qcsd-external-navigation-seeded-whole-graph-retry-plan-v2"
SEEDED_INPUT_TYPE = "qcsd-external-browser-whole-graph-input-v2"
SEEDED_CONTRACT = "catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v2"
SEEDED_PRODUCERS = {
    "graph_input.py": "6e73cb1678ff98396e1416cfce3127cf60122db5500281f5749201d1d23a2eba",
    "operator.py": "d980ad2581fbac7add9c13e5368ad9fd2ed16cefc38d4e0ab7dcd4279988ebb6",
}
CATALOGUE_PLAN_TYPE = "qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v3"
CATALOGUE_INPUT_TYPE = "qcsd-external-browser-whole-graph-input-v3"
CATALOGUE_CONTRACT = "catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v3"
CATALOGUE_PRODUCERS = {
    "graph_input.py": "c4faae9cb516fbb16966855428270fd8e315a1a57edc24232f3a658f914badbc",
    "operator.py": "bf37b0ba64eff7844b04730c9307615c5d91530fb16348aa9345153ed315678a",
}
VERSIONS = {PLAN_TYPE: (1, CONTRACT, INPUT_TYPE, PRODUCERS),
            SEEDED_PLAN_TYPE: (2, SEEDED_CONTRACT, SEEDED_INPUT_TYPE, SEEDED_PRODUCERS),
            CATALOGUE_PLAN_TYPE: (3, CATALOGUE_CONTRACT, CATALOGUE_INPUT_TYPE, CATALOGUE_PRODUCERS)}
EXTERNAL_CONTROL_VERSIONS = {
    4: {"graph_input.py": "e80e00ec650d4c7bea9124b166b722475ac834545ce8c40665dc7299d84182e6"},
    5: {"graph_input.py": "008a8441e9d15390ba4a611e2e63984f3696783a6869f6e92acee275685a9bd6"},
    6: {"graph_input.py": "25beea47d87a703f3d92b72c412743f1286cf1270ac4b34cce506cf5c1f21c1d"},
    8: {"graph_input.py": "ca61994bff27939e04cd4f17a00800afe43e73757a8dd206b2e2f09336cb30d9"},
}
for _version, _sources in EXTERNAL_CONTROL_VERSIONS.items():
    VERSIONS[f"qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v{_version}"] = (
        _version, f"catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v{_version}",
        f"qcsd-external-browser-whole-graph-input-v{_version}",
        {**_sources, "operator.py": CATALOGUE_PRODUCERS["operator.py"]})
CONTINUATION_PLAN_TYPE = "qcsd-external-navigation-seeded-reservation-continuation-plan-v7"
VERSIONS[CONTINUATION_PLAN_TYPE] = (7,
    "retained-v4-reservations-with-owned-canceled-root-control-input-only-v7",
    "qcsd-external-browser-whole-graph-input-v7", {
        "graph_input.py": "786a7af83ceb1edbeba21ede1f6e614fce29c8ef08969214e5060383d1d373a1",
        "operator.py": "85abef7ca2faf0c477eedbe7fcb12e7f2d8445d4e48d7232acf023c3d8c7cf1b"})
CONTROL_SOURCES = {
    5: ("explicit-absent-loadingFailed-errorText-with-owned-terminal-v1", {
        "discovery_evidence_control.py": "cede18fe878b4e8fb94ed0d86ee7fbd3f59951259a19a8b3e798ee60fdee1551",
        "discovery_control.py": "fcfa614ea8fb9ab6a5c9985eced9be51986671fe1737a5062832468b6ba6a71e"}),
    6: ("explicit-terminal-diagnostic-and-owned-canceled-root-continuation-v1", {
        "discovery_evidence_control.py": "cede18fe878b4e8fb94ed0d86ee7fbd3f59951259a19a8b3e798ee60fdee1551",
        "discovery_control.py": "f556ecab3288a287058098c0d8998a3227eba75b02c8b4143420649bf6278d2b",
        "navigation_control.py": "e6bf22f1b89e742586af8715dcddc0c6009a02678d2c89bbe8f4909f870a286d"}),
}
CONTROL_SOURCES[7] = CONTROL_SOURCES[6]
CONTROL_SOURCES[8] = CONTROL_SOURCES[6]
V9_PLAN_TYPE = "qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v9"
V9_CONTINUATION_PLAN_TYPE = "qcsd-external-navigation-seeded-born-interruption-continuation-plan-v9"
V9_INPUT_TYPE = "qcsd-external-browser-whole-graph-input-v9"
V9_CONTRACT = "catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v9"
# These exact prospective reader pins are finalized together with the separately
# reviewed external producer. Historical V1--V8 identities remain unchanged.
V9_PRODUCERS = {"graph_input.py": "dc9715e4cbd4e2e924a5d01e4af2f57a0610000f25cd846bb6451b1a5b6552bc",
                "operator.py": "1468754336f6f375a2340eb1dd5f0c52e8fcd98b6043a8c01170300fb02689f8"}
V9_ACTION_SOURCES = {"action_facts.py": "53ceffa3487f9f7877e77f5ba9389f1786c68e633c8561f16f8e09c071f8c309",
                    "controller.py": "6a8957030c5c1ac2ddb40e5b38e9bd3bd4f48069ec7405fe86f46289395fcdaf"}
for _type in (V9_PLAN_TYPE, V9_CONTINUATION_PLAN_TYPE):
    VERSIONS[_type] = (9, V9_CONTRACT, V9_INPUT_TYPE, V9_PRODUCERS)
CONTROL_SOURCES[9] = CONTROL_SOURCES[6]
ZERO = {"scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}
RESOURCE_KEYS = {"id", "url", "type", "content_length", "data_length", "chaff_priority",
                 "known_valid", "depends_on", "headers"}


def discovery_digest(value: Any) -> str:
    # Match the external producer's explicit canonical encoding; resource
    # values remain unchanged even when a safe header contains Unicode.
    return graph.digest((json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode())


def reference(path: Path) -> dict[str, str]:
    path = path.absolute()
    raw = get._read(path)
    return {"path": str(path), "sha256": graph.digest(raw),
            "mode": f"{stat.S_IMODE(path.lstat().st_mode):04o}"}


def reopen(value: Any) -> Path:
    get._exact(value, {"path", "sha256", "mode"}, "whole graph reference")
    if (not isinstance(value["path"], str) or not Path(value["path"]).is_absolute()
            or ".." in Path(value["path"]).parts):
        raise ValueError("whole graph reference is not absolute and nonescaping")
    path = Path(value["path"])
    if reference(path) != value:
        raise ValueError("whole graph referenced bytes or mode changed")
    return path


def zero(value: Any) -> bool:
    return isinstance(value, dict) and all(type(value.get(k)) is type(v) and value[k] == v for k, v in ZERO.items())


def _producer(plan: dict[str, Any]) -> Path:
    version = VERSIONS.get(plan.get("artifact_type"))
    if (version is None or type(plan.get("schema_version")) is not int or plan["schema_version"] != version[0]
            or plan.get("contract") != version[1]):
        raise ValueError("whole graph declaration has an unrecognized producer version")
    producers = version[3]
    recorded = get._exact(plan.get("producer_sources"), set(producers), "discovery producers")
    paths = {name: reopen(ref) for name, ref in recorded.items()}
    if (any(recorded[name]["sha256"] != digest or recorded[name]["mode"] != "0644"
            for name, digest in producers.items())
            or paths["operator.py"].parent != paths["graph_input.py"].parent
            or any(paths[name].name != name for name in PRODUCERS)):
        raise ValueError("whole graph input has an unrecognized discovery producer")
    if version[0] >= 5:
        parent = paths["operator.py"].parent
        if version[0] == 9:
            refs = get._exact(plan.get("action_local_sources"), set(V9_ACTION_SOURCES), "V9 action readers")
            for name, digest in V9_ACTION_SOURCES.items():
                if (reopen(refs[name]) != parent / name or refs[name]["sha256"] != digest
                        or refs[name]["mode"] != "0644"):
                    raise ValueError("V9 action reader bytes, mode or location changed")
            original = get._load(get._read(reopen(plan["original_plan"])))
            if original.get("schema_version") != 8:
                raise ValueError("V9 retained interruption has another original producer")
            parent = _producer(original).parent
        _external_control(plan, parent)
    return paths["operator.py"]


def _external_control(plan: dict[str, Any], parent: Path) -> None:
    """External control files retain their own labels, separate from the image."""
    policy, sources = CONTROL_SOURCES[plan["schema_version"]]
    value = get._exact(plan.get("discovery_control"),
        {"policy", "sources", "installed_image_source_changed", "module_loading"}, "external discovery control")
    refs = get._exact(value["sources"], set(sources), "external discovery control Sources")
    if (value["policy"] != policy or value["installed_image_source_changed"] is not False
            or value["module_loading"] != "explicit-separate-modules-no-installed-module-replacement"):
        raise ValueError("external discovery control changes its separate producer role")
    for name, digest in sources.items():
        if (reopen(refs[name]) != parent / name or refs[name]["sha256"] != digest
                or refs[name]["mode"] != "0644"):
            raise ValueError("external discovery control bytes, mode or location changed")


def _verify_external(operator: Path, action: str, flag: str, path: Path, *, timeout: int = 60) -> None:
    # Resolve the running Python portably. Captured producer output may contain
    # resource data; neither it nor exception text is emitted by this API.
    env = {k: v for k, v in os.environ.items() if not k.startswith("QCSD_") and k != "PYTHONPATH"}
    result = subprocess.run([sys.executable, "-I", "-B", str(operator), action, flag, str(path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=timeout, check=False)
    if result.returncode != 0:
        raise ValueError("independent whole graph discovery reopening failed")


def load_plan(path: Path) -> dict[str, Any]:
    value = get._load(get._read(path))
    if not isinstance(value, dict) or value.get("artifact_type") not in VERSIONS or not zero(value):
        raise ValueError("whole graph discovery declaration has another role")
    operator = _producer(value)
    _verify_external(operator, "check", "--plan", path.absolute(), **({"timeout": 240} if value["schema_version"] == 9 else {}))
    return value


def project(value: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Lossless graph projection; readiness is deliberately not inferred here."""
    from .manifest import validate_manifest
    get._exact(manifest, {"resources"}, "neutral whole graph manifest")
    resources = manifest["resources"]
    approved = value.get("approved_origin_union")
    if (not isinstance(resources, list) or not resources or not isinstance(approved, list)
            or approved != sorted(set(approved))
            or value.get("resource_graph_sha256") != discovery_digest(resources)
            or type(value.get("resource_count")) is not int or value["resource_count"] != len(resources)):
        raise ValueError("whole graph occurrence count, digest or approved union differs")
    for identifier, row in enumerate(resources):
        if (not isinstance(row, dict) or set(row) != RESOURCE_KEYS
                or type(row["id"]) is not int or row["id"] != identifier
                or row["content_length"] is not None or type(row["data_length"]) is not int or row["data_length"] != 0
                or row["known_valid"] is not False or row["chaff_priority"] is not False
                or not isinstance(row["depends_on"], list)
                or row["depends_on"] != sorted(set(row["depends_on"]))
                or any(type(edge) is not int or not 0 <= edge < identifier for edge in row["depends_on"])
                or get._origin(row["url"]) not in approved):
            raise ValueError("whole graph changed an occurrence, edge or approved resource")
    validate_manifest(manifest)
    if resources[0]["type"] != "Document" or resources[0]["depends_on"] != []:
        raise ValueError("whole graph is not representable with an unchanged primary Document")
    return deepcopy(manifest)


def load_input(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    value = get._load(get._read(path))
    version = next((version for version in VERSIONS.values() if isinstance(value, dict) and value.get("artifact_type") == version[2]), None)
    if (version is None or type(value.get("schema_version")) is not int or value["schema_version"] != version[0]
            or value.get("contract") != version[1] or not zero(value)
            or value.get("http3_get_performed") is not False
            or value.get("admission_state") != "unqualified-graph-input-only"):
        raise ValueError("whole graph input has no distinct unqualified discovery role")
    plan_path = reopen(value["plan"])
    plan = get._load(get._read(plan_path))
    operator = _producer(plan)
    if VERSIONS[plan["artifact_type"]] != version:
        raise ValueError("whole graph input crosses discovery producer versions")
    _verify_external(operator, "verify-input", "--input", path.absolute(), **({"timeout": 240} if version[0] == 9 else {}))
    return value, project(value, get._load(get._read(reopen(value["native_manifest"]))))


def load_failure(path: Path) -> dict[str, Any]:
    """An operational discovery failure is an accounted attempt, never eligibility."""
    value = get._load(get._read(path))
    plan = load_plan(reopen(value["plan"]))
    if plan["schema_version"] >= 4:
        return _controlled_failure(path, value, plan)
    seeded = plan["artifact_type"] in {SEEDED_PLAN_TYPE, CATALOGUE_PLAN_TYPE}
    fields = {"schema_version", "plan", "candidate", "completed_at", "elapsed_ns",
        "error_type", "message", "traceback", "completed_passes", "outcome", *ZERO}
    if seeded:
        fields.update({"completed_navigation", "failure_stage"})
    get._exact(value, fields, "discovery failure")
    if (path.name != "failed.json" or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not zero(value) or value["outcome"] != "operational-discovery-failure-no-admission"
            or type(value["elapsed_ns"]) is not int or value["elapsed_ns"] <= 0
            or any(not isinstance(value[key], str) for key in ("error_type", "message", "traceback"))):
        raise ValueError("whole graph discovery failure changes its operational-only role")
    started = get._exact(get._load(get._read(path.with_name("started.json"))),
        {"schema_version", "plan", "candidate", "runtime", "started_at", *ZERO}, "discovery failure start")
    source = get._read(path.with_name("image-source-metadata.json"))
    execution_role = {PLAN_TYPE: "actual-browser-image-graph-input-only-v1",
        SEEDED_PLAN_TYPE: "actual-browser-image-navigation-seeded-graph-input-only-v2",
        CATALOGUE_PLAN_TYPE: "actual-browser-image-navigation-seeded-graph-input-only-v3"}[plan["artifact_type"]]
    runtime = {"image_digest": plan["browser_image"], "source_metadata": get._load(source),
        "installed_metadata_sha256": graph.digest(source), "execution_role": execution_role}
    if (started["plan"] != value["plan"] or started["candidate"] != value["candidate"]
            or value["candidate"] not in plan["candidates"] or started["runtime"] != runtime or not zero(started)
            or get._load(source) != get._load(get._read(reopen(plan["source_metadata"])))
            or not get._time(plan["declared_at"]) <= get._time(started["started_at"]) <= get._time(value["completed_at"])):
        raise ValueError("whole graph failed attempt has no exact prior declaration/runtime/chronology")
    if not isinstance(value["completed_passes"], list) or len(value["completed_passes"]) > plan["max_origin_passes"]:
        raise ValueError("whole graph failed attempt pass prefix exceeds its declared bound")
    for entry in value["completed_passes"]:
        get._exact(entry, {"started", "result", "completed"}, "failed discovery pass")
        if any(reopen(ref).parent != path.absolute().parent for ref in entry.values()):
            raise ValueError("failed discovery pass escapes its original raw attempt")
    if seeded:
        if value["failure_stage"] not in {"navigation", "convergence"}:
            raise ValueError("seeded discovery failure changes its recorded phase")
        if value["completed_navigation"] is not None:
            get._exact(value["completed_navigation"], {"started", "result", "completed"}, "failed discovery navigation")
            if any(reopen(ref).parent != path.absolute().parent for ref in value["completed_navigation"].values()):
                raise ValueError("failed navigation leaves its retained actual attempt")
    if path.with_name("whole-graph-input.json").exists():
        raise ValueError("successful closed discovery cannot be substituted by a failure")
    return value


def _controlled_failure(path: Path, value: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """Reopen new operational failures without altering historical schemas."""
    fields = {"schema_version", "plan", "candidate", "completed_at", "elapsed_ns", "error_type",
        "message", "traceback", "completed_passes", "completed_navigation", "failure_stage", "outcome", *ZERO}
    version = plan["schema_version"]
    if version >= 5:
        fields.update({"exception_evidence", "exception_evidence_sha256"})
    get._exact(value, fields, "controlled discovery failure")
    if (path.name != "failed.json" or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not zero(value) or value["outcome"] != "operational-discovery-failure-no-admission"
            or type(value["elapsed_ns"]) is not int or value["elapsed_ns"] <= 0
            or any(not isinstance(value[key], str) for key in ("error_type", "message", "traceback"))
            or value["failure_stage"] not in {"navigation", "complete-occurrence-convergence"}):
        raise ValueError("controlled discovery failure changes its operational-only role")
    if version >= 5:
        if (value["exception_evidence"] is not None and not isinstance(value["exception_evidence"], dict)
                or value["exception_evidence_sha256"] != discovery_digest(value["exception_evidence"])):
            raise ValueError("controlled discovery exception evidence changed")
    started = get._exact(get._load(get._read(path.with_name("started.json"))),
        {"schema_version", "plan", "candidate", "runtime", "started_at", *ZERO}, "controlled discovery start")
    source = get._read(path.with_name("image-source-metadata.json"))
    runtime = {"image_digest": plan["browser_image"], "source_metadata": get._load(source),
        "installed_metadata_sha256": graph.digest(source),
        "execution_role": f"actual-browser-image-navigation-seeded-graph-input-only-v{version}"}
    if version >= 5:
        runtime["external_discovery_control"] = plan["discovery_control"]
    if (type(started["schema_version"]) is not int or started["schema_version"] != 1
            or started["plan"] != value["plan"] or started["candidate"] != value["candidate"]
            or value["candidate"] not in plan["candidates"] or started["runtime"] != runtime or not zero(started)
            or get._load(source) != get._load(get._read(reopen(plan["source_metadata"])))
            or not get._time(plan["declared_at"]) <= get._time(started["started_at"]) <= get._time(value["completed_at"])):
        raise ValueError("controlled failed attempt changes declaration, runtime or chronology")
    if not isinstance(value["completed_passes"], list) or len(value["completed_passes"]) > plan["max_origin_passes"]:
        raise ValueError("controlled failed attempt exceeds its pass bound")
    records = [(entry, {"started", "result", "completed"}) for entry in value["completed_passes"]]
    if value["completed_navigation"] is not None:
        records.append((value["completed_navigation"],
            {"started", "result", "completed", "control"} if version >= 6 else {"started", "result", "completed"}))
    for entry, keys in records:
        get._exact(entry, keys, "controlled failed attempt raw records")
        if any(reopen(ref).parent != path.absolute().parent for ref in entry.values()):
            raise ValueError("controlled failed attempt raw records escape their original namespace")
    if path.with_name("whole-graph-input.json").exists():
        raise ValueError("successful discovery cannot become an operational failure")
    return value


def plan_files(path: Path) -> tuple[list[Path], list[Path]]:
    """Complete authenticated declaration dependencies, including retry failures."""
    load_plan(path)
    files, sources, seen = set(), set(), set()

    def ref(value):
        target = reopen(value)
        files.add(target)
        return target

    def plan(reference_value):
        target = ref(reference_value)
        if target in seen:
            return
        seen.add(target)
        declaration = get._load(get._read(target))
        _producer(declaration)
        for entry in declaration["producer_sources"].values():
            ref(entry)
        if declaration["schema_version"] >= 5:
            for entry in declaration["discovery_control"]["sources"].values():
                ref(entry)
        ref(declaration["catalogue"])
        ref(declaration["source_metadata"])
        for key in ("context", "source_list", "profile", "candidate_order"):
            ref(declaration["original_prefix"][key])
        source_root = Path(declaration["source"]["root"])
        sources.add(source_root)
        for relative, record in declaration["source"]["files"].items():
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError("discovery Source inventory escapes its declared root")
            source_path = source_root / relative
            # The independent verifier authenticates this complete inventory;
            # bind those exact files as well for transport/release fences.
            files.add(source_path)
        if declaration["schema_version"] == 9:
            # The independent V9 verifier reconstructs the born interruption,
            # exact old raw tree and every completed ordered successor batch.
            # Bind those same raw files/trees for downstream release fences.
            for entry in declaration["action_local_sources"].values():
                ref(entry)
            plan(declaration["original_plan"])
            retained = get._load(get._read(ref(declaration["retained_interruption"])))
            def retained_refs(value):
                if isinstance(value, dict):
                    if set(value) == {"path", "sha256", "mode"}:
                        ref(value)
                    else:
                        for item in value.values():
                            retained_refs(item)
                elif isinstance(value, list):
                    for item in value:
                        retained_refs(item)
            retained_refs(retained)
            sources.add(Path(retained["original_root"]))
            if declaration["previous_plan"] is not None:
                plan(declaration["previous_plan"])
                batch = ref(declaration["previous_batch"])
                sources.add(batch.parent)
                for item in sorted(batch.parent.rglob("*")):
                    if item.is_symlink():
                        raise ValueError("V9 batch has a linked raw member")
                    if item.is_file():
                        files.add(item)
            return
        for previous in declaration["previous_plans"]:
            plan(previous)
        if declaration["artifact_type"] == SEEDED_PLAN_TYPE:
            retry = declaration["retry"]
            plan(retry["original_plan"])
            ref(retry["failed_batch"])
            for entry in retry["original_producer_sources"].values():
                ref(entry)
            for attempt in retry["all_original_attempts"]:
                for entry in attempt["attempt_files"].values():
                    ref(entry)
                for entry in attempt["actual_operation"].values():
                    ref(entry)
        if declaration["schema_version"] >= 3:
            from .supplied_static_preparation import open_reference

            def history_refs(value):
                if isinstance(value, dict):
                    if set(value) == {"path", "sha256", "mode"}:
                        ref(value)
                    elif set(value) == {"path", "sha256"}:
                        files.add(open_reference(value))
                    else:
                        for item in value.values():
                            history_refs(item)
                elif isinstance(value, list):
                    for item in value:
                        history_refs(item)

            # These fields have already been independently reconstructed by
            # the exact v3 producer. Bind all immutable raw history, including
            # successful inputs and failed attempts; outcome never selects the
            # next catalogue identity. Existing v1/v2 traversal is unchanged.
            history_refs(declaration["history_batches"])
            history_refs(declaration["history"])
            if declaration["schema_version"] == 7:
                history_refs(declaration["reservation_continuation"])
                sources.add(Path(declaration["reservation_continuation"]["retained_root"]))
            if declaration["schema_version"] == 8:
                history_refs(declaration["reservation_retirements"])
            for batch in declaration["history"]:
                for attempt in batch["attempts"]:
                    root = Path(attempt["root"])
                    if not root.is_absolute() or ".." in root.parts or any(path.is_symlink() for path in (root, *root.parents)):
                        raise ValueError("catalogue discovery history leaves its original raw namespace")
                    sources.add(root)

    plan(reference(path))
    for entry in files:
        get._read(entry)
    return sorted(files), sorted(sources)


def input_files(path: Path) -> tuple[list[Path], list[Path]]:
    """Finite authenticated raw dependency inventory, including old discovery Source."""
    value, _ = load_input(path)
    declaration_files, sources = plan_files(reopen(value["plan"]))
    files = {path.absolute(), *declaration_files}

    def ref(value):
        target = reopen(value)
        files.add(target)
        return target

    ref(value["native_manifest"])
    ref(value["final_discovery"])
    for pass_record in value["passes"]:
        for entry in pass_record.values():
            ref(entry)
    if value["schema_version"] >= 2:
        for entry in value["navigation"].values():
            ref(entry)
    files.add(path.with_name("image-source-metadata.json").absolute())
    files.add(path.with_name("started.json").absolute())
    for entry in files:
        get._read(entry)
    return sorted(files), sources


def roots(path: Path) -> list[Path]:
    files, sources = input_files(path)
    candidates = set(sources) | {item.parent for item in files}
    return sorted(item for item in candidates if not any(item != parent and item.is_relative_to(parent) for parent in candidates))


def plan_roots(path: Path) -> list[Path]:
    files, sources = plan_files(path)
    candidates = set(sources) | {item.parent for item in files}
    return sorted(item for item in candidates if not any(item != parent and item.is_relative_to(parent) for parent in candidates))
