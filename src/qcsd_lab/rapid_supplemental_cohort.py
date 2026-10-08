"""Declared supplemental queues attached to an existing selected ledger.

Catalogue reservations and browser graphs retain their original identities.
Only this queue's decisions precede its next GET. The retained ledger is a
metadata membership anchor, not a new interpretation of its acquisition prefix.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import rapid_per_class_selected_enrollment as ledger
from . import rapid_site_admission as receipts
from . import supplied_static_admission as static
from . import supplied_static_get as get
from . import supplied_static_graph as graph
from . import supplied_static_preparation as original
from . import whole_graph_input as inputs
from . import whole_graph_supplement as whole

CONTEXT_TYPE = "qcsd-independent-rapid50-supplemental-cohort-v1"
CONTRACT = "retained-selected-ledger-plus-declared-supplement-only-ordered-get-v1"
FIELDS = {"contract", "data_role", "seed_enrollment", "seed_policy", "seed_classes",
    "profile", "plans", "candidates", "graph_inputs", "failed_discoveries",
    "runtime_binding", "capture_limits", "reader_sources", "declared_at",
    "parent_context", "inherited_terminals", *inputs.ZERO}


@dataclass(frozen=True)
class CohortAnchor:
    root: Path
    provenance: dict
    candidates: tuple = ()


def reader_sources():
    return {module.__name__: inputs.reference(Path(module.__file__)) for module in
        (inputs, whole, ledger, __import__(__name__, fromlist=["_"]))}


def _recognized_reader_sources(value: dict) -> bool:
    """Reopen finite retained Source62/Source63 cohort reader families without new credit."""
    current = reader_sources()
    if value == current:
        return True
    retained_families = ({
        "qcsd_lab.whole_graph_input": "5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5",
        "qcsd_lab.whole_graph_supplement": "164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7",
        "qcsd_lab.rapid_per_class_selected_enrollment": "4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0",
        "qcsd_lab.rapid_supplemental_cohort": "12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be",
    }, {
        "qcsd_lab.whole_graph_input": "5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa",
        "qcsd_lab.whole_graph_supplement": "293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b",
        "qcsd_lab.rapid_per_class_selected_enrollment": "4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0",
        "qcsd_lab.rapid_supplemental_cohort": "39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029",
    }, {
        "qcsd_lab.whole_graph_input": "7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c",
        "qcsd_lab.whole_graph_supplement": "4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0",
        "qcsd_lab.rapid_per_class_selected_enrollment": "4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0",
        "qcsd_lab.rapid_supplemental_cohort": "c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d",
    })
    if not isinstance(value, dict) or set(value) != set(retained_families[0]):
        return False
    paths = {}
    for name in value:
        ref = value[name]
        paths[name] = inputs.reopen(ref)
        if (ref["mode"] != "0644"
                or paths[name].name != name.rsplit(".", 1)[1] + ".py"):
            return False
    if len({path.parent for path in paths.values()}) != 1:
        return False
    retained = next((family for family in retained_families
        if all(value[name]["sha256"] == digest for name, digest in family.items())), None)
    if retained is None:
        return False
    from . import rapid_fixed_condition_target as fixed
    for name, path in paths.items():
        fixed._compatible_acquisition_code("src/qcsd_lab/" + path.name,
                                          fixed.reference(path),
                                          fixed.reference(inputs.reopen(current[name])))
    return True


def is_context(root: Path) -> bool:
    return get._load(get._read(root / "provenance.json")).get("receipt_type") == CONTEXT_TYPE


def _profile(path: Path) -> dict:
    value = get._load(get._read(path))
    expected = {**static.PROFILE, "capture_limits": static.capture_limits(16 * 1024 * 1024, 64)}
    if (not isinstance(value, dict) or set(value) != set(expected)
            or any(type(value[key]) is not type(item) or value[key] != item for key, item in expected.items())):
        raise ValueError("supplement cohort requires the unchanged rapid50 profile and full graph caps")
    return value


def _rows(plans: list[dict], classes: list[dict]) -> list[dict]:
    rows, seen, domains = [], {row["candidate_id"] for row in classes}, set()
    for cls in classes:
        domains.update(cls["canonical_sites"])
    for plan in plans:
        for candidate in plan["candidates"]:
            canonical = ledger.old._canonical_host(candidate["domain"])
            if (candidate["candidate_id"] in seen or canonical in domains
                    or type(candidate["catalogue_position"]) is not int
                    or rows and candidate["catalogue_position"] <= rows[-1]["source_position"]):
                raise ValueError("supplement cohort repeats or reorders an enrolled or reserved identity")
            seen.add(candidate["candidate_id"]); domains.add(canonical)
            rows.append({"position": len(rows) + 1, "source_position": candidate["catalogue_position"],
                "candidate_id": candidate["candidate_id"], "domain": candidate["domain"],
                "catalogue_candidate": candidate})
    if not 1 <= len(rows) <= 5:
        raise ValueError("supplement cohort needs one to five explicit original catalogue reservations")
    return rows


def _seed(path: Path):
    batch, classes, policy = ledger.verify_enrollment(path)
    if (not 1 <= len(classes) < 50 or policy["class_target"] != 50
            or policy["formal_trace_target"] != 16000):
        raise ValueError("supplement cohort needs an unfinished genuine rapid50 selected ledger")
    return batch, classes, policy


def _runtime(value: dict) -> dict:
    return get.runtime_binding(value)


def initialize(root: Path, *, seed_enrollment: Path, profile: Path, plans: list[Path],
               graph_inputs: list[Path], failed_discoveries: list[Path], expected_runtime: dict) -> Path:
    runtime = _runtime(expected_runtime)
    batch, classes, _ = _seed(seed_enrollment)
    _profile(profile)
    declarations = [inputs.load_plan(path) for path in plans]
    candidates = _rows(declarations, classes)
    known = {row["candidate_id"]: row for row in candidates}
    graphs, failures = {}, {}
    for path in graph_inputs:
        value, _ = inputs.load_input(path); key = value["candidate"]["candidate_id"]
        if (key not in known or value["candidate"] != known[key]["catalogue_candidate"]
                or key in graphs or value["plan"] not in [inputs.reference(p) for p in plans]):
            raise ValueError("supplement graph changes a declared candidate or repeats an input")
        graphs[key] = inputs.reference(path)
    for path in failed_discoveries:
        value = inputs.load_failure(path); key = value["candidate"]["candidate_id"]
        if (key not in known or value["candidate"] != known[key]["catalogue_candidate"]
                or key in failures or key in graphs or value["plan"] not in [inputs.reference(p) for p in plans]):
            raise ValueError("supplement failure changes a declared candidate or replaces a graph")
        failures[key] = {"record": inputs.reference(path), "files": whole._tree_files(path.parent)}
    root = root.absolute()
    for protected in (seed_enrollment, profile, *plans, *graph_inputs, *failed_discoveries):
        get.util.require_disjoint_path(root, [protected], label="supplement cohort")
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    value = {"contract": CONTRACT, "data_role": whole.ROLE,
        "seed_enrollment": inputs.reference(seed_enrollment), "seed_policy": batch["policy"],
        "seed_classes": classes, "profile": inputs.reference(profile),
        "plans": [inputs.reference(path) for path in plans], "candidates": candidates,
        "graph_inputs": graphs, "failed_discoveries": failures,
        "runtime_binding": runtime,
        "capture_limits": static.capture_limits(16 * 1024 * 1024, 64),
        "reader_sources": reader_sources(), "declared_at": receipts._now(),
        "parent_context": None, "inherited_terminals": [], **inputs.ZERO}
    path = static._write(root / "provenance.json", CONTEXT_TYPE, value)
    load_context(root)
    return path


def load_context(root: Path) -> whole.Context:
    root = root.absolute()
    value = receipts._unpack(get._read(root / "provenance.json"), CONTEXT_TYPE)
    get._exact(value, FIELDS, "independent supplemental cohort")
    if (value["contract"] != CONTRACT or value["data_role"] != whole.ROLE
            or not inputs.zero(value) or value["parent_context"] is not None
            or value["inherited_terminals"] != [] or not _recognized_reader_sources(value["reader_sources"])
            or get._time(value["declared_at"]) > get._time(receipts._now())):
        raise ValueError("supplement cohort changed its reader, prospective role or cut")
    for ref in value["reader_sources"].values(): inputs.reopen(ref)
    seed = inputs.reopen(value["seed_enrollment"])
    batch, classes, policy = _seed(seed)
    profile = inputs.reopen(value["profile"]); rules = _profile(profile)
    declarations = [inputs.load_plan(inputs.reopen(ref)) for ref in value["plans"]]
    if (classes != value["seed_classes"] or batch["policy"] != value["seed_policy"]
            or _rows(declarations, classes) != value["candidates"]
            or rules["capture_limits"] != value["capture_limits"]
            or get._time(batch["declared_at"]) > get._time(value["declared_at"])):
        raise ValueError("supplement cohort changed its retained ledger, reservations or caps")
    _runtime(value["runtime_binding"])
    known = {row["candidate_id"]: row for row in value["candidates"]}
    if not isinstance(value["graph_inputs"], dict) or not isinstance(value["failed_discoveries"], dict):
        raise ValueError("supplement evidence bindings must be explicit")
    for key, ref in value["graph_inputs"].items():
        graph_value, _ = inputs.load_input(inputs.reopen(ref))
        if (key not in known or graph_value["candidate"] != known[key]["catalogue_candidate"]
                or graph_value["plan"] not in value["plans"]
                or get._time(graph_value["completed_at"]) > get._time(value["declared_at"])):
            raise ValueError("supplement graph changed its whole input, reservation or chronology")
    for key, item in value["failed_discoveries"].items():
        get._exact(item, {"record", "files"}, "supplement discovery failure")
        failure = inputs.load_failure(inputs.reopen(item["record"]))
        if (key not in known or key in value["graph_inputs"]
                or failure["candidate"] != known[key]["catalogue_candidate"]
                or failure["plan"] not in value["plans"]
                or whole._tree_files(Path(item["record"]["path"]).parent) != item["files"]
                or get._time(failure["completed_at"]) > get._time(value["declared_at"])):
            raise ValueError("supplement discovery failure changed its actual evidence")
    anchor = CohortAnchor(seed.parent, {"profile": original.reference(profile),
        "admission_identity": policy["admission_identity"]})
    return whole.Context(root, value, anchor, tuple(value["candidates"]))


def require_order(context: whole.Context, position: int):
    for previous in range(1, position):
        path = whole.terminal_path(context, previous)
        if not path.exists():
            raise ValueError("supplement GET/admission cannot skip an unassessed declared candidate")
        whole.verify_terminal(path, context)


def require_get(context: whole.Context, position: int):
    require_order(context, position)
    _, _, _, neutral = whole._candidate_input(context, position)
    if len({get._origin(row["url"]) for row in neutral["resources"]}) < 2:
        raise ValueError("supplement complete graph fails the rapid50 two-origin GET entry rule")


def metadata(policy: dict, path: Path, files=None) -> dict:
    if path.name != "provenance.json":
        raise ValueError("supplement cohort metadata requires its exact declaration namespace")
    context = load_context(path.parent)
    bound = receipts._unpack(get._read(original.open_reference(context.provenance["seed_policy"])), ledger.POLICY_TYPE)
    if bound != policy:
        raise ValueError("supplement cohort belongs to another selected ledger")
    if files is not None: files.update(dependencies(context))
    return context.provenance


def dependencies(context: whole.Context) -> set[Path]:
    value = context.provenance
    result = {context.root / "provenance.json", inputs.reopen(value["seed_enrollment"]),
        original.open_reference(value["seed_policy"]), inputs.reopen(value["profile"])}
    # These are the selected ledger's metadata/audit files, not the original
    # acquisition queue's unrelated GET histories.
    result.update(ledger.membership_inputs(inputs.reopen(value["seed_enrollment"])))
    result.update(inputs.reopen(ref) for ref in value["reader_sources"].values())
    for ref in value["plans"]:
        files, _ = inputs.plan_files(inputs.reopen(ref)); result.update(files)
    for ref in value["graph_inputs"].values():
        files, _ = inputs.input_files(inputs.reopen(ref)); result.update(files)
    for item in value["failed_discoveries"].values():
        result.update(inputs.reopen(ref) for ref in item["files"].values())
    return result


def roots(context: whole.Context) -> set[Path]:
    return {path.parent for path in dependencies(context)} | {context.root}
