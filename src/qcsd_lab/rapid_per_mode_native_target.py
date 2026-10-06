"""Join original fixed-target proofs through finite, prospective Native epochs.

Original v1 targets, rows and installed/deep validators remain authoritative.
An appended epoch preserves every earlier epoch and accepted logical slot.
"""
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from . import rapid_fixed_condition_target as fixed
from .rapid_operation_facts import current_context

TARGET_TYPE = "qcsd-five-fixed-condition-per-mode-native-epoch-target-v1"
PROGRESS_TYPE = "qcsd-original-verified-per-mode-native-epoch-progress-v1"
CHUNK_INPUT_TYPE = "qcsd-per-mode-native-epoch-remaining-slot-planning-input-v1"
CORPUS_TYPE = "qcsd-exact-fifty-site-five-per-mode-native-epoch-corpus-v1"
CONTRACT = "original-full-graphs-fixed-conditions-finite-native-epochs-16000-v1"
MODES = fixed.MODES
CS_MODE = "cs-buflo"
CLASSES, SLOTS, TOTAL = fixed.CLASSES, fixed.SLOTS, fixed.TOTAL


def _owned(function):
    @wraps(function)
    def run(*args, **kwargs):
        _sources()  # Register every executing control before the first semantic read.
        return function(*args, **kwargs)
    return fixed._owned(run)


def _sources():
    return {"reducer": fixed.reference(Path(__file__)), "fixed": fixed._sources()}


def _source_check(value):
    fixed._keys(value, {"reducer", "fixed"}, "per-mode reducer Source")
    fixed._open(value["reducer"])
    current = fixed.reference(Path(__file__))
    if any(value["reducer"][key] != current[key] for key in ("sha256", "mode")):
        raise ValueError("per-mode reducer code bytes or mode changed")
    fixed._compatible_sources(value["fixed"])


def _write(output, kind, value):
    fixed._check_action()
    result = fixed.epoch._write(Path(output).absolute(), kind, value)
    fixed._check_action()
    return result


def _key(row):
    return row["class_index"], row["mode"], row["logical_visit"]


def _pair(value):
    return {key: value[key] for key in ("native_head", "client_sha256")}


def _lists(value, label):
    fixed._keys(value, MODES, label)
    if any(not isinstance(refs, list) or not refs for refs in value.values()):
        raise ValueError(label + " needs explicit nonempty finite ordered lists")


def _binding(ref, pair):
    context = current_context(); key = ("per-mode-installed-binding", fixed._digest(ref))
    if context.has(key):
        source = context.get(key)
    else:
        source = fixed._measurement_source(ref)
        context.remember(key, source)
    identity = source["binding"]["runtime_identity"]
    if (source["native_head"] != pair["native_head"]
            or any(identity["source"][key] != pair["native_head"]
                   for key in ("neqo_commit", "neqo_pinned_commit"))
            or identity["client_sha256"] != pair["client_sha256"]):
        raise ValueError("epoch differs from its actual clean installed Native/client")
    return source


def _conditions(target):
    return {mode: {key: target["conditions"][mode][key] for key in ("identity", "identity_sha256")} for mode in MODES}


def _components(mode_targets, anchor):
    _lists(mode_targets, "five original mode target lists")
    targets = {}; epochs = {}; sources = {}
    for mode in MODES:
        targets[mode] = []
        for record in mode_targets[mode]:
            fixed._keys(record, {"target", "source_binding"}, "original epoch target")
            target = fixed.validate_target(record["target"])
            if not fixed._typed_equal(_conditions(target), _conditions(anchor)):
                raise ValueError("epoch changed one of the original five fixed conditions")
            targets[mode].append(target)
    ordinary = targets["undefended"][0]
    baseline = _pair(ordinary["target_identity"])
    classes = max((t["classes"] for group in targets.values() for t in group), key=len)
    for mode in MODES:
        epochs[mode] = []; sources[mode] = []; pairs = set()
        for index, (record, target) in enumerate(zip(mode_targets[mode], targets[mode])):
            if target["classes"] != classes[:len(target["classes"])]:
                raise ValueError("epochs fork a class, full graph or capture limits")
            pair = _pair(target["target_identity"]); token = fixed._digest(pair)
            if token in pairs:
                raise ValueError("mode repeats a declared Native/client epoch")
            pairs.add(token)
            original = index == 0 and mode != CS_MODE
            if original and pair != baseline:
                raise ValueError("original ordinary/FRONT/TAM/BuFLO epoch changed")
            if not original and (pair == baseline or any(pair[k] == baseline[k] for k in pair)):
                raise ValueError("repaired epoch needs a distinct truthful Native head and client")
            if not fixed._typed_equal(target["conditions"][mode]["identity"],
                                      ordinary["conditions"][mode]["identity"]):
                raise ValueError("epoch changed its canonical fixed traffic condition")
            if original:
                if record["source_binding"] is not None:
                    raise ValueError("original epoch is authenticated by retained original proofs")
                source = None
            else:
                if record["source_binding"] is None:
                    raise ValueError("repaired epoch lacks actual clean installed Source proof")
                source = _binding(record["source_binding"], pair)
            epochs[mode].append({**pair, "condition_sha256": target["conditions"][mode]["identity_sha256"]})
            sources[mode].append(source)
    return targets, classes, epochs, sources


def _carry_rows(ref, epochs, classes):
    progress = fixed.validate_progress(ref); target = fixed.validate_target(progress["target"])
    baseline = _pair(epochs["undefended"][0])
    if (_pair(target["target_identity"]) != baseline
            or progress["classes"] != classes[:len(progress["classes"])]):
        raise ValueError("carry anchor changed original Native, class, graph or caps")
    rows = [row for row in progress["accepted_rows"] if row["mode"] != CS_MODE]
    for row in rows:
        epoch = epochs[row["mode"]][0]
        if row["condition_sha256"] != epoch["condition_sha256"]:
            raise ValueError("carry anchor changed an original fixed condition")
    return rows


def _append_rows(before, selected):
    current = {_key(row): row for row in selected}
    if any(current.get(_key(row)) != row for row in before):
        raise ValueError("epoch progress dropped, moved or relabelled an original row")
    keys = {_key(row) for row in before}
    return before + [row for row in selected if _key(row) not in keys]


def _target_core(namespace, mode_targets, carry_progress, parent, declared):
    if not isinstance(namespace, str) or fixed.re.fullmatch(r"[a-z0-9][a-z0-9-]{1,95}", namespace) is None:
        raise ValueError("epoch target needs an explicit prospective namespace")
    anchor = fixed.validate_target(fixed.validate_progress(carry_progress)["target"])
    _, classes, epochs, bindings = _components(mode_targets, anchor)
    carried = _carry_rows(carry_progress, epochs, classes)
    old = None if parent is None else validate_target(parent)
    transition = "initial"; revision = 1
    times = {mode: [None if source is None else declared for source in bindings[mode]] for mode in MODES}
    if old is not None:
        if namespace != old["identity"]["namespace"] or old["classes"] != classes[:len(old["classes"])]:
            raise ValueError("epoch revision changed namespace or original class map")
        for mode in MODES:
            prior = old["identity"]["epochs"][mode]
            if epochs[mode][:len(prior)] != prior or len(epochs[mode]) < len(prior):
                raise ValueError("epoch revision must preserve the complete original ordered prefix")
            if any(record["source_binding"] != previous["source_binding"] for record, previous in
                   zip(mode_targets[mode], old["mode_targets"][mode])):
                raise ValueError("epoch revision substituted a retained installed Source binding")
            times[mode][:len(prior)] = old["epoch_declared_at"][mode]
        changed = epochs != old["identity"]["epochs"]
        transition = "epoch-addition" if changed else "same-epochs"
        revision = old["role_revision"] + int(changed)
        _append_rows(_carry_rows(old["carry_progress"], old["identity"]["epochs"], old["classes"]), carried)
    for mode in MODES:
        for source, stamp in zip(bindings[mode], times[mode]):
            if source is not None and not fixed._time(source["binding"]["published_at"]) <= fixed._time(stamp):
                raise ValueError("epoch must follow its actual installed Source proof")
    identity = {"namespace": namespace, "epochs": epochs, "classes": CLASSES, "slots": SLOTS, "total": TOTAL}
    return {"contract": CONTRACT, "identity": identity, "target_id": fixed._digest(identity),
            "mode_targets": mode_targets, "carry_progress": carry_progress, "classes": classes,
            "parent": parent, "transition": transition, "role_revision": revision,
            "epoch_declared_at": times, "declared_at": declared, "scientific_credit": False}


@_owned
def publish_target(*, namespace, mode_targets, carry_progress, output, parent=None):
    value = _target_core(namespace, mode_targets, carry_progress, parent, datetime.now(timezone.utc).isoformat())
    value.update(sources=_sources(), published_at=datetime.now(timezone.utc).isoformat())
    return _write(output, TARGET_TYPE, value)


@_owned
def validate_target(ref, _seen=None):
    context = current_context(); key = ("per-mode-target", fixed._digest(ref))
    if context.has(key): return context.get(key)
    seen = set() if _seen is None else set(_seen)
    if ref["path"] in seen: raise ValueError("epoch target ancestry is cyclic")
    seen.add(ref["path"]); value = fixed._document(ref, TARGET_TYPE)
    fixed._keys(value, {"contract", "identity", "target_id", "mode_targets", "carry_progress", "classes", "parent",
        "transition", "role_revision", "epoch_declared_at", "declared_at", "published_at", "sources", "scientific_credit"},
        "finite per-mode epoch target")
    _source_check(value["sources"])
    if value["parent"] is not None: validate_target(value["parent"], seen)
    expected = _target_core(value["identity"]["namespace"], value["mode_targets"], value["carry_progress"],
                            value["parent"], value["declared_at"])
    if (any(not fixed._typed_equal(value[k], actual) for k, actual in expected.items())
            or type(value["role_revision"]) is not int
            or not fixed._time(value["declared_at"]) <= fixed._time(value["published_at"]) <= datetime.now(timezone.utc)):
        raise ValueError("epoch target changed its original identity, revision or prospective times")
    if value["parent"] is not None and fixed._time(validate_target(value["parent"])["published_at"]) > fixed._time(value["declared_at"]):
        raise ValueError("epoch revision predates its preceding declaration")
    context.remember(key, value)
    return value


def _progress_target(ref, declared):
    """Use the declared original v1 target or its genuine class extension."""
    anchor = fixed.validate_target(declared); seen = set()
    selected = fixed.validate_target(ref)
    while True:
        if ref["path"] in seen: raise ValueError("original progress target lineage is cyclic")
        seen.add(ref["path"]); target = fixed.validate_target(ref)
        if target["target_id"] != anchor["target_id"] or not fixed._typed_equal(_conditions(target), _conditions(anchor)):
            raise ValueError("original progress has an unrelated declared target identity")
        if ref == declared: return selected
        if target["parent"] is None:
            raise ValueError("original progress target must descend from its declared epoch target")
        ref = target["parent"]


def _rows(declaration, mode_progress):
    _lists(mode_progress, "five original mode progress lists")
    selected = []; logical = set(); physical = set()
    for mode in MODES:
        epochs = declaration["identity"]["epochs"][mode]
        if len(mode_progress[mode]) != len(epochs):
            raise ValueError("progress omitted or added an undeclared Native epoch")
        for ref, epoch, stamp, record in zip(mode_progress[mode], epochs, declaration["epoch_declared_at"][mode],
                                             declaration["mode_targets"][mode]):
            value = fixed.validate_progress(ref); target = _progress_target(value["target"], record["target"])
            if (_pair(target["target_identity"]) != _pair(epoch)
                    or target["conditions"][mode]["identity_sha256"] != epoch["condition_sha256"]
                    or value["classes"] != declaration["classes"][:len(value["classes"])]):
                raise ValueError("original progress differs from its selected epoch or full class map")
            for row in value["accepted_rows"]:
                if row["mode"] != mode: continue
                if (row["client_sha256"] != epoch["client_sha256"]
                        or any(row["measurement_source"][k] != epoch["native_head"]
                               for k in ("neqo_commit", "neqo_pinned_commit"))
                        or row["condition_sha256"] != epoch["condition_sha256"]):
                    raise ValueError("original row changed measured Native/client or fixed condition")
                if stamp is not None and fixed._time(row["intent_started_at"]) < fixed._time(stamp):
                    raise ValueError("repaired epoch cannot retrocredit an earlier intent")
                slot = _key(row); sample = row["result_root"], row["sample_id"]
                if slot in logical or sample in physical:
                    raise ValueError("epochs duplicate a logical slot or original physical sample")
                logical.add(slot); physical.add(sample); selected.append(row)
    return selected


def _progress_core(target_ref, mode_progress, parent, previous_progress=None, seen=None):
    declaration = validate_target(target_ref)
    selected = _append_rows(_carry_rows(declaration["carry_progress"], declaration["identity"]["epochs"],
                                       declaration["classes"]), _rows(declaration, mode_progress))
    history = [declaration["carry_progress"]]
    if parent is not None and previous_progress is not None:
        raise ValueError("epoch addition cannot also claim a same-target append")
    prior = previous_progress if previous_progress is not None else parent
    if prior is not None:
        before = validate_progress(prior, seen)
        if previous_progress is not None:
            if declaration["parent"] != before["target"]:
                raise ValueError("target revision must retain its immediate preceding target/progress")
        elif declaration["target_id"] != before["target_id"]:
            raise ValueError("append cannot silently change its epoch target")
        selected = _append_rows(before["accepted_rows"], selected)
        history = [prior, *before["retained_history"]]
        if declaration["carry_progress"] not in history: history.append(declaration["carry_progress"])
    if declaration["parent"] is not None and prior is None:
        raise ValueError("revised target must preserve every preceding original accepted slot")
    return {"contract": CONTRACT, "target": target_ref, "target_id": declaration["target_id"],
            "parent": parent, "previous_progress": previous_progress, "mode_progress": mode_progress,
            "classes": declaration["classes"], "accepted_rows": selected,
            "remaining_vectors": fixed._vectors(declaration["classes"], selected),
            "target_accepted_count": len(selected), "final_target": TOTAL,
            "aggregate_status": fixed._aggregate(declaration["classes"], selected),
            "retained_history": history, "history_counts_as_target_credit": False}


@_owned
def initialize_progress(*, target, mode_progress, output, previous_progress=None):
    value = _progress_core(target, mode_progress, None, previous_progress)
    value.update(sources=_sources(), published_at=datetime.now(timezone.utc).isoformat())
    return _write(output, PROGRESS_TYPE, value)


@_owned
def append_progress(*, progress, mode_progress, output, target=None):
    old = validate_progress(progress)
    value = _progress_core(old["target"] if target is None else target, mode_progress, progress)
    value.update(sources=_sources(), published_at=datetime.now(timezone.utc).isoformat())
    return _write(output, PROGRESS_TYPE, value)


@_owned
def validate_progress(ref, _seen=None):
    context = current_context(); key = ("per-mode-progress", fixed._digest(ref))
    if context.has(key): return context.get(key)
    seen = set() if _seen is None else set(_seen)
    if ref["path"] in seen: raise ValueError("epoch progress ancestry is cyclic")
    seen.add(ref["path"]); value = fixed._document(ref, PROGRESS_TYPE)
    fixed._keys(value, {"contract", "target", "target_id", "parent", "previous_progress", "mode_progress",
        "classes", "accepted_rows", "remaining_vectors", "target_accepted_count", "final_target", "aggregate_status",
        "retained_history", "history_counts_as_target_credit", "sources", "published_at"}, "per-mode epoch progress")
    _source_check(value["sources"])
    expected = _progress_core(value["target"], value["mode_progress"], value["parent"], value["previous_progress"], seen)
    declaration = validate_target(value["target"])
    if (any(not fixed._typed_equal(value[k], actual) for k, actual in expected.items())
            or not fixed._time(declaration["published_at"]) <= fixed._time(value["published_at"]) <= datetime.now(timezone.utc)):
        raise ValueError("epoch progress differs from original proved slots or chronology")
    prior = value["previous_progress"] if value["previous_progress"] is not None else value["parent"]
    if prior is not None and fixed._time(validate_progress(prior)["published_at"]) > fixed._time(value["published_at"]):
        raise ValueError("epoch progress predates its preceding progress")
    for refs in value["mode_progress"].values():
        if any(fixed._time(fixed.validate_progress(r)["published_at"]) > fixed._time(value["published_at"]) for r in refs):
            raise ValueError("epoch progress predates an original proof")
    context.remember(key, value)
    return value


@_owned
def accepted_slots(progress):
    return validate_progress(progress)["accepted_rows"]


@_owned
def chunk_inputs(progress, classes, mode, *, epoch_index, maximum=16):
    value = validate_progress(progress); declaration = validate_target(value["target"])
    if (mode not in MODES or not isinstance(classes, list) or not classes
            or any(type(c) is not int for c in classes) or len(set(classes)) != len(classes)
            or type(epoch_index) is not int or not 0 <= epoch_index < len(declaration["identity"]["epochs"][mode])
            or type(maximum) is not int or not 1 <= maximum <= 16):
        raise ValueError("epoch planning requires ordered classes, a declared epoch and maximum1..16")
    selected = [row for row in value["classes"] if row["class_index"] in classes]
    if [r["class_index"] for r in selected] != classes:
        raise ValueError("epoch planning changed original class ordering")
    vectors = [row["remaining_slots"] for row in value["remaining_vectors"] if row["class_index"] in classes and row["mode"] == mode]
    if any(v != vectors[0] for v in vectors) or any(row["capture_limits"] != selected[0]["capture_limits"] for row in selected):
        raise ValueError("one epoch flight requires homogeneous caps and remaining vectors")
    record = declaration["mode_targets"][mode][epoch_index]
    original = fixed.validate_target(record["target"]); condition = original["conditions"][mode]
    return {"target": value["target"], "progress": progress, "target_id": value["target_id"],
            "epoch_index": epoch_index, "epoch": declaration["identity"]["epochs"][mode][epoch_index],
            "epoch_declared_at": declaration["epoch_declared_at"][mode][epoch_index],
            "source_binding": record["source_binding"], "condition": condition, "classes": selected,
            "capture_limits": fixed._capture_limits(mode, selected[0]["capture_limits"], condition["identity"]),
            "remaining_slots": vectors[0], "ranges": [{"slot_start": s, "slot_count": n}
                for s, n in fixed.chunks.ranges(set(range(SLOTS)) - set(vectors[0]), maximum=maximum)],
            "old_capsule_or_chunk_authority_inferred": False}


@_owned
def publish_chunk_inputs(progress, classes, mode, *, epoch_index, maximum=16, output):
    value = chunk_inputs(progress, classes, mode, epoch_index=epoch_index, maximum=maximum)
    return _write(output, CHUNK_INPUT_TYPE, {"mode": mode, "maximum": maximum, "inputs": value,
        "planning_only": True, "scientific_credit": False, "sources": _sources()})


@_owned
def read_chunk_inputs(ref):
    value = fixed._document(ref, CHUNK_INPUT_TYPE)
    fixed._keys(value, {"mode", "maximum", "inputs", "planning_only", "scientific_credit", "sources"}, "epoch planning input")
    _source_check(value["sources"])
    expected = chunk_inputs(value["inputs"]["progress"], [r["class_index"] for r in value["inputs"]["classes"]],
        value["mode"], epoch_index=value["inputs"]["epoch_index"], maximum=value["maximum"])
    if not fixed._typed_equal(value["inputs"], expected) or value["planning_only"] is not True or value["scientific_credit"] is not False:
        raise ValueError("epoch planning changed its combined remaining-slot authority")
    return value


@_owned
def final_coverage(progress):
    value = validate_progress(progress)
    if len(value["classes"]) != CLASSES or value["target_accepted_count"] != TOTAL or any(r["remaining_slots"] for r in value["remaining_vectors"]):
        raise ValueError("epoch final requires exactly50 distinct sites ×5 modes ×64 original slots")
    declaration = validate_target(value["target"])
    return {"target": value["target"], "progress": progress, "target_id": value["target_id"],
            "epochs": declaration["identity"]["epochs"], "accepted": TOTAL, "classes": CLASSES,
            "conditions": len(MODES), "slots_per_class_condition": SLOTS,
            "original_source_labels_retained": True, "history_counts_as_target_credit": False}


@_owned
def input_files(progress):
    value = validate_progress(progress); files = {}
    def add(ref):
        fixed._open(ref)
        old = files.get(ref["path"])
        if old is not None and old != ref: raise ValueError("epoch input aliases disagree")
        files[ref["path"]] = ref
    add(progress)
    for refs in value["mode_progress"].values():
        for ref in refs:
            for observed in fixed.input_files(ref): add(observed)
    for ref in (value["parent"], value["previous_progress"]):
        if ref is not None:
            for observed in input_files(ref): add(observed)
    def original_inputs(ref):
        add(ref); original = fixed.validate_target(ref)
        for observed in [original["enrollment"], *original["sources"].values(), *original["membership_dependencies"]["files"],
                         *original["retained_history"]]: add(observed)
        for tree in original["membership_dependencies"]["trees"]:
            for name, member in tree["members"].items():
                if member["kind"] == "file":
                    add({"path": str(Path(tree["path"]) / name), "sha256": member["sha256"], "mode": member["mode"]})
        for row in original["classes"]: add(row["original_manifest"])
        for condition in original["conditions"].values():
            add(condition["reference"]); descriptor = fixed._document(condition["reference"], fixed.CONDITION_TYPE)
            add(descriptor["configuration"]); add(descriptor["run"])
        if original["parent"] is not None: original_inputs(original["parent"])
    def binding_inputs(value):
        if isinstance(value, dict):
            if set(value) == {"path", "sha256", "mode"}: add(value)
            else:
                for item in value.values(): binding_inputs(item)
        elif isinstance(value, list):
            for item in value: binding_inputs(item)
    def target_inputs(ref):
        add(ref); declaration = validate_target(ref)
        for observed in [declaration["sources"]["reducer"], *declaration["sources"]["fixed"].values()]: add(observed)
        for observed in fixed.input_files(declaration["carry_progress"]): add(observed)
        for records in declaration["mode_targets"].values():
            for record in records:
                original_inputs(record["target"])
                original = fixed.validate_target(record["target"])
                if record["source_binding"] is not None:
                    add(record["source_binding"]); source = _binding(record["source_binding"], _pair(original["target_identity"]))
                    for observed in [*source["files"].values(), *source["binding"]["read_dependencies"]]: add(observed)
                    binding_inputs(source["binding"])
        if declaration["parent"] is not None: target_inputs(declaration["parent"])
    target_inputs(value["target"])
    return [files[k] for k in sorted(files)]


@_owned
def directory_dependencies(progress):
    value = validate_progress(progress); directories = {}
    def add(row):
        key = row["path"], row["kind"]; old = directories.get(key)
        if old is not None and old != row: raise ValueError("epoch raw directory observations disagree")
        directories[key] = row
    for refs in value["mode_progress"].values():
        for ref in refs:
            for row in fixed.directory_dependencies(ref): add(row)
    for ref in (value["parent"], value["previous_progress"]):
        if ref is not None:
            for row in directory_dependencies(ref): add(row)
    def target_dirs(ref):
        declaration = validate_target(ref)
        for records in declaration["mode_targets"].values():
            for record in records:
                original = fixed.validate_target(record["target"])
                for tree in original["membership_dependencies"]["trees"]:
                    add({"path": tree["path"], "kind": "complete-membership-tree",
                         "ignore_git": tree["ignore_git"], "members": tree["members"]})
                if record["source_binding"] is not None:
                    for row in _binding(record["source_binding"], _pair(original["target_identity"]))["binding"]["directory_dependencies"]:
                        add({"kind": "shallow-directory", **row})
        if declaration["parent"] is not None: target_dirs(declaration["parent"])
    target_dirs(value["target"])
    return [directories[k] for k in sorted(directories)]


@_owned
def publish_final(progress, output):
    facts = final_coverage(progress); value = validate_progress(progress)
    files = input_files(progress); directories = directory_dependencies(progress)
    fixed._check_action()
    return _write(output, CORPUS_TYPE, {"contract": CONTRACT, **facts, "accepted_rows": value["accepted_rows"],
        "retained_history": value["retained_history"], "read_dependencies": files, "directory_dependencies": directories,
        "sources": _sources(), "published_at": datetime.now(timezone.utc).isoformat(), "scientific_credit": True})
