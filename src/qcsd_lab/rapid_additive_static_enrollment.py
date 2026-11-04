"""Prospective selected admissions with explicit unassessed reservations.

Original acquisition cursors and GET producers retain their meaning. Creation
uses recorded original-authority audits; trace membership checks immutable
ledger metadata and the caller verifies only its selected complete raw GET.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import rapid_rolling_capture as rolling
from . import rapid_site_admission as receipts
from . import rapid_lane_evidence as lanes
from . import supplied_static_graph as graph
from . import whole_graph_supplement as whole

POLICY_TYPE = "qcsd-prospective-additive-static-enrollment-policy-v1"
ENROLLMENT_TYPE = "qcsd-prospective-additive-static-enrollment-batch-v1"
CONTRACT = "carried-static-classes-plus-selected-complete-get-admissions-with-unassessed-gaps-v1"
SITE_RULE = "idna-lowercase-host-remove-one-leading-www-v1"
SELECTION_RULE = "available-verified-admissions-in-declared-reservation-order-within-each-batch-v1"
POLICY_FIELDS = {"contract", "seed_policy", "seed_enrollment", "seed_classes",
    "seed_batch_ordinal", "seed_last_original_position", "initial_admission_root",
    "admission_identity", "reservation_provenance", "first_reservation_position",
    "runtime", "runtime_source_manifest", "client_binary", "base_launcher", "host_launcher",
    "implementation_sources", "published_at", "canonical_site_rule", "selection_rule",
    "capture_limits", "class_target", "modes", "visits_per_class_mode", "formal_trace_target",
    "maximum_batch_size", "visits_per_lane_workload", "global_shakedown_required",
    "complete_membership_before_first_lane_required", "formal_accepted_trace_count",
    "scientific_credit", "seed_selection_audit", "seed_inputs", "reservation_candidates",
    "seed_progress", "data_role"}
BATCH_FIELDS = {"policy", "ordinal", "parent", "seed", "decisions", "selected_candidate_ids",
    "first_class_index", "last_candidate_position", "declared_at", "scientific_credit",
    "admission_root", "admission_provenance", "unassessed_reservations", "selection_rule"}


def policy_kind(root: Path) -> bool:
    return lanes._load(lanes._read(root / "policy.json")).get("receipt_type") == POLICY_TYPE


def enrollment_kind(path: Path) -> bool:
    return lanes._load(lanes._read(path)).get("receipt_type") == ENROLLMENT_TYPE


def _sources() -> dict[str, str]:
    return {__name__: lanes._sha(lanes._read(Path(__file__)))}


def _canonical_host(value: str) -> str:
    if not isinstance(value, str) or not value or any(c in value for c in "/\\:@\r\n\x00"):
        raise ValueError("additive class needs a plain canonical primary hostname")
    host = value.rstrip(".").encode("idna").decode("ascii").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host or host.startswith(".") or ".." in host:
        raise ValueError("additive canonical primary hostname is invalid")
    return host


def _aliases(candidate: Mapping[str, Any], manifest: Mapping[str, Any]) -> list[str]:
    host = urlsplit(manifest["preparation"]["final_url"]).hostname
    if host is None:
        raise ValueError("additive class lost its authenticated final primary host")
    return sorted({_canonical_host(candidate["domain"]), _canonical_host(host)})


def _deduplicate(classes: list[dict]) -> None:
    if not 1 <= len(classes) <= 50 or len({item["candidate_id"] for item in classes}) != len(classes):
        raise ValueError("additive enrollment exceeds fifty or repeats a candidate")
    if len({item["workload_id"] for item in classes}) != len(classes):
        raise ValueError("additive enrollment repeats a workload identity")
    aliases: set[str] = set()
    for index, row in enumerate(classes, 1):
        if type(row.get("class_index")) is not int or row["class_index"] != index:
            raise ValueError("additive class numbering changes retained or new membership")
        values = row.get("canonical_sites")
        if (not isinstance(values, list) or not values or values != sorted(set(values))
                or any(_canonical_host(value) != value for value in values) or aliases.intersection(values)):
            raise ValueError("additive enrollment repeats a canonical primary site")
        aliases.update(values)


def input_metadata(reference: Any) -> tuple[dict, dict]:
    """Check recorded admission metadata; own raw GET is checked by the caller."""
    from . import rapid_selected_capture_input as selected
    value = receipts._unpack(lanes._read(selected.reopen(reference)), selected.RECEIPT_TYPE)
    get_audit = selected.read_audit(selected.reopen(value["selection_audit"]))
    rows = [row for row in get_audit["result"]["classes"]
            if row["candidate"]["candidate_id"] == value["candidate_id"]]
    if (value["contract"] != selected.CONTRACT or value["scientific_credit"] is not False
            or type(value["formal_accepted_trace_count"]) is not int or value["formal_accepted_trace_count"] != 0
            or len(rows) != 1 or rows[0]["facts"]["outcome"] != "admitted"
            or rows[0]["manifest"] != {key: value["original_manifest"][key] for key in ("path", "sha256")}
            or value["workload_id"] != Path(value["original_manifest"]["path"]).stem
            or value["capture_limits"] != rows[0]["capture_limits"]
            or not receipts._utc(get_audit["published_at"]) <= receipts._utc(value["declared_at"])):
        raise ValueError("additive input metadata lost its actual admitted graph or audit")
    return value, rows[0]


def _progress(value: Any, classes: list[dict]) -> None:
    """Link retained sample identities; this policy grants no new trace credit."""
    known = {row["candidate_id"]: row["class_index"] for row in classes}
    slots = value.get("accepted_formal_slots") if isinstance(value, dict) else None
    if (not isinstance(slots, list) or not slots
            or value.get("actual_installed_deep_reopened") is not True
            or value.get("measurement_epochs_preserve_original_source_and_runtime_labels") is not True
            or type(value.get("formal_accepted_trace_count")) is not int
            or value["formal_accepted_trace_count"] != len(slots)):
        raise ValueError("selected seed progress lost its retained actual sample-identity anchor")
    identities = []
    for slot in slots:
        basic = {"candidate_id", "class_index", "mode", "visit"}
        block_fields = {"actual_local_visit", "registered_block", "campaign_name"}
        if set(slot) not in (basic, basic | block_fields):
            raise ValueError("retained seed sample has an unknown logical-slot identity")
        if (slot["candidate_id"] not in known or type(slot["class_index"]) is not int
                or slot["class_index"] != known[slot["candidate_id"]]
                or slot["mode"] not in rolling.plan.MODES
                or type(slot["visit"]) is not int or not 0 <= slot["visit"] < 64):
            raise ValueError("selected seed progress renumbers or relabels an original sample")
        if block_fields <= set(slot):
            if (type(slot["registered_block"]) is not int or not 1 <= slot["registered_block"] <= 16
                    or type(slot["actual_local_visit"]) is not int or not 0 <= slot["actual_local_visit"] < 4
                    or slot["visit"] != (slot["registered_block"] - 1) * 4 + slot["actual_local_visit"]
                    or not isinstance(slot["campaign_name"], str)
                    or re.fullmatch(r"rapid-curated-tranco50-v6-formal-b" + f'{slot["registered_block"]:02d}'
                        + r"-s[0-9]{2}-" + re.escape(slot["mode"]) + r"-1200(?:-g[0-9]{2})?", slot["campaign_name"]) is None):
                raise ValueError("retained sample confuses raw local visit with its registered logical block")
        identities.append((slot["class_index"], slot["mode"], slot["visit"]))
    if len(identities) != len(set(identities)):
        raise ValueError("selected seed progress repeats an original sample")


def _context_metadata(policy: Mapping[str, Any], path: Path, *, _files: set[Path] | None = None) -> dict:
    """Read declared reservation ancestry, excluding terminal/raw GET history."""
    from . import supplied_static_admission as static
    initial_path = rolling._open_ref(policy["reservation_provenance"])
    initial = receipts._unpack(lanes._read(initial_path), static.PROVENANCE_TYPE)
    kind = lanes._load(lanes._read(path)).get("receipt_type")
    if kind not in {static.PROVENANCE_TYPE, whole.CONTEXT_TYPE}:
        raise ValueError("selected reservation has an unknown original declaration role")
    value = receipts._unpack(lanes._read(path), kind)
    if _files is not None:
        _files.update({initial_path, path.absolute()})
    if (value["candidates"][:len(initial["candidates"])] != initial["candidates"]
            or kind == whole.CONTEXT_TYPE and value["capture_limits"] != policy["capture_limits"]):
        raise ValueError("selected reservations replace the original order or fixed caps")
    if kind == whole.CONTEXT_TYPE:
        original_path = rolling._open_ref(value["original_context"])
        if original_path != initial_path:
            raise ValueError("whole selected reservation has another original declared queue")
        if _files is not None:
            _files.add(original_path)
        current, seen = value, set()
        while current["parent_context"] is not None:
            parent_path = rolling._open_ref(current["parent_context"])
            if parent_path in seen:
                raise ValueError("whole selected declaration ancestry contains a cycle")
            seen.add(parent_path)
            parent = receipts._unpack(lanes._read(parent_path), whole.CONTEXT_TYPE)
            if (current["candidates"][:len(parent["candidates"])] != parent["candidates"]
                    or parent["original_context"] != value["original_context"]):
                raise ValueError("whole selected reservation reorders an earlier declaration")
            if _files is not None:
                _files.add(parent_path)
            current = parent
    elif path.absolute() != initial_path:
        current, current_path, seen = value, path.absolute(), set()
        while current_path != initial_path:
            if current_path in seen or current["parent_context"] is None:
                raise ValueError("original selected declaration has no authenticated parent ancestry")
            seen.add(current_path)
            parent_path = rolling._open_ref(current["parent_context"])
            parent = receipts._unpack(lanes._read(parent_path), static.PROVENANCE_TYPE)
            if current["candidates"][:len(parent["candidates"])] != parent["candidates"]:
                raise ValueError("original selected declaration reorders an earlier reservation")
            if _files is not None:
                _files.add(parent_path)
            current, current_path = parent, parent_path
    return value


def initialize(root: Path, *, seed_enrollment: Path, runtime: Mapping[str, str],
               seed_selection_audit: Path, seed_inputs: Mapping[str, Mapping[str, Any]],
               seed_progress: Mapping[str, Any]) -> Path:
    from . import rapid_selected_capture_input as selected
    root = lanes._regular_directory(root)
    if any(root.iterdir()):
        raise ValueError("additive policy needs a fresh empty namespace")
    audit = selected.read_audit(seed_selection_audit)
    seed = audit["result"]["seed"]
    if seed is None or seed["enrollment"] != rolling._ref(seed_enrollment):
        raise ValueError("additive policy needs its actual original enrollment audit")
    old = receipts._unpack(lanes._read(rolling._open_ref(seed["policy"])), rolling.STATIC_POLICY_TYPE)
    classes = []
    if set(seed_inputs) != {row["candidate_id"] for row in seed["classes"]}:
        raise ValueError("additive policy needs one direct input per retained class")
    for row in seed["classes"]:
        input_path = selected.reopen(seed_inputs[row["candidate_id"]])
        value, manifest, _ = selected.validate_input(input_path)
        if (value["candidate_id"] != row["candidate_id"] or value["workload_id"] != row["workload_id"]
                or value["selection_audit"] != selected.reference(seed_selection_audit)):
            raise ValueError("additive seed replaces its original class mapping")
        classes.append({**row, "canonical_sites": value["canonical_sites"]})
    _deduplicate(classes)
    if len(classes) >= 50:
        raise ValueError("additive policy must extend an incomplete authentic seed")
    from . import supplied_static_admission as static
    context_ref = audit["result"]["classes"][-1]["context"]
    context_path = rolling._open_ref(context_ref)
    context = receipts._unpack(lanes._read(context_path), static.PROVENANCE_TYPE)
    if context_path.parent != Path(seed["classes"][-1]["admission_root"]):
        raise ValueError("selected initial reservation is not the genuinely audited seed context")
    progress = lanes._load(lanes._read(selected.reopen(seed_progress)))
    _progress(progress, classes)
    actual_runtime = rolling._runtime(dict(runtime))
    if not root.is_relative_to(Path(actual_runtime["data_root"])):
        raise ValueError("additive policy leaves its bound runtime data scope")
    payload = {"contract": CONTRACT, "data_role": selected.ROLE, "seed_policy": seed["policy"],
        "seed_enrollment": rolling._ref(seed_enrollment), "seed_classes": classes,
        "seed_selection_audit": selected.reference(seed_selection_audit),
        "seed_inputs": {key: dict(value) for key, value in seed_inputs.items()},
        "seed_progress": dict(seed_progress),
        "seed_batch_ordinal": seed["ordinal"], "seed_last_original_position": seed["last_candidate_position"],
        "initial_admission_root": str(context_path.parent), "admission_identity": old["admission_identity"],
        "reservation_provenance": dict(context_ref), "first_reservation_position": 1,
        "reservation_candidates": context["candidates"], "runtime": actual_runtime,
        "implementation_sources": _sources(), "published_at": receipts._now(),
        "canonical_site_rule": SITE_RULE, "selection_rule": SELECTION_RULE, "capture_limits": old["capture_limits"],
        "class_target": 50, "modes": list(rolling.plan.MODES), "visits_per_class_mode": 64,
        "formal_trace_target": 16000, "maximum_batch_size": 5, "visits_per_lane_workload": 4,
        "global_shakedown_required": False, "complete_membership_before_first_lane_required": False,
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    for key in ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"):
        payload[key] = rolling._ref(Path(actual_runtime["source_manifest" if key == "runtime_source_manifest" else key]))
    return rolling._write(root / "policy.json", POLICY_TYPE, payload)


def verify_policy(root: Path) -> dict:
    from . import rapid_selected_capture_input as selected
    root = lanes._regular_directory(root)
    value = receipts._unpack(lanes._read(root / "policy.json"), POLICY_TYPE)
    rolling._keys(value, POLICY_FIELDS, "additive policy")
    exact = {"contract": CONTRACT, "data_role": selected.ROLE, "canonical_site_rule": SITE_RULE, "selection_rule": SELECTION_RULE,
        "class_target": 50, "modes": list(rolling.plan.MODES), "visits_per_class_mode": 64,
        "formal_trace_target": 16000, "maximum_batch_size": 5, "visits_per_lane_workload": 4,
        "global_shakedown_required": False, "complete_membership_before_first_lane_required": False,
        "formal_accepted_trace_count": 0, "scientific_credit": False, "implementation_sources": _sources()}
    if any(type(value[key]) is not type(expected) or value[key] != expected for key, expected in exact.items()):
        raise ValueError("additive policy changes its explicit prospective contract")
    audit = selected.read_audit(selected.reopen(value["seed_selection_audit"]))
    seed = audit["result"]["seed"]
    if (seed is None or value["seed_policy"] != seed["policy"] or value["seed_enrollment"] != seed["enrollment"]
            or type(value["seed_batch_ordinal"]) is not int or value["seed_batch_ordinal"] != seed["ordinal"]
            or type(value["seed_last_original_position"]) is not int
            or value["seed_last_original_position"] != seed["last_candidate_position"]
            or len(value["seed_classes"]) != len(seed["classes"])):
        raise ValueError("additive policy replaces its genuine retained membership")
    old = receipts._unpack(lanes._read(rolling._open_ref(value["seed_policy"])), rolling.STATIC_POLICY_TYPE)
    rolling._open_ref(value["seed_enrollment"])
    _deduplicate(value["seed_classes"])
    if value["admission_identity"] != old["admission_identity"]:
        raise ValueError("additive policy relabels its original catalogue authority")
    if set(value["seed_inputs"]) != {row["candidate_id"] for row in value["seed_classes"]}:
        raise ValueError("additive policy loses a retained class input")
    for original_row, row in zip(seed["classes"], value["seed_classes"], strict=True):
        data, _ = input_metadata(value["seed_inputs"][row["candidate_id"]])
        if ({key: row[key] for key in original_row} != original_row
                or data["candidate_id"] != row["candidate_id"] or data["workload_id"] != row["workload_id"]
                or data["canonical_sites"] != row["canonical_sites"]
                or data["selection_audit"] != value["seed_selection_audit"]):
            raise ValueError("additive policy renumbers or replaces a retained class")
    context_path = rolling._open_ref(value["reservation_provenance"])
    context = _context_metadata(value, context_path)
    first = value["first_reservation_position"]
    if (type(first) is not int or first != 1 or value["reservation_candidates"] != context["candidates"]
            or context_path.parent != Path(value["initial_admission_root"])
            or value["capture_limits"] != old["capture_limits"]):
        raise ValueError("selected policy replaces its genuine original reservations or caps")
    _progress(lanes._load(lanes._read(selected.reopen(value["seed_progress"]))), value["seed_classes"])
    runtime = rolling._runtime(value["runtime"])
    if not root.is_relative_to(Path(runtime["data_root"])):
        raise ValueError("additive policy leaves its declared data scope")
    for key in ("runtime_source_manifest", "client_binary", "base_launcher", "host_launcher"):
        if rolling._open_ref(value[key]) != Path(runtime["source_manifest" if key == "runtime_source_manifest" else key]):
            raise ValueError("additive policy changes a bound runtime artifact")
    earliest = max(receipts._utc(audit["published_at"]), receipts._utc(context["declared_at"]))
    if not earliest <= receipts._utc(value["published_at"]) <= receipts._utc(receipts._now()):
        raise ValueError("additive policy precedes its authentic seed or supplement")
    return value


def _batch_path(root: Path, ordinal: int) -> Path:
    return rolling._batch_path(root, ordinal)


def _batches(root: Path, policy: Mapping[str, Any]) -> list[Path]:
    directory = root / "batches"
    if not directory.exists():
        return []
    lanes._regular_directory(directory)
    children = sorted(directory.iterdir())
    first = policy["seed_batch_ordinal"] + 1
    paths = [_batch_path(root, first + offset) for offset in range(len(children))]
    if [path.parent for path in paths] != children or any(not path.is_file() or path.is_symlink() for path in paths):
        raise ValueError("additive batches contain a hole or an unfinished claim")
    return paths


def _chosen(policy: dict, provenance: Any, input_ref: Any, manifest_ref: Any) -> tuple[dict, dict]:
    from . import rapid_selected_capture_input as selected
    context_path = rolling._open_ref(provenance)
    context = _context_metadata(policy, context_path)
    value, audited = input_metadata(input_ref)
    candidate = next((row for row in context["candidates"][policy["first_reservation_position"] - 1:]
                      if row["candidate_id"] == value["candidate_id"]), None)
    if (candidate is None or audited["candidate"] != candidate or audited["context"] != provenance
            or value["original_role"] not in (selected.original.ROLE, whole.ROLE) or value["capture_limits"] != policy["capture_limits"]):
        raise ValueError("additive selection is not an actually admitted reserved complete graph")
    manifest_path = selected.reopen(manifest_ref)
    manifest = lanes._load(lanes._read(manifest_path))
    expected = lanes._load(lanes._read(selected.reopen(value["original_manifest"])))
    expected["preparation"] = {**expected["preparation"], "data_role": selected.ROLE,
        "selected_input_evidence": {"schema_version": 1, "record_type": selected.RECEIPT_TYPE, "receipt": dict(input_ref)}}
    if manifest != expected or manifest_path.stem != value["workload_id"]:
        raise ValueError("additive capture manifest prunes or relabels the selected full graph")
    terminal = audited["terminal"]
    rolling._open_ref(terminal)
    chosen = {"candidate_id": value["candidate_id"], "terminal": terminal,
        "admission_root": str(context_path.parent), "class_index": 0,
        "primary_origin": rolling.origin(manifest["preparation"]["final_url"]), "workload_id": value["workload_id"],
        "canonical_sites": value["canonical_sites"], "capture_input": dict(input_ref), "prepared_workload": dict(manifest_ref)}
    decision = {"position": candidate["position"], "candidate_id": value["candidate_id"], "outcome": "admitted",
        "terminal": terminal, "capture_input": dict(input_ref), "prepared_workload": dict(manifest_ref)}
    return decision, chosen


def verify_enrollment(path: Path) -> tuple[dict, list[dict], dict]:
    value = receipts._unpack(lanes._read(path), ENROLLMENT_TYPE)
    rolling._keys(value, BATCH_FIELDS, "additive enrollment")
    root = rolling._open_ref(value["policy"]).parent
    policy = verify_policy(root)
    ordinal = value["ordinal"]
    if (type(ordinal) is not int or path.absolute() != _batch_path(root, ordinal)
            or value["scientific_credit"] is not False or value["selection_rule"] != SELECTION_RULE):
        raise ValueError("additive enrollment namespace, rule or credit changed")
    if ordinal == policy["seed_batch_ordinal"] + 1:
        if value["parent"] is not None or value["seed"] != policy["seed_enrollment"]:
            raise ValueError("first additive batch lost its exact cross-policy seed")
        previous, earliest = list(policy["seed_classes"]), policy["published_at"]
    else:
        if value["seed"] is not None or rolling._open_ref(value["parent"]) != _batch_path(root, ordinal - 1):
            raise ValueError("additive enrollment skips its immediate append-only predecessor")
        parent, previous, _ = verify_enrollment(rolling._open_ref(value["parent"]))
        earliest = parent["declared_at"]
    if (type(value["first_class_index"]) is not int or value["first_class_index"] != len(previous) + 1
            or not receipts._utc(earliest) <= receipts._utc(value["declared_at"]) <= receipts._utc(receipts._now())
            or Path(value["admission_root"]) != rolling._open_ref(value["admission_provenance"]).parent
            or not isinstance(value["decisions"], list) or not 1 <= len(value["decisions"]) <= 5):
        raise ValueError("additive membership numbering, declaration or selected count changed")
    selected, positions = [], []
    for row in value["decisions"]:
        rolling._keys(row, {"position", "candidate_id", "outcome", "terminal", "capture_input", "prepared_workload"}, "additive selected decision")
        expected, chosen = _chosen(policy, value["admission_provenance"], row["capture_input"], row["prepared_workload"])
        data, _ = input_metadata(row["capture_input"])
        if row != expected or receipts._utc(data["declared_at"]) > receipts._utc(value["declared_at"]):
            raise ValueError("additive selected decision changed its genuine admission or chronology")
        chosen["class_index"] = len(previous) + len(selected) + 1
        selected.append(chosen)
        positions.append(row["position"])
    if (positions != sorted(set(positions)) or value["selected_candidate_ids"] != [row["candidate_id"] for row in selected]
            or type(value["last_candidate_position"]) is not int or value["last_candidate_position"] != positions[-1]):
        raise ValueError("additive batch reorders available admissions or claims a contiguous acquisition cursor")
    context = _context_metadata(policy, rolling._open_ref(value["admission_provenance"]))
    classes = previous + selected
    _deduplicate(classes)
    enrolled = {row["candidate_id"] for row in classes}
    pending = [{"position": row["position"], "candidate_id": row["candidate_id"], "assessment": "unassessed-by-this-ledger"}
               for row in context["candidates"][policy["first_reservation_position"] - 1:] if row["candidate_id"] not in enrolled]
    if value["unassessed_reservations"] != pending:
        raise ValueError("additive enrollment fabricates a decision for an unassessed reservation")
    return value, classes, policy


def enroll(root: Path, *, acquisition_root: Path | None = None,
           inputs: Mapping[str, Mapping[str, Any]], prepared_workloads: Mapping[str, Mapping[str, Any]]) -> Path:
    from . import rapid_selected_capture_input as selected
    policy = verify_policy(root)
    if not 1 <= len(inputs) <= 5 or set(inputs) != set(prepared_workloads):
        raise ValueError("additive batch needs one to five complete selected inputs and manifests")
    batches = _batches(root, policy)
    ordinal, previous = policy["seed_batch_ordinal"] + 1, list(policy["seed_classes"])
    parent, seed, earliest = None, policy["seed_enrollment"], policy["published_at"]
    if batches:
        old, previous, _ = verify_enrollment(batches[-1])
        ordinal, parent, seed, earliest = old["ordinal"] + 1, rolling._ref(batches[-1]), None, old["declared_at"]
    context_path = (acquisition_root or Path(policy["initial_admission_root"])) / "provenance.json"
    provenance = rolling._ref(context_path)
    context = _context_metadata(policy, context_path)
    decisions, chosen = [], []
    for candidate_id, input_ref in inputs.items():
        selected.validate_input(selected.reopen(input_ref))
        decision, row = _chosen(policy, provenance, input_ref, prepared_workloads[candidate_id])
        if row["candidate_id"] != candidate_id:
            raise ValueError("additive input map key changes its actual candidate identity")
        decisions.append(decision)
        chosen.append(row)
    decisions.sort(key=lambda row: row["position"])
    by_id = {row["candidate_id"]: row for row in chosen}
    chosen = [by_id[row["candidate_id"]] for row in decisions]
    for index, row in enumerate(chosen, len(previous) + 1):
        row["class_index"] = index
    classes = previous + chosen
    _deduplicate(classes)
    enrolled = {row["candidate_id"] for row in classes}
    pending = [{"position": row["position"], "candidate_id": row["candidate_id"], "assessment": "unassessed-by-this-ledger"}
               for row in context["candidates"][policy["first_reservation_position"] - 1:] if row["candidate_id"] not in enrolled]
    payload = {"policy": rolling._ref(root / "policy.json"), "ordinal": ordinal, "parent": parent,
        "seed": seed, "decisions": decisions, "selected_candidate_ids": [row["candidate_id"] for row in chosen],
        "first_class_index": len(previous) + 1, "last_candidate_position": decisions[-1]["position"],
        "admission_root": str(context_path.parent), "admission_provenance": provenance,
        "unassessed_reservations": pending, "selection_rule": SELECTION_RULE,
        "declared_at": receipts._now(), "scientific_credit": False}
    output = _batch_path(root, ordinal)
    rolling._write(output, ENROLLMENT_TYPE, payload)
    verify_enrollment(output)
    return output


def membership_inputs(path: Path) -> set[Path]:
    """Exact immutable ledger/audit metadata; no unrelated GET dependency tree."""
    from . import rapid_selected_capture_input as selected
    batch, classes, policy = verify_enrollment(path)
    files = {path.absolute(), rolling._open_ref(batch["policy"]), rolling._open_ref(policy["seed_policy"]),
             rolling._open_ref(policy["seed_enrollment"]), rolling._open_ref(policy["reservation_provenance"])}
    while batch["parent"] is not None:
        parent = rolling._open_ref(batch["parent"])
        files.add(parent)
        batch = receipts._unpack(lanes._read(parent), ENROLLMENT_TYPE)
    input_refs = [*policy["seed_inputs"].values(),
                  *(row["capture_input"] for row in classes if "capture_input" in row)]
    files.add(selected.reopen(policy["seed_progress"]))
    _context_metadata(policy, rolling._open_ref(policy["reservation_provenance"]), _files=files)
    for input_ref in input_refs:
        input_path = selected.reopen(input_ref)
        value, audited = input_metadata(input_ref)
        # Seed contexts were fully reopened by the separately retained seed
        # audit. They may precede the last seed's reservation declaration.
        # New admissions must descend from that declared reservation queue.
        if input_ref not in policy["seed_inputs"].values():
            _context_metadata(policy, rolling._open_ref(audited["context"]), _files=files)
        files.update({input_path, selected.reopen(value["original_manifest"]), rolling._open_ref(audited["terminal"]),
                      rolling._open_ref(audited["context"])})
        audit_path = selected.reopen(value["selection_audit"])
        files.update(selected.audit_inputs(audit_path))
    for row in classes:
        if "prepared_workload" in row:
            files.add(selected.reopen(row["prepared_workload"]))
    return files


def enrollment_roots(spec) -> list[Path]:
    """Transport selected raw GETs and immutable membership at their real names."""
    from . import rapid_selected_capture_input as selected
    batch, classes, policy = verify_enrollment(spec.cohort)
    payload = receipts._unpack(lanes._read(spec.plan_receipt), lanes.PLAN_TYPE)
    if (payload["bindings"]["cohort_sha256"] != lanes._sha(lanes._read(spec.cohort))
            or policy["runtime"]["data_root"] != str(spec.data_root)
            or Path(batch["admission_root"]) != spec.acquisition_root):
        raise ValueError("selected transport changes its bound membership or runtime")
    roots = {path.parent for path in membership_inputs(spec.cohort)}
    runtime = payload["runtime"]
    roots.update(Path(runtime[key]) for key in ("runtime_source_root", "module_root", "execution_root"))
    roots.update(Path(runtime[key]).parent for key in ("source_manifest", "client_binary", "base_launcher", "host_launcher"))
    for row in classes[-len(batch["selected_candidate_ids"]):]:
        manifest = lanes._load(lanes._read(selected.reopen(row["prepared_workload"])))
        roots.update(selected.preparation_roots(manifest["preparation"], manifest["resources"]))
    for root in roots:
        lanes._regular_directory(root)
        if any(char in str(root) for char in ("\n", "\r", "\0", ":")):
            raise ValueError("selected transport requires canonical regular same-absolute RO roots")
    return sorted(roots)
