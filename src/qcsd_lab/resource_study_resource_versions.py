"""Pure all-five, same-host resource-retirement kernel; no publication API.

Callers must first authenticate the original complete cohort head, member
enrollments and accepted-row inventory with the existing records/FD/SQL readers.
The template binds those exact values; it does not replace those readers, live
preparation, own pilots, receipt verification, locks, allocation or certification.

This kernel has no CLI, Store, file access or write path. The distinct cohort
admission and preparation modules supply those original ownership boundaries.
A declaration is prospective input, never proof that preparation or credit occurred.
Historical v0 receipts remain valid under their original contracts, while the
new target can count only a common v1 workload across all five modes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .resource_study_inputs import MODES, canonical_json, normalize_url
from .resource_study_store import _digest, _hostname, _json, _scientific_runtime, _tuple

DECLARATION = "qcsd-resource-domain-same-host-all5-resource-retirement-declaration-v1"
RETIREMENT = "qcsd-resource-domain-target-excluded-historical-resource-version-v1"
RECEIPT_BINDING = "qcsd-resource-domain-active-resource-version-receipt-binding-v1"
STRATA = "qcsd-resource-domain-retired-v0-active-v1-resource-strata-v1"
POLICY = "same-host-common20-all5-zero-carry-retirement-v1"
COHORT_ADMISSION = "qcsd-resource-domain-runtime-cohort-admission-v1"
MODE_ORDER = tuple(sorted(MODES))
CELL_FIELDS = {"hostname", "mode", "root", "study_sha256", "enrollment_path",
               "enrollment_sha256", "definition", "definition_sha256"}
ROW_FIELDS = {"root", "hostname", "mode", "slot", "attempt_id", "five_tuple",
              "receipt_path", "receipt_sha256", "accepted_row_sha256"}


def _need(value, message):
    if not value:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _path(value, *, relative=False):
    _need(type(value) is str and value and "\\" not in value, "resource-version path must be literal")
    path = PurePosixPath(value)
    _need(str(path) == value and ".." not in path.parts
          and path.is_absolute() is not relative, "resource-version path is not canonical")
    return value


def _key(cell):
    return cell["hostname"], cell["mode"]


def _cell(value):
    _need(type(value) is dict and set(value) == CELL_FIELDS,
          "resource-version cell must retain the complete original cell schema")
    _hostname(value["hostname"])
    _need(value["mode"] in MODES, "resource-version cell mode differs")
    _path(value["root"]); _path(value["enrollment_path"], relative=True)
    _digest(value["study_sha256"]); _digest(value["enrollment_sha256"])
    definition = value["definition"]
    _need(type(definition) is dict and set(definition) == {
        "urls", "workload_sha256", "settings", "policies", "native", "acceptance", "ready", "network"},
        "resource-version definition lacks its complete science/network inputs")
    _need(value["definition_sha256"] == digest(definition), "resource-version definition SHA differs")
    urls = definition["urls"]
    _need(type(urls) is list and len(urls) == 20 and all(type(url) is str for url in urls)
          and len(set(urls)) == 20 and all(normalize_url(url) == url
                  and urlsplit(url).hostname == value["hostname"] for url in urls),
          "resource version needs twenty distinct exact-host URLs")
    _digest(definition["workload_sha256"])
    native = definition["native"]
    _need(type(native) is list and len(native) == 3, "resource-version Native identity differs")
    _need(list(_scientific_runtime({"client_sha256": native[0], "platform": native[1],
          "source": {"neqo_commit": native[2]}})) == native, "resource-version Native identity is invalid")
    _need(type(definition["settings"]) is dict and type(definition["policies"]) is dict
          and type(definition["acceptance"]) is str and type(definition["ready"]) is bool,
          "resource-version settings/acceptance/readiness must be explicit")
    network = definition["network"]
    _need(type(network) is dict and set(network) == {
        "mapping_sha256", "assignment", "tuple_uniqueness_scope"}
        and type(network["assignment"]) is dict and type(network["tuple_uniqueness_scope"]) is str,
        "resource-version physical class binding differs")
    _digest(network["mapping_sha256"])
    return value


def _prior(value):
    _need(type(value) is dict and value.get("record_type") == COHORT_ADMISSION,
          "resource retirement requires the actual current cohort authority, never a legacy epoch")
    _need(type(value.get("sequence")) is int and value["sequence"] >= 1,
          "resource retirement requires a genuine cohort sequence")
    _digest(value["parent_study_sha256"])
    transition = value["class_transition"]
    _need(type(transition) is dict, "resource retirement lacks stable class lineage")
    hosts = transition["class_selection"]["selected_hostnames"]
    _need(type(hosts) is list and hosts == sorted(set(hosts)) and len(hosts) == 50,
          "resource retirement must retain exactly the same fifty classes")
    for host in hosts:
        _hostname(host)
    _need(set(transition["class_network"]["assignments"]) == set(hosts),
          "resource retirement lacks the complete physical class map")
    cells = value["cells"]
    _need(type(cells) is list and cells, "resource retirement lacks current cells")
    indexed = {}
    for cell in cells:
        _cell(cell); key = _key(cell)
        _need(key not in indexed and cell["hostname"] in hosts, "resource retirement repeats or adds a cell")
        indexed[key] = cell
    entries = value["cohorts"]
    _need(type(entries) is list and len(entries) == len(indexed)
          and {_key(entry) for entry in entries} == set(indexed),
          "resource retirement cohort/cell inventory differs")
    roots = set()
    for entry in entries:
        _need(type(entry["members"]) is list and entry["members"], "resource retirement lacks historical members")
        ids = set(); writers = []
        for member in entry["members"]:
            _need(type(member) is dict and set(member) == {
                "cohort_id", "cell", "verifier", "frozen_accepted"}, "resource retirement rewrites a member schema")
            cell = _cell(member["cell"])
            _need(_key(cell) == _key(entry) and member["cohort_id"] == digest(cell)
                  and member["cohort_id"] not in ids, "resource retirement member identity differs")
            ids.add(member["cohort_id"]); roots.add(cell["root"])
            if member["cohort_id"] == entry["writer"]:
                writers.append(member)
        _need(len(writers) == 1 and writers[0]["frozen_accepted"] is None
              and writers[0]["cell"] == indexed[_key(entry)], "resource retirement writer differs")
    return indexed, roots


def _rows(values, prior):
    """Bind original _manifest/_row_ref values, without reading or promoting them."""
    cells, _ = _prior(prior)
    members = {(member["cell"]["root"], *_key(entry))
               for entry in prior["cohorts"] for member in entry["members"]}
    _need(type(values) is list and len(values) <= 100000, "resource retirement accepted inventory is unbounded")
    slots = set(); tuples = set(); identities = set()
    for row in values:
        _need(type(row) is dict and set(row) == ROW_FIELDS, "resource retirement row must retain the exact original reference")
        key = row["hostname"], row["mode"]
        _need(key in cells and (row["root"], *key) in members,
              "resource retirement receipt escapes the actual prior member set")
        _path(row["root"]); _path(row["receipt_path"], relative=True)
        _digest(row["receipt_sha256"]); _digest(row["accepted_row_sha256"])
        _need(type(row["slot"]) is int and 1 <= row["slot"] <= 400
              and type(row["attempt_id"]) is str and len(row["attempt_id"]) == 32
              and all(char in "0123456789abcdef" for char in row["attempt_id"]),
              "resource retirement accepted identity differs")
        _need(type(row["five_tuple"]) is str, "resource retirement tuple must retain its exact original SQL bytes")
        actual = _tuple(json.loads(row["five_tuple"]))
        _need(_json(actual).decode() == row["five_tuple"], "resource retirement tuple encoding differs")
        slot = (*key, row["slot"]); tuple_key = (*key, row["five_tuple"])
        identity = row["root"], row["attempt_id"]
        _need(slot not in slots and tuple_key not in tuples and identity not in identities,
              "resource retirement repeats a shared400 slot, tuple or accepted attempt")
        slots.add(slot); tuples.add(tuple_key); identities.add(identity)
    _need(values == sorted(values, key=lambda row: (row["hostname"], row["mode"], row["slot"], row["root"])),
          "resource retirement accepted manifest order differs")
    return values


def _mode_science(cell):
    """Resource-only comparison; preserve Native/settings/acceptance and tuple policy."""
    value = deepcopy(cell["definition"])
    for name in ("urls", "workload_sha256", "ready"):
        del value[name]
    value["network"].pop("mapping_sha256")
    value["network"].pop("assignment")
    return value


def _v1_member_sciences(entry):
    """Closed v0/v1 relation; historical members are retained, never target carry."""
    _need(type(entry) is dict and set(entry) == {
        "hostname", "mode", "science", "members", "writer", "resource_versions"},
        "resource-version entry cannot borrow a Native-only or budget-strata schema")
    value = entry["resource_versions"]
    _need(type(value) is dict and set(value) == {
        "record_type", "schema_version", "policy", "declaration", "strata"}
        and value["record_type"] == STRATA and type(value["schema_version"]) is int
        and value["schema_version"] == 1 and value["policy"] == POLICY,
        "resource-version strata schema differs")
    ref = value["declaration"]
    _need(type(ref) is dict and set(ref) == {"path", "sha256"}, "resource-version declaration reference differs")
    _path(ref["path"]); _digest(ref["sha256"])
    strata = value["strata"]
    _need(type(strata) is list and 1 <= len(strata) <= 2,
          "resource retirement permits only one prospective v0-to-v1 transition")
    versions = [row.get("version") for row in strata if type(row) is dict]
    _need(versions in ([1], [0, 1]), "absent mode must not invent v0 history or a third resource version")
    assigned = []; result = {}
    for row, version in zip(strata, versions):
        _need(set(row) == {"version", "science", "members", "target_eligible"}
              and type(row["version"]) is int and type(row["target_eligible"]) is bool
              and row["target_eligible"] is (version == 1)
              and type(row["science"]) is dict and type(row["members"]) is list and row["members"],
              "resource-version member/target relation differs")
        for identity in row["members"]:
            _digest(identity)
            assigned.append(identity); result[identity] = row["science"]
    members = entry["members"]
    _need(len(assigned) == len(set(assigned)) and assigned == [member["cohort_id"] for member in members]
          and entry["writer"] in strata[-1]["members"] and entry["science"] == strata[-1]["science"],
          "resource-version strata lose or repeat member ancestry or current science")
    if len(strata) == 2:
        old, new = (deepcopy(row["science"]) for row in strata)
        old_resources = old.pop("urls"), old.pop("workload_sha256")
        new_resources = new.pop("urls"), new.pop("workload_sha256")
        _need(old == new and old_resources != new_resources,
              "resource retirement changes non-resource science or repeats v0")
        _need(all(member["frozen_accepted"] is not None for member in members
                  if member["cohort_id"] in strata[0]["members"]),
              "historical resource-version member must remain frozen")
    return result


def target_member_ids(entry):
    member_sciences(entry)
    return frozenset(entry["resource_versions"]["strata"][-1]["members"])


def member_version(entry, identity):
    member_sciences(entry)
    matches = [row["version"] for row in entry["resource_versions"]["strata"] if identity in row["members"]]
    _need(len(matches) == 1, "resource-version member is absent or repeated")
    return matches[0]


def _v1_replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
                         *, hostname, verifier, missing_mode_templates=()):
    """Return an unissued, source-bound all5 zero-carry retirement declaration.

    Existing modes preserve their complete Native/mode science. An absent mode
    uses an explicitly supplied actual current global donor cell of that mode;
    it is recorded as never admitted, not forged into prior same-host membership.
    Original live callers must authenticate every candidate preparation and donor
    before using this pure metadata result. Readiness may remain false; it never
    authorizes that mode's capture or lets it block another ready mode.
    """
    _hostname(hostname); cells, old_roots = _prior(prior)
    _need(type(verifier) is dict and verifier, "resource retirement requires its explicit qualifying reader contract")
    hosts = prior["class_transition"]["class_selection"]["selected_hostnames"]
    _need(hostname in hosts, "resource retirement cannot replace a hostname or add a class")
    _need(type(replacement_cells) is list and len(replacement_cells) == 5,
          "resource retirement must declare all five replacement cells atomically")
    candidates = {_key(_cell(cell)): cell for cell in replacement_cells}
    _need(set(candidates) == {(hostname, mode) for mode in MODES}, "resource retirement affected set is not same-host all5")
    supplied = {_key(_cell(cell))[1]: cell for cell in missing_mode_templates}
    _need(len(supplied) == len(missing_mode_templates), "resource retirement repeats an absent-mode template")
    missing = {mode for mode in MODES if (hostname, mode) not in cells}
    _need(set(supplied) == missing, "resource retirement needs exact actual templates only for never-admitted modes")
    original = [cell for key, cell in cells.items() if key[0] == hostname]
    _need(original, "resource retirement requires an existing same-host workload")
    old = original[0]["definition"]
    _need(all(cell["definition"]["urls"] == old["urls"]
              and cell["definition"]["workload_sha256"] == old["workload_sha256"] for cell in original),
          "old same-host modes already have mixed resource versions")
    first = candidates[(hostname, MODE_ORDER[0])]["definition"]
    _need(type(application_manifest_raw) is bytes and len(application_manifest_raw) <= 16 * 1024**2,
          "resource retirement needs the exact bounded new application manifest bytes")
    from .resource_study_selection import validate_frozen_application_manifest_bytes
    validate_frozen_application_manifest_bytes(application_manifest_raw, hostname, first["urls"])
    workload = hashlib.sha256(application_manifest_raw).hexdigest()
    _need((first["urls"], workload) != (old["urls"], old["workload_sha256"]),
          "resource retirement must actually change the declared resource version")
    leaf = prior["class_transition"]["class_network"]
    allowed_maps = {digest(leaf), leaf["predecessor_sha256"]}
    affected = []
    for mode in MODE_ORDER:
        candidate = candidates[(hostname, mode)]; definition = candidate["definition"]
        baseline = cells.get((hostname, mode), supplied.get(mode))
        if mode in missing:
            _need(cells.get(_key(baseline)) == baseline and baseline["mode"] == mode,
                  "absent-mode donor is not an exact actual current global cell")
        _need(candidate["root"] not in old_roots and definition["urls"] == first["urls"]
              and definition["workload_sha256"] == workload,
              "new all5 resource version needs genuinely fresh roots and one common ordered20 workload")
        _need(_mode_science(candidate) == _mode_science(baseline),
              "resource retirement changes Native, settings, acceptance, policies or tuple scope")
        _need(definition["network"]["assignment"] == leaf["assignments"][hostname]
              and definition["network"]["mapping_sha256"] in allowed_maps,
              "resource retirement changes the persistent class address or map lineage")
        affected.append({"hostname": hostname, "mode": mode, "previously_admitted": mode not in missing,
                         "previous_or_global_template": deepcopy(baseline), "replacement": deepcopy(candidate)})
    rows = _rows(accepted_rows, prior)
    retired = [deepcopy(row) for row in rows if row["hostname"] == hostname]
    retained = [deepcopy(row) for row in rows if row["hostname"] != hostname]
    retirement = {"record_type": RETIREMENT, "hostname": hostname,
                  "old_workload_sha256": old["workload_sha256"], "rows": retired,
                  "historically_valid": True, "target_eligible": False,
                  "old_raw_receipts_relabelled_or_deleted": False}
    return {"record_type": DECLARATION, "schema_version": 1, "policy": POLICY,
            "hostname": hostname, "affected_modes": list(MODE_ORDER), "affected": affected,
            "predecessor_admission_sha256": digest(prior),
            "verifier": deepcopy(verifier),
            "parent_study_sha256": prior["parent_study_sha256"],
            "class_transition_sha256": digest(prior["class_transition"]),
            "selected_hostnames": deepcopy(hosts), "old_resource_urls": deepcopy(old["urls"]),
            "new_resource_urls": deepcopy(first["urls"]), "new_workload_sha256": workload,
            "prior_accepted_manifest_sha256": digest(rows), "prior_accepted_count": len(rows),
            "retirement": retirement, "retirement_sha256": digest(retirement),
            "retired_target_count": len(retired), "retained_other49_manifest_sha256": digest(retained),
            "target_eligible_count_after_retirement": len(retained), "initial_v1_accepted_count": 0,
            "resource_replacement_authorized": False, "compatible_treatment": False,
            "rationale": "", "scientific_credit": False}


def _v1_validate_declaration(value, prior, accepted_rows, replacement_cells, application_manifest_raw,
                         *, hostname, verifier, missing_mode_templates=()):
    """Authenticate exact declaration operands; never publish or issue credit."""
    expected = replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
                                    hostname=hostname, verifier=verifier, missing_mode_templates=missing_mode_templates)
    _need(type(value) is dict and set(value) == set(expected)
          and value["resource_replacement_authorized"] is True
          and type(value["rationale"]) is str and value["rationale"].strip(),
          "resource retirement needs an explicit complete prospective operator declaration")
    expected["resource_replacement_authorized"] = True; expected["rationale"] = value["rationale"]
    _need(canonical_json(value) == canonical_json(expected),
          "resource retirement source/head, all5 scope, prior receipts, retained49 or resource science differs")
    return deepcopy(expected)


def _v1_validate_target_receipt_binding(receipt, cell, declaration, *, resource_entry=None):
    """Additional binding after original whole verification, never a verifier.

    Caller must authenticate the actual published declaration and current member
    first. No JSON verified/passed flag can replace the original receipt audit.
    The result deliberately contains no verified or scientific-credit field.
    """
    _cell(cell)
    _need(type(declaration) is dict and declaration.get("record_type") == DECLARATION
          and declaration.get("policy") == POLICY and declaration.get("resource_replacement_authorized") is True
          and declaration.get("compatible_treatment") is False and declaration.get("scientific_credit") is False,
          "target receipt lacks the explicit resource-version declaration")
    _need(declaration["retirement_sha256"] == digest(declaration["retirement"]),
          "target receipt historical retirement index changed")
    replacements = [row["replacement"] for row in declaration["affected"]]
    member_bound = cell in replacements
    if resource_entry is not None:
        active = target_member_ids(resource_entry)
        member_bound = any(member["cell"] == cell and member["cohort_id"] in active
                           for member in resource_entry["members"])
        _need(resource_entry["resource_versions"]["declaration"]["sha256"] == digest(declaration),
              "target member changes its original resource-retirement declaration")
    _need(member_bound and len(replacements) == 5
          and {_key(item) for item in replacements} == {(declaration["hostname"], mode) for mode in MODES},
          "target receipt is not in the exact all5 new-version member set")
    definition = cell["definition"]
    _need(definition["ready"] is True and receipt.get("hostname") == cell["hostname"]
          and receipt.get("mode") == cell["mode"] and receipt.get("purpose") in ("pilot", "formal")
          and receipt.get("workload_sha256") == declaration["new_workload_sha256"] == definition["workload_sha256"]
          and definition["urls"] == declaration["new_resource_urls"],
          "target receipt uses old/mixed/unready resources, mode, purpose or member")
    _need(list(_scientific_runtime(receipt["runtime"])) == definition["native"]
          and receipt.get("mode_settings") == definition["settings"]
          and receipt.get("mode_policies") == definition["policies"],
          "target receipt changes its exact Native or mode science")
    _need(receipt.get("artifact_paths", {}).get("enrollment") == cell["enrollment_path"]
          and receipt.get("files", {}).get(cell["enrollment_path"]) == cell["enrollment_sha256"],
          "target receipt lacks its exact new-version enrollment")
    actual_tuple = _tuple(receipt["five_tuple"])
    for row in declaration["retirement"]["rows"]:
        _need(not (row["mode"] == cell["mode"] and
                   (_tuple(json.loads(row["five_tuple"])) == actual_tuple
                    or row["attempt_id"] == receipt.get("attempt_id"))),
              "new target cannot reuse a retired accepted connection or attempt")
    if receipt["purpose"] == "formal":
        _need(type(receipt.get("slot")) is int and 1 <= receipt["slot"] <= 400,
              "new-version formal target exceeds its original shared400 quota")
    return {"record_type": RECEIPT_BINDING, "declaration_sha256": digest(declaration),
            "hostname": cell["hostname"], "mode": cell["mode"], "purpose": receipt["purpose"],
            "new_workload_sha256": definition["workload_sha256"],
            "enrollment_sha256": cell["enrollment_sha256"], "historical_v0_target_carry": 0}


# Prospective Source112: a separate policy, never an alias of resource-only v1.
DECLARATION_V2 = "qcsd-resource-domain-Fonts-all5-aggregate8-to-ordinary5-resource-retirement-declaration-v2"
RETIREMENT_V2 = "qcsd-resource-domain-Fonts-target-excluded-historical-resource-version-v2"
RECEIPT_BINDING_V2 = "qcsd-resource-domain-Fonts-active-resource-version-receipt-binding-v2"
STRATA_V2 = "qcsd-resource-domain-Fonts-retired-v0-active-v1-resource-strata-v2"
POLICY_V2 = "fonts-same50-common20-all5-aggregate8-to-ordinary5-zero-carry-v2"
PREPARATION_POLICY_V2 = "qcsd-Fonts-Native130-aggregate8-to-ordinary5-preparation-policy-v2"
FONTS_HOST = "fonts.gstatic.com"
FONTS_NATIVE130 = ["692997fe16335e55cd77acc6b9754190bdf62c761609c2224f4417d460faf291",
                   "linux/arm64", "6ae3dc347be45622efcc723dc669860490142fcc"]
FONTS_ORIGINAL_WORKLOAD = "76921caed2aef23a506e037b7d207d79cb3d62737377f4621d95100a0b1ef394"


def fonts_ordinary_preparation_policy(prior):
    """Bind the actual current donor; this prospective value does not run a GET."""
    cells, _ = _prior(prior)
    _need({mode for host, mode in cells if host == FONTS_HOST} == set(MODES),
          "Fonts v2 needs all five genuine current same-host donors")
    cell = cells[(FONTS_HOST, "buflo")]
    return _fonts_policy_for_cell(cell)


def _fonts_policy_for_cell(cell):
    from .resource_study_native import buflo_aggregate_selection
    _cell(cell)
    definition = cell["definition"]; settings = definition["settings"]
    _need(cell["hostname"] == FONTS_HOST and cell["mode"] == "buflo"
          and definition["native"] == FONTS_NATIVE130
          and definition["workload_sha256"] == FONTS_ORIGINAL_WORKLOAD
          and settings.get("profile") == "research-1200"
          and settings.get("parameters_sha256") == "5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e"
          and settings.get("timeout_seconds") == 680 and settings.get("capture_seconds") == 740
          and definition["policies"].get("buflo_duration_policy") == "rapid-v7-fixed-64ms-640s-duration-budget-v1",
          "Fonts v2 requires the exact original Native130 fixed64ms640s aggregate donor")
    return {"record_type": PREPARATION_POLICY_V2, "schema_version": 2,
        "hostname": FONTS_HOST, "previous_buflo_cell": deepcopy(cell),
        "previous_buflo_cell_sha256": digest(cell),
        "previous_selection": buflo_aggregate_selection(),
        "previous_qualified_parallel_chaff_streams": 8, "previous_native_manifest_schema": 6,
        "new_selection": "ordinary-deterministic-largest-response-only-v1",
        "new_qualified_parallel_chaff_streams": 5, "new_native_manifest_schema": 3,
        "all20_minimum_body_bytes": 8192, "settings_native_and_physics_changed": False,
        "scientific_credit": False}


def checked_fonts_preparation_policy(value, *, prior=None):
    _need(type(value) is dict and type(value.get("schema_version")) is int
          and value.get("schema_version") == 2, "exact Fonts v2 preparation policy required")
    expected = _fonts_policy_for_cell(value["previous_buflo_cell"])
    if prior is not None:
        _need(canonical_json(expected) == canonical_json(fonts_ordinary_preparation_policy(prior)),
              "Fonts v2 policy differs from its actual current Native130 donor")
    _need(canonical_json(value) == canonical_json(expected),
          "Fonts v2 changed cover policy, Native/settings/physics, capacity or credit intent")
    return deepcopy(expected)


def _v2_member_sciences(entry):
    """Closed v0/v1 relation; historical members are retained, never target carry."""
    _need(type(entry) is dict and set(entry) == {
        "hostname", "mode", "science", "members", "writer", "resource_versions"},
        "resource-version entry cannot borrow a Native-only or budget-strata schema")
    value = entry["resource_versions"]
    _need(type(value) is dict and set(value) == {
        "record_type", "schema_version", "policy", "declaration", "strata", "preparation_policy"}
        and value["record_type"] == STRATA_V2 and type(value["schema_version"]) is int
        and value["schema_version"] == 2 and value["policy"] == POLICY_V2,
        "resource-version strata schema differs")
    _need(entry["hostname"] == FONTS_HOST, "Fonts v2 strata cannot authorize a different class")
    checked_fonts_preparation_policy(value["preparation_policy"])
    ref = value["declaration"]
    _need(type(ref) is dict and set(ref) == {"path", "sha256"}, "resource-version declaration reference differs")
    _path(ref["path"]); _digest(ref["sha256"])
    strata = value["strata"]
    _need(type(strata) is list and 1 <= len(strata) <= 2,
          "resource retirement permits only one prospective v0-to-v1 transition")
    versions = [row.get("version") for row in strata if type(row) is dict]
    _need(versions in ([1], [0, 1]), "absent mode must not invent v0 history or a third resource version")
    assigned = []; result = {}
    for row, version in zip(strata, versions):
        _need(set(row) == {"version", "science", "members", "target_eligible"}
              and type(row["version"]) is int and type(row["target_eligible"]) is bool
              and row["target_eligible"] is (version == 1)
              and type(row["science"]) is dict and type(row["members"]) is list and row["members"],
              "resource-version member/target relation differs")
        for identity in row["members"]:
            _digest(identity)
            assigned.append(identity); result[identity] = row["science"]
    members = entry["members"]
    _need(len(assigned) == len(set(assigned)) and assigned == [member["cohort_id"] for member in members]
          and entry["writer"] in strata[-1]["members"] and entry["science"] == strata[-1]["science"],
          "resource-version strata lose or repeat member ancestry or current science")
    if len(strata) == 2:
        old, new = (deepcopy(row["science"]) for row in strata)
        old_resources = old.pop("urls"), old.pop("workload_sha256")
        new_resources = new.pop("urls"), new.pop("workload_sha256")
        _need(old == new and old_resources != new_resources,
              "resource retirement changes non-resource science or repeats v0")
        _need(all(member["frozen_accepted"] is not None for member in members
                  if member["cohort_id"] in strata[0]["members"]),
              "historical resource-version member must remain frozen")
    return result

def _v2_replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
                         *, hostname, verifier, missing_mode_templates=(), preparation_policy):
    """Return an unissued, source-bound all5 zero-carry retirement declaration.

    Existing modes preserve their complete Native/mode science. An absent mode
    uses an explicitly supplied actual current global donor cell of that mode;
    it is recorded as never admitted, not forged into prior same-host membership.
    Original live callers must authenticate every candidate preparation and donor
    before using this pure metadata result. Readiness may remain false; it never
    authorizes that mode's capture or lets it block another ready mode.
    """
    _need(hostname == FONTS_HOST and not missing_mode_templates, "Fonts v2 is one exact existing all-five class")
    checked_fonts_preparation_policy(preparation_policy, prior=prior)
    _hostname(hostname); cells, old_roots = _prior(prior)
    _need(type(verifier) is dict and verifier, "resource retirement requires its explicit qualifying reader contract")
    hosts = prior["class_transition"]["class_selection"]["selected_hostnames"]
    _need(hostname in hosts, "resource retirement cannot replace a hostname or add a class")
    _need(type(replacement_cells) is list and len(replacement_cells) == 5,
          "resource retirement must declare all five replacement cells atomically")
    candidates = {_key(_cell(cell)): cell for cell in replacement_cells}
    _need(set(candidates) == {(hostname, mode) for mode in MODES}, "resource retirement affected set is not same-host all5")
    supplied = {_key(_cell(cell))[1]: cell for cell in missing_mode_templates}
    _need(len(supplied) == len(missing_mode_templates), "resource retirement repeats an absent-mode template")
    missing = {mode for mode in MODES if (hostname, mode) not in cells}
    _need(set(supplied) == missing, "resource retirement needs exact actual templates only for never-admitted modes")
    original = [cell for key, cell in cells.items() if key[0] == hostname]
    _need(original, "resource retirement requires an existing same-host workload")
    old = original[0]["definition"]
    _need(all(cell["definition"]["urls"] == old["urls"]
              and cell["definition"]["workload_sha256"] == old["workload_sha256"] for cell in original),
          "old same-host modes already have mixed resource versions")
    first = candidates[(hostname, MODE_ORDER[0])]["definition"]
    _need(type(application_manifest_raw) is bytes and len(application_manifest_raw) <= 16 * 1024**2,
          "resource retirement needs the exact bounded new application manifest bytes")
    from .resource_study_selection import validate_frozen_application_manifest_bytes
    validate_frozen_application_manifest_bytes(application_manifest_raw, hostname, first["urls"])
    workload = hashlib.sha256(application_manifest_raw).hexdigest()
    _need((first["urls"], workload) != (old["urls"], old["workload_sha256"]),
          "resource retirement must actually change the declared resource version")
    leaf = prior["class_transition"]["class_network"]
    allowed_maps = {digest(leaf), leaf["predecessor_sha256"]}
    affected = []
    for mode in MODE_ORDER:
        candidate = candidates[(hostname, mode)]; definition = candidate["definition"]
        baseline = cells.get((hostname, mode), supplied.get(mode))
        if mode in missing:
            _need(cells.get(_key(baseline)) == baseline and baseline["mode"] == mode,
                  "absent-mode donor is not an exact actual current global cell")
        _need(candidate["root"] not in old_roots and definition["urls"] == first["urls"]
              and definition["workload_sha256"] == workload,
              "new all5 resource version needs genuinely fresh roots and one common ordered20 workload")
        _need(_mode_science(candidate) == _mode_science(baseline),
              "resource retirement changes Native, settings, acceptance, policies or tuple scope")
        _need(definition["network"]["assignment"] == leaf["assignments"][hostname]
              and definition["network"]["mapping_sha256"] in allowed_maps,
              "resource retirement changes the persistent class address or map lineage")
        affected.append({"hostname": hostname, "mode": mode, "previously_admitted": mode not in missing,
                         "previous_or_global_template": deepcopy(baseline), "replacement": deepcopy(candidate)})
    rows = _rows(accepted_rows, prior)
    retired = [deepcopy(row) for row in rows if row["hostname"] == hostname]
    retained = [deepcopy(row) for row in rows if row["hostname"] != hostname]
    retirement = {"record_type": RETIREMENT_V2, "hostname": hostname,
                  "old_workload_sha256": old["workload_sha256"], "rows": retired,
                  "historically_valid": True, "target_eligible": False,
                  "old_raw_receipts_relabelled_or_deleted": False}
    return {"record_type": DECLARATION_V2, "schema_version": 2, "policy": POLICY_V2,
            "preparation_policy": deepcopy(preparation_policy),
            "hostname": hostname, "affected_modes": list(MODE_ORDER), "affected": affected,
            "predecessor_admission_sha256": digest(prior),
            "verifier": deepcopy(verifier),
            "parent_study_sha256": prior["parent_study_sha256"],
            "class_transition_sha256": digest(prior["class_transition"]),
            "selected_hostnames": deepcopy(hosts), "old_resource_urls": deepcopy(old["urls"]),
            "new_resource_urls": deepcopy(first["urls"]), "new_workload_sha256": workload,
            "prior_accepted_manifest_sha256": digest(rows), "prior_accepted_count": len(rows),
            "retirement": retirement, "retirement_sha256": digest(retirement),
            "retired_target_count": len(retired), "retained_other49_manifest_sha256": digest(retained),
            "target_eligible_count_after_retirement": len(retained), "initial_v1_accepted_count": 0,
            "resource_replacement_authorized": False, "compatible_treatment": False,
            "rationale": "", "scientific_credit": False}

def _v2_validate_declaration(value, prior, accepted_rows, replacement_cells, application_manifest_raw,
                         *, hostname, verifier, missing_mode_templates=(), preparation_policy):
    """Authenticate exact declaration operands; never publish or issue credit."""
    expected = _v2_replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
                                    hostname=hostname, verifier=verifier, missing_mode_templates=missing_mode_templates,
                                    preparation_policy=preparation_policy)
    _need(type(value) is dict and set(value) == set(expected)
          and value["resource_replacement_authorized"] is True
          and type(value["rationale"]) is str and value["rationale"].strip(),
          "resource retirement needs an explicit complete prospective operator declaration")
    expected["resource_replacement_authorized"] = True; expected["rationale"] = value["rationale"]
    _need(canonical_json(value) == canonical_json(expected),
          "resource retirement source/head, all5 scope, prior receipts, retained49 or resource science differs")
    return deepcopy(expected)

def _v2_validate_target_receipt_binding(receipt, cell, declaration, *, resource_entry=None):
    """Additional binding after original whole verification, never a verifier.

    Caller must authenticate the actual published declaration and current member
    first. No JSON verified/passed flag can replace the original receipt audit.
    The result deliberately contains no verified or scientific-credit field.
    """
    checked_fonts_preparation_policy(declaration["preparation_policy"])
    _need(cell["hostname"] == FONTS_HOST, "Fonts v2 receipt cannot use another class")
    _cell(cell)
    _need(type(declaration) is dict and declaration.get("record_type") == DECLARATION_V2
          and declaration.get("policy") == POLICY_V2 and declaration.get("resource_replacement_authorized") is True
          and declaration.get("compatible_treatment") is False and declaration.get("scientific_credit") is False,
          "target receipt lacks the explicit resource-version declaration")
    _need(declaration["retirement_sha256"] == digest(declaration["retirement"]),
          "target receipt historical retirement index changed")
    replacements = [row["replacement"] for row in declaration["affected"]]
    member_bound = cell in replacements
    if resource_entry is not None:
        active = target_member_ids(resource_entry)
        member_bound = any(member["cell"] == cell and member["cohort_id"] in active
                           for member in resource_entry["members"])
        _need(resource_entry["resource_versions"]["declaration"]["sha256"] == digest(declaration),
              "target member changes its original resource-retirement declaration")
    _need(member_bound and len(replacements) == 5
          and {_key(item) for item in replacements} == {(declaration["hostname"], mode) for mode in MODES},
          "target receipt is not in the exact all5 new-version member set")
    definition = cell["definition"]
    _need(definition["ready"] is True and receipt.get("hostname") == cell["hostname"]
          and receipt.get("mode") == cell["mode"] and receipt.get("purpose") in ("pilot", "formal")
          and receipt.get("workload_sha256") == declaration["new_workload_sha256"] == definition["workload_sha256"]
          and definition["urls"] == declaration["new_resource_urls"],
          "target receipt uses old/mixed/unready resources, mode, purpose or member")
    _need(list(_scientific_runtime(receipt["runtime"])) == definition["native"]
          and receipt.get("mode_settings") == definition["settings"]
          and receipt.get("mode_policies") == definition["policies"],
          "target receipt changes its exact Native or mode science")
    _need(receipt.get("artifact_paths", {}).get("enrollment") == cell["enrollment_path"]
          and receipt.get("files", {}).get(cell["enrollment_path"]) == cell["enrollment_sha256"],
          "target receipt lacks its exact new-version enrollment")
    actual_tuple = _tuple(receipt["five_tuple"])
    for row in declaration["retirement"]["rows"]:
        _need(not (row["mode"] == cell["mode"] and
                   (_tuple(json.loads(row["five_tuple"])) == actual_tuple
                    or row["attempt_id"] == receipt.get("attempt_id"))),
              "new target cannot reuse a retired accepted connection or attempt")
    if receipt["purpose"] == "formal":
        _need(type(receipt.get("slot")) is int and 1 <= receipt["slot"] <= 400,
              "new-version formal target exceeds its original shared400 quota")
    return {"record_type": RECEIPT_BINDING_V2, "declaration_sha256": digest(declaration),
            "hostname": cell["hostname"], "mode": cell["mode"], "purpose": receipt["purpose"],
            "new_workload_sha256": definition["workload_sha256"],
            "enrollment_sha256": cell["enrollment_sha256"], "historical_v0_target_carry": 0}


def replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
                         *, hostname, verifier, missing_mode_templates=(), preparation_policy=None):
    if preparation_policy is None:
        return _v1_replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
            hostname=hostname, verifier=verifier, missing_mode_templates=missing_mode_templates)
    return _v2_replacement_template(prior, accepted_rows, replacement_cells, application_manifest_raw,
        hostname=hostname, verifier=verifier, missing_mode_templates=missing_mode_templates,
        preparation_policy=preparation_policy)


def validate_declaration(value, prior, accepted_rows, replacement_cells, application_manifest_raw,
                         *, hostname, verifier, missing_mode_templates=(), preparation_policy=None):
    if type(value) is dict and value.get("record_type") == DECLARATION_V2:
        return _v2_validate_declaration(value, prior, accepted_rows, replacement_cells, application_manifest_raw,
            hostname=hostname, verifier=verifier, missing_mode_templates=missing_mode_templates,
            preparation_policy=preparation_policy)
    _need(preparation_policy is None, "resource-only v1 cannot borrow Fonts v2 preparation policy")
    return _v1_validate_declaration(value, prior, accepted_rows, replacement_cells, application_manifest_raw,
        hostname=hostname, verifier=verifier, missing_mode_templates=missing_mode_templates)


def member_sciences(entry):
    if type(entry) is dict and entry.get("resource_versions", {}).get("record_type") == STRATA_V2:
        return _v2_member_sciences(entry)
    return _v1_member_sciences(entry)


def validate_target_receipt_binding(receipt, cell, declaration, *, resource_entry=None):
    if type(declaration) is dict and declaration.get("record_type") == DECLARATION_V2:
        return _v2_validate_target_receipt_binding(receipt, cell, declaration, resource_entry=resource_entry)
    return _v1_validate_target_receipt_binding(receipt, cell, declaration, resource_entry=resource_entry)
