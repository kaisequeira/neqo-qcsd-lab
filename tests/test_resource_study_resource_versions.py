"""Pure prospective retirement controls, not an admission or raw-science pass.

The first fixture's cells, source identities and three accepted references are
declared synthetic metadata, not Clarin's real1588 rows or a certificate. The
last test additionally uses the existing disposable cohort/SQLite fixture and
its explicitly synthetic raw/preparation leaves, retaining actual history bytes
and accepted-row joins. No live preparation, capture or publication occurs.
ROOT alone executes these tests after review.
"""
from copy import deepcopy
import hashlib

import pytest

from qcsd_lab import resource_study_resource_versions as versions
from qcsd_lab.resource_study_inputs import MODES, canonical_json, native_manifest
from qcsd_lab.resource_study_native import REQUEST_HEADERS
from qcsd_lab.resource_study_store import _json
from tests.test_resource_study_lineage import campaign
from tests.test_resource_study_runtime_cohorts import cohort_campaign

HOST = "www.clarin.com"


def manifest(host, version):
    urls = [f"https://{host}/controlled-v{version}/asset-{index:02d}.js" for index in range(20)]
    value = native_manifest(host, urls, {url: 4096 + index for index, url in enumerate(urls)})
    for row in value["resources"]:
        row["headers"] = deepcopy(REQUEST_HEADERS)
    value["resources"][0]["type"] = "Document"
    return urls, canonical_json(value)


def rehash(cell):
    cell["definition_sha256"] = versions.digest(cell["definition"])
    return cell


@pytest.fixture
def proposal():
    hosts = sorted([HOST, *[f"site-{index:02d}.example" for index in range(49)]])
    assignments = {host: {"client_ipv4": f"10.30.{index}.2", "network": f"10.30.{index}.0/29"}
                   for index, host in enumerate(hosts)}
    leaf = {"assignments": assignments, "predecessor_sha256": "1" * 64}
    transition = {"class_selection": {"selected_hostnames": hosts}, "class_network": leaf}
    cells = []
    for host in hosts:
        urls, raw = manifest(host, 0)
        for mode in sorted(MODES):
            if host == HOST and mode == "buflo":
                continue  # Actual semantic case: never admitted, not a zero-count fake member.
            cell = {"hostname": host, "mode": mode, "root": "/synthetic-old/" + host,
                    "study_sha256": "2" * 64, "enrollment_path": "classes/" + host + "/enrollment.json",
                    "enrollment_sha256": "3" * 64,
                    "definition": {"urls": urls, "workload_sha256": hashlib.sha256(raw).hexdigest(),
                        "settings": {"mode": mode, "unchanged_parameter": 5}, "policies": {"strict": "unchanged"},
                        "native": ["a" * 64, "linux/arm64", "b" * 40], "acceptance": "synthetic-strict-v1",
                        "ready": True, "network": {"mapping_sha256": versions.digest(leaf),
                            "assignment": assignments[host], "tuple_uniqueness_scope": "hostname-mode-study-root"}}}
            cells.append(rehash(cell))
    registry = [{"hostname": cell["hostname"], "mode": cell["mode"],
                 "science": deepcopy(cell["definition"]),
                 "members": [{"cohort_id": versions.digest(cell), "cell": deepcopy(cell),
                              "verifier": {"synthetic_source_only": True}, "frozen_accepted": None}],
                 "writer": versions.digest(cell)} for cell in cells]
    prior = {"record_type": versions.COHORT_ADMISSION, "sequence": 7,
             "parent_study_sha256": "4" * 64, "class_transition": transition,
             "cells": cells, "cohorts": registry}
    donor = deepcopy(next(cell for cell in cells if cell["hostname"] != HOST and cell["mode"] == "buflo"))
    new_urls, new_raw = manifest(HOST, 1)
    replacements = []
    for mode in sorted(MODES):
        cell = deepcopy(next((cell for cell in cells if cell["hostname"] == HOST and cell["mode"] == mode), donor))
        cell.update(hostname=HOST, mode=mode, root="/synthetic-new/" + mode,
                    enrollment_path="classes/" + HOST + "/enrollment.json", enrollment_sha256="5" * 64)
        cell["definition"].update(urls=list(new_urls), workload_sha256=hashlib.sha256(new_raw).hexdigest())
        cell["definition"]["network"]["assignment"] = deepcopy(assignments[HOST])
        replacements.append(rehash(cell))
    rows = []
    for index, (host, mode) in enumerate([(HOST, "undefended"), (HOST, "front"), (hosts[0], "undefended")], 1):
        cell = next(cell for cell in cells if cell["hostname"] == host and cell["mode"] == mode)
        rows.append({"root": cell["root"], "hostname": host, "mode": mode, "slot": 1,
                     "attempt_id": f"{index:032x}",
                     "five_tuple": _json([assignments[host]["client_ipv4"], 31000 + index, "192.0.2.1", 443, 17]).decode(),
                     "receipt_path": f"corpus/{host}/{mode}/session-000001/session.json",
                     "receipt_sha256": str(index) * 64, "accepted_row_sha256": versions.digest({"synthetic_row": index})})
    rows.sort(key=lambda row: (row["hostname"], row["mode"], row["slot"], row["root"]))
    return {"prior": prior, "accepted_rows": rows, "replacement_cells": replacements,
            "application_manifest_raw": new_raw, "hostname": HOST, "missing_mode_templates": [donor],
            "verifier": {"declared_synthetic_metadata_contract": True}}


def template(proposal):
    return versions.replacement_template(**proposal)


def declared(proposal):
    value = template(proposal)
    value.update(resource_replacement_authorized=True,
                 rationale="Declared synthetic same-host all5 resource replacement; no live authority or credit.")
    return value


def receipt(cell):
    native = cell["definition"]["native"]
    return {"hostname": cell["hostname"], "mode": cell["mode"], "purpose": "formal", "slot": 1,
            "attempt_id": "f" * 32, "five_tuple": ["10.30.49.2", 45000, "192.0.2.1", 443, 17],
            "workload_sha256": cell["definition"]["workload_sha256"],
            "runtime": {"client_sha256": native[0], "platform": native[1], "source": {"neqo_commit": native[2]}},
            "mode_settings": deepcopy(cell["definition"]["settings"]),
            "mode_policies": deepcopy(cell["definition"]["policies"]),
            "artifact_paths": {"enrollment": cell["enrollment_path"]},
            "files": {cell["enrollment_path"]: cell["enrollment_sha256"]}}


def test_all5_retirement_is_unissued_zero_carry_and_preserves_exact_history(proposal):
    original = deepcopy(proposal)
    value = template(proposal)
    assert proposal == original
    assert value["resource_replacement_authorized"] is False and value["scientific_credit"] is False
    assert value["retired_target_count"] == 2 and value["prior_accepted_count"] == 3
    assert value["target_eligible_count_after_retirement"] == 1 and value["initial_v1_accepted_count"] == 0
    assert value["retirement"]["rows"] == [row for row in proposal["accepted_rows"] if row["hostname"] == HOST]
    assert value["retirement"]["historically_valid"] is True and value["retirement"]["target_eligible"] is False
    assert value["retirement"]["old_raw_receipts_relabelled_or_deleted"] is False
    assert value["affected_modes"] == sorted(MODES)
    assert {row["mode"] for row in value["affected"] if not row["previously_admitted"]} == {"buflo"}
    assert len(value["selected_hostnames"]) == 50 and value["selected_hostnames"] == original["prior"]["class_transition"]["class_selection"]["selected_hostnames"]
    checked = versions.validate_declaration(declared(proposal), **proposal)
    assert checked["retirement_sha256"] == versions.digest(checked["retirement"])


@pytest.mark.parametrize("mutation", ["no-authorization", "empty-rationale", "old-credit-carry", "drop-old-row", "partial-mode", "relabel-history"])
def test_declared_retirement_refuses_count_scope_and_history_shortcuts(proposal, mutation):
    value = declared(proposal)
    if mutation == "no-authorization": value["resource_replacement_authorized"] = False
    elif mutation == "empty-rationale": value["rationale"] = " "
    elif mutation == "old-credit-carry": value["target_eligible_count_after_retirement"] += 2
    elif mutation == "drop-old-row":
        value["retirement"]["rows"].pop(); value["retirement_sha256"] = versions.digest(value["retirement"])
    elif mutation == "partial-mode": value["affected"].pop()
    else: value["retirement"]["historically_valid"] = False
    with pytest.raises(ValueError):
        versions.validate_declaration(value, **proposal)


@pytest.mark.parametrize("mutation", ["new-head", "other49", "changed-receipt", "lost-receipt"])
def test_declaration_binds_actual_head_unaffected49_and_full_accepted_inventory(proposal, mutation):
    value = declared(proposal)
    if mutation == "new-head": proposal["prior"]["sequence"] += 1
    elif mutation == "other49": proposal["prior"]["cohorts"][0]["science"]["controlled_changed_input"] = True
    elif mutation == "changed-receipt": proposal["accepted_rows"][0]["receipt_sha256"] = "e" * 64
    else: proposal["accepted_rows"].pop()
    with pytest.raises(ValueError):
        versions.validate_declaration(value, **proposal)


@pytest.mark.parametrize("mutation", ["partial", "wrong-host", "mixed20", "mixed-workload", "native", "settings", "policies", "address", "old-root", "forged-missing-mode"])
def test_new_version_cannot_smuggle_another_scientific_or_class_change(proposal, mutation):
    cell = proposal["replacement_cells"][0]
    if mutation == "partial": proposal["replacement_cells"].pop()
    elif mutation == "wrong-host": cell["hostname"] = "another.example"
    elif mutation == "mixed20": cell["definition"]["urls"][0] += "?changed=1"
    elif mutation == "mixed-workload": cell["definition"]["workload_sha256"] = "e" * 64
    elif mutation == "native": cell["definition"]["native"][0] = "e" * 64
    elif mutation == "settings": cell["definition"]["settings"]["unchanged_parameter"] = 6
    elif mutation == "policies": cell["definition"]["policies"]["strict"] = "waived"
    elif mutation == "address": cell["definition"]["network"]["assignment"]["client_ipv4"] = "10.99.1.2"
    elif mutation == "old-root": cell["root"] = proposal["prior"]["cells"][0]["root"]
    else: proposal["missing_mode_templates"][0]["enrollment_sha256"] = "e" * 64
    rehash(cell)
    with pytest.raises(ValueError):
        template(proposal)


def test_one_unready_mode_does_not_block_other_ready_mode_binding(proposal):
    front = next(cell for cell in proposal["replacement_cells"] if cell["mode"] == "front")
    front["definition"]["ready"] = False; rehash(front)
    value = declared(proposal)
    versions.validate_declaration(value, **proposal)
    cs = next(cell for cell in proposal["replacement_cells"] if cell["mode"] == "cs-buflo")
    bound = versions.validate_target_receipt_binding(receipt(cs), cs, value)
    assert bound["historical_v0_target_carry"] == 0 and bound["mode"] == "cs-buflo"
    assert "verified" not in bound and "scientific_credit" not in bound
    with pytest.raises(ValueError, match="unready"):
        versions.validate_target_receipt_binding(receipt(front), front, value)


@pytest.mark.parametrize("mutation", ["old-workload", "old-tuple", "old-attempt", "wrong-native", "wrong-settings", "wrong-enrollment", "engineering", "slot0", "slot401"])
def test_target_binding_refuses_old_identity_and_cannot_replace_original_raw_gates(proposal, mutation):
    value = declared(proposal)
    cell = next(cell for cell in proposal["replacement_cells"] if cell["mode"] == "front")
    actual = receipt(cell)
    retired = next(row for row in value["retirement"]["rows"] if row["mode"] == "front")
    if mutation == "old-workload": actual["workload_sha256"] = value["retirement"]["old_workload_sha256"]
    elif mutation == "old-tuple":
        import json
        actual["five_tuple"] = json.loads(retired["five_tuple"])
    elif mutation == "old-attempt": actual["attempt_id"] = retired["attempt_id"]
    elif mutation == "wrong-native": actual["runtime"]["client_sha256"] = "e" * 64
    elif mutation == "wrong-settings": actual["mode_settings"]["unchanged_parameter"] = 99
    elif mutation == "wrong-enrollment": actual["files"][cell["enrollment_path"]] = "e" * 64
    elif mutation == "engineering": actual["purpose"] = "engineering"
    elif mutation == "slot0": actual["slot"] = 0
    else: actual["slot"] = 401
    actual["verified"] = True  # A JSON flag cannot rescue a failed resource/member binding.
    with pytest.raises(ValueError):
        versions.validate_target_receipt_binding(actual, cell, value)


def test_actual_disposable_cohort_history_is_never_rewritten_or_carried_into_v1(cohort_campaign, tmp_path):
    """Real original member/index/receipt bindings; no resource admission issued."""
    import json
    from qcsd_lab import resource_study_cohorts as cohorts
    from qcsd_lab import resource_study_epochs as epochs
    from tests.test_resource_study_runtime_cohorts import HOST as actual_host

    campaign = cohort_campaign
    campaign.append(campaign.fresh())
    before_head = deepcopy(epochs._records(campaign.parent)[-1])
    before_receipt = campaign.old_receipt.read_bytes()
    before_status = cohorts.status(campaign.parent.root)
    old_rows = cohorts._manifest(before_head["cohorts"])
    assert len(old_rows) == 1 and old_rows[0]["receipt_sha256"] == hashlib.sha256(before_receipt).hexdigest()
    new_urls, new_raw = manifest(actual_host, 1)
    candidates = []
    for mode in sorted(MODES):
        cell = deepcopy(next(cell for cell in before_head["cells"] if cell["hostname"] == actual_host and cell["mode"] == mode))
        cell["root"] = str(tmp_path / ("unissued-resource-v1-" + mode))
        cell["definition"].update(urls=list(new_urls), workload_sha256=hashlib.sha256(new_raw).hexdigest())
        candidates.append(rehash(cell))
    kwargs = {"prior": before_head, "accepted_rows": old_rows, "replacement_cells": candidates,
              "application_manifest_raw": new_raw, "hostname": actual_host, "verifier": cohorts.verifier_contract()}
    value = versions.replacement_template(**kwargs)
    value.update(resource_replacement_authorized=True, rationale="Disposable metadata kernel only; no admission issued.")
    versions.validate_declaration(value, **kwargs)
    assert value["retirement"]["rows"] == old_rows
    assert value["retired_target_count"] == 1 and value["target_eligible_count_after_retirement"] == 0
    assert value["initial_v1_accepted_count"] == 0
    front = next(cell for cell in candidates if cell["mode"] == "front")
    reused = receipt(front)
    reused["five_tuple"] = json.loads(before_receipt)["five_tuple"]
    with pytest.raises(ValueError, match="reuse"):
        versions.validate_target_receipt_binding(reused, front, value)
    assert epochs._records(campaign.parent)[-1] == before_head
    assert campaign.old_receipt.read_bytes() == before_receipt
    assert cohorts.status(campaign.parent.root) == before_status
    assert campaign.old.status()["accepted_count"] == 1


def resource_entry(proposal):
    """Declared metadata only; normalize with the original logical science rule."""
    cell = deepcopy(next(cell for cell in proposal["replacement_cells"] if cell["mode"] == "front"))
    old = deepcopy(next(entry for entry in proposal["prior"]["cohorts"]
                        if (entry["hostname"], entry["mode"]) == (HOST, "front")))
    def science(value):
        result = deepcopy(value["definition"])
        del result["native"]; del result["ready"]
        result["network"].pop("mapping_sha256")
        return result
    old_science = science(old["members"][0]["cell"])
    old["members"][0]["frozen_accepted"] = {"path": "runtime-cohorts/declared.json", "sha256": "c" * 64}
    member = {"cohort_id": versions.digest(cell), "cell": cell,
              "verifier": deepcopy(proposal["verifier"]), "frozen_accepted": None}
    declaration = declared(proposal)
    relation = {"record_type": versions.STRATA, "schema_version": 1, "policy": versions.POLICY,
        "declaration": {"path": "/synthetic-retirement.json", "sha256": versions.digest(declaration)},
        "strata": [{"version": 0, "science": old_science,
                    "members": [old["members"][0]["cohort_id"]], "target_eligible": False},
                   {"version": 1, "science": science(cell),
                    "members": [member["cohort_id"]], "target_eligible": True}]}
    return {"hostname": HOST, "mode": "front", "science": science(cell),
            "members": [*old["members"], member], "writer": member["cohort_id"],
            "resource_versions": relation}, declaration


@pytest.mark.parametrize("mutation", ["credit-v0", "omit-old", "unfreeze-old", "mixed-science", "third-version"])
def test_resource_member_strata_refuse_old_credit_and_ancestry_rewrite(proposal, mutation):
    entry, _ = resource_entry(proposal)
    assert versions.target_member_ids(entry) == {entry["writer"]}
    if mutation == "credit-v0": entry["resource_versions"]["strata"][0]["target_eligible"] = True
    elif mutation == "omit-old": entry["resource_versions"]["strata"][0]["members"] = []
    elif mutation == "unfreeze-old": entry["members"][0]["frozen_accepted"] = None
    elif mutation == "mixed-science": entry["resource_versions"]["strata"][0]["science"]["settings"]["changed"] = True
    else: entry["resource_versions"]["strata"].append(deepcopy(entry["resource_versions"]["strata"][-1]))
    with pytest.raises(ValueError):
        versions.member_sciences(entry)


def test_explicit_later_native_member_keeps_v1_resources_without_reactivating_v0(proposal):
    entry, declaration = resource_entry(proposal)
    before = deepcopy(entry)
    entry["members"][-1]["frozen_accepted"] = {"path": "runtime-cohorts/later.json", "sha256": "c" * 64}
    new_member = deepcopy(entry["members"][-1]); cell = new_member["cell"]
    cell["root"] = "/synthetic-subsequent-native"
    cell["definition"]["native"][0] = "e" * 64
    rehash(cell)
    new_member["cohort_id"] = versions.digest(cell); new_member["frozen_accepted"] = None
    entry["members"].append(new_member); entry["writer"] = new_member["cohort_id"]
    entry["resource_versions"]["strata"][-1]["members"].append(new_member["cohort_id"])
    assert versions.target_member_ids(entry) == {*versions.target_member_ids(before), new_member["cohort_id"]}
    result = versions.validate_target_receipt_binding(receipt(cell), cell, declaration, resource_entry=entry)
    assert result["historical_v0_target_carry"] == 0
    retired = entry["members"][0]["cell"]
    with pytest.raises(ValueError, match="exact all5"):
        versions.validate_target_receipt_binding(receipt(retired), retired, declaration, resource_entry=entry)
