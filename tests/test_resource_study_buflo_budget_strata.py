"""Prospective budget-ledger controls; synthetic raw leaves, actual authority.

These never certify the synthetic host/runtime or issue campaign credit. The
existing selected50 fixture, frozen files, replay, locks, allocator and commits
remain real. Only its already explicit preparation/raw proof leaves are stubbed.
"""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from qcsd_lab import buflo_duration_budget as budget
from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab.resource_study_inputs import canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, _create
from qcsd_lab.resource_study_supplements import load_inventory_candidates
from tests import test_resource_study_lineage as lineage_fixture
from tests import test_resource_study_runtime_cohorts as cohort_fixture
from tests.test_resource_study_lineage import campaign, rewrite
from tests.test_resource_study_runtime_cohorts import cohort_campaign


def settings(policy):
    modern = policy == budget.CADENCE64_1280_POLICY
    policies = {"application_body_identity_policy": "controlled-existing-unit-policy", "buflo_duration_policy": policy}
    return {"profile": "research-1200", "request_policy": "as-defined", "max_response_bytes": 16777216,
        "udp_payload_ceiling": 1200, "policies": policies,
        "parameters": deepcopy(budget.CADENCE64_1280_PARAMETERS if modern else budget.CADENCE64_PARAMETERS),
        "parameters_sha256": budget.CADENCE64_1280_PARAMETER_SHA256 if modern else budget.CADENCE64_PARAMETER_SHA256,
        "timeout_seconds": 1320 if modern else 680, "capture_seconds": 1380 if modern else 740}


@pytest.fixture
def budget_campaign(request, monkeypatch, tmp_path):
    # Configure the existing fixture before construction, rather than rewriting
    # an already published cell or inventing credited rows.
    original = lineage_fixture.enrollment
    def enrolled(*args, **kwargs):
        value = original(*args, **kwargs)
        value["mode_settings"]["buflo"] = settings(budget.CADENCE64_POLICY)
        value["mode_policies"]["buflo"] = deepcopy(value["mode_settings"]["buflo"]["policies"])
        return value
    monkeypatch.setattr(lineage_fixture, "enrollment", enrolled)
    monkeypatch.setattr(cohort_fixture, "MODE", "buflo")
    c = request.getfixturevalue("cohort_campaign")
    sequence = {"root": 0, "declaration": 0}
    host = cohort_fixture.HOST

    def fresh(*, source=None, policy=budget.CADENCE64_1280_POLICY, native=None, mutate=None):
        source = c.old if source is None else source
        sequence["root"] += 1
        new = StudyStore(tmp_path / ("budget-root-%02d" % sequence["root"]))
        cohorts.initialize_cohort(c.parent.root, new.root)
        value = deepcopy(epochs._enrollments(source)[host][0])
        _create(new.root / value["workload_path"], source._file(value["workload_path"])[0])
        value["mode_settings"]["buflo"] = settings(policy)
        value["mode_policies"]["buflo"] = deepcopy(value["mode_settings"]["buflo"]["policies"])
        if native is not None:
            value["runtime"]["client_sha256"] = native * 64
            value["runtime"]["source"]["neqo_commit"] = native * 40
        candidate = load_inventory_candidates([new.root / lineage.INVENTORY])["candidates"][0]
        value["source_occurrences"] = candidate["source_occurrences"]
        if mutate is not None: mutate(value)
        new.enroll(lineage.bind_enrollment(new, value))
        return new

    def declaration(new, *, authorize=True, mutate=None):
        value = cohorts.budget_template(c.parent.root, new.root,
            affected_hostnames=[host], affected_modes=["buflo"])
        assert value["budget_change_authorized"] is False
        if authorize:
            value.update(budget_change_authorized=True, rationale="Explicit prospective unit methodology amendment; no live qualification.")
        if mutate is not None: mutate(value)
        sequence["declaration"] += 1
        path = tmp_path / ("budget-declaration-%02d.json" % sequence["declaration"])
        _create(path, canonical_json(value))
        return path, sha256_file(path)

    def append(new, **kwargs):
        path, digest = declaration(new, **kwargs)
        return cohorts.create_budget_amendment(c.parent.root, new.root, path, digest)

    return SimpleNamespace(c=c, host=host, fresh=fresh, declaration=declaration, append=append)


def test_budget_admission_retains640_credit_requires_new_matching_pilot_and_labels_strata(budget_campaign):
    b = budget_campaign; c = b.c
    old_head = deepcopy(epochs._records(c.parent)[-1]); old_receipt = c.old_receipt.read_bytes()
    new = b.fresh()
    # The original Native-only API still refuses the changed science.
    with pytest.raises(ValueError, match="unchanged science"):
        cohorts.compatibility_template(c.parent.root, new.root, affected_hostnames=[b.host], affected_modes=["buflo"])
    admitted = b.append(new)
    assert admitted["change"] == "buflo-duration-budget"
    assert admitted["class_transition"] == old_head["class_transition"]
    assert admitted["exclusions"] == old_head["exclusions"]
    assert len(admitted["cells"]) == len(old_head["cells"])
    assert c.old_receipt.read_bytes() == old_receipt
    assert cohorts.accepted_count(new, b.host, "buflo") == 1 and new.status()["accepted_count"] == 0
    with pytest.raises(ValueError, match="genuine matching mode pilot"):
        new.allocate_attempt(b.host, "buflo")
    assert new.status()["reserved"] == 0
    cohort_fixture.controlled_pilot(new, b.host, "buflo")
    c.credit(new, port=31001)
    report = cohorts.status(c.parent.root)
    cell = next(row for row in report["cells"] if (row["hostname"], row["mode"]) == (b.host, "buflo"))
    assert cell["accepted"] == 2 and cell["target"] == 400
    assert [(row["policy"], row["accepted"]) for row in cell["budget_science_strata"]] == [
        (budget.CADENCE64_POLICY, 1), (budget.CADENCE64_1280_POLICY, 1)]
    assert report["complete"] is report["scientific_credit"] is False
    with pytest.raises(ValueError): c.old.allocate_attempt(b.host, "buflo", purpose="pilot")
    assert c.old.commit_verified(c.old_receipt)["idempotent"] is True


@pytest.mark.parametrize("mutation", ["unsigned", "bool-schema", "bool-authority", "policy", "workload", "body-policy", "not-ready", "other-mode"])
def test_budget_amendment_refuses_unsigned_or_extra_science_changes_without_publication(budget_campaign, mutation):
    b = budget_campaign; c = b.c
    def mutate_enrollment(value):
        if mutation == "policy": value["mode_settings"]["buflo"]["parameters"]["max_events"] = 20001
        elif mutation == "workload": value["urls"] = list(reversed(value["urls"]))
        elif mutation == "body-policy": value["mode_policies"]["buflo"]["application_body_identity_policy"] = "weakened"
        elif mutation == "not-ready": value["mode_readiness"]["buflo"] = False
    before = canonical_json(epochs._records(c.parent)[-1]); receipt = c.old_receipt.read_bytes()
    new = None
    with pytest.raises(ValueError):
        new = b.fresh(mutate=mutate_enrollment)
        if mutation == "other-mode":
            cohorts.budget_template(c.parent.root, new.root, affected_hostnames=[b.host], affected_modes=["front"])
        else:
            b.append(new, authorize=mutation != "unsigned", mutate=(
                (lambda d: d.__setitem__("schema_version", True)) if mutation == "bool-schema" else
                (lambda d: d.__setitem__("budget_change_authorized", 1)) if mutation == "bool-authority" else None))
    assert canonical_json(epochs._records(c.parent)[-1]) == before
    assert c.old_receipt.read_bytes() == receipt
    if new is not None:
        assert new.status()["accepted_count"] == 0
        assert not (new.root / cohorts.MARKER).exists()


def test_budget_declaration_refuses_stale_head_and_repeat_or_downgrade(budget_campaign):
    b = budget_campaign; c = b.c
    first = b.fresh(); stale = b.declaration(first)
    second = b.fresh(); b.append(second)
    with pytest.raises(ValueError, match="stale|foreign"):
        cohorts.create_budget_amendment(c.parent.root, first.root, *stale)
    for policy in (budget.CADENCE64_POLICY, budget.CADENCE64_1280_POLICY):
        next_root = b.fresh(source=second, policy=policy)
        with pytest.raises(ValueError): b.declaration(next_root)
    assert cohorts.status(c.parent.root)["accepted_count"] == 1


def test_later_native_only1280_member_preserves_both_strata_and_replay_rejects_reassignment(budget_campaign):
    b = budget_campaign; c = b.c
    new = b.fresh(); b.append(new)
    next_root = b.fresh(source=new, native="b")
    declaration = cohorts.compatibility_template(c.parent.root, next_root.root,
        affected_hostnames=[b.host], affected_modes=["buflo"])
    declaration.update(compatible_treatment=True, rationale="Only the new Native tuple changes within1280 stratum.")
    path = next_root.root / "unit-native-declaration.json"
    _create(path, canonical_json(declaration))
    value = cohorts.create_cohort(c.parent.root, next_root.root, path, sha256_file(path))
    entry = next(row for row in value["cohorts"] if (row["hostname"], row["mode"]) == (b.host, "buflo"))
    assert [len(row["members"]) for row in entry["science_strata"]["strata"]] == [1, 2]
    assert cohorts.status(c.parent.root)["accepted_count"] == 1
    forged = deepcopy(value)
    target = next(row for row in forged["cohorts"] if row["hostname"] == b.host and row["mode"] == "buflo")
    target["science_strata"]["strata"][0]["members"].append(target["science_strata"]["strata"][1]["members"].pop(0))
    with pytest.raises(ValueError, match="strata"):
        cohorts._validate_record(c.parent, epochs._records(c.parent)[:-1], forged)


def test_budget_shared400_counts_historical_credit_and_new_stratum_without_reset(budget_campaign):
    b = budget_campaign; c = b.c
    # Every one of399 historical rows uses an actual controlled commit and a
    # distinct five-tuple. No quota is lowered or accepted row invented.
    for number in range(1, 399): c.credit(c.old, port=31000 + number)
    new = b.fresh(); b.append(new)
    cohort_fixture.controlled_pilot(new, b.host, "buflo")
    attempt = new.allocate_attempt(b.host, "buflo")
    assert attempt["slot"] == 400
    path = cohort_fixture.controlled_credit(new, attempt, commit=False)
    receipt = json.loads(path.read_bytes()); receipt["five_tuple"][1] = 31399; rewrite(path, receipt)
    c.credit(new, path=path)
    assert cohorts.accepted_count(new, b.host, "buflo") == 400
    with pytest.raises(ValueError, match="four hundred|400|quota"):
        new.allocate_attempt(b.host, "buflo")
    row = next(row for row in cohorts.status(c.parent.root)["cells"] if row["hostname"] == b.host and row["mode"] == "buflo")
    assert [s["accepted"] for s in row["budget_science_strata"]] == [399, 1]


def test_budget_public_actions_are_explicit_and_default640_is_unchanged():
    assert budget.preparation_policy() == budget.CADENCE64_POLICY
    for action in ("cohort-buflo-budget-template", "cohort-buflo-budget-admit"):
        args = [action, "--root", "/unit-parent", "--cohort-root", "/unit-new"]
        args += ["--affected-hostname", "unit.example", "--affected-mode", "buflo"] if action.endswith("template") else ["--declaration", "/unit-declaration", "--declaration-sha256", "a" * 64]
        assert study.parser().parse_args(args).action == action
