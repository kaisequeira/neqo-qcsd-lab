"""Prospective Native148 CS160 guard/condition tests; no capture or network.

Science dictionaries and Native tuple are labelled fixtures. Original frozen
SDK128 rejects the new explicit policy; no negative receipt is converted.
"""
from copy import deepcopy
import pytest
from qcsd_lab import resource_study_native as n
from qcsd_lab import resource_study_cohorts as c
from qcsd_lab import resource_study_cs160_preparation as prep
from qcsd_lab import resource_study_reader_compatibility as reader


def old_science():
    return {"hostname":"example.test","urls":["https://example.test/"+str(i)for i in range(20)],
        "workload_sha256":"a"*64,"settings":{"parameters_sha256":n.CS160_PARAMETERS,
        "parameters":{"kind":"cs_buflo","fixed600_fixture":True},"timeout_seconds":120,
        "capture_seconds":180,"policies":{"parameter_policy":"fixed-cs-buflo-cpsp-live-v1"}},
        "policies":{"parameter_policy":"fixed-cs-buflo-cpsp-live-v1"}}


def runtime():
    return {"canonical_sha256":"b"*64,"client_sha256":n.CS160_CLIENT,"platform":"linux/arm64",
        "native_commit":n.CS160_NATIVE,"collection_image_digest":"sha256:"+"c"*64,
        "prepare_image_digest":"sha256:"+"d"*64,
        "source":{"neqo_commit":n.CS160_NATIVE,"neqo_dirty":False,"neqo_patch_sha256":"e"*64,
        "neqo_pinned_commit":n.CS160_NATIVE,"lab_commit":"f"*40,"lab_dirty":False,
        "lab_patch_sha256":"e"*64,"image_digest":None}}


def test_explicit_new_policy_and_old_defaults_remain_separate():
    assert n.cs_duration_policy(None)is None
    assert n.cs_duration_policy(n.CS180_POLICY)==n.CS180_POLICY
    assert n.cs_duration_policy(n.CS160_POLICY)==n.CS160_POLICY
    with pytest.raises(ValueError):n.cs_duration_policy("CS160")
    assert n.mode_policies()["cs-buflo"].get("cs_buflo_duration_policy")is None
    assert n.mode_policies(cs_buflo_duration_policy=n.CS160_POLICY)["cs-buflo"]["cs_buflo_duration_policy"]==n.CS160_POLICY


def test_full_science_changes_only_declared_duration_and_label():
    old=old_science();saved=deepcopy(old);new=c._cs160_science(old)
    assert old==saved and new["urls"]==old["urls"]and new["workload_sha256"]==old["workload_sha256"]
    restored=deepcopy(new);restored["settings"].update(timeout_seconds=120,capture_seconds=180)
    del restored["policies"]["cs_buflo_duration_policy"]
    del restored["settings"]["policies"]["cs_buflo_duration_policy"]
    assert restored==old
    assert new["settings"]["parameters"]==old["settings"]["parameters"]


@pytest.mark.parametrize("mutation",("urls","parameters","timeout","capture","policy","repeated"))
def test_science_refuses_unrelated_or_repeated_change(mutation):
    old=old_science()
    if mutation=="urls":old["urls"]=old["urls"][:19]
    if mutation=="parameters":old["settings"]["parameters_sha256"]="0"*64
    if mutation=="timeout":old["settings"]["timeout_seconds"]=160
    if mutation=="capture":old["settings"]["capture_seconds"]=240
    if mutation=="policy":old["policies"]["parameter_policy"]="foreign"
    if mutation=="repeated":old["policies"]["cs_buflo_duration_policy"]=n.CS160_POLICY
    with pytest.raises(ValueError):c._cs160_science(old)


@pytest.mark.parametrize("field",("native_commit","client_sha256","platform","source","workload"))
def test_scope_requires_actual148_and_frozen_manifest(field):
    value=runtime();workload="a"*64
    if field=="source":value["source"]["neqo_commit"]="0"*40
    elif field=="workload":workload="not-sha"
    else:value[field]="foreign"
    with pytest.raises((ValueError,KeyError)):n._cs160_scope("example.test",value,workload)


def test_actual148_tuple_is_a_scope_fixture_not_a_runtime_claim():
    n._cs160_scope("example.test",runtime(),"a"*64)
    with pytest.raises(ValueError):n.cs_duration_scope(n.CS180_POLICY,"example.test",runtime(),"a"*64)


def test_condition_keeps_whole_old_members_and_shared400():
    science=old_science();entry={"hostname":"example.test","mode":"cs-buflo","science":science,
        "members":[{"cohort_id":"old-a"},{"cohort_id":"old-b"}],"writer":"old-b"}
    target=c._cs160_science(science);strata=c._cs160_strata(entry,target,"new")
    whole={**entry,"science":target,"members":entry["members"]+[{"cohort_id":"new"}],
        "writer":"new","condition_strata":strata}
    assert strata["shared_quota"]==400
    assert c._cs160_condition_sciences(whole)=={"old-a":science,"old-b":science,"new":target}
    changed=deepcopy(whole);changed["condition_strata"]["strata"][0]["science"]["urls"].reverse()
    with pytest.raises(ValueError):c._cs160_condition_sciences(changed)
    changed=deepcopy(whole);changed["writer"]="old-b"
    with pytest.raises(ValueError):c._cs160_condition_sciences(changed)


def test_focused_preparation_retains_old_science_and_new_pure_target():
    old=old_science();prepared={"preparation":{}}
    prep._fixed_science_preflight(old,prepared,"cs-buflo")
    assert prep._prospective(old)==c._cs160_science(old)
    with pytest.raises(ValueError):prep._fixed_science_preflight(old,prepared,"buflo")
    with pytest.raises(ValueError):prep._fixed_science_preflight(old,{"preparation":{"cs_buflo_duration_policy":n.CS180_POLICY}},"cs-buflo")


def test_reader_qualifies_current129_and_preserves_exact_historical128():
    execution=c.verifier_contract();qualified=reader.qualify_execution(execution)
    assert reader.EXECUTION_KIND=="129"
    assert reader.require_supported(reader.prior_exact128_execution_contract(),qualified)is True
    assert reader.require_supported(reader.prior_exact127_execution_contract(),qualified)is True
    assert reader.require_supported(reader.prior_exact126_execution_contract(),qualified)is True
    assert execution["transitive_source_files"]==179

ORIGINAL128_CS_DURATION_POLICY_SOURCE = 'def cs_duration_policy(value):\n    """Only the explicit prospective Ang condition extends the old120s default."""\n    if value is not None and value != CS180_POLICY:\n        raise ValueError("unsupported explicit CS duration policy")\n    return value'

def test_genuine_original128_policy_leaf_refuses_new_condition_before_new_leaf_accepts():
    namespace={"CS180_POLICY":n.CS180_POLICY}
    exec(compile(ORIGINAL128_CS_DURATION_POLICY_SOURCE,"<actual-frozen128-duration-policy>","exec"),namespace)
    with pytest.raises(ValueError,match="unsupported explicit CS duration policy"):
        namespace["cs_duration_policy"](n.CS160_POLICY)
    assert namespace["cs_duration_policy"](n.CS180_POLICY)==n.CS180_POLICY
    assert n.cs_duration_policy(n.CS160_POLICY)==n.CS160_POLICY


def test_pair_keeps_every_full_science_field_and_original50(monkeypatch):
    old={"hostname":"example.test","mode":"cs-buflo","definition":{
        **old_science(),"native":["1"*64,"linux/arm64","2"*40],"ready":True,
        "acceptance":{"literal_original_guard":True},"network":{"literal_mapping":"unchanged"}}}
    new=deepcopy(old);new["definition"]=c._cs160_science(old["definition"])
    new["definition"].update(native=[n.CS160_CLIENT,"linux/arm64",n.CS160_NATIVE],ready=True)
    transition={"class_selection":{"selected_hostnames":["example.test"]+["host"+str(i)+".test"for i in range(49)]}}
    # The fixture substitutes only already-authenticated lineage projection.
    # No current parent, Native runtime or preparation is represented by it.
    monkeypatch.setattr(c,"_science",lambda cell,_:{k:deepcopy(v)for k,v in cell["definition"].items()if k not in("native","ready")})
    c._cs160_pair(old,new,transition)
    for field in ("urls","acceptance","network","native","workload_sha256"):
        wrong=deepcopy(new)
        if field=="urls":wrong["definition"][field].reverse()
        elif field=="native":wrong["definition"][field][2]="0"*40
        elif field=="workload_sha256":wrong["definition"][field]="0"*64
        else:wrong["definition"][field]["foreign"]=True
        with pytest.raises(ValueError):c._cs160_pair(old,wrong,transition)
    with pytest.raises(ValueError):c._cs160_pair(old,new,{"class_selection":{"selected_hostnames":["example.test"]}})
