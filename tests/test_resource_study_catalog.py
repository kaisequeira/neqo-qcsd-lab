"""Real cohort/SQL/catalog controls with explicit synthetic packet boundaries.

ROOT executes these later. Preparation/raw packet proof and Docker are controlled
fixture leaves; reservation, publication, tuple/quota/head and commit remain real.
No fixture output is Native evidence, a public pilot, or scientific credit.
"""
from copy import deepcopy
import json
from pathlib import Path
import threading

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_catalog as catalog
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_network as network
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab import resource_study_verify_child as verify_child
from qcsd_lab.resource_study_inputs import canonical_json,sha256_file
from qcsd_lab.resource_study_store import StudyStore,_create
from tests.test_resource_study import CaptureBackend
from tests.test_resource_study_epochs import controlled_pilot
from tests.test_resource_study_lineage import campaign,admit,rewrite

HOSTS=(lineage.INCLUDED,"alpha.example")
MODES=(("buflo","undefended"),("front",))


def raw_leaf(root,receipt):
    return {"verified":True,"five_tuple":receipt.get("five_tuple")}


def synthetic_child_verify(owner,root,receipt):
    """Same declared raw leaf at the new exec boundary; no child claim."""
    return raw_leaf(root,receipt),{
        "fixture":"declared-synthetic-packet-verifier-boundary",
        "actual_child_executed":False,"capacity":owner.capacity}


def native(index):
    value=deepcopy(runtime.SHARED_NATIVE)
    char="ab"[index]
    value.update(canonical_sha256=char*64,client_sha256=char*64,native_commit=char*40,
        collection_image_digest="sha256:"+char*64,prepare_image_digest="sha256:"+char*64,
        source={"neqo_commit":char*40})
    return value


@pytest.fixture
def catalog_writers(campaign,tmp_path,monkeypatch,request):
    parent,child,_=campaign
    mode_groups=getattr(request,"param",MODES)
    old=child("old-native");admit(parent,old)
    for module in(epochs,cohorts,study):monkeypatch.setattr(module,"verify_receipt",raw_leaf)
    # Fresh exec intentionally cannot inherit this memory-only raw fixture.
    # Inject the SAME declared leaf at its public Python call boundary only.
    monkeypatch.setattr(verify_child.VerificationChildren,"verify",synthetic_child_verify)
    roots=[]
    for index,(host,modes)in enumerate(zip(HOSTS,mode_groups)):
        store=StudyStore(tmp_path/("catalog-writer-%d"%index))
        cohorts.initialize_cohort(parent.root,store.root)
        donor=old if host==lineage.INCLUDED else parent
        value=deepcopy(epochs._enrollments(donor)[host][0])
        _create(store.root/value["workload_path"],donor._file(value["workload_path"])[0])
        value["runtime"]=native(index)
        value["source_occurrences"]=study.candidate_pool(store.root)[host]["source_occurrences"]
        store.enroll(lineage.bind_enrollment(store,value))
        declaration=cohorts.compatibility_template(parent.root,store.root,
            affected_hostnames=[host],affected_modes=list(modes))
        declaration.update(compatible_treatment=True,rationale="Explicit synthetic two-runtime catalog metadata test.")
        path=tmp_path/("catalog-declaration-%d.json"%index);_create(path,canonical_json(declaration))
        cohorts.create_cohort(parent.root,store.root,path,sha256_file(path));roots.append(store)
    head=epochs._records(parent)[-1]
    value={"record_type":catalog.CATALOG,"schema_version":1,"parent":str(parent.root),
        "admission":{"sequence":head["sequence"],"sha256":epochs._sha(head)},
        "cells":[{"root":str(store.root),"hostname":host,"mode":mode,"runtime":native(index)}
            for index,(store,host,modes)in enumerate(zip(roots,HOSTS,mode_groups))for mode in modes],
        "worker_runtime_keys":[catalog.runtime_key(native(index))for index in range(2)]}
    return parent,roots,value


def pilots(roots):
    for store,host,modes in zip(roots,HOSTS,MODES):
        for mode in modes:controlled_pilot(store,host,mode)


class CatalogBackend:
    """Synthetic raw leaf; real owning Store reservations and seal/commit run."""
    def __init__(self,roots,*,fail_cell=None,overlap=False):
        self.by_host=dict(zip(HOSTS,roots));self.runtime_keys=tuple(catalog.runtime_key(native(i))for i in range(2))
        self.host_runtime_keys=dict(zip(HOSTS,self.runtime_keys));self.calls=[];self.released=[]
        self.fail_cell=fail_cell;self.lock=threading.Lock();self.busy=set();self.max_busy=0
        self.barrier=threading.Barrier(2)if overlap else None
        self.entered=self.closed=False

    def __enter__(self):self.entered=True;return self
    def __exit__(self,*_):self.closed=True
    def release(self,index):self.released.append(index)

    def capture(self,index,attempt,enrollment):
        host,mode=attempt["hostname"],attempt["mode"];store=self.by_host[host]
        assert catalog.runtime_key(enrollment["runtime"])==self.runtime_keys[index]==self.host_runtime_keys[host]
        with store._transaction()as connection:
            row=connection.execute("SELECT state FROM attempts WHERE attempt_id=?",(attempt["attempt_id"],)).fetchone()
        assert row[0]=="reserved"
        with self.lock:
            assert host not in self.busy
            self.busy.add(host);self.max_busy=max(self.max_busy,len(self.busy))
            self.calls.append((index,deepcopy(attempt),deepcopy(enrollment["runtime"])));number=len(self.calls)
        try:
            if self.barrier is not None and number<=2:self.barrier.wait(timeout=10)
            if(host,mode)==self.fail_cell:
                return {"success":False,"failure":{"stage":"declared-packet-fixture","details":[{"rejected":True}]}}
            CaptureBackend(store.root).write_capture(attempt,enrollment,42000+number)
            directory=store.root/attempt["path"]/"capture"
            run=json.loads((directory/"neqo/run.json").read_bytes())
            ip=store.plan()["class_network"]["assignments"][host]["client_ipv4"]
            run["endpoints"]=[{"id":0,"local_address":f"{ip}:{42000+number}","remote_address":"8.8.8.8:443"}]
            rewrite(directory/"neqo/run.json",run)
            (directory/"class-network.json").write_bytes(canonical_json(network.receipt_binding(store.plan(),sha256_file(store.root/"study.json"),host)))
            (directory/"diagnostics/scheduler-runtime-evidence.json").write_bytes(canonical_json({"fixture":"synthetic packet proof; no scheduler claim"}))
            return {"success":True,"mode_policies":enrollment["mode_policies"][mode]}
        finally:
            with self.lock:self.busy.remove(host)


def test_catalog_two_runtimes_two_hosts_real_reserve_seal_commit(catalog_writers):
    parent,roots,value=catalog_writers;pilots(roots)
    backend=CatalogBackend(roots,overlap=True)
    result=catalog.capture_catalog(parent.root,value,workers=2,budget=2,chunk_sessions=1,backend=backend)
    assert backend.entered and backend.closed and backend.max_busy==2
    assert len(backend.calls)==2 and set(index for index,_,_ in backend.calls)=={0,1}
    assert result["record_type"]==catalog.RESULT and result["catalog"]==value
    assert not result["paused_cells"] and sum(store.status()["accepted_count"]for store in roots)==2
    for store in roots:
        with store._transaction()as connection:rows=connection.execute("SELECT receipt_path FROM accepted").fetchall()
        for row in rows:
            receipt=study.load(store.root/row[0]);binding=receipt["capture_catalog"]
            assert receipt["runtime"]==native(HOSTS.index(receipt["hostname"]))
            assert binding["root"]==str(store.root)and binding["runtime"]==receipt["runtime"]
            assert receipt["coordinator_provenance"]["files"]["resource_study_catalog.py"]==sha256_file(Path(catalog.__file__))


def test_catalog_bf_failure_does_not_pause_healthy_mode_or_runtime(catalog_writers):
    parent,roots,value=catalog_writers;pilots(roots)
    class BoundedHealthyBackend(CatalogBackend):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs);self.bf_terminal=threading.Event()
        def capture(self,index,attempt,enrollment):
            if attempt["hostname"]==HOSTS[1]and any(a["hostname"]==HOSTS[1]for _,a,_ in self.calls):
                # Control only synthetic packet latency: keep the fast healthy
                # lane from consuming the finite budget before BF's third real
                # recorded rejection; no scheduler/accounting guard is patched.
                assert self.bf_terminal.wait(timeout=20)
            value=super().capture(index,attempt,enrollment)
            if sum(a["mode"]=="buflo"for _,a,_ in self.calls)>=3:self.bf_terminal.set()
            return value
    backend=BoundedHealthyBackend(roots,fail_cell=(HOSTS[0],"buflo"))
    result=catalog.capture_catalog(parent.root,value,workers=2,budget=8,chunk_sessions=1,backend=backend)
    assert result["paused_cells"]==[{"root":str(roots[0].root),"hostname":HOSTS[0],"mode":"buflo"}]
    assert cohorts.accepted_count(roots[0],HOSTS[0],"undefended")>0
    assert cohorts.accepted_count(roots[1],HOSTS[1],"front")>0
    with roots[0]._transaction()as connection:
        failures=connection.execute("SELECT COUNT(*) FROM attempts WHERE mode='buflo' AND state='failed'").fetchone()[0]
    assert failures==3


def test_catalog_missing_own_pilot_blocks_only_its_cell(catalog_writers):
    parent,roots,value=catalog_writers
    controlled_pilot(roots[0],HOSTS[0],"undefended");controlled_pilot(roots[1],HOSTS[1],"front")
    backend=CatalogBackend(roots)
    result=catalog.capture_catalog(parent.root,value,workers=2,budget=2,chunk_sessions=1,backend=backend)
    assert result["missing_mode_pilots"]==[{"root":str(roots[0].root),"hostname":HOSTS[0],"mode":"buflo"}]
    assert all(attempt["mode"]!="buflo"for _,attempt,_ in backend.calls)


def test_catalog_rejects_stale_head_before_backend_or_reservation(catalog_writers):
    parent,roots,value=catalog_writers
    value["admission"]["sha256"]="0"*64
    backend=CatalogBackend(roots)
    with pytest.raises(ValueError,match="head"):
        catalog.capture_catalog(parent.root,value,workers=2,budget=1,backend=backend)
    assert not backend.entered
    for store in roots:
        with store._transaction()as connection:
            assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==0


def test_catalog_rejoins_unrelated_admission_after_backend_entry(catalog_writers,tmp_path):
    parent,roots,value=catalog_writers;pilots(roots)
    # Prepare an unrelated FRONT admission for the first hostname. Its selected
    # catalog BF/U writers remain unchanged, so only the exact-head rejoin can
    # detect this real gap between catalog validation and backend entry.
    other=StudyStore(tmp_path/"unrelated-front-writer")
    cohorts.initialize_cohort(parent.root,other.root)
    enrollment=deepcopy(epochs._enrollments(roots[0])[HOSTS[0]][0])
    _create(other.root/enrollment["workload_path"],roots[0]._file(enrollment["workload_path"])[0])
    enrollment["runtime"]=native(1)
    enrollment["source_occurrences"]=study.candidate_pool(other.root)[HOSTS[0]]["source_occurrences"]
    other.enroll(lineage.bind_enrollment(other,enrollment))
    declaration=cohorts.compatibility_template(parent.root,other.root,
        affected_hostnames=[HOSTS[0]],affected_modes=["front"])
    declaration.update(compatible_treatment=True,rationale="Synthetic valid unrelated admission in catalog startup gap.")
    path=tmp_path/"unrelated-declaration.json";_create(path,canonical_json(declaration))
    class AdvancingBackend(CatalogBackend):
        def __enter__(self):
            cohorts.create_cohort(parent.root,other.root,path,sha256_file(path))
            return super().__enter__()
    backend=AdvancingBackend(roots)
    with pytest.raises(ValueError,match="head changed"):
        catalog.capture_catalog(parent.root,value,workers=2,budget=2,backend=backend)
    assert backend.entered and backend.closed and backend.calls==[]
    for store in roots:
        with store._transaction()as connection:
            assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==0


def test_catalog_scope_refusals_preserve_real_writer_metadata(catalog_writers):
    parent,roots,original=catalog_writers
    # These six cases change detached payloads only. Reuse the same genuine
    # immutable cohort/SQL fixture instead of rebuilding it for each refusal.
    for change in("runtime","root","stale-writer","same-host-other-runtime","duplicate","lane-missing"):
        value=deepcopy(original)
        if change=="runtime":
            for row in value["cells"][:2]:row["runtime"]["canonical_sha256"]="f"*64
            value["worker_runtime_keys"][0]=catalog.runtime_key(value["cells"][0]["runtime"])
        elif change=="root":value["cells"][0]["root"]=str(parent.root)
        elif change=="stale-writer":
            for row in value["cells"][:2]:row["root"]=str(roots[1].root)
        elif change=="same-host-other-runtime":value["cells"][1]["runtime"]=native(1)
        elif change=="duplicate":value["cells"].append(deepcopy(value["cells"][0]))
        else:value["worker_runtime_keys"][1]=value["worker_runtime_keys"][0]
        with pytest.raises(ValueError):catalog.catalog_context(parent.root,value)
        assert all(store.status()["accepted_count"]==0 for store in roots),change


@pytest.mark.parametrize("catalog_writers",[(MODES[0],("front","tamaraw","cs-buflo"))],indirect=True)
def test_all_five_modes_keep_own_runtime_and_original_ledger_gates(catalog_writers):
    parent,roots,value=catalog_writers
    by_root={str(store.root):store for store in roots}
    for row in value["cells"]:
        controlled_pilot(by_root[row["root"]],row["hostname"],row["mode"])
    class AllModesBackend(CatalogBackend):
        def __init__(self,roots):
            super().__init__(roots)
            self.ordinary_started=threading.Event()
            self.cs_started=threading.Event()

        def capture(self,index,attempt,enrollment):
            if attempt["mode"]=="undefended":
                self.ordinary_started.set()
            if attempt["mode"]=="cs-buflo":
                self.cs_started.set()
            result=super().capture(index,attempt,enrollment)
            if attempt["mode"]=="undefended":
                assert self.cs_started.wait(timeout=10)
            if attempt["mode"]=="cs-buflo":
                # Hold the third mode on this synthetic lane until the other
                # lane starts its second mode. A fast lane must not consume
                # this test's five-call budget through legitimate repeats.
                assert self.ordinary_started.wait(timeout=10)
            return result

    backend=AllModesBackend(roots)
    result=catalog.capture_catalog(parent.root,value,workers=2,budget=5,
        backend=backend,chunk_sessions=1)
    assert result["paused_cells"]==[] and backend.closed
    assert {attempt["mode"]for _,attempt,_ in backend.calls}==set(study.MODES)
    assert sum(store.status()["accepted_count"]for store in roots)==5


def test_catalog_compatible_lane_and_hostname_fairness_before_reserve():
    cells=[("a.example","buflo"),("a.example","undefended"),("b.example","front")]
    jobs={cells[0]:{"runtime_key":"a"},cells[1]:{"runtime_key":"a"},cells[2]:{"runtime_key":"b"},"_lane_keys":("a","b")}
    counts={cell:0 for cell in cells}
    assert catalog.choose_assignment([1],cells,jobs,counts,set(),set(),{})==(cells[2],1)
    assert catalog.choose_assignment([0,1],cells,jobs,counts,set(),{"a.example"},{})==(cells[2],1)
    assert catalog.choose_assignment([0],cells,jobs,counts,set(),set(),{cells[0]:1})==(cells[1],0)


def test_catalog_cli_main_passes_actual_catalog_workers_budget_and_source(tmp_path,monkeypatch,capsys):
    parent=tmp_path/"parent";path=tmp_path/"catalog.json";digest="a"*64
    declared={"explicit":"stub only for CLI argument join; no admission fabricated"};calls=[]
    def load(actual_path,actual_digest,actual_parent):
        assert(actual_path,actual_digest,actual_parent)==(path,digest,parent);return declared
    def run(actual_parent,actual_catalog,**kwargs):
        calls.append((actual_parent,actual_catalog,kwargs));return {"record_type":catalog.RESULT,"paused_cells":[]}
    monkeypatch.setattr(catalog,"load_capture_catalog",load);monkeypatch.setattr(catalog,"capture_catalog",run)
    code=study.main(["capture-catalog","--root",str(parent),"--catalog",str(path),"--catalog-sha256",digest,
        "--workers","2","--attempts","100000","--chunk","1"])
    assert code==0 and len(calls)==1
    root,actual,kwargs=calls[0]
    assert root==parent and actual is declared and kwargs["workers"]==2 and kwargs["budget"]==100000 and kwargs["chunk_sessions"]==1
    assert kwargs["catalog_source"]=={"path":str(path),"sha256":digest}and isinstance(kwargs["stop"],threading.Event)
    assert json.loads(capsys.readouterr().out)["record_type"]==catalog.RESULT


def test_failed_child_reader_never_reaches_real_store_commit_and_healthy_cell_continues(
        catalog_writers,monkeypatch):
    """An exception from the verifier is a failed attempt, never a receipt."""
    parent,roots,value=catalog_writers;pilots(roots)
    value=deepcopy(value)
    value["cells"]=[row for row in value["cells"]
        if row["mode"]=="buflo" or row["hostname"]==HOSTS[1]]
    calls=[];commits=[]
    original_commit=StudyStore.commit_verified

    def verifier(owner,root,receipt):
        calls.append((str(root),receipt["attempt_id"],receipt["mode"]))
        if receipt["mode"]=="buflo":
            raise ValueError("declared synthetic full raw verifier refusal")
        return synthetic_child_verify(owner,root,receipt)

    def observed_commit(store,*args,**kwargs):
        # Observation only: original Store/epoch/inventory/tuple gates run.
        commits.append(str(store.root))
        return original_commit(store,*args,**kwargs)

    monkeypatch.setattr(verify_child.VerificationChildren,"verify",verifier)
    monkeypatch.setattr(StudyStore,"commit_verified",observed_commit)
    backend=CatalogBackend(roots,overlap=True)
    result=catalog.capture_catalog(parent.root,value,workers=2,budget=2,
        chunk_sessions=1,backend=backend)
    assert len(calls)==2 and {mode for _,_,mode in calls}=={"buflo","front"}
    failed_id=next(identifier for _,identifier,mode in calls if mode=="buflo")
    assert commits==[str(roots[1].root)]
    assert result["paused_cells"]==[
        {"root":str(roots[0].root),"hostname":HOSTS[0],"mode":"buflo"}]
    assert cohorts.accepted_count(roots[0],HOSTS[0],"buflo")==0
    assert cohorts.accepted_count(roots[1],HOSTS[1],"front")==1
    with roots[0]._transaction()as connection:
        row=connection.execute(
            "SELECT state,kind,reason FROM attempts WHERE attempt_id=?",(failed_id,)).fetchone()
    assert row[0:2]==("failed","failed")
    assert "declared synthetic full raw verifier refusal"in row[2]
    assert backend.closed and sorted(backend.released)==[0,1]


def test_catalog_holds_actual_lane_and_zero_credit_until_reader_returns(
        catalog_writers,monkeypatch):
    """The observer releases a blocked synthetic leaf; it never runs a child."""
    parent,roots,value=catalog_writers;pilots(roots)
    value=deepcopy(value)
    value["cells"]=[row for row in value["cells"]
        if row["hostname"]==HOSTS[0]and row["mode"]=="buflo"]
    # Both physical lanes are genuinely compatible with the one selected
    # synthetic runtime; one-host scheduling still permits only one capture.
    key=catalog.runtime_key(native(0));value["worker_runtime_keys"]=[key,key]
    backend=CatalogBackend(roots)
    backend.runtime_keys=(key,key);backend.host_runtime_keys={HOSTS[0]:key}
    entered=threading.Event();resume=threading.Event();observations=[];failures=[]

    def verifier(owner,root,receipt):
        entered.set()
        assert resume.wait(timeout=10),"fixture observer did not release reader"
        return synthetic_child_verify(owner,root,receipt)

    def observe_blocked_reader():
        try:
            assert entered.wait(timeout=10),"actual seal did not reach reader boundary"
            assert backend.released==[]
            with roots[0]._transaction()as connection:
                count=connection.execute("SELECT COUNT(*) FROM accepted").fetchone()[0]
            assert count==0
            observations.append("lane-held-and-original-index-still-zero")
        except BaseException as error:
            failures.append(error)
        finally:
            resume.set()

    monkeypatch.setattr(verify_child.VerificationChildren,"verify",verifier)
    observer=threading.Thread(target=observe_blocked_reader)
    observer.start()
    try:
        result=catalog.capture_catalog(parent.root,value,workers=2,budget=1,
            chunk_sessions=1,backend=backend)
    finally:
        resume.set();observer.join(timeout=10)
    assert not observer.is_alive()and not failures
    assert observations==["lane-held-and-original-index-still-zero"]
    assert cohorts.accepted_count(roots[0],HOSTS[0],"buflo")==1
    assert len(backend.released)==1 and backend.closed
    proof=result["new_formal_verification_timing"]["attempts"][0]["proof"]
    assert proof["actual_child_executed"]is False
    assert proof["fixture"]=="declared-synthetic-packet-verifier-boundary"


@pytest.mark.parametrize("proof_workers",[1,2])
def test_catalog_passes_valid_proof_capacity_without_claiming_fixture_child(
        catalog_writers,proof_workers):
    parent,roots,value=catalog_writers;pilots(roots)
    backend=CatalogBackend(roots)
    result=catalog.capture_catalog(parent.root,value,workers=2,budget=2,
        chunk_sessions=1,backend=backend,proof_workers=proof_workers)
    measured=result["new_formal_verification_timing"]
    assert measured["capacity"]==proof_workers and len(measured["attempts"])==2
    assert all(row["proof"]=={
        "fixture":"declared-synthetic-packet-verifier-boundary",
        "actual_child_executed":False,"capacity":proof_workers}
        for row in measured["attempts"])
    assert sum(store.status()["accepted_count"]for store in roots)==2


def test_invalid_proof_capacity_refuses_before_original_reservation(catalog_writers):
    parent,roots,value=catalog_writers
    for capacity in(0,-1,3,True,1.0,"1",None):
        backend=CatalogBackend(roots)
        with pytest.raises(ValueError,match="capacity"):
            catalog.capture_catalog(parent.root,value,workers=2,budget=1,
                backend=backend,proof_workers=capacity)
        with pytest.raises(ValueError,match="capacity"):
            verify_child.VerificationChildren(capacity)
        assert not backend.entered and backend.calls==[]
    for store in roots:
        with store._transaction()as connection:
            assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==0
