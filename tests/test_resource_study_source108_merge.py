"""ROOT-only integration controls; synthetic packet/child leaves issue no credit."""
from copy import deepcopy
import hashlib,json
from pathlib import Path
import pytest
from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_catalog as catalog
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_reader_compatibility as readers
from qcsd_lab import resource_study_verify_child as child
from qcsd_lab.resource_study_inputs import canonical_json,sha256_file
from tests.test_resource_study import CaptureBackend
from tests.test_resource_study_ang_cs180_condition_integration import original250,HOST,MODE,RUNTIME137
from tests.test_resource_study_runtime_cohorts import controlled_pilot

EXPECTED_GRAPH = '7006c77190dac397356c5f0538b47baa1cfaddda20e72d2fbcae5e358c74fafa'
EXPECTED_CONTRACT = '7c088d9fc31aa214f5c99955460b006191b7742b54ab9a8de9b6d23e2dadcfcf'

def test_current108_exact175_and_parents_are_separate_immutable_profiles():
    current=cohorts.verifier_contract();qualified=readers.qualify_execution(current)
    files=readers.execution_files();package=Path(cohorts.__file__).parent
    assert readers.EXECUTION_KIND=="108" and len(files)==len(cohorts.RAW_DEPENDENCIES)==175
    assert set(files)==set(cohorts.RAW_DEPENDENCIES)
    assert all(sha256_file(package/n)==v for n,v in files.items())
    assert current["transitive_source_sha256"]==EXPECTED_GRAPH
    assert hashlib.sha256(readers._encoded(current)).hexdigest()==EXPECTED_CONTRACT
    for parent,size in ((readers.prior_exact106_execution_contract(),175),
                        (readers.prior_exact107_execution_contract(),171),
                        (readers.prior_exact094_execution_contract(),171),
                        (readers.prior_catalog_owned102_execution_contract(),174)):
        original=readers._encoded(parent)
        assert parent["transitive_source_files"]==size and readers.require_supported(parent,qualified)is True
        binding=readers.execution_binding(parent,qualified)
        assert binding["admission_reader"]==parent and binding["execution_reader"]==current
        assert binding["execution_reader_is_admission_reader"]is False
        assert readers._encoded(parent)==original and binding["scientific_credit_added"]==0
        with pytest.raises(ValueError,match="Source108 execution reader"):
            readers.qualify_execution(parent)
        changed=deepcopy(parent);changed["transitive_source_sha256"]="f"*64
        with pytest.raises(ValueError,match="admission reader"):
            readers.require_supported(changed,qualified)

def test_condition_admission_catalog_preserves_own_pilot_and_child_commit(original250,monkeypatch):
    f=original250;c=f.fresh();prepared=f.prepare(c)
    assert prepared["enrollment"][0]["status"]=="enrolled"
    record=f.admit(c);key=catalog.runtime_key(RUNTIME137)
    value={"record_type":catalog.CATALOG,"schema_version":1,"parent":str(f.parent.root),
        "admission":{"sequence":record["sequence"],"sha256":epochs._sha(record)},
        "cells":[{"root":str(c.store.root),"hostname":HOST,"mode":MODE,"runtime":RUNTIME137}],
        "worker_runtime_keys":[key,key]}
    _,jobs,head=catalog.catalog_context(f.parent.root,value)
    assert jobs[(HOST,MODE)]["runtime"]==RUNTIME137 and head==value["admission"]
    original_receipt=f.old_receipt.read_bytes();calls=[]
    def synthetic_verify(owner,root,receipt):
        calls.append((owner.capacity,deepcopy(receipt)))
        assert receipt["runtime"]==RUNTIME137
        assert receipt["workload_sha256"]=="79b01f4c6f50f7d3ab5860a85bbe48ddf99f5537b3b6eba12003a11486e8e66e"
        return f.raw(root,receipt),{"fixture":"synthetic packet proof at unchanged child boundary","actual_child_executed":False}
    monkeypatch.setattr(child.VerificationChildren,"verify",synthetic_verify)
    class Backend:
        runtime_keys=(key,key);host_runtime_keys={HOST:key}
        def __enter__(self):self.captured=[];self.closed=False;return self
        def __exit__(self,*_):self.closed=True
        def release(self,index):pass
        def capture(self,index,attempt,enrollment):
            self.captured.append(deepcopy(attempt))
            CaptureBackend(c.store.root).write_capture(attempt,enrollment,43001)
            directory=c.store.root/attempt["path"]/"capture"
            run=json.loads((directory/"neqo/run.json").read_bytes())
            ip=c.store.plan()["class_network"]["assignments"][HOST]["client_ipv4"]
            run["endpoints"]=[{"id":0,"local_address":ip+":43001","remote_address":"8.8.8.8:443"}]
            (directory/"neqo/run.json").chmod(0o644)
            (directory/"neqo/run.json").write_bytes(canonical_json(run))
            (directory/"neqo/run.json").chmod(0o444)
            from qcsd_lab import resource_study_network as network
            (directory/"class-network.json").write_bytes(canonical_json(network.receipt_binding(c.store.plan(),sha256_file(c.store.root/"study.json"),HOST)))
            (directory/"diagnostics/scheduler-runtime-evidence.json").write_bytes(canonical_json({"fixture":"synthetic scheduler leaf"}))
            return {"success":True,"mode_policies":enrollment["mode_policies"][MODE]}
    no_pilot=Backend()
    with pytest.raises(ValueError,match="catalog selected cells need their own matching focused pilots"):
        catalog.capture_catalog(f.parent.root,value,workers=2,budget=1,chunk_sessions=1,backend=no_pilot,proof_workers=1)
    assert not hasattr(no_pilot,"captured") and calls==[]
    controlled_pilot(c.store,HOST,MODE);backend=Backend()
    result=catalog.capture_catalog(f.parent.root,value,workers=2,budget=1,chunk_sessions=1,backend=backend,proof_workers=1)
    with c.store._connect() as connection:
        terminal=[dict(row) for row in connection.execute("SELECT state,reason FROM attempts")]
    assert backend.closed and len(backend.captured)==len(calls)==1 and calls[0][0]==1, terminal
    assert cohorts.accepted_count(c.store,HOST,MODE)==2
    assert f.old_receipt.read_bytes()==original_receipt
    assert epochs._records(f.parent)[-1]==record and len(record["cells"])==250

def test_condition_strata_cannot_be_accepted_as_resource_versions(original250):
    f=original250;c=f.fresh();assert f.prepare(c)["enrollment"][0]["status"]=="enrolled"
    record=f.admit(c);entry=deepcopy(cohorts._entry(record["cohorts"],(HOST,MODE)))
    entry["resource_versions"]={"invented":True}
    with pytest.raises(ValueError):cohorts._stratum_sciences(entry)
