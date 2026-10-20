"""One real Linux catalog authority; topology/raw leaves are synthetic only.

The public catalog coordinator, actual Docker flock/fdinfo owner, full cohort
history, Source authority, all-root SQL callbacks and reserve/seal/commit run.
Only the Docker topology/backend factory and packet-verifier fixtures are
controlled. These controls create no Native, pilot or scientific evidence.
"""
from contextlib import contextmanager
import json
import sys
import threading

import pytest

from qcsd_lab import resource_study_catalog as catalog
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_runtime as runtime
from qcsd_lab.resource_study_store import StudyStore
from tests.test_resource_study_capture_authority import attack_sql, lock_home
from tests.test_resource_study_catalog import CatalogBackend, catalog_writers, pilots
from tests.test_resource_study_lineage import campaign


pytestmark=pytest.mark.skipif(sys.platform!="linux",reason="actual kernel fdinfo/flock authority")


class OwnedTopologyLeaf(CatalogBackend):
    """Synthetic Docker/raw boundary; never fabricates the capture authority."""
    def __init__(self,roots,authority,*,on_enter=None,restore=None,overlap=False):
        super().__init__(roots,overlap=overlap)
        assert type(authority)is cohorts._CaptureAuthority
        self.authority=authority;self.owner=authority.docker_owner
        self.on_enter=on_enter;self.restore=restore;self.cleanup_count=0

    def __enter__(self):
        super().__enter__()
        if self.on_enter is not None:self.on_enter()
        return self

    def __exit__(self,*errors):
        self.cleanup_count+=1
        if self.restore is not None:self.restore()
        assert self.owner.active and self.authority.active
        return super().__exit__(*errors)

    @contextmanager
    def capture_authority_scope(self):
        # Production runtime tests separately exercise the actual backend's
        # private identity checker. This leaf merely hands the real already
        # bound authority to original coordinator/worker callbacks.
        assert cohorts._CAPTURE_AUTHORITY.get()==(self.authority,threading.get_ident(),None)
        self._capture_authority=self.authority
        try:yield self.authority
        finally:del self._capture_authority


def topology_factory(monkeypatch,roots,*,on_enter=None,restore=None,overlap=False):
    created=[]
    def idle(*args,**kwargs):
        assert args==("ps","-q")and not kwargs
        return ""
    def factory(contexts,workers,*,cell_roots,host_runtimes,worker_runtime_keys,host_modes,_startup_authority):
        assert set(contexts)=={store.root for store in roots}and workers==2
        assert _startup_authority.writers==frozenset(map(str,contexts))
        backend=OwnedTopologyLeaf(roots,_startup_authority,on_enter=on_enter,restore=restore,overlap=overlap)
        assert tuple(worker_runtime_keys)==backend.runtime_keys
        assert set(cell_roots)==set(host_runtimes)==set(host_modes)
        assert all(cell_roots[host]in contexts for host in cell_roots)
        created.append(backend);return backend
    monkeypatch.setattr(runtime,"_docker",idle)
    monkeypatch.setattr(runtime,"CatalogCaptureRuntime",factory)
    return created


def test_public_catalog_one_full_history_before_reservation_and_live_credit(catalog_writers,lock_home,monkeypatch):
    parent,roots,value=catalog_writers;pilots(roots)
    created=topology_factory(monkeypatch,roots,overlap=True)
    history=[0];at_reservation=[]
    history_code=cohorts._records.__code__;reserve_code=StudyStore._allocate_attempt.__code__
    previous=sys.getprofile();thread_previous=threading.getprofile()
    def profile(frame,event,arg):
        if event=="call":
            if frame.f_code is history_code:history[0]+=1
            elif frame.f_code is reserve_code:at_reservation.append(history[0])
    sys.setprofile(profile);threading.setprofile(profile)
    try:
        result=catalog.capture_catalog(parent.root,value,workers=2,budget=2,chunk_sessions=1)
    finally:
        sys.setprofile(previous);threading.setprofile(thread_previous)
    backend=created[0]
    assert history==[1]and at_reservation==[1,1]
    assert len(backend.calls)==2 and backend.max_busy==2 and backend.cleanup_count==1
    assert backend.closed and not backend.owner.active and not backend.authority.active
    assert result["catalog"]==value and not result["paused_cells"]
    assert sum(store.status()["accepted_count"]for store in roots)==2


def test_owned_catalog_rechecks_head_and_class_SQL_before_first_reservation(catalog_writers,lock_home,monkeypatch):
    parent,roots,value=catalog_writers;pilots(roots)
    for mutation in("head","class"):
        if mutation=="head":
            original=epochs._meta(parent,"epoch_head")
            changed=json.loads(original);changed["sha256"]="e"*64
            def attack():attack_sql(parent,"UPDATE meta SET value=? WHERE key='epoch_head'",(json.dumps(changed),))
            def restore():attack_sql(parent,"UPDATE meta SET value=? WHERE key='epoch_head'",(original,))
        else:
            store=roots[0]
            with store._transaction()as connection:
                host,digest=connection.execute("SELECT hostname,sha256 FROM classes ORDER BY hostname LIMIT 1").fetchone()
            def attack():attack_sql(store,"UPDATE classes SET sha256=? WHERE hostname=?",("0"*64,host))
            def restore():attack_sql(store,"UPDATE classes SET sha256=? WHERE hostname=?",(digest,host))
        created=topology_factory(monkeypatch,roots,on_enter=attack,restore=restore)
        with pytest.raises((ValueError,OSError)):
            catalog.capture_catalog(parent.root,value,workers=2,budget=2,chunk_sessions=1)
        backend=created[0]
        assert backend.calls==[] and backend.cleanup_count==1 and backend.closed
        assert not backend.owner.active and not backend.authority.active
        for store in roots:
            with store._transaction()as connection:
                assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==0


def test_owned_catalog_changed_bound_file_refuses_before_first_reservation(catalog_writers,lock_home,monkeypatch):
    parent,roots,value=catalog_writers;pilots(roots)
    path=parent.root/"study.json";raw=path.read_bytes()
    def attack():
        path.chmod(0o644);path.write_bytes(raw+b"\n");path.chmod(0o444)
    def restore():
        # Restore fixture bytes, never claim that changed inode stamps are the
        # original immutable authority. Original finish must refuse them too.
        path.chmod(0o644);path.write_bytes(raw);path.chmod(0o444)
    created=topology_factory(monkeypatch,roots,on_enter=attack,restore=restore)
    with pytest.raises((ValueError,OSError)):
        catalog.capture_catalog(parent.root,value,workers=2,budget=2,chunk_sessions=1)
    backend=created[0]
    assert backend.calls==[]and backend.cleanup_count==1 and backend.closed
    assert not backend.owner.active and not backend.authority.active
    assert path.read_bytes()==raw
    for store in roots:
        with store._transaction()as connection:
            assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]==0
