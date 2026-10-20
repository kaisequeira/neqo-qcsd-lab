"""ROOT-executed real-filesystem controls; SOURCE author did not run tests.

Only selection's methodology _validate is a disclosed synthetic leaf. The
original three publishers, single-link readers, actual OS exclusive rename,
file/parent fsync, immutable bytes and temporary cleanup remain real.
"""
from pathlib import Path
import ast
import errno
import hashlib
import os
import stat
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest
from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_atomic_publish as atomic
from qcsd_lab import resource_study_selection as selection
from qcsd_lab import resource_study_store as storage


def immutable(path,raw=b"complete immutable fixture\n"):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb")as handle:
        handle.write(raw);handle.flush();os.fsync(handle.fileno());os.fchmod(handle.fileno(),0o444)
    return path


def test_exact_old_create_body_exposes_two_link_window_and_new_reader_stays_strict(tmp_path):
    before=Path(__file__).parent/"source-fixtures109/resource_study_store.py.108-before.txt"
    raw=before.read_bytes()
    assert hashlib.sha256(raw).hexdigest()=="9be2314336482cbceded42b61d70a161add53c1dd74f06d474ce711b0f9656fb"
    text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=="_create")
    seen=[]
    def paused_link(source,destination):
        os.link(source,destination)
        seen.append((destination.stat().st_nlink,source.stat().st_ino,destination.stat().st_ino))
        with pytest.raises(ValueError,match="another hard-link authority"):
            storage._unlinked(destination)
    ns={"Path":Path,"tempfile":tempfile,"os":SimpleNamespace(link=paused_link,fchmod=os.fchmod,fsync=os.fsync),
        "_unlinked":storage._unlinked,"_fsync":storage._fsync}
    exec(compile(ast.get_source_segment(text,node),str(before),"exec"),ns)
    destination=tmp_path/"old.json";ns["_create"](destination,b"exact original publication body\n")
    assert len(seen)==1 and seen[0][0]==2 and seen[0][1]==seen[0][2]
    assert storage._unlinked(destination)==destination and destination.stat().st_nlink==1


def test_actual_atomic_rename_first_visibility_is_single_link_and_full_bytes(tmp_path,monkeypatch):
    source=immutable(tmp_path/".source",b"immutable payload"*4096);destination=tmp_path/"result.json"
    ready=threading.Event();observed=[];failures=[]
    real=atomic._rename_noreplace
    def at_boundary(*args):
        ready.set();return real(*args)
    monkeypatch.setattr(atomic,"_rename_noreplace",at_boundary)
    def reader():
        try:
            assert ready.wait(5)
            until=time.monotonic()+5
            while time.monotonic()<until:
                try:
                    fd=os.open(destination,os.O_RDONLY|os.O_NOFOLLOW)
                except FileNotFoundError:continue
                with os.fdopen(fd,"rb")as stream:
                    info=os.fstat(stream.fileno());raw=stream.read()
                observed.append((info.st_nlink,raw));return
            raise AssertionError("publication not observed")
        except BaseException as error:failures.append(error)
    thread=threading.Thread(target=reader);thread.start()
    try:atomic.publish_noreplace(source,destination)
    finally:thread.join(10)
    assert not thread.is_alive() and not failures
    assert observed==[(1,b"immutable payload"*4096)]
    assert not source.exists() and destination.stat().st_nlink==1


def test_existing_destination_cannot_be_overwritten_or_its_bytes_changed(tmp_path):
    source=immutable(tmp_path/".source",b"new");destination=immutable(tmp_path/"existing",b"original")
    before=(destination.stat().st_ino,destination.read_bytes())
    with pytest.raises(FileExistsError):atomic.publish_noreplace(source,destination)
    assert (destination.stat().st_ino,destination.read_bytes())==before
    assert source.read_bytes()==b"new" and source.stat().st_nlink==destination.stat().st_nlink==1


@pytest.mark.parametrize("kind",["symlink","hardlink","writable"])
def test_wrong_source_authority_is_refused_before_publication(tmp_path,kind):
    source=immutable(tmp_path/".source")
    if kind=="symlink":
        real=source;source=tmp_path/".alias";source.symlink_to(real)
    elif kind=="hardlink":os.link(source,tmp_path/".alias")
    else:source.chmod(0o644)
    destination=tmp_path/"destination"
    with pytest.raises((OSError,ValueError)):atomic.publish_noreplace(source,destination)
    assert not destination.exists()


def test_unsupported_platform_refuses_without_link_fallback(tmp_path,monkeypatch):
    source=immutable(tmp_path/".source");destination=tmp_path/"destination"
    def forbidden(*args,**kwargs):raise AssertionError("hard-link fallback forbidden")
    with monkeypatch.context()as scope:
        scope.setattr(atomic.sys,"platform","unsupported-test-platform")
        scope.setattr(atomic.os,"link",forbidden)
        with pytest.raises(OSError)as caught:atomic.publish_noreplace(source,destination)
        assert caught.value.errno==errno.ENOSYS
    assert source.exists() and not destination.exists() and source.stat().st_nlink==1


def publishers(tmp_path,monkeypatch):
    # The pure methodology validator is irrelevant to the publication test;
    # only this leaf is synthetic. Final selection _read is the original one.
    monkeypatch.setattr(selection,"_validate",lambda *args:None)
    def selected(root,value):
        from qcsd_lab.resource_study_inputs import canonical_json
        raw=canonical_json(value)
        return selection.freeze_selection(root,{"raw":raw,"manifest":value,
            "sha256":hashlib.sha256(raw).hexdigest()})
    def store(path):storage._create(path,b"store immutable fixture\n")
    def study_publish(path):study.create_json(path,{"fixture":"study"})
    def selection_publish(path):
        root=path.parent/path.stem;root.mkdir()
        result=selected(root,{"hostname":"fixture.example","fixture":"selection"})
        return root/result["manifest_path"]
    return store,study_publish,selection_publish


def test_all_three_real_publishers_use_single_link_at_visibility(tmp_path,monkeypatch):
    original=atomic._rename_noreplace;observed=[]
    def boundary(parent_fd,source_name,destination_name,parent):
        original(parent_fd,source_name,destination_name,parent)
        path=parent/destination_name
        observed.append(path)
        assert path.stat().st_nlink==1
        storage._unlinked(path)
    monkeypatch.setattr(atomic,"_rename_noreplace",boundary)
    for i,publish in enumerate(publishers(tmp_path,monkeypatch)):
        publish(tmp_path/("publisher%d.json"%i))
    assert len(observed)==3 and all(path.stat().st_nlink==1 for path in observed)


@pytest.mark.parametrize("which",[0,1,2])
def test_failure_cleans_each_original_temporary_without_destination_or_fallback(tmp_path,monkeypatch,which):
    def unsupported(*args):raise OSError(errno.EOPNOTSUPP,"declared unavailable exclusive rename")
    monkeypatch.setattr(atomic,"_rename_noreplace",unsupported)
    def forbidden(*args,**kwargs):raise AssertionError("hard-link fallback forbidden")
    monkeypatch.setattr(atomic.os,"link",forbidden)
    with pytest.raises(OSError)as caught:publishers(tmp_path,monkeypatch)[which](tmp_path/"failure.json")
    assert caught.value.errno==errno.EOPNOTSUPP
    assert [p for p in tmp_path.rglob("*")if p.is_file()]==[]


def test_all_publishers_keep_existing_destination_and_cleanup_temporary(tmp_path,monkeypatch):
    source=tmp_path/"store.json";immutable(source,b"old-store")
    with pytest.raises(FileExistsError):storage._create(source,b"new-store")
    assert source.read_bytes()==b"old-store"
    path=tmp_path/"study.json";immutable(path,b"old-study")
    with pytest.raises(FileExistsError):study.create_json(path,{"new":True})
    assert path.read_bytes()==b"old-study"
    monkeypatch.setattr(selection,"_validate",lambda *args:None)
    from qcsd_lab.resource_study_inputs import canonical_json
    raw=canonical_json({"hostname":"fixture.example"});digest=hashlib.sha256(raw).hexdigest()
    root=tmp_path/"selection";destination=root/"inputs/resource-selections"/(digest+".json")
    immutable(destination,raw)
    before=(destination.stat().st_ino,destination.read_bytes())
    with pytest.raises(FileExistsError):selection.freeze_selection(root,{"raw":raw,"manifest":{"hostname":"fixture.example"},"sha256":digest})
    assert (destination.stat().st_ino,destination.read_bytes())==before
    assert sorted(p.name for p in destination.parent.iterdir())==[digest+".json"]


def test_repeated_concurrent_publishers_and_strict_readers_never_see_two_links(tmp_path):
    errors=[];done=threading.Event();seen=set();seen_event=threading.Event()
    def reader():
        while not done.is_set():
            for path in tmp_path.glob("visible-*.json"):
                try:
                    storage._unlinked(path)
                    assert path.read_bytes()==b"complete\n" and path.stat().st_nlink==1
                    seen.add(path.name)
                    seen_event.set()
                except BaseException as error:errors.append(error);return
    thread=threading.Thread(target=reader);thread.start()
    try:
        for i in range(64):storage._create(tmp_path/("visible-%03d.json"%i),b"complete\n")
        assert seen_event.wait(5)
    finally:done.set();thread.join(10)
    assert not thread.is_alive() and not errors
    assert len(list(tmp_path.glob("visible-*.json")))==64


def test_different_parent_or_same_name_cannot_be_published(tmp_path):
    source=immutable(tmp_path/".source");other=tmp_path/"other";other.mkdir()
    with pytest.raises(ValueError):atomic.publish_noreplace(source,other/"destination")
    with pytest.raises(ValueError):atomic.publish_noreplace(source,source)
    assert source.exists()
