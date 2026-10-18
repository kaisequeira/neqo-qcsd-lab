"""Prospective083 entry/exit byte-read regression over original real fixtures.

Only an observing delegate of the original _records_file is installed before
CaptureAuthority snapshots its implementation identities. All FD/path/stamp,
source, Docker flock, SQL, admission, pilot and mutation guards remain real.
The inherited fixture's preparation/raw-proof leaves remain synthetic; these
controls issue no acquisition or scientific qualification.
"""
from collections import Counter
import os
import sys
import pytest
from qcsd_lab import resource_study_cohorts as cohorts
from tests.test_resource_study_capture_authority import campaign, lock_home, scoped
from tests.test_resource_study_runtime_cohorts import cohort_campaign
pytestmark=pytest.mark.skipif(sys.platform!='linux',reason='genuine Linux fdinfo/flock authority')

def test_owned_immutable_inputs_hash_at_entry_exit_and_fence_each_callback(cohort_campaign,lock_home,monkeypatch):
    c=cohort_campaign
    content_reads=Counter();metadata_reads=Counter()
    original=cohorts._records_file
    def observed(path,*,content=False):
        (content_reads if content else metadata_reads)[str(path)]+=1
        return original(path,content=content)
    # This delegates the exact original guard; it cannot make a failed check
    # positive. Install before the original implementation identity snapshot.
    monkeypatch.setattr(cohorts,'_records_file',observed)
    with scoped(c.old)as(auth,_):
        bound=set(auth.files)
        assert str(c.parent.root/'epoch-admissions/000000.json')in bound
        assert str(c.old.root/'study.json')in bound
        assert all(content_reads[path]>=1 for path in bound),'entry must hash every immutable payload'
        content_reads.clear();metadata_reads.clear()
        with cohorts.capture_records_scope(c.parent,writer_root=c.old.root,latest_only=True)as records:
            assert records==auth.records[-1:]
        assert not content_reads,'interior callbacks must reuse the owned immutable-byte observations'
        assert all(metadata_reads[path]>=2 for path in bound),'both callback boundaries must reopen/fence every immutable FD/path/stamp'
        content_reads.clear();metadata_reads.clear()
    assert all(content_reads[path]>=2 for path in bound),'closure must fully hash every immutable payload before and after original full ancestry validation'


@pytest.mark.parametrize("mutation", ["same-size-restored-mtime", "replacement-inode", "writable-mode", "extra-hardlink"])
def test_interior_rejects_changed_real_file_metadata_without_reading_body(cohort_campaign, lock_home, monkeypatch, mutation):
    """Actual immutable-file attacks, with original FD checks delegated whole.

    Restoring mtime does not restore ctime; replacing identical bytes does not
    restore inode identity. Mode and hardlink failures are observed from the
    freshly opened actual FD. No positive guard or stable stamp is mocked.
    """
    c = cohort_campaign
    body_reads = Counter()
    original = cohorts._records_file

    def observed(path, *, content=False):
        if content:
            body_reads[str(path)] += 1
        return original(path, content=content)

    monkeypatch.setattr(cohorts, "_records_file", observed)
    # Closing damaged ancestry must also refuse. The nested assertion ensures
    # that a later exit error cannot hide an incorrectly successful callback.
    with pytest.raises((ValueError, OSError)):
        with scoped(c.old) as (auth, _):
            path = c.parent.root / "study.json"
            assert str(path) in auth.files
            before = path.stat()
            raw = path.read_bytes()
            assert raw
            if mutation == "same-size-restored-mtime":
                path.chmod(0o644)
                path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                path.chmod(0o444)
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                after = path.stat()
                assert after.st_size == before.st_size
                assert after.st_mtime_ns == before.st_mtime_ns
                assert after.st_ctime_ns != before.st_ctime_ns
            elif mutation == "replacement-inode":
                replacement = path.with_name("replacement-authority-input.json")
                with replacement.open("xb") as stream:
                    stream.write(raw)
                replacement.chmod(0o444)
                os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
                os.replace(replacement, path)
                assert path.stat().st_ino != before.st_ino
                assert path.read_bytes() == raw
            elif mutation == "writable-mode":
                path.chmod(0o644)
            else:
                os.link(path, path.with_name("unexpected-authority-hardlink.json"))
                assert path.stat().st_nlink == 2
            body_reads.clear()
            with pytest.raises((ValueError, OSError)):
                with cohorts.capture_records_scope(c.parent, writer_root=c.old.root, latest_only=True):
                    pytest.fail("changed authority input escaped the fresh FD/stamp check")
            assert not body_reads, "interior rejection must occur without reading immutable bodies"


def test_full_byte_policy_is_an_explicit_boolean_and_invalid_calls_do_not_break_owner(cohort_campaign, lock_home):
    c = cohort_campaign
    with scoped(c.old) as (auth, _):
        for invalid in (None, 0, 1, "true"):
            with pytest.raises(ValueError, match="explicit boolean"):
                auth.check(full_bytes=invalid)
        # The original same owner remains valid after rejected policy inputs.
        auth.check()
        auth.check(full_bytes=True)
