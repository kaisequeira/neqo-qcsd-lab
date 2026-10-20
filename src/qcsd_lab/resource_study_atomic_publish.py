"""Atomic immutable publication without a second hard-link authority.

Only already complete, fsynced,0444 singly linked temporary files may move.
No overwrite, hard-link fallback, retry, or reader relaxation is provided.
Callers retain their original directory fsync and temporary-file cleanup.
"""
from __future__ import annotations
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import stat
import sys

def _need(value,message):
    if not value:raise ValueError(message)

def _stamp(info):
    return(info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,
           info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def _content_identity(info):
    # Renaming may update ctime, but cannot change data, ownership or links.
    return(info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,
           info.st_size,info.st_mtime_ns)

def _hash_fd(fd):
    before=os.fstat(fd);os.lseek(fd,0,os.SEEK_SET);digest=hashlib.sha256();size=0
    for block in iter(lambda:os.read(fd,1024**2),b''):
        digest.update(block);size+=len(block)
    after=os.fstat(fd)
    _need(size==before.st_size and _stamp(before)==_stamp(after),
          'immutable publication source changed during FD hash')
    return digest.digest()

def _rename_noreplace(parent_fd,source_name,destination_name,parent):
    libc=ctypes.CDLL(None,use_errno=True)
    if sys.platform.startswith('linux'):
        try:call=libc.renameat2
        except AttributeError as error:
            raise OSError(errno.ENOSYS,'atomic no-replace renameat2 is unavailable')from error
        call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
        call.restype=ctypes.c_int
        result=call(parent_fd,os.fsencode(source_name),parent_fd,os.fsencode(destination_name),1)
    elif sys.platform=='darwin':
        try:call=libc.renamex_np
        except AttributeError as error:
            raise OSError(errno.ENOSYS,'atomic exclusive renamex_np is unavailable')from error
        call.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint)
        call.restype=ctypes.c_int
        result=call(os.fsencode(parent/source_name),os.fsencode(parent/destination_name),4)
    else:
        raise OSError(errno.ENOSYS,'this platform has no reviewed atomic no-replace publisher')
    if result!=0:
        error=ctypes.get_errno()
        raise OSError(error,os.strerror(error),str(parent/destination_name))

def publish_noreplace(temporary,destination):
    """Move one held immutable inode; an existing destination remains unchanged."""
    temporary,destination=Path(temporary).absolute(),Path(destination).absolute()
    parent=temporary.parent
    _need(parent==destination.parent and temporary.name!=destination.name
          and '..'not in temporary.parts and '..'not in destination.parts
          and all(not p.is_symlink()for p in(parent,*parent.parents))
          and parent.resolve(strict=True)==parent,
          'atomic publication requires one canonical nonsymlink parent')
    directory_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    source_fd=None;published_fd=None
    try:
        directory=os.fstat(directory_fd)
        _need(stat.S_ISDIR(directory.st_mode)
              and(directory.st_dev,directory.st_ino)==(parent.stat().st_dev,parent.stat().st_ino),
              'publication parent FD/path differs')
        source_fd=os.open(temporary.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
        before=os.fstat(source_fd)
        _need(stat.S_ISREG(before.st_mode)and before.st_nlink==1
              and stat.S_IMODE(before.st_mode)==0o444
              and _stamp(before)==_stamp(os.stat(temporary.name,dir_fd=directory_fd,follow_symlinks=False)),
              'publication source must be a single immutable regular inode')
        digest=_hash_fd(source_fd)
        _rename_noreplace(directory_fd,temporary.name,destination.name,parent)
        after=os.fstat(source_fd)
        _need(_content_identity(after)==_content_identity(before)and after.st_nlink==1,
              'atomic rename changed immutable source authority')
        published_fd=os.open(destination.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory_fd)
        published=os.fstat(published_fd)
        _need(_stamp(published)==_stamp(after)and _hash_fd(published_fd)==digest
              and _stamp(os.fstat(source_fd))==_stamp(os.fstat(published_fd))
              and _stamp(os.stat(destination.name,dir_fd=directory_fd,follow_symlinks=False))==_stamp(os.fstat(published_fd)),
              'published FD/path/full bytes differ from the held source')
        _need(all(not p.is_symlink()for p in(parent,*parent.parents))
              and parent.resolve(strict=True)==parent
              and(directory.st_dev,directory.st_ino)==(parent.stat().st_dev,parent.stat().st_ino)
              and _stamp(os.fstat(directory_fd))[:2]==(directory.st_dev,directory.st_ino),
              'publication parent changed during rename')
    finally:
        if published_fd is not None:os.close(published_fd)
        if source_fd is not None:os.close(source_fd)
        os.close(directory_fd)
