#!/usr/bin/python3 -I
"""Exact parent GID-map coordinator; deny setgroups BEFORE publishing gid_map."""
import json
import os
from pathlib import Path
import re
import stat
import sys


def mapping_text(uid, gid):
    if any(type(x) is not int or not 1 <= x <= 2147483647 for x in (uid, gid)):
        raise RuntimeError('GID_GUARD_ID_INVALID')
    return f'0 {uid} 1\n'.encode('ascii'), f'0 {gid} 1\n'.encode('ascii')


def apply_group_map(read, write, expected_uid, expected_gid):
    """The caller pins a verified parent proc directory; no PID paths are accepted here."""
    uid_map, gid_map = mapping_text(expected_uid, expected_gid)
    if read('uid_map').split() != uid_map.split() or read('gid_map').strip():
        raise RuntimeError('GID_GUARD_MAP_STATE_INVALID')
    state = read('setgroups').strip()
    if state == b'allow':
        write('setgroups', b'deny\n')
    elif state != b'deny':
        raise RuntimeError('GID_GUARD_SETGROUPS_INVALID')
    if read('setgroups').strip() != b'deny' or read('gid_map').strip():
        raise RuntimeError('GID_GUARD_DENIAL_NOT_PROVEN')
    write('gid_map', gid_map)
    if read('gid_map').split() != gid_map.split() or read('setgroups').strip() != b'deny':
        raise RuntimeError('GID_GUARD_FINAL_STATE_INVALID')


def target_binding(argv, parent_pid, gid):
    mapping_text(1, gid)
    if type(argv) is not list or len(argv) != 4 or any(type(x) is not str or not re.fullmatch('[0-9]{1,10}', x) for x in argv):
        raise RuntimeError('GID_GUARD_ARGUMENTS_INVALID')
    pid, inner, outer, count = map(int, argv)
    if type(parent_pid) is not int or not 1 < pid <= 2147483647 or pid != parent_pid or (inner, outer, count) != (0, gid, 1):
        raise RuntimeError('GID_GUARD_TARGET_INVALID')
    return pid


def main():
    try:
        here = Path(__file__).resolve().parent
        st = here.stat()
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700 or here.parent != Path('/run'):
            raise RuntimeError('GID_GUARD_DIRECTORY_UNSAFE')
        config_path = here / 'binding.json'
        st = config_path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
            raise RuntimeError('GID_GUARD_BINDING_UNSAFE')
        binding = json.loads(config_path.read_bytes())
        if type(binding) is not dict or set(binding) != {'uid','gid','head'}:
            raise RuntimeError('GID_GUARD_BINDING_INVALID')
        uid, gid = binding['uid'], binding['gid']
        mapping_text(uid, gid)
        if type(binding['head']) is not str or not re.fullmatch('[0-9a-f]{40}',binding['head']):
            raise RuntimeError('GID_GUARD_BINDING_INVALID')
        if os.getresuid() != (0,0,0) or os.getresgid() != (0,0,0) or os.getgroups():
            raise RuntimeError('GID_GUARD_CALLER_INVALID')
        pid = target_binding(sys.argv[1:], os.getppid(), gid)
        proc = os.open('/proc/' + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(proc)
            if st.st_uid != 0 or st.st_gid != 0:
                raise RuntimeError('GID_GUARD_OWNER_INVALID')
            if os.readlink('ns/user',dir_fd=proc) == os.readlink('/proc/self/ns/user'):
                raise RuntimeError('GID_GUARD_NAMESPACE_INVALID')
            def read(name):
                if name not in {'uid_map','gid_map','setgroups'}:
                    raise RuntimeError('GID_GUARD_RESOURCE_INVALID')
                fd = os.open(name,os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=proc)
                try:
                    data = os.read(fd,129)
                    if len(data)>128:raise RuntimeError('GID_GUARD_STATE_INVALID')
                    return data
                finally:os.close(fd)
            def write(name,data):
                if name not in {'gid_map','setgroups'}:
                    raise RuntimeError('GID_GUARD_RESOURCE_INVALID')
                fd = os.open(name,os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,dir_fd=proc)
                try:
                    if os.write(fd,data)!=len(data):raise RuntimeError('GID_GUARD_SHORT_WRITE')
                finally:os.close(fd)
            apply_group_map(read,write,uid,gid)
        finally:os.close(proc)
        return 0
    except BaseException as error:
        # Fixed enums only; no arbitrary exception messages, arguments or proc contents.
        permitted = {'GID_GUARD_ID_INVALID','GID_GUARD_MAP_STATE_INVALID','GID_GUARD_SETGROUPS_INVALID',
                     'GID_GUARD_DENIAL_NOT_PROVEN','GID_GUARD_FINAL_STATE_INVALID','GID_GUARD_DIRECTORY_UNSAFE',
                     'GID_GUARD_BINDING_UNSAFE','GID_GUARD_BINDING_INVALID','GID_GUARD_CALLER_INVALID',
                     'GID_GUARD_ARGUMENTS_INVALID','GID_GUARD_TARGET_INVALID','GID_GUARD_OWNER_INVALID',
                     'GID_GUARD_NAMESPACE_INVALID','GID_GUARD_RESOURCE_INVALID','GID_GUARD_STATE_INVALID','GID_GUARD_SHORT_WRITE'}
        reason = str(error) if type(error) is RuntimeError and str(error) in permitted else 'GID_GUARD_FAILED'
        sys.stderr.write(reason + '\n')
        return 2


if __name__=='__main__':raise SystemExit(main())
