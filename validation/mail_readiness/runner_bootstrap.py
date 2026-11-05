"""Fixed ephemeral-CI bootstrap. No application execution or product authority."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


BOOTSTRAP_REASONS = frozenset({
    'CI_OWNER_ID_INVALID','MAPPING_POLICY_INVALID','MAPPING_POLICY_AMBIGUOUS',
    'MAPPING_POLICY_FILE_UNSAFE','MAPPING_POLICY_CHANGED','MAPPING_POLICY_WRITE_FAILED',
    'MAPPING_POLICY_RESTORE_FAILED','EXPECTED_HEAD_REQUIRED','SOURCE_OWNER_BINDING_MISMATCH',
    'SOURCE_HEAD_MISMATCH','SOURCE_FILE_UNSAFE','SOURCE_BYTES_MISMATCH','BOOTSTRAP_ROOT_REQUIRED',
    'BOOTSTRAP_CALLER_MISMATCH','TEMPORARY_PATH_INVALID','TEMPORARY_OWNER_MISMATCH',
    'BOOTSTRAP_LOCK_UNSAFE','SUPPLEMENTARY_GROUPS_NOT_EMPTY','BOOTSTRAP_RESULT_INVALID'})


def safe_reason(error):
    return str(error) if type(error) is RuntimeError and str(error) in BOOTSTRAP_REASONS else 'BOOTSTRAP_ERROR'


def owner_id(value):
    if type(value) is not int or not 1 <= value <= 2147483647:
        raise RuntimeError('CI_OWNER_ID_INVALID')
    return value


def policy_extension(data, target):
    owner_id(target)
    if type(data) is not bytes or len(data) > 1048576:
        raise RuntimeError('MAPPING_POLICY_INVALID')
    try:
        text = data.decode('ascii')
    except UnicodeError:
        raise RuntimeError('MAPPING_POLICY_INVALID') from None
    exact = False
    root_ranges = []
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        fields = line.split(':')
        if (len(fields) != 3 or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*\$?|[0-9]+', fields[0])
                or any(not re.fullmatch(r'[0-9]+', x) for x in fields[1:])):
            raise RuntimeError('MAPPING_POLICY_INVALID')
        start, count = map(int, fields[1:])
        if start < 1 or count < 1 or start + count > 4294967295:
            raise RuntimeError('MAPPING_POLICY_INVALID')
        if fields[0] == 'root' or fields[0].isdigit() and int(fields[0]) == 0:
            if any(start < end and old < start + count for old, end in root_ranges):
                raise RuntimeError('MAPPING_POLICY_AMBIGUOUS')
            root_ranges.append((start, start + count))
            if start <= target < start + count:
                if fields[0] != 'root' or start != target or count != 1:
                    raise RuntimeError('MAPPING_POLICY_AMBIGUOUS')
                exact = True
    if exact:
        return data
    return data + (b'\n' if data and not data.endswith(b'\n') else b'') + f'root:{target}:1\n'.encode('ascii')


def signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def snapshot(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or st.st_mode & 0o022:
            raise RuntimeError('MAPPING_POLICY_FILE_UNSAFE')
        data = os.read(fd, 1048577)
        if len(data) > 1048576 or signature(os.fstat(fd)) != signature(st):
            raise RuntimeError('MAPPING_POLICY_CHANGED')
        if signature(os.lstat(path)) != signature(st):
            raise RuntimeError('MAPPING_POLICY_CHANGED')
        return st, data
    finally:
        os.close(fd)


def atomic_replace(path, previous, data):
    st, original = previous
    current_st, current = snapshot(path)
    if signature(current_st) != signature(st) or current != original:
        raise RuntimeError('MAPPING_POLICY_CHANGED')
    fd, temp = tempfile.mkstemp(prefix='.usbay-idmap-', dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(st.st_mode))
        os.fchown(fd, st.st_uid, st.st_gid)
        with os.fdopen(fd, 'wb') as out:
            fd = None
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        latest_st, latest = snapshot(path)
        if signature(latest_st) != signature(st) or latest != original:
            raise RuntimeError('MAPPING_POLICY_CHANGED')
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        updated = snapshot(path)
        if updated[1] != data or stat.S_IMODE(updated[0].st_mode) != stat.S_IMODE(st.st_mode):
            raise RuntimeError('MAPPING_POLICY_WRITE_FAILED')
        return updated
    finally:
        if fd is not None:
            os.close(fd)
        if os.path.lexists(temp):
            os.unlink(temp)


def run_with_policy(uid, gid, callback):
    originals = [(Path('/etc/subuid'), snapshot(Path('/etc/subuid')), uid),
                 (Path('/etc/subgid'), snapshot(Path('/etc/subgid')), gid)]
    prepared = [(path, original, policy_extension(original[1], target)) for path, original, target in originals]
    changed = []
    try:
        for path, original, content in prepared:
            if content != original[1]:
                updated = atomic_replace(path, original, content)
                changed.append((path, original, updated))
        return callback()
    finally:
        errors = []
        for path, original, updated in reversed(changed):
            try:
                atomic_replace(path, updated, original[1])
            except BaseException:
                errors.append(True)
        if errors:
            raise RuntimeError('MAPPING_POLICY_RESTORE_FAILED')


def verified_source(repository, head, uid, gid):
    if not re.fullmatch(r'[0-9a-f]{40}', head):
        raise RuntimeError('EXPECTED_HEAD_REQUIRED')
    if repository.stat().st_uid != uid or repository.stat().st_gid != gid:
        raise RuntimeError('SOURCE_OWNER_BINDING_MISMATCH')
    git = ['/usr/bin/git', '-c', 'safe.directory=' + str(repository)]
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
    actual = subprocess.check_output(git + ['rev-parse', 'HEAD'], cwd=repository, env=env, stderr=subprocess.DEVNULL, timeout=5).decode('ascii').strip()
    if actual != head:
        raise RuntimeError('SOURCE_HEAD_MISMATCH')
    for name in ('runner_bootstrap.py', 'isolation_preflight.py', 'result_contract.py'):
        relative = 'validation/mail_readiness/' + name
        path = repository / relative
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_gid != gid or st.st_mode & 0o022:
            raise RuntimeError('SOURCE_FILE_UNSAFE')
        committed = subprocess.check_output(git + ['show', head + ':' + relative], cwd=repository, env=env, stderr=subprocess.DEVNULL, timeout=5)
        if path.read_bytes() != committed:
            raise RuntimeError('SOURCE_BYTES_MISMATCH')


def launcher_diagnostics(stdout, stderr, exit_code):
    raw = stderr[:16384] if type(stderr) is bytes else b''
    categories = [code for code, needle in (
        ('UID_MAP_HELPER_ERROR', b'newuidmap'), ('GID_MAP_HELPER_ERROR', b'newgidmap'),
        ('ID_RANGE_NOT_ALLOWED', b'not allowed'), ('SETGROUPS_FAILED', b'setgroups failed'),
        ('SETUID_FAILED', b'setuid failed'), ('SETGID_FAILED', b'setgid failed'),
        ('UNSHARE_FAILED', b'unshare failed'), ('PERMISSION_DENIED', b'Permission denied'),
        ('OPERATION_NOT_PERMITTED', b'Operation not permitted'), ('WRITE_FAILED', b'write failed'),
        ('SETGROUPS_PATH', b'/proc/self/setgroups'), ('UID_MAP_PATH', b'/proc/self/uid_map'),
        ('GID_MAP_PATH', b'/proc/self/gid_map'), ('EXEC_FAILED', b'failed to execute'),
        ('FILE_NOT_FOUND', b'No such file or directory'), ('MODULE_NOT_FOUND', b'ModuleNotFoundError'),
        ('IMPORT_FAILED', b'ImportError'), ('PYTHON_STARTUP_FAILED', b'Fatal Python error'),
        ('PYTHON_FILE_OPEN_FAILED', b"can\'t open file"), ('MOUNT_FAILED', b'mount failed'),
        ('MOUNT_PROPAGATION_FAILED', b'mount propagation failed'), ('FORK_FAILED', b'fork failed'),
        ('ARGUMENT_INVALID', b'unrecognized arguments'), ('MAPPING_INVALID', b'invalid mapping'),
        ('OPTION_UNRECOGNIZED', b'unrecognized option')) if needle in raw]
    child = {}
    if type(stdout) is bytes and len(stdout) <= 16384:
        try:
            value = json.loads(stdout)
            if type(value) is dict:
                child = value
        except (ValueError, UnicodeError):
            pass
    stages = {'SOURCE_OWNER_BINDING','NAMESPACE_IDENTITY','MOUNT_NAMESPACE_PRIVATE','RUNTIME_BIND',
              'SOURCE_BIND','DEVICE_BIND','CHROOT','DROP_CAPABILITIES','KERNEL_RESTRICTIONS','FRESH_CHILD_CONTROLS'}
    types = {'PermissionError','OSError','RuntimeError','CalledProcessError','TimeoutExpired'}
    return {'stage':child.get('stage') if type(child.get('stage')) is str and child['stage'] in stages else 'NAMESPACE_LAUNCH',
            'error':child.get('error') if type(child.get('error')) is str and child['error'] in types else 'RuntimeError',
            'errno':child.get('errno') if type(child.get('errno')) is int else None,
            'launcher_categories':categories,
            'launcher_exit':exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None,
            'mapping_policy_restored':True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--uid', required=True, type=int)
    parser.add_argument('--gid', required=True, type=int)
    parser.add_argument('--temporary', required=True, type=Path)
    args = parser.parse_args()
    try:
        uid, gid = owner_id(args.uid), owner_id(args.gid)
        if os.getresuid() != (0, 0, 0) or os.getresgid() != (0, 0, 0):
            raise RuntimeError('BOOTSTRAP_ROOT_REQUIRED')
        if os.environ.get('SUDO_UID') != str(uid) or os.environ.get('SUDO_GID') != str(gid):
            raise RuntimeError('BOOTSTRAP_CALLER_MISMATCH')
        repository = Path(__file__).resolve().parents[2]
        verified_source(repository, args.expected_head, uid, gid)
        base = args.temporary.resolve(strict=True)
        if args.temporary != base or base.parent != Path('/tmp') or not base.name.startswith('usbay-synthetic-preflight-'):
            raise RuntimeError('TEMPORARY_PATH_INVALID')
        st = base.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or st.st_gid != gid or stat.S_IMODE(st.st_mode) != 0o700:
            raise RuntimeError('TEMPORARY_OWNER_MISMATCH')
        lock = os.open('/run/usbay-synthetic-idmap.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            st = os.fstat(lock)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o600:
                raise RuntimeError('BOOTSTRAP_LOCK_UNSAFE')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.setgroups([])
            if os.getgroups():
                raise RuntimeError('SUPPLEMENTARY_GROUPS_NOT_EMPTY')
            argv = ['/usr/bin/unshare', '--user', f'--map-users=0:{uid}:1', f'--map-groups=0:{gid}:1',
                    '--setgroups=deny', '--setuid=0', '--net', '--mount', '--pid', '--fork',
                    '/usr/bin/python3', '-I', '-B', str(repository / 'validation/mail_readiness/isolation_preflight.py'),
                    '--inside', str(base), '--inside-host-uid', str(uid), '--inside-host-gid', str(gid)]
            def launch():
                return subprocess.run(argv, env={'PATH':'/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE':'1'},
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=50)
            result = run_with_policy(uid, gid, launch)
        finally:
            os.close(lock)
        # Return only bounded classification/identity/control JSON, never raw stderr.
        if result.returncode:
            safe = launcher_diagnostics(result.stdout, result.stderr, result.returncode)
            print(json.dumps(safe))
            return 2
        payload = json.loads(result.stdout)
        if type(payload) is not dict:
            raise RuntimeError('BOOTSTRAP_RESULT_INVALID')
        payload['mapping_policy_restored'] = True
        print(json.dumps(payload))
        return 0
    except BaseException as error:
        # Exception messages can contain paths/data; do not print them.
        print(json.dumps({'stage':'EPHEMERAL_MAPPING_BOOTSTRAP', 'error':type(error).__name__,
                          'errno':getattr(error,'errno',None), 'bootstrap_reason':safe_reason(error)}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
