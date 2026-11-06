"""Fixed hashed-wheel staging for disposable native tests; no product authority.

Only the nonprivileged controller downloads wheels. No downloaded package is
imported before isolation. The privileged bootstrap independently checks bytes.
No wheel installer, build backend, entrypoint or .pth hook is executed.
"""
import email.parser
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import zipfile

PACKAGES = {'cryptography': '50.0.2', 'cffi': '2.1.1', 'pycparser': '3.11'}
PROFILE_SHA256 = '8e9a4b6b251ead722777d1c74539f6923654bc1ae20c5d85f3b51d28344d0c1d'
SCHEMA = 'usbay.native_crypto_dependencies.v1'
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILES = 4096


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def profile_packages(raw):
    if type(raw) is not bytes or len(raw) > 131072:
        raise RuntimeError('RUNTIME_DEPENDENCY_PROFILE_INVALID')
    text = raw.decode('ascii')
    result = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        pin = re.fullmatch(r'([a-z]+)==([0-9.]+)\s*\\?', line)
        digest = re.fullmatch(r'--hash=sha256:([0-9a-f]{64})\s*\\?', line)
        if pin:
            name, version = pin.groups()
            if name in result or PACKAGES.get(name) != version:
                raise RuntimeError('RUNTIME_DEPENDENCY_PROFILE_INVALID')
            result[name] = {'version': version, 'hashes': set()}
            current = name
        elif digest and current is not None:
            result[current]['hashes'].add(digest.group(1))
        else:
            raise RuntimeError('RUNTIME_DEPENDENCY_PROFILE_INVALID')
    if set(result) != set(PACKAGES) or any(not x['hashes'] for x in result.values()):
        raise RuntimeError('RUNTIME_DEPENDENCY_PROFILE_INVALID')
    return result


def read_regular(path, limit, owner=None):
    if path.resolve(strict=True) != path:
        raise RuntimeError('RUNTIME_DEPENDENCY_PATH_INVALID')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o022 or before.st_size > limit
                or owner is not None and (before.st_uid, before.st_gid) != owner):
            raise RuntimeError('RUNTIME_DEPENDENCY_FILE_INVALID')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        named = path.lstat()
        snapshot = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(raw) > limit or snapshot(before) != snapshot(after) or snapshot(before) != snapshot(named):
            raise RuntimeError('RUNTIME_DEPENDENCY_FILE_CHANGED')
        return raw
    finally:
        os.close(fd)


def wheel_members(raw, profile):
    """Return exact wheel member bytes only after whole-archive hash binding."""
    digest = hashlib.sha256(raw).hexdigest()
    names = [name for name, item in profile.items() if digest in item['hashes']]
    if len(names) != 1 or len(raw) > MAX_ARCHIVE:
        raise RuntimeError('RUNTIME_DEPENDENCY_WHEEL_UNTRUSTED')
    name = names[0]
    result = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_FILES or sum(x.file_size for x in infos) > MAX_TOTAL:
            raise RuntimeError('RUNTIME_DEPENDENCY_SIZE_INVALID')
        seen = set()
        for item in infos:
            path = PurePosixPath(item.filename)
            components = item.filename.rstrip('/').split('/')
            mode = item.external_attr >> 16
            if (item.filename in seen or path.is_absolute() or '\\' in item.filename
                    or any(p in {'', '.', '..'} for p in components)
                    or any(ord(c) < 32 or ord(c) == 127 for c in item.filename)
                    or path.suffix in {'.pth', '.pyc'} or stat.S_ISLNK(mode)
                    or mode & 0o7000 or item.file_size > MAX_ARCHIVE):
                raise RuntimeError('RUNTIME_DEPENDENCY_MEMBER_INVALID')
            seen.add(item.filename)
            top = components[0]
            allowed = (top in {name, name + '.libs', name + '-' + PACKAGES[name] + '.dist-info'}
                       or name == 'cffi' and bool(re.fullmatch(r'_cffi_backend\.[A-Za-z0-9_.-]+\.so', top)))
            if not allowed:
                raise RuntimeError('RUNTIME_DEPENDENCY_MEMBER_INVALID')
            if item.is_dir():
                continue
            if stat.S_IFMT(mode) not in {0, stat.S_IFREG} or item.filename in result:
                raise RuntimeError('RUNTIME_DEPENDENCY_MEMBER_INVALID')
            result[item.filename] = archive.read(item)
    metadata_name = name + '-' + PACKAGES[name] + '.dist-info/METADATA'
    if metadata_name not in result:
        raise RuntimeError('RUNTIME_DEPENDENCY_METADATA_INVALID')
    metadata = email.parser.BytesParser().parsebytes(result[metadata_name])
    if metadata.get_all('Name') != [name] or metadata.get_all('Version') != [PACKAGES[name]]:
        raise RuntimeError('RUNTIME_DEPENDENCY_METADATA_INVALID')
    return name, result


def expected_from_wheels(base, profile, owner=None):
    directory = base / 'wheels'
    if directory.resolve(strict=True) != directory:
        raise RuntimeError('RUNTIME_DEPENDENCY_PATH_INVALID')
    found, files, archives = set(), {}, {}
    paths = sorted(directory.iterdir())
    if len(paths) != len(PACKAGES):
        raise RuntimeError('RUNTIME_DEPENDENCY_WHEEL_SET_INVALID')
    for path in paths:
        if path.suffix != '.whl':
            raise RuntimeError('RUNTIME_DEPENDENCY_WHEEL_SET_INVALID')
        raw = read_regular(path, MAX_ARCHIVE, owner)
        name, members = wheel_members(raw, profile)
        if name in found or set(files).intersection(members):
            raise RuntimeError('RUNTIME_DEPENDENCY_WHEEL_SET_INVALID')
        found.add(name)
        files.update(members)
        archives[name] = hashlib.sha256(raw).hexdigest()
    if found != set(PACKAGES) or len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_TOTAL:
        raise RuntimeError('RUNTIME_DEPENDENCY_WHEEL_SET_INVALID')
    return files, archives


def dependency_manifest(files, archives):
    return {'schema': SCHEMA, 'packages': PACKAGES, 'python': [3, 12], 'archives': archives,
            'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}}


def validate_manifest(manifest):
    if (type(manifest) is not dict
            or set(manifest) != {'schema', 'packages', 'python', 'archives', 'files'}
            or manifest['schema'] != SCHEMA or manifest['packages'] != PACKAGES
            or manifest['python'] != [3, 12]
            or type(manifest['archives']) is not dict or set(manifest['archives']) != set(PACKAGES)
            or any(type(v) is not str or not re.fullmatch('[0-9a-f]{64}', v) for v in manifest['archives'].values())
            or type(manifest['files']) is not dict or not 1 <= len(manifest['files']) <= MAX_FILES):
        raise RuntimeError('RUNTIME_DEPENDENCY_BINDING_MISMATCH')
    for name, digest in manifest['files'].items():
        if (type(name) is not str or name.startswith('/') or '\\' in name
                or any(part in {'', '.', '..'} for part in name.split('/'))
                or any(ord(c) < 32 or ord(c) == 127 for c in name)
                or type(digest) is not str or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise RuntimeError('RUNTIME_DEPENDENCY_BINDING_MISMATCH')


def verify_tree(directory, manifest, owner=None):
    validate_manifest(manifest)
    if directory.resolve(strict=True) != directory:
        raise RuntimeError('RUNTIME_DEPENDENCY_PATH_INVALID')
    root_info = directory.lstat()
    if root_info.st_mode & 0o022 or owner is not None and (root_info.st_uid, root_info.st_gid) != owner:
        raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')
    expected = set(manifest['files']) | {'.usbay-dependencies.json'}
    found = set()
    allowed_directories = {parent.as_posix() for name in manifest['files']
                           for parent in PurePosixPath(name).parents if parent.as_posix() != '.'}
    count = total = 0
    for path in directory.rglob('*'):
        count += 1
        if count > MAX_FILES * 8:
            raise RuntimeError('RUNTIME_DEPENDENCY_SIZE_INVALID')
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022
                or owner is not None and (info.st_uid, info.st_gid) != owner):
            raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')
        if stat.S_ISDIR(info.st_mode):
            if path.relative_to(directory).as_posix() not in allowed_directories:
                raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')
        name = path.relative_to(directory).as_posix()
        if name not in expected:
            raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')
        total += info.st_size
        if total > MAX_TOTAL + 1024 * 1024:
            raise RuntimeError('RUNTIME_DEPENDENCY_SIZE_INVALID')
        raw = read_regular(path, MAX_ARCHIVE, owner)
        if name != '.usbay-dependencies.json' and hashlib.sha256(raw).hexdigest() != manifest['files'][name]:
            raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')
        found.add(name)
    if found != expected or read_regular(directory / '.usbay-dependencies.json', 1024 * 1024, owner) != canonical(manifest):
        raise RuntimeError('RUNTIME_DEPENDENCY_TREE_INVALID')


def fixed_profile(base):
    raw = read_regular(base / 'source/runtime_crypto.lock', 131072)
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise RuntimeError('RUNTIME_DEPENDENCY_PROFILE_MISMATCH')
    return profile_packages(raw)


def prepare_dependencies(base):
    if os.geteuid() == 0 or sys.version_info[:2] != (3, 12):
        raise RuntimeError('RUNTIME_DEPENDENCY_PREPARATION_CONTEXT_INVALID')
    profile = fixed_profile(base)
    wheels = base / 'wheels'
    wheels.mkdir(mode=0o700)
    command = [sys.executable, '-I', '-B', '-m', 'pip', 'download', '--disable-pip-version-check',
               '--no-cache-dir', '--only-binary=:all:', '--no-deps', '--require-hashes',
               '--index-url', 'https://pypi.org/simple', '--dest', str(wheels),
               '-r', str(base / 'source/runtime_crypto.lock')]
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'PIP_CONFIG_FILE': '/dev/null', 'PIP_NO_INPUT': '1'}
    result = subprocess.run(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    if result.returncode:
        raise RuntimeError('RUNTIME_DEPENDENCY_DOWNLOAD_FAILED')
    files, archives = expected_from_wheels(base, profile, (os.geteuid(), os.getegid()))
    destination = base / 'dependencies'
    destination.mkdir(mode=0o700)
    for name, raw in files.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    manifest = dependency_manifest(files, archives)
    (destination / '.usbay-dependencies.json').write_bytes(canonical(manifest))
    (destination / '.usbay-dependencies.json').chmod(0o600)
    verify_tree(destination, manifest, (os.geteuid(), os.getegid()))
    return hashlib.sha256(canonical(manifest)).hexdigest()


def verify_prepared_dependencies(base, uid, gid):
    files, archives = expected_from_wheels(base, fixed_profile(base), (uid, gid))
    manifest = dependency_manifest(files, archives)
    verify_tree(base / 'dependencies', manifest, (uid, gid))
    return hashlib.sha256(canonical(manifest)).hexdigest()


def activate_dependencies(expected_binding):
    """Called only after native gates; never accept an unbound system fallback."""
    directory = Path('/dependencies')
    raw = read_regular(directory / '.usbay-dependencies.json', 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_binding:
        raise RuntimeError('RUNTIME_DEPENDENCY_BINDING_MISMATCH')
    manifest = json.loads(raw)
    validate_manifest(manifest)
    if (manifest.get('schema') != SCHEMA or manifest.get('packages') != PACKAGES
            or manifest.get('python') != [3, 12] or canonical(manifest) != raw):
        raise RuntimeError('RUNTIME_DEPENDENCY_BINDING_MISMATCH')
    verify_tree(directory, manifest)
    try:
        with open(directory / 'cryptography/__init__.py', 'ab'):
            pass
    except OSError as error:
        if error.errno not in {1, 13, 30}:
            raise RuntimeError('RUNTIME_DEPENDENCY_READONLY_UNPROVEN') from None
    else:
        raise RuntimeError('RUNTIME_DEPENDENCY_READONLY_UNPROVEN')
    roots = {'cryptography', 'cffi', 'pycparser', '_cffi_backend'}
    if any(name.split('.')[0] in roots for name in sys.modules):
        raise RuntimeError('RUNTIME_DEPENDENCY_ALREADY_IMPORTED')
    sys.path.insert(0, str(directory))
    for name in roots:
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None or not Path(spec.origin).is_relative_to(directory):
            raise RuntimeError('RUNTIME_DEPENDENCY_IMPORT_ORIGIN_INVALID')
    versions = {d.metadata['Name']: d.version for d in importlib.metadata.distributions(path=[str(directory)])}
    if versions != PACKAGES:
        raise RuntimeError('RUNTIME_DEPENDENCY_VERSION_MISMATCH')
    return {'binding': expected_binding, 'packages': versions, 'read_only_proven': True}
