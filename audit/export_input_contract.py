"""Bounded pre-issued export inputs. Checksums select data; they grant no authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

PACKAGE_FILES = frozenset({
    'audit.jsonl', 'ledger.sha256', 'signatures.json', 'consensus_evidence.json',
    'rfc3161_timestamp.tsr', 'timestamp_verification.json', 'tsa_certificate_chain.pem',
    'tsa_policy_oid.txt', 'governance_release.json', 'tenant_context.json',
    'evidence_archive_manifest.json', 'verification_manifest.json', 'package_signature.json',
    'runtime_authority_identity.json', 'evidence_index.json', 'verification_report.md',
})
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024


class ExportInputError(RuntimeError):
    pass


def require_operational_timestamp_verifier():
    """No production capability is inferred from legacy timestamp metadata.

    The current bundle verifier checks stored booleans/base64 JSON, not an
    independently verified RFC3161 token signature/chain and governed TSA trust.
    An environment flag or owner approval cannot replace that implementation.
    """
    raise ExportInputError('EXPORT_TSA_CRYPTOGRAPHIC_VERIFIER_UNAVAILABLE')


def _identity(info):
    # Reads may update atime. File identity/content metadata must stay fixed.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _require(value, pattern, reason):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise ExportInputError(reason)
    return value


def input_reference(environment):
    return {
        'run_id': _require(environment.get('USBAY_EXPORT_INPUT_RUN_ID'), r'[1-9][0-9]{0,19}', 'EXPORT_INPUT_RUN_REQUIRED'),
        'artifact_id': _require(environment.get('USBAY_EXPORT_INPUT_ARTIFACT_ID'), r'[1-9][0-9]{0,19}', 'EXPORT_INPUT_ARTIFACT_REQUIRED'),
        'tenant_id': _require(environment.get('USBAY_EXPORT_TENANT_ID'), r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', 'EXPORT_TENANT_REQUIRED'),
        'package_hash': _require(environment.get('USBAY_EXPORT_PACKAGE_HASH'), r'[0-9a-f]{64}', 'EXPORT_PACKAGE_HASH_REQUIRED'),
    }


def read_regular(root, name, limit=MAX_FILE_BYTES):
    root = Path(root).absolute()
    if (Path(name).name != name or name in {'', '.', '..'}
            or root.resolve(strict=True) != root):
        raise ExportInputError('EXPORT_INPUT_PATH_INVALID')
    root_before = root.stat()
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if _identity(os.fstat(parent)) != _identity(root_before):
            raise ExportInputError('EXPORT_INPUT_CHANGED')
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                raise ExportInputError('EXPORT_INPUT_FILE_INVALID')
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (len(raw) > limit or _identity(before) != _identity(after)
                    or _identity(before) != _identity(named)
                    or root.resolve(strict=True) != root
                    or _identity(os.fstat(parent)) != _identity(root.stat())):
                raise ExportInputError('EXPORT_INPUT_CHANGED')
            return raw
    finally:
        os.close(parent)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ExportInputError('EXPORT_INPUT_JSON_INVALID')
            result[key] = value
        return result

    def constant(_):
        raise ExportInputError('EXPORT_INPUT_JSON_INVALID')

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ExportInputError('EXPORT_INPUT_JSON_INVALID')
        return number

    if len(raw) > MAX_JSON_BYTES:
        raise ExportInputError('EXPORT_INPUT_JSON_INVALID')
    try:
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite)
    except (ValueError, UnicodeError, RecursionError):
        raise ExportInputError('EXPORT_INPUT_JSON_INVALID') from None


def inspect_preissued_package(package, *, tenant_id, source_commit, source_tree, package_hash):
    _require(tenant_id, r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', 'EXPORT_TENANT_REQUIRED')
    _require(source_commit, r'[0-9a-f]{40}', 'EXPORT_SOURCE_BINDING_REQUIRED')
    _require(source_tree, r'[0-9a-f]{40}', 'EXPORT_SOURCE_BINDING_REQUIRED')
    _require(package_hash, r'[0-9a-f]{64}', 'EXPORT_PACKAGE_HASH_REQUIRED')
    package = Path(package).absolute()
    if not package.is_dir() or package.resolve(strict=True) != package or set(os.listdir(package)) != PACKAGE_FILES:
        raise ExportInputError('EXPORT_PREISSUED_PACKAGE_REQUIRED')
    hashes, objects, total = {}, {}, 0
    for name in sorted(PACKAGE_FILES):
        raw = read_regular(package, name)
        total += len(raw)
        if total > MAX_PACKAGE_BYTES:
            raise ExportInputError('EXPORT_INPUT_SIZE_INVALID')
        hashes[name] = hashlib.sha256(raw).hexdigest()
        if name.endswith('.json'):
            objects[name] = strict_json(raw)
        elif name == 'audit.jsonl':
            for line in raw.splitlines():
                if line.strip():
                    strict_json(line)
    release, manifest, tenant = (objects[name] for name in (
        'governance_release.json', 'verification_manifest.json', 'tenant_context.json'))
    if any(type(value) is not dict for value in (release, manifest, tenant)):
        raise ExportInputError('EXPORT_INPUT_BINDING_INVALID')
    if any(value.get('tenant_id') != tenant_id for value in (release, manifest, tenant)):
        raise ExportInputError('EXPORT_TENANT_MISMATCH')
    if release.get('git_commit') != source_commit or manifest.get('git_commit') != source_commit:
        raise ExportInputError('EXPORT_SOURCE_MISMATCH')
    if manifest.get('package_hash') != package_hash:
        raise ExportInputError('EXPORT_PACKAGE_HASH_MISMATCH')
    # These are untrusted observations until the actual signature/source/ledger
    # verifiers succeed. No positive execution decision is returned here.
    return hashes


def stage_public_source_manifest(inputs, checkout):
    checkout = Path(checkout).absolute()
    if checkout.resolve(strict=True) != checkout:
        raise ExportInputError('EXPORT_INPUT_PATH_INVALID')
    raw = read_regular(inputs, 'runtime_source_manifest.json', MAX_JSON_BYTES)
    strict_json(raw)
    # Never overwrite source or choose a caller-controlled destination name.
    target = checkout / 'runtime_source_manifest.json'
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('reference')
    stage = commands.add_parser('stage-source')
    stage.add_argument('--inputs', required=True, type=Path)
    stage.add_argument('--checkout', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'reference':
            values = input_reference(os.environ)
            for name, value in values.items():
                print(f'{name}={value}')
        else:
            stage_public_source_manifest(args.inputs, args.checkout)
            print('EXPORT_PUBLIC_SOURCE_STAGED_NOT_VERIFIED')
    except ExportInputError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print('EXPORT_INPUT_PREPARATION_DENIED', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
