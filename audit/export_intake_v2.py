"""Local, read-only composition of pre-issued source and V2 package evidence.

Explicit public verifier inputs select cryptographic observations, not adopted
trust. No producer, transport, registry, release issuer or exporter is invoked.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat

from audit.export_input_contract import read_regular, strict_json, _identity
from audit.export_timestamp_v2 import (
    V2_FILES, ExportTimestampV2Observation, _bindings, canonical, digest,
    inspect_native_export_v2,
)
from security.runtime_artifact_provenance import (
    ProducerTrust, public_key_id, validate_managed_path, verify_runtime_artifact,
)

PROFILE_SCHEMA = 'usbay.preissued_export_verifier_inputs.v1'
REFERENCE_SCHEMA = 'usbay.preissued_export_reference.v1'
SOURCE_MANIFEST = 'runtime_source_manifest.json'
MAX_SOURCE_FILES = 4096
MAX_SOURCE_FILE = 4 * 1024 * 1024
MAX_SOURCE_TOTAL = 64 * 1024 * 1024
MAX_SOURCE_DIRS = 4096
MAX_DEPTH = 32
REFERENCE_FIELDS = frozenset({'schema', 'repository', 'run_id', 'artifact_id',
    'tenant_id', 'source_commit', 'source_tree', 'manifest_sha256', 'source_manifest_sha256'})
PROFILE_FIELDS = frozenset({'schema', 'reference', 'bindings',
    'package_signer_public_key_hex', 'source_producer_public_key_hex',
    'source_producer_scope', 'source_verifier_mode', 'tsa_roots_pem',
    'evaluation_time', 'max_source_age_seconds', 'max_age_seconds',
    'clock_skew_seconds', 'maximum_accuracy_seconds', 'max_crl_age_seconds'})


class ExportIntakeError(RuntimeError):
    """Only fixed, content-free reason codes may leave this boundary."""


def _require(condition, code):
    if not condition:
        raise ExportIntakeError(code)


@dataclass(frozen=True)
class ExportIntakeObservation:
    verifier_inputs_sha256: str
    reference_sha256: str
    source_manifest_sha256: str
    source_managed_set_sha256: str
    source_producer_key_id: str
    source_file_count: int
    source_commit: str
    source_tree: str
    package: ExportTimestampV2Observation
    scope: str = field(default='PREISSUED_SOURCE_AND_V2_OBSERVATIONS_ONLY', init=False)
    remaining_requirements: tuple[str, ...] = field(default=(
        'ADOPTED_SOURCE_PRODUCER_TRUST',
        'PROVIDER_ARTIFACT_ORIGIN_AND_TRANSPORT',
        'INDEPENDENT_GIT_GRAPH_AND_NATIVE_BUILD_VERIFICATION',
        'GOVERNED_OPERATIONAL_RELEASE_AUTHORITY',
        'POINT_OF_USE_REVALIDATION',
    ), init=False)


def _utc(value):
    _require(type(value) is str, 'INTAKE_TIME_INVALID')
    try:
        parsed = datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        _require(parsed.strftime('%Y-%m-%dT%H:%M:%SZ') == value, 'INTAKE_TIME_INVALID')
        return parsed
    except (ValueError, OverflowError):
        raise ExportIntakeError('INTAKE_TIME_INVALID') from None


def _profile(value):
    # Snapshot caller data. No object callback or mutable profile is consulted later.
    _require(type(value) is dict, 'INTAKE_PROFILE_INVALID')
    checked = value.copy()
    _require(set(checked) == PROFILE_FIELDS and checked['schema'] == PROFILE_SCHEMA,
             'INTAKE_PROFILE_INVALID')
    ref = checked['reference']
    _require(type(ref) is dict, 'INTAKE_REFERENCE_INVALID')
    ref = ref.copy(); checked['reference'] = ref
    _require(set(ref) == REFERENCE_FIELDS and ref['schema'] == REFERENCE_SCHEMA,
             'INTAKE_REFERENCE_INVALID')
    for name in REFERENCE_FIELDS:
        _require(type(ref[name]) is str, 'INTAKE_REFERENCE_INVALID')
    _require(bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',
                              ref['repository'])), 'INTAKE_REFERENCE_INVALID')
    for name in ('run_id', 'artifact_id'):
        _require(bool(re.fullmatch(r'[1-9][0-9]{0,19}', ref[name])), 'INTAKE_REFERENCE_INVALID')
    for name in ('manifest_sha256', 'source_manifest_sha256'):
        _require(bool(re.fullmatch(r'[0-9a-f]{64}', ref[name])), 'INTAKE_REFERENCE_INVALID')
    _require(type(checked['bindings']) is dict, 'INTAKE_PROFILE_INVALID')
    bindings = _bindings(checked['bindings'].copy())
    checked['bindings'] = bindings
    _require(all(ref[name] == bindings[name] for name in ('tenant_id', 'source_commit', 'source_tree')),
             'INTAKE_REFERENCE_BINDING_MISMATCH')
    for name in ('package_signer_public_key_hex', 'source_producer_public_key_hex'):
        _require(type(checked[name]) is str and bool(re.fullmatch(r'[0-9a-f]{64}', checked[name])),
                 'INTAKE_PUBLIC_KEY_INVALID')
    public = bytes.fromhex(checked['source_producer_public_key_hex'])
    trust = ProducerTrust(public, public_key_id(public), checked['source_producer_scope'],
                          checked['source_verifier_mode'])
    trust.validate()
    _require(type(checked['tsa_roots_pem']) is str and 0 < len(checked['tsa_roots_pem']) <= 2*1024*1024,
             'INTAKE_PUBLIC_ROOTS_INVALID')
    checked['tsa_roots_pem'].encode('ascii', 'strict')
    for name in ('max_source_age_seconds', 'max_age_seconds', 'max_crl_age_seconds'):
        _require(type(checked[name]) is int and 1 <= checked[name] <= 86400, 'INTAKE_PROFILE_INVALID')
    for name, minimum in (('clock_skew_seconds', 0), ('maximum_accuracy_seconds', 1)):
        _require(type(checked[name]) is int and minimum <= checked[name] <= 3600, 'INTAKE_PROFILE_INVALID')
    return checked, bindings, trust, _utc(checked['evaluation_time'])


def _root_state(root):
    _require(root.resolve(strict=True) == root, 'INTAKE_PATH_INVALID')
    info = root.lstat()
    _require(stat.S_ISDIR(info.st_mode), 'INTAKE_PATH_INVALID')
    return _identity(info)


def _inventory(root, files, *, max_file=MAX_SOURCE_FILE, max_total=MAX_SOURCE_TOTAL):
    """Bounded openat/scandir walk; no symlink or managed-directory exemptions."""
    expected_dirs = set()
    for name in files:
        parts = name.split('/')
        _require(len(parts) <= MAX_DEPTH, 'INTAKE_SOURCE_LIMIT')
        expected_dirs.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    _require(len(files) <= MAX_SOURCE_FILES + 1 and len(expected_dirs) <= MAX_SOURCE_DIRS,
             'INTAKE_SOURCE_LIMIT')
    _root_state(root)
    states = []; seen = set(); directories = set(); total = 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def walk(fd, prefix):
        nonlocal total
        before = _identity(os.fstat(fd)); states.append((prefix, before))
        with os.scandir(fd) as entries:
            for entry in entries:
                name = prefix + '/' + entry.name if prefix else entry.name
                validate_managed_path(name)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    _require(name in expected_dirs, 'INTAKE_INVENTORY_INVALID')
                    directories.add(name)
                    child = os.open(entry.name, flags, dir_fd=fd)
                    try:
                        _require(_identity(os.fstat(child)) == _identity(info), 'INTAKE_INPUT_CHANGED')
                        walk(child, name)
                        _require(_identity(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) == _identity(info),
                                 'INTAKE_INPUT_CHANGED')
                    finally:
                        os.close(child)
                else:
                    _require(name in files and stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                             'INTAKE_INVENTORY_INVALID')
                    _require(0 <= info.st_size <= max_file, 'INTAKE_SOURCE_LIMIT')
                    total += info.st_size
                    _require(total <= max_total, 'INTAKE_SOURCE_LIMIT')
                    seen.add(name); states.append((name, _identity(info)))
        _require(_identity(os.fstat(fd)) == before, 'INTAKE_INPUT_CHANGED')

    fd = os.open(root, flags)
    try:
        walk(fd, '')
    finally:
        os.close(fd)
    _require(seen == set(files) and directories == expected_dirs, 'INTAKE_INVENTORY_INVALID')
    _require(_identity(root.lstat()) == states[0][1], 'INTAKE_INPUT_CHANGED')
    return tuple(sorted(states))


def _managed_files(manifest):
    _require(type(manifest) is dict, 'INTAKE_SOURCE_INVALID')
    entries = manifest.get('managed_files')
    _require(type(entries) is list and 0 < len(entries) <= MAX_SOURCE_FILES, 'INTAKE_SOURCE_LIMIT')
    names = set(); total = 0
    for entry in entries:
        _require(type(entry) is dict and set(entry) == {'path', 'mode', 'sha256', 'size'},
                 'INTAKE_SOURCE_INVALID')
        name = validate_managed_path(entry['path'])
        _require(name not in names and name != SOURCE_MANIFEST, 'INTAKE_SOURCE_INVALID')
        size = entry['size']
        _require(type(size) is int and 0 <= size <= MAX_SOURCE_FILE, 'INTAKE_SOURCE_LIMIT')
        total += size
        _require(total <= MAX_SOURCE_TOTAL, 'INTAKE_SOURCE_LIMIT')
        names.add(name)
    return names


def _bundle_state(root, names):
    root_state = _root_state(root)
    with os.scandir(root) as entries:
        _require({e.name for _, e in zip(range(5), entries)} == {'input_reference.json', 'source', 'package'},
                 'INTAKE_INVENTORY_INVALID')
    reference_state = _identity((root/'input_reference.json').lstat())
    source_state = _inventory(root/'source', names | {SOURCE_MANIFEST})
    package_state = _inventory(root/'package', V2_FILES, max_file=2*1024*1024, max_total=32*1024*1024)
    _require(_root_state(root) == root_state, 'INTAKE_INPUT_CHANGED')
    return root_state, reference_state, source_state, package_state


def inspect_preissued_export_v2(inputs, *, verifier_inputs):
    """Return observations only; caller profiles are never adopted authority."""
    try:
        profile, bindings, source_verifier, at = _profile(verifier_inputs)
        ref = profile['reference']; root = Path(inputs).absolute()
        initial_root = _root_state(root)
        raw_ref = read_regular(root, 'input_reference.json', 4096)
        _require(raw_ref == canonical(ref), 'INTAKE_REFERENCE_MISMATCH')
        raw_source = read_regular(root/'source', SOURCE_MANIFEST, MAX_SOURCE_FILE)
        _require(digest(raw_source) == ref['source_manifest_sha256'], 'INTAKE_SOURCE_PIN_MISMATCH')
        manifest = strict_json(raw_source)
        _require(raw_source == canonical(manifest), 'INTAKE_SOURCE_ENCODING_INVALID')
        names = _managed_files(manifest)
        before = _bundle_state(root, names)
        _require(before[0] == initial_root, 'INTAKE_INPUT_CHANGED')
        created = _utc(manifest.get('created_at'))
        age = (at-created).total_seconds()
        _require(-profile['clock_skew_seconds'] <= age <= profile['max_source_age_seconds'],
                 'INTAKE_SOURCE_FRESHNESS_INVALID')
        _require(manifest.get('build_reference') == 'github-actions:' + ref['run_id'],
                 'INTAKE_SOURCE_REFERENCE_MISMATCH')
        try:
            source = verify_runtime_artifact(raw_source, root/'source', source_verifier,
                expected_source_commit=bindings['source_commit'], expected_source_tree=bindings['source_tree'])
        except Exception:
            raise ExportIntakeError('INTAKE_SOURCE_VERIFICATION_FAILED') from None
        try:
            package = inspect_native_export_v2(root/'package', expected_bindings=bindings,
                expected_manifest_sha256=ref['manifest_sha256'],
                signer_public_key=bytes.fromhex(profile['package_signer_public_key_hex']),
                tsa_roots_pem=profile['tsa_roots_pem'].encode('ascii'), evaluation_time=at,
                **{name: profile[name] for name in ('max_age_seconds', 'clock_skew_seconds',
                    'maximum_accuracy_seconds', 'max_crl_age_seconds')})
        except Exception:
            raise ExportIntakeError('INTAKE_PACKAGE_VERIFICATION_FAILED') from None
        # Revalidate the complete local inputs after genuine native verification.
        again = verify_runtime_artifact(raw_source, root/'source', source_verifier,
            expected_source_commit=bindings['source_commit'], expected_source_tree=bindings['source_tree'])
        _require(again == source, 'INTAKE_INPUT_CHANGED')
        _require(read_regular(root/'source', SOURCE_MANIFEST, MAX_SOURCE_FILE) == raw_source
                 and read_regular(root, 'input_reference.json', 4096) == raw_ref, 'INTAKE_INPUT_CHANGED')
        for name, expected in package.observed_file_hashes:
            _require(digest(read_regular(root/'package', name, 2*1024*1024)) == expected, 'INTAKE_INPUT_CHANGED')
        _require(_bundle_state(root, names) == before, 'INTAKE_INPUT_CHANGED')
        return ExportIntakeObservation(digest(canonical(profile)), digest(raw_ref), digest(raw_source),
            source.managed_set_hash, source.producer_key_id, len(source.managed_files),
            source.source_commit, source.source_tree_reference, package)
    except ExportIntakeError:
        raise
    except Exception:
        raise ExportIntakeError('INTAKE_VERIFICATION_FAILED') from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ExportIntakeError('INTAKE_ARGUMENTS_INVALID')


def main(argv=None):
    try:
        parser = _Parser(description='Observe local pre-issued inputs; never authorize an export.')
        command = parser.add_subparsers(dest='command', required=True).add_parser('observe')
        command.add_argument('--inputs', required=True, type=Path)
        command.add_argument('--profile', required=True, type=Path)
        args = parser.parse_args(argv)
        profile_path = args.profile.absolute()
        profile = strict_json(read_regular(profile_path.parent, profile_path.name, MAX_SOURCE_FILE))
        observation = inspect_preissued_export_v2(args.inputs, verifier_inputs=profile)
        print(json.dumps({'status': 'OBSERVED_ONLY_NOT_OPERATIONALLY_AUTHORIZED',
                          'observation': asdict(observation)}, sort_keys=True))
        return 0
    except ExportIntakeError as error:
        print(json.dumps({'status': 'DENY', 'reason_code': str(error)}))
    except Exception:
        print(json.dumps({'status': 'DENY', 'reason_code': 'INTAKE_VERIFICATION_FAILED'}))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
