"""Fixed synthetic source export and result contract; no execution authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from result_contract import controls_pass, fresh_identity_pass
from execution_boundary import fresh_exec_gate_pass

SCHEMA = 'usbay.offline_mail_validation.v1'
PRODUCT_PATHS = (
    'governance/__init__.py', 'control_plane/__init__.py',
    'governance/mail_draft_preview.py', 'governance/mail_draft_repository.py',
    'governance/mail_draft_review.py', 'governance/mail_preview_access_proposal.py',
    'governance/product_dry_run.py', 'governance/connector_framework.py',
    'governance/human_approval_gate_contract.py', 'control_plane/agent_registry.py',
)
SOURCE_MAP = {name: name for name in PRODUCT_PATHS} | {
    name: 'validation/mail_readiness/' + name
    for name in ('offline_mail_contract.py', 'offline_mail_cases.py', 'result_contract.py', 'execution_boundary.py')
}
CASE_NAMES = (
    'test_preview_is_not_authority', 'test_no_constructor_authority_override',
    'test_bcc_not_disclosed', 'test_html_escapes_content',
    'test_forged_preview_rejected', 'test_changed_content_rejected',
    'test_changed_tenant_rejected', 'test_duplicate_recipient_rejected',
    'test_header_injection_rejected', 'test_repository_cross_tenant_rejected',
    'test_repository_cross_owner_rejected', 'test_stale_snapshot_rejected',
    'test_copied_snapshot_rejected', 'test_tampered_snapshot_rejected',
    'test_render_tenant_mismatch_rejected', 'test_concurrent_cas_has_one_winner',
    'test_complete_hypothesis_never_grants', 'test_stale_hypothesis_stays_blocked',
    'test_missing_source_stays_blocked', 'test_mime_is_deterministic',
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def preconditions_pass(controls, identity, execution_gate):
    return controls_pass(controls) and fresh_identity_pass(identity) and fresh_exec_gate_pass(execution_gate)


def committed_sources(repository, head):
    if type(head) is not str or not re.fullmatch('[0-9a-f]{40}', head):
        raise RuntimeError('OFFLINE_MAIL_HEAD_INVALID')
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    git = ['/usr/bin/git', '-c', 'safe.directory=' + str(repository)]
    result = {}
    for alias, path in SOURCE_MAP.items():
        entry = subprocess.check_output(git + ['ls-tree', '-z', head, '--', path],
                                        cwd=repository, env=env, stderr=subprocess.DEVNULL, timeout=5)
        fields = entry.rstrip(b'\0').split(b'\t')
        if (len(fields) != 2 or fields[1] != path.encode()
                or fields[0].split()[0] != b'100644' or fields[0].split()[1] != b'blob'):
            raise RuntimeError('OFFLINE_MAIL_SOURCE_MODE_INVALID')
        raw = subprocess.check_output(git + ['show', head + ':' + path], cwd=repository,
                                      env=env, stderr=subprocess.DEVNULL, timeout=5)
        if not 0 < len(raw) <= 131072:
            raise RuntimeError('OFFLINE_MAIL_SOURCE_SIZE_INVALID')
        result[alias] = raw
    return result


def binding(head, sources):
    return {'schema': SCHEMA, 'head': head,
            'files': {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(sources.items())},
            'cases': list(CASE_NAMES)}


def stage_source(repository, head, destination):
    sources = committed_sources(repository, head)
    for name, raw in sources.items():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    data = binding(head, sources)
    fd = os.open(destination / 'offline-mail-binding.json',
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(data))
    return data


def verify_staged_source(repository, head, destination, uid, gid):
    sources = committed_sources(repository, head)
    for name, raw in sources.items():
        path = destination / name
        info = path.lstat()
        if (path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode)
                or info.st_uid != uid or info.st_gid != gid or info.st_mode & 0o022
                or path.read_bytes() != raw):
            raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')
    metadata = destination / 'offline-mail-binding.json'
    info = metadata.lstat()
    if (metadata.resolve(strict=True) != metadata or not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid or info.st_gid != gid or info.st_mode & 0o022
            or metadata.read_bytes() != canonical(binding(head, sources))):
        raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')


def verify_payload(root, expected_head):
    manifest_path = root / 'offline-mail-binding.json'
    raw = manifest_path.read_bytes()
    if len(raw) > 16384:
        raise RuntimeError('OFFLINE_MAIL_BINDING_INVALID')
    manifest = json.loads(raw)
    if (type(expected_head) is not str or not re.fullmatch('[0-9a-f]{40}', expected_head)
            or type(manifest) is not dict or set(manifest) != {'schema', 'head', 'files', 'cases'}
            or manifest['schema'] != SCHEMA or manifest['head'] != expected_head
            or manifest['cases'] != list(CASE_NAMES) or type(manifest['files']) is not dict
            or set(manifest['files']) != set(SOURCE_MAP) or canonical(manifest) != raw):
        raise RuntimeError('OFFLINE_MAIL_BINDING_INVALID')
    expected = set(SOURCE_MAP) | {'offline-mail-binding.json', 'synthetic.py'}
    found = set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')
        if path.is_dir() and path.relative_to(root).as_posix() not in {'governance', 'control_plane'}:
            raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')
        if path.is_file():
            found.add(path.relative_to(root).as_posix())
    if found != expected:
        raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')
    for name, wanted in manifest['files'].items():
        path = root / name
        if (type(wanted) is not str or not re.fullmatch('[0-9a-f]{64}', wanted)
                or not path.is_file() or not 0 < path.stat().st_size <= 131072
                or hashlib.sha256(path.read_bytes()).hexdigest() != wanted):
            raise RuntimeError('OFFLINE_MAIL_SOURCE_BINDING_MISMATCH')
    return hashlib.sha256(raw).hexdigest()


def result_structure_pass(value, source_binding):
    return (type(source_binding) is str and bool(re.fullmatch('[0-9a-f]{64}', source_binding))
            and type(value) is dict
            and set(value) == {'schema', 'source_binding', 'reports', 'tests_run', 'execution_authorized'}
            and value['schema'] == SCHEMA and value['source_binding'] == source_binding
            and type(value['tests_run']) is int and value['tests_run'] == len(CASE_NAMES)
            and value['execution_authorized'] is False and type(value['reports']) is dict
            and set(value['reports']) == set(CASE_NAMES)
            and all(type(v) is str and v in {'passed', 'failed', 'error', 'skipped'} for v in value['reports'].values()))


def result_pass(value, source_binding):
    return (result_structure_pass(value, source_binding)
            and all(v == 'passed' for v in value['reports'].values()))


def bounded_result(value):
    """Diagnostic projection only; never use this projection to accept a run."""
    if type(value) is not dict:
        return {'reported_tests_run': None, 'reports': {}}
    count = value.get('tests_run')
    count = count if type(count) is int and 0 <= count <= len(CASE_NAMES) else None
    reports = value.get('reports')
    outcomes = {}
    if type(reports) is dict:
        for name in CASE_NAMES:
            outcome = reports.get(name)
            if type(outcome) is str and outcome in {'passed', 'failed', 'error', 'skipped'}:
                outcomes[name] = outcome
    return {'reported_tests_run': count, 'reports': outcomes}
