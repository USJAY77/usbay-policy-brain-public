from __future__ import annotations

import importlib
import pytest

pytestmark=pytest.mark.governance

def _config():
    return {'USBAY_ENV':'production','USBAY_RUNTIME_ENVIRONMENT':'staging','PORT':'8000'}

@pytest.mark.parametrize('changes', [
    {'USBAY_ENV':None}, {'USBAY_ENV':'staging'}, {'USBAY_ENV':'test'}, {'USBAY_ENV':'typo'},
    {'USBAY_ENVIRONMENT':'test'}, {'USBAY_RUNTIME_ENVIRONMENT':None}, {'USBAY_RUNTIME_ENVIRONMENT':'production'},
    {'PORT':None}, {'PORT':'0'}, {'PORT':'65536'}, {'PORT':'x'}, {'WEB_CONCURRENCY':'2'}, {'UVICORN_WORKERS':'2'},
    {'UVICORN_RELOAD':'true'}, {'UVICORN_LIFESPAN':'off'}, {'UVICORN_ENV_FILE':'unapproved.env'}, {'UVICORN_APP_DIR':'/unapproved'},
    {'USBAY_LIVE_POLICY_EVALUATION_ENABLED':'true'}, {'USBAY_LIVE_POLICY_EVALUATION_ENABLED':'1'}, {'USBAY_LIVE_POLICY_EVALUATION_ENABLED':'yes'},
])
def test_profile_rejects_missing_or_ambiguous_mode_and_scale(changes):
    module=importlib.import_module('staging.launch')
    env=_config()
    for name,value in changes.items():
        if value is None:env.pop(name,None)
        else:env[name]=value
    with pytest.raises(ValueError):module.launch_arguments(env)

def test_explicit_profile_preserves_production_checks_and_staging_scope():
    module=importlib.import_module('staging.launch')
    args=module.launch_arguments(_config())
    assert args==['-m','uvicorn','gateway.app:app','--host','0.0.0.0','--port','8000','--workers','1','--lifespan','on']

@pytest.fixture(scope='module')
def source_bound_staging_package(tmp_path_factory):
    from pathlib import Path
    from tests.helpers.staging_source_package import snapshot_staging_source
    package = tmp_path_factory.mktemp('staging-source') / 'package'
    metadata = snapshot_staging_source(Path(__file__).resolve().parents[1], package)
    return package, metadata


@pytest.mark.parametrize('mutation', ['valid', 'missing', 'tampered', 'stale'])
def test_unmodified_lifespan_with_synthetic_production_mode_release(source_bound_staging_package, tmp_path, mutation):
    from tests.helpers.staging_source_package import run_staging_case
    package, metadata = source_bound_staging_package
    result = run_staging_case(package, metadata, tmp_path/'state', mutation)
    assert result.get('outcome') != 'ERROR', result
    assert result['source_commit'] == metadata['source_commit']
    assert result['source_tree'] == metadata['source_tree_reference']
    assert result['module_origins_verified'] is True
    assert result['same_source_authority'] is True
    assert result['verification_functions_replaced'] is False
    assert result['no_exec_gate']['installed'] is True
    expected = {'valid': None, 'missing': 'release_manifest_missing',
                'tampered': 'release_signature_invalid', 'stale': 'release_manifest_freshness'}[mutation]
    assert result['reason'] == expected
    assert result['outcome'] == ('PASS' if mutation == 'valid' else 'DENY')

def test_signed_staging_adoption_is_not_supported_by_current_approval_contract(monkeypatch,tmp_path):
    from tests.test_governance_validation import _write_policy_authority_fixture
    from tests.test_policy_authority_adoption import _scoped_approvals, _arguments
    from security.policy_authority_adoption_store import adopt_current_scoped_policy_authority
    def approvals(records):
        _scoped_approvals(records)
        for record in records:record['environment']='staging'
    def registry(data,_records):
        data['authorized_environments']=['staging']
        for record in data['approvers']:record['authorized_environment']=['staging']
    paths=_write_policy_authority_fixture(monkeypatch,tmp_path,approval_mutation=approvals,registry_mutation=registry)
    args=_arguments(paths['replay_db']);args['environment']='staging'
    with pytest.raises(RuntimeError,match='POLICY_APPROVAL_ENVIRONMENT_UNAUTHORIZED'):
        adopt_current_scoped_policy_authority(**args)
