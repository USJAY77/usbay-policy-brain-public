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

@pytest.mark.parametrize('mutation', ['valid', 'missing', 'tampered', 'stale'])
def test_unmodified_lifespan_with_synthetic_production_mode_release(monkeypatch, tmp_path, mutation):
    import asyncio
    import json
    import secrets
    from datetime import datetime, timedelta, timezone
    from security.deployment_attestation import build_release_manifest, sign_release_manifest
    from gateway.app import app
    import gateway.app as gateway

    for name,value in _config().items():monkeypatch.setenv(name,value)
    # Fresh synthetic signing material; never emitted or used outside this test.
    monkeypatch.setenv('USBAY_DEPLOYMENT_SIGNING_MATERIAL',secrets.token_hex(32))
    release=tmp_path/'synthetic-release.json'
    monkeypatch.setenv('USBAY_GOVERNANCE_RELEASE_PATH',str(release))
    manifest=build_release_manifest(tenant_id='t1')
    if mutation=='tampered':manifest['release_signature']='invalid'
    if mutation=='stale':
        from governance_runtime_monitor import load_runtime_governance_policy
        max_age=load_runtime_governance_policy().release_manifest_max_age_seconds
        manifest['deployment_timestamp']=(datetime.now(timezone.utc)-timedelta(seconds=max_age+10)).isoformat().replace('+00:00','Z')
        manifest['release_signature']=sign_release_manifest(manifest)
    if mutation!='missing':release.write_text(json.dumps(manifest))
    monkeypatch.setattr(gateway,'_policy_registry_cache',None)
    monkeypatch.setattr(gateway,'_policy_registry_cache_key',None)
    async def enter():
        async with app.router.lifespan_context(app):
            assert gateway.runtime_provenance_authority().release_path==str(release)
    if mutation=='valid':asyncio.run(enter())
    else:
        with pytest.raises(Exception) as caught:asyncio.run(enter())
        expected={'missing':'release_manifest','tampered':'release_signature','stale':'release_manifest_freshness'}[mutation]
        assert expected in str(caught.value).lower()

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
