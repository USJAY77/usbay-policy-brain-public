from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import audit.keys as audit_keys
import security.tenant_context as tenant_context
from audit.keys import AuditKeyPathError
from security.tenant_context import TenantIsolationError


def _configure_audit_roots(monkeypatch, root: Path) -> None:
    private_dir = root / "private"
    public_dir = root / "public"
    monkeypatch.setattr(audit_keys, "DEFAULT_REGISTRY_PATH", root / "registry.json")
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_PATH", private_dir / "audit_private_key.pem")
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_PATH", public_dir / "audit_public_key.pem")
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_DIR", private_dir)
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_DIR", public_dir)
    monkeypatch.setattr(audit_keys, "DEFAULT_REGISTRY_ROOT", root)
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_ROOT", root)
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_ROOT", root)


def _tenant_policy() -> dict:
    return {
        "allowed_tenant_ids": ["t1"],
        "tenant_evidence_isolation": True,
        "tenant_export_permissions": {"t1": True},
        "tenant_retention_policy": {"t1": {"retention_days": 30}},
    }


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _configure_tenant_roots(monkeypatch, root: Path) -> None:
    monkeypatch.setattr(tenant_context, "DEFAULT_TENANT_POLICY_ROOT", root)
    monkeypatch.setattr(tenant_context, "DEFAULT_TENANT_AUTHORITY_FIXTURE_ROOT", root)


def test_audit_registry_allows_valid_files_inside_authorized_root(tmp_path: Path, monkeypatch) -> None:
    _configure_audit_roots(monkeypatch, tmp_path)
    nested_registry = tmp_path / "nested" / "registry.json"

    audit_keys._write_registry({"keys": {"k1": {"public_key": "public"}}}, nested_registry)

    assert audit_keys._read_registry(nested_registry)["keys"]["k1"]["public_key"] == "public"


@pytest.mark.parametrize(
    "escape_path",
    [
        "../outside/registry.json",
        "nested/../../outside/registry.json",
    ],
)
def test_audit_registry_rejects_parent_and_multilevel_traversal(
    tmp_path: Path,
    monkeypatch,
    escape_path: str,
) -> None:
    _configure_audit_roots(monkeypatch, tmp_path / "root")

    with pytest.raises(AuditKeyPathError, match="audit_key_registry_path_invalid"):
        audit_keys._read_registry(Path(escape_path))


def test_audit_registry_rejects_absolute_and_sibling_escape(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "sibling" / "registry.json"
    _write_json(outside, {"keys": {}})
    _configure_audit_roots(monkeypatch, root)

    for path in (outside, root / ".." / "sibling" / "registry.json"):
        with pytest.raises(AuditKeyPathError, match="audit_key_registry_path_invalid"):
            audit_keys._read_registry(path)


def test_audit_registry_rejects_empty_malformed_and_write_escape(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside" / "registry.json"
    _configure_audit_roots(monkeypatch, root)

    with pytest.raises(AuditKeyPathError, match="audit_key_registry_path_invalid"):
        audit_keys._read_registry(Path(""))
    with pytest.raises(AuditKeyPathError, match="audit_key_registry_path_invalid"):
        audit_keys._write_registry({"keys": {}}, outside)

    assert not outside.exists()


def test_audit_registry_rejects_symlink_escape_where_supported(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    _write_json(outside / "registry.json", {"keys": {}})
    symlink = root / "linked"
    try:
        symlink.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unsupported on this platform")
    _configure_audit_roots(monkeypatch, root)

    with pytest.raises(AuditKeyPathError, match="audit_key_registry_path_invalid"):
        audit_keys._read_registry(symlink / "registry.json")


def test_audit_signing_key_version_escape_is_rejected(tmp_path: Path, monkeypatch) -> None:
    _configure_audit_roots(monkeypatch, tmp_path)

    for version in ("../escape", "..", "", "nested/escape"):
        with pytest.raises(AuditKeyPathError, match="audit_key_version_invalid"):
            audit_keys.key_paths_for_version(version)


def test_audit_signing_key_paths_remain_inside_authorized_roots(tmp_path: Path, monkeypatch) -> None:
    _configure_audit_roots(monkeypatch, tmp_path)

    private_key_path, public_key_path = audit_keys.key_paths_for_version("v2")

    assert private_key_path.relative_to(tmp_path)
    assert public_key_path.relative_to(tmp_path)


def test_tenant_policy_allows_valid_files_inside_authorized_root(tmp_path: Path, monkeypatch) -> None:
    _configure_tenant_roots(monkeypatch, tmp_path)
    policy_path = _write_json(tmp_path / "governance" / "tenant_policy.json", _tenant_policy())

    assert tenant_context.load_tenant_policy(policy_path)["allowed_tenant_ids"] == ["t1"]


def test_tenant_policy_rejects_traversal_absolute_sibling_and_malformed_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "root"
    sibling = tmp_path / "sibling" / "tenant_policy.json"
    _write_json(sibling, _tenant_policy())
    _configure_tenant_roots(monkeypatch, root)

    for path in (
        "../sibling/tenant_policy.json",
        "nested/../../sibling/tenant_policy.json",
        sibling,
        root / ".." / "sibling" / "tenant_policy.json",
        "",
    ):
        with pytest.raises(TenantIsolationError, match="tenant_policy_invalid:path"):
            tenant_context.load_tenant_policy(path)


def test_tenant_policy_rejects_symlink_escape_where_supported(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    _write_json(outside / "tenant_policy.json", _tenant_policy())
    symlink = root / "linked"
    try:
        symlink.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unsupported on this platform")
    _configure_tenant_roots(monkeypatch, root)

    with pytest.raises(TenantIsolationError, match="tenant_policy_invalid:path"):
        tenant_context.load_tenant_policy(symlink / "tenant_policy.json")


def test_tenant_authority_fixture_rejects_outside_root_without_path_disclosure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "root"
    policy_path = _write_json(root / "tenant_policy.json", _tenant_policy())
    outside_fixture = _write_json(tmp_path / "outside" / "fixture.json", {"request_tenant_id": "t1", "runtime_tenant_id": "t1"})
    _configure_tenant_roots(monkeypatch, root)

    report = tenant_context.tenant_authority_readiness_report(
        fixture_path=outside_fixture,
        policy_path=policy_path,
    )
    rendered = json.dumps(report, sort_keys=True)

    assert report["tenant_authority_status"] == "BLOCKED"
    assert tenant_context.REASON_TENANT_AUTHORITY_FIXTURE_INVALID in report["reason_codes"]
    assert str(outside_fixture) not in rendered
    assert report["fixture_path"] == "redacted"
    assert report["fixture_path_reference"].startswith("sha256:")


def test_tenant_authority_fixture_allows_valid_file_inside_authorized_root(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _configure_tenant_roots(monkeypatch, tmp_path)
    policy_path = _write_json(tmp_path / "tenant_policy.json", _tenant_policy())
    fixture = _write_json(tmp_path / "fixture.json", {"request_tenant_id": "t1", "runtime_tenant_id": "t1"})

    report = tenant_context.tenant_authority_readiness_report(fixture_path=fixture, policy_path=policy_path)

    assert report["tenant_authority_status"] == "VALID"
    assert report["fixture_path"] == "redacted"
