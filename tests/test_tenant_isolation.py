from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit.immutable_ledger import LedgerIntegrityError, append_evidence_event, export_evidence_bundle
from audit.worm_archive import WORMArchive, WORMArchiveError
from scripts.verify_evidence_bundle import verify_bundle
from security.tenant_context import (
    REASON_CROSS_TENANT_EXECUTION_BLOCKED,
    TenantIsolationError,
    canonical_tenant_authority_decision,
    tenant_authority_inventory,
    tenant_execution_context,
    tenant_hash,
    tenant_isolation_audit_evidence,
    tenant_scoped_path,
    validate_consensus_tenant,
    validate_records_single_tenant,
)
from tests.provenance_helpers import install_runtime_authority
from tests.test_audit_exporter import isolated_anchor_keys
from tests.test_worm_evidence_archive import _policy as retention_policy


def _attestation(tenant_id: str = "t1") -> dict:
    return {
        "logical_node_id": "node-1",
        "node_id": "attested-node-1",
        "node_role": "primary",
        "tenant_id": tenant_id,
        "tenant_hash": tenant_hash(tenant_id),
        "provider_mode": "mock_local",
        "hardware_backed": False,
        "attestation_hash": "attestation-hash-1",
        "attestation_timestamp": 1,
    }


def _decision(tenant_id: str = "t1", *, attestation_tenant: str | None = None, consensus_tenant: str | None = None) -> dict:
    evidence_tenant = consensus_tenant or tenant_id
    return {
        "node_id": "node-1",
        "tenant_id": tenant_id,
        "tenant_hash": tenant_hash(tenant_id),
        "policy_hash": "policy-hash-1",
        "consensus_result": "ALLOW",
        "nonce_hash": "nonce-hash-1",
        "request_hash": "request-hash-1",
        "consensus_evidence_bundle": {
            "node_ids": ["node-1", "node-2", "node-3"],
            "timestamps": {"node-1": 1, "node-2": 1, "node-3": 1},
            "policy_hash": "policy-hash-1",
            "tenant_id": evidence_tenant,
            "tenant_hash": tenant_hash(evidence_tenant),
            "consensus_result": "allow",
            "attestation_evidence": [_attestation(attestation_tenant or evidence_tenant)],
            "attestation_evidence_hash": "attestation-evidence-hash-1",
            "sha256_evidence_hash": "evidence-hash-1",
            "consensus_signature": "consensus-signature-1",
        },
    }


def _bundle(
    tmp_path: Path,
    monkeypatch,
    tenant_id: str = "t1",
    *,
    install_provenance: bool = True,
    provenance_authority=None,
) -> Path:
    if install_provenance:
        authority = install_runtime_authority(monkeypatch, tmp_path, tenant_id=tenant_id)
    else:
        authority = provenance_authority
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision(tenant_id))
    bundle_dir = tmp_path / "bundle"
    export_evidence_bundle(ledger, bundle_dir, provenance_authority=authority)
    return bundle_dir


def test_valid_tenant_isolation_passes(tmp_path: Path, monkeypatch) -> None:
    context = tenant_execution_context("t1")
    bundle = _bundle(tmp_path, monkeypatch)
    report = verify_bundle(bundle)

    assert context["tenant_id"] == "t1"
    assert tenant_scoped_path(tmp_path, "t1") == tmp_path / "tenant" / "t1"
    assert report["result"] == "PASS"


def test_tenant_isolation_path_uses_canonical_ci_validator(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("USBAY_ENV", raising=False)
    authority = install_runtime_authority(monkeypatch, tmp_path)
    bundle = _bundle(tmp_path, monkeypatch, install_provenance=False, provenance_authority=authority)

    report = verify_bundle(bundle)

    assert report["result"] == "PASS"
    context = report["evidence_summary"]["deployment_provenance"]["provenance_context"]
    assert context == authority.context_dict()


def test_missing_tenant_context_fails_closed(tmp_path: Path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    decision = _decision("t1")
    decision.pop("tenant_id")

    with pytest.raises(LedgerIntegrityError, match="tenant_context_missing"):
        append_evidence_event(ledger, action="consensus_allow", decision=decision)


def test_cross_tenant_evidence_fails_closed(tmp_path: Path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision("t1"))
    append_evidence_event(ledger, action="consensus_allow", decision=_decision("t2"))

    with pytest.raises(LedgerIntegrityError, match="cross_tenant_evidence_reference"):
        export_evidence_bundle(ledger, tmp_path / "export")


def test_tenant_a_evidence_cannot_validate_under_tenant_b(tmp_path: Path, monkeypatch) -> None:
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision("t1"))
    records = [
        json.loads(line)
        for line in ledger.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    with pytest.raises(TenantIsolationError, match="tenant_mismatch_detected"):
        validate_records_single_tenant(records, expected_tenant_id="t2")


def test_foreign_attestation_evidence_fails_closed() -> None:
    with pytest.raises(TenantIsolationError, match="tenant_mismatch_detected"):
        validate_consensus_tenant(_decision("t1", attestation_tenant="t2")["consensus_evidence_bundle"], "t1")


def test_foreign_consensus_evidence_fails_closed() -> None:
    with pytest.raises(TenantIsolationError, match="tenant_mismatch_detected"):
        validate_consensus_tenant(_decision("t1", consensus_tenant="t2")["consensus_evidence_bundle"], "t1")


def test_canonical_tenant_authority_inventory_selects_single_owner() -> None:
    inventory = tenant_authority_inventory()

    assert inventory["canonical_owner_module"] == "security.tenant_context"
    assert [entry for entry in inventory["ownership_points"] if entry["role"] == "aggregate_owner"] == [
        {
            "module": "security.tenant_context",
            "role": "aggregate_owner",
            "surface": "tenant validation, tenant hashing, tenant-scoped paths, runtime tenant consistency",
        }
    ]
    assert inventory["duplicate_aggregate_owners"] == []
    assert inventory["execution_enabled"] is False


def test_canonical_tenant_authority_blocks_cross_tenant_mismatch() -> None:
    decision = canonical_tenant_authority_decision(request_tenant_id="t2", runtime_tenant_id="t1")

    assert decision["tenant_authority_status"] == "BLOCKED"
    assert REASON_CROSS_TENANT_EXECUTION_BLOCKED in decision["reason_codes"]
    assert decision["fail_closed"] is True


def test_tenant_isolation_audit_evidence_blocks_mismatch_fixture(tmp_path: Path) -> None:
    fixture = tmp_path / "tenant-mismatch.json"
    fixture.write_text(
        json.dumps({"request_tenant_id": "t2", "runtime_tenant_id": "t1"}, sort_keys=True),
        encoding="utf-8",
    )

    evidence = tenant_isolation_audit_evidence(fixture_path=fixture)

    assert evidence["tenant_isolation_status"] == "BLOCKED"
    assert evidence["canonical_authority"] == "security.tenant_context"
    assert REASON_CROSS_TENANT_EXECUTION_BLOCKED in evidence["readiness"]["reason_codes"]


def test_tenant_export_leakage_fails_closed(tmp_path: Path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    records = [
        json.loads(line)
        for line in (bundle / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    records[0]["decision"]["tenant_id"] = "t2"
    (bundle / "audit.jsonl").write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records) + "\n",
        encoding="utf-8",
    )

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert any("TENANT" in control for control in report["failed_control_ids"])


def test_export_bundle_tenant_context_mismatch_fails_closed(tmp_path: Path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    context = json.loads((bundle / "tenant_context.json").read_text(encoding="utf-8"))
    context["tenant_id"] = "t2"
    context["tenant_hash"] = tenant_hash("t2")
    context["tenant_scope"] = "tenant/t2"
    (bundle / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    report = verify_bundle(bundle)

    assert report["result"] == "FAIL"
    assert "TENANT_CONTEXT_MISMATCH" in report["failed_control_ids"]
    assert "RFC3161_MESSAGE_IMPRINT" in report["failed_control_ids"]


def test_tenant_provenance_mismatch_fails_closed(tmp_path: Path, monkeypatch) -> None:
    authority = install_runtime_authority(monkeypatch, tmp_path, tenant_id="t1")
    isolated_anchor_keys(tmp_path, monkeypatch)
    ledger = tmp_path / "evidence.jsonl"
    append_evidence_event(ledger, action="consensus_allow", decision=_decision("t2"))

    with pytest.raises(LedgerIntegrityError, match="tenant_deployment_provenance_mismatch"):
        export_evidence_bundle(ledger, tmp_path / "export", provenance_authority=authority)


def test_tenant_specific_worm_archive_passes(tmp_path: Path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=retention_policy(tmp_path))
    manifest = archive.archive_bundle(bundle)

    assert manifest["tenant_id"] == "t1"
    assert manifest["tenant_hash"] == tenant_hash("t1")
    assert manifest["tenant_scope"] == "tenant/t1"
    assert (tmp_path / "archive" / "tenant" / "t1" / manifest["primary_region"] / manifest["object_id"]).is_dir()
    assert archive.validate_archive(manifest["object_id"]) is True


def test_mixed_tenant_worm_archive_fails_closed(tmp_path: Path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    context = json.loads((bundle / "tenant_context.json").read_text(encoding="utf-8"))
    context["tenant_id"] = "t2"
    context["tenant_hash"] = tenant_hash("t2")
    context["tenant_scope"] = "tenant/t2"
    (bundle / "tenant_context.json").write_text(json.dumps(context, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    archive = WORMArchive(tmp_path / "archive", retention_policy_path=retention_policy(tmp_path))

    with pytest.raises(WORMArchiveError, match="tenant_mismatch_detected"):
        archive.archive_bundle(bundle)


def test_no_secret_leakage_regression(tmp_path: Path, monkeypatch) -> None:
    bundle = _bundle(tmp_path, monkeypatch)
    text = "\n".join(path.read_text(encoding="utf-8") for path in bundle.iterdir() if path.is_file()).lower()

    assert "raw_nonce" not in text
    assert "approval" not in text
    assert "private" + "_" + "key" not in text
    assert "secret" not in text
