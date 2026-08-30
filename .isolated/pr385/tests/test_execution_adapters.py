from __future__ import annotations

from pathlib import Path

import pytest

from execution.adapters.base import (
    ADAPTER_ACTION_SCOPE_OWNER,
    ADAPTER_APPROVAL_AUTHORITY,
    ADAPTER_APPROVAL_OWNER,
    ADAPTER_CONTRACT_OWNER,
    ADAPTER_GOVERNANCE_GATE_REFERENCE,
    ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY,
    ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY,
    ADAPTER_IDENTITY_OWNER,
    ADAPTER_NOT_IMPLEMENTED,
    ADAPTER_PROVENANCE_OWNER,
    ADAPTER_PROVENANCE_SOURCE,
    ADAPTER_REGISTRATION_AUTHORITY,
    ADAPTER_REGISTRATION_OWNER,
    ADAPTER_REVOCATION_AUTHORITY,
    ADAPTER_REVOCATION_OWNER,
    E2E_EVIDENCE_HASH_AUTHORITY,
    E2E_EVIDENCE_HASH_LINEAGE,
    E2E_EVIDENCE_HASH_OWNER,
    E2E_EVIDENCE_HASH_STATUS,
    EXECUTION_BLOCKED,
    EXECUTION_DISABLED,
    GATEWAY_ADAPTER_BINDING_AUTHORITY,
    GATEWAY_ADAPTER_BINDING_LINEAGE,
    GATEWAY_ADAPTER_BINDING_OWNER,
    GATEWAY_ADAPTER_BINDING_STATUS,
    POLICY_BRAIN_BINDING_AUTHORITY,
    POLICY_BRAIN_BINDING_LINEAGE,
    POLICY_BRAIN_BINDING_OWNER,
    POLICY_BRAIN_BINDING_STATUS,
    REGULATOR_PACKAGE_AUTHORITY,
    REGULATOR_PACKAGE_LINEAGE,
    REGULATOR_PACKAGE_OWNER,
    REGULATOR_PACKAGE_STATUS,
    SIMULATOR_RUNTIME_BINDING_AUTHORITY,
    SIMULATOR_RUNTIME_BINDING_LINEAGE,
    SIMULATOR_RUNTIME_BINDING_OWNER,
    SIMULATOR_RUNTIME_BINDING_STATUS,
    adapter_capability_map,
    build_adapter_action_contract,
    validate_adapter_action_contract,
    validate_adapter_governance_consistency,
    validate_adapter_governance_reconciliation,
)
from execution.adapters.browser_adapter import BrowserExecutionAdapter
from execution.adapters.filesystem_adapter import FilesystemExecutionAdapter
from execution.adapters.github_adapter import GitHubExecutionAdapter
from execution.adapters.shell_adapter import ShellExecutionAdapter


pytestmark = pytest.mark.governance


def ready_gate_proof():
    return {
        "execution_gate_status": "READY",
        "runtime_validation_status": "VALID",
        "production_readiness_status": "READY",
        "read_only": True,
        "execution_enabled": False,
        "deployment_enabled": False,
        "runtime_modification_enabled": False,
        "policy_mutation_enabled": False,
        "connector_write_enabled": False,
    }


@pytest.mark.parametrize(
    "adapter",
    [
        GitHubExecutionAdapter(),
        FilesystemExecutionAdapter(),
        BrowserExecutionAdapter(),
        ShellExecutionAdapter(),
    ],
)
def test_adapter_returns_execution_disabled(adapter):
    result = adapter.evaluate({"request_id": "exec-request-1"})

    assert result["status"] == EXECUTION_DISABLED
    assert result["decision"] == EXECUTION_BLOCKED
    assert result["reason"] == ADAPTER_NOT_IMPLEMENTED


def test_adapters_do_not_reference_execution_libraries_or_write_apis():
    adapter_dir = Path("execution/adapters")
    forbidden_fragments = [
        "sub" + "process",
        "os." + "system",
        "play" + "wright",
        "selen" + "ium",
        "pya" + "utogui",
        "requests." + "post",
        "requests." + "put",
        "requests." + "patch",
        "git " + "push",
        "pr " + "merge",
        ".write" + "_text",
        ".unlink" + "(",
    ]

    for path in adapter_dir.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for fragment in forbidden_fragments:
            assert fragment not in source


def test_adapter_capability_map_has_single_canonical_owner():
    mapping = adapter_capability_map()

    assert mapping["canonical_owner"] == ADAPTER_CONTRACT_OWNER
    assert mapping["governance_consistency_authority"] == ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY
    assert mapping["governance_reconciliation_authority"] == ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY
    assert mapping["read_only"] is True
    assert mapping["execution_enabled"] is False
    assert {record["adapter_name"] for record in mapping["adapters"]} == {
        "browser",
        "filesystem",
        "github",
        "shell",
    }
    assert all(record["required_gate_proof"] is True for record in mapping["adapters"])
    assert all(record["owner"] == ADAPTER_CONTRACT_OWNER for record in mapping["adapters"])
    assert all(record["action_scope_owner"] == ADAPTER_ACTION_SCOPE_OWNER for record in mapping["adapters"])
    assert all(record["action_scope_id"] for record in mapping["adapters"])
    assert all(len(record["action_scope_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["adapter_id"] for record in mapping["adapters"])
    assert all(record["adapter_owner"] == ADAPTER_IDENTITY_OWNER for record in mapping["adapters"])
    assert all(len(record["adapter_identity_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["attestation_reference"].startswith("usbay.adapter.") for record in mapping["adapters"])
    assert all(record["provenance_owner"] == ADAPTER_PROVENANCE_OWNER for record in mapping["adapters"])
    assert all(record["provenance_source"] == ADAPTER_PROVENANCE_SOURCE for record in mapping["adapters"])
    assert all(record["provenance_registered_at"] == "2026-06-21T00:00:00Z" for record in mapping["adapters"])
    assert all(record["provenance_attestation_reference"].startswith("usbay.adapter.") for record in mapping["adapters"])
    assert all(len(record["provenance_chain_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["policy_binding_id"].startswith("policy-binding.") for record in mapping["adapters"])
    assert all(record["policy_binding_owner"] == POLICY_BRAIN_BINDING_OWNER for record in mapping["adapters"])
    assert all(record["policy_binding_authority"] == POLICY_BRAIN_BINDING_AUTHORITY for record in mapping["adapters"])
    assert all(record["policy_binding_reference"].startswith("runtime/policy_validator.py#") for record in mapping["adapters"])
    assert all(record["policy_binding_lineage"] == POLICY_BRAIN_BINDING_LINEAGE for record in mapping["adapters"])
    assert all(record["policy_binding_status"] == POLICY_BRAIN_BINDING_STATUS for record in mapping["adapters"])
    assert all(len(record["policy_binding_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["gateway_binding_id"].startswith("gateway-binding.") for record in mapping["adapters"])
    assert all(record["gateway_binding_owner"] == GATEWAY_ADAPTER_BINDING_OWNER for record in mapping["adapters"])
    assert all(record["gateway_binding_authority"] == GATEWAY_ADAPTER_BINDING_AUTHORITY for record in mapping["adapters"])
    assert all(record["gateway_binding_reference"].startswith("docs/audits/EXECUTION_SURFACE_MAP.md#") for record in mapping["adapters"])
    assert all(record["gateway_binding_lineage"] == GATEWAY_ADAPTER_BINDING_LINEAGE for record in mapping["adapters"])
    assert all(record["gateway_binding_status"] == GATEWAY_ADAPTER_BINDING_STATUS for record in mapping["adapters"])
    assert all(len(record["gateway_binding_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["simulator_binding_id"].startswith("simulator-runtime-binding.") for record in mapping["adapters"])
    assert all(record["simulator_binding_owner"] == SIMULATOR_RUNTIME_BINDING_OWNER for record in mapping["adapters"])
    assert all(record["simulator_binding_authority"] == SIMULATOR_RUNTIME_BINDING_AUTHORITY for record in mapping["adapters"])
    assert all(record["simulator_binding_reference"].startswith("tests/test_simulation_governance.py#") for record in mapping["adapters"])
    assert all(record["simulator_binding_lineage"] == SIMULATOR_RUNTIME_BINDING_LINEAGE for record in mapping["adapters"])
    assert all(record["simulator_binding_status"] == SIMULATOR_RUNTIME_BINDING_STATUS for record in mapping["adapters"])
    assert all(len(record["simulator_binding_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["e2e_evidence_hash_id"].startswith("e2e-evidence-hash.") for record in mapping["adapters"])
    assert all(record["e2e_evidence_hash_owner"] == E2E_EVIDENCE_HASH_OWNER for record in mapping["adapters"])
    assert all(record["e2e_evidence_hash_authority"] == E2E_EVIDENCE_HASH_AUTHORITY for record in mapping["adapters"])
    assert all(record["e2e_evidence_hash_reference"].startswith("docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#") for record in mapping["adapters"])
    assert all(record["e2e_evidence_hash_lineage"] == E2E_EVIDENCE_HASH_LINEAGE for record in mapping["adapters"])
    assert all(record["e2e_evidence_hash_status"] == E2E_EVIDENCE_HASH_STATUS for record in mapping["adapters"])
    assert all(len(record["e2e_evidence_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["regulator_package_id"].startswith("regulator-package.") for record in mapping["adapters"])
    assert all(record["regulator_package_owner"] == REGULATOR_PACKAGE_OWNER for record in mapping["adapters"])
    assert all(record["regulator_package_authority"] == REGULATOR_PACKAGE_AUTHORITY for record in mapping["adapters"])
    assert all(record["regulator_package_reference"].startswith("docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#") for record in mapping["adapters"])
    assert all(record["regulator_package_lineage"] == REGULATOR_PACKAGE_LINEAGE for record in mapping["adapters"])
    assert all(record["regulator_package_status"] == REGULATOR_PACKAGE_STATUS for record in mapping["adapters"])
    assert all(len(record["regulator_package_hash"]) == 64 for record in mapping["adapters"])
    assert all(record["registration_id"].startswith("adapter-registration.") for record in mapping["adapters"])
    assert all(record["registration_state"] == "ACTIVE" for record in mapping["adapters"])
    assert all(record["registration_owner"] == ADAPTER_REGISTRATION_OWNER for record in mapping["adapters"])
    assert all(record["registration_authority"] == ADAPTER_REGISTRATION_AUTHORITY for record in mapping["adapters"])
    assert all(record["registration_reference"].startswith("usbay.adapter.") for record in mapping["adapters"])
    assert all(record["revocation_id"].startswith("adapter-revocation.") for record in mapping["adapters"])
    assert all(record["revocation_reason"] == "NOT_REVOKED" for record in mapping["adapters"])
    assert all(record["revocation_owner"] == ADAPTER_REVOCATION_OWNER for record in mapping["adapters"])
    assert all(record["revocation_authority"] == ADAPTER_REVOCATION_AUTHORITY for record in mapping["adapters"])
    assert all(record["revoked_by"] == "NONE" for record in mapping["adapters"])
    assert all(record["revoked_at"] == "NONE" for record in mapping["adapters"])
    assert all(record["revocation_reference"].startswith("usbay.adapter.") for record in mapping["adapters"])
    assert all(record["approval_id"].startswith("adapter-approval.") for record in mapping["adapters"])
    assert all(record["approval_state"] == "APPROVED" for record in mapping["adapters"])
    assert all(record["approval_owner"] == ADAPTER_APPROVAL_OWNER for record in mapping["adapters"])
    assert all(record["approval_authority"] == ADAPTER_APPROVAL_AUTHORITY for record in mapping["adapters"])
    assert all(record["approved_by"] == "adapter-governance-board" for record in mapping["adapters"])
    assert all(record["approved_at"] == "2026-06-21T00:00:00Z" for record in mapping["adapters"])
    assert all(record["approval_reference"].startswith("usbay.adapter.") for record in mapping["adapters"])
    assert all(record["reconciliation_id"].startswith("adapter-reconciliation.") for record in mapping["adapters"])
    assert all(record["reconciliation_status"] == "RECONCILED" for record in mapping["adapters"])
    assert all(record["reconciliation_owner"] == ADAPTER_CONTRACT_OWNER for record in mapping["adapters"])
    assert all(record["reconciliation_authority"] == ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY for record in mapping["adapters"])
    assert all(record["reconciled_at"] == "2026-06-21T00:00:00Z" for record in mapping["adapters"])
    assert all(record["reconciliation_reference"].startswith("usbay.adapter.") for record in mapping["adapters"])
    assert all(len(record["reconciliation_hash"]) == 64 for record in mapping["adapters"])
    assert all(
        record["governance_gate_reference"] == ADAPTER_GOVERNANCE_GATE_REFERENCE
        for record in mapping["adapters"]
    )


def test_valid_adapter_action_contract_requires_ready_gate_proof():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


def test_unknown_adapter_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="unknown",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "UNKNOWN_ADAPTER" in result["reason_codes"]


def test_unknown_capability_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="SHELL_EXECUTION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "UNKNOWN_CAPABILITY" in result["reason_codes"]


def test_unknown_action_type_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="click_button",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "UNKNOWN_ACTION_TYPE" in result["reason_codes"]


@pytest.mark.parametrize(
    ("adapter_name", "capability", "undeclared_action"),
    [
        ("browser", "READ_ONLY_NAVIGATION", "submit_form"),
        ("filesystem", "FILE_READ", "delete_file"),
        ("github", "ISSUE_COMMENT_DRAFT", "publish_issue_comment"),
        ("github", "PR_DESCRIPTION_DRAFT", "merge_pull_request"),
        ("shell", "REPORT_GENERATION", "execute_command"),
        ("shell", "GOVERNANCE_STATUS_READ", "mutate_governance_status"),
    ],
)
def test_undeclared_adapter_actions_fail_closed(adapter_name, capability, undeclared_action):
    contract = build_adapter_action_contract(
        adapter_name=adapter_name,
        capability=capability,
        action_type=undeclared_action,
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "UNKNOWN_ACTION_TYPE" in result["reason_codes"]


def test_capability_action_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "UNKNOWN_ACTION_TYPE" in result["reason_codes"]


def test_mismatched_action_scope_owner_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["action_scope_owner"] = "execution.adapters.browser_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_ACTION_SCOPE_OWNER_MISMATCH" in result["reason_codes"]


def test_mismatched_action_scope_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["action_scope_hash"] = "0" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_ACTION_SCOPE_HASH_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "reason_code"),
    [
        ("adapter_id", "ADAPTER_ID_MISSING"),
        ("adapter_owner", "ADAPTER_OWNER_MISSING"),
        ("adapter_identity_hash", "ADAPTER_IDENTITY_HASH_MISSING"),
        ("attestation_reference", "ADAPTER_ATTESTATION_REFERENCE_MISSING"),
    ],
)
def test_missing_adapter_identity_fields_fail_closed(field, reason_code):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert reason_code in result["reason_codes"]


def test_mismatched_adapter_id_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["adapter_id"] = "adapter.shell.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_ID_MISMATCH" in result["reason_codes"]


def test_mismatched_adapter_owner_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["adapter_owner"] = "execution.adapters.filesystem_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_OWNER_MISMATCH" in result["reason_codes"]


def test_mismatched_adapter_identity_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["adapter_identity_hash"] = "1" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_IDENTITY_HASH_MISMATCH" in result["reason_codes"]


def test_mismatched_attestation_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["attestation_reference"] = "usbay.adapter.browser.identity.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_ATTESTATION_REFERENCE_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    "field",
    [
        "provenance_owner",
        "provenance_source",
        "provenance_registered_at",
        "provenance_attestation_reference",
        "provenance_chain_hash",
    ],
)
def test_missing_adapter_provenance_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_PROVENANCE_MISSING" in result["reason_codes"]


def test_mismatched_provenance_owner_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["provenance_owner"] = "execution.adapters.browser_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_PROVENANCE_OWNER_MISMATCH" in result["reason_codes"]


def test_mismatched_provenance_source_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["provenance_source"] = "unregistered.adapter.registry"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_PROVENANCE_SOURCE_MISMATCH" in result["reason_codes"]


def test_mismatched_provenance_registration_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["provenance_registered_at"] = "2026-06-20T00:00:00Z"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_PROVENANCE_REGISTRATION_MISMATCH" in result["reason_codes"]


def test_mismatched_provenance_attestation_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["provenance_attestation_reference"] = "usbay.adapter.browser.provenance.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_PROVENANCE_ATTESTATION_MISMATCH" in result["reason_codes"]


def test_mismatched_provenance_chain_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["provenance_chain_hash"] = "2" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_PROVENANCE_CHAIN_HASH_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    "field",
    [
        "registration_id",
        "registration_state",
        "registration_owner",
        "registration_reference",
    ],
)
def test_missing_adapter_registration_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REGISTRATION_MISSING" in result["reason_codes"]


def test_invalid_adapter_registration_state_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["registration_state"] = "UNKNOWN"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REGISTRATION_STATE_INVALID" in result["reason_codes"]


@pytest.mark.parametrize(
    ("state", "reason_code"),
    [
        ("REVOKED", "ADAPTER_REGISTRATION_REVOKED"),
        ("SUSPENDED", "ADAPTER_REGISTRATION_SUSPENDED"),
        ("REGISTERED", "ADAPTER_REGISTRATION_NOT_ACTIVE"),
        ("APPROVED", "ADAPTER_REGISTRATION_NOT_ACTIVE"),
    ],
)
def test_inactive_adapter_registration_states_fail_closed(state, reason_code):
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["registration_state"] = state

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert reason_code in result["reason_codes"]


def test_mismatched_registration_owner_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["registration_owner"] = "execution.adapters.github_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REGISTRATION_OWNER_MISMATCH" in result["reason_codes"]


def test_mismatched_registration_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["registration_reference"] = "usbay.adapter.browser.registration.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REGISTRATION_REFERENCE_MISMATCH" in result["reason_codes"]


def test_active_approved_adapter_registration_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["registration_state"] == "ACTIVE"
    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


@pytest.mark.parametrize(
    "field",
    [
        "revocation_id",
        "revocation_reason",
        "revocation_owner",
        "revoked_by",
        "revoked_at",
        "revocation_reference",
    ],
)
def test_missing_adapter_revocation_record_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REVOCATION_MISSING" in result["reason_codes"]


def test_adapter_revoked_by_revocation_authority_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["revocation_reason"] = "SECURITY_COMPROMISE"
    contract["revoked_by"] = "security-governance"
    contract["revoked_at"] = "2026-06-21T01:00:00Z"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REVOKED" in result["reason_codes"]


def test_invalid_revocation_reason_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["revocation_reason"] = "UNKNOWN_REASON"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REVOCATION_REASON_INVALID" in result["reason_codes"]
    assert "ADAPTER_REVOKED" in result["reason_codes"]


def test_mismatched_revocation_owner_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["revocation_owner"] = "execution.adapters.github_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REVOCATION_OWNER_MISMATCH" in result["reason_codes"]


def test_mismatched_revocation_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["revocation_reference"] = "usbay.adapter.browser.revocation.none.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REVOCATION_REFERENCE_MISMATCH" in result["reason_codes"]


def test_invalid_revocation_timestamp_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["revocation_reason"] = "POLICY_VIOLATION"
    contract["revoked_by"] = "policy-governance"
    contract["revoked_at"] = "2026/06/21 01:00"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_REVOCATION_TIMESTAMP_INVALID" in result["reason_codes"]
    assert "ADAPTER_REVOKED" in result["reason_codes"]


@pytest.mark.parametrize(
    "field",
    [
        "approval_id",
        "approval_state",
        "approval_owner",
        "approved_by",
        "approved_at",
        "approval_reference",
    ],
)
def test_missing_adapter_approval_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_APPROVAL_MISSING" in result["reason_codes"]


@pytest.mark.parametrize(
    ("state", "reason_code"),
    [
        ("PENDING", "ADAPTER_APPROVAL_PENDING"),
        ("REJECTED", "ADAPTER_APPROVAL_REJECTED"),
        ("EXPIRED", "ADAPTER_APPROVAL_EXPIRED"),
        ("REVOKED", "ADAPTER_APPROVAL_REVOKED"),
    ],
)
def test_non_approved_adapter_approval_states_fail_closed(state, reason_code):
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["approval_state"] = state

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert reason_code in result["reason_codes"]


def test_invalid_adapter_approval_state_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["approval_state"] = "UNKNOWN"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_APPROVAL_STATE_INVALID" in result["reason_codes"]


def test_mismatched_approval_owner_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["approval_owner"] = "execution.adapters.github_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_APPROVAL_OWNER_MISMATCH" in result["reason_codes"]


def test_mismatched_approval_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["approval_reference"] = "usbay.adapter.browser.approval.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_APPROVAL_REFERENCE_MISMATCH" in result["reason_codes"]


def test_approved_active_non_revoked_adapter_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["registration_state"] == "ACTIVE"
    assert contract["approval_state"] == "APPROVED"
    assert contract["revocation_reason"] == "NOT_REVOKED"
    assert result["adapter_contract_status"] == "VALID"
    assert result["governance_consistency_status"] == "CONSISTENT"
    assert result["reason_codes"] == []


def test_governance_consistency_validation_success():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )

    result = validate_adapter_governance_consistency(contract)

    assert result["authority"] == ADAPTER_GOVERNANCE_CONSISTENCY_AUTHORITY
    assert result["governance_consistency_status"] == "CONSISTENT"
    assert result["reason_codes"] == []


def test_consistency_authority_owner_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["approval_owner"] = "execution.adapters.browser_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_AUTHORITY_OWNER_MISMATCH" in result["reason_codes"]


def test_consistency_authority_reference_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["approval_reference"] = "usbay.adapter.browser.approval.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_AUTHORITY_REFERENCE_MISMATCH" in result["reason_codes"]


def test_consistency_capability_action_drift_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_CAPABILITY_ACTION_DRIFT" in result["reason_codes"]


def test_consistency_identity_provenance_drift_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["attestation_reference"] = "usbay.adapter.shell.identity.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_IDENTITY_PROVENANCE_DRIFT" in result["reason_codes"]


def test_consistency_registration_approval_drift_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["registration_state"] = "APPROVED"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_REGISTRATION_APPROVAL_DRIFT" in result["reason_codes"]


def test_consistency_approval_revocation_conflict_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["revocation_reason"] = "OWNER_REVOKED"
    contract["revoked_by"] = "adapter-owner"
    contract["revoked_at"] = "2026-06-21T03:00:00Z"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_APPROVAL_REVOCATION_CONFLICT" in result["reason_codes"]


def test_consistency_duplicate_authority_identifier_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["approval_id"] = contract["registration_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_DUPLICATE_AUTHORITY_IDENTIFIER" in result["reason_codes"]


def test_consistency_missing_required_authority_linkage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract.pop("approval_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_consistency_status"] == "BLOCKED"
    assert "ADAPTER_CONSISTENCY_LINKAGE_MISSING" in result["reason_codes"]


def test_governance_reconciliation_validation_success():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )

    result = validate_adapter_governance_reconciliation(contract)

    assert result["authority"] == ADAPTER_GOVERNANCE_RECONCILIATION_AUTHORITY
    assert result["governance_reconciliation_status"] == "RECONCILED"
    assert result["reason_codes"] == []


def test_reconciliation_orphan_authority_record_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["adapter_name"] = "unknown"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_ORPHAN_AUTHORITY_RECORD" in result["reason_codes"]


def test_reconciliation_stale_state_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["reconciliation_status"] = "STALE"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_STALE_STATE" in result["reason_codes"]


def test_reconciliation_unresolved_conflict_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract["approval_reference"] = "usbay.adapter.browser.approval.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_UNRESOLVED_CONFLICT" in result["reason_codes"]


def test_reconciliation_timestamp_drift_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["reconciled_at"] = "2026-06-21T01:00:00Z"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_TIMESTAMP_DRIFT" in result["reason_codes"]


def test_reconciliation_ownership_divergence_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["reconciliation_owner"] = "execution.adapters.browser_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_OWNERSHIP_DIVERGENCE" in result["reason_codes"]


def test_reconciliation_reference_divergence_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["reconciliation_reference"] = "usbay.adapter.browser.reconciliation.v1"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_REFERENCE_DIVERGENCE" in result["reason_codes"]


def test_reconciliation_missing_linkage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract.pop("reconciliation_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_MISSING" in result["reason_codes"]
    assert "ADAPTER_RECONCILIATION_LINKAGE_MISSING" in result["reason_codes"]


def test_reconciliation_evidence_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["reconciliation_hash"] = "4" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_EVIDENCE_MISMATCH" in result["reason_codes"]


def test_reconciliation_duplicate_record_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="read_page_metadata",
        request_id="adapter-request-1",
    )
    contract["reconciliation_id"] = contract["approval_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["governance_reconciliation_status"] == "BLOCKED"
    assert "ADAPTER_RECONCILIATION_DUPLICATE_RECORD" in result["reason_codes"]


@pytest.mark.parametrize(
    "field",
    [
        "policy_binding_id",
        "policy_binding_owner",
        "policy_binding_status",
        "policy_binding_hash",
    ],
)
def test_missing_policy_binding_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_BINDING_MISSING" in result["reason_codes"]


def test_missing_policy_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract.pop("policy_binding_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_REFERENCE_MISSING" in result["reason_codes"]


def test_missing_policy_lineage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract.pop("policy_binding_lineage")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_LINEAGE_MISSING" in result["reason_codes"]


def test_policy_owner_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["policy_binding_owner"] = "execution.adapters.github_adapter"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_OWNER_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("policy_binding_id", "policy-binding.browser.read-only-navigation.v1"),
        ("policy_binding_reference", "runtime/policy_validator.py#browser.read-only-navigation"),
    ],
)
def test_policy_reference_mismatch_fails_closed(field, value):
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract[field] = value

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_REFERENCE_MISMATCH" in result["reason_codes"]


def test_policy_hash_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["policy_binding_hash"] = "5" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_HASH_MISMATCH" in result["reason_codes"]


def test_stale_policy_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="read_page_metadata",
        request_id="adapter-request-1",
    )
    contract["policy_binding_status"] = "STALE"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_BINDING_STALE" in result["reason_codes"]


def test_duplicate_policy_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["policy_binding_id"] = contract["registration_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_BINDING_DUPLICATE" in result["reason_codes"]


def test_orphan_policy_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["capability"] = "UNKNOWN_CAPABILITY"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["policy_binding_status"] == "BLOCKED"
    assert "POLICY_BINDING_ORPHAN" in result["reason_codes"]


def test_policy_bound_adapter_contract_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["policy_binding_owner"] == POLICY_BRAIN_BINDING_OWNER
    assert contract["policy_binding_status"] == POLICY_BRAIN_BINDING_STATUS
    assert result["policy_binding_status"] == POLICY_BRAIN_BINDING_STATUS
    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


def test_adapter_evaluate_blocks_missing_policy_binding():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("policy_binding_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "POLICY_BINDING_MISSING" in result["reason"]


@pytest.mark.parametrize(
    "field",
    [
        "gateway_binding_id",
        "gateway_binding_owner",
        "gateway_binding_status",
        "gateway_binding_hash",
    ],
)
def test_missing_gateway_binding_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_BINDING_MISSING" in result["reason_codes"]


def test_missing_gateway_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract.pop("gateway_binding_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_REFERENCE_MISSING" in result["reason_codes"]


def test_missing_gateway_lineage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract.pop("gateway_binding_lineage")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_LINEAGE_MISSING" in result["reason_codes"]


def test_gateway_owner_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["gateway_binding_owner"] = "runtime.enforcement_gateway"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_OWNER_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("gateway_binding_id", "gateway-binding.browser.read-only-navigation.v1"),
        ("gateway_binding_reference", "docs/audits/EXECUTION_SURFACE_MAP.md#browser.read-only-navigation"),
    ],
)
def test_gateway_reference_mismatch_fails_closed(field, value):
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract[field] = value

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_REFERENCE_MISMATCH" in result["reason_codes"]


def test_gateway_hash_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["gateway_binding_hash"] = "6" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_HASH_MISMATCH" in result["reason_codes"]


def test_stale_gateway_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="read_page_metadata",
        request_id="adapter-request-1",
    )
    contract["gateway_binding_status"] = "STALE"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_BINDING_STALE" in result["reason_codes"]


def test_duplicate_gateway_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["gateway_binding_id"] = contract["policy_binding_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_BINDING_DUPLICATE" in result["reason_codes"]


def test_orphan_gateway_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["capability"] = "UNKNOWN_CAPABILITY"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["gateway_binding_status"] == "BLOCKED"
    assert "GATEWAY_BINDING_ORPHAN" in result["reason_codes"]


def test_gateway_reconciled_adapter_contract_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["gateway_binding_owner"] == GATEWAY_ADAPTER_BINDING_OWNER
    assert contract["gateway_binding_status"] == GATEWAY_ADAPTER_BINDING_STATUS
    assert result["gateway_binding_status"] == GATEWAY_ADAPTER_BINDING_STATUS
    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


def test_adapter_evaluate_blocks_missing_gateway_binding():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("gateway_binding_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "GATEWAY_BINDING_MISSING" in result["reason"]


@pytest.mark.parametrize(
    "field",
    [
        "simulator_binding_id",
        "simulator_binding_owner",
        "simulator_binding_status",
        "simulator_binding_hash",
    ],
)
def test_missing_simulator_binding_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_BINDING_MISSING" in result["reason_codes"]


def test_missing_simulator_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract.pop("simulator_binding_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_REFERENCE_MISSING" in result["reason_codes"]


def test_missing_simulator_lineage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract.pop("simulator_binding_lineage")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_LINEAGE_MISSING" in result["reason_codes"]


def test_simulator_owner_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["simulator_binding_owner"] = "runtime.enforcement_gateway"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_OWNER_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("simulator_binding_id", "simulator-runtime-binding.browser.read-only-navigation.v1"),
        ("simulator_binding_reference", "tests/test_simulation_governance.py#browser.read-only-navigation"),
    ],
)
def test_simulator_reference_mismatch_fails_closed(field, value):
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract[field] = value

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_REFERENCE_MISMATCH" in result["reason_codes"]


def test_simulator_hash_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["simulator_binding_hash"] = "7" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_HASH_MISMATCH" in result["reason_codes"]


def test_stale_simulator_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="read_page_metadata",
        request_id="adapter-request-1",
    )
    contract["simulator_binding_status"] = "STALE"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_BINDING_STALE" in result["reason_codes"]


def test_duplicate_simulator_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["simulator_binding_id"] = contract["gateway_binding_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_BINDING_DUPLICATE" in result["reason_codes"]


def test_orphan_simulator_binding_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["capability"] = "UNKNOWN_CAPABILITY"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["simulator_binding_status"] == "BLOCKED"
    assert "SIMULATOR_BINDING_ORPHAN" in result["reason_codes"]


def test_simulator_runtime_bound_adapter_contract_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["simulator_binding_owner"] == SIMULATOR_RUNTIME_BINDING_OWNER
    assert contract["simulator_binding_status"] == SIMULATOR_RUNTIME_BINDING_STATUS
    assert result["simulator_binding_status"] == SIMULATOR_RUNTIME_BINDING_STATUS
    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


def test_adapter_evaluate_blocks_missing_simulator_binding():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("simulator_binding_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "SIMULATOR_BINDING_MISSING" in result["reason"]


@pytest.mark.parametrize(
    "field",
    [
        "e2e_evidence_hash_id",
        "e2e_evidence_hash_owner",
        "e2e_evidence_hash_status",
        "e2e_evidence_hash",
    ],
)
def test_missing_e2e_evidence_hash_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_HASH_MISSING" in result["reason_codes"]


def test_missing_e2e_evidence_source_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract.pop("e2e_evidence_hash_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_SOURCE_MISSING" in result["reason_codes"]


def test_missing_e2e_evidence_lineage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract.pop("e2e_evidence_hash_lineage")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_LINEAGE_MISSING" in result["reason_codes"]


def test_e2e_evidence_ownership_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["e2e_evidence_hash_owner"] = "runtime.enforcement_gateway"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_OWNERSHIP_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("e2e_evidence_hash_id", "e2e-evidence-hash.browser.read-only-navigation.v1"),
        (
            "e2e_evidence_hash_reference",
            "docs/audits/CROSS_LAYER_GOVERNANCE_EVIDENCE_MATRIX.md#browser.read-only-navigation",
        ),
    ],
)
def test_e2e_evidence_source_mismatch_fails_closed(field, value):
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract[field] = value

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_SOURCE_MISMATCH" in result["reason_codes"]


def test_e2e_evidence_hash_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["e2e_evidence_hash"] = "8" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_HASH_MISMATCH" in result["reason_codes"]


def test_stale_e2e_evidence_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="read_page_metadata",
        request_id="adapter-request-1",
    )
    contract["e2e_evidence_hash_status"] = "STALE"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_HASH_STALE" in result["reason_codes"]


def test_duplicate_e2e_evidence_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["e2e_evidence_hash_id"] = contract["simulator_binding_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_HASH_DUPLICATE" in result["reason_codes"]


def test_orphan_e2e_evidence_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["capability"] = "UNKNOWN_CAPABILITY"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["e2e_evidence_hash_status"] == "BLOCKED"
    assert "E2E_EVIDENCE_HASH_ORPHAN" in result["reason_codes"]


def test_e2e_evidence_verified_adapter_contract_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["e2e_evidence_hash_owner"] == E2E_EVIDENCE_HASH_OWNER
    assert contract["e2e_evidence_hash_status"] == E2E_EVIDENCE_HASH_STATUS
    assert result["e2e_evidence_hash_status"] == E2E_EVIDENCE_HASH_STATUS
    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


def test_adapter_evaluate_blocks_missing_e2e_evidence_hash():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("e2e_evidence_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "E2E_EVIDENCE_HASH_MISSING" in result["reason"]


@pytest.mark.parametrize(
    "field",
    [
        "regulator_package_id",
        "regulator_package_owner",
        "regulator_package_status",
    ],
)
def test_missing_regulator_package_fails_closed(field):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop(field)

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_MISSING" in result["reason_codes"]


def test_missing_regulator_package_hash_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract.pop("regulator_package_hash")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_HASH_MISSING" in result["reason_codes"]


def test_missing_regulator_package_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )
    contract.pop("regulator_package_reference")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_REFERENCE_MISSING" in result["reason_codes"]


def test_missing_regulator_package_lineage_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract.pop("regulator_package_lineage")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_LINEAGE_MISSING" in result["reason_codes"]


def test_missing_regulator_package_e2e_hash_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract.pop("e2e_evidence_hash")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_E2E_HASH_REFERENCE_MISSING" in result["reason_codes"]


def test_stale_regulator_package_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="read_page_metadata",
        request_id="adapter-request-1",
    )
    contract["regulator_package_status"] = "STALE"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_STALE" in result["reason_codes"]


def test_orphan_regulator_package_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["capability"] = "UNKNOWN_CAPABILITY"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_ORPHAN" in result["reason_codes"]


def test_duplicate_regulator_package_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["regulator_package_id"] = contract["e2e_evidence_hash_id"]

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_DUPLICATE" in result["reason_codes"]


def test_regulator_package_ownership_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="PR_DESCRIPTION_DRAFT",
        action_type="draft_pr_description",
        request_id="adapter-request-1",
    )
    contract["regulator_package_owner"] = "runtime.enforcement_gateway"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_OWNERSHIP_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("regulator_package_id", "regulator-package.browser.read-only-navigation.v1"),
        (
            "regulator_package_reference",
            "docs/audits/REGULATOR_GRADE_EVIDENCE_PACKAGE_MATRIX.md#browser.read-only-navigation",
        ),
    ],
)
def test_regulator_package_source_mismatch_fails_closed(field, value):
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract[field] = value

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_SOURCE_MISMATCH" in result["reason_codes"]


def test_regulator_package_hash_mismatch_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )
    contract["regulator_package_hash"] = "9" * 64

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_HASH_MISMATCH" in result["reason_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("regulator_package_reference", "raw_payload:classified"),
        ("regulator_package_lineage", "contains-secret-material"),
        ("regulator_package_id", "raw_client_id-123"),
        ("regulator_package_owner", "signature-authority"),
    ],
)
def test_regulator_package_sensitive_data_fails_closed(field, value):
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract[field] = value

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert result["regulator_package_status"] == "BLOCKED"
    assert "REGULATOR_PACKAGE_SENSITIVE_DATA_PRESENT" in result["reason_codes"]


def test_regulator_package_verified_adapter_contract_is_allowed():
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="GOVERNANCE_STATUS_READ",
        action_type="read_governance_status",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert contract["regulator_package_owner"] == REGULATOR_PACKAGE_OWNER
    assert contract["regulator_package_status"] == REGULATOR_PACKAGE_STATUS
    assert result["regulator_package_status"] == REGULATOR_PACKAGE_STATUS
    assert result["adapter_contract_status"] == "VALID"
    assert result["reason_codes"] == []


def test_adapter_evaluate_blocks_missing_regulator_package_hash():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("regulator_package_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "REGULATOR_PACKAGE_HASH_MISSING" in result["reason"]


def test_missing_capability_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("capability")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_CONTRACT_CAPABILITY_MISSING" in result["reason_codes"]


def test_missing_adapter_ownership_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("owner")

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_OWNERSHIP_MISSING" in result["reason_codes"]


def test_mismatched_adapter_ownership_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(
        contract,
        canonical_gate_proof=ready_gate_proof(),
        expected_adapter_name="browser",
    )

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_OWNERSHIP_MISMATCH" in result["reason_codes"]


def test_wrong_governance_gate_reference_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["governance_gate_reference"] = "runtime.unapproved_gate"

    result = validate_adapter_action_contract(contract, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_GATE_REFERENCE_MISMATCH" in result["reason_codes"]


def test_missing_canonical_gate_proof_fails_closed():
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )

    result = validate_adapter_action_contract(contract)

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "MISSING_CANONICAL_GATE_PROOF" in result["reason_codes"]


def test_malformed_adapter_contract_fails_closed():
    result = validate_adapter_action_contract({"adapter_name": "browser"}, canonical_gate_proof=ready_gate_proof())

    assert result["adapter_contract_status"] == "BLOCKED"
    assert "ADAPTER_CONTRACT_MALFORMED" in result["reason_codes"]


def test_adapter_evaluate_blocks_invalid_contract_before_disabled_response():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="click_button",
        request_id="adapter-request-1",
    )

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "UNKNOWN_ACTION_TYPE" in result["reason"]


@pytest.mark.parametrize(
    ("adapter", "capability", "undeclared_action"),
    [
        (BrowserExecutionAdapter(), "READ_ONLY_NAVIGATION", "submit_form"),
        (FilesystemExecutionAdapter(), "FILE_READ", "delete_file"),
        (GitHubExecutionAdapter(), "ISSUE_COMMENT_DRAFT", "publish_issue_comment"),
        (ShellExecutionAdapter(), "REPORT_GENERATION", "execute_command"),
    ],
)
def test_adapter_evaluate_blocks_undeclared_action_scope(adapter, capability, undeclared_action):
    contract = build_adapter_action_contract(
        adapter_name=adapter.adapter_name,
        capability=capability,
        action_type=undeclared_action,
        request_id="adapter-request-1",
    )

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "UNKNOWN_ACTION_TYPE" in result["reason"]


def test_adapter_evaluate_blocks_mismatched_action_scope_owner():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["action_scope_owner"] = "execution.adapters.browser_adapter"

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_ACTION_SCOPE_OWNER_MISMATCH" in result["reason"]


def test_adapter_evaluate_blocks_missing_identity_attestation():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("adapter_identity_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_IDENTITY_HASH_MISSING" in result["reason"]


def test_adapter_evaluate_blocks_mismatched_identity_attestation():
    adapter = ShellExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract["adapter_owner"] = "execution.adapters.shell_adapter"

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_OWNER_MISMATCH" in result["reason"]


def test_adapter_evaluate_blocks_missing_provenance():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract.pop("provenance_chain_hash")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_PROVENANCE_MISSING" in result["reason"]


def test_adapter_evaluate_blocks_mismatched_provenance_chain_hash():
    adapter = FilesystemExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["provenance_chain_hash"] = "3" * 64

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_PROVENANCE_CHAIN_HASH_MISMATCH" in result["reason"]


def test_adapter_evaluate_blocks_revoked_registration():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["registration_state"] = "REVOKED"

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_REGISTRATION_REVOKED" in result["reason"]


def test_adapter_evaluate_blocks_suspended_registration():
    adapter = FilesystemExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="filesystem",
        capability="FILE_READ",
        action_type="preview_file",
        request_id="adapter-request-1",
    )
    contract["registration_state"] = "SUSPENDED"

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_REGISTRATION_SUSPENDED" in result["reason"]


def test_adapter_evaluate_blocks_missing_registration():
    adapter = ShellExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract.pop("registration_reference")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_REGISTRATION_MISSING" in result["reason"]


def test_adapter_evaluate_blocks_revocation_record():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["revocation_reason"] = "OWNER_REVOKED"
    contract["revoked_by"] = "adapter-owner"
    contract["revoked_at"] = "2026-06-21T02:00:00Z"

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_REVOKED" in result["reason"]


def test_adapter_evaluate_blocks_malformed_revocation_record():
    adapter = ShellExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract.pop("revocation_reference")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_REVOCATION_MISSING" in result["reason"]


def test_adapter_evaluate_blocks_pending_approval():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="browser",
        capability="READ_ONLY_NAVIGATION",
        action_type="open_url_preview",
        request_id="adapter-request-1",
    )
    contract["approval_state"] = "PENDING"

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_APPROVAL_PENDING" in result["reason"]


def test_adapter_evaluate_blocks_missing_approval():
    adapter = ShellExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="shell",
        capability="REPORT_GENERATION",
        action_type="generate_report",
        request_id="adapter-request-1",
    )
    contract.pop("approval_reference")

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_APPROVAL_MISSING" in result["reason"]


def test_adapter_evaluate_blocks_action_request_without_contract():
    adapter = FilesystemExecutionAdapter()

    result = adapter.evaluate({"action_type": "preview_file", "request_id": "adapter-request-1"})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_ACTION_CONTRACT_MISSING" in result["reason"]


def test_adapter_evaluate_blocks_contract_for_different_adapter():
    adapter = BrowserExecutionAdapter()
    contract = build_adapter_action_contract(
        adapter_name="github",
        capability="ISSUE_COMMENT_DRAFT",
        action_type="draft_issue_comment",
        request_id="adapter-request-1",
    )

    result = adapter.evaluate({"adapter_contract": contract, "canonical_gate_proof": ready_gate_proof()})

    assert result["decision"] == EXECUTION_BLOCKED
    assert result["status"] == EXECUTION_DISABLED
    assert "ADAPTER_OWNERSHIP_MISMATCH" in result["reason"]
