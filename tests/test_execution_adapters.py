from __future__ import annotations

from pathlib import Path

import pytest

from execution.adapters.base import (
    ADAPTER_ACTION_SCOPE_OWNER,
    ADAPTER_CONTRACT_OWNER,
    ADAPTER_GOVERNANCE_GATE_REFERENCE,
    ADAPTER_IDENTITY_OWNER,
    ADAPTER_NOT_IMPLEMENTED,
    ADAPTER_PROVENANCE_OWNER,
    ADAPTER_PROVENANCE_SOURCE,
    ADAPTER_REGISTRATION_AUTHORITY,
    ADAPTER_REGISTRATION_OWNER,
    ADAPTER_REVOCATION_AUTHORITY,
    ADAPTER_REVOCATION_OWNER,
    EXECUTION_BLOCKED,
    EXECUTION_DISABLED,
    adapter_capability_map,
    build_adapter_action_contract,
    validate_adapter_action_contract,
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
