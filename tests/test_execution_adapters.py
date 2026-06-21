from __future__ import annotations

from pathlib import Path

import pytest

from execution.adapters.base import (
    ADAPTER_CONTRACT_OWNER,
    ADAPTER_GOVERNANCE_GATE_REFERENCE,
    ADAPTER_NOT_IMPLEMENTED,
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
