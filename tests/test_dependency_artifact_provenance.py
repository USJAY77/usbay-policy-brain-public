from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from governance.dependency_artifact_provenance import (
    DENY,
    ELIGIBLE,
    FAILED,
    PARTIAL,
    PROVEN,
    UNKNOWN,
    VerificationResult,
    artifact_record_hash,
    evaluate_artifact_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-04T12:00:00Z"
ARTIFACT_HASH = "a" * 64


def active_policy() -> dict:
    policy = json.loads((ROOT / "governance/dependency_artifact_policy.json").read_text(encoding="utf-8"))
    policy.update(
        status="active",
        policy_version="test-policy-v1",
        accepted_predicate_types=["https://slsa.dev/provenance/v1"],
        accepted_signer_identities=["https://example.test/workflows/release.yml@refs/tags/v1.0.0"],
        accepted_issuers=["https://issuer.example.test"],
        accepted_source_repositories=["https://example.test/human-reviewed/project"],
        accepted_transparency_logs=["test-log"],
        accepted_checkpoint_authorities=["test-checkpoint-authority"],
        allowed_human_actors=["human-reviewer-1"],
    )
    return policy


def evidence_record() -> dict:
    record = {
        "schema": "usbay.dependency_artifact_evidence.v1",
        "record_id": "synthetic-record-1",
        "package": {
            "normalized_project_name": "synthetic-package",
            "index_project_identity": "https://index.example.test/project/synthetic-package",
            "version": "1.0.0",
        },
        "artifact": {"filename": "synthetic_package-1.0.0-cp311-cp311-macosx_11_0_arm64.whl", "sha256": ARTIFACT_HASH, "size": 1234},
        "platform": {
            "os": "macos", "architecture": "arm64", "python_implementation": "cpython",
            "python_version": "3.11", "python_tag": "cp311", "abi_tag": "cp311",
            "wheel_platform_tag": "macosx_11_0_arm64",
        },
        "source": {
            "upstream_repository": "https://example.test/human-reviewed/project",
            "release_tag": "v1.0.0", "source_commit_sha": "b" * 40,
        },
        "build": {
            "workflow_identity": "release.yml", "workflow_definition_sha256": "c" * 64,
            "workflow_run_id": "run-1", "workflow_job_id": "job-1", "builder_identity": "builder-1",
        },
        "attestation": {
            "predicate_type": "https://slsa.dev/provenance/v1",
            "subject_name": "synthetic_package-1.0.0-cp311-cp311-macosx_11_0_arm64.whl",
            "subject_sha256": ARTIFACT_HASH, "signature": "public-test-signature",
            "certificate_or_key_fingerprint": "sha256:" + "d" * 64,
            "signer_identity": "https://example.test/workflows/release.yml@refs/tags/v1.0.0",
            "issuer_identity": "https://issuer.example.test",
            "issued_at": "2026-09-04T00:00:00Z", "expires_at": "2026-09-05T00:00:00Z",
        },
        "transparency": {
            "log_id": "test-log", "entry_identifier": "entry-1",
            "integrated_time": "2026-09-04T00:01:00Z",
            "inclusion_proof_hash": "sha256:" + "e" * 64,
            "signed_checkpoint": "public-test-checkpoint", "checkpoint_identity": "test-checkpoint-authority",
            "checkpoint_time": "2026-09-04T00:02:00Z",
        },
        "witnesses": [
            {"witness_id": "witness-1", "state": PROVEN, "acquisition_channel": "channel-a", "operator_domain": "operator-a", "evidence_sha256": "sha256:" + "1" * 64, "independence_state": PROVEN},
            {"witness_id": "witness-2", "state": PROVEN, "acquisition_channel": "channel-b", "operator_domain": "operator-b", "evidence_sha256": "sha256:" + "2" * 64, "independence_state": PROVEN},
        ],
        "approvals": [
            {"decision": "APPROVE", "actor_type": "human", "actor_id": "human-reviewer-1", "actor_role": "USBAY_HUMAN_GOVERNANCE", "device_id": "device-1", "timestamp": "2026-09-04T01:00:00Z", "policy_version": "test-policy-v1", "approval_evidence_sha256": "sha256:" + "3" * 64}
        ],
        "lineage": {
            "generation": 1, "previous_record_hash": "sha256:" + "0" * 64,
            "supersedes_record_id": None, "effective_at": "2026-09-04T01:00:00Z",
            "expires_at": "2026-09-05T00:00:00Z",
        },
        "record_hash": "sha256:" + "0" * 64,
    }
    record["record_hash"] = artifact_record_hash(record)
    return record


class ProvenVerifier:
    def __init__(self, *, state=PROVEN, **overrides):
        self.state = state
        self.overrides = overrides

    def verify(self, record, policy, *, evaluated_at):
        del policy, evaluated_at
        values = {
            "state": self.state,
            "subject_name": record["artifact"]["filename"],
            "subject_sha256": record["artifact"]["sha256"],
            "predicate_type": record["attestation"]["predicate_type"],
            "signer_identity": record["attestation"]["signer_identity"],
            "issuer_identity": record["attestation"]["issuer_identity"],
            "source_repository": record["source"]["upstream_repository"],
            "source_commit_sha": record["source"]["source_commit_sha"],
            "workflow_identity": record["build"]["workflow_identity"],
            "workflow_run_id": record["build"]["workflow_run_id"],
            "workflow_job_id": record["build"]["workflow_job_id"],
            "transparency_state": PROVEN,
            "transparency_log_id": record["transparency"]["log_id"],
            "checkpoint_identity": record["transparency"]["checkpoint_identity"],
            "checkpoint_time": record["transparency"]["checkpoint_time"],
            "verified_at": NOW,
        }
        values.update(self.overrides)
        return VerificationResult(**values)


def evaluate(record=None, policy=None, verifier=None):
    return evaluate_artifact_evidence(
        record or evidence_record(), policy or active_policy(), verifier or ProvenVerifier(), evaluated_at=NOW
    )


def rehash(record):
    record["record_hash"] = artifact_record_hash(record)
    return record


def test_complete_independently_proven_human_approved_evidence_is_eligible():
    decision = evaluate()
    assert decision.decision == ELIGIBLE
    assert decision.evidence_state == PROVEN
    assert decision.reason_codes == ()


def test_repository_policy_initial_state_is_deny():
    policy = json.loads((ROOT / "governance/dependency_artifact_policy.json").read_text(encoding="utf-8"))
    decision = evaluate(policy=policy)
    assert decision.decision == DENY
    assert "DEPENDENCY_ARTIFACT_POLICY_INACTIVE" in decision.reason_codes
    assert policy["accepted_signer_identities"] == []
    assert policy["allowed_human_actors"] == []


@pytest.mark.parametrize("state", [PARTIAL, UNKNOWN, FAILED])
def test_non_proven_verifier_states_deny(state):
    decision = evaluate(verifier=ProvenVerifier(state=state))
    assert decision.decision == DENY
    assert "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN" in decision.reason_codes


def test_unavailable_default_verifier_denies():
    decision = evaluate_artifact_evidence(evidence_record(), active_policy(), evaluated_at=NOW)
    assert decision.decision == DENY
    assert "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN" in decision.reason_codes


@pytest.mark.parametrize(
    "override",
    [
        {"subject_sha256": "f" * 64},
        {"source_repository": "https://substitute.example.test/project"},
        {"source_commit_sha": "f" * 40},
        {"workflow_job_id": "substituted-job"},
        {"signer_identity": "substituted-signer"},
        {"issuer_identity": "substituted-issuer"},
        {"transparency_log_id": "substituted-log"},
    ],
)
def test_substitution_in_verified_result_denies(override):
    decision = evaluate(verifier=ProvenVerifier(**override))
    assert decision.decision == DENY
    assert "DEPENDENCY_ARTIFACT_SUBSTITUTION" in decision.reason_codes


def test_artifact_to_attestation_digest_mismatch_denies():
    record = evidence_record()
    record["attestation"]["subject_sha256"] = "f" * 64
    decision = evaluate(record=rehash(record))
    assert "DEPENDENCY_ARTIFACT_BINDING_MISMATCH" in decision.reason_codes


def test_integrity_hash_mismatch_denies():
    record = evidence_record()
    record["package"]["version"] = "2.0.0"
    assert "DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE" in evaluate(record=record).reason_codes


def test_stale_evidence_and_checkpoint_deny():
    record = evidence_record()
    record["attestation"]["issued_at"] = "2026-08-01T00:00:00Z"
    record["transparency"]["checkpoint_time"] = "2026-08-01T00:00:00Z"
    decision = evaluate(record=rehash(record), verifier=ProvenVerifier(checkpoint_time="2026-08-01T00:00:00Z"))
    assert "DEPENDENCY_ARTIFACT_EVIDENCE_STALE" in decision.reason_codes
    assert "DEPENDENCY_ARTIFACT_EXTERNAL_CHECKPOINT_MISSING" in decision.reason_codes


def test_duplicate_or_unknown_witness_independence_does_not_reach_threshold():
    record = evidence_record()
    record["witnesses"][1]["operator_domain"] = "operator-a"
    record["witnesses"][1]["acquisition_channel"] = "channel-a"
    assert "DEPENDENCY_ARTIFACT_INDEPENDENCE_UNKNOWN" in evaluate(record=rehash(record)).reason_codes


def test_conflicting_mandatory_evidence_denies():
    record = evidence_record()
    conflict = copy.deepcopy(record["witnesses"][0])
    conflict["witness_id"] = "witness-conflict"
    conflict["state"] = FAILED
    conflict["operator_domain"] = "operator-c"
    conflict["acquisition_channel"] = "channel-c"
    record["witnesses"].append(conflict)
    assert "DEPENDENCY_ARTIFACT_CONFLICT" in evaluate(record=rehash(record)).reason_codes


@pytest.mark.parametrize("actor_type", ["model", "provider", "ai", "agent"])
def test_model_or_provider_cannot_supply_approval(actor_type):
    record = evidence_record()
    record["approvals"][0]["actor_type"] = actor_type
    decision = evaluate(record=rehash(record))
    assert "DEPENDENCY_ARTIFACT_MODEL_AUTHORITY_FORBIDDEN" in decision.reason_codes
    assert "DEPENDENCY_ARTIFACT_APPROVAL_MISSING" in decision.reason_codes


def test_unapproved_human_and_wrong_policy_version_deny():
    record = evidence_record()
    record["approvals"][0]["actor_id"] = "unknown-human"
    record["approvals"][0]["policy_version"] = "other-policy"
    assert "DEPENDENCY_ARTIFACT_APPROVAL_MISSING" in evaluate(record=rehash(record)).reason_codes


def test_verifier_exception_fails_closed():
    class BrokenVerifier:
        def verify(self, record, policy, *, evaluated_at):
            raise TimeoutError("ambiguous verifier outcome")

    decision = evaluate(verifier=BrokenVerifier())
    assert decision.decision == DENY
    assert "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN" in decision.reason_codes


def test_schema_and_policy_contain_no_observed_or_sensitive_material():
    schema = json.loads((ROOT / "governance/dependency_artifact_provenance.schema.json").read_text(encoding="utf-8"))
    policy_text = (ROOT / "governance/dependency_artifact_policy.json").read_text(encoding="utf-8").lower()
    schema_text = json.dumps(schema).lower()
    forbidden = ("e0d65b8c354be7fb5f720c3caa8bc940bc2d20ce749c8e06135f07f8ed95dd7c", "private key", "access_token", "bearer ", "password")
    assert schema["additionalProperties"] is False
    assert all(value not in policy_text + schema_text for value in forbidden)
