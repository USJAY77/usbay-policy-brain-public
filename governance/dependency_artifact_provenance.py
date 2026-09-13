"""Fail-closed, provider-neutral dependency artifact provenance decisions.

This module performs no network access and grants no authority to a verifier,
model, package index, or dependency publisher. A verifier supplies evidence;
human-governed policy determines whether that evidence is eligible.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, Sequence

from governance.hashing import is_sha256_hex, is_sha256_reference, sha256_reference


PROVEN = "PROVEN"
PARTIAL = "PARTIAL"
UNKNOWN = "UNKNOWN"
FAILED = "FAILED"
ELIGIBLE = "ELIGIBLE"
DENY = "DENY"
ZERO_HASH = "sha256:" + ("0" * 64)


@dataclass(frozen=True)
class VerificationResult:
    state: str
    subject_name: str = ""
    subject_sha256: str = ""
    predicate_type: str = ""
    signer_identity: str = ""
    issuer_identity: str = ""
    source_repository: str = ""
    source_commit_sha: str = ""
    workflow_identity: str = ""
    workflow_run_id: str = ""
    workflow_job_id: str = ""
    transparency_state: str = UNKNOWN
    transparency_log_id: str = ""
    checkpoint_identity: str = ""
    checkpoint_time: str = ""
    verified_at: str = ""
    reason_code: str = "DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN"


@dataclass(frozen=True)
class EligibilityDecision:
    decision: str
    evidence_state: str
    reason_codes: tuple[str, ...]
    record_id: str = ""
    record_hash: str = ""

    @property
    def eligible(self) -> bool:
        return self.decision == ELIGIBLE and self.evidence_state == PROVEN


class ArtifactAttestationVerifier(Protocol):
    """Evidence mechanism only; implementations never set governance policy."""

    def verify(
        self,
        record: Mapping[str, Any],
        policy: Mapping[str, Any],
        *,
        evaluated_at: str,
    ) -> VerificationResult: ...


class UnavailableArtifactAttestationVerifier:
    """Safe default until a separately governed verifier is configured."""

    def verify(
        self,
        record: Mapping[str, Any],
        policy: Mapping[str, Any],
        *,
        evaluated_at: str,
    ) -> VerificationResult:
        del record, policy, evaluated_at
        return VerificationResult(state=UNKNOWN)


def artifact_record_hash(record: Mapping[str, Any]) -> str:
    body = dict(record)
    body.pop("record_hash", None)
    return sha256_reference(body)


def evaluate_artifact_evidence(
    record: Mapping[str, Any],
    policy: Mapping[str, Any],
    verifier: ArtifactAttestationVerifier | None = None,
    *,
    evaluated_at: str,
) -> EligibilityDecision:
    """Return ELIGIBLE only when every independently required gate is proven."""

    record_id = str(record.get("record_id", "")) if isinstance(record, Mapping) else ""
    record_hash = str(record.get("record_hash", "")) if isinstance(record, Mapping) else ""
    reasons: list[str] = []

    if not _policy_valid(policy):
        reasons.append("DEPENDENCY_ARTIFACT_POLICY_INACTIVE")
    if not _record_shape_valid(record):
        reasons.append("DEPENDENCY_ARTIFACT_EVIDENCE_INCOMPLETE")
        return _deny(record_id, record_hash, reasons)
    if record_hash != artifact_record_hash(record):
        reasons.append("DEPENDENCY_ARTIFACT_INTEGRITY_FAILURE")

    target = policy.get("target", {})
    platform = record["platform"]
    for key in ("os", "architecture", "python_implementation", "python_version", "python_tag"):
        if platform.get(key) != target.get(key):
            reasons.append("DEPENDENCY_ARTIFACT_PLATFORM_MISMATCH")
            break

    artifact = record["artifact"]
    attestation = record["attestation"]
    if (
        artifact.get("filename") != attestation.get("subject_name")
        or artifact.get("sha256") != attestation.get("subject_sha256")
        or not is_sha256_hex(artifact.get("sha256"))
    ):
        reasons.append("DEPENDENCY_ARTIFACT_BINDING_MISMATCH")

    if _contains_model_authority(record):
        reasons.append("DEPENDENCY_ARTIFACT_MODEL_AUTHORITY_FORBIDDEN")

    now = _timestamp(evaluated_at)
    if now is None or not _fresh(record, policy, now):
        reasons.append("DEPENDENCY_ARTIFACT_EVIDENCE_STALE")

    verification = _safe_verify(verifier or UnavailableArtifactAttestationVerifier(), record, policy, evaluated_at)
    if verification.state != PROVEN:
        reasons.append("DEPENDENCY_ARTIFACT_PROVENANCE_NOT_PROVEN")
    elif not _verification_binding_valid(record, policy, verification):
        reasons.append("DEPENDENCY_ARTIFACT_SUBSTITUTION")

    if verification.transparency_state != PROVEN:
        reasons.append("DEPENDENCY_ARTIFACT_TRANSPARENCY_FAILED")
    if not _checkpoint_valid(record, policy, verification, now):
        reasons.append("DEPENDENCY_ARTIFACT_EXTERNAL_CHECKPOINT_MISSING")

    if not _witness_threshold_satisfied(record["witnesses"], policy):
        reasons.append("DEPENDENCY_ARTIFACT_INDEPENDENCE_UNKNOWN")
    if _conflicting_witnesses(record["witnesses"]):
        reasons.append("DEPENDENCY_ARTIFACT_CONFLICT")
    if not _human_approvals_valid(record["approvals"], policy):
        reasons.append("DEPENDENCY_ARTIFACT_APPROVAL_MISSING")

    if reasons:
        return _deny(record_id, record_hash, reasons)
    return EligibilityDecision(ELIGIBLE, PROVEN, (), record_id, record_hash)


def _deny(record_id: str, record_hash: str, reasons: Sequence[str]) -> EligibilityDecision:
    return EligibilityDecision(DENY, FAILED, tuple(dict.fromkeys(reasons)), record_id, record_hash)


def _policy_valid(policy: Mapping[str, Any]) -> bool:
    try:
        return bool(
            policy.get("schema") == "usbay.dependency_artifact_policy.v1"
            and policy.get("status") == "active"
            and policy.get("default_decision") == DENY
            and policy.get("model_provider_authority") == DENY
            and policy.get("accepted_predicate_types")
            and policy.get("accepted_signer_identities")
            and policy.get("accepted_issuers")
            and policy.get("accepted_source_repositories")
            and policy.get("accepted_transparency_logs")
            and policy.get("accepted_checkpoint_authorities")
            and policy.get("allowed_human_actors")
            and all(policy.get("required_evidence", {}).values())
            and policy.get("human_approval", {}).get("required") is True
            and int(policy.get("human_approval", {}).get("minimum_approvals", 0)) > 0
            and int(policy.get("witness_policy", {}).get("minimum_independent_witnesses", 0)) > 0
            and policy.get("witness_policy", {}).get("unknown_independence_satisfies_threshold") is False
        )
    except (TypeError, ValueError):
        return False


def _record_shape_valid(record: Mapping[str, Any]) -> bool:
    if not isinstance(record, Mapping):
        return False
    required = {
        "schema", "record_id", "package", "artifact", "platform", "source", "build",
        "attestation", "transparency", "witnesses", "approvals", "lineage", "record_hash",
    }
    if set(record) != required or record.get("schema") != "usbay.dependency_artifact_evidence.v1":
        return False
    mappings = ("package", "artifact", "platform", "source", "build", "attestation", "transparency", "lineage")
    if any(not isinstance(record.get(key), Mapping) for key in mappings):
        return False
    if not isinstance(record.get("witnesses"), list) or not isinstance(record.get("approvals"), list):
        return False
    if not record.get("record_id") or not is_sha256_reference(record.get("record_hash")):
        return False
    artifact = record["artifact"]
    source = record["source"]
    lineage = record["lineage"]
    return bool(
        artifact.get("filename")
        and is_sha256_hex(artifact.get("sha256"))
        and isinstance(artifact.get("size"), int) and artifact["size"] > 0
        and isinstance(source.get("source_commit_sha"), str) and len(source["source_commit_sha"]) == 40
        and isinstance(lineage.get("generation"), int) and lineage["generation"] > 0
        and is_sha256_reference(lineage.get("previous_record_hash"))
    )


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _fresh(record: Mapping[str, Any], policy: Mapping[str, Any], now: datetime) -> bool:
    try:
        freshness = policy["freshness"]
        maximum_age = int(freshness["maximum_evidence_age_seconds"])
        clock_skew = int(freshness["maximum_clock_skew_seconds"])
        issued = _timestamp(record["attestation"]["issued_at"])
        attestation_expiry = _timestamp(record["attestation"]["expires_at"])
        effective = _timestamp(record["lineage"]["effective_at"])
        record_expiry = _timestamp(record["lineage"]["expires_at"])
        if None in (issued, attestation_expiry, effective, record_expiry):
            return False
        assert issued is not None and attestation_expiry is not None and effective is not None and record_expiry is not None
        age = (now - issued).total_seconds()
        return -clock_skew <= age <= maximum_age and effective <= now <= record_expiry and now <= attestation_expiry
    except (KeyError, TypeError, ValueError):
        return False


def _safe_verify(
    verifier: ArtifactAttestationVerifier,
    record: Mapping[str, Any],
    policy: Mapping[str, Any],
    evaluated_at: str,
) -> VerificationResult:
    try:
        result = verifier.verify(record, policy, evaluated_at=evaluated_at)
        return result if isinstance(result, VerificationResult) else VerificationResult(state=FAILED)
    except Exception:
        return VerificationResult(state=FAILED, reason_code="DEPENDENCY_ARTIFACT_ATTESTATION_FAILED")


def _verification_binding_valid(
    record: Mapping[str, Any], policy: Mapping[str, Any], result: VerificationResult
) -> bool:
    artifact = record["artifact"]
    source = record["source"]
    build = record["build"]
    attestation = record["attestation"]
    transparency = record["transparency"]
    return bool(
        result.subject_name == artifact["filename"] == attestation["subject_name"]
        and result.subject_sha256 == artifact["sha256"] == attestation["subject_sha256"]
        and result.predicate_type == attestation["predicate_type"]
        and result.predicate_type in policy["accepted_predicate_types"]
        and result.signer_identity == attestation["signer_identity"]
        and result.signer_identity in policy["accepted_signer_identities"]
        and result.issuer_identity == attestation["issuer_identity"]
        and result.issuer_identity in policy["accepted_issuers"]
        and result.source_repository == source["upstream_repository"]
        and result.source_repository in policy["accepted_source_repositories"]
        and result.source_commit_sha == source["source_commit_sha"]
        and result.workflow_identity == build["workflow_identity"]
        and result.workflow_run_id == build["workflow_run_id"]
        and result.workflow_job_id == build["workflow_job_id"]
        and result.transparency_log_id == transparency["log_id"]
        and result.transparency_log_id in policy["accepted_transparency_logs"]
        and result.checkpoint_identity == transparency["checkpoint_identity"]
        and result.checkpoint_identity in policy["accepted_checkpoint_authorities"]
    )


def _checkpoint_valid(
    record: Mapping[str, Any],
    policy: Mapping[str, Any],
    result: VerificationResult,
    now: datetime | None,
) -> bool:
    if now is None or result.transparency_state != PROVEN:
        return False
    try:
        checkpoint_time = _timestamp(result.checkpoint_time)
        recorded_time = _timestamp(record["transparency"]["checkpoint_time"])
        maximum_age = int(policy["freshness"]["maximum_checkpoint_age_seconds"])
        clock_skew = int(policy["freshness"]["maximum_clock_skew_seconds"])
        if checkpoint_time is None or recorded_time is None or checkpoint_time != recorded_time:
            return False
        age = (now - checkpoint_time).total_seconds()
        return -clock_skew <= age <= maximum_age
    except (KeyError, TypeError, ValueError):
        return False


def _witness_threshold_satisfied(witnesses: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> bool:
    try:
        dimensions = tuple(policy["witness_policy"]["independence_dimensions"])
        required = int(policy["witness_policy"]["minimum_independent_witnesses"])
        independent: set[tuple[str, ...]] = set()
        ids: set[str] = set()
        for witness in witnesses:
            if witness.get("state") != PROVEN or witness.get("independence_state") != PROVEN:
                continue
            if not is_sha256_reference(witness.get("evidence_sha256")):
                continue
            witness_id = str(witness.get("witness_id", ""))
            key = tuple(str(witness.get(dimension, "")) for dimension in dimensions)
            if not witness_id or not all(key) or witness_id in ids:
                continue
            ids.add(witness_id)
            independent.add(key)
        return len(independent) >= required
    except (KeyError, TypeError, ValueError):
        return False


def _conflicting_witnesses(witnesses: Sequence[Mapping[str, Any]]) -> bool:
    states_by_evidence: dict[str, set[str]] = {}
    for witness in witnesses:
        evidence = str(witness.get("evidence_sha256", ""))
        states_by_evidence.setdefault(evidence, set()).add(str(witness.get("state", UNKNOWN)))
    return any(PROVEN in states and (FAILED in states or UNKNOWN in states or PARTIAL in states) for states in states_by_evidence.values())


def _human_approvals_valid(approvals: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> bool:
    try:
        required = int(policy["human_approval"]["minimum_approvals"])
        roles = set(policy["human_approval"]["allowed_roles"])
        actors = set(policy["allowed_human_actors"])
        valid: set[str] = set()
        for approval in approvals:
            actor = str(approval.get("actor_id", ""))
            if (
                approval.get("decision") == "APPROVE"
                and approval.get("actor_type") == "human"
                and actor in actors
                and approval.get("actor_role") in roles
                and approval.get("policy_version") == policy.get("policy_version")
                and approval.get("device_id")
                and _timestamp(approval.get("timestamp")) is not None
                and is_sha256_reference(approval.get("approval_evidence_sha256"))
            ):
                valid.add(actor)
        return len(valid) >= required
    except (KeyError, TypeError, ValueError):
        return False


def _contains_model_authority(record: Mapping[str, Any]) -> bool:
    forbidden = {"ai", "model", "provider", "llm", "agent"}
    for approval in record.get("approvals", []):
        actor_type = str(approval.get("actor_type", "")).lower()
        if actor_type in forbidden or any(token in actor_type for token in ("model", "provider")):
            return True
    return False
