from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from governance.hashing import canonical_json, is_sha256_reference, sha256_reference


ALLOW = "ALLOW"
BLOCK = "BLOCK"
SCHEMA_VERSION = "usbay.pbsec001.target_authorization.v1"
BLOCKED_TARGET_AUTHORIZATION_UNKNOWN = "BLOCKED_TARGET_AUTHORIZATION_UNKNOWN"
APPROVED_SCAN_PROFILES = frozenset({"PBSEC001_ZAP_BASELINE_NON_PROD_V1"})
REJECTED_AUTONOMOUS_ACTORS = frozenset({"AI", "AI_AGENT", "AUTOMATION", "CODEX", "SYSTEM"})
SENSITIVE_MARKERS = ("password", "secret", "token", "credential", "private_key", "authorization:")
WILDCARD_MARKERS = ("*", "0.0.0.0/0", "::/0", "any", "all", "wildcard")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _contains_sensitive_marker(value: Any) -> bool:
    text = canonical_json(value, default_to_str=True).lower()
    return any(marker in text for marker in SENSITIVE_MARKERS)


def _contains_wildcard_marker(value: Any) -> bool:
    text = canonical_json(value, default_to_str=True).lower()
    return any(marker in text for marker in WILDCARD_MARKERS)


@dataclass(frozen=True)
class PBSEC001TargetRecord:
    target_id: str
    target_identity_hash: str
    environment: str
    allowed_scan_profile: str
    policy_id: str
    policy_version_hash: str
    workspace_or_repository_binding: Mapping[str, Any]
    release_revision_binding_requirement: bool
    authorized_by: tuple[str, ...]
    authorization_evidence: Mapping[str, Any]
    authorized_at: str
    expires_at: str
    enabled: bool
    schema_version: str = SCHEMA_VERSION

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_id": self.target_id,
            "target_identity_hash": self.target_identity_hash,
            "environment": self.environment,
            "allowed_scan_profile": self.allowed_scan_profile,
            "policy_id": self.policy_id,
            "policy_version_hash": self.policy_version_hash,
            "workspace_or_repository_binding": dict(self.workspace_or_repository_binding),
            "release_revision_binding_requirement": self.release_revision_binding_requirement,
            "authorized_by": list(self.authorized_by),
            "authorization_evidence": dict(self.authorization_evidence),
            "authorized_at": self.authorized_at,
            "expires_at": self.expires_at,
            "enabled": self.enabled,
        }


@dataclass(frozen=True)
class PBSEC001TargetAuthorizationRequest:
    target_id: str
    target_identity_hash: str
    allowed_scan_profile: str
    policy_id: str
    policy_version_hash: str
    workspace_or_repository_binding: Mapping[str, Any]


@dataclass(frozen=True)
class PBSEC001TargetAuthorizationDecision:
    decision: str
    reason_code: str
    evidence: dict[str, Any]
    target_record: PBSEC001TargetRecord | None = None


def target_record_binding_hash(record: PBSEC001TargetRecord | Mapping[str, Any]) -> str:
    payload = record.to_record() if isinstance(record, PBSEC001TargetRecord) else dict(record)
    evidence = payload.get("authorization_evidence")
    if isinstance(evidence, Mapping):
        evidence = {key: value for key, value in evidence.items() if key != "record_binding_hash"}
    payload["authorization_evidence"] = evidence
    return sha256_reference(payload)


class PBSEC001TargetAuthorizationRegistry:
    def __init__(
        self,
        records: list[PBSEC001TargetRecord | Mapping[str, Any]] | tuple[PBSEC001TargetRecord | Mapping[str, Any], ...],
        *,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._records = tuple(_coerce_record(record) for record in records)
        self._clock = clock

    def authorize(self, request: PBSEC001TargetAuthorizationRequest | Mapping[str, Any] | None) -> PBSEC001TargetAuthorizationDecision:
        timestamp = self._clock()
        req = _coerce_request(request)
        reason = BLOCKED_TARGET_AUTHORIZATION_UNKNOWN if req is None else None
        matches: list[PBSEC001TargetRecord] = []
        if reason is None and req is not None:
            matches = [record for record in self._records if record.target_id == req.target_id]
            if not matches:
                reason = BLOCKED_TARGET_AUTHORIZATION_UNKNOWN
            elif len(matches) > 1:
                reason = "PBSEC001_TARGET_AUTHORIZATION_DUPLICATE"
        if reason is None and req is not None:
            identity_matches = [record for record in self._records if record.target_identity_hash == req.target_identity_hash]
            if len(identity_matches) > 1:
                reason = "PBSEC001_TARGET_AUTHORIZATION_AMBIGUOUS"
        record = matches[0] if len(matches) == 1 else None
        if reason is None and record is not None and req is not None:
            reason = _validate_record(record, req, timestamp)
        decision = ALLOW if reason is None else BLOCK
        return PBSEC001TargetAuthorizationDecision(
            decision=decision,
            reason_code="PBSEC001_TARGET_AUTHORIZED" if reason is None else reason,
            target_record=record if reason is None else None,
            evidence=_decision_evidence(
                decision=decision,
                reason_code="PBSEC001_TARGET_AUTHORIZED" if reason is None else reason,
                timestamp=timestamp,
                request=req,
                record=record,
            ),
        )

    def register_target_autonomously(self, actor_type: str, record: PBSEC001TargetRecord | Mapping[str, Any]) -> PBSEC001TargetAuthorizationDecision:
        timestamp = self._clock()
        reason = "PBSEC001_AUTONOMOUS_TARGET_REGISTRATION_BLOCKED"
        if str(actor_type).upper() not in REJECTED_AUTONOMOUS_ACTORS:
            reason = "PBSEC001_RUNTIME_TARGET_REGISTRATION_BLOCKED"
        return PBSEC001TargetAuthorizationDecision(
            decision=BLOCK,
            reason_code=reason,
            target_record=None,
            evidence=_decision_evidence(
                decision=BLOCK,
                reason_code=reason,
                timestamp=timestamp,
                request=None,
                record=_coerce_record(record),
            ),
        )

    def mutate_target_autonomously(self, actor_type: str, target_id: str, updates: Mapping[str, Any]) -> PBSEC001TargetAuthorizationDecision:
        timestamp = self._clock()
        reason = "PBSEC001_AUTONOMOUS_TARGET_MUTATION_BLOCKED"
        if str(actor_type).upper() not in REJECTED_AUTONOMOUS_ACTORS:
            reason = "PBSEC001_RUNTIME_TARGET_MUTATION_BLOCKED"
        return PBSEC001TargetAuthorizationDecision(
            decision=BLOCK,
            reason_code=reason,
            target_record=None,
            evidence=_decision_evidence(
                decision=BLOCK,
                reason_code=reason,
                timestamp=timestamp,
                request={"target_id": target_id, "update_hash": sha256_reference(dict(updates))},
                record=None,
            ),
        )

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "target_count": len(self._records),
            "scan_execution_authority": False,
            "network_authority": False,
            "deployment_authority": False,
            "production_authority": False,
            "autonomous_target_registration": False,
            "autonomous_policy_creation": False,
            "policy_mutation": False,
        }


def authorize_pbsec001_target(
    registry: PBSEC001TargetAuthorizationRegistry | None,
    request: PBSEC001TargetAuthorizationRequest | Mapping[str, Any] | None,
) -> PBSEC001TargetAuthorizationDecision:
    if not isinstance(registry, PBSEC001TargetAuthorizationRegistry):
        timestamp = utc_now()
        return PBSEC001TargetAuthorizationDecision(
            decision=BLOCK,
            reason_code=BLOCKED_TARGET_AUTHORIZATION_UNKNOWN,
            target_record=None,
            evidence=_decision_evidence(
                decision=BLOCK,
                reason_code=BLOCKED_TARGET_AUTHORIZATION_UNKNOWN,
                timestamp=timestamp,
                request=_coerce_request(request),
                record=None,
            ),
        )
    try:
        return registry.authorize(request)
    except Exception:
        timestamp = utc_now()
        return PBSEC001TargetAuthorizationDecision(
            decision=BLOCK,
            reason_code="PBSEC001_TARGET_AUTHORIZATION_REGISTRY_FAILURE",
            target_record=None,
            evidence=_decision_evidence(
                decision=BLOCK,
                reason_code="PBSEC001_TARGET_AUTHORIZATION_REGISTRY_FAILURE",
                timestamp=timestamp,
                request=_coerce_request(request),
                record=None,
            ),
        )


def _coerce_record(record: PBSEC001TargetRecord | Mapping[str, Any] | None) -> PBSEC001TargetRecord | None:
    if isinstance(record, PBSEC001TargetRecord):
        return record
    if not isinstance(record, Mapping):
        return None
    try:
        authorized_by = record.get("authorized_by", ())
        if not isinstance(authorized_by, (list, tuple)):
            authorized_by = ()
        return PBSEC001TargetRecord(
            target_id=str(record.get("target_id", "")),
            target_identity_hash=str(record.get("target_identity_hash", "")),
            environment=str(record.get("environment", "")),
            allowed_scan_profile=str(record.get("allowed_scan_profile", "")),
            policy_id=str(record.get("policy_id", "")),
            policy_version_hash=str(record.get("policy_version_hash", "")),
            workspace_or_repository_binding=dict(record.get("workspace_or_repository_binding", {})),
            release_revision_binding_requirement=bool(record.get("release_revision_binding_requirement", False)),
            authorized_by=tuple(str(actor) for actor in authorized_by),
            authorization_evidence=dict(record.get("authorization_evidence", {})),
            authorized_at=str(record.get("authorized_at", "")),
            expires_at=str(record.get("expires_at", "")),
            enabled=bool(record.get("enabled", False)),
            schema_version=str(record.get("schema_version", "")),
        )
    except Exception:
        return None


def _coerce_request(request: PBSEC001TargetAuthorizationRequest | Mapping[str, Any] | None) -> PBSEC001TargetAuthorizationRequest | None:
    if isinstance(request, PBSEC001TargetAuthorizationRequest):
        return request
    if not isinstance(request, Mapping):
        return None
    try:
        return PBSEC001TargetAuthorizationRequest(
            target_id=str(request.get("target_id", "")),
            target_identity_hash=str(request.get("target_identity_hash", "")),
            allowed_scan_profile=str(request.get("allowed_scan_profile", "")),
            policy_id=str(request.get("policy_id", "")),
            policy_version_hash=str(request.get("policy_version_hash", "")),
            workspace_or_repository_binding=dict(request.get("workspace_or_repository_binding", {})),
        )
    except Exception:
        return None


def _validate_record(record: PBSEC001TargetRecord, request: PBSEC001TargetAuthorizationRequest, timestamp: str) -> str | None:
    payload = record.to_record()
    if _contains_sensitive_marker(payload):
        return "PBSEC001_TARGET_AUTHORIZATION_SENSITIVE_DATA"
    if record.schema_version != SCHEMA_VERSION:
        return "PBSEC001_TARGET_AUTHORIZATION_SCHEMA_INVALID"
    required_strings = (
        record.target_id,
        record.target_identity_hash,
        record.environment,
        record.allowed_scan_profile,
        record.authorized_at,
        record.expires_at,
    )
    if any(not isinstance(value, str) or not value.strip() for value in required_strings):
        return "PBSEC001_TARGET_AUTHORIZATION_MALFORMED"
    if not isinstance(record.policy_id, str) or not record.policy_id.strip() or not isinstance(record.policy_version_hash, str) or not record.policy_version_hash.strip():
        return "PBSEC001_POLICY_BINDING_MISSING"
    if not is_sha256_reference(record.target_identity_hash):
        return "PBSEC001_TARGET_IDENTITY_HASH_INVALID"
    if not is_sha256_reference(record.policy_version_hash):
        return "PBSEC001_POLICY_VERSION_HASH_INVALID"
    if _contains_wildcard_marker(
        {
            "target_id": record.target_id,
            "target_identity_hash": record.target_identity_hash,
            "workspace_or_repository_binding": record.workspace_or_repository_binding,
        }
    ):
        return "PBSEC001_WILDCARD_TARGET_BLOCKED"
    if record.enabled is not True:
        return "PBSEC001_TARGET_DISABLED"
    if record.environment != "NON_PRODUCTION":
        return "PBSEC001_PRODUCTION_TARGET_BLOCKED"
    if record.allowed_scan_profile not in APPROVED_SCAN_PROFILES:
        return "PBSEC001_SCAN_PROFILE_UNAUTHORIZED"
    if record.release_revision_binding_requirement is not True:
        return "PBSEC001_RELEASE_REVISION_BINDING_REQUIRED"
    if _workspace_binding_hash(record.workspace_or_repository_binding) is None:
        return "PBSEC001_WORKSPACE_BINDING_INVALID"
    if record.target_identity_hash != request.target_identity_hash:
        return "PBSEC001_TARGET_IDENTITY_MISMATCH"
    if record.allowed_scan_profile != request.allowed_scan_profile:
        return "PBSEC001_SCAN_PROFILE_MISMATCH"
    if record.policy_id != request.policy_id:
        return "PBSEC001_POLICY_ID_MISMATCH"
    if record.policy_version_hash != request.policy_version_hash:
        return "PBSEC001_POLICY_VERSION_MISMATCH"
    if _workspace_binding_hash(record.workspace_or_repository_binding) != _workspace_binding_hash(request.workspace_or_repository_binding):
        return "PBSEC001_WORKSPACE_BINDING_MISMATCH"
    authorized_at = parse_utc(record.authorized_at)
    expires_at = parse_utc(record.expires_at)
    now = parse_utc(timestamp)
    if authorized_at is None or expires_at is None or now is None:
        return "PBSEC001_TARGET_AUTHORIZATION_TIMESTAMP_INVALID"
    if authorized_at > now:
        return "PBSEC001_TARGET_AUTHORIZATION_NOT_YET_VALID"
    if now >= expires_at:
        return "PBSEC001_TARGET_AUTHORIZATION_EXPIRED"
    evidence = record.authorization_evidence
    if not evidence:
        return "PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_MISSING"
    if evidence.get("human_authorized") is not True:
        return "PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_MISSING"
    if evidence.get("autonomous_authorized") is not False:
        return "PBSEC001_AUTONOMOUS_AUTHORIZATION_REJECTED"
    evidence_hash = evidence.get("evidence_hash")
    if not is_sha256_reference(evidence_hash):
        return "PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_INVALID"
    if len(set(record.authorized_by)) != len(record.authorized_by) or not record.authorized_by:
        return "PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_INVALID"
    if any(not isinstance(actor, str) or not actor.strip() for actor in record.authorized_by):
        return "PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_INVALID"
    if any(actor.upper() in REJECTED_AUTONOMOUS_ACTORS for actor in record.authorized_by):
        return "PBSEC001_AUTONOMOUS_AUTHORIZATION_REJECTED"
    if tuple(evidence.get("authorized_by", ())) != record.authorized_by:
        return "PBSEC001_HUMAN_AUTHORIZATION_EVIDENCE_INVALID"
    if evidence.get("record_binding_hash") != target_record_binding_hash(record):
        return "PBSEC001_TARGET_AUTHORIZATION_BINDING_MISMATCH"
    return None


def _workspace_binding_hash(binding: Mapping[str, Any]) -> str | None:
    if not isinstance(binding, Mapping) or not binding:
        return None
    allowed_keys = {
        "workspace_id",
        "repository_id",
        "remote_identity_hash",
        "local_identity_hash",
        "policy_id",
        "policy_version_hash",
    }
    if not set(binding).issubset(allowed_keys):
        return None
    if not (binding.get("workspace_id") or binding.get("repository_id")):
        return None
    for hash_field in ("remote_identity_hash", "local_identity_hash", "policy_version_hash"):
        value = binding.get(hash_field)
        if value is not None and not is_sha256_reference(value):
            return None
    return sha256_reference(dict(binding))


def _decision_evidence(
    *,
    decision: str,
    reason_code: str,
    timestamp: str,
    request: PBSEC001TargetAuthorizationRequest | Mapping[str, Any] | None,
    record: PBSEC001TargetRecord | None,
) -> dict[str, Any]:
    request_record = request.__dict__ if isinstance(request, PBSEC001TargetAuthorizationRequest) else request
    evidence = {
        "schema_version": "usbay.pbsec001.target_authorization_decision.v1",
        "decision": decision,
        "reason_code": reason_code,
        "timestamp": timestamp,
        "request_hash": sha256_reference(request_record or {}),
        "target_id": (request_record or {}).get("target_id", "") if isinstance(request_record, Mapping) else "",
        "target_record_hash": target_record_binding_hash(record) if record is not None else "",
        "network_performed": False,
        "scan_executed": False,
        "deployment_authority": False,
        "production_authority": False,
        "autonomous_target_registration": False,
        "autonomous_policy_creation": False,
        "policy_mutation": False,
    }
    evidence["event_hash"] = sha256_reference(evidence)
    return evidence
