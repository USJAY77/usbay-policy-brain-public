"""Governed local Suricata rule source fetcher.

This module reads local rule bundle files only. It never fetches network
resources, calls connectors, or returns raw rule contents.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_rule_signature import SuricataRuleSignatureResult
from publication.suricata_rule_source_registry import SuricataRuleSourceRegistryResult


POLICY_VERSION = "USBAY-SURICATA-007"
NETWORK_PATH_MARKERS = ("://", "http:", "https:", "ftp:", "s3:", "gs:", "\\\\")


@dataclass(frozen=True)
class LocalRuleSourceFetchRequest:
    source_id: str
    local_path: str
    registry_evidence_hash: str
    signature_evidence_hash: str
    policy_version: str
    requested_at: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LocalRuleSourceFetchRequest":
        return cls(
            source_id=str(payload.get("source_id") or ""),
            local_path=str(payload.get("local_path") or ""),
            registry_evidence_hash=str(payload.get("registry_evidence_hash") or ""),
            signature_evidence_hash=str(payload.get("signature_evidence_hash") or ""),
            policy_version=str(payload.get("policy_version") or ""),
            requested_at=str(payload.get("requested_at") or ""),
        )

    def to_redacted_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "local_path_hash": hash_payload({"local_path": self.local_path}),
            "registry_evidence_hash": self.registry_evidence_hash,
            "signature_evidence_hash": self.signature_evidence_hash,
            "policy_version": self.policy_version,
            "requested_at": self.requested_at,
        }


@dataclass(frozen=True)
class LocalRuleSourceFetchResult:
    approved: bool
    blocked: bool
    reason: str
    source_id: str
    rule_bundle_hash: str
    rule_bundle_size: int
    registry_evidence_hash: str
    signature_evidence_hash: str
    policy_version: str
    evidence_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "blocked": self.blocked,
            "reason": self.reason,
            "source_id": self.source_id,
            "rule_bundle_hash": self.rule_bundle_hash,
            "rule_bundle_size": self.rule_bundle_size,
            "registry_evidence_hash": self.registry_evidence_hash,
            "signature_evidence_hash": self.signature_evidence_hash,
            "policy_version": self.policy_version,
            "evidence_hash": self.evidence_hash,
        }


def evaluate_local_rule_source_fetch(
    request: LocalRuleSourceFetchRequest | dict[str, Any] | None,
    *,
    source_registry_result: SuricataRuleSourceRegistryResult | None,
    signature_result: SuricataRuleSignatureResult | None,
) -> LocalRuleSourceFetchResult:
    if request is None:
        return _blocked("SURICATA_RULE_FETCH_REQUEST_MISSING", "", "", "", "", 0)
    resolved = request if isinstance(request, LocalRuleSourceFetchRequest) else LocalRuleSourceFetchRequest.from_dict(request)

    malformed_reason = _request_malformed_reason(resolved)
    if malformed_reason:
        return _blocked(
            malformed_reason,
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )

    if source_registry_result is None or not source_registry_result.approved:
        return _blocked(
            "SURICATA_RULE_FETCH_REGISTRY_NOT_APPROVED",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )
    if signature_result is None or not signature_result.approved:
        return _blocked(
            "SURICATA_RULE_FETCH_SIGNATURE_NOT_APPROVED",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )
    if resolved.registry_evidence_hash != source_registry_result.evidence_hash:
        return _blocked(
            "SURICATA_RULE_FETCH_REGISTRY_EVIDENCE_MISMATCH",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )
    if resolved.signature_evidence_hash != signature_result.evidence_hash:
        return _blocked(
            "SURICATA_RULE_FETCH_SIGNATURE_EVIDENCE_MISMATCH",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )
    if resolved.source_id != source_registry_result.approved_source_id or resolved.source_id != signature_result.approved_source_id:
        return _blocked(
            "SURICATA_RULE_FETCH_SOURCE_MISMATCH",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )
    if resolved.policy_version != source_registry_result.approved_policy_version or resolved.policy_version != signature_result.policy_version:
        return _blocked(
            "SURICATA_RULE_FETCH_POLICY_MISMATCH",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )

    path_result = _resolve_local_path(resolved.local_path)
    if isinstance(path_result, str):
        return _blocked(
            path_result,
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )

    file_bytes = path_result.read_bytes()
    if not file_bytes:
        return _blocked(
            "SURICATA_RULE_FETCH_EMPTY_FILE",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            0,
        )

    rule_bundle_hash = "sha256:" + hashlib.sha256(file_bytes).hexdigest()
    if rule_bundle_hash != signature_result.rule_bundle_hash:
        return _blocked(
            "SURICATA_RULE_FETCH_BUNDLE_HASH_MISMATCH",
            resolved.source_id,
            resolved.policy_version,
            resolved.registry_evidence_hash,
            resolved.signature_evidence_hash,
            len(file_bytes),
            rule_bundle_hash=rule_bundle_hash,
        )

    payload = _evidence_payload(
        approved=True,
        blocked=False,
        reason="SURICATA_RULE_FETCH_APPROVED",
        source_id=resolved.source_id,
        rule_bundle_hash=rule_bundle_hash,
        rule_bundle_size=len(file_bytes),
        registry_evidence_hash=resolved.registry_evidence_hash,
        signature_evidence_hash=resolved.signature_evidence_hash,
        policy_version=resolved.policy_version,
        request=resolved,
    )
    return LocalRuleSourceFetchResult(
        approved=True,
        blocked=False,
        reason="SURICATA_RULE_FETCH_APPROVED",
        source_id=resolved.source_id,
        rule_bundle_hash=rule_bundle_hash,
        rule_bundle_size=len(file_bytes),
        registry_evidence_hash=resolved.registry_evidence_hash,
        signature_evidence_hash=resolved.signature_evidence_hash,
        policy_version=resolved.policy_version,
        evidence_hash=hash_payload(payload),
    )


def _request_malformed_reason(request: LocalRuleSourceFetchRequest) -> str:
    if not request.source_id or not request.local_path or not request.policy_version or not request.requested_at:
        return "SURICATA_RULE_FETCH_REQUEST_MALFORMED"
    if not is_sha256_ref(request.registry_evidence_hash):
        return "SURICATA_RULE_FETCH_REGISTRY_EVIDENCE_INVALID"
    if not is_sha256_ref(request.signature_evidence_hash):
        return "SURICATA_RULE_FETCH_SIGNATURE_EVIDENCE_INVALID"
    return ""


def _resolve_local_path(raw_path: str) -> Path | str:
    lowered = raw_path.strip().lower()
    if not lowered:
        return "SURICATA_RULE_FETCH_PATH_MISSING"
    if any(marker in lowered for marker in NETWORK_PATH_MARKERS) or lowered.startswith("//"):
        return "SURICATA_RULE_FETCH_NETWORK_PATH_FORBIDDEN"

    candidate = Path(raw_path)
    if ".." in candidate.parts:
        return "SURICATA_RULE_FETCH_PATH_TRAVERSAL"
    if candidate.is_dir():
        return "SURICATA_RULE_FETCH_NOT_A_FILE"
    if not candidate.exists():
        return "SURICATA_RULE_FETCH_FILE_MISSING"
    if not candidate.is_file():
        return "SURICATA_RULE_FETCH_NOT_A_FILE"
    return candidate


def _blocked(
    reason: str,
    source_id: str,
    policy_version: str,
    registry_evidence_hash: str,
    signature_evidence_hash: str,
    rule_bundle_size: int,
    *,
    rule_bundle_hash: str = "",
) -> LocalRuleSourceFetchResult:
    payload = {
        "approved": False,
        "blocked": True,
        "reason": reason,
        "source_id": source_id,
        "rule_bundle_hash": rule_bundle_hash,
        "rule_bundle_size": rule_bundle_size,
        "registry_evidence_hash": registry_evidence_hash,
        "signature_evidence_hash": signature_evidence_hash,
        "policy_version": policy_version,
    }
    return LocalRuleSourceFetchResult(
        approved=False,
        blocked=True,
        reason=reason,
        source_id=source_id,
        rule_bundle_hash=rule_bundle_hash,
        rule_bundle_size=rule_bundle_size,
        registry_evidence_hash=registry_evidence_hash,
        signature_evidence_hash=signature_evidence_hash,
        policy_version=policy_version,
        evidence_hash=hash_payload(payload),
    )


def _evidence_payload(
    *,
    approved: bool,
    blocked: bool,
    reason: str,
    source_id: str,
    rule_bundle_hash: str,
    rule_bundle_size: int,
    registry_evidence_hash: str,
    signature_evidence_hash: str,
    policy_version: str,
    request: LocalRuleSourceFetchRequest,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "blocked": blocked,
        "reason": reason,
        "source_id": source_id,
        "rule_bundle_hash": rule_bundle_hash,
        "rule_bundle_size": rule_bundle_size,
        "registry_evidence_hash": registry_evidence_hash,
        "signature_evidence_hash": signature_evidence_hash,
        "policy_version": policy_version,
        "request": request.to_redacted_dict(),
    }
