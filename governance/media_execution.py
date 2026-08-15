"""USBAY governed media execution foundation.

Bounded MediaExecutionContract + fail-closed validation gate + single-use
consumption store + hash-chained provenance evidence + human publication gate.

USBAY is the execution control layer; external media providers (e.g.
Higgsfield) are execution mechanisms only and hold no policy, approval, or
publication authority. Every unknown/malformed/failed state BLOCKS.

Evidence is written through the existing append-only, hash-chained USBAY
audit ledger format (audit/ledger.py: append_entry / verify_chain) — no
parallel uncontrolled audit store. Evidence stores hashes/references only;
raw prompts, media bytes, and secrets are never written.
"""

from __future__ import annotations

import re
import sqlite3
import subprocess  # noqa: F401  (not used; kept out intentionally — no CLI here)
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from audit.ledger import append_entry, canonical_json_bytes, sha256_bytes

# Deny-by-default provider allowlist for governed media execution.
ALLOWED_MEDIA_PROVIDERS = ("higgsfield",)

# Hard governance ceilings (contract construction fails above these).
MAX_DURATION_SECONDS_CEILING = 300
MAX_OUTPUTS_CEILING = 10
MAX_TIMEOUT_SECONDS_CEILING = 600

DEFAULT_MEDIA_EVIDENCE_LOG = Path("audit/media_execution_evidence.jsonl")

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class MediaGovernanceError(ValueError):
    """Raised when a media governance object cannot be constructed safely."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_nonempty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MediaGovernanceError(f"MEDIA_CONTRACT_INVALID:{field}_REQUIRED")
    return value.strip()


def _require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value.lower()):
        raise MediaGovernanceError(f"MEDIA_CONTRACT_INVALID:{field}_MUST_BE_SHA256_HEX")
    return value.lower()


def _require_positive_int(value: Any, field: str, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > ceiling:
        raise MediaGovernanceError(f"MEDIA_CONTRACT_INVALID:{field}_OUT_OF_BOUNDS")
    return value


@dataclass(frozen=True)
class MediaExecutionContract:
    """Bounded, hash-referenced media execution contract.

    Holds no raw prompts, no media bytes, no credentials — hashes and
    references only. publication_allowed is False by construction and cannot
    be enabled through this contract; publication requires a separate
    PublicationAuthorization (human gate).
    """

    execution_id: str
    actor_id: str
    tenant_reference: str
    provider: str
    action: str
    model_identifier: Optional[str]
    prompt_hash: str
    input_asset_hashes: tuple
    requested_duration_seconds: int
    output_type: str
    max_outputs: int
    budget_ceiling: Optional[float]
    timeout_seconds: int
    authorization_id: str
    policy_decision_id: str
    evidence_id: str
    publication_allowed: bool = False


def build_media_execution_contract(
    *,
    execution_id: str,
    actor_id: str,
    tenant_reference: str,
    provider: str,
    action: str,
    model_identifier: Optional[str] = None,
    prompt_hash: str,
    input_asset_hashes: Sequence[str] = (),
    requested_duration_seconds: int,
    output_type: str,
    max_outputs: int,
    budget_ceiling: Optional[float] = None,
    timeout_seconds: int,
    authorization_id: str,
    policy_decision_id: str,
    evidence_id: str,
) -> MediaExecutionContract:
    provider_clean = _require_nonempty_str(provider, "provider").lower()
    if provider_clean not in ALLOWED_MEDIA_PROVIDERS:
        raise MediaGovernanceError("MEDIA_CONTRACT_INVALID:PROVIDER_NOT_ALLOWED")
    hashes = tuple(_require_sha256(h, "input_asset_hash") for h in input_asset_hashes)
    if budget_ceiling is not None:
        if isinstance(budget_ceiling, bool) or not isinstance(budget_ceiling, (int, float)) or budget_ceiling <= 0:
            raise MediaGovernanceError("MEDIA_CONTRACT_INVALID:budget_ceiling_OUT_OF_BOUNDS")
    return MediaExecutionContract(
        execution_id=_require_nonempty_str(execution_id, "execution_id"),
        actor_id=_require_nonempty_str(actor_id, "actor_id"),
        tenant_reference=_require_nonempty_str(tenant_reference, "tenant_reference"),
        provider=provider_clean,
        action=_require_nonempty_str(action, "action"),
        model_identifier=(_require_nonempty_str(model_identifier, "model_identifier")
                          if model_identifier is not None else None),
        prompt_hash=_require_sha256(prompt_hash, "prompt_hash"),
        input_asset_hashes=hashes,
        requested_duration_seconds=_require_positive_int(
            requested_duration_seconds, "requested_duration_seconds", MAX_DURATION_SECONDS_CEILING
        ),
        output_type=_require_nonempty_str(output_type, "output_type"),
        max_outputs=_require_positive_int(max_outputs, "max_outputs", MAX_OUTPUTS_CEILING),
        budget_ceiling=float(budget_ceiling) if budget_ceiling is not None else None,
        timeout_seconds=_require_positive_int(timeout_seconds, "timeout_seconds", MAX_TIMEOUT_SECONDS_CEILING),
        authorization_id=_require_nonempty_str(authorization_id, "authorization_id"),
        policy_decision_id=_require_nonempty_str(policy_decision_id, "policy_decision_id"),
        evidence_id=_require_nonempty_str(evidence_id, "evidence_id"),
        publication_allowed=False,
    )


@dataclass(frozen=True)
class MediaAuthorization:
    """What a human/policy decision actually authorized (caller-supplied)."""

    authorization_id: str
    provider: str
    action: str
    model_identifier: Optional[str]
    prompt_hash: str
    max_outputs: int
    max_duration_seconds: int
    budget_ceiling: Optional[float]
    policy_decision_id: str
    publication_authorized: bool = False


def build_media_authorization(
    *,
    authorization_id: str,
    provider: str,
    action: str,
    model_identifier: Optional[str] = None,
    prompt_hash: str,
    max_outputs: int,
    max_duration_seconds: int,
    budget_ceiling: Optional[float] = None,
    policy_decision_id: str,
    publication_authorized: bool = False,
) -> MediaAuthorization:
    return MediaAuthorization(
        authorization_id=_require_nonempty_str(authorization_id, "authorization_id"),
        provider=_require_nonempty_str(provider, "provider").lower(),
        action=_require_nonempty_str(action, "action"),
        model_identifier=(_require_nonempty_str(model_identifier, "model_identifier")
                          if model_identifier is not None else None),
        prompt_hash=_require_sha256(prompt_hash, "prompt_hash"),
        max_outputs=_require_positive_int(max_outputs, "max_outputs", MAX_OUTPUTS_CEILING),
        max_duration_seconds=_require_positive_int(
            max_duration_seconds, "max_duration_seconds", MAX_DURATION_SECONDS_CEILING
        ),
        budget_ceiling=float(budget_ceiling) if budget_ceiling is not None else None,
        policy_decision_id=_require_nonempty_str(policy_decision_id, "policy_decision_id"),
        publication_authorized=bool(publication_authorized),
    )


class MediaExecutionConsumptionStore:
    """Persistent single-use execution reservation (SQLite, WAL).

    reserve() returns True exactly once per execution_id; duplicates return
    False. Any store error must be treated as BLOCK by callers.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS media_execution_consumption ("
                "execution_id TEXT PRIMARY KEY, reserved_at TEXT NOT NULL)"
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def reserve(self, execution_id: str) -> bool:
        with self._conn() as conn:
            try:
                conn.execute(
                    "INSERT INTO media_execution_consumption (execution_id, reserved_at) VALUES (?, ?)",
                    (execution_id, _utc_now_iso()),
                )
                return True
            except sqlite3.IntegrityError:
                return False


def _block(reason_code: str, **extra: Any) -> dict:
    decision = {"decision": "BLOCK", "reason_code": reason_code, "timestamp": _utc_now_iso()}
    decision.update(extra)
    return decision


def validate_media_execution(
    contract: Optional[MediaExecutionContract],
    authorization: Optional[MediaAuthorization],
    *,
    consumption_store: Optional[MediaExecutionConsumptionStore] = None,
    reserve: bool = False,
) -> dict:
    """Fail-closed pre-execution validation. Returns explicit decision dict.

    Never raises for governance failures; any internal error also BLOCKS.
    When reserve=True the single-use reservation is taken atomically here.
    """
    try:
        if contract is None or not isinstance(contract, MediaExecutionContract):
            return _block("CONTRACT_MISSING")
        if authorization is None or not isinstance(authorization, MediaAuthorization):
            return _block("AUTHORIZATION_MISSING")
        if contract.authorization_id != authorization.authorization_id:
            return _block("AUTHORIZATION_MISMATCH")
        if contract.policy_decision_id != authorization.policy_decision_id:
            return _block("POLICY_DECISION_MISMATCH")
        if contract.provider not in ALLOWED_MEDIA_PROVIDERS:
            return _block("PROVIDER_NOT_ALLOWED")
        if contract.provider != authorization.provider:
            return _block("PROVIDER_MISMATCH")
        if contract.action != authorization.action:
            return _block("ACTION_NOT_AUTHORIZED")
        if contract.prompt_hash != authorization.prompt_hash:
            return _block("PROMPT_HASH_MISMATCH")
        if authorization.model_identifier is not None and (
            contract.model_identifier != authorization.model_identifier
        ):
            return _block("MODEL_MISMATCH")
        if contract.max_outputs > authorization.max_outputs:
            return _block("OUTPUT_LIMIT_EXCEEDED")
        if contract.requested_duration_seconds > authorization.max_duration_seconds:
            return _block("DURATION_LIMIT_EXCEEDED")
        if authorization.budget_ceiling is not None:
            if contract.budget_ceiling is None or contract.budget_ceiling > authorization.budget_ceiling:
                return _block("BUDGET_LIMIT_EXCEEDED")
        if contract.timeout_seconds <= 0 or contract.timeout_seconds > MAX_TIMEOUT_SECONDS_CEILING:
            return _block("TIMEOUT_INVALID")
        if contract.publication_allowed:
            return _block("PUBLICATION_FLAG_TAMPERED")
        if reserve:
            if consumption_store is None:
                return _block("CONSUMPTION_STORE_MISSING")
            try:
                reserved = consumption_store.reserve(contract.execution_id)
            except Exception:
                return _block("CONSUMPTION_STORE_FAILURE")
            if reserved is not True:
                return _block("EXECUTION_ALREADY_CONSUMED")
        return {"decision": "ALLOW_VALIDATION", "timestamp": _utc_now_iso()}
    except Exception:
        return _block("MEDIA_GOVERNANCE_INTERNAL_ERROR")


def record_media_execution_evidence(
    *,
    contract: MediaExecutionContract,
    output_asset_hash: str,
    output_metadata: dict,
    provider_request_reference: Optional[str],
    execution_result: str,
    evidence_log: Path | str = DEFAULT_MEDIA_EVIDENCE_LOG,
    commit_sha: str = "UNKNOWN",
) -> dict:
    """Append hash-chained provenance evidence via the existing USBAY ledger.

    Stores references/hashes only. Raises on any write failure (caller must
    BLOCK). Chain integrity of the log is verifiable with audit.ledger.verify_chain.
    """
    asset_hash = _require_sha256(output_asset_hash, "output_asset_hash")
    metadata = {str(k): str(v) for k, v in (output_metadata or {}).items()}
    payload = {
        "execution_id": contract.execution_id,
        "authorization_id": contract.authorization_id,
        "policy_decision_id": contract.policy_decision_id,
        "evidence_id": contract.evidence_id,
        "provider": contract.provider,
        "action": contract.action,
        "model_identifier": contract.model_identifier or "UNSPECIFIED",
        "prompt_hash": contract.prompt_hash,
        "input_asset_hashes": list(contract.input_asset_hashes),
        "provider_request_reference": provider_request_reference or "NONE",
        "output_asset_hash": asset_hash,
        "output_metadata": metadata,
        "execution_result": execution_result,
        "publication_status": "NOT_AUTHORIZED",
        "tenant_reference": contract.tenant_reference,
        "actor_id": contract.actor_id,
    }
    snapshot_hash = sha256_bytes(canonical_json_bytes(payload))
    entry = dict(payload)
    entry.update(
        {
            "entry_type": "MEDIA_EXECUTION_EVIDENCE",
            "timestamp": _utc_now_iso(),
            "commit_sha": commit_sha,
            "policy_hash": sha256_bytes(contract.policy_decision_id.encode("utf-8")),
            "approval_1_hash": sha256_bytes(contract.authorization_id.encode("utf-8")),
            "approval_2_hash": sha256_bytes(b"PUBLICATION:NOT_AUTHORIZED"),
            "evidence_snapshot_hash": snapshot_hash,
            "runtime_attestation_hash": sha256_bytes(b"MEDIA_EXECUTION_FOUNDATION:NO_RUNTIME_ATTESTATION"),
        }
    )
    return append_entry(Path(evidence_log), entry)


@dataclass(frozen=True)
class PublicationAuthorization:
    """Explicit human publication approval for one execution's output."""

    execution_id: str
    approver_id: str
    evidence_reference: str
    approved_at: str


def build_publication_authorization(
    *, execution_id: str, approver_id: str, evidence_reference: str
) -> PublicationAuthorization:
    return PublicationAuthorization(
        execution_id=_require_nonempty_str(execution_id, "execution_id"),
        approver_id=_require_nonempty_str(approver_id, "approver_id"),
        evidence_reference=_require_nonempty_str(evidence_reference, "evidence_reference"),
        approved_at=_utc_now_iso(),
    )


def enforce_publication_gate(
    contract: Optional[MediaExecutionContract],
    *,
    publication_authorization: Optional[PublicationAuthorization],
) -> dict:
    """Generation != publication. Fails closed without explicit human approval."""
    try:
        if contract is None or not isinstance(contract, MediaExecutionContract):
            return _block("CONTRACT_MISSING")
        if publication_authorization is None or not isinstance(
            publication_authorization, PublicationAuthorization
        ):
            return _block("PUBLICATION_NOT_AUTHORIZED")
        if publication_authorization.execution_id != contract.execution_id:
            return _block("PUBLICATION_AUTHORIZATION_MISMATCH")
        return {
            "decision": "ALLOW",
            "execution_id": contract.execution_id,
            "approver_id": publication_authorization.approver_id,
            "timestamp": _utc_now_iso(),
        }
    except Exception:
        return _block("MEDIA_GOVERNANCE_INTERNAL_ERROR")
