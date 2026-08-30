"""USBAY external media provider adapter boundary (Higgsfield).

The ONLY sanctioned path to an external media provider. The Higgsfield
adapter is FAIL-CLOSED: no official Higgsfield execution interface has been
independently proven from this environment, so execute() always returns a
structured PROVIDER_EXECUTION_BLOCKED result and performs NO network calls.
No endpoints, SDKs, or authentication schemes are invented.

A stub adapter exists solely for automated tests of the governance chain.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Optional

from governance.media_execution import (
    DEFAULT_MEDIA_EVIDENCE_LOG,
    MediaAuthorization,
    MediaExecutionContract,
    MediaExecutionConsumptionStore,
    record_media_execution_evidence,
    validate_media_execution,
)

# Names only — values are never read into results/evidence/logs.
_HIGGSFIELD_SECRET_NAMES = ("HIGGSFIELD_API_KEY", "HIGGSFIELD_TOKEN", "HIGGSFIELD_SECRET")

STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_INTERFACE_UNKNOWN = "INTERFACE_UNKNOWN"


def higgsfield_status() -> str:
    """Evidenced status only. Never claims CONNECTED/READY/VERIFIED."""
    if not any(name in os.environ for name in _HIGGSFIELD_SECRET_NAMES):
        return STATUS_NOT_CONFIGURED
    # A credential name exists, but no official execution interface has been
    # independently proven — still fail closed.
    return STATUS_INTERFACE_UNKNOWN


class MediaProviderAdapter:
    """Provider adapter interface. execute() must never be called directly;
    use execute_media_contract(), which enforces the fail-closed gate."""

    provider_name = "abstract"

    def status(self) -> str:
        return STATUS_NOT_CONFIGURED

    def execute(self, contract: MediaExecutionContract) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class HiggsfieldAdapter(MediaProviderAdapter):
    """Fail-closed Higgsfield boundary. No proven interface => always BLOCK."""

    provider_name = "higgsfield"

    def status(self) -> str:
        return higgsfield_status()

    def execute(self, contract: MediaExecutionContract) -> dict:
        status = self.status()
        reason = (
            "PROVIDER_NOT_CONFIGURED"
            if status == STATUS_NOT_CONFIGURED
            else "HIGGSFIELD_INTERFACE_NOT_PROVEN"
        )
        return {
            "decision": "BLOCK",
            "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            "reason_code": reason,
            "provider_status": status,
            "execution_id": contract.execution_id,
        }


class StubMediaProviderAdapter(MediaProviderAdapter):
    """Deterministic test stub. Never leaves the process."""

    provider_name = "higgsfield"

    def __init__(self, fail: bool = False):
        self.fail = bool(fail)
        self.call_count = 0

    def status(self) -> str:
        return "STUB"

    def execute(self, contract: MediaExecutionContract) -> dict:
        self.call_count += 1
        if self.fail:
            return {
                "decision": "BLOCK",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
                "reason_code": "PROVIDER_EXECUTION_FAILED",
                "execution_id": contract.execution_id,
            }
        fake_asset = f"stub-media-output:{contract.execution_id}".encode("utf-8")
        return {
            "decision": "PROVIDER_RESULT",
            "output_asset_hash": hashlib.sha256(fake_asset).hexdigest(),
            "output_metadata": {"output_type": contract.output_type, "outputs": "1"},
            "provider_request_reference": f"stub-ref-{contract.execution_id}",
            "execution_id": contract.execution_id,
        }


# Closed adapter registry: the ONLY adapter classes permitted per provider.
# StubMediaProviderAdapter is test-only and never performs external calls.
def _approved_adapter_classes(provider: str) -> tuple:
    if provider == "higgsfield":
        return (HiggsfieldAdapter, StubMediaProviderAdapter)
    return ()

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SAFE_METADATA_KEYS = {"output_type", "outputs", "duration_seconds", "format", "resolution"}
_MAX_METADATA_VALUE_LEN = 128
_MAX_REFERENCE_LEN = 128


def _sanitize_output_metadata(metadata: dict) -> dict:
    """Allowlist + bound metadata so provider-controlled values cannot smuggle
    prompts/secrets into the evidence ledger."""
    clean = {}
    for key in _SAFE_METADATA_KEYS:
        if key in (metadata or {}):
            value = str(metadata[key])
            if len(value) > _MAX_METADATA_VALUE_LEN:
                raise ValueError("METADATA_VALUE_TOO_LONG")
            clean[key] = value
    return clean


def execute_media_contract(
    contract: Optional[MediaExecutionContract],
    authorization: Optional[MediaAuthorization],
    adapter: MediaProviderAdapter,
    *,
    consumption_store: MediaExecutionConsumptionStore,
    authority_registry=None,
    evidence_log: Path | str = DEFAULT_MEDIA_EVIDENCE_LOG,
) -> dict:
    """Single governed entry point: validate -> reserve (single-use) ->
    authority registry verification -> adapter -> provenance evidence ->
    result. Fail-closed at every step.

    authority_registry is MANDATORY: a missing/invalid registry, or an actor
    or approval that is unknown, revoked, expired, substituted, or replayed,
    DENIES before any provider execution.

    publication_authorized is always False in results; publication requires
    the separate human gate (enforce_publication_gate).
    """
    try:
        if contract is not None:
            approved = _approved_adapter_classes(getattr(contract, "provider", ""))
            if (
                not approved
                or not isinstance(adapter, approved)
                or adapter.provider_name != contract.provider
            ):
                return {
                    "decision": "BLOCK",
                    "reason_code": "ADAPTER_NOT_APPROVED",
                    "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
                }
        validation = validate_media_execution(
            contract, authorization, consumption_store=consumption_store, reserve=True
        )
        if validation.get("decision") != "ALLOW_VALIDATION":
            validation.setdefault("provider_execution", "PROVIDER_EXECUTION_BLOCKED")
            return validation

        # Mandatory durable authority verification (fail-closed).
        from governance.authority_registry import verify_media_authority

        authority = verify_media_authority(authority_registry, contract, authorization)
        if authority.get("decision") != "ALLOW_AUTHORITY":
            blocked = dict(authority)
            blocked["decision"] = "BLOCK"
            blocked.setdefault("reason_code", "AUTHORITY_REGISTRY_FAILURE")
            blocked.setdefault("provider_execution", "PROVIDER_EXECUTION_BLOCKED")
            return blocked

        try:
            provider_result = adapter.execute(contract)
        except Exception:
            return {
                "decision": "BLOCK",
                "reason_code": "PROVIDER_EXECUTION_FAILED",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            }
        if not isinstance(provider_result, dict) or provider_result.get("decision") != "PROVIDER_RESULT":
            blocked = {
                "decision": "BLOCK",
                "reason_code": (provider_result or {}).get("reason_code", "PROVIDER_EXECUTION_FAILED")
                if isinstance(provider_result, dict)
                else "PROVIDER_EXECUTION_FAILED",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            }
            if isinstance(provider_result, dict) and "provider_status" in provider_result:
                blocked["provider_status"] = provider_result["provider_status"]
            return blocked

        # Bind the provider result back to this exact contract.
        if provider_result.get("execution_id") != contract.execution_id:
            return {
                "decision": "BLOCK",
                "reason_code": "PROVIDER_RESULT_MISMATCH",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            }
        reference = provider_result.get("provider_request_reference")
        if reference is not None and (
            not isinstance(reference, str) or len(reference) > _MAX_REFERENCE_LEN
        ):
            return {
                "decision": "BLOCK",
                "reason_code": "PROVIDER_RESULT_MALFORMED",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            }
        output_asset_hash = provider_result.get("output_asset_hash")
        if not isinstance(output_asset_hash, str) or not _SHA256_HEX.fullmatch(
            output_asset_hash.lower()
        ):
            return {
                "decision": "BLOCK",
                "reason_code": "PROVIDER_RESULT_MALFORMED",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            }
        try:
            metadata = _sanitize_output_metadata(provider_result.get("output_metadata", {}))
        except Exception:
            return {
                "decision": "BLOCK",
                "reason_code": "PROVIDER_RESULT_MALFORMED",
                "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
            }
        try:
            entry = record_media_execution_evidence(
                contract=contract,
                output_asset_hash=provider_result["output_asset_hash"],
                output_metadata=metadata,
                provider_request_reference=reference,
                execution_result="SUCCESS",
                evidence_log=evidence_log,
            )
        except Exception:
            return {
                "decision": "BLOCK",
                "reason_code": "EVIDENCE_WRITE_FAILED",
                "provider_execution": "PROVIDER_EXECUTION_COMPLETED_EVIDENCE_FAILED",
            }

        return {
            "decision": "ALLOW",
            "execution_id": contract.execution_id,
            "output_asset_hash": provider_result["output_asset_hash"],
            "evidence_entry_hash": entry["entry_hash"],
            "publication_authorized": False,
        }
    except Exception:
        return {
            "decision": "BLOCK",
            "reason_code": "MEDIA_GOVERNANCE_INTERNAL_ERROR",
            "provider_execution": "PROVIDER_EXECUTION_BLOCKED",
        }
