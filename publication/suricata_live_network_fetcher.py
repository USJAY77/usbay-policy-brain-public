"""Governed live Suricata EVE JSON network fetcher.

The fetcher is production-capable but fail-closed. Tests can inject a local
transport so validation never requires real network access.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_evidence_adapter import evaluate_suricata_eve_json
from publication.suricata_fetch_receipt import SuricataFetchReceiptResult
from publication.suricata_live_fetcher_gate import SuricataLiveFetcherGateResult
from publication.suricata_source_replacement_flow import SuricataSourceReplacementFlowResult
from publication.suricata_trust_anchor_store import SuricataTrustAnchorResult


POLICY_VERSION = "USBAY-SURICATA-015"


@dataclass(frozen=True)
class LiveFetchTransportResponse:
    status_code: int
    body: bytes
    certificate_fingerprint: str
    certificate_valid: bool
    certificate_expired: bool = False
    certificate_self_signed: bool = False
    hostname_matches: bool = True
    fetched_at: str = ""


@dataclass(frozen=True)
class SuricataLiveNetworkFetchResult:
    approved: bool
    blocked: bool
    decision: str
    reason: str
    evidence_hash: str
    bundle_hash: str
    timestamp: str
    policy_version: str
    trust_anchor_fingerprint: str
    fetch_receipt_id: str
    source_url_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "blocked": self.blocked,
            "decision": self.decision,
            "reason": self.reason,
            "evidence_hash": self.evidence_hash,
            "bundle_hash": self.bundle_hash,
            "timestamp": self.timestamp,
            "policy_version": self.policy_version,
            "trust_anchor_fingerprint": self.trust_anchor_fingerprint,
            "fetch_receipt_id": self.fetch_receipt_id,
            "source_url_hash": self.source_url_hash,
        }


Transport = Callable[[str, float], LiveFetchTransportResponse]


def fetch_suricata_live_eve_json(
    *,
    source_url: str,
    config: dict[str, Any] | None,
    trust_anchor: SuricataTrustAnchorResult | None,
    fetch_receipt: SuricataFetchReceiptResult | None,
    replacement_flow: SuricataSourceReplacementFlowResult | None,
    live_fetcher_gate: SuricataLiveFetcherGateResult | None,
    transport: Transport | None = None,
) -> SuricataLiveNetworkFetchResult:
    config = config or {}
    policy_version = str(config.get("policy_version") or POLICY_VERSION)
    source_url_hash = hash_payload({"source_url": source_url})

    config_error = _config_error(source_url, config)
    if config_error:
        return _blocked(config_error, policy_version, source_url_hash)

    if trust_anchor is None or not trust_anchor.approved:
        return _blocked("SURICATA_LIVE_NETWORK_TRUST_ANCHOR_INVALID", policy_version, source_url_hash)
    if fetch_receipt is None or not fetch_receipt.approved:
        return _blocked("SURICATA_LIVE_NETWORK_FETCH_RECEIPT_INVALID", policy_version, source_url_hash)
    if replacement_flow is None or not replacement_flow.approved:
        return _blocked("SURICATA_LIVE_NETWORK_REPLACEMENT_FLOW_INVALID", policy_version, source_url_hash)
    if live_fetcher_gate is None or not live_fetcher_gate.approved:
        return _blocked("SURICATA_LIVE_NETWORK_GATE_INVALID", policy_version, source_url_hash)
    if (
        trust_anchor.policy_version != policy_version
        or replacement_flow.policy_version != policy_version
        or live_fetcher_gate.policy_version != policy_version
    ):
        return _blocked("SURICATA_LIVE_NETWORK_POLICY_MISMATCH", policy_version, source_url_hash)
    if not is_sha256_ref(trust_anchor.public_key_fingerprint):
        return _blocked("SURICATA_LIVE_NETWORK_TRUST_FINGERPRINT_INVALID", policy_version, source_url_hash)

    timeout = float(config["timeout"])
    max_payload_size = int(config["max_payload_size"])
    try:
        response = (transport or _urllib_transport)(source_url, timeout)
    except TimeoutError:
        return _blocked("SURICATA_LIVE_NETWORK_TIMEOUT", policy_version, source_url_hash)
    except Exception:
        return _blocked("SURICATA_LIVE_NETWORK_FETCH_FAILED", policy_version, source_url_hash)

    cert_error = _certificate_error(response, trust_anchor.public_key_fingerprint, verify_certificate=config.get("verify_certificate") is True)
    if cert_error:
        return _blocked(cert_error, policy_version, source_url_hash)
    if response.status_code != 200:
        return _blocked("SURICATA_LIVE_NETWORK_STATUS_INVALID", policy_version, source_url_hash)
    if not response.body:
        return _blocked("SURICATA_LIVE_NETWORK_EMPTY_PAYLOAD", policy_version, source_url_hash)
    if len(response.body) > max_payload_size:
        return _blocked("SURICATA_LIVE_NETWORK_PAYLOAD_TOO_LARGE", policy_version, source_url_hash)

    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return _blocked("SURICATA_LIVE_NETWORK_PAYLOAD_DECODE_FAILED", policy_version, source_url_hash)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _blocked("SURICATA_LIVE_NETWORK_JSON_MALFORMED", policy_version, source_url_hash)
    if not _schema_expected(parsed):
        return _blocked("SURICATA_LIVE_NETWORK_UNEXPECTED_SCHEMA", policy_version, source_url_hash)

    evidence = evaluate_suricata_eve_json(parsed, threshold=0, policy_version=policy_version)
    if not evidence.accepted:
        return _blocked(evidence.reason, policy_version, source_url_hash)

    bundle_hash = hash_payload({"redacted_eve_json": evidence.redacted_event})
    timestamp = response.fetched_at or str(config.get("requested_at") or "")
    if not timestamp:
        return _blocked("SURICATA_LIVE_NETWORK_TIMESTAMP_MISSING", policy_version, source_url_hash)

    payload = _payload(
        approved=True,
        blocked=False,
        decision="ALLOW",
        reason="SURICATA_LIVE_NETWORK_FETCH_APPROVED",
        bundle_hash=bundle_hash,
        timestamp=timestamp,
        policy_version=policy_version,
        trust_anchor_fingerprint=trust_anchor.public_key_fingerprint,
        fetch_receipt_id=fetch_receipt.evidence_hash,
        source_url_hash=source_url_hash,
        redacted_event_hash=evidence.evidence_hash,
    )
    return SuricataLiveNetworkFetchResult(
        approved=True,
        blocked=False,
        decision="ALLOW",
        reason="SURICATA_LIVE_NETWORK_FETCH_APPROVED",
        evidence_hash=hash_payload(payload),
        bundle_hash=bundle_hash,
        timestamp=timestamp,
        policy_version=policy_version,
        trust_anchor_fingerprint=trust_anchor.public_key_fingerprint,
        fetch_receipt_id=fetch_receipt.evidence_hash,
        source_url_hash=source_url_hash,
    )


def _config_error(source_url: str, config: dict[str, Any]) -> str:
    if config.get("enabled") is not True:
        return "SURICATA_LIVE_NETWORK_DISABLED"
    parsed = urlparse(source_url)
    if parsed.scheme != "https":
        return "SURICATA_LIVE_NETWORK_HTTPS_REQUIRED"
    allowlist = config.get("allowlist")
    if not isinstance(allowlist, list) or source_url not in allowlist:
        return "SURICATA_LIVE_NETWORK_SOURCE_NOT_ALLOWED"
    if config.get("tls_required") is not True:
        return "SURICATA_LIVE_NETWORK_TLS_REQUIRED"
    if config.get("verify_certificate") is not True:
        return "SURICATA_LIVE_NETWORK_CERT_VERIFY_REQUIRED"
    if not isinstance(config.get("timeout"), (int, float)) or float(config["timeout"]) <= 0:
        return "SURICATA_LIVE_NETWORK_TIMEOUT_INVALID"
    if not isinstance(config.get("max_payload_size"), int) or int(config["max_payload_size"]) <= 0:
        return "SURICATA_LIVE_NETWORK_MAX_PAYLOAD_INVALID"
    if not isinstance(config.get("retry_count"), int) or int(config["retry_count"]) < 0:
        return "SURICATA_LIVE_NETWORK_RETRY_INVALID"
    if not isinstance(config.get("retry_backoff"), (int, float)) or float(config["retry_backoff"]) < 0:
        return "SURICATA_LIVE_NETWORK_RETRY_INVALID"
    return ""


def _certificate_error(response: LiveFetchTransportResponse, expected_fingerprint: str, *, verify_certificate: bool) -> str:
    if not verify_certificate:
        return "SURICATA_LIVE_NETWORK_CERT_VERIFY_REQUIRED"
    if response.certificate_expired:
        return "SURICATA_LIVE_NETWORK_CERT_EXPIRED"
    if response.certificate_self_signed:
        return "SURICATA_LIVE_NETWORK_CERT_SELF_SIGNED"
    if not response.hostname_matches:
        return "SURICATA_LIVE_NETWORK_CERT_HOSTNAME_MISMATCH"
    if not response.certificate_valid:
        return "SURICATA_LIVE_NETWORK_CERT_INVALID"
    if response.certificate_fingerprint != expected_fingerprint:
        return "SURICATA_LIVE_NETWORK_CERT_FINGERPRINT_MISMATCH"
    return ""


def _schema_expected(value: Any) -> bool:
    events = value if isinstance(value, list) else [value]
    if not events:
        return False
    for event in events:
        if not isinstance(event, dict):
            return False
        if event.get("event_type") != "alert":
            return False
        alert = event.get("alert")
        if not isinstance(alert, dict) or not isinstance(alert.get("severity"), int):
            return False
    return True


def _urllib_transport(source_url: str, timeout: float) -> LiveFetchTransportResponse:
    context = ssl.create_default_context()
    with urllib.request.urlopen(source_url, timeout=timeout, context=context) as response:  # noqa: S310 - governed allowlisted HTTPS only
        body = response.read()
    return LiveFetchTransportResponse(
        status_code=getattr(response, "status", 0),
        body=body,
        certificate_fingerprint="",
        certificate_valid=False,
        fetched_at="",
    )


def _blocked(reason: str, policy_version: str, source_url_hash: str) -> SuricataLiveNetworkFetchResult:
    payload = _payload(
        approved=False,
        blocked=True,
        decision="BLOCK",
        reason=reason,
        bundle_hash="",
        timestamp="",
        policy_version=policy_version or POLICY_VERSION,
        trust_anchor_fingerprint="",
        fetch_receipt_id="",
        source_url_hash=source_url_hash,
        redacted_event_hash="",
    )
    return SuricataLiveNetworkFetchResult(
        approved=False,
        blocked=True,
        decision="BLOCK",
        reason=reason,
        evidence_hash=hash_payload(payload),
        bundle_hash="",
        timestamp="",
        policy_version=policy_version or POLICY_VERSION,
        trust_anchor_fingerprint="",
        fetch_receipt_id="",
        source_url_hash=source_url_hash,
    )


def _payload(
    *,
    approved: bool,
    blocked: bool,
    decision: str,
    reason: str,
    bundle_hash: str,
    timestamp: str,
    policy_version: str,
    trust_anchor_fingerprint: str,
    fetch_receipt_id: str,
    source_url_hash: str,
    redacted_event_hash: str,
) -> dict[str, Any]:
    return {
        "approved": approved,
        "blocked": blocked,
        "decision": decision,
        "reason": reason,
        "bundle_hash": bundle_hash,
        "timestamp": timestamp,
        "policy_version": policy_version,
        "trust_anchor_fingerprint": trust_anchor_fingerprint,
        "fetch_receipt_id": fetch_receipt_id,
        "source_url_hash": source_url_hash,
        "redacted_event_hash": redacted_event_hash,
        "validator_policy_version": POLICY_VERSION,
    }
