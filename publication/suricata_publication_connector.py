"""Governed Suricata publication connector.

The connector publishes only hash-only governance evidence to an approved
Gateway endpoint. Tests inject a local transport; production use must supply an
explicit allowlisted HTTPS endpoint and trust fingerprint.
"""

from __future__ import annotations

import json
import ssl
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from publication.models import hash_payload, is_sha256_ref
from publication.suricata_live_network_fetcher import SuricataLiveNetworkFetchResult


CONNECTOR_VERSION = "USBAY-SURICATA-016"


@dataclass(frozen=True)
class SuricataPublicationConnectorResponse:
    status_code: int
    body: bytes
    certificate_fingerprint: str
    certificate_valid: bool
    certificate_expired: bool = False
    certificate_self_signed: bool = False
    hostname_matches: bool = True
    responded_at: str = ""


@dataclass(frozen=True)
class SuricataPublicationConnectorResult:
    approved: bool
    blocked: bool
    decision: str
    reason: str
    evidence_hash: str
    policy_version: str
    trust_fingerprint: str
    timestamp: str
    nonce: str
    connector_version: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approved": self.approved,
            "blocked": self.blocked,
            "decision": self.decision,
            "reason": self.reason,
            "evidence_hash": self.evidence_hash,
            "policy_version": self.policy_version,
            "trust_fingerprint": self.trust_fingerprint,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "connector_version": self.connector_version,
        }


ConnectorTransport = Callable[[str, bytes, float], SuricataPublicationConnectorResponse]


@dataclass(frozen=True)
class SuricataGatewayEndpointConfig:
    endpoint_url: str
    enabled: bool
    policy_version: str
    expected_evidence_hash: str
    trust_fingerprint: str

    @classmethod
    def from_dict(cls, endpoint_url: str, config: dict[str, Any]) -> "SuricataGatewayEndpointConfig":
        return cls(
            endpoint_url=endpoint_url,
            enabled=config.get("enabled") is True,
            policy_version=str(config.get("policy_version") or ""),
            expected_evidence_hash=str(config.get("expected_evidence_hash") or ""),
            trust_fingerprint=str(config.get("trust_fingerprint") or ""),
        )


class FileBackedNonceStore:
    """Local nonce store for deterministic replay protection."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def has_seen(self, nonce: str) -> bool:
        return nonce in self._read()

    def record(self, nonce: str, timestamp: str) -> None:
        data = self._read()
        data[nonce] = timestamp
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    def _read(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(loaded, dict):
            return {}
        return {str(key): str(value) for key, value in loaded.items()}


def publish_suricata_governance_evidence(
    *,
    endpoint_url: str,
    config: dict[str, Any] | None,
    live_network_fetch: SuricataLiveNetworkFetchResult | None,
    nonce: str,
    timestamp: str,
    seen_nonces: Iterable[str] | None = None,
    nonce_store: FileBackedNonceStore | None = None,
    transport: ConnectorTransport | None = None,
) -> SuricataPublicationConnectorResult:
    config = config or {}
    endpoint_config = SuricataGatewayEndpointConfig.from_dict(endpoint_url, config)
    policy_version = endpoint_config.policy_version or CONNECTOR_VERSION
    trust_fingerprint = endpoint_config.trust_fingerprint

    config_error = _config_error(endpoint_config, config)
    if config_error:
        return _blocked(config_error, policy_version, trust_fingerprint, timestamp, nonce)
    if live_network_fetch is None or not live_network_fetch.approved:
        return _blocked("SURICATA_CONNECTOR_LIVE_FETCH_INVALID", policy_version, trust_fingerprint, timestamp, nonce)
    if live_network_fetch.policy_version != policy_version:
        return _blocked("SURICATA_CONNECTOR_POLICY_MISMATCH", policy_version, trust_fingerprint, timestamp, nonce)
    if live_network_fetch.trust_anchor_fingerprint != trust_fingerprint:
        return _blocked("SURICATA_CONNECTOR_TRUST_FINGERPRINT_MISMATCH", policy_version, trust_fingerprint, timestamp, nonce)
    if not is_sha256_ref(live_network_fetch.evidence_hash):
        return _blocked("SURICATA_CONNECTOR_EVIDENCE_HASH_INVALID", policy_version, trust_fingerprint, timestamp, nonce)
    if str(config.get("expected_evidence_hash") or "") != live_network_fetch.evidence_hash:
        return _blocked("SURICATA_CONNECTOR_EVIDENCE_HASH_MISMATCH", policy_version, trust_fingerprint, timestamp, nonce)
    if not nonce:
        return _blocked("SURICATA_CONNECTOR_NONCE_MISSING", policy_version, trust_fingerprint, timestamp, nonce)
    if nonce in set(seen_nonces or ()):
        return _blocked("SURICATA_CONNECTOR_REPLAYED_NONCE", policy_version, trust_fingerprint, timestamp, nonce)
    if nonce_store is not None and nonce_store.has_seen(nonce):
        return _blocked("SURICATA_CONNECTOR_REPLAYED_NONCE", policy_version, trust_fingerprint, timestamp, nonce)

    freshness_error = _freshness_error(timestamp, max_age_seconds=int(config["max_timestamp_age_seconds"]), now=str(config.get("now") or ""))
    if freshness_error:
        return _blocked(freshness_error, policy_version, trust_fingerprint, timestamp, nonce)

    payload = _publication_payload(
        evidence_hash=live_network_fetch.evidence_hash,
        policy_version=policy_version,
        trust_fingerprint=trust_fingerprint,
        decision=live_network_fetch.decision,
        reason=live_network_fetch.reason,
        timestamp=timestamp,
        nonce=nonce,
        connector_version=CONNECTOR_VERSION,
    )
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        response = (transport or _urllib_transport)(endpoint_url, body, float(config["timeout"]))
    except TimeoutError:
        return _blocked("SURICATA_CONNECTOR_TIMEOUT", policy_version, trust_fingerprint, timestamp, nonce)
    except Exception:
        return _blocked("SURICATA_CONNECTOR_TRANSPORT_FAILED", policy_version, trust_fingerprint, timestamp, nonce)

    cert_error = _certificate_error(response, trust_fingerprint)
    if cert_error:
        return _blocked(cert_error, policy_version, trust_fingerprint, timestamp, nonce)
    if response.status_code >= 500:
        return _blocked("SURICATA_CONNECTOR_GATEWAY_5XX", policy_version, trust_fingerprint, timestamp, nonce)
    if response.status_code < 200 or response.status_code >= 300:
        return _blocked("SURICATA_CONNECTOR_GATEWAY_STATUS_INVALID", policy_version, trust_fingerprint, timestamp, nonce)
    try:
        response_payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _blocked("SURICATA_CONNECTOR_RESPONSE_MALFORMED", policy_version, trust_fingerprint, timestamp, nonce)
    if response_payload.get("accepted") is not True or response_payload.get("accepted_evidence_hash") != live_network_fetch.evidence_hash:
        return _blocked("SURICATA_CONNECTOR_RESPONSE_MALFORMED", policy_version, trust_fingerprint, timestamp, nonce)
    if nonce_store is not None:
        try:
            nonce_store.record(nonce, timestamp)
        except OSError:
            return _blocked("SURICATA_CONNECTOR_NONCE_STORE_FAILED", policy_version, trust_fingerprint, timestamp, nonce)

    return SuricataPublicationConnectorResult(
        approved=True,
        blocked=False,
        decision="ALLOW",
        reason="SURICATA_CONNECTOR_PUBLICATION_APPROVED",
        evidence_hash=hash_payload({"publication_payload": payload, "response_hash": hash_payload(response_payload)}),
        policy_version=policy_version,
        trust_fingerprint=trust_fingerprint,
        timestamp=timestamp,
        nonce=nonce,
        connector_version=CONNECTOR_VERSION,
    )


def _config_error(endpoint_config: SuricataGatewayEndpointConfig, config: dict[str, Any]) -> str:
    if not endpoint_config.endpoint_url:
        return "SURICATA_CONNECTOR_ENDPOINT_MISSING"
    if not endpoint_config.enabled:
        return "SURICATA_CONNECTOR_DISABLED"
    if not endpoint_config.policy_version:
        return "SURICATA_CONNECTOR_POLICY_MISSING"
    parsed = urlparse(endpoint_config.endpoint_url)
    if parsed.scheme != "https":
        return "SURICATA_CONNECTOR_HTTPS_REQUIRED"
    allowlist = config.get("allowlist")
    if not isinstance(allowlist, list) or endpoint_config.endpoint_url not in allowlist:
        return "SURICATA_CONNECTOR_ENDPOINT_NOT_ALLOWED"
    if not isinstance(config.get("timeout"), (int, float)) or float(config["timeout"]) <= 0:
        return "SURICATA_CONNECTOR_TIMEOUT_INVALID"
    if not isinstance(config.get("retry_count"), int) or int(config["retry_count"]) < 0:
        return "SURICATA_CONNECTOR_RETRY_INVALID"
    if config.get("tls_required") is not True or config.get("verify_certificate") is not True:
        return "SURICATA_CONNECTOR_CERT_VERIFY_REQUIRED"
    if not is_sha256_ref(endpoint_config.trust_fingerprint):
        return "SURICATA_CONNECTOR_TRUST_FINGERPRINT_MISSING"
    if not is_sha256_ref(endpoint_config.expected_evidence_hash):
        return "SURICATA_CONNECTOR_EVIDENCE_HASH_INVALID"
    if not isinstance(config.get("max_timestamp_age_seconds"), int) or int(config["max_timestamp_age_seconds"]) <= 0:
        return "SURICATA_CONNECTOR_FRESHNESS_POLICY_INVALID"
    trust_provider_error = _trust_provider_error(config.get("trust_provider"), endpoint_config.policy_version)
    if trust_provider_error:
        return trust_provider_error
    return ""


def _trust_provider_error(provider: Any, policy_version: str) -> str:
    if not isinstance(provider, dict):
        return "SURICATA_CONNECTOR_TRUST_PROVIDER_MISSING"
    if provider.get("configured") is not True:
        return "SURICATA_CONNECTOR_TRUST_PROVIDER_NOT_CONFIGURED"
    if provider.get("human_approved") is not True:
        return "SURICATA_CONNECTOR_TRUST_PROVIDER_NOT_APPROVED"
    if not provider.get("provider_type") or not provider.get("provider_id"):
        return "SURICATA_CONNECTOR_TRUST_PROVIDER_MALFORMED"
    if str(provider.get("policy_version") or "") != policy_version:
        return "SURICATA_CONNECTOR_TRUST_PROVIDER_POLICY_MISMATCH"
    if not is_sha256_ref(str(provider.get("provider_reference_hash") or "")):
        return "SURICATA_CONNECTOR_TRUST_PROVIDER_REFERENCE_INVALID"
    return ""


def _certificate_error(response: SuricataPublicationConnectorResponse, trust_fingerprint: str) -> str:
    if not response.certificate_fingerprint:
        return "SURICATA_CONNECTOR_CERT_FINGERPRINT_MISSING"
    if response.certificate_expired:
        return "SURICATA_CONNECTOR_CERT_EXPIRED"
    if response.certificate_self_signed:
        return "SURICATA_CONNECTOR_CERT_SELF_SIGNED"
    if not response.hostname_matches:
        return "SURICATA_CONNECTOR_CERT_HOSTNAME_MISMATCH"
    if not response.certificate_valid:
        return "SURICATA_CONNECTOR_CERT_INVALID"
    if response.certificate_fingerprint != trust_fingerprint:
        return "SURICATA_CONNECTOR_TRUST_FINGERPRINT_MISMATCH"
    return ""


def _freshness_error(timestamp: str, *, max_age_seconds: int, now: str) -> str:
    if not timestamp or not now:
        return "SURICATA_CONNECTOR_TIMESTAMP_MISSING"
    try:
        timestamp_dt = _parse_time(timestamp)
        now_dt = _parse_time(now)
    except ValueError:
        return "SURICATA_CONNECTOR_TIMESTAMP_MALFORMED"
    age = (now_dt - timestamp_dt).total_seconds()
    if age < 0 or age > max_age_seconds:
        return "SURICATA_CONNECTOR_TIMESTAMP_STALE"
    return ""


def _publication_payload(
    *,
    evidence_hash: str,
    policy_version: str,
    trust_fingerprint: str,
    decision: str,
    reason: str,
    timestamp: str,
    nonce: str,
    connector_version: str,
) -> dict[str, str]:
    return {
        "evidence_hash": evidence_hash,
        "policy_version": policy_version,
        "trust_fingerprint": trust_fingerprint,
        "decision": decision,
        "reason": reason,
        "timestamp": timestamp,
        "nonce": nonce,
        "connector_version": connector_version,
    }


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _urllib_transport(endpoint_url: str, body: bytes, timeout: float) -> SuricataPublicationConnectorResponse:
    request = urllib.request.Request(endpoint_url, data=body, method="POST", headers={"content-type": "application/json"})
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:  # noqa: S310 - governed allowlisted HTTPS only
        response_body = response.read()
    return SuricataPublicationConnectorResponse(
        status_code=getattr(response, "status", 0),
        body=response_body,
        certificate_fingerprint="",
        certificate_valid=False,
    )


def _blocked(reason: str, policy_version: str, trust_fingerprint: str, timestamp: str, nonce: str) -> SuricataPublicationConnectorResult:
    payload = {
        "approved": False,
        "blocked": True,
        "decision": "BLOCK",
        "reason": reason,
        "policy_version": policy_version or CONNECTOR_VERSION,
        "trust_fingerprint": trust_fingerprint,
        "timestamp": timestamp,
        "nonce": nonce,
        "connector_version": CONNECTOR_VERSION,
    }
    return SuricataPublicationConnectorResult(
        approved=False,
        blocked=True,
        decision="BLOCK",
        reason=reason,
        evidence_hash=hash_payload(payload),
        policy_version=policy_version or CONNECTOR_VERSION,
        trust_fingerprint=trust_fingerprint,
        timestamp=timestamp,
        nonce=nonce,
        connector_version=CONNECTOR_VERSION,
    )
