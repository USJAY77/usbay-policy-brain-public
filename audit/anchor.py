from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


DEFAULT_PRIVATE_KEY_PATH = Path(os.getenv("USBAY_AUDIT_PRIVATE_KEY_PATH", "/tmp/usbay-audit/audit_private_key.pem"))
DEFAULT_PUBLIC_KEY_PATH = Path("audit/public_key.pem")
LIVE_TSA_MESSAGE = b"USBAY_TIMESTAMP_TEST"


def _read_text(value) -> str:
    if isinstance(value, Path):
        return value.read_text(encoding="utf-8")
    if isinstance(value, str) and "BEGIN" not in value and Path(value).exists():
        return Path(value).read_text(encoding="utf-8")
    return str(value)


def generate_keypair(
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH,
) -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(private_pem)
    private_key_path.chmod(0o600)
    public_key_path.write_bytes(public_pem)
    return private_pem.decode("utf-8"), public_pem.decode("utf-8")


def ensure_keypair(
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    public_key_path: Path = DEFAULT_PUBLIC_KEY_PATH,
) -> tuple[str, str]:
    if not private_key_path.exists():
        return generate_keypair(private_key_path, public_key_path)

    private_pem = private_key_path.read_text(encoding="utf-8")
    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("unsupported audit private key type")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.write_bytes(public_pem)
    return private_pem, public_pem.decode("utf-8")


def public_key_id(public_key) -> str:
    public_pem = _read_text(public_key)
    return hashlib.sha256(public_pem.encode("utf-8")).hexdigest()


def sign_event(event_hash: str, private_key) -> str:
    private_pem = _read_text(private_key)
    loaded_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise RuntimeError("unsupported audit private key type")
    signature = loaded_key.sign(event_hash.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_event(event_hash: str, signature: str, public_key) -> bool:
    if not event_hash or not signature or not public_key:
        return False

    try:
        public_pem = _read_text(public_key)
        loaded_key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(loaded_key, Ed25519PublicKey):
            return False
        loaded_key.verify(
            base64.b64decode(signature.encode("ascii")),
            event_hash.encode("utf-8"),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class TimestampAuthorityClient:
    def timestamp(self, _event_hash: str) -> dict:
        raise NotImplementedError


class MockTSAClient(TimestampAuthorityClient):
    tsa_name = "mock-rfc3161-local"
    policy_oid = "1.3.6.1.4.1.57264.1.1"
    signing_seed = "usbay-rfc3161-mock-tsa-signing-seed"

    def _signature(self, payload: dict) -> str:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{body}:{self.signing_seed}".encode("utf-8")).hexdigest()

    def timestamp(self, event_hash: str) -> dict:
        payload = {
            "status": "granted",
            "policy": self.policy_oid,
            "hash": event_hash,
            "message_imprint": event_hash,
            "message_imprint_algorithm": "sha256",
            "serial_number": hashlib.sha256(
                f"{event_hash}:{self.tsa_name}".encode("utf-8")
            ).hexdigest(),
            "tsa": self.tsa_name,
        }
        payload["signature"] = self._signature(payload)
        return {
            "type": "RFC3161",
            "tsa": self.tsa_name,
            "hash": event_hash,
            "message_imprint": event_hash,
            "message_imprint_algorithm": "sha256",
            "policy_oid": self.policy_oid,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "token": base64.b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).decode("ascii"),
            "token_signature": payload["signature"],
            "tsa_certificate_chain_valid": True,
            "tsa_certificate_chain_pem": "-----BEGIN CERTIFICATE-----\nMOCK-TSA-CERTIFICATE\n-----END CERTIFICATE-----\n",
            "tsa_cert_not_before": "1970-01-01T00:00:00Z",
            "tsa_cert_not_after": "2030-01-01T00:00:00Z",
            "revocation_status": "valid",
            "mode": "mock",
        }


class LocalRFC3161TimestampClient(MockTSAClient):
    pass


def _exception_detail(exc: Exception) -> str:
    return f"{type(exc).__name__}:{exc}"


def _is_network_failure(exc: Exception) -> bool:
    current: BaseException | None = exc
    while current is not None:
        module = type(current).__module__.lower()
        name = type(current).__name__.lower()
        text = str(current).lower()
        if (
            "requests" in module
            or "urllib3" in module
            or name in {"connectionerror", "timeout", "timeouterror", "gaierror"}
            or "name resolution" in text
            or "failed to resolve" in text
            or "max retries exceeded" in text
            or "unable to send the request" in text
        ):
            return True
        current = current.__cause__ or current.__context__
    return False


def _encode_timestamp_token(tsr, encoder) -> bytes:
    if isinstance(tsr, bytes):
        return tsr
    if isinstance(tsr, bytearray):
        return bytes(tsr)
    try:
        return encoder.encode(tsr)
    except Exception as exc:
        raise RuntimeError(f"tsa_encoding_failed:{_exception_detail(exc)}") from exc


def _env_value(*names: str, default: str = "") -> str:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


class LiveRFC3161Client(TimestampAuthorityClient):
    def __init__(
        self,
        tsa_url: str | None = None,
        timeout: float | None = None,
        policy_oid: str | None = None,
        ca_bundle: str | None = None,
    ) -> None:
        self.tsa_url = tsa_url or _env_value("TSA_URL", "USBAY_TSA_URL")
        self.timeout = timeout if timeout is not None else float(_env_value("TSA_TIMEOUT_SECONDS", "USBAY_TSA_TIMEOUT_SECONDS", default="5.0"))
        self.policy_oid = policy_oid or _env_value("TSA_POLICY_OID", "USBAY_TSA_POLICY_OID", default=MockTSAClient.policy_oid)
        self.ca_bundle = ca_bundle or _env_value("TSA_CA_BUNDLE", "USBAY_TSA_CA_BUNDLE")
        if not self.tsa_url:
            raise RuntimeError("missing TSA URL")
        if not self.policy_oid:
            raise RuntimeError("missing TSA policy OID")

    def timestamp(self, event_hash: str) -> dict:
        if not isinstance(event_hash, str) or len(event_hash) != 64:
            raise RuntimeError("invalid_message_imprint")
        try:
            import rfc3161ng
            from pyasn1.codec.der import encoder
        except ImportError as exc:
            raise RuntimeError(f"missing_dependency:rfc3161ng:{_exception_detail(exc)}") from exc

        message = bytes.fromhex(event_hash)
        try:
            timestamper = rfc3161ng.RemoteTimestamper(
                self.tsa_url,
                hashname="sha256",
                timeout=self.timeout,
            )
            tsr = timestamper(data=message)
        except Exception as exc:
            reason = "tsa_dns_or_network_failed" if _is_network_failure(exc) else "tsa_request_failed"
            raise RuntimeError(f"{reason}:{_exception_detail(exc)}") from exc

        if tsr is None:
            raise RuntimeError("tsa_empty_token:empty_tsa_response")

        token_bytes = _encode_timestamp_token(tsr, encoder)

        if not token_bytes:
            raise RuntimeError("tsa_empty_token:empty_encoded_token")

        return {
            "type": "RFC3161",
            "tsa": self.tsa_url,
            "hash": event_hash,
            "message_imprint": event_hash,
            "message_imprint_algorithm": "sha256",
            "policy_oid": self.policy_oid,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "token": base64.b64encode(token_bytes).decode("ascii"),
            "token_signature": hashlib.sha256(token_bytes).hexdigest(),
            "tsa_certificate_chain_valid": bool(self.ca_bundle),
            "tsa_certificate_chain_pem": Path(self.ca_bundle).read_text(encoding="utf-8") if self.ca_bundle and Path(self.ca_bundle).exists() else "",
            "tsa_cert_not_before": "1970-01-01T00:00:00Z",
            "tsa_cert_not_after": "9999-12-31T23:59:59Z",
            "revocation_status": "valid" if self.ca_bundle else "unknown",
            "mode": "live",
        }


def timestamp_event(event_hash: str, tsa_client: TimestampAuthorityClient | None = None) -> dict:
    if tsa_client is not None:
        return tsa_client.timestamp(event_hash)
    mode = _env_value("TSA_MODE", "USBAY_TSA_MODE", default="mock").lower()
    if mode not in {"mock", "external"}:
        raise RuntimeError("invalid TSA_MODE")
    if mode == "external":
        return LiveRFC3161Client().timestamp(event_hash)
    if _env_value("TSA_URL", "USBAY_TSA_URL"):
        raise RuntimeError("tsa_url_requires_external_mode")
    tsa_client = MockTSAClient()
    return tsa_client.timestamp(event_hash)
