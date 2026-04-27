from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from urllib import request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


DEFAULT_PRIVATE_KEY_PATH = Path("tmp/audit_private_key.pem")
DEFAULT_PUBLIC_KEY_PATH = Path("audit/public_key.pem")


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
    def timestamp(self, event_hash: str) -> dict:
        raise NotImplementedError


class MockTSAClient(TimestampAuthorityClient):
    tsa_name = "mock-rfc3161-local"
    policy_oid = "1.3.6.1.4.1.57264.1.1"

    def timestamp(self, event_hash: str) -> dict:
        return {
            "type": "RFC3161",
            "tsa": self.tsa_name,
            "hash": event_hash,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "token": base64.b64encode(
                json.dumps(
                    {
                        "status": "granted",
                        "policy": self.policy_oid,
                        "hash": event_hash,
                        "serial_number": hashlib.sha256(
                            f"{event_hash}:{self.tsa_name}".encode("utf-8")
                        ).hexdigest(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).decode("ascii"),
            "mode": "mock",
        }


class LocalRFC3161TimestampClient(MockTSAClient):
    pass


class LiveRFC3161Client(TimestampAuthorityClient):
    def __init__(self, tsa_url: str | None = None, timeout: float = 5.0) -> None:
        self.tsa_url = tsa_url or os.getenv("USBAY_TSA_URL", "")
        self.timeout = timeout
        if not self.tsa_url:
            raise RuntimeError("missing TSA URL")

    def timestamp(self, event_hash: str) -> dict:
        body = json.dumps({"hash": event_hash}).encode("utf-8")
        tsa_request = request.Request(
            self.tsa_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(tsa_request, timeout=self.timeout) as response:
                token_bytes = response.read()
        except Exception as exc:
            raise RuntimeError("TSA timestamp request failed") from exc

        if not token_bytes:
            raise RuntimeError("TSA timestamp response empty")

        return {
            "type": "RFC3161",
            "tsa": self.tsa_url,
            "hash": event_hash,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "token": base64.b64encode(token_bytes).decode("ascii"),
            "mode": "live",
        }


def timestamp_event(event_hash: str, tsa_client: TimestampAuthorityClient | None = None) -> dict:
    if tsa_client is not None:
        return tsa_client.timestamp(event_hash)
    if os.getenv("USBAY_TSA_URL"):
        return LiveRFC3161Client().timestamp(event_hash)
    tsa_client = MockTSAClient()
    return tsa_client.timestamp(event_hash)
