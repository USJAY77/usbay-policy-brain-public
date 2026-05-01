from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security.request_signing import sign_request_payload


REQUEST_PUBKEY_ID = "test_request_key"
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PRIVATE_KEY_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
_PUBLIC_KEY_PEM = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def sign_payload_ed25519(payload: dict) -> dict:
    return sign_request_payload(payload, _PRIVATE_KEY_PEM, REQUEST_PUBKEY_ID)


def attach_signature_ed25519(payload: dict) -> None:
    signed = sign_payload_ed25519(payload)
    payload.clear()
    payload.update(signed)


def configure_request_signing(tmp_path: Path, monkeypatch, gateway_app) -> None:
    public_key_path = tmp_path / "request_public.key"
    config_path = tmp_path / "request_signing_keys.json"
    public_key_path.write_bytes(_PUBLIC_KEY_PEM)
    config_path.write_text(
        (
            '{"active_keys":["%s"],"revoked_keys":[],"key_map":{"%s":"%s"}}'
            % (REQUEST_PUBKEY_ID, REQUEST_PUBKEY_ID, public_key_path.name)
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(gateway_app, "REQUEST_SIGNING_KEY_CONFIG_PATH", config_path)


def request_private_key_pem() -> bytes:
    return _PRIVATE_KEY_PEM


def request_public_key_pem() -> bytes:
    return _PUBLIC_KEY_PEM
