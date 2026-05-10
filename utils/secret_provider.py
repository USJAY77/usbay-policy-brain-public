from __future__ import annotations

import os
from pathlib import Path

import requests


class SecretProvider:
    def get_device_key(self, tenant_id: str, device: str):
        vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")
        token = os.getenv("VAULT_TOKEN", "root")
        url = f"{vault_addr}/v1/secret/data/{tenant_id}/devices/{device}"
        headers = {"X-Vault-Token": token}

        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code != 200:
                raise RuntimeError("FAIL_CLOSED")
            return response.json()["data"]["data"]
        except Exception as exc:
            raise RuntimeError("FAIL_CLOSED") from exc

    def rotate_device_key(self, tenant_id: str, device: str, new_key: bytes) -> None:
        raise NotImplementedError


class LocalFileSecretProvider(SecretProvider):
    def __init__(self, root: Path | str = "secrets"):
        self.root = Path(root)

    def _path(self, tenant_id: str, device: str) -> Path:
        return self.root / tenant_id / "devices" / f"{device}.key"

    def get_device_key(self, tenant_id: str, device: str) -> bytes:
        try:
            key = self._path(tenant_id, device).read_bytes()
        except OSError as exc:
            raise RuntimeError("FAIL_CLOSED") from exc
        if not key:
            raise RuntimeError("FAIL_CLOSED")
        return key

    def rotate_device_key(self, tenant_id: str, device: str, new_key: bytes) -> None:
        if not new_key:
            raise RuntimeError("FAIL_CLOSED")
        path = self._path(tenant_id, device)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(new_key))


class VaultSecretProvider(SecretProvider):
    def __init__(self):
        vault_addr = os.getenv("VAULT_ADDR")
        token = os.getenv("VAULT_TOKEN")
        if not vault_addr or not token:
            raise RuntimeError("FAIL_CLOSED")
        self.vault_addr = vault_addr.rstrip("/")
        self.token = token

    def _url(self, tenant_id: str, device: str) -> str:
        return f"{self.vault_addr}/v1/secret/data/{tenant_id}/devices/{device}"

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self.token}

    def get_device_key(self, tenant_id: str, device: str) -> str:
        try:
            response = requests.get(
                self._url(tenant_id, device),
                headers=self._headers(),
                timeout=3,
            )
            if response.status_code != 200:
                raise RuntimeError("FAIL_CLOSED")
            data = response.json()["data"]["data"]
            key = data["key"]
        except Exception as exc:
            raise RuntimeError("FAIL_CLOSED") from exc
        if key is None:
            raise RuntimeError("FAIL_CLOSED")
        return key

    def rotate_device_key(self, tenant_id: str, device: str, new_key: bytes) -> None:
        if not new_key:
            raise RuntimeError("FAIL_CLOSED")
        try:
            response = requests.post(
                self._url(tenant_id, device),
                headers=self._headers(),
                json={"data": {"key": bytes(new_key).decode("utf-8")}},
                timeout=3,
            )
            if response.status_code not in (200, 204):
                raise RuntimeError("FAIL_CLOSED")
        except Exception as exc:
            raise RuntimeError("FAIL_CLOSED") from exc
