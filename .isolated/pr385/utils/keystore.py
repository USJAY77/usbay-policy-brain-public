from contextlib import contextmanager
import os

from utils.secret_provider import LocalFileSecretProvider, SecretProvider, VaultSecretProvider


class KeyStore:
    def __init__(self, provider: SecretProvider = None):
        if provider is not None:
            self.provider = provider
            return

        provider_type = os.getenv("USBAY_SECRET_PROVIDER", "local")
        if provider_type == "local":
            self.provider = LocalFileSecretProvider()
        elif provider_type == "vault":
            self.provider = VaultSecretProvider()
        else:
            raise RuntimeError("FAIL_CLOSED")

    def load_device_key(self, tenant_id: str, device: str):
        key = self.provider.get_device_key(tenant_id, device)
        if key is None:
            raise RuntimeError("FAIL_CLOSED")
        return key

    @contextmanager
    def use_device_key(self, tenant_id: str, device: str):
        key = self.load_device_key(tenant_id, device)
        if isinstance(key, dict):
            key = key.get("key", key.get("private_key"))
        if isinstance(key, str):
            key = key.encode("utf-8")
        key_bytes = bytearray(bytes(key))
        if not key_bytes:
            raise RuntimeError("FAIL_CLOSED")
        try:
            yield key_bytes
        finally:
            for i in range(len(key_bytes)):
                key_bytes[i] = 0

    def rotate_device_key(self, tenant_id: str, device: str, new_key: bytes):
        self.provider.rotate_device_key(tenant_id, device, new_key)
