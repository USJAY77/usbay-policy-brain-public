from contextlib import contextmanager
import os

from .secret_provider import LocalFileSecretProvider, SecretProvider, VaultSecretProvider


class KeyStore:
    def __init__(self, provider: SecretProvider = None):
        if provider is not None:
            self.provider = provider
            return

        provider_type = os.getenv("USBAY_SECRET_PROVIDER", "local")
        if provider_type == "vault":
            self.provider = VaultSecretProvider()
        else:
            self.provider = LocalFileSecretProvider()

    def load_device_key(self, tenant_id: str, device: str) -> bytearray:
        key = self.provider.get_device_key(tenant_id, device)
        if key is None:
            raise RuntimeError("FAIL_CLOSED")
        if isinstance(key, str):
            key = key.encode("utf-8")
        key_bytes = bytes(key)
        if not key_bytes:
            raise RuntimeError("FAIL_CLOSED")
        return bytearray(key_bytes)

    @contextmanager
    def use_device_key(self, tenant_id: str, device: str):
        key = self.load_device_key(tenant_id, device)
        try:
            yield key
        finally:
            if isinstance(key, bytearray):
                for i in range(len(key)):
                    key[i] = 0

    def rotate_device_key(self, tenant_id: str, device: str, new_key: bytes):
        self.provider.rotate_device_key(tenant_id, device, new_key)
