from __future__ import annotations

from pathlib import Path


def install_isolated_audit_key_registry(monkeypatch, tmp_path: Path) -> None:
    registry_path = tmp_path / "key_registry.json"
    private_key_path = tmp_path / "audit_private_key.pem"
    public_key_path = tmp_path / "public_key.pem"
    private_key_dir = tmp_path / "private_keys"
    public_key_dir = tmp_path / "public_keys"
    execution_evidence_path = tmp_path / "execution_evidence.jsonl"

    monkeypatch.setenv("USBAY_AUDIT_KEY_REGISTRY_PATH", str(registry_path))
    monkeypatch.setenv("USBAY_AUDIT_PRIVATE_KEY_PATH", str(private_key_path))
    monkeypatch.setenv("USBAY_AUDIT_PUBLIC_KEY_PATH", str(public_key_path))
    monkeypatch.setenv("USBAY_AUDIT_PRIVATE_KEY_DIR", str(private_key_dir))
    monkeypatch.setenv("USBAY_AUDIT_PUBLIC_KEY_DIR", str(public_key_dir))
    monkeypatch.setenv("USBAY_EXECUTION_EVIDENCE_PATH", str(execution_evidence_path))

    import audit.keys as audit_keys

    monkeypatch.setattr(audit_keys, "DEFAULT_REGISTRY_PATH", registry_path)
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_PATH", private_key_path)
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_PATH", public_key_path)
    monkeypatch.setattr(audit_keys, "DEFAULT_PRIVATE_KEY_DIR", private_key_dir)
    monkeypatch.setattr(audit_keys, "DEFAULT_PUBLIC_KEY_DIR", public_key_dir)


__all__ = ["install_isolated_audit_key_registry"]
