from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "usbay.persistent_nonce_store.v1"
NONCE_STATUS_RESERVED = "RESERVED"
NONCE_RESULT_RESERVED = "reserved"
NONCE_RESULT_REPLAY = "replay"
NONCE_RESULT_EXPIRED = "expired"
REASON_NONCE_STORE_UNAVAILABLE = "nonce_store_unavailable"
REASON_NONCE_STORE_CORRUPTED = "nonce_store_corrupted"


class PersistentNonceStoreError(RuntimeError):
    pass


def _is_sha256_hex(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def empty_nonce_store() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "records": {},
    }


def initialize_persistent_nonce_store(path: Path | str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(empty_nonce_store(), sort_keys=True, separators=(",", ":")), encoding="utf-8")


class LocalPersistentNonceStore:
    def __init__(self, path: Path | str, ttl_seconds: int = 300, now_fn=time.time):
        self.path = Path(path)
        self.ttl_seconds = int(ttl_seconds)
        self.now_fn = now_fn
        if self.ttl_seconds <= 0:
            raise PersistentNonceStoreError(REASON_NONCE_STORE_UNAVAILABLE)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            raise PersistentNonceStoreError(REASON_NONCE_STORE_UNAVAILABLE)
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED) from exc
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION or not isinstance(data.get("records"), dict):
            raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED)
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, raw_tmp_path = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        tmp_path = Path(raw_tmp_path)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(data, sort_keys=True, separators=(",", ":")))
            tmp_path.replace(self.path)
        except Exception as exc:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise PersistentNonceStoreError(REASON_NONCE_STORE_UNAVAILABLE) from exc

    def lookup(self, nonce_hash: str) -> dict[str, Any]:
        if not _is_sha256_hex(nonce_hash):
            raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED)
        data = self._load()
        record = data["records"].get(nonce_hash)
        if record is None:
            return {"state": "unused"}
        if not isinstance(record, dict):
            raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED)
        try:
            expires_at = float(record["expires_at"])
        except Exception as exc:
            raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED) from exc
        if self.now_fn() > expires_at:
            return {"state": NONCE_RESULT_EXPIRED, "record": record}
        return {"state": NONCE_RESULT_REPLAY, "record": record}

    def reserve(self, nonce_hash: str, *, decision_id: str, timestamp: str) -> dict[str, Any]:
        if not _is_sha256_hex(nonce_hash):
            raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED)
        data = self._load()
        records = data["records"]
        existing = self.lookup(nonce_hash)
        if existing["state"] in {NONCE_RESULT_REPLAY, NONCE_RESULT_EXPIRED}:
            return existing
        now = float(self.now_fn())
        records[nonce_hash] = {
            "decision_id": str(decision_id),
            "created_at": now,
            "expires_at": now + self.ttl_seconds,
            "status": NONCE_STATUS_RESERVED,
            "timestamp": str(timestamp),
        }
        self._save(data)
        return {"state": NONCE_RESULT_RESERVED, "record": records[nonce_hash]}

    def cleanup(self, *, retention_seconds: int) -> int:
        if retention_seconds <= 0:
            raise PersistentNonceStoreError(REASON_NONCE_STORE_UNAVAILABLE)
        data = self._load()
        threshold = self.now_fn() - retention_seconds
        records = data["records"]
        removed = 0
        for nonce_hash, record in list(records.items()):
            if not _is_sha256_hex(nonce_hash) or not isinstance(record, dict):
                raise PersistentNonceStoreError(REASON_NONCE_STORE_CORRUPTED)
            if float(record.get("expires_at", 0)) < threshold:
                removed += 1
                records.pop(nonce_hash, None)
        self._save(data)
        return removed
