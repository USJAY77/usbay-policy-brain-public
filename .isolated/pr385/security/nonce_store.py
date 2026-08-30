from __future__ import annotations

import json
import time
from pathlib import Path


class NonceStore:
    def __init__(self, path: Path | str = "tmp/used_nonces.json", ttl_seconds: int = 300):
        self.path = Path(path)
        self.ttl_seconds = ttl_seconds

    def _load(self) -> dict[str, float]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("nonce store must be a JSON object")
            return {str(key): float(value) for key, value in data.items()}
        except Exception as exc:
            raise RuntimeError("FAIL_CLOSED") from exc

    def _save(self, nonces: dict[str, float]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(nonces, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def _prune(self, nonces: dict[str, float], now: float) -> dict[str, float]:
        return {
            nonce: used_at
            for nonce, used_at in nonces.items()
            if now - used_at <= self.ttl_seconds
        }

    def is_used(self, nonce: str) -> bool:
        if not nonce:
            raise RuntimeError("FAIL_CLOSED")
        now = time.time()
        nonces = self._prune(self._load(), now)
        self._save(nonces)
        return nonce in nonces

    def exists(self, nonce: str) -> bool:
        return self.is_used(nonce)

    def contains(self, nonce: str) -> bool:
        return self.exists(nonce)

    def mark_used(self, nonce: str) -> None:
        if not nonce:
            raise RuntimeError("FAIL_CLOSED")
        now = time.time()
        nonces = self._prune(self._load(), now)
        if nonce in nonces:
            raise RuntimeError("FAIL_CLOSED")
        nonces[nonce] = now
        self._save(nonces)

    def store(self, nonce: str, ts: int | float | str) -> bool:
        if not nonce:
            raise RuntimeError("FAIL_CLOSED")
        nonces = self._prune(self._load(), time.time())
        if nonce in nonces:
            return False
        nonces[nonce] = float(ts)
        self._save(nonces)
        return True

    def add(self, nonce: str) -> bool:
        return self.store(nonce, int(time.time()))
