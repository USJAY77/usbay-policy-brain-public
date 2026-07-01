from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class ComputerUseAuditRecorder:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        previous_hash = self._previous_hash()
        payload = {
            **event,
            "timestamp": event.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256((previous_hash + _canonical(payload)).encode("utf-8")).hexdigest()
        payload["audit_hash"] = event_hash
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(_canonical(payload) + "\n")
        return payload

    def _previous_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return "0" * 64
        try:
            return str(json.loads(lines[-1])["audit_hash"])
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError("COMPUTER_USE_AUDIT_CHAIN_INVALID") from exc
