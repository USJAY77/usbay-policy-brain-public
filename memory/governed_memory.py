from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class MemoryRecord:
    timestamp: str
    device_id: str
    action: str
    decision: str
    risk: str
    audit_id: str
    ai_explanation: str = ""
    previous_hash: str = ""
    record_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "action": self.action,
            "decision": self.decision,
            "risk": self.risk,
            "audit_id": self.audit_id,
            "ai_explanation": self.ai_explanation,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


class GovernedMemory:
    """
    USBAY local governed memory.
    No third-party dependency.
    File-based, auditable, integrity-verifiable.
    """

    def __init__(self, device_id: str, memory_dir: str = "memory/store") -> None:
        self.device_id = device_id
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.memory_file = self.memory_dir / f"{device_id}.jsonl"

    def _last_hash(self) -> str:
        if not self.memory_file.exists():
            return ""
        lines = self.memory_file.read_text(encoding="utf-8").splitlines()
        if not lines:
            return ""
        last = json.loads(lines[-1])
        return last.get("record_hash", "")

    def _build_record_hash(self, payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return sha256_text(canonical)

    def remember_decision(
        self,
        action: str,
        decision: str,
        risk: str,
        audit_id: str,
        ai_explanation: str = "",
    ) -> Dict[str, Any]:
        record = MemoryRecord(
            timestamp=utc_now_iso(),
            device_id=self.device_id,
            action=action,
            decision=decision,
            risk=risk,
            audit_id=audit_id,
            ai_explanation=ai_explanation,
            previous_hash=self._last_hash(),
        )

        payload = record.to_dict()
        payload["record_hash"] = self._build_record_hash(
            {
                "timestamp": payload["timestamp"],
                "device_id": payload["device_id"],
                "action": payload["action"],
                "decision": payload["decision"],
                "risk": payload["risk"],
                "audit_id": payload["audit_id"],
                "ai_explanation": payload["ai_explanation"],
                "previous_hash": payload["previous_hash"],
            }
        )

        with self.memory_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

        return payload

    def recall_history(self, action: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.memory_file.exists():
            return []
        lines = self.memory_file.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        if action:
            records = [r for r in records if r.get("action") == action]
        return records[-limit:]

    def full_audit_search(self, query: str) -> List[Dict[str, Any]]:
        if not self.memory_file.exists():
            return []
        query_lower = query.lower()
        matches: List[Dict[str, Any]] = []
        for line in self.memory_file.read_text(encoding="utf-8").splitlines():
            if query_lower in line.lower():
                matches.append(json.loads(line))
        return matches

    def risk_from_history(self, action: str) -> str:
        history = self.recall_history(action=action, limit=100)
        denials = [r for r in history if r.get("decision") == "DENY"]
        count = len(denials)
        if count > 10:
            return "CRITICAL"
        if count > 5:
            return "HIGH"
        if count > 2:
            return "MEDIUM"
        return "LOW"

    def verify_memory_integrity(self) -> Dict[str, Any]:
        if not self.memory_file.exists():
            return {"valid": True, "invalid_indexes": [], "records_checked": 0}

        lines = self.memory_file.read_text(encoding="utf-8").splitlines()
        invalid_indexes: List[int] = []
        previous_hash = ""

        for idx, line in enumerate(lines):
            record = json.loads(line)
            expected_hash = self._build_record_hash(
                {
                    "timestamp": record["timestamp"],
                    "device_id": record["device_id"],
                    "action": record["action"],
                    "decision": record["decision"],
                    "risk": record["risk"],
                    "audit_id": record["audit_id"],
                    "ai_explanation": record.get("ai_explanation", ""),
                    "previous_hash": record.get("previous_hash", ""),
                }
            )

            if record.get("previous_hash", "") != previous_hash:
                invalid_indexes.append(idx)

            if record.get("record_hash", "") != expected_hash:
                invalid_indexes.append(idx)

            previous_hash = record.get("record_hash", "")

        return {
            "valid": len(invalid_indexes) == 0,
            "invalid_indexes": sorted(set(invalid_indexes)),
            "records_checked": len(lines),
        }


if __name__ == "__main__":
    mem = GovernedMemory("mac-prod-001")
    created = mem.remember_decision(
        action="deploy",
        decision="DENY",
        risk="HIGH",
        audit_id="audit-001",
        ai_explanation="Blocked by USBAY fail-closed policy.",
    )
    print(json.dumps(created, indent=2))
    print(json.dumps(mem.verify_memory_integrity(), indent=2))
