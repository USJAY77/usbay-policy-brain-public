import json
import hashlib
import threading
from datetime import datetime
from pathlib import Path

from audit.immutable_ledger import append_evidence_event, assert_ledger_valid, ledger_path_for

FILE = Path("tmp/audit_chain.json")
GENESIS_HASH = "GENESIS"
_AUDIT_APPEND_LOCK = threading.RLock()


def _path(path=None):
    return Path(path) if path is not None else FILE


def load_chain(path=None):
    file_path = _path(path)
    if not file_path.exists():
        return []

    try:
        return json.loads(file_path.read_text())
    except Exception:
        return []


def save_chain(chain, path=None):
    file_path = _path(path)
    file_path.parent.mkdir(exist_ok=True)
    file_path.write_text(json.dumps(chain, indent=2, sort_keys=True))


def compute_hash(event, prev_hash):
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + raw).encode()).hexdigest()


def append_event(action, decision, path=None):
    with _AUDIT_APPEND_LOCK:
        ledger_path = ledger_path_for(_path(path))
        assert_ledger_valid(ledger_path) if ledger_path.exists() else None
        chain = load_chain(path)
        prev_hash = chain[-1]["hash_current"] if chain else GENESIS_HASH

        timestamp = datetime.utcnow().isoformat() + "Z"
        event = {
            "timestamp": timestamp,
            "action": action,
            "decision": decision,
            "hash_prev": prev_hash
        }

        current_hash = compute_hash(event, prev_hash)
        event["hash_current"] = current_hash

        chain.append(event)
        save_chain(chain, path)
        append_evidence_event(
            ledger_path,
            action=action,
            decision=decision,
            timestamp=timestamp,
        )

        return event


def verify_chain(path=None):
    chain = load_chain(path)
    ledger_path = ledger_path_for(_path(path))
    if ledger_path.exists():
        try:
            assert_ledger_valid(ledger_path)
        except Exception:
            return False
    prev_hash = GENESIS_HASH

    for entry in chain:
        event = {
            "timestamp": entry["timestamp"],
            "action": entry["action"],
            "decision": entry["decision"],
            "hash_prev": entry["hash_prev"]
        }

        expected = compute_hash(event, prev_hash)

        if entry.get("hash_prev") != prev_hash:
            return False

        if entry.get("hash_current") != expected:
            return False

        prev_hash = entry["hash_current"]

    return True


class AuditHashChain:
    def __init__(self, *args, **kwargs):
        self.path = Path(args[0]) if args else Path(kwargs.get("path", FILE))

    def append(self, action, decision):
        return append_event(action, decision, self.path)

    def append_event(self, action, decision):
        return append_event(action, decision, self.path)

    def load(self):
        return load_chain(self.path)

    def verify(self):
        return verify_chain(self.path)
