import json
import hashlib
from datetime import datetime
from pathlib import Path

from audit.immutable_ledger import (
    LedgerIntegrityError,
    _chain_snapshot,
    _check_read_state,
    _commit_transaction,
    _ledger_lock,
    _prepare_record,
    _storage_path,
    _transaction_snapshot,
    append_evidence_event,
    assert_ledger_valid,
    assert_legacy_append_allowed,
    ledger_path_for,
)

FILE = Path("tmp/audit_chain.json")
GENESIS_HASH = "GENESIS"


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
    """Standalone mutation cannot establish a completed audit transaction."""
    raise LedgerIntegrityError("uncoordinated_chain_write_unsupported")


def compute_hash(event, prev_hash):
    raw = json.dumps(event, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + raw).encode()).hexdigest()


def append_event(action, decision, path=None):
    chain_path = _storage_path(_path(path))
    ledger_path = ledger_path_for(chain_path)
    try:
        with _ledger_lock(ledger_path, exclusive=True) as context:
            if _check_read_state(ledger_path):
                raise LedgerIntegrityError("ledger_journal_write_unsupported")
            snapshot = _transaction_snapshot(context)
            if snapshot[1] and snapshot[1] != chain_path.name:
                raise LedgerIntegrityError("ledger_integrity_invalid")
            _, chain = _chain_snapshot(chain_path)
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
            chain_bytes = json.dumps(chain, indent=2, sort_keys=True, allow_nan=False).encode()
            block = _prepare_record(
                snapshot[3],
                action=action,
                decision=decision,
                timestamp=timestamp,
            )
            _commit_transaction(context, snapshot, block, chain_path=chain_path, chain_bytes=chain_bytes)
            return event
    except LedgerIntegrityError:
        raise
    except Exception as exc:
        raise LedgerIntegrityError("ledger_integrity_invalid") from exc


def verify_chain(path=None):
    try:
        chain_path = _storage_path(_path(path))
        ledger_path = ledger_path_for(chain_path)
        with _ledger_lock(ledger_path, exclusive=False) as context:
            snapshot = _transaction_snapshot(context)
            if snapshot[1] and snapshot[1] != chain_path.name:
                return False
            _chain_snapshot(chain_path)
            return True
    except Exception:
        return False


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
