from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import fcntl

from audit.journal_compatibility import AuditCompatibilityError, check_read_state
from audit.anchor import sign_event, verify_event
from audit.keys import DEFAULT_KEY_VERSION, get_signing_key, resolve_public_key
from audit.rfc3161_anchor import (
    component_hashes,
    create_timestamp_proof,
    message_imprint,
    verify_timestamp_proof,
    write_timestamp_files,
)
from security.deployment_attestation import (
    RuntimeProvenanceAuthority,
    assert_runtime_provenance_authority,
    load_release_manifest,
    validate_release_manifest,
)
from security.tenant_context import (
    TenantIsolationError,
    tenant_hash,
    validate_consensus_tenant,
    validate_records_single_tenant,
    validate_tenant_id,
)


GENESIS_HASH = "GENESIS"
FORBIDDEN_FIELD_NAMES = {
    "approval",
    "approval_contents",
    "approval_material",
    "private_key",
    "raw_nonce",
    "raw_payload",
    "secret",
    "token",
}


class LedgerIntegrityError(RuntimeError):
    pass


_PROCESS_LOCK = threading.RLock()
_FORK_LOCK = threading.Lock()
_LOCK_LOCAL = threading.local()
_INHERITED_LOCK_FDS = set()
_RECORD_LIMIT = 16 * 1024
_LOG_LIMIT = 64 * 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _before_fork():
    _FORK_LOCK.acquire()


def _after_fork_parent():
    _FORK_LOCK.release()


def _after_fork():
    global _PROCESS_LOCK, _FORK_LOCK, _LOCK_LOCAL
    for descriptor in tuple(_INHERITED_LOCK_FDS):
        try:
            os.close(descriptor)
        except OSError:
            pass
    _INHERITED_LOCK_FDS.clear()
    _PROCESS_LOCK = threading.RLock()
    _FORK_LOCK = threading.Lock()
    _LOCK_LOCAL = threading.local()


os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_parent,
                    after_in_child=_after_fork)


class _LockContext:
    __slots__ = ("path", "descriptor", "exclusive")

    def __init__(self, path, descriptor, exclusive):
        self.path, self.descriptor, self.exclusive = path, descriptor, exclusive

    def require(self, path, *, write=False):
        if (getattr(_LOCK_LOCAL, "active", None) is not self
                or self.path != _storage_path(path) or (write and not self.exclusive)):
            raise LedgerIntegrityError("ledger_lock_context_invalid")
        os.fstat(self.descriptor)


def _storage_path(path):
    path = Path(path)
    if ".." in path.parts:
        raise LedgerIntegrityError("ledger_integrity_invalid")
    path = Path(os.path.abspath(path))
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise LedgerIntegrityError("ledger_integrity_invalid")
    return path


def _check_parent(path):
    metadata = path.stat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    for ancestor in path.parents:
        metadata = ancestor.stat()
        if metadata.st_uid not in {0, os.geteuid()}:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        if metadata.st_mode & 0o022 and not metadata.st_mode & stat.S_ISVTX:
            raise LedgerIntegrityError("ledger_integrity_invalid")


def _bytes(path, *, limit=None):
    path = _storage_path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        if limit is not None and before.st_size > limit:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        chunks = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(path.stat(follow_symlinks=False)):
            raise LedgerIntegrityError("ledger_integrity_invalid")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _state(data):
    return {"exists": data is not None, "size": len(data) if data is not None else 0,
            "sha256": hashlib.sha256(data).hexdigest() if data is not None else None}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        result[key] = value
    return result


def _strict_json(data):
    def invalid(_):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    return json.loads(data, object_pairs_hook=_unique, parse_constant=invalid)


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _chain_snapshot(path):
    data = _bytes(path)
    chain = [] if data is None else _strict_json(data)
    if not isinstance(chain, list):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    previous = GENESIS_HASH
    for entry in chain:
        if not isinstance(entry, dict):
            raise LedgerIntegrityError("ledger_integrity_invalid")
        event = {key: entry[key] for key in ("timestamp", "action", "decision", "hash_prev")}
        digest = hashlib.sha256(previous.encode() + _encode(event)).hexdigest()
        if entry["hash_prev"] != previous or entry.get("hash_current") != digest:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        previous = digest
    return data, chain


def _log_path(path):
    return Path(str(path) + ".pair-transactions-v1.jsonl")


def _valid_state(value):
    if not isinstance(value, dict) or set(value) != {"exists", "size", "sha256"}:
        return False
    if type(value["exists"]) is not bool or type(value["size"]) is not int or value["size"] < 0:
        return False
    if not value["exists"]:
        return value["size"] == 0 and value["sha256"] is None
    return isinstance(value["sha256"], str) and bool(_HEX.fullmatch(value["sha256"]))


def _valid_snapshot(value, bound):
    return (isinstance(value, dict) and set(value) == {"chain", "ledger"}
            and _valid_state(value["ledger"])
            and (_valid_state(value["chain"]) if bound else value["chain"] is None))


def _read_log(path):
    data = _bytes(_log_path(path), limit=_LOG_LIMIT)
    if data is None:
        return [], None
    if not data or len(data) > _LOG_LIMIT or not data.endswith(b"\n"):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    records, seen, binding, previous_complete = [], set(), None, None
    for line in data.splitlines(keepends=True):
        if len(line) > _RECORD_LIMIT:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        record = _strict_json(line)
        fields = {"version", "seq", "kind", "txid", "previous_record_sha256", "payload", "record_sha256"}
        if not isinstance(record, dict) or set(record) != fields:
            raise LedgerIntegrityError("ledger_integrity_invalid")
        digest = record["record_sha256"]
        unsigned = {key: value for key, value in record.items() if key != "record_sha256"}
        if (type(record["version"]) is not int or record["version"] != 1
                or type(record["seq"]) is not int or record["seq"] != len(records) + 1
                or record["previous_record_sha256"] != (records[-1]["record_sha256"] if records else None)
                or not isinstance(record["txid"], str)
                or re.fullmatch(r"[0-9a-f]{32}", record["txid"]) is None
                or digest != hashlib.sha256(_encode(unsigned)).hexdigest()
                or _encode(record) + b"\n" != line):
            raise LedgerIntegrityError("ledger_integrity_invalid")
        payload = record["payload"]
        if len(records) % 2 == 0:
            if (record["kind"] != "INTENT" or record["txid"] in seen
                    or not isinstance(payload, dict) or set(payload) != {
                        "operation", "ledger_name", "chain_name", "before", "after", "previous_complete_sha256"}):
                raise LedgerIntegrityError("ledger_integrity_invalid")
            seen.add(record["txid"])
            name = payload["chain_name"]
            if (payload["operation"] not in {"paired_append", "ledger_append"}
                    or payload["ledger_name"] != path.name
                    or payload["previous_complete_sha256"] != previous_complete
                    or (name is not None and (not isinstance(name, str) or not name
                         or Path(name).name != name or name in {".", ".."}))
                    or (binding is not None and name != binding)
                    or (payload["operation"] == "paired_append" and name is None)
                    or not _valid_snapshot(payload["before"], name is not None)
                    or not _valid_snapshot(payload["after"], name is not None)):
                raise LedgerIntegrityError("ledger_integrity_invalid")
            if records:
                prior = records[-1]["payload"]["after"]
                if (prior["ledger"] != payload["before"]["ledger"]
                        or (binding is not None and prior["chain"] != payload["before"]["chain"])):
                    raise LedgerIntegrityError("ledger_integrity_invalid")
            if (payload["operation"] == "ledger_append"
                    and payload["before"]["chain"] != payload["after"]["chain"]):
                raise LedgerIntegrityError("ledger_integrity_invalid")
            binding = name
        else:
            intent = records[-1]
            if (record["kind"] != "COMPLETE" or record["txid"] != intent["txid"]
                    or not isinstance(payload, dict) or set(payload) != {"intent_sha256", "after"}
                    or payload["intent_sha256"] != intent["record_sha256"]
                    or payload["after"] != intent["payload"]["after"]):
                raise LedgerIntegrityError("ledger_integrity_invalid")
            previous_complete = digest
        records.append(record)
    if len(records) % 2:
        raise LedgerIntegrityError("ledger_write_uncertain")
    return records, binding


def _transaction_snapshot(context):
    path = context.path
    context.require(path)
    _check_read_state(path)
    log, binding = _read_log(path)
    ledger_bytes = _bytes(path)
    records = _read_records(path)
    if not _verify_records(records):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    chain_bytes, chain = _chain_snapshot(path.parent / binding) if binding else (None, None)
    state = {"chain": _state(chain_bytes) if binding else None, "ledger": _state(ledger_bytes)}
    if log and log[-1]["payload"]["after"] != state:
        raise LedgerIntegrityError("ledger_integrity_invalid")
    return log, binding, ledger_bytes, records, chain_bytes, chain


def _write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _append_bytes(path, data):
    existed = _bytes(path) is not None
    flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_APPEND if existed else os.O_CREAT | os.O_EXCL)
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _record(log, kind, txid, payload):
    record = {"version": 1, "seq": len(log) + 1, "kind": kind, "txid": txid,
              "previous_record_sha256": log[-1]["record_sha256"] if log else None, "payload": payload}
    record["record_sha256"] = hashlib.sha256(_encode(record)).hexdigest()
    encoded = _encode(record) + b"\n"
    if len(encoded) > _RECORD_LIMIT:
        raise LedgerIntegrityError("ledger_integrity_invalid")
    return record, encoded


def _publish_chain(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix=".audit-pair-", dir=path.parent)
    try:
        if path.exists():
            os.fchmod(descriptor, stat.S_IMODE(path.stat().st_mode) & 0o600)
        _write_all(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _commit_transaction(context, snapshot, block, *, chain_path=None, chain_bytes=None):
    context.require(context.path, write=True)
    path = context.path
    log, binding, before_ledger, records, before_chain, _ = snapshot
    operation = "ledger_append"
    if chain_path is not None:
        operation = "paired_append"
        chain_path = _storage_path(chain_path)
        if chain_path.parent != path.parent or (binding and chain_path.name != binding):
            raise LedgerIntegrityError("ledger_integrity_invalid")
        if not binding:
            before_chain, _ = _chain_snapshot(chain_path)
        binding = chain_path.name
    else:
        chain_bytes = before_chain
    next_ledger = (before_ledger or b"") + (canonical_json(block) + "\n").encode()
    if before_ledger and not before_ledger.endswith(b"\n"):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    if not _verify_records([*records, block]):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    before = {"chain": _state(before_chain) if binding else None, "ledger": _state(before_ledger)}
    after = {"chain": _state(chain_bytes) if binding else None, "ledger": _state(next_ledger)}
    txid = os.urandom(16).hex()
    if any(r["txid"] == txid for r in log):
        raise LedgerIntegrityError("ledger_integrity_invalid")
    intent, encoded = _record(log, "INTENT", txid, {
        "operation": operation, "ledger_name": path.name, "chain_name": binding,
        "before": before, "after": after,
        "previous_complete_sha256": log[-1]["record_sha256"] if log else None})
    _, completion_bytes = _record([*log, intent], "COMPLETE", txid,
        {"intent_sha256": intent["record_sha256"], "after": after})
    current_log = _bytes(_log_path(path)) or b""
    if len(current_log) + len(encoded) + len(completion_bytes) > _LOG_LIMIT:
        raise LedgerIntegrityError("ledger_integrity_invalid")
    try:
        _append_bytes(_log_path(path), encoded)
        if chain_path is not None:
            _publish_chain(chain_path, chain_bytes)
        _append_bytes(path, (canonical_json(block) + "\n").encode())
        _check_read_state(path)
        actual_chain, _ = _chain_snapshot(path.parent / binding) if binding else (None, None)
        if ({"chain": _state(actual_chain) if binding else None, "ledger": _state(_bytes(path))} != after
                or not _verify_records(_read_records(path))):
            raise LedgerIntegrityError("ledger_write_uncertain")
        _append_bytes(_log_path(path), completion_bytes)
        _transaction_snapshot(context)
    except Exception as exc:
        raise LedgerIntegrityError("ledger_write_uncertain") from exc
    return block


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, allow_nan=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _contains_forbidden(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in FORBIDDEN_FIELD_NAMES:
                return True
            if _contains_forbidden(item):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False


def _safe_decision(decision: Any) -> dict[str, Any]:
    if isinstance(decision, dict):
        if _contains_forbidden(decision):
            raise LedgerIntegrityError("forbidden_evidence_field")
        return dict(decision)
    return {"decision": str(decision)}


def _consensus_result(decision: dict[str, Any]) -> str:
    value = (
        decision.get("consensus_result")
        or decision.get("final_decision")
        or decision.get("decision")
        or "DENY"
    )
    return str(value).upper()


def _policy_hash(decision: dict[str, Any]) -> str:
    return str(decision.get("policy_hash") or decision.get("policy_registry_hash") or "UNKNOWN_POLICY_HASH")


def _node_id(decision: dict[str, Any]) -> str:
    return str(decision.get("node_id") or decision.get("gateway_id") or "gateway-1")


def _tenant_id(decision: dict[str, Any]) -> str:
    try:
        return validate_tenant_id(decision.get("tenant_id"))
    except TenantIsolationError as exc:
        raise LedgerIntegrityError(str(exc)) from exc


def block_payload(block: dict[str, Any]) -> dict[str, Any]:
    payload = dict(block)
    payload.pop("current_event_hash", None)
    payload.pop("signature", None)
    payload.pop("public_key_id", None)
    payload.pop("key_version", None)
    return payload


def compute_event_hash(block: dict[str, Any]) -> str:
    return sha256_text(canonical_json(block_payload(block)))


def ledger_sha256(records: list[dict[str, Any]]) -> str:
    return sha256_text("\n".join(canonical_json(record) for record in records))


def tenant_evidence_context(tenant_id: str) -> dict[str, str]:
    validated = validate_tenant_id(tenant_id)
    return {
        "tenant_id": validated,
        "tenant_hash": tenant_hash(validated),
        "tenant_scope": f"tenant/{validated}",
    }


def ledger_path_for(chain_path: Path | str) -> Path:
    path = Path(chain_path)
    return path.with_suffix(path.suffix + ".ledger.jsonl")


def _read_records(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise LedgerIntegrityError("ledger_integrity_invalid")
    if not path.exists():
        return []
    records = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise LedgerIntegrityError("ledger_integrity_invalid") from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            records.append(_strict_json(line))
        except Exception as exc:
            raise LedgerIntegrityError("ledger_corruption_detected") from exc
    return records


def _uncertain_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".uncertain")


def _check_read_state(path: Path) -> bool:
    try:
        return check_read_state(path)
    except AuditCompatibilityError as exc:
        raise LedgerIntegrityError(str(exc)) from exc


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _ledger_lock(path: Path, *, exclusive: bool):
    """Own a stable advisory lock; never inherit an active descriptor on fork."""
    if getattr(_LOCK_LOCAL, "active", None) is not None:
        raise LedgerIntegrityError("ledger_nested_lock_rejected")
    path = _storage_path(path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    mutex, owner_pid = _PROCESS_LOCK, os.getpid()
    descriptor, context = None, None
    mutex.acquire()
    try:
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            _check_parent(path.parent)
            # Fork must see either no descriptor or a registered one. Never
            # hold this short-lived guard while waiting for the storage lock.
            with _FORK_LOCK:
                descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                _INHERITED_LOCK_FDS.add(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("invalid lock identity")
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        except OSError as exc:
            raise LedgerIntegrityError("ledger_lock_unavailable") from exc
        context = _LockContext(path, descriptor, exclusive)
        _LOCK_LOCAL.active = context
        yield context
    finally:
        # A fork child has already closed these descriptors and reset its mutex.
        # It must neither unlock the parent's open-file description nor release
        # an inherited Python mutex if it unwinds the parent's context manager.
        if os.getpid() == owner_pid:
            if context is not None and getattr(_LOCK_LOCAL, "active", None) is context:
                _LOCK_LOCAL.active = None
            try:
                if descriptor is not None:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    # Keep close and unregister atomic with fork as well: a
                    # reused descriptor number must not be closed in the child.
                    with _FORK_LOCK:
                        try:
                            os.close(descriptor)
                        finally:
                            _INHERITED_LOCK_FDS.discard(descriptor)
            finally:
                mutex.release()


def _verify_records(records: list[dict[str, Any]]) -> bool:
    previous_hash = GENESIS_HASH
    seen_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            return False
        required = {
            "event_id",
            "previous_event_hash",
            "current_event_hash",
            "timestamp",
            "node_id",
            "policy_hash",
            "consensus_result",
        }
        if any(record.get(field) in (None, "") for field in required):
            return False
        try:
            tenant_id = validate_tenant_id(record.get("tenant_id"))
        except TenantIsolationError:
            return False
        if record.get("tenant_hash") != tenant_hash(tenant_id):
            return False
        if record["event_id"] in seen_ids:
            return False
        seen_ids.add(str(record["event_id"]))
        if record.get("previous_event_hash") != previous_hash:
            return False
        if compute_event_hash(record) != record.get("current_event_hash"):
            return False
        if not _verify_record_signature(record):
            return False
        previous_hash = str(record["current_event_hash"])
    return True


def _verify_record_signature(record: dict[str, Any]) -> bool:
    try:
        public_key = resolve_public_key(str(record.get("public_key_id", "")))
        return verify_event(
            str(record.get("current_event_hash", "")),
            str(record.get("signature", "")),
            public_key,
        )
    except Exception:
        return False


def verify_ledger(path: Path | str) -> bool:
    try:
        ledger_path = Path(path)
        with _ledger_lock(ledger_path, exclusive=False) as context:
            _transaction_snapshot(context)
            return True
    except Exception:
        return False


def assert_ledger_valid(path: Path | str) -> None:
    if not verify_ledger(path):
        raise LedgerIntegrityError("ledger_integrity_invalid")


def verified_ledger_records(path: Path | str) -> list[dict[str, Any]]:
    """Return one integrity-checked snapshot while holding the reader lock."""
    ledger_path = Path(path)
    try:
        with _ledger_lock(ledger_path, exclusive=False) as context:
            return _transaction_snapshot(context)[3]
    except LedgerIntegrityError:
        raise
    except Exception as exc:
        raise LedgerIntegrityError("ledger_integrity_invalid") from exc



def assert_legacy_append_allowed(path: Path | str) -> None:
    """Reject incompatible history before a legacy caller mutates its chain.

    This is admission only, not a reservation or a transaction across files.
    The actual ledger writer must retain its independent locked checks.
    """
    ledger_path = Path(path)
    with _ledger_lock(ledger_path, exclusive=False) as context:
        if _check_read_state(context.path):
            raise LedgerIntegrityError("ledger_journal_write_unsupported")
        _transaction_snapshot(context)


def _prepare_record(records, *, action, decision, timestamp=None, key_version=DEFAULT_KEY_VERSION):
    previous_hash = records[-1]["current_event_hash"] if records else GENESIS_HASH
    safe_decision = _safe_decision(decision)
    tenant_id = _tenant_id(safe_decision)
    expected_tenant_hash = tenant_hash(tenant_id)
    if safe_decision.get("tenant_hash") in (None, ""):
        safe_decision["tenant_hash"] = expected_tenant_hash
    if safe_decision.get("tenant_hash") != expected_tenant_hash:
        raise LedgerIntegrityError("tenant_mismatch_detected")
    consensus_evidence = safe_decision.get("consensus_evidence_bundle")
    if isinstance(consensus_evidence, dict):
        try:
            validate_consensus_tenant(consensus_evidence, tenant_id)
        except TenantIsolationError as exc:
            raise LedgerIntegrityError(str(exc)) from exc
    created_at = timestamp or datetime.utcnow().isoformat() + "Z"
    event_id = sha256_text(canonical_json({
        "action": action,
        "decision": safe_decision,
        "previous_event_hash": previous_hash,
        "tenant_hash": tenant_hash(tenant_id),
        "tenant_id": tenant_id,
        "timestamp": created_at,
    }))
    block = {
        "event_id": event_id,
        "previous_event_hash": previous_hash,
        "timestamp": created_at,
        "node_id": _node_id(safe_decision),
        "policy_hash": _policy_hash(safe_decision),
        "consensus_result": _consensus_result(safe_decision),
        "tenant_id": tenant_id,
        "tenant_hash": tenant_hash(tenant_id),
        "action": str(action),
        "decision": safe_decision,
    }
    block["current_event_hash"] = compute_event_hash(block)
    signing_key = get_signing_key(key_version)
    block["signature"] = sign_event(block["current_event_hash"], signing_key["private_key"])
    block["public_key_id"] = signing_key["public_key_id"]
    block["key_version"] = signing_key["key_version"]
    return block


def append_evidence_event(
    path: Path | str,
    *,
    action: str,
    decision: Any,
    timestamp: str | None = None,
    key_version: str = DEFAULT_KEY_VERSION,
) -> dict[str, Any]:
    ledger_path = _storage_path(path)
    try:
        with _ledger_lock(ledger_path, exclusive=True) as context:
            if _check_read_state(ledger_path):
                raise LedgerIntegrityError("ledger_journal_write_unsupported")
            snapshot = _transaction_snapshot(context)
            block = _prepare_record(snapshot[3], action=action, decision=decision,
                                    timestamp=timestamp, key_version=key_version)
            return _commit_transaction(context, snapshot, block)
    except LedgerIntegrityError:
        raise
    except Exception as exc:
        raise LedgerIntegrityError("ledger_integrity_invalid") from exc


def export_evidence_bundle(
    path: Path | str,
    export_dir: Path | str,
    *,
    provenance_context: dict[str, Any] | None = None,
    provenance_authority: RuntimeProvenanceAuthority | None = None,
) -> dict[str, Any]:
    ledger_path = Path(path)
    records = verified_ledger_records(ledger_path)
    try:
        tenant_id = validate_records_single_tenant(records)
    except TenantIsolationError as exc:
        raise LedgerIntegrityError(str(exc)) from exc
    tenant_context = tenant_evidence_context(tenant_id)
    out_dir = Path(export_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_jsonl = "\n".join(canonical_json(record) for record in records)
    if audit_jsonl:
        audit_jsonl += "\n"
    signatures = {
        record["event_id"]: {
            "current_event_hash": record["current_event_hash"],
            "signature": record["signature"],
            "public_key_id": record["public_key_id"],
            "key_version": record["key_version"],
        }
        for record in records
    }
    consensus_evidence = {
        record["event_id"]: record["decision"].get("consensus_evidence_bundle")
        for record in records
        if isinstance(record.get("decision"), dict) and record["decision"].get("consensus_evidence_bundle")
    }
    if provenance_authority is not None:
        authority = assert_runtime_provenance_authority(provenance_authority)
        provenance_context = authority.context_dict()
    if not isinstance(provenance_context, dict):
        raise LedgerIntegrityError("provenance_context_missing")
    release_summary = validate_release_manifest(expected_provenance_context=provenance_context)
    deployment_provenance = load_release_manifest()
    if deployment_provenance.get("tenant_id") != tenant_id:
        raise LedgerIntegrityError("tenant_deployment_provenance_mismatch")
    if release_summary["provenance_context"] != provenance_context:
        raise LedgerIntegrityError("provenance_context_mismatch")
    if tenant_context["tenant_hash"] != tenant_hash(str(deployment_provenance.get("tenant_id", ""))):
        raise LedgerIntegrityError("tenant_deployment_provenance_mismatch")
    ledger_hash = ledger_sha256(records)
    components = component_hashes(
        audit_jsonl=audit_jsonl,
        ledger_sha256=ledger_hash,
        signatures=signatures,
        consensus_evidence=consensus_evidence,
        deployment_provenance=deployment_provenance,
        tenant_context=tenant_context,
    )
    imprint = message_imprint(components)
    proof = create_timestamp_proof(imprint)
    verification = verify_timestamp_proof(proof, imprint)
    if not verification.get("valid"):
        raise LedgerIntegrityError("timestamp_verification_failed")
    (out_dir / "audit.jsonl").write_text(audit_jsonl, encoding="utf-8")
    (out_dir / "ledger.sha256").write_text(ledger_hash + "\n", encoding="utf-8")
    (out_dir / "signatures.json").write_text(canonical_json(signatures), encoding="utf-8")
    (out_dir / "consensus_evidence.json").write_text(canonical_json(consensus_evidence), encoding="utf-8")
    (out_dir / "governance_release.json").write_text(canonical_json(deployment_provenance), encoding="utf-8")
    (out_dir / "tenant_context.json").write_text(canonical_json(tenant_context), encoding="utf-8")
    write_timestamp_files(out_dir, proof, verification)
    return {
        "audit.jsonl": audit_jsonl,
        "ledger.sha256": ledger_hash,
        "signatures.json": signatures,
        "consensus_evidence.json": consensus_evidence,
        "governance_release.json": deployment_provenance,
        "tenant_context.json": tenant_context,
        "tenant_id": tenant_context["tenant_id"],
        "tenant_hash": tenant_context["tenant_hash"],
        "rfc3161_timestamp.tsr": proof["token"],
        "timestamp_verification.json": verification,
        "tsa_certificate_chain.pem": proof.get("tsa_certificate_chain_pem", ""),
        "tsa_policy_oid.txt": str(proof.get("policy_oid", "")),
    }
