"""Dormant transactional output store. No installed authority source or signer.

Trusted composition must supply independently authenticated live adoption,
currentness and source observations. Request fields cannot configure these ports.
Fixture ports in tests are not operational authority. SQLite commits output and
consumption together; external signing and external publication are NOT atomic
with SQLite. No file publication, CLI, environment defaults or Gateway hook.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from governance.release_owner_contract import (
    MAX_BYTES, ContractDenied, ReleaseTrustContext, _hash, _is_hash, _need, _parse, _time,
    inspect_release_owner_contract,
)
from security.runtime_artifact_provenance import canonical_bytes

VERSION = "usbay.release_transaction_store.v1"
STATE_FIELDS = {"tenant_id", "target_id", "resource_id", "source_commit", "source_tree",
                "policy_bundle_hash", "predecessor_hash", "epoch", "sequence", "adoption_reference"}
SCHEMA = {
    "contract": "CREATE TABLE contract (version TEXT NOT NULL)",
    "state": "CREATE TABLE state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), value BLOB NOT NULL)",
    "outputs": "CREATE TABLE outputs (transaction_id TEXT PRIMARY KEY, request_hash TEXT NOT NULL UNIQUE, output BLOB NOT NULL, receipt BLOB NOT NULL)",
    "nonces": "CREATE TABLE nonces (tenant TEXT NOT NULL, issuer TEXT NOT NULL, nonce TEXT NOT NULL, transaction_id TEXT NOT NULL, PRIMARY KEY(tenant, issuer, nonce))",
    "budgets": "CREATE TABLE budgets (grant_hash TEXT PRIMARY KEY, transaction_id TEXT NOT NULL)",
}
SCALAR_CORE_FIELDS = {"release_id", "git_commit", "policy_bundle_hash", "deployment_timestamp",
               "activating_node_id", "tenant_id", "previous_release_hash"}
CORE_FIELDS = SCALAR_CORE_FIELDS | {"release_history"}
RECEIPT_FIELDS = {"schema", "transaction_id", "request_hash", "grant_hash", "root_hash", "policy_hash",
    "status_hash", "adoption_reference", "fence_hash", "authority_fence_reference", "output_digest",
    "release_core_hash", "nonce_reference", "issuer_reference"}
WRITER_DENIAL_CODES = frozenset({
    "STATE_INVALID", "STORE_PATH_UNSAFE", "STORE_INVALID", "STORE_SCHEMA_INVALID", "STORE_VERSION_INVALID",
    "WRITER_AUTHORITY_UNAVAILABLE", "RECORDS_INVALID", "RELEASE_CORE_INVALID", "ADOPTION_MISMATCH",
    "AUTHORITY_FENCE_UNAVAILABLE", "AUTHORITY_FENCE_INVALID", "AUTHORITY_FENCE_EXPIRED", "CLOCK_INVALID",
    "AUTHORITY_SOURCE_UNAVAILABLE", "CURRENT_HEAD_MISMATCH", "RELEASE_CONTRACT_DENIED", "VERIFICATION_EXPIRED",
    "SIGNER_TOOL_MISMATCH", "SOURCE_PREDECESSOR_CAS_MISMATCH", "SOURCE_OBSERVATION_MISMATCH",
    "RELEASE_CORE_MISMATCH", "RELEASE_TIME_INVALID", "NONCE_CONSUMED", "BUDGET_CONSUMED",
    "SIGNER_UNAVAILABLE", "SIGNER_OUTPUT_INVALID", "COMMIT_FENCE_MISMATCH",
    "RELEASE_HISTORY_INVALID", "PREDECESSOR_SIGNATURE_INVALID",
})


@dataclass(frozen=True)
class AuthorityObservation:
    trust: ReleaseTrustContext
    adoption_reference: str
    source_commit: str
    source_tree: str
    policy_bundle_hash: str


@dataclass(frozen=True)
class HeldAuthorityFence:
    request_hash: str
    state_hash: str
    adoption_reference: str
    reference: str
    valid_until: str


class ReleaseAuthoritySource(ABC):
    """Privileged port: verify adoption, live revocations and source externally.

    Implementations must authenticate current state independently of the caller,
    including rollback protection. No operational implementation is installed.
    """
    @abstractmethod
    def observe(self, request_hash: str, now: datetime, state_hash: str) -> AuthorityObservation:
        raise NotImplementedError

    @abstractmethod
    def hold_fence(self, request_hash: str, state_hash: str):
        """Context manager: serialize applicable authority changes through COMMIT.

        Read-only observations alone do not fence concurrent revocation. The
        source must hold its authenticated fence until this context exits.
        No such operational provider is installed by this module.
        """
        raise NotImplementedError


class ReleaseSigner(ABC):
    """Explicit trusted signer port, never selected by request/environment."""
    @property
    @abstractmethod
    def tool_id(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def sign(self, canonical_core: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    def verify(self, canonical_core: bytes, signature: str) -> None:
        """Raise on failed cryptographic verification; no authority from HMAC."""
        raise NotImplementedError


@dataclass(frozen=True)
class WriteResult:
    outcome: str
    reason: str
    transaction_id: str | None = None
    signer_attempted: bool = False
    output_digest: str | None = None


def _strict_json(raw):
    # Reuse bounded duplicate/nonfinite/float rejection, without envelope semantics.
    return _parse(raw)


def _state(value):
    _need(type(value) is dict and set(value) == STATE_FIELDS, "STATE_INVALID")
    _need(all(type(value[k]) is str and value[k] and len(value[k]) <= 256
              for k in STATE_FIELDS - {"sequence"}), "STATE_INVALID")
    _need(type(value["sequence"]) is int and value["sequence"] >= 0, "STATE_INVALID")
    _need(all(_is_hash(value[k]) for k in ("policy_bundle_hash", "predecessor_hash", "adoption_reference")),
          "STATE_INVALID")
    _need(all(re.fullmatch(r"[0-9a-f]{40}", value[k]) for k in ("source_commit", "source_tree")),
          "STATE_INVALID")
    return value


def _verify_history(core, signer):
    """Verify supplied history without inventing a predecessor or modifying core.

    The complete history is inside the authorized core hash and HMAC payload.
    Legacy GENESIS may occur only at the historical origin, never as a default
    for the current operation. The trusted adoption source must establish that
    this pinned historical origin is applicable; signatures alone cannot.
    """
    history = core["release_history"]
    _need(type(history) is list and 1 <= len(history) <= 32, "RELEASE_HISTORY_INVALID")
    previous_hash = "GENESIS"
    previous_time = None
    for index, manifest in enumerate(history):
        _need(type(manifest) is dict and set(manifest) in
              (SCALAR_CORE_FIELDS | {"release_signature"}, CORE_FIELDS | {"release_signature"}),
              "RELEASE_HISTORY_INVALID")
        _need(all(type(manifest[k]) is str and 0 < len(manifest[k]) <= 256 for k in SCALAR_CORE_FIELDS),
              "RELEASE_HISTORY_INVALID")
        _need(manifest["tenant_id"] == core["tenant_id"]
            and manifest["previous_release_hash"] == previous_hash
            and manifest.get("release_history", []) == history[:index], "RELEASE_HISTORY_INVALID")
        observed_time = _time(manifest["deployment_timestamp"])
        _need((previous_time is None or previous_time <= observed_time)
            and observed_time <= _time(core["deployment_timestamp"]), "RELEASE_HISTORY_INVALID")
        signature = manifest["release_signature"]
        payload = dict(manifest)
        del payload["release_signature"]
        _need(type(signature) is str and re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", signature) is not None,
              "PREDECESSOR_SIGNATURE_INVALID")
        try:
            verified = signer.verify(canonical_bytes(payload), signature)
        except Exception:
            raise ContractDenied("PREDECESSOR_SIGNATURE_INVALID") from None
        _need(verified is None, "PREDECESSOR_SIGNATURE_INVALID")
        previous_hash = _hash(payload).split(":", 1)[1]
        previous_time = observed_time
    _need(core["previous_release_hash"] == previous_hash, "RELEASE_HISTORY_INVALID")


class ReleaseTransactionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()

    @classmethod
    def provision(cls, path: str | Path, initial_state: dict):
        """Explicit task/operator operation; never called by writer or reconcile.

        This creates storage, not trusted adoption or a grant. The parent must
        already be a private operator-owned directory. No repair/replacement.
        """
        initial = canonical_bytes(_state(dict(initial_state)))
        store = cls(path)
        store._parent()
        fd = os.open(store.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with store._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for ddl in SCHEMA.values():
                connection.execute(ddl)
            connection.execute("INSERT INTO contract VALUES (?)", (VERSION,))
            connection.execute("INSERT INTO state VALUES (1,?)", (initial,))
            connection.commit()
        return store

    def _parent(self):
        parent = self.path.parent
        _need(parent.resolve() == parent, "STORE_PATH_UNSAFE")
        info = parent.stat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
              and stat.S_IMODE(info.st_mode) == 0o700, "STORE_PATH_UNSAFE")

    @contextmanager
    def _connection(self):
        self._parent()
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        connection = None
        try:
            before = os.fstat(fd)
            _need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                  and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1, "STORE_PATH_UNSAFE")
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                timeout=0, isolation_level=None)
            after = self.path.lstat()
            _need((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                  and not stat.S_ISLNK(after.st_mode), "STORE_PATH_UNSAFE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            yield connection
        finally:
            if connection is not None:
                connection.close()
            os.close(fd)

    def _read_state(self, connection):
        _need(connection.execute("PRAGMA quick_check").fetchall() == [("ok",)], "STORE_INVALID")
        actual = dict(connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        _need(actual == SCHEMA, "STORE_SCHEMA_INVALID")
        _need(connection.execute("SELECT version FROM contract").fetchall() == [(VERSION,)], "STORE_VERSION_INVALID")
        rows = connection.execute("SELECT singleton,value FROM state").fetchall()
        _need(len(rows) == 1 and rows[0][0] == 1 and type(rows[0][1]) is bytes, "STATE_INVALID")
        return _state(_strict_json(rows[0][1]))

    def state(self):
        with self._connection() as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            value = self._read_state(connection)
            connection.rollback()
            return value

    def reconcile(self, transaction_id: str) -> WriteResult:
        """Query-only; absence stays UNKNOWN, never permission to retry signing.

        SQLite may perform its normal hot-journal rollback on opening a crashed
        store. This does not initialize, issue, sign or repair authority state.
        """
        try:
            _need(_is_hash(transaction_id), "TRANSACTION_ID_INVALID")
            with self._connection() as connection:
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
                self._read_state(connection)
                row = connection.execute("SELECT request_hash,output,receipt FROM outputs WHERE transaction_id=?",
                                         (transaction_id,)).fetchone()
                if row is None:
                    return WriteResult("UNKNOWN", "TRANSACTION_NOT_OBSERVED", transaction_id)
                request_hash, raw_output, raw_receipt = row
                receipt = _strict_json(raw_receipt)
                _need(set(receipt) == RECEIPT_FIELDS and receipt["schema"] == VERSION + ".receipt"
                    and all(_is_hash(receipt[k]) for k in RECEIPT_FIELDS - {"schema"}), "RECEIPT_INVALID")
                _need(receipt["transaction_id"] == transaction_id and receipt["request_hash"] == request_hash
                    and transaction_id == _hash({"domain": VERSION, "request_hash": request_hash})
                    and receipt["output_digest"] == "sha256:" + hashlib.sha256(raw_output).hexdigest(), "RECEIPT_INVALID")
                output = _strict_json(raw_output)
                _need(set(output) == CORE_FIELDS | {"release_signature"}, "RECEIPT_INVALID")
                signature = output.pop("release_signature")
                _need(type(signature) is str and re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", signature) is not None
                    and _hash(output) == receipt["release_core_hash"], "RECEIPT_INVALID")
                nonces = connection.execute("SELECT tenant,issuer,nonce FROM nonces WHERE transaction_id=?", (transaction_id,)).fetchall()
                budgets = connection.execute("SELECT grant_hash FROM budgets WHERE transaction_id=?", (transaction_id,)).fetchall()
                _need(len(nonces) == 1 and nonces[0][0] == output["tenant_id"]
                    and nonces[0][2] == receipt["nonce_reference"]
                    and _hash({"issuer_id": nonces[0][1]}) == receipt["issuer_reference"]
                    and budgets == [(receipt["grant_hash"],)], "CONSUMPTION_INVALID")
                return WriteResult("COMMITTED", "STORED_OUTPUT_CONFIRMED", transaction_id,
                                   output_digest=receipt["output_digest"])
        except Exception:
            return WriteResult("UNKNOWN", "RECONCILIATION_UNAVAILABLE",
                               transaction_id if _is_hash(transaction_id) else None)


class ReleaseTransactionWriter:
    def __init__(self, store: ReleaseTransactionStore, *, authority_source: ReleaseAuthoritySource | None = None,
                 signer: ReleaseSigner | None = None, adoption_reference: str | None = None, clock=None):
        self.store = store
        self.authority_source = authority_source
        self.signer = signer
        self.adoption_reference = adoption_reference
        self.clock = clock

    def _checkpoint(self, stage):
        """No-op test fault boundary, never called from request-selected code."""

    def _commit(self, connection):
        connection.commit()

    def write(self, records: dict[str, bytes], core: dict) -> WriteResult:
        attempted = False
        committing = False
        transaction_id = None
        try:
            _need(isinstance(self.authority_source, ReleaseAuthoritySource) and isinstance(self.signer, ReleaseSigner)
                and _is_hash(self.adoption_reference) and callable(self.clock), "WRITER_AUTHORITY_UNAVAILABLE")
            _need(type(records) is dict and all(type(k) is str and type(v) is bytes for k,v in records.items()),
                  "RECORDS_INVALID")
            records = dict(records)
            request = _parse(records["request"])
            request_hash = _hash(request)
            transaction_id = _hash({"domain": VERSION, "request_hash": request_hash})
            _need(type(core) is dict and set(core) == CORE_FIELDS, "RELEASE_CORE_INVALID")
            raw_core = canonical_bytes(core)
            core = _strict_json(raw_core)  # immutable private copy of caller data
            with self.store._connection() as connection, ExitStack() as fences:
                connection.execute("BEGIN IMMEDIATE")
                state = self.store._read_state(connection)
                _need(state["adoption_reference"] == self.adoption_reference, "ADOPTION_MISMATCH")
                state_hash = _hash(state)
                try:
                    fence = fences.enter_context(self.authority_source.hold_fence(request_hash, state_hash))
                except Exception:
                    raise ContractDenied("AUTHORITY_FENCE_UNAVAILABLE") from None
                _need(type(fence) is HeldAuthorityFence and fence.request_hash == request_hash
                    and fence.state_hash == state_hash and fence.adoption_reference == self.adoption_reference
                    and _is_hash(fence.reference), "AUTHORITY_FENCE_INVALID")

                def current():
                    try:
                        now = self.clock()
                    except Exception:
                        raise ContractDenied("CLOCK_INVALID") from None
                    _need(type(now) is datetime and now.tzinfo is timezone.utc, "CLOCK_INVALID")
                    _need(now < _time(fence.valid_until), "AUTHORITY_FENCE_EXPIRED")
                    try:
                        observation = self.authority_source.observe(request_hash, now, state_hash)
                    except Exception:
                        raise ContractDenied("AUTHORITY_SOURCE_UNAVAILABLE") from None
                    _need(type(observation) is AuthorityObservation
                        and observation.adoption_reference == self.adoption_reference, "ADOPTION_MISMATCH")
                    trust = observation.trust
                    _need(type(trust) is ReleaseTrustContext and trust.head_hash == state_hash
                        and trust.epoch == state["epoch"] and trust.sequence == state["sequence"], "CURRENT_HEAD_MISMATCH")
                    inspection = inspect_release_owner_contract(records, trust=trust, now=now)
                    _need(inspection.bindings_valid and inspection.reason == "RELEASE_WRITER_UNAVAILABLE"
                        and inspection.decision == "DENY" and not inspection.issuance_authorized,
                        "RELEASE_CONTRACT_DENIED")
                    _need(_time(inspection.verification_valid_until) > now, "VERIFICATION_EXPIRED")
                    scope = request["payload"]["scope"]
                    _need(scope["tool_id"] == self.signer.tool_id, "SIGNER_TOOL_MISMATCH")
                    _need(all(scope[k] == state[k] for k in ("tenant_id", "target_id", "resource_id",
                        "source_commit", "source_tree", "policy_bundle_hash", "predecessor_hash")), "SOURCE_PREDECESSOR_CAS_MISMATCH")
                    _need(all(getattr(observation,k) == state[k] for k in
                        ("source_commit", "source_tree", "policy_bundle_hash")), "SOURCE_OBSERVATION_MISMATCH")
                    _need(_hash(core) == scope["release_core_hash"] and core["git_commit"] == scope["source_commit"]
                        and core["tenant_id"] == scope["tenant_id"]
                        and core["policy_bundle_hash"] == scope["policy_bundle_hash"].split(":",1)[1]
                        and core["previous_release_hash"] == scope["predecessor_hash"].split(":",1)[1], "RELEASE_CORE_MISMATCH")
                    _need(all(type(core[k]) is str and 0 < len(core[k]) <= 256 for k in SCALAR_CORE_FIELDS), "RELEASE_CORE_INVALID")
                    # The stored signed output must remain readable by the same
                    # bounded parser used by reconciliation, including signature.
                    _need(len(canonical_bytes(dict(core,release_signature="hmac-sha256:"+"0"*64))) <= MAX_BYTES,
                          "RELEASE_CORE_INVALID")
                    _need(_time(request["payload"]["issued_at"]) <= _time(core["deployment_timestamp"]) <= now,
                          "RELEASE_TIME_INVALID")
                    return scope, trust

                scope, trust = current()
                issuer = request["payload"]["issuer_id"]
                nonce = request["payload"]["nonce"]
                nonce_reference = _hash({"tenant_id": scope["tenant_id"], "issuer_id": issuer, "nonce": nonce})
                grant_hash = request["payload"]["issuer_grant_hash"]
                _need(connection.execute("SELECT 1 FROM nonces WHERE tenant=? AND issuer=? AND nonce=?",
                    (scope["tenant_id"],issuer,nonce_reference)).fetchone() is None, "NONCE_CONSUMED")
                _need(connection.execute("SELECT 1 FROM budgets WHERE grant_hash=?", (grant_hash,)).fetchone() is None,
                      "BUDGET_CONSUMED")
                self._checkpoint("before_sign")
                _verify_history(core, self.signer)
                current()  # after any admission/fault boundary, before the effect
                attempted = True
                try:
                    signature = self.signer.sign(raw_core)
                except Exception:
                    raise ContractDenied("SIGNER_UNAVAILABLE") from None
                _need(type(signature) is str and re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", signature) is not None,
                      "SIGNER_OUTPUT_INVALID")
                try:
                    verified = self.signer.verify(raw_core, signature)
                except Exception:
                    raise ContractDenied("SIGNER_OUTPUT_INVALID") from None
                _need(verified is None, "SIGNER_OUTPUT_INVALID")
                self._checkpoint("after_sign")
                output = canonical_bytes(dict(core, release_signature=signature))
                output_digest = "sha256:" + hashlib.sha256(output).hexdigest()
                receipt = canonical_bytes({"schema": VERSION + ".receipt", "transaction_id": transaction_id,
                    "request_hash": request_hash, "grant_hash": grant_hash, "root_hash": trust.root_hash,
                    "policy_hash": trust.review_policy_hash, "status_hash": trust.status_hash,
                    "adoption_reference": self.adoption_reference, "fence_hash": state_hash,
                    "authority_fence_reference": fence.reference,
                    "nonce_reference": nonce_reference, "issuer_reference": _hash({"issuer_id":issuer}),
                    "output_digest": output_digest, "release_core_hash": _hash(core)})
                connection.execute("INSERT INTO outputs VALUES (?,?,?,?)", (transaction_id,request_hash,output,receipt))
                connection.execute("INSERT INTO nonces VALUES (?,?,?,?)", (scope["tenant_id"],issuer,nonce_reference,transaction_id))
                connection.execute("INSERT INTO budgets VALUES (?,?)", (grant_hash,transaction_id))
                new_state = dict(state, predecessor_hash=_hash(core), sequence=state["sequence"]+1)
                cursor = connection.execute("UPDATE state SET value=? WHERE singleton=1 AND value=?",
                                            (canonical_bytes(new_state),canonical_bytes(state)))
                _need(cursor.rowcount == 1, "COMMIT_FENCE_MISMATCH")
                self._checkpoint("before_commit")
                current()  # committed state remains locked; recheck source/authority after signing
                committing = True
                self._commit(connection)
                self._checkpoint("after_commit")
                return WriteResult("COMMITTED", "OUTPUT_AND_CONSUMPTION_COMMITTED", transaction_id, attempted, output_digest)
        except Exception as error:
            if committing:
                return WriteResult("UNKNOWN", "COMMIT_OUTCOME_UNKNOWN", transaction_id, attempted)
            reason = str(error) if type(error) is ContractDenied and str(error) in WRITER_DENIAL_CODES else "TRANSACTION_UNAVAILABLE"
            return WriteResult("DENIED", reason, transaction_id, attempted)
