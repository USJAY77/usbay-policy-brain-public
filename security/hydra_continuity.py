"""Synthetic continuity authority and live append-only witness.

Neither backend enrolls humans or recovers a witness. A new witness process is
stopped until explicit synthetic genesis provisioning binds its fresh challenge.
There is deliberately no open/recover/reset API for an existing witness.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from urllib import error, request

from security.hydra_continuity_contracts import (
    VERSION, ContinuityDenied, binding, canonical, check_scope, decode, digest, exact,
    integer, require, scope, sign, timestamp, trust, verify, verify_mandate, check_issuer_key,
)

ZERO = "0" * 64
CONTROL_FIELDS = {"schema", "action", "boot_challenge", "authorization_id", "issued_at", "expires_at",
                  "scope", "data"}


def control_payload(config, action, challenge, data, now=None):
    """Unsigned control draft; only external fixture/human tooling may sign it."""
    now = time.time() if now is None else now
    return dict(schema=VERSION, action=action, boot_challenge=challenge,
                authorization_id=secrets.token_hex(32), issued_at=now, expires_at=now + 30,
                scope=scope(config), data=data)


def check_control(packet, config, action, challenge, now):
    value = verify(packet, config["control_public_key"])
    exact(value, CONTROL_FIELDS)
    require(value["schema"] == VERSION and value["action"] == action and
            value["boot_challenge"] == challenge)
    exact(value["scope"], scope(config)); check_scope(value["scope"], config)
    require(type(value["authorization_id"]) is str and len(value["authorization_id"]) == 64)
    timestamp(value["issued_at"]); timestamp(value["expires_at"])
    require(value["issued_at"] <= now < value["expires_at"] <= value["issued_at"] + 30)
    return value["data"]


def validate_recovery_contract(packet, config, challenge, now):
    """Verify a synthetic review contract; never reopen, reset or recover stores.

    The witness's independent recovery protocol is deliberately unavailable.
    A valid signature on this draft does not establish current history.
    No admission/provisioning handler accepts the RECOVER action.
    """
    data = check_control(packet, trust(config), "RECOVER", challenge, now)
    exact(data, {"expected_head", "expected_sequence", "target_generation", "target_epoch",
                 "revocation_digest", "preservation_policy", "recovery_mode"})
    for key in ("expected_head", "revocation_digest"):
        require(type(data[key]) is str and len(data[key]) == 64 and all(ch in "0123456789abcdef" for ch in data[key]))
    integer(data["expected_sequence"])
    integer(data["target_generation"], config["generation"])
    integer(data["target_epoch"], config["authority_epoch"])
    require(data["preservation_policy"] == "PRESERVE_CONSUMPTION_AND_REVOCATION" and
            data["recovery_mode"] == "STOPPED_RECONCILIATION_ONLY")
    from types import MappingProxyType
    return MappingProxyType(data)


class Log:
    """Small append-only SQLite event log; creation is never an admission step."""
    SCHEMA = "CREATE TABLE events (sequence INTEGER PRIMARY KEY, previous TEXT NOT NULL, event TEXT NOT NULL, head TEXT NOT NULL)"
    def __init__(self, path):
        self.path = Path(path)

    def create(self, genesis):
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        conn = sqlite3.connect(self.path, isolation_level=None)
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(self.SCHEMA)
            self.append(conn, [], genesis)
            conn.commit()
        finally:
            conn.close()

    def open(self):
        require(self.path.is_file() and not self.path.is_symlink())
        conn = sqlite3.connect(self.path.resolve().as_uri() + "?mode=rw", uri=True,
                               timeout=1, isolation_level=None)
        try:
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("BEGIN IMMEDIATE")
            require(conn.execute("SELECT name,type,sql FROM sqlite_master").fetchall() == [("events", "table", self.SCHEMA)])
            require([row[1:3] for row in conn.execute("PRAGMA table_info(events)")] ==
                    [("sequence", "INTEGER"), ("previous", "TEXT"), ("event", "TEXT"), ("head", "TEXT")])
            return conn
        except Exception:
            conn.close(); raise

    @staticmethod
    def rows(conn):
        rows = []
        for sequence, previous, raw, head in conn.execute("SELECT * FROM events ORDER BY sequence"):
            integer(sequence)
            require(sequence == len(rows) and previous == (rows[-1]["head"] if rows else ZERO))
            event = decode(raw)
            require(canonical(event).decode() == raw and
                    digest(dict(sequence=sequence, previous=previous, event=event)) == head)
            rows.append(dict(sequence=sequence, previous=previous, event=event, head=head))
        require(bool(rows))
        return rows

    @staticmethod
    def append(conn, rows, event):
        seq = len(rows); prev = rows[-1]["head"] if rows else ZERO
        head = digest(dict(sequence=seq, previous=prev, event=event))
        conn.execute("INSERT INTO events VALUES (?,?,?,?)", (seq, prev, canonical(event).decode(), head))
        return seq, head


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ContinuityDenied()


def exchange(url, value):
    # Only trusted loopback reference URLs are admitted by trust(). No proxies.
    req = request.Request(url, data=canonical(value), headers={"Content-Type": "application/json"})
    try:
        response = request.build_opener(request.ProxyHandler({}), NoRedirect()).open(req, timeout=5)
    except error.HTTPError as response:
        raw = response.read(1048577)
        require(len(raw) <= 1048576)
        if response.code != 403:
            raise ContinuityDenied() from None
        denied = decode(raw)
        exact(denied, {"denied"})
        require(type(denied["denied"]) is str)
        raise ContinuityDenied(denied["denied"])
    with response:
        raw = response.read(1048577)
        require(len(raw) <= 1048576)
        return decode(raw)


def witness_query(config, *, target=None):
    query = dict(operation="observe", scope=scope(config), challenge=secrets.token_hex(32), target=target)
    started = time.monotonic(); now = time.time()
    packet = exchange(config["witness_url"], query)
    value = verify(packet, config["witness_public_key"])
    exact(value, {"schema", "kind", "scope", "challenge", "request_hash", "sequence", "head",
                  "witness_head", "target", "issued_at", "expires_at"})
    require(value["schema"] == VERSION and value["kind"] == "witness_current")
    exact(value["scope"], scope(config)); check_scope(value["scope"], config)
    require(value["challenge"] == query["challenge"] and value["request_hash"] == digest(query)
            and value["target"] == target)
    integer(value["sequence"])
    for key in ("head", "witness_head"):
        require(type(value[key]) is str and len(value[key]) == 64 and all(c in "0123456789abcdef" for c in value[key]))
    timestamp(value["issued_at"]); timestamp(value["expires_at"])
    current = max(time.time(), now + time.monotonic() - started)
    require(value["issued_at"] <= current < value["expires_at"] <= value["issued_at"] + 5)
    return value


class Witness:
    def __init__(self, path, config, private_key):
        self.config = trust(config); self.log = Log(path); self.key = private_key
        self.boot_challenge = secrets.token_hex(32)
        self.tip = None; self.stopped = True; self.provision_attempted = False; self.lock = threading.RLock()

    def provision(self, authorization):
        with self.lock:
            require(not self.provision_attempted and self.tip is None and not self.log.path.exists())
            data = check_control(authorization, self.config, "PROVISION_WITNESS", self.boot_challenge, time.time())
            exact(data, {"initial_service_head"})
            require(type(data["initial_service_head"]) is str and len(data["initial_service_head"]) == 64)
            self.provision_attempted = True
            self.log.create(dict(kind="WITNESS_GENESIS", authorization=authorization))
            conn = self.log.open()
            try: self.tip = self.log.rows(conn)[-1]["head"]
            finally: conn.close()
            self.stopped = False

    def _read(self):
        require(not self.stopped and self.tip is not None)
        conn = None
        try:
            conn = self.log.open(); rows = self.log.rows(conn)
            require(rows[-1]["head"] == self.tip)
            first = rows[0]["event"]
            exact(first, {"kind", "authorization"}); require(first["kind"] == "WITNESS_GENESIS")
            grant = verify(first["authorization"], self.config["control_public_key"])
            exact(grant, CONTROL_FIELDS); check_scope(grant["scope"], self.config)
            require(grant["action"] == "PROVISION_WITNESS" and grant["boot_challenge"] == self.boot_challenge)
            sequence, head = 0, grant["data"]["initial_service_head"]
            history = {0: head}
            for row in rows[1:]:
                event = row["event"]
                exact(event, {"kind", "advance"}); require(event["kind"] == "ADVANCE")
                value = verify(event["advance"], self.config["service_public_key"])
                exact(value, {"schema", "kind", "scope", "previous", "sequence", "head"})
                exact(value["scope"], scope(self.config)); check_scope(value["scope"], self.config)
                require(value["schema"] == VERSION and value["kind"] == "service_commit")
                integer(value["sequence"], 1)
                require(value["previous"] == head and value["sequence"] == sequence + 1)
                sequence, head = value["sequence"], value["head"]
                history[sequence] = head
            return conn, rows, sequence, head, history
        except Exception:
            if conn: conn.close()
            self.stopped = True
            raise ContinuityDenied() from None

    def handle(self, value):
        with self.lock:
            if value.get("operation") == "advance":
                exact(value, {"operation", "advance"})
                advance = verify(value["advance"], self.config["service_public_key"])
                exact(advance, {"schema", "kind", "scope", "previous", "sequence", "head"})
                exact(advance["scope"], scope(self.config)); check_scope(advance["scope"], self.config)
                integer(advance["sequence"], 1)
                require(advance["schema"] == VERSION and advance["kind"] == "service_commit")
                conn, rows, seq, head, _ = self._read()
                try:
                    require(advance["sequence"] == seq + 1 and advance["previous"] == head)
                    _, tip = self.log.append(conn, rows, dict(kind="ADVANCE", advance=value["advance"]))
                    conn.commit()
                    self.tip = tip
                except Exception:
                    self.stopped = True
                    raise ContinuityDenied() from None
                finally: conn.close()
                return {"committed": True}
            exact(value, {"operation", "scope", "challenge", "target"})
            require(value["operation"] == "observe" and type(value["challenge"]) is str and len(value["challenge"]) == 64)
            exact(value["scope"], scope(self.config)); check_scope(value["scope"], self.config)
            conn, rows, seq, head, history = self._read()
            try:
                if value["target"] is not None:
                    exact(value["target"], {"sequence", "head"})
                    integer(value["target"]["sequence"])
                    require(history.get(value["target"]["sequence"]) == value["target"]["head"])
                now = time.time()
                return sign(self.key, dict(schema=VERSION, kind="witness_current", scope=scope(self.config),
                    challenge=value["challenge"], request_hash=digest(value), sequence=seq, head=head,
                    witness_head=rows[-1]["head"], target=value["target"], issued_at=now, expires_at=now+5))
            finally: conn.close()


class Authority:
    def __init__(self, path, config, private_key):
        self.config = trust(config); self.log = Log(path); self.key = private_key
        self.boot_challenge = secrets.token_hex(32); self.stopped = False; self.provision_attempted = False
        self.lock = threading.RLock()

    def provision(self, authorization):
        with self.lock:
            require(not self.provision_attempted and not self.stopped)
            data = check_control(authorization, self.config, "PROVISION_SERVICE", self.boot_challenge, time.time())
            exact(data, set())
            self.provision_attempted = True
            self.log.create(dict(kind="SERVICE_GENESIS", authorization=authorization))

    def _read(self):
        require(not self.stopped)
        conn = None
        try:
            conn = self.log.open(); rows = self.log.rows(conn)
            first = rows[0]["event"]
            exact(first, {"kind", "authorization"}); require(first["kind"] == "SERVICE_GENESIS")
            grant = verify(first["authorization"], self.config["control_public_key"])
            exact(grant, CONTROL_FIELDS); exact(grant["scope"], scope(self.config)); check_scope(grant["scope"], self.config)
            require(grant["action"] == "PROVISION_SERVICE")
            current = witness_query(self.config)
            require(current["sequence"] == rows[-1]["sequence"] and current["head"] == rows[-1]["head"])
            issuers = {}; spent_nonce = set(); spent_id = set(); challenges = set()
            for row in rows[1:]:
                event = row["event"]
                if event.get("kind") == "ISSUER":
                    exact(event, {"kind", "authorization"})
                    payload = verify(event["authorization"], self.config["control_public_key"])
                    exact(payload, CONTROL_FIELDS); check_scope(payload["scope"], self.config)
                    data = payload["data"]
                    exact(data, {"previous", "sequence", "record"})
                    require(payload["action"] == "SET_ISSUER" and data["previous"] == row["previous"]
                            and data["sequence"] == row["sequence"])
                    record = data["record"]; ref = record["authority_reference"]
                    require(not issuers.get(ref, {}).get("revoked") or record.get("revoked"))
                    issuers[ref] = record
                else:
                    exact(event, {"kind", "binding", "challenge", "issuer_hash", "reserved_at"})
                    require(event["kind"] == "RESERVATION")
                    item = event["binding"]
                    require(item["nonce_hash"] not in spent_nonce and item["authorization_hash"] not in spent_id
                            and event["challenge"] not in challenges)
                    spent_nonce.add(item["nonce_hash"]); spent_id.add(item["authorization_hash"])
                    challenges.add(event["challenge"])
            return conn, rows, issuers, spent_nonce, spent_id, challenges
        except Exception:
            if conn: conn.close()
            self.stopped = True
            raise ContinuityDenied() from None

    def _commit(self, conn, rows, event):
        try:
            sequence, head = self.log.append(conn, rows, event)
            conn.commit()  # Consumption is durable before witness publication/receipt.
            advance = sign(self.key, dict(schema=VERSION, kind="service_commit", scope=scope(self.config),
                previous=rows[-1]["head"], sequence=sequence, head=head))
            exchange(self.config["witness_url"], dict(operation="advance", advance=advance))
            current = witness_query(self.config, target=dict(sequence=sequence, head=head))
            require(current["sequence"] == sequence and current["head"] == head)
            return sequence, head
        except Exception:
            self.stopped = True  # DB/witness commits are separate: never repair automatically.
            raise ContinuityDenied() from None

    def handle(self, value):
        with self.lock:
            if value.get("operation") == "control":
                exact(value, {"operation", "authorization"})
                data = check_control(value["authorization"], self.config, "SET_ISSUER", self.boot_challenge, time.time())
                exact(data, {"previous", "sequence", "record"})
                from governance.durable_authority_registries import _record_malformed_reason, _assert_safe_payload, HUMAN_APPROVAL
                require(type(data["record"]) is dict and not _record_malformed_reason(data["record"])
                        and data["record"]["domain"] == HUMAN_APPROVAL)
                _assert_safe_payload(data["record"])
                check_issuer_key(data["record"], self.config)
                conn, rows, issuers, _, _, _ = self._read()
                try:
                    require(data["previous"] == rows[-1]["head"] and data["sequence"] == len(rows))
                    ref = data["record"]["authority_reference"]
                    require(not issuers.get(ref, {}).get("revoked") or data["record"].get("revoked"))
                    self._commit(conn, rows, dict(kind="ISSUER", authorization=value["authorization"]))
                    return {"committed": True}
                finally: conn.close()
            exact(value, {"operation", "mandate", "challenge"})
            require(value["operation"] == "reserve" and type(value["challenge"]) is str and len(value["challenge"]) == 64)
            conn, rows, issuers, nonces, ids, challenges = self._read()
            try:
                mandate = value["mandate"]; record = issuers.get(mandate.get("issuer_reference"))
                require(record is not None, "issuer_invalid")
                verify_mandate(mandate, record, self.config, time.time())
                item = binding(mandate)
                require(item["nonce_hash"] not in nonces and item["authorization_hash"] not in ids
                        and value["challenge"] not in challenges, "replayed")
                now = time.time()
                event = dict(kind="RESERVATION", binding=item, challenge=value["challenge"],
                             issuer_hash=digest(record), reserved_at=now)
                seq, head = self._commit(conn, rows, event)
                # Revalidate after waits. Failure burns the committed reservation.
                verify_mandate(mandate, record, self.config, time.time())
                return sign(self.key, dict(schema=VERSION, kind="admission", binding=item,
                    challenge=value["challenge"], sequence=seq, head=head, issuer_hash=digest(record),
                    issued_at=now, expires_at=min(now+5, mandate["expires_at"])))
            finally: conn.close()


def reserve(config, mandate):
    config = trust(config)
    challenge = secrets.token_hex(32); started = time.monotonic(); now = time.time()
    packet = exchange(config["service_url"], dict(operation="reserve", mandate=mandate, challenge=challenge))
    value = verify(packet, config["service_public_key"])
    exact(value, {"schema", "kind", "binding", "challenge", "sequence", "head", "issuer_hash", "issued_at", "expires_at"})
    require(value["schema"] == VERSION and value["kind"] == "admission" and
            value["binding"] == binding(mandate) and value["challenge"] == challenge)
    integer(value["sequence"], 1)
    witness_query(config, target=dict(sequence=value["sequence"], head=value["head"]))
    timestamp(value["issued_at"]); timestamp(value["expires_at"])
    current = max(time.time(), now + time.monotonic() - started)
    require(value["issued_at"] <= current < value["expires_at"] <= min(value["issued_at"]+5, mandate["expires_at"]))
    return packet
