"""Explicit synthetic provisioning and open-only Gateway replay storage."""
import os
import secrets
import sqlite3
import time
from pathlib import Path

from security.hydra_continuity import CONTROL_FIELDS, check_control
from security.hydra_continuity_contracts import canonical, check_scope, decode, digest, exact, require, scope, trust, verify

SCHEMA = {
    "metadata": "CREATE TABLE metadata (slot INTEGER PRIMARY KEY CHECK(slot=1), authorization TEXT NOT NULL)",
    "hydra_transport_reservations": "CREATE TABLE hydra_transport_reservations (nonce_hash TEXT PRIMARY KEY, authorization_hash TEXT UNIQUE NOT NULL, evidence_hash TEXT NOT NULL, reserved_at REAL NOT NULL, receipt TEXT NOT NULL)",
    "hydra_transport_events": "CREATE TABLE hydra_transport_events (sequence INTEGER PRIMARY KEY, previous TEXT NOT NULL, receipt TEXT NOT NULL, head TEXT NOT NULL)",
}


class LocalStore:
    def __init__(self, path, config):
        self.path = Path(path); self.config = trust(config)
        self.boot_challenge = secrets.token_hex(32)
        self.provision_attempted = False

    def provision(self, authorization):
        require(not self.provision_attempted)
        data = check_control(authorization, self.config, "PROVISION_LOCAL", self.boot_challenge, time.time())
        exact(data, set())
        self.provision_attempted = True
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        conn = sqlite3.connect(self.path, isolation_level=None)
        try:
            conn.execute("PRAGMA synchronous=FULL"); conn.execute("BEGIN IMMEDIATE")
            for sql in SCHEMA.values(): conn.execute(sql)
            conn.execute("INSERT INTO metadata VALUES (1,?)", (canonical(authorization).decode(),))
            conn.commit()
        finally: conn.close()

    def open(self):
        require(self.path.is_file() and not self.path.is_symlink())
        conn = sqlite3.connect(self.path.resolve().as_uri()+"?mode=rw", uri=True, timeout=1, isolation_level=None)
        try:
            conn.execute("PRAGMA synchronous=FULL"); conn.execute("BEGIN IMMEDIATE")
            actual = dict(conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
            require(actual == SCHEMA)
            require(not conn.execute("SELECT name FROM sqlite_master WHERE type NOT IN ('table','index') OR (type='index' AND sql IS NOT NULL)").fetchall())
            metadata = conn.execute("SELECT slot,authorization FROM metadata").fetchall()
            require(len(metadata) == 1 and metadata[0][0] == 1)
            packet = decode(metadata[0][1]); value = verify(packet, self.config["control_public_key"])
            exact(value, CONTROL_FIELDS); exact(value["scope"], scope(self.config)); check_scope(value["scope"], self.config)
            require(value["action"] == "PROVISION_LOCAL")
            # Verify the append-only evidence and its materialized replay index.
            previous = "0"*64; latest = {}; seen_ids = {}
            for index, row in enumerate(conn.execute("SELECT * FROM hydra_transport_events ORDER BY sequence")):
                seq, prev, raw, head = row
                require(type(seq) is int and seq == index and prev == previous)
                receipt = decode(raw)
                require(canonical(receipt).decode() == raw and digest(dict(sequence=seq, previous=prev, receipt=receipt)) == head)
                nonce = receipt["nonce_hash"]; identifier = receipt["authorization_hash"]
                if nonce not in latest:
                    require(receipt["state"] == "CONTINUITY_PENDING" and identifier not in seen_ids)
                    seen_ids[identifier] = nonce
                else:
                    require(latest[nonce]["state"] == "CONTINUITY_PENDING" and receipt["state"] == "START_RESERVED"
                            and latest[nonce]["authorization_hash"] == identifier)
                latest[nonce] = receipt; previous = head
            materialized = list(conn.execute("SELECT * FROM hydra_transport_reservations"))
            require(len(materialized) == len(latest))
            for nonce, identifier, evidence, reserved, raw in materialized:
                require(nonce in latest and decode(raw) == latest[nonce] and
                        latest[nonce]["authorization_hash"] == identifier and latest[nonce]["mandate_hash"] == evidence
                        and latest[nonce]["reserved_at"] == reserved)
            return conn
        except Exception:
            conn.close(); raise

    @staticmethod
    def append(conn, receipt):
        last = conn.execute("SELECT sequence,head FROM hydra_transport_events ORDER BY sequence DESC LIMIT 1").fetchone()
        seq, previous = (last[0]+1, last[1]) if last else (0, "0"*64)
        head = digest(dict(sequence=seq, previous=previous, receipt=receipt))
        conn.execute("INSERT INTO hydra_transport_events VALUES (?,?,?,?)", (seq, previous, canonical(receipt).decode(), head))
