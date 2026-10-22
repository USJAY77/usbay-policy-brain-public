"""Explicit synthetic control authority. Never imported by application code."""
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from governance.approval_issuance import generate_issuer_keypair
from security import hydra_continuity as continuity
from security.hydra_continuity_contracts import VERSION, scope, sign
from security.hydra_continuity_store import LocalStore


class SyntheticContinuity:
    def __init__(self, tmp_path, monkeypatch, record, *, native=False):
        self.children = []
        self.native = native
        self.root, root_public = generate_issuer_keypair()
        self.service_key, service_public = generate_issuer_keypair()
        self.witness_key, witness_public = generate_issuer_keypair()
        self.config = dict(schema=VERSION, mode="synthetic_reference_only",
            continuity_identity="sha256:"+secrets.token_hex(32), witness_identity="sha256:"+secrets.token_hex(32),
            store_identity="sha256:"+secrets.token_hex(32), generation=1, authority_epoch=1,
            **{k: record[k] for k in ("tenant_reference", "environment_reference", "policy_reference", "policy_hash")},
            control_public_key=root_public, service_public_key=service_public, witness_public_key=witness_public,
            service_url="http://127.0.0.1:1/", witness_url="http://127.0.0.1:2/")
        monkeypatch.setenv("USBAY_ENV", "test")
        self.trust_path = tmp_path/"continuity-trust.json"
        self.trust_path.write_text(json.dumps(self.config))
        monkeypatch.setenv("USBAY_HYDRA_CONTINUITY_TRUST", str(self.trust_path))
        service_dir = tmp_path/"continuity-domain"; service_dir.mkdir()
        witness_dir = tmp_path/"witness-domain"; witness_dir.mkdir()
        self.original_exchange = continuity.exchange
        if native:
            for role in ("service", "witness"):
                with socket.socket() as allocator:
                    allocator.bind(("127.0.0.1", 0))
                    self.config[role+"_url"] = "http://127.0.0.1:"+str(allocator.getsockname()[1])+"/"
            self.trust_path.write_text(json.dumps(self.config))
            try:
                self.service = self.launch(service_dir, "service", self.service_key, {})
                conn = self.service.log.open()
                try: head = self.service.log.rows(conn)[-1]["head"]
                finally: conn.close()
                self.witness = self.launch(witness_dir, "witness", self.witness_key, {"initial_service_head": head})
            except Exception:
                self.close(); raise
        else:
            self.service = continuity.Authority(service_dir/"service.db", self.config, self.service_key)
            self.service.provision(self.authorization(self.service, "PROVISION_SERVICE", {}))
            conn = self.service.log.open()
            try: head = self.service.log.rows(conn)[-1]["head"]
            finally: conn.close()
            self.witness = continuity.Witness(witness_dir/"witness.db", self.config, self.witness_key)
            self.witness.provision(self.authorization(self.witness, "PROVISION_WITNESS", {"initial_service_head": head}))
            monkeypatch.setattr(continuity, "exchange", self.exchange)
        self.publish(record)
        local = LocalStore(tmp_path/"replay.db", self.config)
        local.provision(self.authorization(local, "PROVISION_LOCAL", {}))

    def authorization(self, target, action, data):
        return sign(self.root, continuity.control_payload(self.config, action, target.boot_challenge, data))

    def exchange(self, url, packet):
        if url == self.config["service_url"]:
            return self.service.handle(packet)
        if url == self.config["witness_url"]:
            return self.witness.handle(packet)
        raise RuntimeError("SYNTHETIC_ENDPOINT_UNAVAILABLE")

    def publish(self, record):
        conn = self.service.log.open()
        try: row = self.service.log.rows(conn)[-1]
        finally: conn.close()
        data = dict(previous=row["head"], sequence=row["sequence"]+1, record=dict(record))
        return self.service.handle(dict(operation="control", authorization=self.authorization(self.service, "SET_ISSUER", data)))

    def launch(self, directory, role, private_key, data, *, store=None, existing=False, stopped=False):
        path = store if store is not None else directory/(role+".db")
        with open(directory/"signing-key.pem", "x", opener=lambda p, f: os.open(p, f, 0o600)) as key:
            key.write(private_key)
        (directory/"launch.json").write_text(json.dumps(dict(role=role, config=self.config,
            store=str(path), synthetic_clock=time.time(), existing=existing, stopped=stopped)))
        child = subprocess.Popen([sys.executable, "-S", str(Path(__file__).with_name("hydra_continuity_server.py")),
            str(directory)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(child)
        def wait_for(name):
            deadline = time.monotonic()+15
            while not (directory/name).exists():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("SYNTHETIC_REFERENCE_START_FAILED")
                time.sleep(.01)
        wait_for("challenge.json")
        challenge = json.loads((directory/"challenge.json").read_text())["challenge"]
        handle = SimpleNamespace(boot_challenge=challenge, log=continuity.Log(path),
            handle=lambda value: self.original_exchange(self.config[role+"_url"], value))
        if not existing and not stopped:
            authorization = self.authorization(handle, "PROVISION_"+role.upper(), data)
            pending = directory/"authorization.pending"
            pending.write_text(json.dumps(authorization)); pending.replace(directory/"authorization.json")
        wait_for("ready")
        return handle

    def restart(self, role):
        index = 0 if role == "service" else 1
        child = self.children[index]
        if child.poll() is None: child.terminate(); child.wait(timeout=5)
        old = getattr(self, role)
        directory = old.log.path.parent/(role+"-restart")
        directory.mkdir()
        handle = self.launch(directory, role, self.service_key if role == "service" else self.witness_key,
            {}, store=old.log.path, existing=role == "service", stopped=role == "witness")
        setattr(self, role, handle)

    def close(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate(); child.wait(timeout=5)

    def mandate_bindings(self):
        return {key: self.config[key] for key in ("continuity_identity", "store_identity", "generation", "authority_epoch")}
