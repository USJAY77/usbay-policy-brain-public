"""Disposable loopback reference process, explicitly provisioned by test tooling."""
import json
import os
from pathlib import Path
import socket
import sys
import time


def guard(event, args):
    if event in ("socket.bind", "socket.connect") and args[0].family in (socket.AF_INET, socket.AF_INET6):
        if args[1][0] not in ("127.0.0.1", "::1"):
            raise RuntimeError("NON_LOOPBACK_BLOCKED")
    if event == "subprocess.Popen":
        raise RuntimeError("CHILD_PROCESS_BLOCKED")


sys.addaudithook(guard)
assert os.getenv("USBAY_ENV") == "test"
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from security import hydra_continuity as continuity
from security.hydra_continuity import Authority, Witness
from security.hydra_continuity_contracts import ContinuityDenied, canonical, decode

directory = Path(sys.argv[1])
options = decode((directory/"launch.json").read_bytes())
time.time = lambda: options["synthetic_clock"]
config = options["config"]
role = options["role"]
target = (Witness if role == "witness" else Authority)(options["store"], config,
            (directory/"signing-key.pem").read_text())
(directory/"challenge.pending").write_bytes(canonical({"challenge": target.boot_challenge}))
(directory/"challenge.pending").replace(directory/"challenge.json")
if options["existing"]:
    assert role == "service"  # Open-only; first request must prove current witness head.
elif options["stopped"]:
    assert role == "witness"  # No recovery API; fresh witness memory cannot be reconstructed.
else:
    deadline = time.monotonic()+15
    while not (directory/"authorization.json").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("EXPLICIT_PROVISIONING_REQUIRED")
        time.sleep(.01)
    target.provision(decode((directory/"authorization.json").read_bytes()))

# Disposable crash-injection markers owned by the test fixture, never request data.
original_exchange = continuity.exchange
def injected_exchange(url, value):
    if value.get("operation") == "advance":
        if (directory/"pause-after-db-commit").exists():
            (directory/"commit-paused").write_text("DB_COMMITTED")
            while True: time.sleep(.01)
        result = original_exchange(url, value)
        if (directory/"pause-after-witness").exists():
            (directory/"commit-paused").write_text("WITNESS_COMMITTED")
            while True: time.sleep(.01)
        return result
    return original_exchange(url, value)
continuity.exchange = injected_exchange


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            length = int(self.headers["Content-Length"])
            if not 0 < length <= 1048576:
                raise ContinuityDenied()
            value = decode(self.rfile.read(length))
            eligible = (role == "service" and value.get("operation") == "reserve") or (
                role == "witness" and value.get("operation") == "observe")
            if eligible and (directory/"replay-response").exists():
                result = decode((directory/"recorded-response.json").read_bytes())
            else:
                result = target.handle(value)
            if eligible and (directory/"capture-response").exists():
                (directory/"response.pending").write_bytes(canonical(result))
                (directory/"response.pending").replace(directory/"recorded-response.json")
            raw = canonical(result); self.send_response(200)
        except Exception as error:
            code = error.code if isinstance(error, ContinuityDenied) else "STOPPED_UNVERIFIED_HEAD"
            raw = canonical({"denied": code}); self.send_response(403)
        self.end_headers()
        try: self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError): pass


url = urlsplit(config[role+"_url"])
server = ThreadingHTTPServer(("127.0.0.1", url.port), Handler)
(directory/"ready").write_text("READY")
server.serve_forever()
