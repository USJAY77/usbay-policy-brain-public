#!/usr/bin/env python3
"""
USBAY governance enforcement gateway.

Fail-closed guarantees:
- invalid or unverifiable policy blocks every governance action
- device actions are denied unless the device is registered, authenticated, and attested
- every allow/deny decision is appended to the governance audit log before returning
- no client-provided badge or session state is trusted for enforcement
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit import ledger, sealing
from runtime import policy_validator


AUDIT_LOG_DIR = ROOT / "audit" / "logs"
AUDIT_ROOT = ROOT / "audit"
AUDIT_LOG_JSONL = AUDIT_ROOT / "audit_log.jsonl"
LEDGER_HEAD_JSON = AUDIT_ROOT / "ledger_head.json"
LEDGER_HEAD_SIG = AUDIT_ROOT / "ledger_head.sig"
AUDIT_SEAL_KEY = ROOT / "audit" / "audit_seal_key.pem"
AUDIT_SCHEMA = ROOT / "audit" / "decision_record.schema.json"
DEVICE_REGISTRY = ROOT / "runtime" / "device_registry.json"
FORBIDDEN_PRIVATE_KEY = ROOT / "private_key.pem"
RUNTIME_ATTESTATION_JSON = AUDIT_LOG_DIR / "runtime_attestation.json"
RUNTIME_ATTESTATION_SIG = AUDIT_LOG_DIR / "runtime_attestation.sig"
RUNTIME_ATTESTATION_KEY = ROOT / "runtime" / "runtime_attestation_key.pem"
EXECUTION_ATTESTATION_JSON = AUDIT_LOG_DIR / "execution_attestation.json"
EXECUTION_ATTESTATION_SIG = AUDIT_LOG_DIR / "execution_attestation.sig"
ACTION_TOKEN_JSON = AUDIT_LOG_DIR / "action_token.json"
ACTION_TOKEN_SIG = AUDIT_LOG_DIR / "action_token.sig"
EXPECTED_POLICY_HASH_ENV = "USBAY_EXPECTED_POLICY_HASH"
EXPECTED_POLICY_HASH_FILE_ENV = "USBAY_EXPECTED_POLICY_HASH_FILE"


def _canonical_json_bytes(payload: dict) -> bytes:
    return ledger.canonical_json_bytes(payload)


def _sha256_bytes(payload: bytes) -> str:
    return ledger.sha256_bytes(payload)


def _sha256_file(path: Path) -> str:
    return ledger.sha256_file(path)


def _approval_hashes() -> tuple[str, str]:
    return policy_validator._approval_hashes()


def _evidence_snapshot_hash() -> str:
    return policy_validator.validate_evidence_snapshot()


def _approvals_hash() -> str:
    approval_1_hash, approval_2_hash = _approval_hashes()
    payload = f"{approval_1_hash}\n{approval_2_hash}".encode("utf-8")
    return _sha256_bytes(payload)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _policy_sha256_from_disk() -> str:
    return hashlib.sha256(policy_validator.POLICY_JSON.read_bytes()).hexdigest().lower()


def _git_commit_hash() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"unable to resolve git commit hash: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() or "git rev-parse failed"
        raise RuntimeError(f"unable to resolve git commit hash: {detail}")

    commit_hash = (result.stdout or "").strip()
    if len(commit_hash) != 40:
        raise RuntimeError("git commit hash must be a 40-character SHA-1 hex digest")
    return commit_hash


def _read_expected_policy_hash() -> str:
    expected_hash = os.environ.get(EXPECTED_POLICY_HASH_ENV, "").strip().lower()
    if expected_hash:
        if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
            raise RuntimeError("configured expected policy hash must be a 64-character sha256 hex digest")
        return expected_hash

    expected_hash_file = os.environ.get(EXPECTED_POLICY_HASH_FILE_ENV, "").strip()
    if expected_hash_file:
        raw = Path(expected_hash_file).read_text(encoding="utf-8").strip().lower()
        expected_hash = raw.split()[0]
        if len(expected_hash) != 64 or any(ch not in "0123456789abcdef" for ch in expected_hash):
            raise RuntimeError("expected policy hash file must contain a 64-character sha256 hex digest")
        return expected_hash

    return ""


def _enforce_expected_policy_hash(*, loaded_policy_hash: str) -> None:
    expected_hash = _read_expected_policy_hash()
    if not expected_hash:
        return
    if loaded_policy_hash != expected_hash:
        raise RuntimeError(
            f"POLICY_MISMATCH_RUNTIME_BLOCK: expected {expected_hash}, loaded {loaded_policy_hash}"
        )


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise RuntimeError(f"expected JSON object in {path}")
    return data


def _load_request(path: Path) -> dict:
    payload = _read_json(path)
    required_fields = ["actor", "actor_type", "device_id", "action", "reason"]
    missing = [field for field in required_fields if not payload.get(field)]
    if missing:
        raise RuntimeError(f"request missing required fields: {', '.join(missing)}")
    return payload


def _policy_metadata_best_effort() -> dict:
    try:
        return policy_validator.load_policy_metadata()
    except Exception:
        return {
            "policy_version": "unknown",
            "policy_hash": "0" * 64,
            "policy": {},
        }


def _load_audit_schema() -> dict:
    return _read_json(AUDIT_SCHEMA)


def _validate_audit_event(event: dict) -> None:
    schema = _load_audit_schema()
    required = schema.get("required", [])
    missing = [field for field in required if not event.get(field)]
    if missing:
        raise RuntimeError(f"audit event missing required fields: {', '.join(missing)}")

    allowed_results = schema["properties"]["result"]["enum"]
    if event["result"] not in allowed_results:
        raise RuntimeError(f"invalid audit result: {event['result']}")

    allowed_actor_types = schema["properties"]["actor_type"]["enum"]
    if event["actor_type"] not in allowed_actor_types:
        raise RuntimeError(f"invalid actor_type: {event['actor_type']}")

    policy_hash = event["policy_hash"]
    if len(policy_hash) != 64 or any(ch not in "0123456789abcdef" for ch in policy_hash):
        raise RuntimeError("policy_hash must be a 64-character lowercase sha256 hex digest")

    commit_sha = str(event["commit_sha"]).lower()
    if len(commit_sha) != 40 or any(ch not in "0123456789abcdef" for ch in commit_sha):
        raise RuntimeError("commit_sha must be a 40-character lowercase git sha")

    for field in [
        "approval_1_hash",
        "approval_2_hash",
        "evidence_snapshot_hash",
        "runtime_attestation_hash",
    ]:
        value = str(event.get(field, "")).lower()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise RuntimeError(f"{field} must be a 64-character lowercase sha256 hex digest")

    for field in ["action_token_hash", "execution_attestation_hash"]:
        if field not in event:
            continue
        value = str(event.get(field, "")).lower()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise RuntimeError(f"{field} must be a 64-character lowercase sha256 hex digest")


def _append_audit_event(event: dict) -> None:
    if not AUDIT_ROOT.exists() or not AUDIT_ROOT.is_dir():
        raise RuntimeError(f"audit root directory missing: {AUDIT_ROOT}")
    _validate_existing_audit_chain()

    approval_1_hash, approval_2_hash = _approval_hashes()
    event["approval_1_hash"] = approval_1_hash
    event["approval_2_hash"] = approval_2_hash
    event["evidence_snapshot_hash"] = _evidence_snapshot_hash()
    event["runtime_attestation_hash"] = _sha256_file(RUNTIME_ATTESTATION_JSON)
    event["approval_nonces"] = policy_validator.current_approval_nonces()
    _validate_audit_event(event)

    _, entry_count = ledger.latest_chain_state(AUDIT_LOG_JSONL)
    try:
        appended = ledger.append_entry(AUDIT_LOG_JSONL, event)
    except OSError as exc:
        raise RuntimeError(f"unable to append governance audit log: {exc}") from exc
    _write_audit_seal(latest_entry_hash=appended["entry_hash"], entry_count=entry_count + 1)


def _make_audit_event(
    *,
    request: dict | None,
    policy_version: str,
    policy_hash: str,
    result: str,
    reason: str,
    entry_type: str = "governance_decision",
) -> dict:
    request = request or {}
    actor = str(request.get("actor", "unknown"))
    actor_type = str(request.get("actor_type", "unknown"))
    if actor_type not in {"human", "service", "system", "device", "unknown"}:
        actor_type = "unknown"

    return {
        "entry_type": entry_type,
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc_now(),
        "commit_sha": _git_commit_hash(),
        "actor": actor,
        "actor_type": actor_type,
        "device_id": str(request.get("device_id", "unknown")),
        "action": str(request.get("action", "unknown")),
        "reason": reason,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "result": result,
    }


def _make_automation_audit_event(
    *,
    automation_id: str,
    execution_result: str,
    validation_result: str,
    execution_allowed: bool,
    policy_version: str,
    policy_hash: str,
    reason: str,
) -> dict:
    event = _make_audit_event(
        request={
            "actor": "automation",
            "actor_type": "system",
            "device_id": "automation",
            "action": "automation_run",
            "reason": reason,
        },
        policy_version=policy_version,
        policy_hash=policy_hash,
        result="allow" if execution_allowed else "deny",
        reason=reason,
        entry_type="automation_execution",
    )
    event["automation_id"] = automation_id
    event["execution_result"] = execution_result
    event["validation_result"] = validation_result
    event["execution_allowed"] = execution_allowed
    return event


def _make_remote_execution_audit_event(
    *,
    request: dict,
    policy_version: str,
    policy_hash: str,
    command_id: str,
    action_token_hash: str,
    execution_attestation_hash: str,
    execution_result: str,
    reason: str,
) -> dict:
    event = _make_audit_event(
        request=request,
        policy_version=policy_version,
        policy_hash=policy_hash,
        result="allow" if execution_result == "allow" else "deny",
        reason=reason,
        entry_type="remote_execution",
    )
    event["command_id"] = command_id
    event["action_token_hash"] = action_token_hash
    event["execution_attestation_hash"] = execution_attestation_hash
    event["execution_result"] = execution_result
    return event


def _deny(
    *,
    request: dict | None,
    policy_version: str,
    policy_hash: str,
    reason: str,
) -> int:
    event = _make_audit_event(
        request=request,
        policy_version=policy_version,
        policy_hash=policy_hash,
        result="deny",
        reason=reason,
    )
    _append_audit_event(event)
    print(json.dumps({"result": "deny", "reason": reason, "event_id": event["event_id"]}))
    return 1


def _allow(
    *,
    request: dict,
    policy_version: str,
    policy_hash: str,
    reason: str,
) -> int:
    event = _make_audit_event(
        request=request,
        policy_version=policy_version,
        policy_hash=policy_hash,
        result="allow",
        reason=reason,
    )
    _append_audit_event(event)
    print(json.dumps({"result": "allow", "reason": reason, "event_id": event["event_id"]}))
    return 0


def _record_runtime_loaded(*, policy_version: str, policy_hash: str) -> None:
    event = _make_audit_event(
        request={
            "actor": "runtime",
            "actor_type": "system",
            "device_id": "runtime",
            "action": "runtime_loaded",
            "reason": "runtime attestation generated",
        },
        policy_version=policy_version,
        policy_hash=policy_hash,
        result="allow",
        reason="runtime attestation generated",
        entry_type="runtime_loaded",
    )
    _append_audit_event(event)


def _validate_automation_request(path: Path) -> dict:
    payload = _read_json(path)
    automation_id = str(payload.get("automation_id", "")).strip()
    if not automation_id:
        raise RuntimeError("AUTOMATION_BYPASS_ATTEMPT")

    action = str(payload.get("action", "")).strip().lower()
    if action not in {"summarize", "suggest", "prepare"}:
        raise RuntimeError("AUTOMATION_BYPASS_ATTEMPT")

    context = payload.get("automation_context")
    if not isinstance(context, dict):
        raise RuntimeError("AUTOMATION_BYPASS_ATTEMPT")

    trigger_context = str(context.get("context", "")).strip()
    policy_hash = str(context.get("expected_policy_hash", "")).strip().lower()
    trigger_timestamp = str(context.get("trigger_timestamp", "")).strip()

    if not policy_hash:
        raise RuntimeError("AUTOMATION_POLICY_HASH_MISSING")
    if len(policy_hash) != 64 or any(ch not in "0123456789abcdef" for ch in policy_hash):
        raise RuntimeError("AUTOMATION_POLICY_MISMATCH")
    if trigger_context != "automation_triggered":
        raise RuntimeError("AUTOMATION_BYPASS_ATTEMPT")
    if not trigger_timestamp:
        raise RuntimeError("AUTOMATION_BYPASS_ATTEMPT")

    payload["automation_id"] = automation_id
    payload["action"] = action
    payload["automation_context"] = {
        "expected_policy_hash": policy_hash,
        "trigger_timestamp": trigger_timestamp,
        "context": trigger_context,
    }
    return payload


def _load_command_request(path: Path) -> dict:
    from runtime import command_model

    return command_model.load_command_request(path)


def _validate_automation_context(*, metadata: dict, request: dict) -> None:
    context = request["automation_context"]
    if context["expected_policy_hash"] != metadata["loaded_policy_hash"]:
        raise RuntimeError("AUTOMATION_POLICY_MISMATCH")
    policy_validator.validate_runtime_attestation(policy_hash=metadata["loaded_policy_hash"])
    policy_validator.validate_audit_chain(policy_hash=metadata["loaded_policy_hash"])


def _execute_automation(request: dict) -> tuple[str, str]:
    action = request["action"]
    automation_id = request["automation_id"]
    result = {
        "automation_id": automation_id,
        "action": action,
        "status": "prepared",
    }
    return "allow", json.dumps(result, sort_keys=True)


def _generate_action_token(*, command: dict, policy_hash: str) -> dict:
    from runtime import action_token

    return action_token.generate_action_token(
        command=command,
        policy_hash=policy_hash,
        approvals_hash=_approvals_hash(),
        evidence_hash=_evidence_snapshot_hash(),
        private_key=AUDIT_SEAL_KEY,
        cwd=ROOT,
        token_path=ACTION_TOKEN_JSON,
        signature_path=ACTION_TOKEN_SIG,
    )


def check_private_key_not_present() -> None:
    if FORBIDDEN_PRIVATE_KEY.exists():
        raise RuntimeError(f"forbidden private key material present: {FORBIDDEN_PRIVATE_KEY}")


def check_audit_log_writability() -> None:
    if not AUDIT_LOG_DIR.exists() or not AUDIT_LOG_DIR.is_dir():
        raise RuntimeError(f"audit log directory missing: {AUDIT_LOG_DIR}")
    if not AUDIT_ROOT.exists() or not AUDIT_ROOT.is_dir():
        raise RuntimeError(f"audit root directory missing: {AUDIT_ROOT}")

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=AUDIT_LOG_DIR,
            prefix=".append_probe_",
            delete=True,
            encoding="utf-8",
        ) as handle:
            handle.write("append-only-audit-probe\n")
            handle.flush()
    except OSError as exc:
        raise RuntimeError(f"audit log directory not writable: {AUDIT_LOG_DIR} ({exc})") from exc


def _runtime_attestation_payload(*, loaded_policy_hash: str) -> dict:
    instance_id = str(uuid.uuid4())
    commit_hash = _git_commit_hash()
    timestamp = _utc_now()
    return {
        "instance_id": instance_id,
        "commit_hash": commit_hash,
        "loaded_policy_hash": loaded_policy_hash,
        "runtime_hash": policy_validator.compute_runtime_hash(
            instance_id=instance_id,
            commit_hash=commit_hash,
            loaded_policy_hash=loaded_policy_hash,
            timestamp=timestamp,
        ),
        "timestamp": timestamp,
    }


def _sign_runtime_attestation(attestation_path: Path) -> bool:
    if not RUNTIME_ATTESTATION_KEY.exists():
        raise RuntimeError(f"missing runtime attestation key: {RUNTIME_ATTESTATION_KEY}")

    command = [
        "openssl",
        "dgst",
        "-sha256",
        "-sign",
        str(RUNTIME_ATTESTATION_KEY),
        "-out",
        str(RUNTIME_ATTESTATION_SIG),
        str(attestation_path),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"failed to sign runtime attestation: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip() or "openssl signing failed"
        raise RuntimeError(f"failed to sign runtime attestation: {detail}")
    return True


def _sign_audit_seal(seal_path: Path) -> None:
    if not AUDIT_SEAL_KEY.exists():
        raise RuntimeError(f"missing audit seal key: {AUDIT_SEAL_KEY}")
    try:
        sealing.sign_path(
            private_key=AUDIT_SEAL_KEY,
            payload_path=seal_path,
            signature_path=LEDGER_HEAD_SIG,
            cwd=ROOT,
        )
    except Exception as exc:
        raise RuntimeError(f"failed to sign audit seal: {exc}") from exc


def _latest_audit_chain_state() -> tuple[str, int]:
    return ledger.latest_chain_state(AUDIT_LOG_JSONL)


def _validate_existing_audit_chain() -> None:
    if not AUDIT_LOG_JSONL.exists():
        return
    if not LEDGER_HEAD_JSON.exists() or not LEDGER_HEAD_SIG.exists() or not policy_validator.AUDIT_SEAL_PUBLIC_KEY.exists():
        raise RuntimeError("AUDIT_LEDGER_HEAD_INVALID: invalid seal")
    try:
        last_entry_hash, entry_count, _ = ledger.verify_chain(AUDIT_LOG_JSONL)
    except Exception as exc:
        raise RuntimeError(f"AUDIT_CHAIN_INVALID: {exc}") from exc
    try:
        seal = sealing.verify_seal(
            seal_path=LEDGER_HEAD_JSON,
            signature_path=LEDGER_HEAD_SIG,
            public_key=policy_validator.AUDIT_SEAL_PUBLIC_KEY,
            cwd=ROOT,
        )
    except Exception as exc:
        raise RuntimeError(f"AUDIT_LEDGER_HEAD_SIGNATURE_INVALID: {exc}") from exc
    if seal.get("latest_entry_hash") != last_entry_hash or int(seal.get("entry_count", -1)) != entry_count:
        raise RuntimeError("AUDIT_LEDGER_HEAD_INVALID: invalid seal")


def _write_audit_seal(*, latest_entry_hash: str, entry_count: int) -> None:
    if entry_count <= 0:
        raise RuntimeError("ROLLBACK_DETECTED: entry_count must be positive")

    if LEDGER_HEAD_JSON.exists() or LEDGER_HEAD_SIG.exists():
        if not LEDGER_HEAD_JSON.exists() or not LEDGER_HEAD_SIG.exists():
            raise RuntimeError("AUDIT_LEDGER_HEAD_INVALID: ledger head is incomplete")
        existing = sealing.verify_seal(
            seal_path=LEDGER_HEAD_JSON,
            signature_path=LEDGER_HEAD_SIG,
            public_key=policy_validator.AUDIT_SEAL_PUBLIC_KEY,
            cwd=ROOT,
        )
        previous_count = int(existing["entry_count"])
        if entry_count <= previous_count:
            raise RuntimeError(
                f"ROLLBACK_DETECTED: new entry_count {entry_count} must be greater than previous entry_count {previous_count}"
            )

    sealing.write_seal(
        seal_path=LEDGER_HEAD_JSON,
        signature_path=LEDGER_HEAD_SIG,
        private_key=AUDIT_SEAL_KEY,
        cwd=ROOT,
        latest_entry_hash=latest_entry_hash,
        entry_count=entry_count,
        sealed_at=_utc_now(),
        commit_sha=_git_commit_hash(),
    )


def generate_runtime_attestation(*, loaded_policy_hash: str) -> dict:
    if not AUDIT_LOG_DIR.exists() or not AUDIT_LOG_DIR.is_dir():
        raise RuntimeError(f"audit log directory missing: {AUDIT_LOG_DIR}")

    attestation = _runtime_attestation_payload(loaded_policy_hash=loaded_policy_hash)
    RUNTIME_ATTESTATION_JSON.write_bytes(_canonical_json_bytes(attestation))
    _sign_runtime_attestation(RUNTIME_ATTESTATION_JSON)
    attestation["signature_generated"] = True
    return attestation


def _load_runtime_attestation() -> dict:
    attestation = _read_json(RUNTIME_ATTESTATION_JSON)
    attestation["signature_generated"] = RUNTIME_ATTESTATION_SIG.exists()
    return attestation


def _dashboard_html(attestation: dict) -> str:
    sig_state = "present" if attestation.get("signature_generated") else "missing"
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>USBAY Runtime Attestation</title>
    <style>
      body {{ font-family: monospace; margin: 2rem; background: #f4f0e8; color: #1f1f1f; }}
      .panel {{ background: #fff; border: 2px solid #1f1f1f; padding: 1rem; max-width: 48rem; }}
      h1 {{ margin-top: 0; font-size: 1.5rem; }}
      dt {{ font-weight: bold; margin-top: 0.75rem; }}
      dd {{ margin-left: 0; }}
      code {{ word-break: break-all; }}
    </style>
  </head>
  <body>
    <div class="panel">
      <h1>USBAY Runtime Attestation</h1>
      <dl>
        <dt>Runtime Instance</dt>
        <dd><code>{html.escape(str(attestation["instance_id"]))}</code></dd>
        <dt>Commit Hash</dt>
        <dd><code>{html.escape(str(attestation["commit_hash"]))}</code></dd>
        <dt>Loaded Policy Hash</dt>
        <dd><code>{html.escape(str(attestation["loaded_policy_hash"]))}</code></dd>
        <dt>Timestamp</dt>
        <dd><code>{html.escape(str(attestation["timestamp"]))}</code></dd>
        <dt>Runtime Attestation Signature</dt>
        <dd><code>{sig_state}</code></dd>
      </dl>
    </div>
  </body>
</html>
"""


def serve_attestation(*, host: str, port: int) -> int:
    try:
        check_private_key_not_present()
        check_audit_log_writability()
        metadata = validate_signed_policy()
        generate_runtime_attestation(loaded_policy_hash=metadata["policy_hash"])
        _record_runtime_loaded(
            policy_version=metadata["policy_version"],
            policy_hash=metadata["loaded_policy_hash"],
        )
    except Exception as exc:
        print(f"ENFORCEMENT_GATEWAY_FAILED: {exc}")
        return 1

    class AttestationHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/attestation":
                payload = _load_runtime_attestation()
                body = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/":
                payload = _load_runtime_attestation()
                body = _dashboard_html(payload).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer((host, port), AttestationHandler)
    print(f"ENFORCEMENT_GATEWAY_SERVING http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def validate_signed_policy() -> dict:
    policy_validator.validate_required_files()
    policy_validator.validate_policy_json()
    policy_validator.validate_sha256()
    policy_validator.validate_signature()
    metadata = policy_validator.load_policy_metadata()
    loaded_policy_hash = _policy_sha256_from_disk()
    if metadata["policy_hash"] != loaded_policy_hash:
        raise RuntimeError("loaded policy hash does not match policy metadata hash")
    policy_validator.validate_approval_artifacts(
        policy_hash=loaded_policy_hash,
        policy_version=metadata["policy_version"],
    )
    _enforce_expected_policy_hash(loaded_policy_hash=loaded_policy_hash)
    metadata["loaded_policy_hash"] = loaded_policy_hash
    return metadata


def _load_device_registry() -> dict:
    registry = _read_json(DEVICE_REGISTRY)
    devices = registry.get("devices")
    if not isinstance(devices, dict):
        raise RuntimeError("device registry must contain a top-level 'devices' object")
    return devices


def _enforce_zero_trust_device(request: dict) -> None:
    devices = _load_device_registry()
    device_id = str(request["device_id"])
    device_entry = devices.get(device_id)

    if not isinstance(device_entry, dict):
        raise RuntimeError(f"device not registered: {device_id}")

    if device_entry.get("registered") is not True:
        raise RuntimeError(f"device not registered: {device_id}")
    if device_entry.get("authenticated") is not True:
        raise RuntimeError(f"device not authenticated: {device_id}")
    if device_entry.get("attested") is not True:
        raise RuntimeError(f"device not attested: {device_id}")

    bound_actor = device_entry.get("actor")
    if bound_actor and bound_actor != request["actor"]:
        raise RuntimeError(
            f"device actor mismatch: request actor {request['actor']} is not bound to {device_id}"
        )


def _policy_allows_action(policy: dict, action: str) -> tuple[bool, str]:
    for rule in policy.get("policies", []):
        if rule.get("action_type") != action:
            continue

        effect = str(rule.get("effect", "")).upper()
        if effect == "ALLOW":
            return True, "policy rule allows action"
        if effect == "REVIEW":
            return False, "policy requires explicit human approval for this action"
        return False, f"unsupported policy effect for action {action}: {effect or 'missing'}"

    rules = policy.get("rules", {})
    if isinstance(rules, dict):
        rule = rules.get(action)
        if isinstance(rule, dict):
            effect = str(rule.get("effect", rule.get("action", ""))).upper()
            if effect == "ALLOW":
                return True, "policy rule allows action"
            if effect in {"REVIEW", "BLOCK", "DENY"}:
                return False, "policy requires explicit human approval for this action"
            return False, f"unsupported policy effect for action {action}: {effect or 'missing'}"

    return False, f"no policy rule found for action: {action}"


def evaluate_governance_request(request_path: Path) -> int:
    request: dict | None = None
    policy_version = "unknown"
    policy_hash = "0" * 64

    try:
        request = _load_request(request_path)
    except Exception as exc:
        return _deny(
            request=None,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason=str(exc),
        )

    try:
        check_private_key_not_present()
        check_audit_log_writability()
        metadata = validate_signed_policy()
        policy_version = metadata["policy_version"]
        policy_hash = metadata["loaded_policy_hash"]
        generate_runtime_attestation(loaded_policy_hash=policy_hash)
    except Exception as exc:
        best_effort = _policy_metadata_best_effort()
        return _deny(
            request=request,
            policy_version=best_effort["policy_version"],
            policy_hash=best_effort["policy_hash"],
            reason=f"policy verification failed: {exc}",
        )

    try:
        _enforce_zero_trust_device(request)
    except Exception as exc:
        return _deny(
            request=request,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason=str(exc),
        )

    allowed, reason = _policy_allows_action(metadata["policy"], str(request["action"]))
    if not allowed:
        return _deny(
            request=request,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason=reason,
        )

    return _allow(
        request=request,
        policy_version=policy_version,
        policy_hash=policy_hash,
        reason=reason,
    )


def preflight_only() -> int:
    try:
        check_private_key_not_present()
        check_audit_log_writability()
        validate_signed_policy()
        _load_device_registry()
        _load_audit_schema()
        print("ENFORCEMENT_GATEWAY_OK")
        return 0
    except Exception as exc:
        print(f"ENFORCEMENT_GATEWAY_FAILED: {exc}")
        return 1


def evaluate_automation_request(request_path: Path) -> int:
    policy_version = "unknown"
    policy_hash = "0" * 64
    request: dict | None = None

    try:
        check_private_key_not_present()
        check_audit_log_writability()
        metadata = validate_signed_policy()
        policy_version = metadata["policy_version"]
        policy_hash = metadata["loaded_policy_hash"]
        generate_runtime_attestation(loaded_policy_hash=policy_hash)
        _record_runtime_loaded(policy_version=policy_version, policy_hash=policy_hash)
    except Exception as exc:
        event = _make_automation_audit_event(
            automation_id="unknown",
            execution_result="deny",
            validation_result="failed",
            execution_allowed=False,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason="AUTOMATION_VALIDATION_FAILED",
        )
        _append_audit_event(event)
        print(json.dumps({"result": "deny", "reason": "AUTOMATION_VALIDATION_FAILED", "event_id": event["event_id"]}))
        return 1

    try:
        request = _validate_automation_request(request_path)
        _validate_automation_context(metadata=metadata, request=request)
    except Exception as exc:
        reason = str(exc)
        if reason not in {"AUTOMATION_POLICY_HASH_MISSING", "AUTOMATION_POLICY_MISMATCH", "AUTOMATION_BYPASS_ATTEMPT"}:
            reason = "AUTOMATION_VALIDATION_FAILED"
        event = _make_automation_audit_event(
            automation_id=(request or {}).get("automation_id", "unknown"),
            execution_result="deny",
            validation_result="failed",
            execution_allowed=False,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason=reason,
        )
        _append_audit_event(event)
        print(json.dumps({"result": "deny", "reason": reason, "event_id": event["event_id"]}))
        return 1

    execution_result, payload = _execute_automation(request)
    event = _make_automation_audit_event(
        automation_id=request["automation_id"],
        execution_result=execution_result,
        validation_result="passed",
        execution_allowed=True,
        policy_version=policy_version,
        policy_hash=policy_hash,
        reason=payload,
    )
    _append_audit_event(event)
    print(payload)
    return 0


def evaluate_command_request(request_path: Path) -> int:
    request: dict | None = None
    policy_version = "unknown"
    policy_hash = "0" * 64

    try:
        request = _load_command_request(request_path)
    except Exception as exc:
        return _deny(
            request=None,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason=str(exc),
        )

    try:
        check_private_key_not_present()
        check_audit_log_writability()
        metadata = validate_signed_policy()
        policy_version = metadata["policy_version"]
        policy_hash = metadata["loaded_policy_hash"]
        generate_runtime_attestation(loaded_policy_hash=policy_hash)
        _record_runtime_loaded(policy_version=policy_version, policy_hash=policy_hash)
        policy_validator.validate_runtime_attestation(policy_hash=policy_hash)
        policy_validator.validate_audit_chain(policy_hash=policy_hash)
        _enforce_zero_trust_device(request)
        token = _generate_action_token(command=request["command"], policy_hash=policy_hash)
        from runtime import replit_executor

        execution = replit_executor.execute_command(
            command=request["command"],
            token_path=ACTION_TOKEN_JSON,
            signature_path=ACTION_TOKEN_SIG,
            governance_public_key=policy_validator.AUDIT_SEAL_PUBLIC_KEY,
            runtime_private_key=RUNTIME_ATTESTATION_KEY,
            cwd=ROOT,
            attestation_path=EXECUTION_ATTESTATION_JSON,
            attestation_signature_path=EXECUTION_ATTESTATION_SIG,
        )
    except Exception as exc:
        return _deny(
            request=request,
            policy_version=policy_version,
            policy_hash=policy_hash,
            reason=str(exc),
        )

    event = _make_remote_execution_audit_event(
        request=request,
        policy_version=policy_version,
        policy_hash=policy_hash,
        command_id=str(token["command_id"]),
        action_token_hash=execution["action_token_hash"],
        execution_attestation_hash=execution["execution_attestation_hash"],
        execution_result="allow",
        reason="remote command executed under signed action token",
    )
    _append_audit_event(event)
    print(
        json.dumps(
            {
                "result": "allow",
                "command_id": token["command_id"],
                "exit_code": execution["exit_code"],
                "stdout": execution["stdout"],
                "stderr": execution["stderr"],
            },
            sort_keys=True,
        )
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="USBAY governance enforcement gateway")
    parser.add_argument(
        "--request",
        type=Path,
        help="Path to a governance action request JSON file",
    )
    parser.add_argument(
        "--automation-request",
        type=Path,
        help="Path to an automation execution request JSON file",
    )
    parser.add_argument(
        "--command-request",
        type=Path,
        help="Path to a signed remote command request JSON file",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Serve runtime attestation API and dashboard",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the attestation server to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the attestation server to",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    if args.serve:
        return serve_attestation(host=args.host, port=args.port)
    if args.automation_request:
        return evaluate_automation_request(args.automation_request)
    if args.command_request:
        return evaluate_command_request(args.command_request)
    if args.request:
        return evaluate_governance_request(args.request)
    return preflight_only()


if __name__ == "__main__":
    raise SystemExit(main())
