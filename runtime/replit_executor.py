#!/usr/bin/env python3
"""
USBAY remote executor.
"""

from __future__ import annotations

import base64
import hmac
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib import error, request

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit import ledger
from audit import sealing
from governance.hashing import is_sha256_reference
from runtime.computer_use import ai_act_live_policy_engine
import runtime.action_token as action_token
import runtime.attestation as attestation
import runtime.policy_validator as policy_validator
from security import execution_lifecycle_store

EXECUTOR_PUBLIC_KEY = ROOT / "policy" / "public_key.pem"
DEFAULT_COMMAND_PATH = ROOT / "commands" / "test_command.json"
COMMAND_RAW_URL = "https://raw.githubusercontent.com/USBAY-GLOBAL/usbay-policy-brain/main/commands/test_command.json"
FETCH_TIMEOUT_SECONDS = 5
REQUIRED_COMMAND_FIELDS = (
    "command_id",
    "action",
    "payload",
    "timestamp",
    "expires_at",
    "nonce",
    "policy_hash",
    "actor_role",
    "signed_by",
    "signing_context",
    "signature",
)
ALLOWED_SIGNERS = {"OCO", "SYSTEM_AUTOMATION", "CI_PIPELINE"}
ALLOWED_SIGNING_CONTEXTS = {
    "OCO": {"human_governance"},
    "SYSTEM_AUTOMATION": {"system_automation"},
    "CI_PIPELINE": {"ci_pipeline"},
}
SEEN_NONCES: set[str] = set()
SEEN_COMMAND_IDS: set[str] = set()


class _RuntimePrivateKeySignerAdapter:
    signer_type = "runtime_private_key"

    def __init__(self, private_key: Path) -> None:
        self._private_key = private_key

    def sign_file(self, *, payload_path: Path, signature_path: Path, cwd: Path) -> None:
        sealing.sign_path(
            private_key=self._private_key,
            payload_path=payload_path,
            signature_path=signature_path,
            cwd=cwd,
        )


def _canonical_json_bytes(payload: dict) -> bytes:
    return ledger.canonical_json_bytes(payload)


def _utc_now() -> int:
    return int(time.time())


def _command_hash(command: dict) -> str:
    return _sha256_bytes(_command_bytes_without_signature(command))


def _sha256_bytes(payload: bytes) -> str:
    return ledger.sha256_bytes(payload)


def _run_subprocess(command: dict, *, cwd: Path) -> dict:
    try:
        result = subprocess.run(
            [command["entrypoint"], *command.get("args", [])],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: unable to execute command: {exc}") from exc
    return {
        "stdout": result.stdout or "",
        "stderr": result.stderr or "",
        "exit_code": result.returncode,
    }


def _runtime_signer_adapter(*, runtime_signer_adapter, runtime_private_key: Path | None):
    if runtime_signer_adapter is not None:
        return runtime_signer_adapter
    if runtime_private_key is not None:
        return _RuntimePrivateKeySignerAdapter(runtime_private_key)
    return None


def _require_governed_execution_inputs(
    *,
    token_path: Path | None,
    signature_path: Path | None,
    governance_public_key: Path | None,
    runtime_signer_adapter,
    runtime_key_id: str | None,
    attestation_path: Path | None,
    attestation_signature_path: Path | None,
) -> None:
    required = {
        "token_path": token_path,
        "signature_path": signature_path,
        "governance_public_key": governance_public_key,
        "runtime_signer_adapter": runtime_signer_adapter,
        "runtime_key_id": runtime_key_id,
        "attestation_path": attestation_path,
        "attestation_signature_path": attestation_signature_path,
    }
    missing = sorted(name for name, value in required.items() if value is None)
    if missing:
        raise RuntimeError(
            f"EXECUTOR_VALIDATION_FAILED: missing governed execution inputs: {missing}"
        )
    if not str(runtime_key_id).strip():
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing runtime_key_id")
    if not hasattr(runtime_signer_adapter, "signer_type"):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: runtime signer type unavailable")
    if not callable(getattr(runtime_signer_adapter, "sign_file", None)):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: runtime signer unavailable")


def _validate_before_subprocess(
    *,
    command: dict,
    token_path: Path | None,
    signature_path: Path | None,
    governance_public_key: Path | None,
    runtime_signer_adapter,
    runtime_key_id: str | None,
    cwd: Path,
    attestation_path: Path | None,
    attestation_signature_path: Path | None,
    governed_request: dict | None,
    governed_execution_contract: dict | None,
    governed_execution_authorization: dict | None,
    consumed_decision_evidence_hash: str | None,
) -> dict:
    _require_governed_execution_inputs(
        token_path=token_path,
        signature_path=signature_path,
        governance_public_key=governance_public_key,
        runtime_signer_adapter=runtime_signer_adapter,
        runtime_key_id=runtime_key_id,
        attestation_path=attestation_path,
        attestation_signature_path=attestation_signature_path,
    )
    return action_token.verify_action_token(
        command=command,
        token_path=token_path,
        signature_path=signature_path,
        public_key=governance_public_key,
        cwd=cwd,
        governed_execution_authorization=governed_execution_authorization,
    )


def _validate_command_parameter_hash(*, command: dict, governed_execution_contract: dict | None) -> None:
    if not isinstance(governed_execution_contract, dict):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: EXEC_AUTH_PARAMETER_HASH_MISSING")
    parameter_hash = governed_execution_contract.get("parameter_hash")
    if parameter_hash is None:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: EXEC_AUTH_PARAMETER_HASH_MISSING")
    if not is_sha256_reference(parameter_hash):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: EXEC_AUTH_PARAMETER_HASH_MALFORMED")
    command_hash = attestation.command_hash(command)
    if not hmac.compare_digest(command_hash, parameter_hash):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: EXEC_AUTH_PARAMETER_COMMAND_HASH_MISMATCH")


def execute_command(
    *,
    command: dict,
    token_path: Path | None = None,
    signature_path: Path | None = None,
    governance_public_key: Path | None = None,
    runtime_signer_adapter=None,
    runtime_private_key: Path | None = None,
    runtime_key_id: str | None = None,
    cwd: Path,
    attestation_path: Path | None = None,
    attestation_signature_path: Path | None = None,
    governed_request: dict | None = None,
    governed_execution_contract: dict | None = None,
    governed_execution_authorization: dict | None = None,
    consumed_decision_evidence_hash: str | None = None,
    lifecycle_store: execution_lifecycle_store.ExecutionLifecycleStore | None = None,
) -> dict:
    signer_adapter = _runtime_signer_adapter(
        runtime_signer_adapter=runtime_signer_adapter,
        runtime_private_key=runtime_private_key,
    )
    token = _validate_before_subprocess(
        command=command,
        token_path=token_path,
        signature_path=signature_path,
        governance_public_key=governance_public_key,
        runtime_signer_adapter=signer_adapter,
        runtime_key_id=runtime_key_id,
        cwd=cwd,
        attestation_path=attestation_path,
        attestation_signature_path=attestation_signature_path,
        governed_request=governed_request,
        governed_execution_contract=governed_execution_contract,
        governed_execution_authorization=governed_execution_authorization,
        consumed_decision_evidence_hash=consumed_decision_evidence_hash,
    )
    execution_authorization_error = ai_act_live_policy_engine.validate_governed_execution_authorization(
        governed_execution_authorization,
        governed_request,
        governed_execution_contract,
        consumed_decision_evidence_hash=consumed_decision_evidence_hash,
    )
    if execution_authorization_error:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {execution_authorization_error}")
    _validate_command_parameter_hash(
        command=command,
        governed_execution_contract=governed_execution_contract,
    )
    lifecycle_binding = execution_lifecycle_store.lifecycle_binding(
        command=command,
        governed_execution_authorization=governed_execution_authorization,
        governed_execution_contract=governed_execution_contract,
        consumed_decision_evidence_hash=consumed_decision_evidence_hash,
        command_hash=attestation.command_hash(command),
        execution_contract_hash=attestation.execution_contract_hash(governed_execution_contract),
    )
    store = lifecycle_store or execution_lifecycle_store.default_lifecycle_store()
    start = store.acquire_execution_start(
        lifecycle_binding,
        started_at=execution_lifecycle_store.utc_now_iso(),
    )
    if start.result != execution_lifecycle_store.START_ACQUIRED:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {start.reason_code}")
    try:
        execution = _run_subprocess(command, cwd=cwd)
    except Exception:
        store.record_terminal_outcome(
            lifecycle_binding,
            outcome_state=execution_lifecycle_store.PARTIAL_UNKNOWN,
            outcome_hash=execution_lifecycle_store.ZERO_SHA256_REFERENCE,
            current_evidence_hash=execution_lifecycle_store.ZERO_SHA256_REFERENCE,
            reconciliation_phase=execution_lifecycle_store.RECONCILIATION_PHASE_PRE_SIDE_EFFECT_SUBPROCESS_FAILURE,
            failure_class=execution_lifecycle_store.FAILURE_CLASS_SUBPROCESS_EXECUTION_FAILED,
            completed_at=execution_lifecycle_store.utc_now_iso(),
        )
        raise
    partial_reconciliation_phase = execution_lifecycle_store.RECONCILIATION_PHASE_POST_SUBPROCESS_ATTESTATION_FAILURE
    partial_failure_class = execution_lifecycle_store.FAILURE_CLASS_ATTESTATION_GENERATION_FAILED
    try:
        execution_attestation = attestation.generate_execution_attestation(
            command_id=str(token["command_id"]),
            command=command,
            stdout=execution["stdout"],
            stderr=execution["stderr"],
            exit_code=execution["exit_code"],
            signer_adapter=signer_adapter,
            key_id=str(runtime_key_id),
            cwd=cwd,
            attestation_path=attestation_path,
            signature_path=attestation_signature_path,
            governed_execution_authorization=governed_execution_authorization,
            governed_execution_contract=governed_execution_contract,
            consumed_decision_evidence_hash=consumed_decision_evidence_hash,
            previous_evidence_hash=governed_execution_authorization.get("execution_authorization_hash")
            if isinstance(governed_execution_authorization, dict)
            else "sha256:" + ("0" * 64),
        )
        outcome_error = attestation.validate_execution_outcome_attestation(
            execution_attestation,
            command=command,
            governed_execution_authorization=governed_execution_authorization,
            governed_execution_contract=governed_execution_contract,
            consumed_decision_evidence_hash=consumed_decision_evidence_hash or "",
        )
        if outcome_error:
            raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {outcome_error}")
        partial_reconciliation_phase = execution_lifecycle_store.RECONCILIATION_PHASE_SIGNATURE_VERIFICATION_FAILURE
        partial_failure_class = execution_lifecycle_store.FAILURE_CLASS_SIGNATURE_VERIFICATION_FAILED
        signature_error, signature_evidence = attestation.execution_attestation_signature_evidence(
            attestation=execution_attestation,
            attestation_path=attestation_path,
            signature_path=attestation_signature_path,
            public_key=governance_public_key,
            cwd=cwd,
        )
        if signature_error:
            raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {signature_error}")
    except Exception:
        store.record_terminal_outcome(
            lifecycle_binding,
            outcome_state=execution_lifecycle_store.PARTIAL_UNKNOWN,
            outcome_hash=execution_lifecycle_store.ZERO_SHA256_REFERENCE,
            current_evidence_hash=execution_lifecycle_store.ZERO_SHA256_REFERENCE,
            reconciliation_phase=partial_reconciliation_phase,
            failure_class=partial_failure_class,
            completed_at=execution_lifecycle_store.utc_now_iso(),
        )
        raise
    terminal = store.record_terminal_outcome(
        lifecycle_binding,
        outcome_state=execution_attestation["outcome_state"],
        outcome_hash=execution_attestation["outcome_hash"],
        current_evidence_hash=execution_attestation["current_evidence_hash"],
        attestation_payload_hash=signature_evidence["attestation_payload_hash"],
        attestation_signature_hash=signature_evidence["attestation_signature_hash"],
        signature_verification_result=signature_evidence["signature_verification_result"],
        attestation_path=attestation_path,
        attestation_signature_path=attestation_signature_path,
        signature_public_key=governance_public_key,
        signature_verification_cwd=cwd,
        completed_at=execution_lifecycle_store.utc_now_iso(),
    )
    if terminal.result != execution_lifecycle_store.TERMINAL_RECORDED:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {terminal.reason_code}")
    return {
        "token": token,
        "stdout": execution["stdout"],
        "stderr": execution["stderr"],
        "exit_code": execution["exit_code"],
        "action_token_hash": ledger.sha256_file(token_path),
        "execution_attestation": execution_attestation,
        "execution_attestation_hash": ledger.sha256_file(attestation_path),
        "execution_outcome_state": execution_attestation["outcome_state"],
        "execution_outcome_hash": execution_attestation["outcome_hash"],
        "execution_lifecycle": terminal.evidence,
    }


def _load_signed_command(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: missing command file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: command must be a JSON object")
    _validate_command_schema(payload)
    return payload


def _fetch_signed_command() -> dict:
    print(f"FETCH_REMOTE_URL: {COMMAND_RAW_URL}")
    try:
        with request.urlopen(COMMAND_RAW_URL, timeout=FETCH_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8")
    except (error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise RuntimeError(f"FETCH_REMOTE_FAILED: {exc}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"FETCH_REMOTE_FAILED: invalid JSON from remote command: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("FETCH_REMOTE_FAILED: command must be a JSON object")
    _validate_command_schema(payload)
    return payload


def _load_command_source(command_path: Path | None) -> tuple[dict, str]:
    if command_path is not None:
        return _load_signed_command(command_path), str(command_path)
    return _fetch_signed_command(), COMMAND_RAW_URL


def _command_bytes_without_signature(command: dict) -> bytes:
    payload = {key: value for key, value in command.items() if key != "signature"}
    return _canonical_json_bytes(payload)


def _validate_command_schema(command: dict) -> None:
    for field in REQUIRED_COMMAND_FIELDS:
        if field not in command:
            raise RuntimeError(f"COMMAND_SCHEMA_INVALID: missing {field}")
    if not isinstance(command.get("payload"), dict):
        raise RuntimeError("COMMAND_SCHEMA_INVALID: missing payload")


def _load_policy() -> dict:
    try:
        with open(ROOT / "policy" / "policy.json", encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError as exc:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing policy/policy.json") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: invalid policy JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: policy must be a JSON object")
    return payload


def _verify_ed25519_signature(command: dict) -> None:
    if not EXECUTOR_PUBLIC_KEY.exists():
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: missing executor public key: {EXECUTOR_PUBLIC_KEY}")
    signature_b64 = str(command.get("signature", "")).strip()
    if not signature_b64:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing command signature")
    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: invalid signature encoding: {exc}") from exc

    payload_bytes = _command_bytes_without_signature(command)
    with tempfile.NamedTemporaryFile(delete=False) as payload_handle:
        payload_handle.write(payload_bytes)
        payload_path = Path(payload_handle.name)
    with tempfile.NamedTemporaryFile(delete=False) as signature_handle:
        signature_handle.write(signature_bytes)
        signature_path = Path(signature_handle.name)

    command_line = [
        "openssl",
        "pkeyutl",
        "-verify",
        "-pubin",
        "-inkey",
        str(EXECUTOR_PUBLIC_KEY),
        "-sigfile",
        str(signature_path),
        "-rawin",
        "-in",
        str(payload_path),
    ]
    try:
        result = subprocess.run(
            command_line,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: unable to verify signature: {exc}") from exc
    finally:
        payload_path.unlink(missing_ok=True)
        signature_path.unlink(missing_ok=True)

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = " | ".join(part for part in [stdout, stderr] if part) or "signature verification failed"
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: {detail}")


def _validate_replay_protection(command: dict) -> None:
    command_id = str(command.get("command_id", "")).strip()
    nonce = str(command.get("nonce", "")).strip()
    if not command_id:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing command_id")
    if not nonce:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing nonce")
    if command_id in SEEN_COMMAND_IDS:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: command_id reused")
    if nonce in SEEN_NONCES:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: nonce reused")


def _validate_timestamps(command: dict) -> None:
    try:
        timestamp = int(command.get("timestamp"))
        expires_at = int(command.get("expires_at"))
    except Exception as exc:
        raise RuntimeError(f"EXECUTOR_VALIDATION_FAILED: invalid timestamp fields: {exc}") from exc
    if expires_at <= timestamp:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: expires_at must be greater than timestamp")
    if _utc_now() >= expires_at:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: command expired")


def _validate_policy_hash(command: dict) -> str:
    loaded_policy_hash = policy_validator.compute_policy_hash()
    command_policy_hash = str(command.get("policy_hash", "")).strip().lower()
    if not command_policy_hash:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing policy_hash")
    if command_policy_hash != loaded_policy_hash:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: policy_hash mismatch")
    return loaded_policy_hash


def _validate_signer_identity(command: dict) -> None:
    actor_role = str(command.get("actor_role", "")).strip()
    signed_by = str(command.get("signed_by", "")).strip()
    signing_context = str(command.get("signing_context", "")).strip()

    if not actor_role:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing actor_role")
    if not signed_by:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing signed_by")
    if not signing_context:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: missing signing_context")
    if signed_by not in ALLOWED_SIGNERS:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: signer is not trusted")
    if signing_context not in ALLOWED_SIGNING_CONTEXTS[signed_by]:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: signing_context is not trusted")
    if actor_role != signed_by:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: actor_role does not match signer identity")

    policy = _load_policy()
    override = policy.get("override")
    if not isinstance(override, dict):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: policy override configuration missing")
    roles = override.get("roles")
    if not isinstance(roles, list):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: policy override roles missing")
    allowed_roles = {str(value) for value in roles}
    if actor_role not in allowed_roles:
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: actor_role is not allowed by policy")


def _resolve_whitelisted_command(command: dict) -> dict:
    action = str(command.get("action", "")).strip()
    payload = command.get("payload")
    if not action.startswith("echo"):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: action is not whitelisted")
    if not isinstance(payload, dict):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: payload must be an object")
    if "message" in payload:
        message = str(payload["message"])
        return {"entrypoint": "echo", "args": [message]}
    args = payload.get("args", [])
    if not isinstance(args, list) or any(not isinstance(value, str) for value in args):
        raise RuntimeError("EXECUTOR_VALIDATION_FAILED: payload.args must be an array of strings")
    return {"entrypoint": "echo", "args": [str(value) for value in args]}


def _mark_command_used(command: dict) -> None:
    SEEN_COMMAND_IDS.add(str(command["command_id"]))
    SEEN_NONCES.add(str(command["nonce"]))


def execute_signed_command(command_path: Path | None = None) -> int:
    print("DIRECT_EXECUTION_BYPASS_BLOCKED: all execution must pass through runtime/enforcement_gateway.py")
    return 1


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    command_path = Path(args[0]) if args else None
    return execute_signed_command(command_path)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
