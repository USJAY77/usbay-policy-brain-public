#!/usr/bin/env python3
"""
Validate policy integrity for USBAY governance.

Fail-closed behavior:
- any missing artifact, parse issue, digest mismatch, or signature failure returns non-zero
- no uncertain or partially validated policy is accepted
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit import ledger, sealing
POLICY_JSON = ROOT / "policy" / "policy.json"
POLICY_SHA256 = ROOT / "policy" / "policy.sha256"
POLICY_SIG = ROOT / "policy" / "policy.sig"
PUBLIC_KEY = ROOT / "policy" / "public_key.pem"
APPROVAL_1_JSON = ROOT / "approvals" / "policy-approval-1.json"
APPROVAL_1_SIG = ROOT / "approvals" / "policy-approval-1.sig"
APPROVAL_1_PUBLIC_KEY = ROOT / "approvals" / "approver1_public_key.pem"
APPROVAL_2_JSON = ROOT / "approvals" / "policy-approval-2.json"
APPROVAL_2_SIG = ROOT / "approvals" / "policy-approval-2.sig"
APPROVAL_2_PUBLIC_KEY = ROOT / "approvals" / "approver2_public_key.pem"
EVIDENCE_RULESET_JSON = ROOT / "evidence" / "rulesets.json"
EVIDENCE_RULESET_SHA256 = ROOT / "evidence" / "rulesets.sha256"
EVIDENCE_RULESET_META = ROOT / "evidence" / "rulesets.meta.json"
RUNTIME_ATTESTATION_JSON = ROOT / "audit" / "logs" / "runtime_attestation.json"
RUNTIME_ATTESTATION_SIG = ROOT / "audit" / "logs" / "runtime_attestation.sig"
RUNTIME_ATTESTATION_PUBLIC_KEY = ROOT / "runtime" / "runtime_attestation_public_key.pem"
AUDIT_LOG_JSONL = ROOT / "audit" / "audit_log.jsonl"
LEDGER_HEAD_JSON = ROOT / "audit" / "ledger_head.json"
LEDGER_HEAD_SIG = ROOT / "audit" / "ledger_head.sig"
AUDIT_SEAL_PUBLIC_KEY = ROOT / "audit" / "audit_seal_public_key.pem"
APPROVAL_MAX_AGE = timedelta(days=7)
APPROVAL_MAX_FUTURE_SKEW = timedelta(minutes=5)


def _fail(message: str, code: int = 1) -> int:
    print(f"POLICY_VALIDATION_FAILED: {message}")
    return code


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"unable to read {path}: {exc}") from exc


def _require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"missing required file: {path}")
    if not path.is_file():
        raise RuntimeError(f"required path is not a file: {path}")
    if path.stat().st_size <= 0:
        raise RuntimeError(f"required file is empty: {path}")


def _canonical_json_bytes(payload: dict) -> bytes:
    return ledger.canonical_json_bytes(payload)


def _coded_error(code: str, detail: str | None = None) -> RuntimeError:
    if detail:
        return RuntimeError(f"{code}: {detail}")
    return RuntimeError(code)


def _approval_code(label: str, suffix: str) -> str:
    if label == "approval[1]":
        prefix = "POLICY_APPROVAL_1"
    elif label == "approval[2]":
        prefix = "POLICY_APPROVAL_2"
    else:
        prefix = "POLICY_APPROVAL"
    return f"{prefix}_{suffix}"


def _approval_paths() -> list[tuple[str, Path, Path, Path]]:
    return [
        ("approval[1]", APPROVAL_1_JSON, APPROVAL_1_SIG, APPROVAL_1_PUBLIC_KEY),
        ("approval[2]", APPROVAL_2_JSON, APPROVAL_2_SIG, APPROVAL_2_PUBLIC_KEY),
    ]


def _sha256_bytes(payload: bytes) -> str:
    return ledger.sha256_bytes(payload)


def _sha256_file(path: Path) -> str:
    return ledger.sha256_file(path)


def validate_required_files() -> None:
    _require_file(POLICY_JSON)
    _require_file(POLICY_SHA256)
    _require_file(POLICY_SIG)
    _require_file(PUBLIC_KEY)


def validate_policy_json() -> None:
    raw = _read_text(POLICY_JSON)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON") from exc

    if not isinstance(parsed, dict):
        raise ValueError("policy.json must contain a JSON object at top level")

    if not parsed:
        raise ValueError("policy.json must not be empty")


def load_policy_document() -> dict:
    raw = _read_text(POLICY_JSON)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise ValueError("policy.json must contain a JSON object at top level")
    return parsed


def compute_policy_hash() -> str:
    return hashlib.sha256(_read_bytes(POLICY_JSON)).hexdigest().lower()


def load_policy_metadata() -> dict:
    policy = load_policy_document()
    return {
        "policy_version": str(policy.get("policy_version", policy.get("version", "unknown"))),
        "policy_hash": compute_policy_hash(),
        "policy": policy,
    }


def validate_sha256() -> None:
    policy_bytes = _read_bytes(POLICY_JSON)
    expected_raw = _read_text(POLICY_SHA256)

    # accepteer zowel "<hash>" als "<hash>  filename"
    expected_hash = expected_raw.split()[0].strip().lower()
    actual_hash = hashlib.sha256(policy_bytes).hexdigest().lower()

    if len(expected_hash) != 64:
        raise ValueError(f"invalid sha256 format in {POLICY_SHA256}")

    if actual_hash != expected_hash:
        raise ValueError(
            f"sha256 mismatch for {POLICY_JSON}: expected {expected_hash}, got {actual_hash}"
        )


def validate_signature() -> None:
    command = [
        "openssl",
        "pkeyutl",
        "-verify",
        "-pubin",
        "-inkey",
        str(PUBLIC_KEY),
        "-sigfile",
        str(POLICY_SIG),
        "-rawin",
        "-in",
        str(POLICY_JSON),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl not available for signature verification") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if result.returncode != 0:
        detail = " | ".join(part for part in [stdout, stderr] if part)
        if not detail:
            detail = "openssl signature verification returned non-zero exit code"
        raise RuntimeError(f"signature verification failed: {detail}")

    if "signature verified successfully" not in stdout.lower():
        detail = " | ".join(part for part in [stdout, stderr] if part)
        raise RuntimeError(f"unexpected openssl verification output: {detail}")


def _approval_signature_payload(approval: dict) -> bytes:
    policy_sha = _read_text(POLICY_SHA256).split()[0].strip().lower()
    if len(policy_sha) != 64:
        raise ValueError(f"invalid sha256 format in {POLICY_SHA256}")
    return _canonical_json_bytes(approval) + b"\n" + policy_sha.encode("utf-8")


def _approval_bundle_hash(approval_json: Path, approval_sig: Path, approver_public_key: Path) -> str:
    payload = bytearray()
    payload.extend(_read_bytes(approval_json))
    payload.extend(b"\n")
    payload.extend(_read_bytes(approval_sig))
    payload.extend(b"\n")
    payload.extend(_read_bytes(approver_public_key))
    payload.extend(b"\n")
    return _sha256_bytes(bytes(payload))


def _approval_hashes() -> tuple[str, str]:
    values: list[str] = []
    for _, approval_json, approval_sig, approver_public_key in _approval_paths():
        values.append(_approval_bundle_hash(approval_json, approval_sig, approver_public_key))
    return values[0], values[1]


def _evidence_snapshot_hash() -> str:
    return _sha256_file(EVIDENCE_RULESET_JSON)


def _parse_utc_timestamp(value: str, *, label: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception as exc:
        raise RuntimeError(f"{label} timestamp is invalid: {exc}") from exc


def _github_sha() -> str:
    return os.environ.get("GITHUB_SHA", "").strip().lower()


def current_approval_nonces() -> list[str]:
    nonces: list[str] = []
    for _, approval_json, _, _ in _approval_paths():
        approval = json.loads(_read_text(approval_json))
        nonce = str(approval.get("nonce", "")).strip()
        if nonce:
            nonces.append(nonce)
    return nonces


def _verify_detached_signature(*, public_key: Path, signature: Path, payload: bytes) -> None:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(payload)
        payload_path = Path(handle.name)

    command = [
        "openssl",
        "dgst",
        "-sha256",
        "-verify",
        str(public_key),
        "-signature",
        str(signature),
        str(payload_path),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl not available for signature verification") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc
    finally:
        try:
            payload_path.unlink()
        except FileNotFoundError:
            pass

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = " | ".join(part for part in [stdout, stderr] if part)
        if not detail:
            detail = "openssl signature verification returned non-zero exit code"
        raise RuntimeError(f"signature verification failed: {detail}")

    if "verified ok" not in stdout.lower():
        detail = " | ".join(part for part in [stdout, stderr] if part)
        raise RuntimeError(f"unexpected openssl verification output: {detail}")


def _public_key_fingerprint(public_key: Path) -> str:
    command = ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"]
    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl not available for public key fingerprinting") from exc
    except OSError as exc:
        raise RuntimeError(f"failed to execute openssl: {exc}") from exc

    if result.returncode != 0:
        detail = ((result.stderr or b"") + (result.stdout or b"")).decode("utf-8", errors="replace").strip()
        if not detail:
            detail = "openssl public key export returned non-zero exit code"
        raise RuntimeError(f"unable to derive public key fingerprint: {detail}")

    return hashlib.sha256(result.stdout).hexdigest().lower()


def _verify_signature_for_path(*, public_key: Path, signature: Path, payload_path: Path) -> None:
    try:
        sealing.verify_path(
            public_key=public_key,
            payload_path=payload_path,
            signature_path=signature,
            cwd=ROOT,
        )
    except Exception as exc:
        raise RuntimeError(f"signature verification failed: {exc}") from exc


def compute_runtime_hash(*, instance_id: str, commit_hash: str, loaded_policy_hash: str, timestamp: str) -> str:
    payload = "\n".join([instance_id, commit_hash, loaded_policy_hash, timestamp]).encode("utf-8")
    return _sha256_bytes(payload)


def _validate_approval_document(*, approval: dict, label: str, policy_hash: str, policy_version: str) -> None:
    required = {
        "policy_hash",
        "approver_id",
        "policy_version",
        "author",
        "approver",
        "approved_at",
        "timestamp",
        "nonce",
        "reason",
        "status",
    }
    missing = sorted(required - set(approval.keys()))
    if missing:
        raise _coded_error(
            "POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK",
            f"{label} missing required fields: {missing}",
        )
    if approval.get("status") != "approved":
        code = _approval_code(label, "STATUS_INVALID")
        raise _coded_error(code, "status must be 'approved'")
    if str(approval.get("policy_hash", "")).lower() != policy_hash:
        code = _approval_code(label, "HASH_MISMATCH")
        raise _coded_error(code, "policy_hash does not match current policy hash")
    approver_id = str(approval.get("approver_id", "")).strip()
    if not approver_id:
        raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", f"{label} approver_id is required")
    approval_policy_version = approval.get("policy_version")
    if approval_policy_version is not None and str(approval_policy_version) != policy_version:
        raise _coded_error(
            "POLICY_APPROVAL_VERSION_MISMATCH",
            f"{label} policy_version does not match current policy version",
        )
    commit_sha = str(approval.get("commit_sha", "")).strip().lower()
    github_sha = _github_sha()
    if commit_sha:
        if not github_sha:
            raise _coded_error("POLICY_APPROVAL_COMMIT_SHA_MISMATCH", f"{label} commit_sha present but GITHUB_SHA is unset")
        if commit_sha != github_sha:
            raise _coded_error("POLICY_APPROVAL_COMMIT_SHA_MISMATCH", f"{label} commit_sha does not match GITHUB_SHA")
    nonce = str(approval.get("nonce", "")).strip()
    if not nonce:
        raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", f"{label} nonce is required")
    approved_at = str(approval.get("approved_at", "")).strip()
    timestamp = str(approval.get("timestamp", "")).strip()
    if approved_at != timestamp:
        raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", f"{label} approved_at and timestamp must match")
    approval_time = _parse_utc_timestamp(timestamp, label=label)
    now = datetime.now(timezone.utc)
    if approval_time < now - APPROVAL_MAX_AGE or approval_time > now + APPROVAL_MAX_FUTURE_SKEW:
        raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", f"{label} timestamp outside allowed window")


def validate_approval_artifacts(*, policy_hash: str, policy_version: str) -> None:
    approver_fingerprints: set[str] = set()
    seen_nonces: set[str] = set()
    approval_policy_hashes: list[str] = []

    for label, approval_json, approval_sig, approver_public_key in _approval_paths():
        try:
            _require_file(approval_json)
        except Exception as exc:
            code = _approval_code(label, "MISSING")
            raise _coded_error(code, str(exc)) from exc
        try:
            _require_file(approval_sig)
        except Exception as exc:
            code = _approval_code(label, "SIGNATURE_INVALID")
            raise _coded_error(code, str(exc)) from exc
        try:
            _require_file(approver_public_key)
        except Exception as exc:
            raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", str(exc)) from exc

        try:
            approval = json.loads(_read_text(approval_json))
        except json.JSONDecodeError as exc:
            raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", f"invalid JSON in {approval_json}: {exc}") from exc

        if not isinstance(approval, dict):
            raise _coded_error(
                "POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK",
                f"{approval_json} must contain a JSON object at top level",
            )

        _validate_approval_document(
            approval=approval,
            label=label,
            policy_hash=policy_hash,
            policy_version=policy_version,
        )
        approval_policy_hashes.append(str(approval["policy_hash"]).strip().lower())
        nonce = str(approval["nonce"]).strip()
        if nonce in seen_nonces:
            raise _coded_error("POLICY_APPROVAL_REUSE_DETECTED", "approval nonce reused")
        seen_nonces.add(nonce)
        payload = _approval_signature_payload(approval)
        try:
            _verify_detached_signature(
                public_key=approver_public_key,
                signature=approval_sig,
                payload=payload,
            )
        except Exception as exc:
            code = _approval_code(label, "SIGNATURE_INVALID")
            detail = str(exc)
            if "unexpected openssl verification output" in detail or "signature verification failed" in detail:
                detail = f"POLICY_APPROVAL_CANONICAL_BINDING_INVALID: {detail}"
            raise _coded_error(code, detail) from exc

        try:
            fingerprint = _public_key_fingerprint(approver_public_key)
        except Exception as exc:
            raise _coded_error("POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK", str(exc)) from exc
        if fingerprint in approver_fingerprints:
            raise _coded_error("POLICY_APPROVAL_KEYS_NOT_DISTINCT", "dual approval requires different approver public keys")
        approver_fingerprints.add(fingerprint)

    if len(approver_fingerprints) != 2:
        raise _coded_error(
            "POLICY_APPROVAL_PARTIAL_VALIDATION_BLOCK",
            "dual approval requires two distinct approver public keys",
        )
    if len(approval_policy_hashes) != 2 or approval_policy_hashes[0] != approval_policy_hashes[1]:
        raise _coded_error(
            "POLICY_APPROVAL_HASH_MISMATCH",
            "approval policy_hash values must match each other and the current policy hash",
        )

    if AUDIT_LOG_JSONL.exists():
        try:
            ledger.verify_chain(AUDIT_LOG_JSONL)
            prior_nonces: set[str] = set()
            for line in AUDIT_LOG_JSONL.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                for nonce in entry.get("approval_nonces", []):
                    prior_nonces.add(str(nonce))
        except RuntimeError:
            raise
        except Exception:
            prior_nonces = set()
        if seen_nonces & prior_nonces:
            raise _coded_error("POLICY_APPROVAL_REUSE_DETECTED", "approval nonce reused")


def validate_runtime_attestation(*, policy_hash: str) -> None:
    _require_file(RUNTIME_ATTESTATION_JSON)
    _require_file(RUNTIME_ATTESTATION_SIG)
    _require_file(RUNTIME_ATTESTATION_PUBLIC_KEY)
    try:
        attestation = json.loads(_read_text(RUNTIME_ATTESTATION_JSON))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {RUNTIME_ATTESTATION_JSON}: {exc}") from exc

    if not isinstance(attestation, dict):
        raise RuntimeError(f"{RUNTIME_ATTESTATION_JSON} must contain a JSON object at top level")

    required = {"instance_id", "commit_hash", "loaded_policy_hash", "runtime_hash", "timestamp"}
    missing = sorted(required - set(attestation.keys()))
    if missing:
        raise RuntimeError(f"runtime attestation missing required fields: {missing}")
    if str(attestation.get("loaded_policy_hash", "")).lower() != policy_hash:
        raise RuntimeError("runtime attestation loaded_policy_hash does not match current policy hash")
    expected_runtime_hash = compute_runtime_hash(
        instance_id=str(attestation["instance_id"]),
        commit_hash=str(attestation["commit_hash"]),
        loaded_policy_hash=str(attestation["loaded_policy_hash"]),
        timestamp=str(attestation["timestamp"]),
    )
    if str(attestation.get("runtime_hash", "")).lower() != expected_runtime_hash:
        raise RuntimeError("runtime attestation runtime_hash does not match attested payload")
    _verify_signature_for_path(
        public_key=RUNTIME_ATTESTATION_PUBLIC_KEY,
        signature=RUNTIME_ATTESTATION_SIG,
        payload_path=RUNTIME_ATTESTATION_JSON,
    )


def validate_evidence_snapshot() -> str:
    _require_file(EVIDENCE_RULESET_JSON)
    _require_file(EVIDENCE_RULESET_SHA256)
    _require_file(EVIDENCE_RULESET_META)

    expected_hash = _read_text(EVIDENCE_RULESET_SHA256).split()[0].strip().lower()
    if len(expected_hash) != 64:
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_HASH_INVALID",
            "rulesets.sha256 must contain a 64-character sha256 hex digest",
        )

    actual_hash = _evidence_snapshot_hash()
    if actual_hash != expected_hash:
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_HASH_MISMATCH",
            "rulesets.sha256 does not match rulesets.json",
        )

    try:
        snapshot = json.loads(EVIDENCE_RULESET_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_INVALID",
            f"invalid JSON in {EVIDENCE_RULESET_JSON}: {exc}",
        ) from exc
    if not isinstance(snapshot, list):
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_INVALID",
            "rulesets.json must contain a JSON array at top level",
        )

    try:
        meta = json.loads(EVIDENCE_RULESET_META.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_META_INVALID",
            f"invalid JSON in {EVIDENCE_RULESET_META}: {exc}",
        ) from exc
    if not isinstance(meta, dict):
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_META_INVALID",
            "rulesets.meta.json must contain a JSON object at top level",
        )

    required = {"source", "fetched_at", "commit_sha", "sha256"}
    missing = sorted(required - set(meta.keys()))
    if missing:
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_META_INVALID",
            f"rulesets.meta.json missing required fields: {missing}",
        )
    _parse_utc_timestamp(str(meta["fetched_at"]), label="rulesets.meta.json.fetched_at")
    commit_sha = str(meta["commit_sha"]).strip().lower()
    if len(commit_sha) != 40 or any(ch not in "0123456789abcdef" for ch in commit_sha):
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_META_INVALID",
            "rulesets.meta.json commit_sha must be a 40-character git sha",
        )
    if str(meta["sha256"]).strip().lower() != actual_hash:
        raise _coded_error(
            "EVIDENCE_SNAPSHOT_META_INVALID",
            "rulesets.meta.json sha256 does not match rulesets.json",
        )
    return actual_hash


def validate_audit_chain(*, policy_hash: str) -> None:
    _require_file(AUDIT_LOG_JSONL)
    _require_file(LEDGER_HEAD_JSON)
    _require_file(LEDGER_HEAD_SIG)
    _require_file(AUDIT_SEAL_PUBLIC_KEY)

    approval_1_hash, approval_2_hash = _approval_hashes()
    evidence_snapshot_hash = validate_evidence_snapshot()
    attestation_hash = _sha256_file(RUNTIME_ATTESTATION_JSON)

    last_entry_hash, entry_count, last_entry = ledger.verify_chain(AUDIT_LOG_JSONL)
    seal_payload = sealing.verify_seal(
        seal_path=LEDGER_HEAD_JSON,
        signature_path=LEDGER_HEAD_SIG,
        public_key=AUDIT_SEAL_PUBLIC_KEY,
        cwd=ROOT,
    )
    if seal_payload["latest_entry_hash"] != last_entry_hash:
        raise _coded_error("AUDIT_LEDGER_HEAD_MISMATCH", "ledger head latest_entry_hash does not match audit log")
    if int(seal_payload["entry_count"]) != entry_count:
        raise _coded_error("AUDIT_LEDGER_HEAD_MISMATCH", "ledger head entry_count does not match audit log")
    if last_entry["policy_hash"] != policy_hash:
        raise _coded_error("AUDIT_POLICY_HASH_MISMATCH", "latest audit log policy_hash does not match current policy hash")
    if not last_entry.get("approval_1_hash"):
        raise _coded_error("AUDIT_BOUND_ARTIFACT_MISSING", "latest audit log approval_1_hash is missing")
    if not last_entry.get("approval_2_hash"):
        raise _coded_error("AUDIT_BOUND_ARTIFACT_MISSING", "latest audit log approval_2_hash is missing")
    if not last_entry.get("evidence_snapshot_hash"):
        raise _coded_error("AUDIT_BOUND_ARTIFACT_MISSING", "latest audit log evidence_snapshot_hash is missing")
    if not last_entry.get("runtime_attestation_hash"):
        raise _coded_error("AUDIT_BOUND_ARTIFACT_MISSING", "latest audit log runtime_attestation_hash is missing")
    if last_entry["approval_1_hash"] != approval_1_hash:
        raise _coded_error("AUDIT_APPROVAL_1_HASH_MISMATCH", "latest audit log approval_1_hash does not match current approval[1]")
    if last_entry["approval_2_hash"] != approval_2_hash:
        raise _coded_error("AUDIT_APPROVAL_2_HASH_MISMATCH", "latest audit log approval_2_hash does not match current approval[2]")
    if last_entry["evidence_snapshot_hash"] != evidence_snapshot_hash:
        raise _coded_error("AUDIT_EVIDENCE_HASH_MISMATCH", "latest audit log evidence_snapshot_hash does not match current evidence snapshot")
    if last_entry["runtime_attestation_hash"] != attestation_hash:
        raise _coded_error("AUDIT_RUNTIME_ATTESTATION_HASH_MISMATCH", "latest audit log runtime_attestation_hash does not match current attestation")


def main() -> int:
    try:
        validate_required_files()
        validate_policy_json()
        validate_sha256()
        validate_signature()
        metadata = load_policy_metadata()
        validate_approval_artifacts(
            policy_hash=metadata["policy_hash"],
            policy_version=metadata["policy_version"],
        )
        validate_runtime_attestation(policy_hash=metadata["policy_hash"])
        validate_audit_chain(policy_hash=metadata["policy_hash"])
    except Exception as exc:
        return _fail(str(exc), code=1)

    print("POLICY_VALIDATION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
