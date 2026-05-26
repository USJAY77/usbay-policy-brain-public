#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from audit.rfc3161_anchor import verify_timestamp_proof


CHAIN_GENESIS_HASH = "GENESIS"
REQUIRED_HISTORY_FILE = "gate_history.json"
REQUIRED_SUMMARY_FILE = "chain_summary.json"
REQUIRED_MANIFEST_FILE = "manifest.json"
REQUIRED_TIMESTAMP_FILE = "timestamp.tsr"
FORBIDDEN_MARKERS = (
    "PRIVATE " + "KEY",
    "BEGIN PGP " + "SIGNATURE",
    "ghp" + "_",
    "github" + "_pat_",
    "xoxb" + "-",
    "approval" + "_contents",
    "private" + "_key",
    "raw_" + "payload",
)
REQUIRED_SIGNER_FIELDS = {
    "signer_id",
    "signer_fingerprint",
    "signer_created_at",
    "signer_algorithm",
    "trust_anchor",
    "continuity_status",
}
REQUIRED_EVENT_FIELDS = {
    "previous_event_hash",
    "current_event_hash",
    "chain_position",
    "chain_integrity_status",
    "generated_at",
    "event_type",
    "decision",
    "evidence_hash",
}
REQUIRED_TIMESTAMP_FIELDS = {
    "timestamp_mode",
    "tsa_url",
    "timestamp_utc",
    "tsa_policy_oid",
    "timestamp_serial",
    "timestamp_hash_algorithm",
    "tsa",
    "hash",
    "timestamped_evidence_hash",
    "timestamp_token_sha256",
    "token_signature",
    "message_imprint",
    "message_imprint_algorithm",
    "previous_timestamp_hash",
    "timestamp_hash",
    "tsa_certificate_chain_valid",
    "tsa_certificate_chain_pem",
    "tsa_cert_not_before",
    "tsa_cert_not_after",
    "revocation_status",
}


class VerificationError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_json(path: Path) -> Any:
    if not path.is_file():
        raise VerificationError(f"REQUIRED_FILE_MISSING:{path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VerificationError(f"JSON_MALFORMED:{path.name}") from exc


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_required_text(path: Path) -> str:
    if not path.is_file():
        raise VerificationError(f"REQUIRED_FILE_MISSING:{path.name}")
    return path.read_text(encoding="utf-8")


def _assert_no_secret_markers(value: Any) -> None:
    rendered = canonical_json(value)
    leaked = [marker for marker in FORBIDDEN_MARKERS if marker in rendered]
    if leaked:
        raise VerificationError("SECRET_MARKER_DETECTED")


def _require_sha256(value: Any, reason: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise VerificationError(reason)
    return value


def _parse_utc(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise VerificationError("TIMESTAMP_UTC_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise VerificationError("TIMESTAMP_UTC_INVALID") from exc
    if parsed.tzinfo is None:
        raise VerificationError("TIMESTAMP_UTC_INVALID")
    return parsed.astimezone(timezone.utc)


def _signer_from_pack(gate_history: dict[str, Any], chain_summary: dict[str, Any]) -> dict[str, Any]:
    signer = gate_history.get("signer_continuity_metadata")
    summary_signer = chain_summary.get("signer_continuity_metadata")
    if not isinstance(signer, dict) or not isinstance(summary_signer, dict):
        raise VerificationError("SIGNER_IDENTITY_MISSING")
    if signer != summary_signer:
        raise VerificationError("SIGNER_IDENTITY_MISMATCH")
    missing = sorted(REQUIRED_SIGNER_FIELDS - set(signer))
    if missing:
        raise VerificationError("SIGNER_IDENTITY_MISSING_FIELDS:" + ",".join(missing))
    _require_sha256(signer.get("signer_fingerprint"), "SIGNER_FINGERPRINT_INVALID")
    if signer.get("continuity_status") not in {"STABLE", "REVIEW_REQUIRED"}:
        raise VerificationError("SIGNER_CONTINUITY_INVALID")
    return signer


def _chain_event_hash(previous_event: dict[str, Any] | None, event_payload: dict[str, Any], signer_identity: dict[str, Any]) -> str:
    previous_canonical = CHAIN_GENESIS_HASH if previous_event is None else canonical_json(previous_event)
    return sha256_text(
        canonical_json(
            {
                "canonicalized_previous_event": previous_canonical,
                "current_event_payload": event_payload,
                "signer_continuity_metadata": signer_identity,
            }
        )
    )


def _timestamped_evidence_hash(manifest_entries: list[dict[str, Any]]) -> str:
    scoped_entries = [
        {
            "path": entry["path"],
            "sha256": entry["sha256"],
            "size_bytes": entry["size_bytes"],
        }
        for entry in manifest_entries
        if entry.get("path") in {REQUIRED_HISTORY_FILE, REQUIRED_SUMMARY_FILE}
    ]
    return sha256_text(
        canonical_json(
            {
                "timestamp_scope": "sha256-only-evidence-pack-lineage",
                "included_file_hashes": scoped_entries,
            }
        )
    )


def _verify_timestamp_lineage(
    *,
    pack_dir: Path,
    manifest: dict[str, Any],
    manifest_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    token = _read_required_text(pack_dir / REQUIRED_TIMESTAMP_FILE).strip()
    if not token:
        raise VerificationError("TIMESTAMP_TOKEN_MISSING")
    metadata = manifest.get("rfc3161_timestamp")
    if not isinstance(metadata, dict):
        raise VerificationError("TIMESTAMP_METADATA_MISSING")
    missing = sorted(REQUIRED_TIMESTAMP_FIELDS - set(metadata))
    if missing:
        raise VerificationError("TIMESTAMP_METADATA_MISSING_FIELDS:" + ",".join(missing))
    if manifest.get("tsa_url") != metadata.get("tsa_url"):
        raise VerificationError("TIMESTAMP_MANIFEST_TSA_URL_MISMATCH")
    if manifest.get("timestamp_utc") != metadata.get("timestamp_utc"):
        raise VerificationError("TIMESTAMP_MANIFEST_UTC_MISMATCH")
    if manifest.get("tsa_policy_oid") != metadata.get("tsa_policy_oid"):
        raise VerificationError("TIMESTAMP_MANIFEST_POLICY_MISMATCH")
    if manifest.get("timestamp_serial") != metadata.get("timestamp_serial"):
        raise VerificationError("TIMESTAMP_MANIFEST_SERIAL_MISMATCH")
    if manifest.get("timestamp_hash_algorithm") != metadata.get("timestamp_hash_algorithm"):
        raise VerificationError("TIMESTAMP_MANIFEST_ALGORITHM_MISMATCH")
    if metadata.get("timestamp_hash_algorithm") != "sha256":
        raise VerificationError("TIMESTAMP_HASH_ALGORITHM_INVALID")
    try:
        token_payload = json.loads(base64.b64decode(token.encode("ascii"), validate=True).decode("utf-8"))
    except Exception as exc:
        raise VerificationError("TIMESTAMP_TOKEN_MALFORMED") from exc
    if token_payload.get("serial_number") != metadata.get("timestamp_serial"):
        raise VerificationError("TIMESTAMP_SERIAL_MISMATCH")
    expected_hash = _timestamped_evidence_hash(manifest_entries)
    if metadata.get("timestamped_evidence_hash") != expected_hash:
        raise VerificationError("TIMESTAMP_EVIDENCE_HASH_MISMATCH")
    if metadata.get("message_imprint") != expected_hash:
        raise VerificationError("TIMESTAMP_MESSAGE_IMPRINT_MISMATCH")
    token_hash = sha256_text(token)
    if metadata.get("timestamp_token_sha256") != token_hash:
        raise VerificationError("TIMESTAMP_TOKEN_HASH_MISMATCH")
    seen_token_hashes = set(manifest.get("replayed_timestamp_token_hashes") or [])
    proof = {
        "type": "RFC3161",
        "tsa": metadata["tsa"],
        "hash": metadata["hash"],
        "token": token,
        "token_signature": metadata["token_signature"],
        "message_imprint": metadata["message_imprint"],
        "message_imprint_algorithm": metadata["message_imprint_algorithm"],
        "policy_oid": metadata["tsa_policy_oid"],
        "created_at": metadata["timestamp_utc"],
        "mode": metadata["timestamp_mode"],
        "previous_timestamp_hash": metadata["previous_timestamp_hash"],
        "timestamp_hash": metadata["timestamp_hash"],
        "tsa_certificate_chain_valid": metadata["tsa_certificate_chain_valid"],
        "tsa_certificate_chain_pem": metadata["tsa_certificate_chain_pem"],
        "tsa_cert_not_before": metadata["tsa_cert_not_before"],
        "tsa_cert_not_after": metadata["tsa_cert_not_after"],
        "revocation_status": metadata["revocation_status"],
    }
    verification = verify_timestamp_proof(
        proof,
        expected_hash,
        seen_token_hashes=seen_token_hashes,
        now=_parse_utc(metadata["timestamp_utc"]),
        mode="mock",
    )
    if not verification.get("valid"):
        reason = ",".join(str(item) for item in verification.get("errors", [])) or "timestamp_verification_failed"
        raise VerificationError("TIMESTAMP_VERIFY_FAILED:" + reason)
    return {
        "timestamp_result": "PASS",
        "timestamp_hash": verification["timestamp_hash"],
        "timestamp_utc": metadata["timestamp_utc"],
    }


def verify_pack(pack_dir: Path) -> dict[str, Any]:
    gate_history = _load_json(pack_dir / REQUIRED_HISTORY_FILE)
    chain_summary = _load_json(pack_dir / REQUIRED_SUMMARY_FILE)
    manifest = _load_json(pack_dir / REQUIRED_MANIFEST_FILE)
    if not isinstance(gate_history, dict):
        raise VerificationError("GATE_HISTORY_INVALID")
    if not isinstance(chain_summary, dict):
        raise VerificationError("CHAIN_SUMMARY_INVALID")
    if not isinstance(manifest, dict):
        raise VerificationError("MANIFEST_INVALID")
    _assert_no_secret_markers(gate_history)
    _assert_no_secret_markers(chain_summary)
    _assert_no_secret_markers(manifest)
    signer = _signer_from_pack(gate_history, chain_summary)

    events = gate_history.get("events")
    if not isinstance(events, list) or not events:
        raise VerificationError("GATE_HISTORY_EVENTS_MISSING")

    previous_event: dict[str, Any] | None = None
    latest_hash = ""
    for expected_position, event in enumerate(events):
        if not isinstance(event, dict):
            raise VerificationError(f"GATE_HISTORY_EVENT_INVALID:{expected_position}")
        missing = sorted(REQUIRED_EVENT_FIELDS - set(event))
        if missing:
            raise VerificationError("GATE_HISTORY_EVENT_MISSING_FIELDS:" + ",".join(missing))
        if event.get("chain_position") != expected_position:
            raise VerificationError(f"CHAIN_POSITION_INVALID:{expected_position}")
        expected_previous_hash = CHAIN_GENESIS_HASH if previous_event is None else previous_event["current_event_hash"]
        if event.get("previous_event_hash") != expected_previous_hash:
            raise VerificationError(f"PREVIOUS_EVENT_HASH_INVALID:{expected_position}")
        payload = {
            "event_type": event["event_type"],
            "generated_at": event["generated_at"],
            "decision": event["decision"],
            "evidence_hash": event["evidence_hash"],
        }
        expected_hash = _chain_event_hash(previous_event, payload, signer)
        if event.get("current_event_hash") != expected_hash:
            raise VerificationError(f"EVENT_HASH_MISMATCH:{expected_position}")
        latest_hash = event["current_event_hash"]
        previous_event = event

    summary_latest = _require_sha256(chain_summary.get("latest_event_hash"), "LATEST_EVENT_HASH_INVALID")
    gate_latest = _require_sha256(gate_history.get("latest_event_hash"), "GATE_HISTORY_LATEST_EVENT_HASH_INVALID")
    if latest_hash != summary_latest or latest_hash != gate_latest:
        raise VerificationError("LATEST_EVENT_HASH_MISMATCH")
    if chain_summary.get("chain_integrity_status") != "PASS" or gate_history.get("chain_integrity_status") != "PASS":
        warning = str(chain_summary.get("broken_chain_warning") or gate_history.get("broken_chain_warning") or "CHAIN_MARKED_BROKEN")
        raise VerificationError(warning)
    if list(chain_summary.get("chain_positions", [])) != [event["chain_position"] for event in events]:
        raise VerificationError("CHAIN_POSITIONS_MISMATCH")
    manifest_entries = manifest.get("included_files")
    if not isinstance(manifest_entries, list) or not manifest_entries:
        raise VerificationError("MANIFEST_INCLUDED_FILES_MISSING")
    expected_manifest_paths = {REQUIRED_HISTORY_FILE, REQUIRED_SUMMARY_FILE, REQUIRED_TIMESTAMP_FILE}
    seen_manifest_paths = set()
    ordered_manifest_entries = []
    for entry in manifest_entries:
        if not isinstance(entry, dict):
            raise VerificationError("MANIFEST_ENTRY_INVALID")
        path_name = entry.get("path")
        if path_name not in expected_manifest_paths:
            raise VerificationError("MANIFEST_UNEXPECTED_FILE")
        seen_manifest_paths.add(path_name)
        expected_sha = _require_sha256(entry.get("sha256"), "MANIFEST_SHA256_INVALID")
        if not isinstance(entry.get("size_bytes"), int) or entry["size_bytes"] < 1:
            raise VerificationError("MANIFEST_SIZE_INVALID")
        artifact_path = pack_dir / str(path_name)
        if not artifact_path.is_file():
            raise VerificationError(f"REQUIRED_FILE_MISSING:{path_name}")
        actual_sha = _sha256_file(artifact_path)
        if actual_sha != expected_sha:
            raise VerificationError(f"MANIFEST_SHA256_MISMATCH:{path_name}")
        if artifact_path.stat().st_size != entry["size_bytes"]:
            raise VerificationError(f"MANIFEST_SIZE_MISMATCH:{path_name}")
        ordered_manifest_entries.append(entry)
    if seen_manifest_paths != expected_manifest_paths:
        raise VerificationError("MANIFEST_REQUIRED_FILE_MISSING")
    if manifest.get("latest_event_hash") != latest_hash:
        raise VerificationError("MANIFEST_LATEST_EVENT_HASH_MISMATCH")
    if manifest.get("chain_integrity_status") != "PASS":
        raise VerificationError("MANIFEST_CHAIN_INTEGRITY_INVALID")
    timestamp_report = _verify_timestamp_lineage(
        pack_dir=pack_dir,
        manifest=manifest,
        manifest_entries=ordered_manifest_entries,
    )

    return {
        "result": "PASS",
        "latest_event_hash": latest_hash,
        "event_count": len(events),
        "signer_fingerprint": signer["signer_fingerprint"],
        "timestamp_result": timestamp_report["timestamp_result"],
        "timestamp_hash": timestamp_report["timestamp_hash"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a USBAY governance evidence pack offline")
    parser.add_argument("pack_dir", type=Path)
    args = parser.parse_args(argv)
    try:
        report = verify_pack(args.pack_dir)
    except VerificationError as exc:
        print(f"VERIFY_FAIL {exc}")
        return 1
    except OSError:
        print("VERIFY_FAIL IO_ERROR")
        return 1
    print(f"VERIFY_PASS latest_event_hash={report['latest_event_hash']} event_count={report['event_count']}")
    print(f"TIMESTAMP_VERIFY_PASS timestamp_hash={report['timestamp_hash']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
