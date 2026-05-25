#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


CHAIN_GENESIS_HASH = "GENESIS"
REQUIRED_HISTORY_FILE = "gate_history.json"
REQUIRED_SUMMARY_FILE = "chain_summary.json"
REQUIRED_MANIFEST_FILE = "manifest.json"
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


def _assert_no_secret_markers(value: Any) -> None:
    rendered = canonical_json(value)
    leaked = [marker for marker in FORBIDDEN_MARKERS if marker in rendered]
    if leaked:
        raise VerificationError("SECRET_MARKER_DETECTED")


def _require_sha256(value: Any, reason: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
        raise VerificationError(reason)
    return value


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
    expected_manifest_paths = {REQUIRED_HISTORY_FILE, REQUIRED_SUMMARY_FILE}
    seen_manifest_paths = set()
    for entry in manifest_entries:
        if not isinstance(entry, dict):
            raise VerificationError("MANIFEST_ENTRY_INVALID")
        path_name = entry.get("path")
        if path_name not in expected_manifest_paths:
            raise VerificationError("MANIFEST_UNEXPECTED_FILE")
        seen_manifest_paths.add(path_name)
        expected_sha = _require_sha256(entry.get("sha256"), "MANIFEST_SHA256_INVALID")
        actual_sha = _sha256_file(pack_dir / str(path_name))
        if actual_sha != expected_sha:
            raise VerificationError(f"MANIFEST_SHA256_MISMATCH:{path_name}")
    if seen_manifest_paths != expected_manifest_paths:
        raise VerificationError("MANIFEST_REQUIRED_FILE_MISSING")
    if manifest.get("latest_event_hash") != latest_hash:
        raise VerificationError("MANIFEST_LATEST_EVENT_HASH_MISMATCH")
    if manifest.get("chain_integrity_status") != "PASS":
        raise VerificationError("MANIFEST_CHAIN_INTEGRITY_INVALID")

    return {
        "result": "PASS",
        "latest_event_hash": latest_hash,
        "event_count": len(events),
        "signer_fingerprint": signer["signer_fingerprint"],
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
