from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

try:
    import redis
except ImportError:  # pragma: no cover - exercised only when redis-py is absent.
    redis = None


DEFAULT_DECISION_TTL_SECONDS = 300
DEFAULT_DECISION_SIGNING_KEY = "usbay-local-decision-signing-key"
DEFAULT_CLOCK_SKEW_SECONDS = 5
DEFAULT_ALG_VERSION = "hmac-sha256-v1"
DEFAULT_CLASSIC_ALG = "HMAC-SHA256"
DEFAULT_PQC_ALG = "HMAC-SHA512"
STRICT_SIGNATURE_POLICY = "STRICT"
COMPAT_SIGNATURE_POLICY = "COMPAT"
TRANSITION_SIGNATURE_POLICY = "TRANSITION"
SIGNATURE_POLICY_MODES = {
    STRICT_SIGNATURE_POLICY,
    COMPAT_SIGNATURE_POLICY,
    TRANSITION_SIGNATURE_POLICY,
}
SUPPORTED_ALG_VERSIONS = {DEFAULT_ALG_VERSION}
DECISION_CHAIN_GENESIS = "0" * 64
IMMUTABLE_DECISION_FIELDS = (
    "actor_hash",
    "alg_version",
    "compute_policy_hash",
    "compute_target",
    "data_sensitivity",
    "decision",
    "decision_id",
    "execution_location",
    "expires_at",
    "policy_version",
    "policy_hash",
    "policy_pubkey_id",
    "policy_sequence",
    "policy_valid_from",
    "policy_valid_until",
    "request_hash",
    "signature_valid",
)
EXECUTION_PROOF_FIELDS = {
    "actual_execution_target",
    "execution_verified",
}


class DecisionStoreError(RuntimeError):
    pass


def decision_ttl_seconds() -> int:
    raw_ttl = os.getenv("USBAY_DECISION_TTL_SECONDS", str(DEFAULT_DECISION_TTL_SECONDS))
    try:
        ttl = int(raw_ttl)
    except (TypeError, ValueError) as exc:
        raise DecisionStoreError("invalid_decision_ttl") from exc
    if ttl <= 0:
        raise DecisionStoreError("invalid_decision_ttl")
    return ttl


def clock_skew_seconds() -> int:
    raw_skew = os.getenv("USBAY_CLOCK_SKEW_SECONDS", str(DEFAULT_CLOCK_SKEW_SECONDS))
    try:
        skew = int(raw_skew)
    except (TypeError, ValueError) as exc:
        raise DecisionStoreError("invalid_clock_skew") from exc
    if skew < 0:
        raise DecisionStoreError("invalid_clock_skew")
    return skew


def enterprise_mode() -> bool:
    return os.getenv("USBAY_ENTERPRISE_MODE", "").lower() == "true"


def utc_iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc_iso(value: str) -> int:
    if not isinstance(value, str) or not value:
        raise DecisionStoreError("malformed_decision_time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception as exc:
        raise DecisionStoreError("malformed_decision_time") from exc
    if parsed.tzinfo is None:
        raise DecisionStoreError("malformed_decision_time")
    return int(parsed.timestamp())


def decision_signing_key() -> str:
    configured_key = os.getenv("USBAY_DECISION_SIGNING_KEY")
    if configured_key:
        return configured_key
    if os.getenv("REDIS_URL") or enterprise_mode():
        raise DecisionStoreError("missing_decision_signing_key")
    return DEFAULT_DECISION_SIGNING_KEY


def decision_alg_version() -> str:
    return os.getenv("USBAY_DECISION_ALG_VERSION", DEFAULT_ALG_VERSION)


def is_supported_alg_version(alg_version: Any) -> bool:
    return isinstance(alg_version, str) and alg_version in SUPPORTED_ALG_VERSIONS


def decision_classic_alg() -> str:
    return os.getenv("USBAY_DECISION_CLASSIC_ALG", DEFAULT_CLASSIC_ALG).upper()


def decision_pqc_alg() -> str:
    return os.getenv("USBAY_DECISION_PQC_ALG", DEFAULT_PQC_ALG).upper()


def signature_policy_mode() -> str:
    mode = os.getenv("signature_policy_mode") or os.getenv("USBAY_SIGNATURE_POLICY_MODE") or STRICT_SIGNATURE_POLICY
    normalized = mode.upper()
    if normalized not in SIGNATURE_POLICY_MODES:
        raise DecisionStoreError("unsupported_signature_policy_mode")
    return normalized


def decision_classic_signing_key() -> str:
    return os.getenv("USBAY_DECISION_CLASSIC_SIGNING_KEY") or decision_signing_key()


def decision_pqc_signing_key() -> str:
    configured_key = os.getenv("USBAY_DECISION_PQC_SIGNING_KEY")
    if configured_key:
        return configured_key
    # Simulated PQC domain separation for phase-1 crypto agility. This is not real PQC.
    return f"{decision_signing_key()}:pqc-sim-v1"


def decision_signature_payload(record: dict[str, Any]) -> str:
    return "|".join(
        [
            str(record.get("decision_id", "")),
            str(record.get("decision", "")),
            str(record.get("policy_hash", "")),
            str(record.get("request_hash", "")),
            str(record.get("policy_version", "")),
            str(record.get("policy_pubkey_id", "")),
            str(record.get("signature_valid", "")),
            str(record.get("expires_at_epoch", record.get("expires_at", 0))),
            str(record.get("nonce_hash", "")),
            str(record.get("actor_hash", "")),
            str(record.get("gateway_id", "")),
            str(record.get("previous_hash", "")),
        ]
    )


def _record_for_hash(record: dict[str, Any]) -> dict[str, Any]:
    evidence = {}
    for field in IMMUTABLE_DECISION_FIELDS:
        value = record.get(field)
        if value in (None, ""):
            raise DecisionStoreError(f"missing_immutable_field:{field}")
        evidence[field] = value
    return evidence


def decision_record_hash(record: dict[str, Any]) -> str:
    previous_hash = str(record.get("previous_hash", DECISION_CHAIN_GENESIS))
    body = json.dumps(_record_for_hash(record), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(f"{previous_hash}{body}".encode("utf-8")).hexdigest()


def verify_decision_chain(records: list[dict[str, Any]]) -> bool:
    previous_hash = DECISION_CHAIN_GENESIS
    for record in records:
        if record.get("previous_hash") != previous_hash:
            return False
        try:
            expected_hash = decision_record_hash(record)
        except DecisionStoreError:
            return False
        if record.get("current_hash") != expected_hash:
            return False
        if record.get("audit_hash") != expected_hash:
            return False
        previous_hash = str(record.get("current_hash", ""))
    return True


def _hmac_signature(record: dict[str, Any], key: str, alg: str) -> str:
    if alg == "HMAC-SHA256":
        digestmod = hashlib.sha256
    elif alg == "HMAC-SHA512":
        digestmod = hashlib.sha512
    else:
        raise DecisionStoreError("unsupported_decision_signature_algorithm")
    return hmac.new(
        key.encode("utf-8"),
        decision_signature_payload(record).encode("utf-8"),
        digestmod,
    ).hexdigest()


def sign_decision_classic(record: dict[str, Any], signing_key: str | None = None) -> str:
    return _hmac_signature(
        record,
        signing_key or decision_classic_signing_key(),
        decision_classic_alg(),
    )


def sign_decision_pqc(record: dict[str, Any], signing_key: str | None = None) -> str:
    return _hmac_signature(
        record,
        signing_key or decision_pqc_signing_key(),
        decision_pqc_alg(),
    )


def sign_decision(record: dict[str, Any], signing_key: str | None = None) -> str:
    return sign_decision_classic(record, signing_key)


def sign_decision_hybrid(record: dict[str, Any]) -> dict[str, str]:
    alg_version = decision_alg_version()
    if alg_version not in SUPPORTED_ALG_VERSIONS:
        raise DecisionStoreError("unsupported_decision_algorithm_version")
    return {
        "alg_version": alg_version,
        "decision_signature_classic": sign_decision_classic(record),
        "decision_signature_pqc": sign_decision_pqc(record),
    }


def verify_decision_signature(record: dict[str, Any], signing_key: str | None = None) -> bool:
    signature = record.get("decision_signature_classic", record.get("decision_signature"))
    if not isinstance(signature, str) or not signature:
        return False
    expected = sign_decision_classic(record, signing_key)
    return hmac.compare_digest(signature, expected)


def decision_signature_validity(record: dict[str, Any]) -> tuple[bool, bool]:
    classic_signature = record.get("decision_signature_classic")
    pqc_signature = record.get("decision_signature_pqc")
    alg_version = record.get("alg_version")
    if not isinstance(alg_version, str) or not alg_version:
        return False, False
    if alg_version != decision_alg_version() or not is_supported_alg_version(alg_version):
        return False, False
    expected_classic = sign_decision_classic(record)
    expected_pqc = sign_decision_pqc(record)
    classic_valid = isinstance(classic_signature, str) and hmac.compare_digest(classic_signature, expected_classic)
    pqc_valid = isinstance(pqc_signature, str) and hmac.compare_digest(pqc_signature, expected_pqc)
    return classic_valid, pqc_valid


def verify_decision_signatures(record: dict[str, Any], mode: str | None = None) -> bool:
    try:
        policy_mode = (mode or signature_policy_mode()).upper()
    except DecisionStoreError:
        return False
    if policy_mode not in SIGNATURE_POLICY_MODES:
        return False
    classic_valid, pqc_valid = decision_signature_validity(record)
    if policy_mode == STRICT_SIGNATURE_POLICY:
        return classic_valid and pqc_valid
    if policy_mode == COMPAT_SIGNATURE_POLICY:
        return classic_valid or pqc_valid
    if policy_mode == TRANSITION_SIGNATURE_POLICY:
        return classic_valid
    return False


def verify_submitted_decision_signatures(
    record: dict[str, Any],
    submitted_classic_signature: Any,
    submitted_pqc_signature: Any,
    mode: str | None = None,
) -> bool:
    try:
        policy_mode = (mode or signature_policy_mode()).upper()
    except DecisionStoreError:
        return False
    if policy_mode not in SIGNATURE_POLICY_MODES:
        return False

    classic_valid, pqc_valid = decision_signature_validity(record)
    classic_matches = (
        isinstance(submitted_classic_signature, str)
        and isinstance(record.get("decision_signature_classic"), str)
        and hmac.compare_digest(submitted_classic_signature, record["decision_signature_classic"])
    )
    pqc_matches = (
        isinstance(submitted_pqc_signature, str)
        and isinstance(record.get("decision_signature_pqc"), str)
        and hmac.compare_digest(submitted_pqc_signature, record["decision_signature_pqc"])
    )
    if policy_mode == STRICT_SIGNATURE_POLICY:
        return classic_valid and pqc_valid and classic_matches and pqc_matches
    if policy_mode == COMPAT_SIGNATURE_POLICY:
        return (classic_valid and classic_matches) or (pqc_valid and pqc_matches)
    if policy_mode == TRANSITION_SIGNATURE_POLICY:
        return classic_valid and classic_matches
    return False


def decision_key(decision_id: str) -> str:
    return f"decision:{decision_id}"


def nonce_key(nonce_hash: str) -> str:
    return f"decision_nonce:{nonce_hash}"


def decision_chain_head_key() -> str:
    return "decision_chain:head"


def normalize_decision_record(record: dict[str, Any]) -> dict[str, Any]:
    ttl = decision_ttl_seconds()
    now = int(time.time())
    stored = record.copy()
    created_epoch = int(stored.get("created_at_epoch", now))
    expires_epoch = int(stored.get("expires_at_epoch", created_epoch + ttl))
    stored["created_at_epoch"] = created_epoch
    stored["expires_at_epoch"] = expires_epoch
    stored["created_at"] = stored.get("created_at") or utc_iso(created_epoch)
    stored["expires_at"] = stored.get("expires_at") or utc_iso(expires_epoch)
    stored["used"] = bool(stored.get("used", False))
    return stored


def validate_decision_time(record: dict[str, Any]) -> bool:
    try:
        ttl = decision_ttl_seconds()
        skew = clock_skew_seconds()
        now = int(time.time())
        created_epoch = int(record.get("created_at_epoch"))
        expires_epoch = int(record.get("expires_at_epoch"))
        if parse_utc_iso(str(record.get("created_at"))) != created_epoch:
            return False
        if parse_utc_iso(str(record.get("expires_at"))) != expires_epoch:
            return False
        if expires_epoch <= now:
            return False
        if created_epoch > now + skew:
            return False
        if expires_epoch <= created_epoch:
            return False
        if expires_epoch - created_epoch > ttl + skew:
            return False
        return True
    except Exception:
        return False


class RedisDecisionStore:
    def __init__(self, redis_client=None, redis_url: str | None = None) -> None:
        self.redis_client = redis_client
        self.redis_url = redis_url or os.getenv("REDIS_URL", "")
        if self.redis_client is None and not self.redis_url:
            raise DecisionStoreError("redis_not_configured")

    def _client(self):
        if self.redis_client is not None:
            return self.redis_client
        if redis is None:
            raise DecisionStoreError("missing_dependency:redis")
        try:
            self.redis_client = redis.Redis.from_url(self.redis_url, decode_responses=True)
            self.redis_client.ping()
        except Exception as exc:
            raise DecisionStoreError("redis_unavailable") from exc
        return self.redis_client

    def create_decision(self, record: dict[str, Any]) -> dict[str, Any]:
        now = int(time.time())
        stored = normalize_decision_record(record)
        try:
            previous_hash = self._client().get(decision_chain_head_key()) or DECISION_CHAIN_GENESIS
        except Exception as exc:
            raise DecisionStoreError("decision_store_unavailable") from exc
        stored["previous_hash"] = previous_hash
        stored["alg_version"] = decision_alg_version()
        stored["current_hash"] = decision_record_hash(stored)
        stored["audit_hash"] = stored["current_hash"]
        stored.update(sign_decision_hybrid(stored))
        stored["decision_signature"] = stored["decision_signature_classic"]

        try:
            client = self._client()
            ok = client.set(
                decision_key(str(stored["decision_id"])),
                json.dumps(stored, sort_keys=True, separators=(",", ":")),
                ex=max(1, int(stored["expires_at_epoch"]) - now),
            )
            if ok is True:
                client.set(decision_chain_head_key(), stored["current_hash"])
        except Exception as exc:
            raise DecisionStoreError("decision_store_unavailable") from exc
        if ok is not True:
            raise DecisionStoreError("decision_store_write_failed")
        return stored

    def load_decision(self, decision_id: str) -> dict[str, Any] | None:
        try:
            raw = self._client().get(decision_key(str(decision_id)))
        except Exception as exc:
            raise DecisionStoreError("decision_store_unavailable") from exc
        if raw is None:
            return None
        try:
            record = json.loads(raw)
        except Exception as exc:
            raise DecisionStoreError("decision_store_corrupt") from exc
        return record

    def reserve_nonce(self, nonce_hash_value: str, ttl: int | None = None) -> bool:
        try:
            stored = self._client().set(
                nonce_key(nonce_hash_value),
                "1",
                nx=True,
                ex=ttl or decision_ttl_seconds(),
            )
        except Exception as exc:
            raise DecisionStoreError("decision_store_unavailable") from exc
        return stored is True

    def mark_used(self, decision_id: str, execution_proof: dict[str, Any] | None = None) -> bool:
        client = self._client()
        key = decision_key(str(decision_id))
        try:
            with client.pipeline() as pipe:
                while True:
                    try:
                        pipe.watch(key)
                        raw = pipe.get(key)
                        if raw is None:
                            pipe.unwatch()
                            return False
                        record = json.loads(raw)
                        if record.get("used") is True:
                            pipe.unwatch()
                            return False
                        ttl = pipe.ttl(key)
                        if ttl is None or int(ttl) <= 0:
                            pipe.unwatch()
                            return False
                        record["used"] = True
                        if execution_proof:
                            for field in EXECUTION_PROOF_FIELDS:
                                if field in execution_proof:
                                    record[field] = execution_proof[field]
                        pipe.multi()
                        pipe.set(
                            key,
                            json.dumps(record, sort_keys=True, separators=(",", ":")),
                            ex=int(ttl),
                        )
                        pipe.execute()
                        return True
                    except getattr(redis, "WatchError", Exception):
                        continue
        except Exception as exc:
            raise DecisionStoreError("decision_store_unavailable") from exc

    def delete_decision(self, decision_id: str) -> None:
        try:
            self._client().delete(decision_key(str(decision_id)))
        except Exception as exc:
            raise DecisionStoreError("decision_store_unavailable") from exc


class InMemoryDecisionStore:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        self.fail_create = False
        self.fail_load = False
        self.fail_mark_used = False
        self.nonces: dict[str, int] = {}
        self.chain_head = DECISION_CHAIN_GENESIS

    def create_decision(self, record: dict[str, Any]) -> dict[str, Any]:
        if self.fail_create:
            raise DecisionStoreError("decision_store_unavailable")
        stored = normalize_decision_record(record)
        stored["previous_hash"] = self.chain_head
        stored["alg_version"] = decision_alg_version()
        stored["current_hash"] = decision_record_hash(stored)
        stored["audit_hash"] = stored["current_hash"]
        stored.update(sign_decision_hybrid(stored))
        stored["decision_signature"] = stored["decision_signature_classic"]
        self.records[str(stored["decision_id"])] = stored
        self.chain_head = stored["current_hash"]
        return stored.copy()

    def verify_chain(self) -> bool:
        return verify_decision_chain(list(self.records.values()))

    def load_decision(self, decision_id: str) -> dict[str, Any] | None:
        if self.fail_load:
            raise DecisionStoreError("decision_store_unavailable")
        record = self.records.get(str(decision_id))
        if record is None:
            return None
        return record.copy()

    def mark_used(self, decision_id: str, execution_proof: dict[str, Any] | None = None) -> bool:
        if self.fail_mark_used:
            raise DecisionStoreError("decision_store_unavailable")
        record = self.records.get(str(decision_id))
        if record is None or record.get("used") is True:
            return False
        record["used"] = True
        if execution_proof:
            for field in EXECUTION_PROOF_FIELDS:
                if field in execution_proof:
                    record[field] = execution_proof[field]
        return True

    def delete_decision(self, decision_id: str) -> None:
        self.records.pop(str(decision_id), None)

    def reserve_nonce(self, nonce_hash_value: str, ttl: int | None = None) -> bool:
        now = int(time.time())
        expires_at = self.nonces.get(nonce_hash_value)
        if expires_at is not None and expires_at > now:
            return False
        self.nonces[nonce_hash_value] = now + int(ttl or decision_ttl_seconds())
        return True


DecisionStoreTestDouble = InMemoryDecisionStore


class UnavailableDecisionStore:
    def __init__(self, reason: str = "decision_store_unavailable") -> None:
        self.reason = reason

    def create_decision(self, record: dict[str, Any]) -> dict[str, Any]:
        raise DecisionStoreError(self.reason)

    def load_decision(self, decision_id: str) -> dict[str, Any] | None:
        raise DecisionStoreError(self.reason)

    def mark_used(self, decision_id: str, execution_proof: dict[str, Any] | None = None) -> bool:
        raise DecisionStoreError(self.reason)

    def delete_decision(self, decision_id: str) -> None:
        raise DecisionStoreError(self.reason)

    def reserve_nonce(self, nonce_hash_value: str, ttl: int | None = None) -> bool:
        raise DecisionStoreError(self.reason)


def create_decision_store():
    if enterprise_mode() and not os.getenv("REDIS_URL"):
        raise DecisionStoreError("redis_required")
    if enterprise_mode() and not os.getenv("USBAY_DECISION_SIGNING_KEY"):
        raise DecisionStoreError("missing_decision_signing_key")
    if os.getenv("REDIS_URL"):
        return RedisDecisionStore()
    if os.getenv("USBAY_ALLOW_IN_MEMORY_DECISION_STORE", "").lower() == "true":
        return InMemoryDecisionStore()
    raise DecisionStoreError("redis_required")
