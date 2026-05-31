import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


INTAKE_POLICY_VERSION = "usbay.intake_gateway.phase1.v1"
INTAKE_ACTOR = "public_intake_gateway"
INTAKE_DEVICE = "usbay-intake-static-mvp"
INTAKE_NOTIFICATION_RECIPIENTS = ("governance@usbay.global", "pilot@usbay.global", "audit@usbay.global")
INTAKE_NOTIFICATION_RECIPIENT = INTAKE_NOTIFICATION_RECIPIENTS[0]
INTAKE_SCHEMA = "usbay.intake_submission.v1"
INTAKE_AUDIT_SCHEMA = "usbay.intake_audit.worm.v1"
INTAKE_NOTIFICATION_SCHEMA = "usbay.intake_notification.v1"
DEFAULT_INTAKE_STORAGE_DIR = Path("intake/storage")
DEFAULT_RETENTION_DAYS = 365
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 3600
DEFAULT_RATE_LIMIT_MAX_REQUESTS = 5

REQUIRED_FIELDS = (
    "organization",
    "contact_name",
    "contact_email",
    "role",
    "governance_scope",
    "policy_validation_required",
    "human_oversight_required",
    "audit_evidence_required",
    "provenance_required",
    "fail_closed_required",
)

BOOLEAN_FIELDS = (
    "regulated_industry",
    "high_risk_ai",
    "policy_validation_required",
    "human_oversight_required",
    "audit_evidence_required",
    "provenance_required",
    "fail_closed_required",
)

ALLOWED_ROLES = {
    "CISO",
    "Compliance Officer",
    "AI Governance Lead",
    "Enterprise Risk Manager",
    "Internal Audit",
    "Legal",
    "Security Engineering",
    "Other",
}

ROLE_SCOPES = {
    "intake_admin": {"intake:read", "intake:audit", "intake:policy"},
    "intake_auditor": {"intake:audit", "intake:policy"},
    "intake_operator": {"intake:read", "intake:policy"},
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_redis_client_override = None


class IntakeGatewayError(Exception):
    """Raised when the intake gateway must fail closed."""


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256_text(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def storage_root():
    return Path(os.getenv("USBAY_INTAKE_STORAGE_DIR", str(DEFAULT_INTAKE_STORAGE_DIR)))


def intake_paths(root=None):
    base = Path(root) if root is not None else storage_root()
    return {
        "root": base,
        "database": base / "intake.db",
        "worm_audit": base / "audit.worm.jsonl",
        "retention": base / "retention.json",
        "email_policy": base / "email_delivery_policy.json",
        "admin_identity_policy": base / "admin_identity_policy.json",
    }


def retention_days():
    raw = os.getenv("USBAY_INTAKE_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS))
    try:
        value = int(raw)
    except Exception as exc:
        raise IntakeGatewayError("INTAKE_RETENTION_POLICY_INVALID") from exc
    if value <= 0:
        raise IntakeGatewayError("INTAKE_RETENTION_POLICY_INVALID")
    return value


def rate_limit_policy():
    try:
        window = int(os.getenv("USBAY_INTAKE_RATE_LIMIT_WINDOW_SECONDS", str(DEFAULT_RATE_LIMIT_WINDOW_SECONDS)))
        max_requests = int(os.getenv("USBAY_INTAKE_RATE_LIMIT_MAX_REQUESTS", str(DEFAULT_RATE_LIMIT_MAX_REQUESTS)))
    except Exception as exc:
        raise IntakeGatewayError("INTAKE_RATE_LIMIT_POLICY_INVALID") from exc
    if window <= 0 or max_requests <= 0:
        raise IntakeGatewayError("INTAKE_RATE_LIMIT_POLICY_INVALID")
    return {"backend": "REDIS", "window_seconds": window, "max_requests": max_requests}


def set_redis_client_for_tests(client):
    global _redis_client_override
    _redis_client_override = client


def redis_rate_limit_client():
    if _redis_client_override is not None:
        return _redis_client_override
    if redis is None:
        raise IntakeGatewayError("INTAKE_REDIS_RATE_LIMIT_UNAVAILABLE")
    redis_url = os.getenv("USBAY_INTAKE_REDIS_URL") or os.getenv("REDIS_URL")
    if not redis_url:
        raise IntakeGatewayError("INTAKE_REDIS_RATE_LIMIT_UNAVAILABLE")
    try:
        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
        return client
    except Exception as exc:
        raise IntakeGatewayError("INTAKE_REDIS_RATE_LIMIT_UNAVAILABLE") from exc


def default_admin_identities():
    token = os.getenv("USBAY_INTAKE_ADMIN_TOKEN", "").strip()
    token_hash = os.getenv("USBAY_INTAKE_ADMIN_TOKEN_SHA256", "").strip() or (sha256_text(token) if token else "")
    if not token_hash:
        return []
    return [
        {
            "identity_id": "env-admin",
            "token_sha256": token_hash,
            "role": "intake_admin",
            "key_version": "env-v1",
            "status": "ACTIVE",
        }
    ]


def admin_identity_policy(*, root=None):
    raw = os.getenv("USBAY_INTAKE_ADMIN_IDENTITIES_JSON", "").strip()
    if raw:
        try:
            identities = json.loads(raw)
        except Exception as exc:
            raise IntakeGatewayError("INTAKE_ADMIN_IDENTITY_POLICY_INVALID") from exc
    else:
        identities = default_admin_identities()
    if not isinstance(identities, list):
        raise IntakeGatewayError("INTAKE_ADMIN_IDENTITY_POLICY_INVALID")
    safe = []
    for identity in identities:
        if not isinstance(identity, dict):
            raise IntakeGatewayError("INTAKE_ADMIN_IDENTITY_POLICY_INVALID")
        role = str(identity.get("role", ""))
        token_hash = str(identity.get("token_sha256", ""))
        status = str(identity.get("status", ""))
        key_version = str(identity.get("key_version", ""))
        if role not in ROLE_SCOPES or len(token_hash) != 64 or not key_version or status not in {"ACTIVE", "REVOKED"}:
            raise IntakeGatewayError("INTAKE_ADMIN_IDENTITY_POLICY_INVALID")
        safe.append(
            {
                "identity_id": str(identity.get("identity_id", "")),
                "token_sha256": token_hash,
                "role": role,
                "key_version": key_version,
                "status": status,
                "scopes": sorted(ROLE_SCOPES[role]),
                "rotates_after_epoch": identity.get("rotates_after_epoch"),
            }
        )
    policy = {
        "schema": "usbay.intake_admin_identity_policy.v1",
        "policy_version": INTAKE_POLICY_VERSION,
        "identity_count": len(safe),
        "key_rotation_required": True,
        "revoked_identities_blocked": True,
        "identities": safe,
    }
    policy["policy_hash"] = sha256_text(canonical_json(policy))
    paths = intake_paths(root)
    paths["admin_identity_policy"].parent.mkdir(parents=True, exist_ok=True)
    paths["admin_identity_policy"].write_text(canonical_json(policy), encoding="utf-8")
    return policy


def verify_admin_token(token, *, required_scope="intake:read", root=None):
    policy = admin_identity_policy(root=root)
    provided = sha256_text(str(token or ""))
    for identity in policy["identities"]:
        if not hmac.compare_digest(provided, identity["token_sha256"]):
            continue
        if identity["status"] != "ACTIVE":
            return False
        if required_scope not in set(identity["scopes"]):
            return False
        return True
    return False


def client_identity_hash(identity):
    value = str(identity or "unknown-client")
    return sha256_text(value)


def _connect(paths):
    paths["root"].mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(paths["database"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS submissions (submission_id TEXT PRIMARY KEY, created_at_epoch INTEGER NOT NULL, retention_until_epoch INTEGER NOT NULL, risk_level TEXT NOT NULL, submission_hash TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS notifications (notification_hash TEXT PRIMARY KEY, submission_id TEXT NOT NULL, created_at_epoch INTEGER NOT NULL, recipient TEXT NOT NULL, record_json TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    conn.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)", ("schema", "usbay.intake.sqlite.phase1.v1"))
    conn.commit()
    return conn


def _clean_text(value, *, max_length=400):
    if value is None:
        return ""
    text = str(value).strip()
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text[:max_length]


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    return None


def normalize_intake_payload(payload):
    if not isinstance(payload, dict):
        raise IntakeGatewayError("INTAKE_PAYLOAD_INVALID")
    normalized = {}
    for field in REQUIRED_FIELDS:
        if field not in payload:
            raise IntakeGatewayError(f"INTAKE_REQUIRED_FIELD_MISSING:{field}")
    normalized["organization"] = _clean_text(payload.get("organization"), max_length=160)
    normalized["contact_name"] = _clean_text(payload.get("contact_name"), max_length=120)
    normalized["contact_email"] = _clean_text(payload.get("contact_email"), max_length=180).lower()
    normalized["role"] = _clean_text(payload.get("role"), max_length=80)
    normalized["governance_scope"] = _clean_text(payload.get("governance_scope"), max_length=1200)
    normalized["target_timeline"] = _clean_text(payload.get("target_timeline"), max_length=120)
    for field in BOOLEAN_FIELDS:
        value = _as_bool(payload.get(field))
        if value is None:
            raise IntakeGatewayError(f"INTAKE_BOOLEAN_FIELD_INVALID:{field}")
        normalized[field] = value
    if not normalized["organization"]:
        raise IntakeGatewayError("INTAKE_REQUIRED_FIELD_EMPTY:organization")
    if not normalized["contact_name"]:
        raise IntakeGatewayError("INTAKE_REQUIRED_FIELD_EMPTY:contact_name")
    if not EMAIL_RE.match(normalized["contact_email"]):
        raise IntakeGatewayError("INTAKE_EMAIL_INVALID")
    if normalized["role"] not in ALLOWED_ROLES:
        raise IntakeGatewayError("INTAKE_ROLE_INVALID")
    if len(normalized["governance_scope"]) < 20:
        raise IntakeGatewayError("INTAKE_SCOPE_TOO_SHORT")
    if normalized["fail_closed_required"] is not True:
        raise IntakeGatewayError("INTAKE_FAIL_CLOSED_REQUIRED")
    return normalized


def classify_intake_risk(submission):
    score = 0
    reasons = []
    for field, reason in (
        ("regulated_industry", "REGULATED_INDUSTRY"),
        ("high_risk_ai", "HIGH_RISK_AI_WORKFLOW"),
        ("human_oversight_required", "HUMAN_OVERSIGHT_REQUIRED"),
        ("audit_evidence_required", "AUDIT_EVIDENCE_REQUIRED"),
        ("provenance_required", "PROVENANCE_REQUIRED"),
        ("policy_validation_required", "POLICY_VALIDATION_REQUIRED"),
        ("fail_closed_required", "FAIL_CLOSED_REQUIRED"),
    ):
        if submission.get(field) is True:
            score += 1
            reasons.append(reason)
    if submission.get("regulated_industry") and submission.get("high_risk_ai"):
        score += 2
        reasons.append("REGULATED_HIGH_RISK_INTERSECTION")
    if score >= 6:
        return "HIGH", reasons
    if score >= 3:
        return "MEDIUM", reasons
    return "LOW", reasons


def submission_record(submission, *, now_epoch=None, submission_id=None):
    risk_level, risk_reasons = classify_intake_risk(submission)
    created_at = int(now_epoch if now_epoch is not None else time.time())
    retention_until = created_at + retention_days() * 86400
    record = {
        "schema": INTAKE_SCHEMA,
        "submission_id": submission_id or str(uuid.uuid4()),
        "created_at_epoch": created_at,
        "retention_until_epoch": retention_until,
        "policy_version": INTAKE_POLICY_VERSION,
        "notification_recipients": list(INTAKE_NOTIFICATION_RECIPIENTS),
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "submission": submission,
    }
    record["submission_hash"] = sha256_text(canonical_json(record))
    return record


def _read_worm_records(path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _verify_worm_chain(path):
    previous = "0" * 64
    for row in _read_worm_records(path):
        signable = dict(row)
        current = signable.pop("audit_hash", "")
        if row.get("previous_hash") != previous or sha256_text(canonical_json(signable)) != current:
            return False
        previous = current
    return True


def _previous_worm_hash(path):
    if path.exists() and not _verify_worm_chain(path):
        raise IntakeGatewayError("INTAKE_WORM_AUDIT_CHAIN_INVALID")
    rows = _read_worm_records(path)
    return rows[-1]["audit_hash"] if rows else "0" * 64


def email_delivery_policy(*, root=None):
    paths = intake_paths(root)
    policy = {
        "schema": "usbay.intake_email_delivery_policy.phase1.v1",
        "recipients": list(INTAKE_NOTIFICATION_RECIPIENTS),
        "transport_mode": os.getenv("USBAY_INTAKE_EMAIL_TRANSPORT", "GOVERNED_OUTBOX"),
        "network_delivery_allowed": False,
        "fail_closed_on_delivery_policy_missing": True,
        "delivery_audit_required": True,
        "default_status": "QUEUED_GOVERNED_OUTBOX",
        "policy_version": INTAKE_POLICY_VERSION,
    }
    if policy["transport_mode"] != "GOVERNED_OUTBOX":
        raise IntakeGatewayError("INTAKE_EMAIL_POLICY_UNGOVERNED_TRANSPORT")
    policy["policy_hash"] = sha256_text(canonical_json(policy))
    paths["email_policy"].parent.mkdir(parents=True, exist_ok=True)
    paths["email_policy"].write_text(canonical_json(policy), encoding="utf-8")
    return policy


def notification_record(record, *, root=None):
    policy = email_delivery_policy(root=root)
    payload = {
        "schema": INTAKE_NOTIFICATION_SCHEMA,
        "recipients": list(INTAKE_NOTIFICATION_RECIPIENTS),
        "submission_id": record["submission_id"],
        "submission_hash": record["submission_hash"],
        "risk_level": record["risk_level"],
        "risk_reasons": list(record["risk_reasons"]),
        "created_at_epoch": record["created_at_epoch"],
        "policy_version": INTAKE_POLICY_VERSION,
        "delivery_policy_hash": policy["policy_hash"],
        "notification_status": policy["default_status"],
    }
    payload["notification_hash"] = sha256_text(canonical_json(payload))
    return payload


def audit_record(record, notification, *, previous_hash):
    event = {
        "schema": INTAKE_AUDIT_SCHEMA,
        "actor": INTAKE_ACTOR,
        "device": INTAKE_DEVICE,
        "decision": "ACCEPTED_FOR_GOVERNANCE_REVIEW",
        "timestamp": record["created_at_epoch"],
        "policy_version": INTAKE_POLICY_VERSION,
        "submission_id": record["submission_id"],
        "submission_hash": record["submission_hash"],
        "contact_email_hash": sha256_text(record["submission"]["contact_email"]),
        "organization_hash": sha256_text(record["submission"]["organization"]),
        "risk_level": record["risk_level"],
        "risk_reasons": list(record["risk_reasons"]),
        "retention_until_epoch": record["retention_until_epoch"],
        "notification_recipients": list(INTAKE_NOTIFICATION_RECIPIENTS),
        "notification_hash": notification["notification_hash"],
        "worm_storage": "APPEND_ONLY_HASH_CHAIN",
        "previous_hash": previous_hash,
    }
    event["audit_hash"] = sha256_text(canonical_json(event))
    return event


def _append_worm(path, event):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not _verify_worm_chain(path):
        raise IntakeGatewayError("INTAKE_WORM_AUDIT_CHAIN_INVALID")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(event) + "\n")


def _store_submission(paths, record, notification, audit):
    conn = _connect(paths)
    try:
        with conn:
            conn.execute(
                "INSERT INTO submissions(submission_id, created_at_epoch, retention_until_epoch, risk_level, submission_hash, record_json) VALUES (?, ?, ?, ?, ?, ?)",
                (record["submission_id"], record["created_at_epoch"], record["retention_until_epoch"], record["risk_level"], record["submission_hash"], canonical_json(record)),
            )
            for recipient in INTAKE_NOTIFICATION_RECIPIENTS:
                per_recipient = dict(notification)
                per_recipient["recipient"] = recipient
                per_recipient["recipient_hash"] = sha256_text(recipient)
                per_recipient["notification_hash"] = sha256_text(canonical_json(per_recipient))
                conn.execute(
                    "INSERT INTO notifications(notification_hash, submission_id, created_at_epoch, recipient, record_json) VALUES (?, ?, ?, ?, ?)",
                    (per_recipient["notification_hash"], record["submission_id"], record["created_at_epoch"], recipient, canonical_json(per_recipient)),
                )
            _append_worm(paths["worm_audit"], audit)
    finally:
        conn.close()


def create_intake_submission(payload, *, root=None, now_epoch=None):
    paths = intake_paths(root)
    try:
        normalized = normalize_intake_payload(payload)
        record = submission_record(normalized, now_epoch=now_epoch)
        notification = notification_record(record, root=root)
        previous_hash = _previous_worm_hash(paths["worm_audit"])
        audit = audit_record(record, notification, previous_hash=previous_hash)
        _store_submission(paths, record, notification, audit)
    except IntakeGatewayError:
        raise
    except Exception as exc:
        raise IntakeGatewayError("INTAKE_PERSISTENCE_FAILED") from exc
    return {
        "submission_id": record["submission_id"],
        "decision": "ACCEPTED_FOR_GOVERNANCE_REVIEW",
        "risk_level": record["risk_level"],
        "risk_reasons": record["risk_reasons"],
        "submission_hash": record["submission_hash"],
        "audit_hash": audit["audit_hash"],
        "notification_status": notification["notification_status"],
        "notification_recipients": list(INTAKE_NOTIFICATION_RECIPIENTS),
        "policy_version": INTAKE_POLICY_VERSION,
        "storage_backend": "SQLITE_DURABLE",
        "audit_storage": "WORM_APPEND_ONLY_HASH_CHAIN",
    }


def enforce_rate_limit(client_hash, *, root=None, now_epoch=None):
    now = int(now_epoch if now_epoch is not None else time.time())
    policy = rate_limit_policy()
    redis_client = redis_rate_limit_client()
    key = f"usbay:intake:rate:{client_hash}"
    try:
        current = int(redis_client.incr(key))
        if current == 1:
            redis_client.expire(key, policy["window_seconds"])
        ttl = redis_client.ttl(key) if hasattr(redis_client, "ttl") else policy["window_seconds"]
    except Exception as exc:
        raise IntakeGatewayError("INTAKE_REDIS_RATE_LIMIT_UNAVAILABLE") from exc
    if current > policy["max_requests"]:
        raise IntakeGatewayError("INTAKE_RATE_LIMIT_EXCEEDED")
    return {
        "rate_limit_backend": "REDIS",
        "rate_limit_remaining": policy["max_requests"] - current,
        "rate_limit_window_seconds": policy["window_seconds"],
        "rate_limit_reset_seconds": ttl,
        "rate_limit_checked_at_epoch": now,
    }


def retention_policy_export(*, root=None):
    paths = intake_paths(root)
    policy = {
        "schema": "usbay.intake_retention_policy.phase1.v1",
        "policy_version": INTAKE_POLICY_VERSION,
        "retention_days": retention_days(),
        "submission_storage": "SQLITE_DURABLE",
        "audit_storage": "WORM_APPEND_ONLY_HASH_CHAIN",
        "delete_mode": "MANUAL_REVIEW_REQUIRED",
        "fail_closed_on_invalid_policy": True,
    }
    policy["policy_hash"] = sha256_text(canonical_json(policy))
    paths["retention"].parent.mkdir(parents=True, exist_ok=True)
    paths["retention"].write_text(canonical_json(policy), encoding="utf-8")
    return policy


def _db_rows(paths, table):
    conn = _connect(paths)
    try:
        rows = conn.execute(f"SELECT record_json FROM {table} ORDER BY created_at_epoch ASC").fetchall()
        return [json.loads(row["record_json"]) for row in rows]
    finally:
        conn.close()


def intake_audit_export(*, root=None):
    paths = intake_paths(root)
    rows = _read_worm_records(paths["worm_audit"])
    valid = _verify_worm_chain(paths["worm_audit"])
    head = rows[-1]["audit_hash"] if rows else "0" * 64
    return {
        "schema": "usbay.intake_audit_export.phase1.v1",
        "policy_version": INTAKE_POLICY_VERSION,
        "event_count": len(rows),
        "chain_valid": valid,
        "head_hash": head,
        "storage_backend": "WORM_APPEND_ONLY_HASH_CHAIN",
        "events": rows,
    }


def intake_admin_export(*, root=None):
    paths = intake_paths(root)
    submissions = _db_rows(paths, "submissions")
    notifications = _db_rows(paths, "notifications")
    audit = intake_audit_export(root=root)
    return {
        "schema": "usbay.intake_admin_export.phase1.v1",
        "policy_version": INTAKE_POLICY_VERSION,
        "submission_count": len(submissions),
        "notification_count": len(notifications),
        "audit_event_count": audit["event_count"],
        "audit_chain_valid": audit["chain_valid"],
        "storage_backend": "SQLITE_DURABLE",
        "rate_limit_backend": "REDIS",
        "admin_identity_policy": admin_identity_policy(root=root),
        "retention_policy": retention_policy_export(root=root),
        "email_delivery_policy": email_delivery_policy(root=root),
        "submissions": submissions,
        "notifications": notifications,
        "audit": audit,
    }
