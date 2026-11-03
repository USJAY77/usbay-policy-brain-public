"""Non-production mutation currentness projection and held SQLite fence.

No trust, keys, roots, authority, schema, recovery, or production updater is
provisioned here. This adapter can only expose already-governed signed artifacts
through the existing EnrollmentAuthorityView SQLite transaction boundary.

A usable source requires:
- an existing projection table prepared by separately governed schema work;
- pinned signers already present in EnrollmentTrust for exact status roles;
- an independent high-water anchor whose hold spans SQLite COMMIT.

Without those dependencies protected mutation remains fail-closed.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import timedelta
import sqlite3

from governance.mutation_authority import (
    AUTHORITY_DOMAIN, COMMON, ParentAuthorityStatusV1, fingerprint, _signed,
)
from governance.mutation_commit import (
    CommitFenceRejected, MutationAuthorityCurrentnessFence, MutationCommitFenceV1,
    MutationFenceGuard, commit_fingerprint,
)
from governance.mutation_issuer_authority import (
    IssuerAuthorityStatusV1, authority_fingerprint,
)
from governance.tenant_enrollment_contracts import (
    SCOPE_FIELDS, EnrollmentDenied, canonical, digest, instant, parse_json, require,
)

PROJECTION_SCHEMA = "usbay.mutation_currentness.projection.v1"
PROJECTION_TABLE = "mutation_currentness_projection"
PROJECTION_FIELDS = {
    "schema_version", "scope", "authority_domain", "parent_artifact",
    "root_authority", "issuer_grant", "review_policy", "currentness",
    "target_object", "target_state", "parent_status_signer",
    "root_status_signer", "commit_fence_signer", "expected_current_head",
    "revocation_reference",
}
SIGNER_FIELDS = {"issuer_id", "issuer_key_id"}
STATUS_ROLES = {
    "parent": "mutation_parent_currentness",
    "root": "mutation_root_currentness",
    "commit": "mutation_commit_fence",
}


def _time_text(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def projection_scope(command):
    return {k: command[k] for k in (*SCOPE_FIELDS, "authority_domain")}


def projection_scope_hash(command):
    return digest(projection_scope(command))


def projection_payload_hash(payload):
    return digest(payload)


class MutationProjectionSigner:
    """Privileged signer interface. No key material or default signer lives here."""

    issuer_id: str
    key_id: str

    def sign(self, payload: dict, *, role: str) -> dict:
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UNPROVEN")


class MutationCurrentnessHighWater:
    """Rollback-resistant anchor interface; default is unavailable."""

    @contextmanager
    def hold(self, *, scope_hash: str):
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UNPROVEN")
        yield  # pragma: no cover


class MutationCurrentnessProjectionUpdater:
    """Governed updater interface only; no live writer is supplied."""

    def update(self, *args, **kwargs):
        raise EnrollmentDenied("AUTHORITY_CURRENTNESS_UPDATER_UNAVAILABLE")


def _validate_signer_reference(value):
    require(type(value) is dict and set(value) == SIGNER_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(all(type(value[k]) is str and value[k] and "*" not in value[k]
                for k in SIGNER_FIELDS), "AUTHORITY_CURRENTNESS_UNPROVEN")
    return deepcopy(value)


def _validate_projection(payload, command):
    require(type(payload) is dict and set(payload) == PROJECTION_FIELDS,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    canonical(payload)
    require(payload["schema_version"] == PROJECTION_SCHEMA
            and payload["authority_domain"] == AUTHORITY_DOMAIN,
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(payload["scope"] == projection_scope(command), "TENANT_MISMATCH")
    require(payload["expected_current_head"] == command["expected_current_head"],
            "EXPECTED_HEAD_MISMATCH")
    require(payload["target_state"] == command["expected_state"],
            "EXPECTED_STATE_MISMATCH")
    for name in ("parent_artifact", "root_authority", "issuer_grant",
                 "review_policy", "target_object"):
        require(type(payload[name]) is dict
                and set(payload[name]) == {"payload", "signature"},
                "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(type(payload["currentness"]) is dict
            and set(payload["currentness"]) ==
                {"policy", "adoption", "h", "w", "revocations", "expected",
                 "challenge", "request_digest"},
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    for name in ("policy", "adoption", "h", "w", "revocations"):
        require(type(payload["currentness"][name]) is dict
                and set(payload["currentness"][name]) == {"payload", "signature"},
                "AUTHORITY_CURRENTNESS_UNPROVEN")
    require(payload["currentness"]["expected"]["head_hash"]
            == command["expected_current_head"], "EXPECTED_HEAD_MISMATCH")
    require(payload["revocation_reference"]
            == payload["currentness"]["revocations"]["payload"].get("revocation_reference"),
            "AUTHORITY_CURRENTNESS_UNPROVEN")
    for name in ("parent_status_signer", "root_status_signer",
                 "commit_fence_signer"):
        _validate_signer_reference(payload[name])
    return deepcopy(payload)


def _signer_key(trust, signer_ref, role):
    key = trust._keys.get(signer_ref["issuer_key_id"])
    require(key is not None and key.issuer_id == signer_ref["issuer_id"]
            and role in key.roles, "AUTHORITY_CURRENTNESS_UNPROVEN")
    return key


def _bounded_status_deadline(trust, now, signer_key, *payloads):
    deadlines = [
        instant(signer_key.expires_at),
        now + timedelta(seconds=trust.max_age_seconds),
    ]
    for payload in payloads:
        end = payload.get("valid_until", payload.get("expires_at"))
        require(end is not None, "AUTHORITY_CURRENTNESS_UNPROVEN")
        deadlines.append(instant(end))
    result = min(deadlines)
    require(now < result, "AUTHORITY_CURRENTNESS_UNPROVEN")
    return result


class _ProjectionStatusSource:
    def __init__(self, projection, *, trust, signer, signer_ref, kind,
                 epoch, version, clock):
        self._projection = projection
        self._trust = trust
        self._signer = signer
        self._signer_ref = signer_ref
        self._kind = kind
        self._epoch = epoch
        self._version = version
        self._clock = clock

    def _signed_status(self, payload, model, role):
        envelope = self._signer.sign(deepcopy(payload), role=role)
        parsed, _ = _signed(self._trust, envelope, model, role, self._clock())
        require(parsed == payload, "AUTHORITY_CURRENTNESS_UNPROVEN")
        return envelope

    def read_parent_authority(self, *, request_binding, challenge):
        require(self._kind == "parent", "AUTHORITY_CURRENTNESS_UNPROVEN")
        p = self._projection
        parent = p["parent_artifact"]["payload"]
        signer_key = _signer_key(
            self._trust, self._signer_ref, STATUS_ROLES["parent"])
        now = self._clock()
        valid_until = _bounded_status_deadline(
            self._trust, now, signer_key, parent)
        common = {
            k: deepcopy(parent[k]) for k in COMMON
            if k not in ("schema_version", "issuer_id", "issuer_key_id",
                         "valid_from", "valid_until", "issued_at")
        }
        payload = dict(
            common,
            schema_version="usbay.mutation_authority.parent_status.v1",
            issuer_id=self._signer_ref["issuer_id"],
            issuer_key_id=self._signer_ref["issuer_key_id"],
            valid_from=_time_text(now),
            valid_until=_time_text(valid_until),
            issued_at=_time_text(now),
            parent_authority_id=parent["authority_id"],
            parent_authority_hash=digest(parent),
            subject_issuer_id=parent["subject_issuer_id"],
            issuance_scope=AUTHORITY_DOMAIN,
            parent_status="ACTIVE",
            state_sequence=self._version,
            state_epoch=self._epoch,
            expected_current_head=p["expected_current_head"],
            revocation_reference=p["revocation_reference"],
            challenge=challenge,
            request_binding=request_binding,
            status_fingerprint="",
        )
        payload["status_fingerprint"] = fingerprint(payload, "parent_status")
        ParentAuthorityStatusV1.from_payload(payload)
        return self._signed_status(
            payload, ParentAuthorityStatusV1, STATUS_ROLES["parent"])

    def read_issuer_authority(self, *, request_binding, challenge):
        require(self._kind == "root", "AUTHORITY_CURRENTNESS_UNPROVEN")
        p = self._projection
        root = p["root_authority"]["payload"]
        issuer = p["issuer_grant"]["payload"]
        signer_key = _signer_key(
            self._trust, self._signer_ref, STATUS_ROLES["root"])
        now = self._clock()
        valid_until = _bounded_status_deadline(
            self._trust, now, signer_key, root, issuer)
        common = {
            k: deepcopy(issuer[k]) for k in COMMON
            if k not in ("schema_version", "issuer_id", "issuer_key_id",
                         "valid_from", "valid_until", "issued_at")
        }
        payload = dict(
            common,
            schema_version="usbay.mutation_issuance.status.v1",
            issuer_id=self._signer_ref["issuer_id"],
            issuer_key_id=self._signer_ref["issuer_key_id"],
            valid_from=_time_text(now),
            valid_until=_time_text(valid_until),
            issued_at=_time_text(now),
            root_authority_id=root["root_authority_id"],
            root_authority_hash=digest(root),
            issuer_grant_id=issuer["issuer_grant_id"],
            issuer_grant_hash=digest(issuer),
            subject_issuer_id=issuer["issuer_id"],
            root_status="ACTIVE",
            issuer_status="ACTIVE",
            issuance_state="AVAILABLE",
            state_sequence=self._version,
            state_epoch=self._epoch,
            expected_current_head=p["expected_current_head"],
            revocation_reference=p["revocation_reference"],
            challenge=challenge,
            request_binding=request_binding,
            status_fingerprint="",
        )
        payload["status_fingerprint"] = authority_fingerprint(payload, "status")
        IssuerAuthorityStatusV1.from_payload(payload)
        return self._signed_status(
            payload, IssuerAuthorityStatusV1, STATUS_ROLES["root"])


class SQLiteMutationCurrentnessFence(MutationAuthorityCurrentnessFence):
    """Held non-production source in the existing authority SQLite database."""

    def __init__(self, view, *, signers: dict,
                 high_water: MutationCurrentnessHighWater):
        self._view = view
        self._signers = dict(signers or {})
        self._high_water = high_water

    def _signer(self, name, projection):
        role = STATUS_ROLES[name]
        signer = self._signers.get(role)
        require(isinstance(signer, MutationProjectionSigner),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        field = {
            "parent": "parent_status_signer",
            "root": "root_status_signer",
            "commit": "commit_fence_signer",
        }[name]
        ref = projection[field]
        require(signer.issuer_id == ref["issuer_id"]
                and signer.key_id == ref["issuer_key_id"],
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        _signer_key(self._view.trust, ref, role)
        return signer, ref

    @staticmethod
    def _load(connection, scope_hash):
        try:
            row = connection.execute(
                "SELECT source_epoch,source_version,projection,projection_hash "
                "FROM mutation_currentness_projection WHERE scope_hash=?",
                (scope_hash,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise EnrollmentDenied("COMMIT_FENCE_UNAVAILABLE") from exc
        require(row is not None, "AUTHORITY_CURRENTNESS_UNPROVEN")
        epoch, version, encoded, stored_hash = row
        require(type(epoch) is int and type(version) is int
                and epoch >= 1 and version >= 1,
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        payload = parse_json(encoded)
        require(stored_hash == projection_payload_hash(payload),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        return epoch, version, payload, stored_hash

    @contextmanager
    def hold(self, connection, *, command, challenge):
        require(connection.in_transaction, "TRANSACTION_CONFLICT")
        scope_hash = projection_scope_hash(command)
        require(isinstance(self._high_water, MutationCurrentnessHighWater),
                "AUTHORITY_CURRENTNESS_UNPROVEN")
        with self._high_water.hold(scope_hash=scope_hash) as anchor:
            epoch, version, projection, projection_hash = self._load(
                connection, scope_hash)
            projection = _validate_projection(projection, command)
            current = anchor.current()
            require(current == {
                "scope_hash": scope_hash,
                "source_epoch": epoch,
                "source_version": version,
                "projection_hash": projection_hash,
            }, "AUTHORITY_CURRENTNESS_UNPROVEN")
            yield _SQLiteMutationCurrentnessGuard(
                self, connection, command, challenge, projection,
                projection_hash, epoch, version, anchor)


class _SQLiteMutationCurrentnessGuard(MutationFenceGuard):
    def __init__(self, source, connection, command, challenge, projection,
                 projection_hash, epoch, version, anchor):
        self._source = source
        self._connection = connection
        self._command = deepcopy(command)
        self._challenge = challenge
        self._projection = projection
        self._projection_hash = projection_hash
        self._epoch = epoch
        self._version = version
        self._anchor = anchor
        self._parent_signer, self._parent_ref = source._signer(
            "parent", projection)
        self._root_signer, self._root_ref = source._signer(
            "root", projection)
        self._commit_signer, self._commit_ref = source._signer(
            "commit", projection)

    def authority_material(self):
        p = self._projection
        clock = self._source._view.clock
        return dict(
            parent_artifact=deepcopy(p["parent_artifact"]),
            parent_source=_ProjectionStatusSource(
                p, trust=self._source._view.trust,
                signer=self._parent_signer, signer_ref=self._parent_ref,
                kind="parent", epoch=self._epoch,
                version=self._version, clock=clock),
            root_authority=deepcopy(p["root_authority"]),
            issuer_grant=deepcopy(p["issuer_grant"]),
            review_policy=deepcopy(p["review_policy"]),
            root_source=_ProjectionStatusSource(
                p, trust=self._source._view.trust,
                signer=self._root_signer, signer_ref=self._root_ref,
                kind="root", epoch=self._epoch,
                version=self._version, clock=clock),
            currentness=deepcopy(p["currentness"]),
            target_object=deepcopy(p["target_object"]),
        )

    def read_state(self, connection, command):
        require(connection is self._connection and connection.in_transaction,
                "TRANSACTION_CONFLICT")
        require(projection_scope_hash(command)
                == projection_scope_hash(self._command), "TENANT_MISMATCH")
        return deepcopy(self._projection["target_state"])

    def evidence(self, *, command, bindings, now):
        require(command == self._command, "COMMIT_FENCE_MISMATCH")
        payload = {k: deepcopy(command[k]) for k in COMMON}
        payload.update(
            schema_version="usbay.mutation_commit.fence.v1",
            issuer_id=self._commit_ref["issuer_id"],
            issuer_key_id=self._commit_ref["issuer_key_id"],
            **deepcopy(bindings),
            source_version=self._version,
            source_epoch=self._epoch,
            issued_at=_time_text(now),
            valid_from=_time_text(now),
            fence_created_at=_time_text(now),
            valid_until=bindings["verification_valid_until"],
            fence_valid_until=bindings["verification_valid_until"],
            fence_fingerprint="",
        )
        payload["fence_fingerprint"] = commit_fingerprint(payload, "fence")
        MutationCommitFenceV1.from_payload(payload)
        envelope = self._commit_signer.sign(
            deepcopy(payload), role=STATUS_ROLES["commit"])
        parsed, _ = _signed(
            self._source._view.trust, envelope, MutationCommitFenceV1,
            STATUS_ROLES["commit"], now)
        require(parsed == payload, "COMMIT_FENCE_MISMATCH")
        return envelope

    def commit_if_current(self, connection, *, fence, now):
        require(connection is self._connection and connection.in_transaction,
                "TRANSACTION_CONFLICT")
        try:
            epoch, version, projection, projection_hash = self._source._load(
                connection, projection_scope_hash(self._command))
            if (epoch, version, projection_hash) != (
                    self._epoch, self._version, self._projection_hash):
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            if projection_payload_hash(
                    _validate_projection(projection, self._command)
            ) != self._projection_hash:
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            if not (instant(fence["valid_from"])
                    <= now < instant(fence["fence_valid_until"])):
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            expected = {
                "scope_hash": projection_scope_hash(self._command),
                "source_epoch": self._epoch,
                "source_version": self._version,
                "projection_hash": self._projection_hash,
            }
            if self._anchor.current() != expected:
                raise CommitFenceRejected("COMMIT_FENCE_STALE")
            self._anchor.commit_if_unchanged(connection, expected=expected)
        except CommitFenceRejected:
            raise
        except Exception as exc:
            raise CommitFenceRejected("COMMIT_FENCE_STALE") from exc
